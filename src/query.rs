//! The query language of the web UI, compiled to SQLite.
//!
//! ```text
//! signature.status = unsigned and not pe.aslr
//! rule = "Tampered signed file" or severity >= error
//! path ~ "\\Google\\" and writable_by has Users
//! signature.signer changed
//! chrome                       (bare word: path contains "chrome")
//! ```
//!
//! Operators: `=` `!=` `<` `<=` `>` `>=`, `~` (regex, case-insensitive), `has`
//! (substring, or element of an array), `exists`, `missing`, `changed`.
//! `and` binds tighter than `or`; adjacent terms are and-ed; `not` and parentheses work
//! as usual. A bare field is true when its value is truthy (`not pe.aslr`).
//!
//! Every value becomes a bound parameter; field paths are validated and bound too, so
//! user input never reaches the SQL text.

use crate::model::Severity;
use anyhow::{Result, anyhow, bail};
use rusqlite::types::Value as Sql;

/// What the query runs over, which decides how meta fields map to columns.
/// Process names from imported Procmon captures (see procmon.rs).
const MODIFIED_BY: &str = "modified_by";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Rows of `results r` joined to `blobs b` (the compare side, or base if deleted).
    Results,
    /// Rows of `objects o` joined to `blobs b`.
    Objects,
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    Num(f64),
    Op(&'static str),
    LParen,
    RParen,
}

fn tokenize(s: &str) -> Result<Vec<Tok>> {
    let mut out = Vec::new();
    let mut chars = s.char_indices().peekable();
    while let Some(&(i, c)) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else if c == '(' {
            chars.next();
            out.push(Tok::LParen);
        } else if c == ')' {
            chars.next();
            out.push(Tok::RParen);
        } else if c == '"' || c == '\'' {
            // No escapes: Windows paths and regexes are written as-is ("C:\Windows",
            // "\\Google\\"); to include a quote, delimit with the other kind.
            chars.next();
            let mut v = String::new();
            loop {
                match chars.next() {
                    None => bail!("unterminated string starting at column {}", i + 1),
                    Some((_, q)) if q == c => break,
                    Some((_, ch)) => v.push(ch),
                }
            }
            out.push(Tok::Str(v));
        } else if "=!<>~".contains(c) {
            chars.next();
            let next = chars.peek().map(|&(_, n)| n);
            let op = match (c, next) {
                ('=', Some('=')) => {
                    chars.next();
                    "="
                }
                ('!', Some('=')) => {
                    chars.next();
                    "!="
                }
                ('<', Some('=')) => {
                    chars.next();
                    "<="
                }
                ('>', Some('=')) => {
                    chars.next();
                    ">="
                }
                ('=', _) => "=",
                ('<', _) => "<",
                ('>', _) => ">",
                ('~', _) => "~",
                _ => bail!("unexpected '{c}' at column {}", i + 1),
            };
            out.push(Tok::Op(op));
        } else {
            let mut w = String::new();
            while let Some(&(_, ch)) = chars.peek() {
                if ch.is_whitespace() || "()=!<>~\"'".contains(ch) {
                    break;
                }
                w.push(ch);
                chars.next();
            }
            match w.parse::<f64>() {
                Ok(n)
                    if w.chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_digit() || c == '-') =>
                {
                    out.push(Tok::Num(n))
                }
                _ => out.push(Tok::Word(w)),
            }
        }
    }
    Ok(out)
}

#[derive(Debug, PartialEq)]
enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Cmp {
        field: String,
        op: &'static str,
        value: Tok,
    },
    Has {
        field: String,
        value: Tok,
    },
    Exists {
        field: String,
        present: bool,
    },
    Changed {
        field: String,
    },
    Truthy {
        field: String,
    },
    /// Bare word or string: path contains it.
    Text(String),
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

fn is_kw(t: Option<&Tok>, kw: &str) -> bool {
    matches!(t, Some(Tok::Word(w)) if w.eq_ignore_ascii_case(kw))
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn or(&mut self) -> Result<Expr> {
        let mut e = self.and()?;
        while is_kw(self.peek(), "or") {
            self.next();
            e = Expr::Or(Box::new(e), Box::new(self.and()?));
        }
        Ok(e)
    }

    fn and(&mut self) -> Result<Expr> {
        let mut e = self.not()?;
        loop {
            if is_kw(self.peek(), "and") {
                self.next();
            } else if self.peek().is_none()
                || matches!(self.peek(), Some(Tok::RParen))
                || is_kw(self.peek(), "or")
            {
                break;
            }
            // Adjacent terms are and-ed.
            e = Expr::And(Box::new(e), Box::new(self.not()?));
        }
        Ok(e)
    }

    fn not(&mut self) -> Result<Expr> {
        if is_kw(self.peek(), "not") {
            self.next();
            return Ok(Expr::Not(Box::new(self.not()?)));
        }
        self.atom()
    }

    fn value(&mut self) -> Result<Tok> {
        match self.next() {
            Some(t @ (Tok::Word(_) | Tok::Str(_) | Tok::Num(_))) => Ok(t),
            Some(t) => bail!("expected a value, found {t:?}"),
            None => bail!("expected a value at end of query"),
        }
    }

    fn atom(&mut self) -> Result<Expr> {
        match self.next() {
            Some(Tok::LParen) => {
                let e = self.or()?;
                match self.next() {
                    Some(Tok::RParen) => Ok(e),
                    _ => bail!("missing ')'"),
                }
            }
            Some(Tok::Str(s)) => Ok(Expr::Text(s)),
            Some(Tok::Num(n)) => Ok(Expr::Text(n.to_string())),
            Some(Tok::Word(w)) => {
                match self.peek() {
                    Some(Tok::Op(op)) => {
                        let op = *op;
                        self.next();
                        return Ok(Expr::Cmp {
                            field: w,
                            op,
                            value: self.value()?,
                        });
                    }
                    _ if is_kw(self.peek(), "has") => {
                        self.next();
                        return Ok(Expr::Has {
                            field: w,
                            value: self.value()?,
                        });
                    }
                    _ if is_kw(self.peek(), "exists") || is_kw(self.peek(), "missing") => {
                        let present = is_kw(self.peek(), "exists");
                        self.next();
                        return Ok(Expr::Exists { field: w, present });
                    }
                    _ if is_kw(self.peek(), "changed") => {
                        self.next();
                        return Ok(Expr::Changed { field: w });
                    }
                    _ => {}
                }
                // A bare word is a truthy test if it names a field (dotted path or known
                // flag); otherwise it is a path search.
                let looks_like_field = w.contains('.') || FLAG_FIELDS.contains(&w.as_str());
                Ok(if looks_like_field {
                    Expr::Truthy { field: w }
                } else {
                    Expr::Text(w)
                })
            }
            Some(t) => bail!("unexpected {t:?}"),
            None => bail!("unexpected end of query"),
        }
    }
}

/// Boolean fields a bare word refers to, rather than a path search.
const FLAG_FIELDS: &[&str] = &[
    // files
    "executable",
    "hidden",
    "system",
    "readonly",
    // services and drivers
    "unquoted_path",
    "delayed_start",
    "binary_missing",
    // firewall
    "enabled",
    "firewall_enabled",
    // COM
    "elevation",
    "shadows_machine",
    "server_missing",
    // users and groups
    "administrator",
    "password_required",
    "password_expires",
    "privileged",
    // certificates, ports, Wi-Fi
    "self_signed",
    "has_private_key",
    "dynamic",
    "hidden_network",
    "uses_802_1x",
    // tasks
    "script_host",
    // Defender
    "realtime_protection",
    "behavior_monitoring",
    "scan_downloads",
    "script_scanning",
    "disabled_by_policy",
    "tamper_protection",
    "cloud_protection",
    // user rights
    "sensitive",
    // security options
    "uac_enabled",
    "uac_secure_desktop",
    "remote_uac_filtering",
    "builtin_admin_approval",
    "wdigest_plaintext",
    "lsa_protection",
    "credential_guard",
    "lm_hash_stored",
    "restrict_anonymous",
    "restrict_anonymous_sam",
    "everyone_includes_anonymous",
    "smb1_server",
    "smb1_client",
    "smb_server_signing_required",
    "smb_client_signing_required",
    "smb_insecure_guest_logons",
    "remote_desktop",
    "rdp_nla",
    // TPM, keys
    "present",
    "activated",
    "owned",
    "secure_boot",
    "legacy",
    "exportable",
    "plaintext_exportable",
];

fn field_path(field: &str) -> Result<String> {
    if field.is_empty()
        || !field
            .split('.')
            .all(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
    {
        bail!("invalid field name '{field}'");
    }
    Ok(format!("$.{field}"))
}

fn tok_sql(t: &Tok) -> Sql {
    match t {
        Tok::Num(n) if n.fract() == 0.0 && n.abs() < 9e15 => Sql::Integer(*n as i64),
        Tok::Num(n) => Sql::Real(*n),
        Tok::Word(w) if w.eq_ignore_ascii_case("true") => Sql::Integer(1),
        Tok::Word(w) if w.eq_ignore_ascii_case("false") => Sql::Integer(0),
        Tok::Word(w) | Tok::Str(w) => Sql::Text(w.clone()),
        _ => Sql::Null,
    }
}

fn tok_text(t: &Tok) -> String {
    match t {
        Tok::Num(n) => n.to_string(),
        Tok::Word(w) | Tok::Str(w) => w.clone(),
        _ => String::new(),
    }
}

pub fn severity_rank(s: Severity) -> i64 {
    s as i64
}

/// A compiled query: a boolean SQL expression plus its parameters.
#[derive(Debug, Default)]
pub struct Compiled {
    pub sql: String,
    pub params: Vec<Sql>,
    /// Whether the expression reads `b.data` (so the caller must join blobs).
    pub needs_body: bool,
}

struct Compiler {
    scope: Scope,
    params: Vec<Sql>,
    needs_body: bool,
}

impl Compiler {
    fn bind(&mut self, v: Sql) -> String {
        self.params.push(v);
        format!("?{}", self.params.len())
    }

    fn meta_column(&self, field: &str) -> Option<&'static str> {
        match (self.scope, field.to_ascii_lowercase().as_str()) {
            (Scope::Results, "path" | "identity") => Some("r.identity"),
            (Scope::Results, "kind") => Some("r.kind"),
            (Scope::Results, "change") => Some("r.change"),
            (Scope::Results, "triage") => Some(crate::store::TRIAGE_STATUS_SQL),
            (Scope::Objects, "path" | "identity") => Some("o.identity"),
            (Scope::Objects, "kind") => Some("o.kind"),
            _ => None,
        }
    }

    /// SQL for an object field's value.
    fn json(&mut self, field: &str) -> Result<String> {
        self.needs_body = true;
        let p = self.bind(Sql::Text(field_path(field)?));
        Ok(format!("json_extract(b.data, {p})"))
    }

    fn compile(&mut self, e: &Expr) -> Result<String> {
        Ok(match e {
            Expr::And(a, b) => format!("({} AND {})", self.compile(a)?, self.compile(b)?),
            Expr::Or(a, b) => format!("({} OR {})", self.compile(a)?, self.compile(b)?),
            Expr::Not(a) => format!("(NOT COALESCE({}, 0))", self.compile(a)?),
            Expr::Text(s) => {
                let col = self.meta_column("path").unwrap();
                let p = self.bind(Sql::Text(s.to_lowercase()));
                format!("(instr(lower({col}), {p}) > 0)")
            }
            Expr::Truthy { field } => {
                let j = self.json(field)?;
                format!("(COALESCE({j}, 0) NOT IN (0, '', 'false'))")
            }
            Expr::Exists { field, present }
                if self.scope == Scope::Results && field.eq_ignore_ascii_case(MODIFIED_BY) =>
            {
                format!(
                    "({}EXISTS (SELECT 1 FROM attribution t WHERE t.comparison = r.comparison AND t.result = r.id))",
                    if *present { "" } else { "NOT " }
                )
            }
            Expr::Exists { field, present } => {
                let x = match self.meta_column(field) {
                    Some(c) => c.to_string(),
                    None => self.json(field)?,
                };
                format!("({x} IS {}NULL)", if *present { "NOT " } else { "" })
            }
            Expr::Changed { field } => {
                if self.scope != Scope::Results {
                    bail!("'changed' only applies to comparison results");
                }
                field_path(field)?;
                let exact = self.bind(Sql::Text(field.clone()));
                let prefix = self.bind(Sql::Text(format!("{field}.%")));
                format!(
                    "(EXISTS (SELECT 1 FROM json_each(r.diffs) d WHERE \
                     json_extract(d.value, '$.field') = {exact} OR json_extract(d.value, '$.field') LIKE {prefix}))"
                )
            }
            Expr::Has { field, value } => {
                let needle = tok_text(value).to_lowercase();
                if self.scope == Scope::Results && field.eq_ignore_ascii_case("rule") {
                    let p = self.bind(Sql::Text(needle));
                    return Ok(format!(
                        "(EXISTS (SELECT 1 FROM findings f WHERE f.comparison = r.comparison \
                         AND f.result = r.id AND instr(lower(f.rule), {p}) > 0))"
                    ));
                }
                if self.scope == Scope::Results && field.eq_ignore_ascii_case(MODIFIED_BY) {
                    let p = self.bind(Sql::Text(needle));
                    return Ok(format!(
                        "(EXISTS (SELECT 1 FROM attribution t WHERE t.comparison = r.comparison \
                         AND t.result = r.id AND instr(lower(t.process), {p}) > 0))"
                    ));
                }
                if let Some(c) = self.meta_column(field) {
                    let p = self.bind(Sql::Text(needle));
                    return Ok(format!("(instr(lower({c}), {p}) > 0)"));
                }
                self.needs_body = true;
                let path = self.bind(Sql::Text(field_path(field)?));
                let n = self.bind(Sql::Text(needle));
                format!(
                    "(CASE json_type(b.data, {path}) \
                       WHEN 'array' THEN EXISTS (SELECT 1 FROM json_each(b.data, {path}) e WHERE lower(e.value) = {n}) \
                       ELSE instr(lower(json_extract(b.data, {path})), {n}) > 0 END)"
                )
            }
            Expr::Cmp { field, op, value } => self.cmp(field, op, value)?,
        })
    }

    fn cmp(&mut self, field: &str, op: &str, value: &Tok) -> Result<String> {
        let lower = field.to_ascii_lowercase();
        if self.scope == Scope::Results && lower == "severity" {
            let sev: Severity = tok_text(value).parse()?;
            if op == "~" {
                bail!("'~' does not apply to severity");
            }
            let p = self.bind(Sql::Integer(severity_rank(sev)));
            return Ok(format!("(r.severity {op} {p})"));
        }
        if self.scope == Scope::Results && lower == MODIFIED_BY {
            let cond = match op {
                "=" | "!=" => {
                    let p = self.bind(Sql::Text(tok_text(value)));
                    format!("t.process = {p} COLLATE NOCASE")
                }
                "~" => {
                    let p = self.bind(Sql::Text(tok_text(value)));
                    format!("regexp({p}, t.process)")
                }
                _ => bail!("'{op}' does not apply to modified_by (use =, != or ~)"),
            };
            let exists = format!(
                "EXISTS (SELECT 1 FROM attribution t WHERE t.comparison = r.comparison AND t.result = r.id AND {cond})"
            );
            return Ok(if op == "!=" {
                format!("(NOT {exists})")
            } else {
                format!("({exists})")
            });
        }
        if self.scope == Scope::Results && lower == "rule" {
            let cond = match op {
                "=" | "!=" => {
                    let p = self.bind(Sql::Text(tok_text(value)));
                    format!("f.rule = {p} COLLATE NOCASE")
                }
                "~" => {
                    let p = self.bind(Sql::Text(tok_text(value)));
                    format!("regexp({p}, f.rule)")
                }
                _ => bail!("'{op}' does not apply to rule (use =, != or ~)"),
            };
            let exists = format!(
                "EXISTS (SELECT 1 FROM findings f WHERE f.comparison = r.comparison AND f.result = r.id AND {cond})"
            );
            return Ok(if op == "!=" {
                format!("(NOT {exists})")
            } else {
                format!("({exists})")
            });
        }

        let x = match self.meta_column(field) {
            Some(c) => c.to_string(),
            None => self.json(field)?,
        };
        Ok(match op {
            "~" => {
                let p = self.bind(Sql::Text(tok_text(value)));
                format!("(regexp({p}, {x}))")
            }
            "=" | "!=" => {
                let v = tok_sql(value);
                let is_text = matches!(v, Sql::Text(_));
                let p = self.bind(v);
                let eq = if is_text {
                    format!("{x} = {p} COLLATE NOCASE")
                } else {
                    format!("{x} = {p}")
                };
                if op == "=" {
                    format!("({eq})")
                } else {
                    format!("({x} IS NULL OR NOT ({eq}))")
                }
            }
            "<" | "<=" | ">" | ">=" => {
                let v = tok_sql(value);
                if !matches!(v, Sql::Integer(_) | Sql::Real(_)) {
                    bail!("'{op}' on '{field}' needs a number");
                }
                let p = self.bind(v);
                format!("({x} {op} {p})")
            }
            other => return Err(anyhow!("unsupported operator '{other}'")),
        })
    }
}

pub fn compile(query: &str, scope: Scope) -> Result<Compiled> {
    let toks = tokenize(query)?;
    if toks.is_empty() {
        return Ok(Compiled {
            sql: "1".into(),
            params: vec![],
            needs_body: false,
        });
    }
    let mut parser = Parser { toks, pos: 0 };
    let expr = parser.or()?;
    if parser.pos < parser.toks.len() {
        bail!("unexpected {:?}", parser.toks[parser.pos]);
    }
    let mut c = Compiler {
        scope,
        params: vec![],
        needs_body: false,
    };
    let sql = c.compile(&expr)?;
    Ok(Compiled {
        sql,
        params: c.params,
        needs_body: c.needs_body,
    })
}

/// Registers `regexp(pattern, text)` (case-insensitive) on a connection, caching the
/// compiled pattern per statement.
pub fn register_functions(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    use rusqlite::functions::FunctionFlags;
    conn.create_scalar_function(
        "regexp",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let re: std::sync::Arc<regex::Regex> = ctx.get_or_create_aux(0, |vr| {
                let pat = vr.as_str()?;
                regex::RegexBuilder::new(pat)
                    .case_insensitive(true)
                    .size_limit(1 << 20)
                    .build()
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            })?;
            let text = match ctx.get_raw(1) {
                rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                rusqlite::types::ValueRef::Integer(i) => i.to_string(),
                rusqlite::types::ValueRef::Real(f) => f.to_string(),
                _ => return Ok(false),
            };
            Ok(re.is_match(&text))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{Connection, params_from_iter};
    use serde_json::json;

    /// Runs a query over a tiny objects table and returns matching identities.
    fn run(q: &str) -> Result<Vec<String>> {
        let conn = Connection::open_in_memory()?;
        register_functions(&conn)?;
        conn.execute_batch(
            "CREATE TABLE blobs (id INTEGER PRIMARY KEY, data TEXT);
             CREATE TABLE objects (run INT, kind TEXT, identity TEXT, blob INT);",
        )?;
        let rows = [
            (
                r"C:\Program Files\Google\chrome.exe",
                json!({"format":"pe","executable":true,"pe":{"aslr":true},"signature":{"status":"valid","signer":"Google LLC"},"size":3000000}),
            ),
            (
                r"C:\Program Files\AsaTest\unsigned.exe",
                json!({"format":"pe","executable":true,"pe":{"aslr":false},"signature":{"status":"unsigned"},"writable_by":["Users"],"size":9000000}),
            ),
            (
                r"C:\Windows\notes.txt",
                json!({"executable":false,"size":10}),
            ),
        ];
        for (i, (path, data)) in rows.iter().enumerate() {
            conn.execute(
                "INSERT INTO blobs VALUES (?1, ?2)",
                rusqlite::params![i as i64, data.to_string()],
            )?;
            conn.execute(
                "INSERT INTO objects VALUES (1, 'file', ?1, ?2)",
                rusqlite::params![path, i as i64],
            )?;
        }
        let c = compile(q, Scope::Objects)?;
        let sql = format!(
            "SELECT o.identity FROM objects o JOIN blobs b ON b.id = o.blob WHERE {} ORDER BY o.identity",
            c.sql
        );
        let mut stmt = conn.prepare(&sql)?;
        let out = stmt
            .query_map(params_from_iter(c.params.iter()), |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(out
            .into_iter()
            .map(|p| p.rsplit('\\').next().unwrap().to_string())
            .collect())
    }

    #[test]
    fn queries() {
        assert_eq!(run("").unwrap().len(), 3);
        assert_eq!(run("chrome").unwrap(), vec!["chrome.exe"]);
        assert_eq!(
            run("signature.status = UNSIGNED").unwrap(),
            vec!["unsigned.exe"]
        );
        assert_eq!(
            run("not pe.aslr and executable").unwrap(),
            vec!["unsigned.exe"]
        );
        assert_eq!(run("writable_by has users").unwrap(), vec!["unsigned.exe"]);
        assert_eq!(
            run("signature.signer has google").unwrap(),
            vec!["chrome.exe"]
        );
        assert_eq!(
            run(r#"path ~ "\\program files\\""#).unwrap(),
            vec!["unsigned.exe", "chrome.exe"]
        );
        assert_eq!(
            run("size > 1000000 and not chrome").unwrap(),
            vec!["unsigned.exe"]
        );
        assert_eq!(run("signature missing").unwrap(), vec!["notes.txt"]);
        assert_eq!(
            run("signature.status != valid").unwrap(),
            vec!["unsigned.exe", "notes.txt"]
        );
        assert_eq!(
            run("(chrome or notes) and executable = false").unwrap(),
            vec!["notes.txt"]
        );
        assert_eq!(run("program files unsigned").unwrap(), vec!["unsigned.exe"]);
    }

    #[test]
    fn rejects_bad_queries_and_never_splices_input() {
        for bad in ["size >", "(chrome", "size > big", "a.b-c = 1", "x = 'open"] {
            assert!(run(bad).is_err(), "should reject: {bad}");
        }
        // Injection attempts are just values or invalid fields.
        assert!(
            run("path = \"x'); DROP TABLE objects; --\"")
                .unwrap()
                .is_empty()
        );
        assert!(run("x');DROP = 1").is_err());
        assert!(compile("signature.signer changed", Scope::Objects).is_err());
    }
}
