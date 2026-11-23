//! Declarative YAML rules evaluated against changes.
//!
//! ```yaml
//! defaults:
//!   file: info
//! rules:
//!   - name: Unsigned executable
//!     severity: warning
//!     kinds: [file]
//!     changes: [created, modified]
//!     when:
//!       all:
//!         - { field: format, eq: pe }
//!         - not: { field: signature.status, eq: valid }
//! ```
//!
//! A condition is `all: [..]`, `any: [..]`, `not: {..}`, or a leaf
//! `{ field: <dotted.path>, <op>: <value> }` with exactly one operator.

use crate::model::{Change, ChangeType, Finding, Kind, Severity};
use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

pub const WINDOWS_RULES: &str = include_str!("../rules/default.yaml");
pub const LINUX_RULES: &str = include_str!("../rules/linux.yaml");

/// The built-in rules for the platform asa runs on: snapshots are compared on the
/// machine (or at least the platform) they were taken from.
pub fn builtin_rules() -> &'static str {
    if cfg!(target_os = "linux") {
        LINUX_RULES
    } else {
        WINDOWS_RULES
    }
}

/// Fields every change exposes in addition to the object's own fields.
const META_FIELDS: &[&str] = &["identity", "kind", "change"];

#[derive(Debug)]
pub struct RuleSet {
    pub defaults: HashMap<Kind, Severity>,
    pub rules: Vec<Rule>,
}

#[derive(Debug)]
pub struct Rule {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    /// Empty means every kind / change type / platform.
    pub kinds: Vec<Kind>,
    pub changes: Vec<ChangeType>,
    pub platforms: Vec<String>,
    pub when: Option<Cond>,
}

#[derive(Debug)]
pub enum Cond {
    All(Vec<Cond>),
    Any(Vec<Cond>),
    Not(Box<Cond>),
    Leaf { field: String, op: Op },
}

#[derive(Debug)]
pub enum Op {
    Eq(Value),
    Ne(Value),
    In(Vec<Value>),
    Lt(f64),
    Le(f64),
    Gt(f64),
    Ge(f64),
    /// Any of: substring of a string, element of an array, or key of an object.
    Contains(Vec<Value>),
    StartsWith(Vec<String>),
    EndsWith(Vec<String>),
    Regex(Vec<Regex>),
    Exists(bool),
    /// The field differs between base and compare (only true for modifications).
    Changed(bool),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default)]
    defaults: HashMap<Kind, Severity>,
    #[serde(default)]
    rules: Vec<RawRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    severity: Severity,
    #[serde(default)]
    kinds: Vec<Kind>,
    #[serde(default)]
    changes: Vec<ChangeType>,
    #[serde(default)]
    platforms: Vec<String>,
    when: Option<Value>,
}

impl RuleSet {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        Ok(Self::load_hashed(path)?.0)
    }

    /// Loads rules and returns a hash of their source, which identifies stored
    /// comparisons: editing the rules makes the web UI recompute.
    pub fn load_hashed(path: Option<&Path>) -> Result<(Self, String)> {
        let (text, rules) = match path {
            Some(p) => {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("reading rules file {}", p.display()))?;
                let rules =
                    Self::parse(&text).with_context(|| format!("in rules file {}", p.display()))?;
                (text, rules)
            }
            None => (
                builtin_rules().to_string(),
                Self::parse(builtin_rules()).context("in built-in default rules")?,
            ),
        };
        Ok((
            rules,
            blake3::hash(text.as_bytes()).to_hex()[..16].to_string(),
        ))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let raw: RawFile = serde_yaml::from_str(text)?;
        let rules = raw
            .rules
            .into_iter()
            .map(|r| {
                let when = r
                    .when
                    .as_ref()
                    .map(Cond::compile)
                    .transpose()
                    .with_context(|| format!("in rule '{}'", r.name))?;
                Ok(Rule {
                    name: r.name,
                    description: r.description,
                    severity: r.severity,
                    kinds: r.kinds,
                    changes: r.changes,
                    platforms: r.platforms,
                    when,
                })
            })
            .collect::<Result<_>>()?;
        Ok(RuleSet {
            defaults: raw.defaults,
            rules,
        })
    }

    pub fn default_severity(&self, kind: Kind) -> Severity {
        self.defaults.get(&kind).copied().unwrap_or(Severity::Info)
    }

    pub fn evaluate(&self, change: &Change) -> Vec<Finding> {
        let os = std::env::consts::OS;
        self.rules
            .iter()
            .filter(|r| r.kinds.is_empty() || r.kinds.contains(&change.kind))
            .filter(|r| r.changes.is_empty() || r.changes.contains(&change.change))
            .filter(|r| r.platforms.is_empty() || r.platforms.iter().any(|p| p == os))
            .filter(|r| r.when.as_ref().is_none_or(|c| c.eval(change)))
            .map(|r| Finding {
                rule: r.name.clone(),
                severity: r.severity,
                description: r.description.clone(),
            })
            .collect()
    }

    /// Static checks beyond parsing: unknown field names and suspicious regexes.
    /// `known_fields` maps each kind to the top-level fields its objects have.
    pub fn lint(&self, known_fields: &HashMap<Kind, Vec<&str>>) -> Vec<String> {
        let mut warnings = Vec::new();
        for rule in &self.rules {
            let Some(cond) = &rule.when else { continue };
            let kinds: Vec<Kind> = if rule.kinds.is_empty() {
                Kind::ALL.to_vec()
            } else {
                rule.kinds.clone()
            };
            cond.visit(&mut |field, op| {
                let top = field.split('.').next().unwrap_or(field);
                if !META_FIELDS.contains(&top)
                    && !kinds
                        .iter()
                        .any(|k| known_fields.get(k).is_some_and(|f| f.contains(&top)))
                {
                    warnings.push(format!(
                        "rule '{}': field '{field}' does not exist on {}",
                        rule.name,
                        kinds
                            .iter()
                            .map(|k| k.as_str())
                            .collect::<Vec<_>>()
                            .join("/")
                    ));
                }
                if let Op::Regex(res) = op {
                    for re in res {
                        let p = re.as_str();
                        if (p.ends_with('^') && !p.ends_with("\\^"))
                            || (p.starts_with('$') && p.len() > 1)
                        {
                            warnings.push(format!(
                                "rule '{}': regex '{p}' has a misplaced anchor and can never match",
                                rule.name
                            ));
                        }
                    }
                }
            });
        }
        warnings
    }
}

impl Cond {
    fn compile(v: &Value) -> Result<Cond> {
        let obj = v
            .as_object()
            .ok_or_else(|| anyhow!("condition must be a mapping, got {v}"))?;
        let list = |key: &str| -> Result<Vec<Cond>> {
            let items = obj[key]
                .as_array()
                .ok_or_else(|| anyhow!("'{key}' expects a list"))?;
            if items.is_empty() {
                bail!("'{key}' must not be empty");
            }
            items.iter().map(Cond::compile).collect()
        };
        if obj.contains_key("all") || obj.contains_key("any") || obj.contains_key("not") {
            if obj.len() != 1 {
                bail!("'all', 'any' and 'not' must be the only key of their condition");
            }
            return Ok(if obj.contains_key("all") {
                Cond::All(list("all")?)
            } else if obj.contains_key("any") {
                Cond::Any(list("any")?)
            } else {
                Cond::Not(Box::new(Cond::compile(&obj["not"])?))
            });
        }

        let field = obj
            .get("field")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("condition needs 'field' (or all/any/not): {v}"))?
            .to_string();
        let ops: Vec<(&String, &Value)> = obj.iter().filter(|(k, _)| *k != "field").collect();
        let [(name, arg)] = ops.as_slice() else {
            bail!(
                "condition on '{field}' must have exactly one operator, got {}",
                ops.len()
            );
        };
        let num = || {
            arg.as_f64()
                .ok_or_else(|| anyhow!("'{name}' on '{field}' expects a number"))
        };
        let strings = || -> Result<Vec<String>> {
            one_or_many(arg)
                .into_iter()
                .map(|s| {
                    s.as_str()
                        .map(String::from)
                        .ok_or_else(|| anyhow!("'{name}' on '{field}' expects strings"))
                })
                .collect()
        };
        let boolean = || {
            arg.as_bool()
                .ok_or_else(|| anyhow!("'{name}' on '{field}' expects true or false"))
        };
        let op = match name.as_str() {
            "eq" => Op::Eq((*arg).clone()),
            "ne" => Op::Ne((*arg).clone()),
            "in" => Op::In(one_or_many(arg)),
            "lt" => Op::Lt(num()?),
            "le" => Op::Le(num()?),
            "gt" => Op::Gt(num()?),
            "ge" => Op::Ge(num()?),
            "contains" => Op::Contains(one_or_many(arg)),
            "starts_with" => Op::StartsWith(strings()?),
            "ends_with" => Op::EndsWith(strings()?),
            "regex" => Op::Regex(
                strings()?
                    .iter()
                    .map(|p| Regex::new(p).with_context(|| format!("invalid regex on '{field}'")))
                    .collect::<Result<_>>()?,
            ),
            "exists" => Op::Exists(boolean()?),
            "changed" => Op::Changed(boolean()?),
            other => bail!("unknown operator '{other}' on '{field}'"),
        };
        Ok(Cond::Leaf { field, op })
    }

    fn visit(&self, f: &mut impl FnMut(&str, &Op)) {
        match self {
            Cond::All(cs) | Cond::Any(cs) => cs.iter().for_each(|c| c.visit(f)),
            Cond::Not(c) => c.visit(f),
            Cond::Leaf { field, op } => f(field, op),
        }
    }

    pub fn eval(&self, change: &Change) -> bool {
        match self {
            Cond::All(cs) => cs.iter().all(|c| c.eval(change)),
            Cond::Any(cs) => cs.iter().any(|c| c.eval(change)),
            Cond::Not(c) => !c.eval(change),
            Cond::Leaf { field, op } => eval_leaf(field, op, change),
        }
    }
}

fn one_or_many(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(items) => items.clone(),
        other => vec![other.clone()],
    }
}

fn resolve(field: &str, change: &Change) -> Option<Value> {
    match field {
        "identity" => return Some(Value::String(change.identity.clone())),
        "kind" => return Some(Value::String(change.kind.to_string())),
        "change" => return Some(Value::String(change.change.to_string())),
        _ => {}
    }
    let mut cur = change.subject();
    for seg in field.split('.') {
        cur = match cur {
            Value::Object(m) => m.get(seg)?,
            Value::Array(a) => a.get(seg.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    (!cur.is_null()).then(|| cur.clone())
}

fn as_number(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str()?.trim().parse().ok())
}

/// Equality that tolerates the string/number mismatch YAML authors inevitably hit
/// (`eq: "22"` vs a numeric port).
fn loose_eq(a: &Value, b: &Value) -> bool {
    a == b || matches!((as_number(a), as_number(b)), (Some(x), Some(y)) if x == y)
}

/// Strings in a value: itself if a string, its string elements if an array.
fn strings_of(v: &Value) -> Vec<&str> {
    match v {
        Value::String(s) => vec![s],
        Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    }
}

fn eval_leaf(field: &str, op: &Op, change: &Change) -> bool {
    if let Op::Changed(want) = op {
        let changed = change
            .diffs
            .iter()
            .any(|d| d.field == field || d.field.starts_with(&format!("{field}.")));
        return changed == *want;
    }
    let value = resolve(field, change);
    if let Op::Exists(want) = op {
        return value.is_some() == *want;
    }
    let Some(v) = value else {
        // A missing field never satisfies a comparison, but is trivially "not equal".
        return matches!(op, Op::Ne(_));
    };
    match op {
        Op::Eq(x) => loose_eq(&v, x),
        Op::Ne(x) => !loose_eq(&v, x),
        Op::In(xs) => xs.iter().any(|x| loose_eq(&v, x)),
        Op::Lt(x) => as_number(&v).is_some_and(|n| n < *x),
        Op::Le(x) => as_number(&v).is_some_and(|n| n <= *x),
        Op::Gt(x) => as_number(&v).is_some_and(|n| n > *x),
        Op::Ge(x) => as_number(&v).is_some_and(|n| n >= *x),
        Op::Contains(needles) => needles.iter().any(|n| match &v {
            Value::String(s) => n.as_str().is_some_and(|n| s.contains(n)),
            Value::Array(items) => items.iter().any(|i| loose_eq(i, n)),
            Value::Object(m) => n.as_str().is_some_and(|n| m.contains_key(n)),
            _ => false,
        }),
        Op::StartsWith(ps) => strings_of(&v)
            .iter()
            .any(|s| ps.iter().any(|p| s.starts_with(p))),
        Op::EndsWith(ps) => strings_of(&v)
            .iter()
            .any(|s| ps.iter().any(|p| s.ends_with(p))),
        Op::Regex(res) => strings_of(&v)
            .iter()
            .any(|s| res.iter().any(|r| r.is_match(s))),
        Op::Exists(_) | Op::Changed(_) => unreachable!("handled above"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::field_diffs;
    use serde_json::json;

    fn change(kind: Kind, ct: ChangeType, base: Option<Value>, compare: Option<Value>) -> Change {
        let diffs = match (&base, &compare) {
            (Some(b), Some(c)) => field_diffs(b, c),
            _ => vec![],
        };
        Change {
            kind,
            identity: "x".into(),
            change: ct,
            severity: Severity::Info,
            findings: vec![],
            diffs,
            base,
            compare,
        }
    }

    fn names(rs: &RuleSet, c: &Change) -> Vec<String> {
        rs.evaluate(c).into_iter().map(|f| f.rule).collect()
    }

    #[test]
    fn nested_conditions() {
        let rs = RuleSet::parse(
            r#"
rules:
  - name: public privileged port
    severity: warning
    kinds: [file]
    when:
      all:
        - { field: port, lt: 1024 }
        - not: { field: address, in: ["127.0.0.1", "::1"] }
"#,
        )
        .unwrap();
        let public = change(
            Kind::File,
            ChangeType::Created,
            None,
            Some(json!({"port": 22, "address": "0.0.0.0"})),
        );
        let local = change(
            Kind::File,
            ChangeType::Created,
            None,
            Some(json!({"port": 22, "address": "127.0.0.1"})),
        );
        let high = change(
            Kind::File,
            ChangeType::Created,
            None,
            Some(json!({"port": 8080, "address": "0.0.0.0"})),
        );
        assert_eq!(names(&rs, &public), vec!["public privileged port"]);
        assert!(names(&rs, &local).is_empty());
        assert!(names(&rs, &high).is_empty());
    }

    #[test]
    fn changed_operator_and_change_filter() {
        let rs = RuleSet::parse(
            "rules:\n  - name: shell changed\n    changes: [modified]\n    when: { field: shell, changed: true }\n",
        )
        .unwrap();
        let c = change(
            Kind::File,
            ChangeType::Modified,
            Some(json!({"shell": "/usr/sbin/nologin"})),
            Some(json!({"shell": "/bin/bash"})),
        );
        assert_eq!(names(&rs, &c), vec!["shell changed"]);
        let created = change(
            Kind::File,
            ChangeType::Created,
            None,
            Some(json!({"shell": "/bin/bash"})),
        );
        assert!(names(&rs, &created).is_empty());
    }

    #[test]
    fn deleted_objects_are_evaluated_on_base() {
        let rs =
            RuleSet::parse("rules:\n  - name: r\n    when: { field: setuid, eq: true }\n").unwrap();
        let c = change(
            Kind::File,
            ChangeType::Deleted,
            Some(json!({"setuid": true})),
            None,
        );
        assert_eq!(names(&rs, &c), vec!["r"]);
    }

    #[test]
    fn contains_regex_and_loose_eq() {
        let rs = RuleSet::parse(
            r#"
rules:
  - { name: arr, when: { field: groups, contains: sudo } }
  - { name: re, when: { field: path, regex: '^/usr/bin/(bash|sh)$' } }
  - { name: num, when: { field: port, eq: "22" } }
"#,
        )
        .unwrap();
        let c = change(
            Kind::File,
            ChangeType::Created,
            None,
            Some(json!({"groups": ["adm", "sudo"], "path": "/usr/bin/bash", "port": 22})),
        );
        assert_eq!(names(&rs, &c), vec!["arr", "re", "num"]);
    }

    #[test]
    fn rejects_bad_rules() {
        for bad in [
            "rules:\n  - name: r\n    when: { field: a }\n",
            "rules:\n  - name: r\n    when: { field: a, eq: 1, ne: 2 }\n",
            "rules:\n  - name: r\n    when: { field: a, regex: '(' }\n",
            "rules:\n  - name: r\n    when: { field: a, frobnicate: 1 }\n",
            "rules:\n  - name: r\n    when: { all: [] }\n",
            "rules:\n  - name: r\n    sevrity: warning\n",
        ] {
            assert!(RuleSet::parse(bad).is_err(), "should reject: {bad}");
        }
    }

    #[test]
    fn lint_catches_typos_and_dead_regexes() {
        let rs = RuleSet::parse(
            "rules:\n  - name: r\n    kinds: [file]\n    when:\n      any:\n        - { field: PATH, eq: x }\n        - { field: path, regex: '/bash^' }\n",
        )
        .unwrap();
        let known: HashMap<Kind, Vec<&str>> = HashMap::from([(Kind::File, vec!["path"])]);
        let w = rs.lint(&known);
        assert_eq!(w.len(), 2, "{w:?}");
    }

    #[test]
    fn default_rules_parse() {
        RuleSet::parse(WINDOWS_RULES).unwrap();
        RuleSet::parse(LINUX_RULES).unwrap();
    }

    #[test]
    fn builtin_rule_files_lint_clean() {
        let known = crate::collectors::known_fields();
        for (name, text) in [("windows", WINDOWS_RULES), ("linux", LINUX_RULES)] {
            let w = RuleSet::parse(text).unwrap().lint(&known);
            assert!(w.is_empty(), "{name} rules: {w:?}");
        }
    }

    #[test]
    fn linux_rules() {
        let rs = RuleSet::parse(LINUX_RULES).unwrap();
        let has = |c: &Change, rule: &str| names(&rs, c).iter().any(|n| n == rule);
        let created = |kind, obj: Value| change(kind, ChangeType::Created, None, Some(obj));
        let modified = |kind, before: Value, after: Value| {
            change(kind, ChangeType::Modified, Some(before), Some(after))
        };

        // The three things Google Chrome's .deb adds.
        let sandbox = created(
            Kind::File,
            json!({"path": "/opt/google/chrome/chrome-sandbox", "file_type": "file", "owner": "root",
                   "mode": "4755", "setuid": true, "executable": true, "format": "elf"}),
        );
        assert!(has(&sandbox, "New setuid-root file"));
        assert!(!has(&sandbox, "Setuid or setgid file writable by non-root"));
        let cron = created(
            Kind::File,
            json!({"path": "/etc/cron.daily/google-chrome", "file_type": "symlink",
                   "target": "/opt/google/chrome/cron/google-chrome"}),
        );
        assert!(has(&cron, "Cron job added or changed"));
        let repo = created(
            Kind::File,
            json!({"path": "/etc/apt/sources.list.d/google-chrome.sources", "file_type": "file"}),
        );
        assert!(has(&repo, "Package repository added or changed"));

        // Churn is debug only; a placeholder is not a cron job.
        let dpkg = modified(
            Kind::File,
            json!({"path": "/var/lib/dpkg/status", "size": 1}),
            json!({"path": "/var/lib/dpkg/status", "size": 2}),
        );
        assert_eq!(names(&rs, &dpkg), ["Package manager and log churn"]);
        assert!(!has(
            &created(Kind::File, json!({"path": "/etc/cron.d/.placeholder"})),
            "Cron job added or changed"
        ));

        let writable_suid = modified(
            Kind::File,
            json!({"path": "/usr/local/bin/t", "setuid": false, "owner": "root", "mode": "0755", "executable": true}),
            json!({"path": "/usr/local/bin/t", "setuid": true, "owner": "root", "mode": "4777",
                   "executable": true, "writable_by": ["everyone"], "world_writable": true, "file_type": "file"}),
        );
        for r in [
            "New setuid-root file",
            "Setuid or setgid file writable by non-root",
            "Executable writable by non-root in a system location",
            "World-writable file in a system location",
            "Permissions changed",
        ] {
            assert!(has(&writable_suid, r), "{r}");
        }
        // A user's own script in their home is not a system-location finding.
        let home = created(
            Kind::File,
            json!({"path": "/home/a/bin/x", "executable": true, "writable_by": ["a"], "owner": "a"}),
        );
        assert!(names(&rs, &home).is_empty(), "{:?}", names(&rs, &home));
        let tmp_dir = created(
            Kind::File,
            json!({"path": "/usr/lib/app/plugins", "file_type": "dir", "writable_by": ["everyone"]}),
        );
        assert!(has(&tmp_dir, "Writable directory in a protected location"));
        let sticky = created(
            Kind::File,
            json!({"path": "/usr/lib/app/spool", "file_type": "dir", "writable_by": ["everyone"], "sticky": true}),
        );
        assert!(!has(&sticky, "Writable directory in a protected location"));

        let toor = created(
            Kind::User,
            json!({"name": "toor", "uid": 0, "password": "set", "administrator": true}),
        );
        assert!(has(&toor, "Additional uid 0 account"));
        assert!(has(&toor, "Account gained administrator rights"));
        let empty = created(
            Kind::User,
            json!({"name": "x", "uid": 1001, "password": "empty"}),
        );
        assert!(has(&empty, "Account with an empty password"));
        let weak = created(
            Kind::User,
            json!({"name": "y", "uid": 1002, "password": "set", "password_hash": "md5", "hash_in_passwd": true}),
        );
        assert!(has(&weak, "Weak password hash") && has(&weak, "Password hash in /etc/passwd"));

        let svc = modified(
            Kind::Service,
            json!({"name": "ssh.service", "commands": ["ExecStart=/usr/sbin/sshd -D"], "start": "enabled"}),
            json!({"name": "ssh.service", "commands": ["ExecStart=/usr/sbin/sshd -D", "ExecStartPost=/opt/x"],
                   "drop_ins": ["/etc/systemd/system/ssh.service.d/x.conf"], "start": "enabled",
                   "unit_writable_by": ["%adm"]}),
        );
        for r in [
            "Service commands changed",
            "Service drop-in added or changed",
            "Service unit writable by non-root",
        ] {
            assert!(has(&svc, r), "{r}");
        }

        let shell = created(
            Kind::Port,
            json!({"protocol": "tcp", "port": 4444, "scope": "any", "process_name": "nc.openbsd"}),
        );
        for r in [
            "Listening program is a shell or relay tool",
            "Listener on a commonly abused port",
            "New port listening on all interfaces",
        ] {
            assert!(has(&shell, r), "{r}");
        }
    }

    #[test]
    fn default_rules_for_url_handlers() {
        let rs = RuleSet::parse(WINDOWS_RULES).unwrap();
        let has = |c: &Change, rule: &str| names(&rs, c).iter().any(|n| n == rule);
        let handler = |obj: Value| change(Kind::Handler, ChangeType::Created, None, Some(obj));

        let hijackable = handler(json!({"scheme": "x", "writable_by": ["Users"]}));
        assert!(has(
            &hijackable,
            "URL protocol handler hijackable by non-admins"
        ));

        let writable_bin =
            handler(json!({"scheme": "x", "binary": r"C:\t.exe", "binary_writable_by": ["Users"]}));
        assert!(has(
            &writable_bin,
            "URL protocol handler binary writable by non-admins"
        ));

        let unsigned = handler(
            json!({"scheme": "x", "binary": r"C:\t.exe", "binary_signature": {"status": "unsigned"}}),
        );
        assert!(has(
            &unsigned,
            "URL protocol handler runs an unsigned binary"
        ));

        // A normal signed handler nobody can tamper with raises nothing.
        let clean = handler(
            json!({"scheme": "x", "binary": r"C:\t.exe", "binary_signature": {"status": "valid"}}),
        );
        assert!(names(&rs, &clean).is_empty());
    }

    #[test]
    fn default_rules_for_service_permissions() {
        let rs = RuleSet::parse(WINDOWS_RULES).unwrap();
        let has = |c: &Change, rule: &str| names(&rs, c).iter().any(|n| n == rule);

        // The LibreOfficeMaintenance case: SYSTEM service any user can start.
        let startable = change(
            Kind::Service,
            ChangeType::Created,
            None,
            Some(json!({"name": "Svc", "account": "LocalSystem", "startable_by": ["Interactive"]})),
        );
        assert!(has(
            &startable,
            "Privileged service startable by non-admins"
        ));
        assert!(!has(&startable, "Service reconfigurable by non-admins"));

        // A user-account service a user can start is not flagged.
        let user_svc = change(
            Kind::Service,
            ChangeType::Created,
            None,
            Some(json!({"name": "Svc", "account": r"NT Service\Foo", "startable_by": ["Users"]})),
        );
        assert!(!has(
            &user_svc,
            "Privileged service startable by non-admins"
        ));

        // Reconfigurable is always critical, regardless of account.
        let reconf = change(
            Kind::Service,
            ChangeType::Created,
            None,
            Some(
                json!({"name": "Svc", "account": "LocalSystem", "reconfigurable_by": ["Everyone"]}),
            ),
        );
        assert!(has(&reconf, "Service reconfigurable by non-admins"));
    }

    #[test]
    fn default_rules_for_tasks_defender_and_rights() {
        let rs = RuleSet::parse(WINDOWS_RULES).unwrap();
        let has = |c: &Change, rule: &str| names(&rs, c).iter().any(|n| n == rule);

        let task = change(
            Kind::Task,
            ChangeType::Created,
            None,
            Some(
                json!({"path": r"\Updater", "enabled": true, "hidden": true, "privileged": true,
                        "script_host": true, "arguments": "-nop -enc AAAA",
                        "binary_writable_by": ["Users"], "binary_signature": {"status": "unsigned"}}),
            ),
        );
        for r in [
            "Scheduled task runs a binary writable by non-admins",
            "Privileged scheduled task runs an unsigned binary",
            "Encoded or downloading command in scheduled task",
            "Scheduled task runs a script host",
            "Privileged scheduled task added",
            "Hidden scheduled task added",
        ] {
            assert!(has(&task, r), "{r}: {:?}", names(&rs, &task));
        }
        let ms = change(
            Kind::Task,
            ChangeType::Created,
            None,
            Some(
                json!({"path": r"\Microsoft\Windows\Defrag\X", "enabled": true, "script_host": true}),
            ),
        );
        assert!(!has(&ms, "Scheduled task runs a script host"));
        let gained = change(
            Kind::Task,
            ChangeType::Modified,
            Some(json!({"path": r"\T", "privileged": false})),
            Some(json!({"path": r"\T", "privileged": true})),
        );
        assert!(has(&gained, "Scheduled task gained privileges"));

        let ex = |cat: &str, value: &str, w: Value| {
            change(
                Kind::Defender,
                ChangeType::Created,
                None,
                Some(
                    json!({"type": "exclusion", "source": "local", "category": cat, "value": value, "writable_by": w}),
                ),
            )
        };
        assert!(has(
            &ex("path", r"C:\", Value::Null),
            "Broad Defender exclusion"
        ));
        assert!(has(
            &ex("path", r"C:\Users\bob\AppData\Local\x", Value::Null),
            "Broad Defender exclusion"
        ));
        assert!(has(
            &ex("extension", ".ps1", Value::Null),
            "Broad Defender exclusion"
        ));
        let narrow = ex("path", r"C:\Program Files\Vendor\db", Value::Null);
        assert!(!has(&narrow, "Broad Defender exclusion"));
        assert!(has(&narrow, "Defender exclusion added"));
        assert!(has(
            &ex("path", r"D:\build", json!(["Users"])),
            "Defender exclusion on a folder non-admins can write"
        ));
        let off = change(
            Kind::Defender,
            ChangeType::Modified,
            Some(
                json!({"type": "settings", "realtime_protection": true, "cloud_protection": true}),
            ),
            Some(
                json!({"type": "settings", "realtime_protection": false, "cloud_protection": false}),
            ),
        );
        assert!(has(&off, "Defender real-time protection turned off"));
        assert!(has(&off, "Defender protection weakened"));

        let right = change(
            Kind::Right,
            ChangeType::Modified,
            Some(json!({"name": "SeDebugPrivilege", "sensitive": true, "members": ["A"]})),
            Some(
                json!({"name": "SeDebugPrivilege", "sensitive": true, "members": ["A", "bob"],
                        "unexpected_members": ["bob"]}),
            ),
        );
        for r in [
            "Sensitive privilege granted to an unexpected account",
            "Sensitive user right assignment changed",
            "User right assignment changed",
        ] {
            assert!(has(&right, r), "{r}");
        }
    }

    #[test]
    fn default_rules_for_security_wmi_tpm_and_keys() {
        let rs = RuleSet::parse(WINDOWS_RULES).unwrap();
        let has = |c: &Change, rule: &str| names(&rs, c).iter().any(|n| n == rule);
        let modified = |kind, before: Value, after: Value| {
            change(kind, ChangeType::Modified, Some(before), Some(after))
        };

        let sec = modified(
            Kind::Security,
            json!({"uac_enabled": true, "wdigest_plaintext": false, "lm_compatibility_level": 5, "smb1_server": false, "rdp_nla": true, "lsa_protection": true}),
            json!({"uac_enabled": false, "wdigest_plaintext": true, "lm_compatibility_level": 1, "smb1_server": true, "rdp_nla": false, "lsa_protection": false}),
        );
        for r in [
            "UAC disabled",
            "WDigest stores clear-text passwords",
            "LM or NTLMv1 authentication allowed",
            "SMBv1 enabled",
            "Remote Desktop without Network Level Authentication",
            "LSA protection or Credential Guard turned off",
        ] {
            assert!(has(&sec, r), "{r}: {:?}", names(&rs, &sec));
        }
        // Hardening is not reported as weakening.
        let better = modified(
            Kind::Security,
            json!({"wdigest_plaintext": true}),
            json!({"wdigest_plaintext": false}),
        );
        assert!(names(&rs, &better).is_empty());

        let consumer = change(
            Kind::Wmi,
            ChangeType::Created,
            None,
            Some(
                json!({"type": "consumer", "class": "CommandLineEventConsumer", "binary_writable_by": ["Users"]}),
            ),
        );
        assert!(has(&consumer, "WMI consumer runs a command or script"));
        assert!(has(&consumer, "WMI consumer binary writable by non-admins"));
        let log = change(
            Kind::Wmi,
            ChangeType::Created,
            None,
            Some(json!({"type": "consumer", "class": "NTEventLogEventConsumer"})),
        );
        assert!(!has(&log, "WMI consumer runs a command or script"));
        let binding = change(
            Kind::Wmi,
            ChangeType::Created,
            None,
            Some(json!({"type": "binding"})),
        );
        assert!(has(&binding, "WMI event subscription added"));

        let tpm = modified(
            Kind::Tpm,
            json!({"present": true, "enabled": true, "owned": true, "secure_boot": true}),
            json!({"present": true, "enabled": false, "owned": false, "secure_boot": false}),
        );
        for r in [
            "Secure Boot turned off",
            "TPM disabled or removed",
            "TPM ownership changed",
        ] {
            assert!(has(&tpm, r), "{r}");
        }

        let key = change(
            Kind::Key,
            ChangeType::Created,
            None,
            Some(json!({"name": "k", "plaintext_exportable": true, "readable_by": ["Users"]})),
        );
        for r in [
            "Private key readable by non-admins",
            "Private key exportable in plain text",
            "Machine key added",
        ] {
            assert!(has(&key, r), "{r}");
        }
    }
}
