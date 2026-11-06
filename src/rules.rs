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

pub const DEFAULT_RULES: &str = include_str!("../rules/default.yaml");

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
                DEFAULT_RULES.to_string(),
                Self::parse(DEFAULT_RULES).context("in built-in default rules")?,
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
    pub fn lint(&self, known_fields: &HashMap<Kind, &[&str]>) -> Vec<String> {
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
        let known: HashMap<Kind, &[&str]> = HashMap::from([(Kind::File, &["path"][..])]);
        let w = rs.lint(&known);
        assert_eq!(w.len(), 2, "{w:?}");
    }

    #[test]
    fn default_rules_parse() {
        RuleSet::parse(DEFAULT_RULES).unwrap();
    }
}
