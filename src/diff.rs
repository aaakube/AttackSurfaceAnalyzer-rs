use crate::model::{Change, FieldDiff, Severity};
use crate::rules::RuleSet;
use crate::store::RawChange;
use serde_json::Value;

/// Leaf-level differences between two JSON objects, as dotted paths. Arrays are
/// compared as a whole: element-wise diffs of e.g. group member lists are noisier
/// than useful.
pub fn field_diffs(before: &Value, after: &Value) -> Vec<FieldDiff> {
    let mut out = Vec::new();
    walk("", before, after, &mut out);
    out
}

fn walk(prefix: &str, before: &Value, after: &Value, out: &mut Vec<FieldDiff>) {
    match (before, after) {
        (Value::Object(b), Value::Object(a)) => {
            let mut keys: Vec<&String> = b.keys().chain(a.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                let (bv, av) = (
                    b.get(k).unwrap_or(&Value::Null),
                    a.get(k).unwrap_or(&Value::Null),
                );
                walk(&path, bv, av, out);
            }
        }
        (b, a) if b != a => out.push(FieldDiff {
            field: prefix.to_string(),
            before: b.clone(),
            after: a.clone(),
        }),
        _ => {}
    }
}

/// Turns a raw change into an analyzed one: computes field diffs and applies rules.
pub fn analyze(r: RawChange, rules: &RuleSet) -> Change {
    let diffs = match (&r.base, &r.compare) {
        (Some(b), Some(c)) => field_diffs(b, c),
        _ => Vec::new(),
    };
    let mut change = Change {
        kind: r.kind,
        identity: r.identity,
        change: r.change,
        severity: Severity::Info,
        findings: Vec::new(),
        diffs,
        base: r.base,
        compare: r.compare,
    };
    change.findings = rules.evaluate(&change);
    change.severity = change
        .findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or_else(|| rules.default_severity(change.kind));
    change
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn diffs_nested_fields() {
        let d = field_diffs(
            &json!({"a": 1, "n": {"x": 1, "y": 2}, "gone": true}),
            &json!({"a": 1, "n": {"x": 5, "y": 2}, "new": "v"}),
        );
        let fields: Vec<&str> = d.iter().map(|d| d.field.as_str()).collect();
        assert_eq!(fields, vec!["gone", "n.x", "new"]);
        assert_eq!(d[1].before, json!(1));
        assert_eq!(d[1].after, json!(5));
    }
}
