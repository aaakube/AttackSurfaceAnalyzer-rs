//! Streaming report writers. Changes arrive one at a time and are written (or, for
//! the table, ranked into a bounded top-N) immediately, so a diff with hundreds of
//! thousands of changes uses about as much memory as one with ten.

use crate::model::{Change, ChangeType, FieldDiff, Finding, Kind, Severity};
use crate::rules::RuleSet;
use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::io::Write;

/// Counters over *all* changes, including those below the display threshold.
#[derive(Default, Serialize)]
pub struct Stats {
    pub total: u64,
    pub reported: u64,
    pub max_severity: Option<Severity>,
    by_kind: BTreeMap<Kind, BTreeMap<ChangeType, u64>>,
    by_rule: BTreeMap<String, (Severity, u64)>,
}

impl Stats {
    pub fn record(&mut self, c: &Change) {
        self.total += 1;
        self.max_severity = self.max_severity.max(Some(c.severity));
        *self
            .by_kind
            .entry(c.kind)
            .or_default()
            .entry(c.change)
            .or_default() += 1;
        for f in &c.findings {
            self.by_rule
                .entry(f.rule.clone())
                .or_insert((f.severity, 0))
                .1 += 1;
        }
    }

    fn rules_by_severity(&self) -> Vec<(&String, Severity, u64)> {
        let mut v: Vec<_> = self.by_rule.iter().map(|(r, (s, n))| (r, *s, *n)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)).then(a.0.cmp(b.0)));
        v
    }
}

pub trait ReportWriter {
    fn change(&mut self, c: &Change) -> Result<()>;
    fn finish(self: Box<Self>, stats: &Stats) -> Result<()>;
}

pub struct Context<'a> {
    pub base: &'a str,
    pub compare: &'a str,
    pub rules: &'a RuleSet,
    pub min_severity: Severity,
    /// Include full object bodies for modified objects (diffs are always included).
    pub objects: bool,
}

/// What a change looks like in JSON output: modified objects carry only their
/// field diffs unless full objects were requested, halving report size.
#[derive(Serialize)]
struct ChangeView<'a> {
    kind: Kind,
    identity: &'a str,
    change: ChangeType,
    severity: Severity,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    findings: &'a [Finding],
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    diffs: &'a [FieldDiff],
    #[serde(skip_serializing_if = "Option::is_none")]
    base: Option<&'a Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compare: Option<&'a Value>,
}

fn view<'a>(c: &'a Change, objects: bool) -> ChangeView<'a> {
    let bodies = objects || c.change != ChangeType::Modified;
    ChangeView {
        kind: c.kind,
        identity: &c.identity,
        change: c.change,
        severity: c.severity,
        findings: &c.findings,
        diffs: &c.diffs,
        base: c.base.as_ref().filter(|_| bodies),
        compare: c.compare.as_ref().filter(|_| bodies),
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ------------------------------------------------------------------ JSON / JSONL

pub struct JsonWriter<W: Write> {
    out: W,
    objects: bool,
    first: bool,
}

impl<W: Write> JsonWriter<W> {
    pub fn new(mut out: W, ctx: &Context) -> Result<Self> {
        write!(
            out,
            r#"{{"base":{},"compare":{},"generated":{},"changes":["#,
            json!(ctx.base),
            json!(ctx.compare),
            json!(now())
        )?;
        Ok(JsonWriter {
            out,
            objects: ctx.objects,
            first: true,
        })
    }
}

impl<W: Write> ReportWriter for JsonWriter<W> {
    fn change(&mut self, c: &Change) -> Result<()> {
        if !self.first {
            self.out.write_all(b",")?;
        }
        self.first = false;
        self.out.write_all(b"\n")?;
        serde_json::to_writer(&mut self.out, &view(c, self.objects))?;
        Ok(())
    }

    fn finish(mut self: Box<Self>, stats: &Stats) -> Result<()> {
        write!(self.out, "\n],\"summary\":")?;
        serde_json::to_writer(&mut self.out, stats)?;
        writeln!(self.out, "}}")?;
        self.out.flush()?;
        Ok(())
    }
}

/// One change per line: friendliest format for very large diffs (grep, jq -c, ...).
pub struct JsonlWriter<W: Write> {
    out: W,
    objects: bool,
}

impl<W: Write> JsonlWriter<W> {
    pub fn new(out: W, ctx: &Context) -> Self {
        JsonlWriter {
            out,
            objects: ctx.objects,
        }
    }
}

impl<W: Write> ReportWriter for JsonlWriter<W> {
    fn change(&mut self, c: &Change) -> Result<()> {
        serde_json::to_writer(&mut self.out, &view(c, self.objects))?;
        self.out.write_all(b"\n")?;
        Ok(())
    }

    fn finish(mut self: Box<Self>, _: &Stats) -> Result<()> {
        self.out.flush()?;
        Ok(())
    }
}

// ------------------------------------------------------------------ SARIF

/// SARIF 2.1.0: one result per rule finding, so it plugs into code-scanning UIs.
pub struct SarifWriter<W: Write> {
    out: W,
    ids: HashMap<String, (String, usize)>,
    first: bool,
}

impl<W: Write> SarifWriter<W> {
    pub fn new(mut out: W, ctx: &Context) -> Result<Self> {
        let mut ids = HashMap::new();
        let driver_rules: Vec<Value> = ctx
            .rules
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let id = slug(&r.name);
                ids.insert(r.name.clone(), (id.clone(), i));
                let mut v = json!({
                    "id": id,
                    "name": r.name,
                    "shortDescription": { "text": r.name },
                    "defaultConfiguration": { "level": sarif_level(r.severity) },
                });
                if !r.description.is_empty() {
                    v["fullDescription"] = json!({ "text": r.description });
                }
                v
            })
            .collect();
        let tool = json!({ "driver": {
            "name": "asa",
            "version": env!("CARGO_PKG_VERSION"),
            "rules": driver_rules,
        }});
        let props = json!({ "baseRun": ctx.base, "compareRun": ctx.compare });
        write!(
            out,
            r#"{{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{{"tool":{tool},"properties":{props},"results":["#
        )?;
        Ok(SarifWriter {
            out,
            ids,
            first: true,
        })
    }
}

impl<W: Write> ReportWriter for SarifWriter<W> {
    fn change(&mut self, c: &Change) -> Result<()> {
        for f in &c.findings {
            let Some((id, index)) = self.ids.get(&f.rule) else {
                continue;
            };
            let mut location = json!({
                "logicalLocations": [{ "fullyQualifiedName": c.identity, "kind": c.kind.as_str() }]
            });
            if c.kind == Kind::File {
                location["physicalLocation"] =
                    json!({ "artifactLocation": { "uri": file_uri(&c.identity) } });
            }
            let result = json!({
                "ruleId": id,
                "ruleIndex": index,
                "level": sarif_level(f.severity),
                "message": { "text": format!("{} {} {}: {}", c.kind, c.identity, c.change, f.rule) },
                "locations": [location],
                "properties": { "changeType": c.change, "severity": f.severity },
            });
            if !self.first {
                self.out.write_all(b",")?;
            }
            self.first = false;
            self.out.write_all(b"\n")?;
            serde_json::to_writer(&mut self.out, &result)?;
        }
        Ok(())
    }

    fn finish(mut self: Box<Self>, _: &Stats) -> Result<()> {
        writeln!(self.out, "\n]}}]}}")?;
        self.out.flush()?;
        Ok(())
    }
}

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Debug | Severity::Info => "note",
        Severity::Warning => "warning",
        Severity::Error | Severity::Critical => "error",
    }
}

fn slug(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    s.trim_matches('-').to_string()
}

fn file_uri(path: &str) -> String {
    let p = path.replace('\\', "/");
    let encoded: String = p
        .chars()
        .map(|c| match c {
            ' ' => "%20".to_string(),
            '#' => "%23".to_string(),
            '?' => "%3F".to_string(),
            '%' => "%25".to_string(),
            c => c.to_string(),
        })
        .collect();
    if encoded.starts_with('/') {
        format!("file://{encoded}")
    } else {
        format!("file:///{encoded}")
    }
}

// ------------------------------------------------------------------ table

/// Human-readable summary. Only the `limit` most severe changes are listed; the
/// rest are counted, which keeps memory and terminal output bounded.
pub struct TableWriter<W: Write> {
    out: W,
    base: String,
    compare: String,
    min_severity: Severity,
    limit: usize,
    seq: u64,
    // Min-heap on (severity, earliest-first) so the least important entry is evicted.
    top: BinaryHeap<Reverse<(Severity, Reverse<u64>, String)>>,
}

impl<W: Write> TableWriter<W> {
    /// `limit == 0` lists every reported change.
    pub fn new(out: W, ctx: &Context, limit: usize) -> Self {
        TableWriter {
            out,
            base: ctx.base.into(),
            compare: ctx.compare.into(),
            min_severity: ctx.min_severity,
            limit,
            seq: 0,
            top: BinaryHeap::new(),
        }
    }

    fn render(c: &Change) -> String {
        let mut s = format!(
            "[{:<8}] {:<8} {}\n",
            c.severity.to_string().to_uppercase(),
            c.change,
            c.identity
        );
        for f in &c.findings {
            s += &format!("             ! {}\n", f.rule);
        }
        for d in c.diffs.iter().take(6) {
            s += &format!(
                "             ~ {}: {} -> {}\n",
                d.field,
                short(&d.before),
                short(&d.after)
            );
        }
        if c.diffs.len() > 6 {
            s += &format!("             ~ ... {} more fields\n", c.diffs.len() - 6);
        }
        s
    }
}

impl<W: Write> ReportWriter for TableWriter<W> {
    fn change(&mut self, c: &Change) -> Result<()> {
        self.seq += 1;
        let key = (c.severity, Reverse(self.seq));
        if self.limit == 0 || self.top.len() < self.limit {
            self.top.push(Reverse((key.0, key.1, Self::render(c))));
        } else if let Some(Reverse(min)) = self.top.peek()
            && (key.0, key.1) > (min.0, min.1)
        {
            self.top.pop();
            self.top.push(Reverse((key.0, key.1, Self::render(c))));
        }
        Ok(())
    }

    fn finish(mut self: Box<Self>, stats: &Stats) -> Result<()> {
        let o = &mut self.out;
        writeln!(o, "Comparing {} -> {}\n", self.base, self.compare)?;
        writeln!(
            o,
            "{:<10} {:>10} {:>10} {:>10}",
            "KIND", "CREATED", "DELETED", "MODIFIED"
        )?;
        if stats.by_kind.is_empty() {
            writeln!(o, "(no differences)")?;
        }
        for (kind, counts) in &stats.by_kind {
            let n = |t| counts.get(&t).copied().unwrap_or(0);
            writeln!(
                o,
                "{:<10} {:>10} {:>10} {:>10}",
                kind.as_str(),
                n(ChangeType::Created),
                n(ChangeType::Deleted),
                n(ChangeType::Modified)
            )?;
        }

        let rules = stats.rules_by_severity();
        if !rules.is_empty() {
            writeln!(o, "\n{:<10} {:>8}  RULE", "SEVERITY", "COUNT")?;
            for (rule, sev, n) in rules {
                writeln!(o, "{:<10} {n:>8}  {rule}", sev.to_string())?;
            }
        }

        let listed = self.top.len() as u64;
        let entries = std::mem::take(&mut self.top).into_sorted_vec(); // ascending Reverse = most severe first
        if !entries.is_empty() {
            writeln!(o)?;
        }
        for Reverse((_, _, text)) in entries {
            write!(o, "{text}")?;
        }

        let below = stats.total - stats.reported;
        writeln!(o)?;
        if stats.reported > listed {
            writeln!(
                o,
                "listed the {listed} most severe of {} changes at '{}' or above \
                 (--limit 0 lists all; --format jsonl streams everything)",
                stats.reported, self.min_severity
            )?;
        }
        if below > 0 {
            writeln!(
                o,
                "{below} change(s) below '{}' not listed (see --min-severity)",
                self.min_severity
            )?;
        }
        o.flush()?;
        Ok(())
    }
}

fn short(v: &Value) -> String {
    let s = match v {
        Value::Null => "∅".to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    if s.chars().count() > 60 {
        format!("{}…", s.chars().take(59).collect::<String>())
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(i: u64, sev: Severity) -> Change {
        Change {
            kind: Kind::File,
            identity: format!(r"C:\f{i}"),
            change: ChangeType::Created,
            severity: sev,
            findings: vec![],
            diffs: vec![],
            base: None,
            compare: Some(json!({ "path": i })),
        }
    }

    fn ctx(rules: &RuleSet) -> Context<'_> {
        Context {
            base: "a",
            compare: "b",
            rules,
            min_severity: Severity::Info,
            objects: false,
        }
    }

    #[test]
    fn slugs_and_uris() {
        assert_eq!(slug("UPnP / SSDP port"), "upnp-ssdp-port");
        assert_eq!(
            file_uri("C:\\Program Files\\x"),
            "file:///C:/Program%20Files/x"
        );
    }

    #[test]
    fn table_keeps_most_severe_within_limit() {
        let rules = RuleSet::parse("rules: []").unwrap();
        let mut buf = Vec::new();
        let mut stats = Stats::default();
        {
            let mut w: Box<dyn ReportWriter> =
                Box::new(TableWriter::new(&mut buf, &ctx(&rules), 3));
            for i in 0..100_000u64 {
                let sev = if i % 25_000 == 7 {
                    Severity::Critical
                } else {
                    Severity::Info
                };
                let c = change(i, sev);
                stats.record(&c);
                stats.reported += 1;
                w.change(&c).unwrap();
            }
            w.finish(&stats).unwrap();
        }
        let text = String::from_utf8(buf).unwrap();
        assert_eq!(text.matches("[CRITICAL]").count(), 3, "{text}");
        assert!(text.contains("listed the 3 most severe of 100000 changes"));
        assert!(text.contains("100000"));
    }

    #[test]
    fn json_and_sarif_are_valid_documents() {
        let rules =
            RuleSet::parse("rules:\n  - { name: Any file, severity: warning, kinds: [file] }\n")
                .unwrap();
        for sarif in [false, true] {
            let mut buf = Vec::new();
            let mut stats = Stats::default();
            {
                let mut w: Box<dyn ReportWriter> = if sarif {
                    Box::new(SarifWriter::new(&mut buf, &ctx(&rules)).unwrap())
                } else {
                    Box::new(JsonWriter::new(&mut buf, &ctx(&rules)).unwrap())
                };
                for i in 0..3 {
                    let mut c = change(i, Severity::Warning);
                    c.findings = rules.evaluate(&c);
                    stats.record(&c);
                    w.change(&c).unwrap();
                }
                w.finish(&stats).unwrap();
            }
            let v: Value = serde_json::from_slice(&buf).unwrap();
            if sarif {
                assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 3);
                assert_eq!(v["runs"][0]["results"][0]["ruleId"], "any-file");
            } else {
                assert_eq!(v["changes"].as_array().unwrap().len(), 3);
                assert_eq!(v["summary"]["total"], 3);
            }
        }
    }

    #[test]
    fn modified_objects_are_slim_by_default() {
        let mut c = change(1, Severity::Info);
        c.change = ChangeType::Modified;
        c.base = Some(json!({"a": 1}));
        let slim = serde_json::to_value(view(&c, false)).unwrap();
        assert!(slim.get("base").is_none() && slim.get("compare").is_none());
        let full = serde_json::to_value(view(&c, true)).unwrap();
        assert!(full.get("base").is_some());
    }
}
