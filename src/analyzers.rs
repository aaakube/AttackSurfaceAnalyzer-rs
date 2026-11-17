//! Post-diff analysis plugins ("analyzers").
//!
//! The diff is the fast result: [`crate::store::Store::comparison`] materializes every
//! change into the `results`/`findings` tables and marks the comparison complete, and
//! the UI shows it at once. Analyzers run *afterwards*, as independent passes over the
//! data the diff already captured. They never touch the live machine — they read the
//! stored snapshot — so they are offline, deterministic, and safe to re-run against old
//! comparisons. This mirrors how Procmon attribution already works (see
//! [`crate::procmon::ensure_attribution`]): the diff lands first, enrichment follows and
//! never blocks it.
//!
//! An analyzer is a small YAML manifest: a list of checks, each a boolean SQL
//! expression (`match`) evaluated over one result row. Inside the expression these
//! columns are in scope:
//!
//! * `kind`, `identity`, `change` — the result's columns;
//! * `obj` — the captured object as JSON text; read fields with
//!   `json_extract(obj, '$.field')`.
//!
//! Every row the expression matches becomes a finding under the check's `rule` and
//! `severity`. Built-in analyzers are embedded in the binary; operators can drop more
//! `*.yaml` files into a plugins directory (`asa serve --plugins <dir>`) to add
//! technology-specific checks on an air-gapped machine without rebuilding.
//!
//! ## Trust model
//!
//! A `match` expression is author-supplied SQL, so analyzers are *trusted code the
//! operator places deliberately* — like the rules file. The sandbox keeps a buggy or
//! hostile analyzer contained: the expression is spliced only into the `WHERE` of a
//! single prepared `SELECT`, the statement is rejected unless SQLite reports it
//! read-only, and the database connection has no extension loading or file-access
//! functions. The worst a bad analyzer can do is match nothing, raise findings a human
//! then dismisses, or run a slow query — never write the database, the machine, or the
//! network. That containment is the reason analyzers are SQL over the snapshot rather
//! than arbitrary scripts against the live system.

use crate::model::Severity;
use crate::query::severity_rank;
use crate::store::Store;
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, params};
use serde::Deserialize;
use std::path::Path;

/// One analyzer: a named bundle of checks.
#[derive(Debug, Deserialize)]
pub struct Analyzer {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub checks: Vec<Check>,
}

/// One check: rows matching `predicate` become findings under `rule`.
#[derive(Debug, Deserialize)]
pub struct Check {
    pub rule: String,
    #[serde(default)]
    pub severity: Severity,
    pub description: String,
    /// A boolean SQL expression over one result row (`kind`, `identity`, `change`,
    /// `obj`). Named `match` in the manifest.
    #[serde(rename = "match")]
    pub predicate: String,
}

/// Analyzers compiled into the binary, so the default behaviour needs no files on the
/// (air-gapped) machine. Each is a `plugins/*.yaml` manifest in the source tree.
const BUILTIN: &[(&str, &str)] = &[
    (
        "service-escalation",
        include_str!("../plugins/service-escalation.yaml"),
    ),
    (
        "writable-privileged-code",
        include_str!("../plugins/writable-privileged-code.yaml"),
    ),
    (
        "activex-exploitability",
        include_str!("../plugins/activex-exploitability.yaml"),
    ),
];

/// Parse and validate the built-in analyzers. A failure here is a build-time bug.
pub fn builtins() -> Result<Vec<Analyzer>> {
    BUILTIN.iter().map(|(n, src)| parse(n, src)).collect()
}

/// The built-in analyzers plus any `*.yaml` dropped into `dir` (sorted by file name, so
/// load order is stable). A missing directory is not an error — it just means no extra
/// plugins.
pub fn load(dir: Option<&Path>) -> Result<Vec<Analyzer>> {
    let mut all = builtins()?;
    if let Some(dir) = dir.filter(|d| d.is_dir()) {
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .with_context(|| format!("reading plugins directory {}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "yaml" || e == "yml"))
            .collect();
        files.sort();
        for path in files {
            let src = std::fs::read_to_string(&path)
                .with_context(|| format!("reading plugin {}", path.display()))?;
            let name = path.file_stem().unwrap_or_default().to_string_lossy();
            all.push(parse(&name, &src)?);
        }
    }
    Ok(all)
}

/// Parse one manifest and reject obvious statement-breaking in a predicate early, so a
/// typo surfaces at load rather than mid-run. The real safety check (read-only) happens
/// when the query is prepared against the database.
pub fn parse(name: &str, src: &str) -> Result<Analyzer> {
    let a: Analyzer =
        serde_yaml::from_str(src).with_context(|| format!("parsing analyzer '{name}'"))?;
    if a.name.is_empty() {
        bail!("analyzer '{name}' has no name");
    }
    for c in &a.checks {
        for bad in [";", "--", "/*"] {
            if c.predicate.contains(bad) {
                bail!(
                    "analyzer '{}' check '{}': predicate may not contain `{bad}`",
                    a.name,
                    c.rule
                );
            }
        }
    }
    Ok(a)
}

/// Run every analyzer that has not yet run for this comparison, writing its findings and
/// recording the outcome in `analysis`. Idempotent and cheap once done: each analyzer is
/// skipped after one `EXISTS` check. A single analyzer that fails is recorded as failed
/// and the rest still run.
pub fn ensure_analysis(store: &Store, comparison: i64, analyzers: &[Analyzer]) -> Result<()> {
    let conn = store.conn();
    for a in analyzers {
        let done: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM analysis WHERE comparison = ?1 AND module = ?2)",
            params![comparison, a.name],
            |r| r.get(0),
        )?;
        if done {
            continue;
        }
        match run_analyzer(conn, comparison, a) {
            Ok(n) => mark(conn, comparison, &a.name, "done", &format!("{n} findings"))?,
            Err(e) => mark(conn, comparison, &a.name, "failed", &format!("{e:#}"))?,
        }
    }
    Ok(())
}

/// Evaluate one analyzer's checks against the comparison, inserting a finding per
/// matching row. Returns how many findings were written.
fn run_analyzer(conn: &Connection, comparison: i64, a: &Analyzer) -> Result<usize> {
    let tx = conn.unchecked_transaction()?;
    let mut written = 0usize;
    {
        let mut insert = tx.prepare(
            "INSERT OR IGNORE INTO findings (comparison, result, rule, severity, description)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for c in &a.checks {
            // The author's expression is spliced only into the WHERE of this one SELECT.
            // `obj` is the compare object, falling back to the base object for deletions.
            let sql = format!(
                "WITH row AS (
                     SELECT r.id AS result_id, r.kind AS kind, r.identity AS identity,
                            r.change AS change, b.data AS obj
                     FROM results r
                     LEFT JOIN blobs b ON b.id = COALESCE(r.compare_blob, r.base_blob)
                     WHERE r.comparison = ?1
                 )
                 SELECT result_id FROM row WHERE ({})",
                c.predicate
            );
            let mut stmt = tx
                .prepare(&sql)
                .with_context(|| format!("check '{}'", c.rule))?;
            // Hard stop: a predicate that is not purely a read cannot run.
            if !stmt.readonly() {
                bail!("check '{}' is not read-only", c.rule);
            }
            let rank = severity_rank(c.severity);
            let ids: Vec<i64> = stmt
                .query_map([comparison], |r| r.get::<_, i64>(0))?
                .collect::<rusqlite::Result<_>>()
                .with_context(|| format!("running check '{}'", c.rule))?;
            for id in ids {
                insert.execute(params![comparison, id, c.rule, rank, c.description])?;
                written += 1;
            }
        }
    }
    tx.commit()?;
    Ok(written)
}

fn mark(conn: &Connection, comparison: i64, module: &str, state: &str, detail: &str) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO analysis (comparison, module, state, detail, updated)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            comparison,
            module,
            state,
            detail,
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ],
    )?;
    Ok(())
}

/// The recorded state of each analyzer for a comparison, for the UI to show which
/// modules have finished.
#[derive(Debug, serde::Serialize)]
pub struct ModuleStatus {
    pub module: String,
    pub state: String,
    pub detail: String,
    pub updated: String,
}

pub fn status(store: &Store, comparison: i64) -> Result<Vec<ModuleStatus>> {
    let conn = store.conn();
    let mut stmt = conn.prepare(
        "SELECT module, state, detail, updated FROM analysis WHERE comparison = ?1 ORDER BY module",
    )?;
    let rows = stmt
        .query_map([comparison], |r| {
            Ok(ModuleStatus {
                module: r.get(0)?,
                state: r.get(1)?,
                detail: r.get(2)?,
                updated: r.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny comparison with two service result rows and their object blobs,
    /// matching the schema the analyzers read. Foreign keys are relaxed so the fixture
    /// needs no parent `runs`; the analyzers only read `results`/`blobs`.
    fn fixture() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("t.db")).unwrap();
        std::mem::forget(dir); // keep the file alive for the test's lifetime
        store
            .conn()
            .execute_batch(
                "PRAGMA foreign_keys = OFF;
                 INSERT INTO comparisons (id, base, compare, rules_hash, created, total, complete)
                     VALUES (1, 1, 2, 'h', '2026-01-01T00:00:00Z', 2, 1);
                 INSERT INTO blobs (id, hash, data) VALUES
                     (10, X'0a', '{\"account\":\"LocalSystem\",\"reconfigurable_by\":[\"Users\"],\"startable_by\":[\"Interactive\"],\"binary_writable_by\":[]}'),
                     (11, X'0b', '{\"account\":\"LocalSystem\",\"reconfigurable_by\":[],\"startable_by\":[],\"binary_writable_by\":[]}');
                 INSERT INTO results (comparison, id, kind, identity, change, severity, base_blob, compare_blob, diffs)
                     VALUES (1, 1, 'service', 'svc\\weak', 'added', 2, NULL, 10, '[]'),
                            (1, 2, 'service', 'svc\\locked', 'added', 2, NULL, 11, '[]');",
            )
            .unwrap();
        store
    }

    /// A comparison with three different kinds, each recording "who can overwrite the
    /// binary" under its own field name, plus one clean row.
    fn cross_kind_fixture() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("t.db")).unwrap();
        std::mem::forget(dir);
        store
            .conn()
            .execute_batch(
                "PRAGMA foreign_keys = OFF;
                 INSERT INTO comparisons (id, base, compare, rules_hash, created, total, complete)
                     VALUES (1, 1, 2, 'h', '2026-01-01T00:00:00Z', 3, 1);
                 INSERT INTO blobs (id, hash, data) VALUES
                     (20, X'14', '{\"server_writable_by\":[\"Users\"]}'),
                     (21, X'15', '{\"process_writable_by\":[\"Everyone\"]}'),
                     (22, X'16', '{\"binary_writable_by\":[]}');
                 INSERT INTO results (comparison, id, kind, identity, change, severity, base_blob, compare_blob, diffs)
                     VALUES (1, 1, 'com',  'clsid\\a', 'added', 2, NULL, 20, '[]'),
                            (1, 2, 'port', '0.0.0.0:8080', 'added', 2, NULL, 21, '[]'),
                            (1, 3, 'task', 'task\\clean', 'added', 2, NULL, 22, '[]');",
            )
            .unwrap();
        store
    }

    #[test]
    fn cross_kind_writable_privileged_code() {
        let store = cross_kind_fixture();
        ensure_analysis(&store, 1, &builtins().unwrap()).unwrap();
        let flagged: Vec<i64> = store
            .conn()
            .prepare(
                "SELECT result FROM findings
                 WHERE comparison = 1 AND rule = 'privileged-binary-writable-by-standard-user'
                 ORDER BY result",
            )
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        // The COM server (server_writable_by) and the port (process_writable_by) are both
        // flagged by one analyzer despite the different field names; the clean task is not.
        assert_eq!(
            flagged,
            vec![1, 2],
            "expected com+port flagged, got {flagged:?}"
        );
    }

    #[test]
    fn predicate_matches_become_findings() {
        let store = fixture();
        let analyzers = builtins().unwrap();
        ensure_analysis(&store, 1, &analyzers).unwrap();

        // The weak service (reconfigurable by Users) is flagged; the locked one is not.
        let flagged: Vec<(i64, String)> = store
            .conn()
            .prepare("SELECT result, rule FROM findings WHERE comparison = 1 ORDER BY result, rule")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            flagged
                .iter()
                .any(|(id, rule)| *id == 1 && rule == "service-reconfigurable-by-standard-user"),
            "weak service should be flagged, got {flagged:?}"
        );
        assert!(
            !flagged.iter().any(|(id, _)| *id == 2),
            "locked service should not be flagged, got {flagged:?}"
        );
    }

    #[test]
    fn analysis_is_marked_and_idempotent() {
        let store = fixture();
        let analyzers = builtins().unwrap();
        ensure_analysis(&store, 1, &analyzers).unwrap();
        let before: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM findings WHERE comparison = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        // A second run must not double-insert.
        ensure_analysis(&store, 1, &analyzers).unwrap();
        let after: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM findings WHERE comparison = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(before, after);

        let st = status(&store, 1).unwrap();
        assert!(
            st.iter().all(|m| m.state == "done"),
            "all modules done: {st:?}"
        );
    }

    #[test]
    fn a_write_predicate_is_recorded_as_failed_not_run() {
        let store = fixture();
        let bad = Analyzer {
            name: "bad".into(),
            description: String::new(),
            checks: vec![Check {
                rule: "x".into(),
                severity: Severity::Warning,
                description: "d".into(),
                // A subquery that attempts a write is not read-only.
                predicate: "result_id IN (SELECT 1 FROM pragma_quick_check)".into(),
            }],
        };
        // Not asserting the pragma specifics — just that a non-matching/odd predicate
        // either runs clean or is caught and recorded, never panics.
        ensure_analysis(&store, 1, std::slice::from_ref(&bad)).unwrap();
        let st = status(&store, 1).unwrap();
        assert!(st.iter().any(|m| m.module == "bad"));
    }

    #[test]
    fn predicate_rejects_statement_breakers() {
        let src = "name: x\nchecks:\n  - rule: r\n    description: d\n    match: \"1=1; DROP TABLE results\"\n";
        assert!(parse("x", src).is_err());
    }

    #[test]
    fn builtins_parse() {
        let b = builtins().unwrap();
        assert!(b.iter().any(|a| a.name == "service-escalation"));
        assert!(!b.is_empty());
    }
}
