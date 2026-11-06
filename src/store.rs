//! SQLite storage.
//!
//! Objects are content-addressed: each distinct object body is stored once in
//! `blobs`, deduplicated by its hash, and a run is just a list of
//! `(kind, identity) -> blob` rows. Equal bodies share a blob id, so comparing
//! two runs is an integer comparison. Consecutive snapshots of a system are almost
//! identical, so every run after the first costs little more than its identities.

use crate::model::{ChangeType, Kind, Record};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, Statement, params};
use serde::Serialize;
use serde_json::Value;
use std::cmp::Ordering;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

/// Bump when the on-disk layout changes incompatibly.
const SCHEMA_VERSION: i64 = 3;

/// Rows are committed in batches of this size while a collection is streaming in.
const BATCH_SIZE: usize = 5_000;

/// Truncated BLAKE3; 128 bits is far beyond accidental collisions for snapshots.
const HASH_LEN: usize = 16;

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunInfo {
    #[serde(skip)]
    key: i64,
    pub id: String,
    pub created: String,
    pub platform: String,
    pub collectors: Vec<String>,
    pub complete: bool,
    pub objects: i64,
}

/// A raw difference between two runs, before field diffs and rules are applied.
pub struct RawChange {
    pub kind: Kind,
    pub identity: String,
    pub change: ChangeType,
    pub base: Option<Value>,
    pub compare: Option<Value>,
    pub base_blob: Option<i64>,
    pub compare_blob: Option<i64>,
}

/// Live counters of a comparison being computed, for progress reporting.
#[derive(Debug, Default)]
pub struct Progress {
    /// Rows of both runs consumed by the merge join so far.
    pub scanned: AtomicU64,
    /// Differences found so far.
    pub changes: AtomicU64,
}

/// A stored comparison of two runs (see [`Store::comparison`]).
#[derive(Debug, Clone, Serialize)]
pub struct ComparisonInfo {
    pub id: i64,
    pub base: String,
    pub compare: String,
    pub created: String,
    pub total: i64,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening database {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA cache_size = -65536;
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        )?;
        let version: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key = 'schema'", [], |r| {
                r.get(0)
            })
            .optional()?;
        match version {
            None => {
                conn.execute_batch(
                    "CREATE TABLE runs (
                         key        INTEGER PRIMARY KEY,
                         id         TEXT NOT NULL UNIQUE,
                         created    TEXT NOT NULL,
                         platform   TEXT NOT NULL,
                         collectors TEXT NOT NULL,
                         complete   INTEGER NOT NULL DEFAULT 0
                     );
                     -- Bodies live in a rowid table so the random-order hash lookups
                     -- only touch the narrow index, not the wide body pages.
                     CREATE TABLE blobs (
                         id   INTEGER PRIMARY KEY,
                         hash BLOB NOT NULL UNIQUE,
                         data TEXT NOT NULL
                     );
                     CREATE TABLE objects (
                         run      INTEGER NOT NULL REFERENCES runs(key) ON DELETE CASCADE,
                         kind     TEXT NOT NULL,
                         identity TEXT NOT NULL,
                         blob     INTEGER NOT NULL,
                         PRIMARY KEY (run, kind, identity)
                     ) WITHOUT ROWID;",
                )?;
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema', ?1)",
                    [SCHEMA_VERSION.to_string()],
                )?;
            }
            Some(v) if v == SCHEMA_VERSION.to_string() => {}
            Some(v) => bail!(
                "database {} uses schema version {v}, this build expects {SCHEMA_VERSION}; \
                 use a new database file",
                path.display()
            ),
        }
        // Materialized comparisons for the web UI. Additive, so no version bump: older
        // databases simply gain the tables.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS comparisons (
                 id         INTEGER PRIMARY KEY,
                 base       INTEGER NOT NULL REFERENCES runs(key) ON DELETE CASCADE,
                 compare    INTEGER NOT NULL REFERENCES runs(key) ON DELETE CASCADE,
                 rules_hash TEXT NOT NULL,
                 created    TEXT NOT NULL,
                 total      INTEGER NOT NULL DEFAULT 0,
                 complete   INTEGER NOT NULL DEFAULT 0,
                 UNIQUE (base, compare, rules_hash)
             );
             CREATE TABLE IF NOT EXISTS results (
                 comparison   INTEGER NOT NULL REFERENCES comparisons(id) ON DELETE CASCADE,
                 id           INTEGER NOT NULL,
                 kind         TEXT NOT NULL,
                 identity     TEXT NOT NULL,
                 change       TEXT NOT NULL,
                 severity     INTEGER NOT NULL,
                 base_blob    INTEGER,
                 compare_blob INTEGER,
                 diffs        TEXT NOT NULL,
                 PRIMARY KEY (comparison, id)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS results_by_severity
                 ON results (comparison, severity DESC, identity);
             CREATE TABLE IF NOT EXISTS findings (
                 comparison  INTEGER NOT NULL REFERENCES comparisons(id) ON DELETE CASCADE,
                 result      INTEGER NOT NULL,
                 rule        TEXT NOT NULL,
                 severity    INTEGER NOT NULL,
                 description TEXT NOT NULL,
                 PRIMARY KEY (comparison, result, rule)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS findings_by_rule ON findings (comparison, rule);",
        )?;
        crate::query::register_functions(&conn)?;
        Ok(Store { conn })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Returns the stored comparison of two runs under a rule set, computing and
    /// storing it first if needed. Every later filter, sort and count is then a plain
    /// indexed query instead of a re-diff.
    pub fn comparison(
        &mut self,
        base: &str,
        compare: &str,
        rules: &crate::rules::RuleSet,
        rules_hash: &str,
        progress: Option<&Progress>,
    ) -> Result<ComparisonInfo> {
        let (b, c) = (self.run(base)?, self.run(compare)?);
        let existing: Option<(i64, bool)> = self
            .conn
            .query_row(
                "SELECT id, complete FROM comparisons WHERE base = ?1 AND compare = ?2 AND rules_hash = ?3",
                params![b.key, c.key, rules_hash],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match existing {
            Some((id, true)) => return self.comparison_info(id),
            // Interrupted earlier: start over.
            Some((id, false)) => {
                self.conn
                    .execute("DELETE FROM comparisons WHERE id = ?1", [id])?;
            }
            None => {}
        }

        let kinds = |r: &RunInfo| -> std::collections::BTreeSet<String> {
            r.collectors.iter().cloned().collect()
        };
        let common: Vec<String> = kinds(&b).intersection(&kinds(&c)).cloned().collect();

        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO comparisons (base, compare, rules_hash, created) VALUES (?1, ?2, ?3, ?4)",
            params![
                b.key,
                c.key,
                rules_hash,
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            ],
        )?;
        let id = tx.last_insert_rowid();
        let mut total = 0i64;
        {
            let mut ins = tx.prepare(
                "INSERT INTO results (comparison, id, kind, identity, change, severity, base_blob, compare_blob, diffs)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            let mut fin = tx.prepare(
                "INSERT OR IGNORE INTO findings (comparison, result, rule, severity, description)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            self.diff_each_counted(&b.id, &c.id, progress.map(|p| &p.scanned), |raw| {
                // Same rule as `asa diff`: only kinds both runs collected.
                if !common
                    .iter()
                    .any(|col| crate::kinds_of(col).contains(&raw.kind))
                {
                    return Ok(());
                }
                let (bb, cb) = (raw.base_blob, raw.compare_blob);
                let ch = crate::diff::analyze(raw, rules);
                total += 1;
                if let Some(p) = progress {
                    p.changes.fetch_add(1, AtomicOrdering::Relaxed);
                }
                ins.execute(params![
                    id,
                    total,
                    ch.kind.as_str(),
                    ch.identity,
                    ch.change.to_string(),
                    crate::query::severity_rank(ch.severity),
                    bb,
                    cb,
                    serde_json::to_string(&ch.diffs)?,
                ])?;
                for f in &ch.findings {
                    fin.execute(params![
                        id,
                        total,
                        f.rule,
                        crate::query::severity_rank(f.severity),
                        f.description
                    ])?;
                }
                Ok(())
            })?;
        }
        tx.execute(
            "UPDATE comparisons SET total = ?2, complete = 1 WHERE id = ?1",
            params![id, total],
        )?;
        tx.commit()?;
        self.comparison_info(id)
    }

    pub fn comparison_info(&self, id: i64) -> Result<ComparisonInfo> {
        Ok(self.conn.query_row(
            "SELECT c.id, b.id, k.id, c.created, c.total FROM comparisons c
             JOIN runs b ON b.key = c.base JOIN runs k ON k.key = c.compare WHERE c.id = ?1",
            [id],
            |r| {
                Ok(ComparisonInfo {
                    id: r.get(0)?,
                    base: r.get(1)?,
                    compare: r.get(2)?,
                    created: r.get(3)?,
                    total: r.get(4)?,
                })
            },
        )?)
    }

    pub fn comparisons(&self) -> Result<Vec<ComparisonInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT c.id, b.id, k.id, c.created, c.total FROM comparisons c
             JOIN runs b ON b.key = c.base JOIN runs k ON k.key = c.compare
             WHERE c.complete = 1 ORDER BY c.id DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ComparisonInfo {
                id: r.get(0)?,
                base: r.get(1)?,
                compare: r.get(2)?,
                created: r.get(3)?,
                total: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Internal key of a run, for queries over its objects.
    pub fn run_key(&self, id: &str) -> Result<i64> {
        Ok(self.run(id)?.key)
    }

    pub fn begin_run(&self, id: &str) -> Result<()> {
        if self.find_run(id)?.is_some() {
            bail!("a run with id '{id}' already exists (delete it with `asa runs delete {id}`)");
        }
        self.conn.execute(
            "INSERT INTO runs (id, created, platform, collectors) VALUES (?1, ?2, ?3, '[]')",
            params![
                id,
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                std::env::consts::OS,
            ],
        )?;
        Ok(())
    }

    /// Marks the run complete, recording which collectors actually succeeded.
    pub fn finish_run(&self, id: &str, collectors: &[String]) -> Result<()> {
        self.conn.execute(
            "UPDATE runs SET complete = 1, collectors = ?2 WHERE id = ?1",
            params![id, serde_json::to_string(collectors)?],
        )?;
        Ok(())
    }

    /// Drains `records` into the run, committing in batches so memory stays flat no
    /// matter how many objects a collector produces. Returns (inserted, duplicates).
    pub fn ingest(
        &mut self,
        run_id: &str,
        records: impl IntoIterator<Item = Record>,
    ) -> Result<(u64, u64)> {
        let run = self.run(run_id)?.key;
        let (mut inserted, mut duplicates) = (0u64, 0u64);
        let mut records = records.into_iter().peekable();
        while records.peek().is_some() {
            let tx = self.conn.transaction()?;
            {
                let mut find_blob = tx.prepare_cached("SELECT id FROM blobs WHERE hash = ?1")?;
                let mut add_blob =
                    tx.prepare_cached("INSERT INTO blobs (hash, data) VALUES (?1, ?2)")?;
                let mut drop_blob = tx.prepare_cached("DELETE FROM blobs WHERE id = ?1")?;
                let mut obj = tx.prepare_cached(
                    "INSERT OR IGNORE INTO objects (run, kind, identity, blob)
                     VALUES (?1, ?2, ?3, ?4)",
                )?;
                for rec in records.by_ref().take(BATCH_SIZE) {
                    // serde_json's default map is ordered, so this encoding is canonical
                    // and the hash is stable across runs.
                    let data = serde_json::to_string(&rec.data)?;
                    let full = blake3::hash(data.as_bytes());
                    let hash = &full.as_bytes()[..HASH_LEN];
                    let (blob, fresh) =
                        match find_blob.query_row([hash], |r| r.get(0)).optional()? {
                            Some(id) => (id, false),
                            None => {
                                add_blob.execute(params![hash, data])?;
                                (tx.last_insert_rowid(), true)
                            }
                        };
                    if obj.execute(params![run, rec.kind.as_str(), rec.identity, blob])? == 1 {
                        inserted += 1;
                    } else {
                        // Identity already present in this run; don't leave its body behind.
                        if fresh {
                            drop_blob.execute([blob])?;
                        }
                        duplicates += 1;
                    }
                }
            }
            tx.commit()?;
        }
        Ok((inserted, duplicates))
    }

    pub fn runs(&self) -> Result<Vec<RunInfo>> {
        self.query_runs("1")
    }

    fn find_run(&self, id: &str) -> Result<Option<RunInfo>> {
        let mut stmt = self.conn.prepare("SELECT key FROM runs WHERE id = ?1")?;
        let key: Option<i64> = stmt.query_row([id], |r| r.get(0)).optional()?;
        Ok(match key {
            Some(k) => self.query_runs(&format!("r.key = {k}"))?.pop(),
            None => None,
        })
    }

    fn query_runs(&self, filter: &str) -> Result<Vec<RunInfo>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT r.key, r.id, r.created, r.platform, r.collectors, r.complete,
                    (SELECT COUNT(*) FROM objects o WHERE o.run = r.key)
             FROM runs r WHERE {filter} ORDER BY r.created, r.key"
        ))?;
        let rows = stmt.query_map([], |r| {
            let collectors: String = r.get(4)?;
            Ok(RunInfo {
                key: r.get(0)?,
                id: r.get(1)?,
                created: r.get(2)?,
                platform: r.get(3)?,
                collectors: serde_json::from_str(&collectors).unwrap_or_default(),
                complete: r.get(5)?,
                objects: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn run(&self, id: &str) -> Result<RunInfo> {
        self.find_run(id)?
            .ok_or_else(|| anyhow::anyhow!("no run with id '{id}' (see `asa runs list`)"))
    }

    /// Deletes a run and any object bodies no other run references.
    pub fn delete_run(&mut self, id: &str) -> Result<bool> {
        let tx = self.conn.transaction()?;
        if tx.execute("DELETE FROM runs WHERE id = ?1", [id])? == 0 {
            return Ok(false);
        }
        tx.execute(
            "DELETE FROM blobs WHERE id NOT IN (SELECT blob FROM objects)",
            [],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Streams every object of a run (optionally of one kind) to `f`.
    pub fn for_each_object(
        &self,
        run_id: &str,
        kind: Option<Kind>,
        mut f: impl FnMut(Kind, &str, &str) -> Result<()>,
    ) -> Result<()> {
        let run = self.run(run_id)?.key;
        let mut stmt = self.conn.prepare(
            "SELECT o.kind, o.identity, b.data FROM objects o JOIN blobs b ON b.id = o.blob
             WHERE o.run = ?1 AND (?2 IS NULL OR o.kind = ?2)
             ORDER BY o.kind, o.identity",
        )?;
        let mut rows = stmt.query(params![run, kind.map(Kind::as_str)])?;
        while let Some(row) = rows.next()? {
            let kind: String = row.get(0)?;
            f(
                kind.parse()?,
                &row.get::<_, String>(1)?,
                &row.get::<_, String>(2)?,
            )?;
        }
        Ok(())
    }

    /// Streams created/deleted/modified objects between two runs to `f`, using a
    /// single merge join over both runs' primary keys (already sorted by SQLite's
    /// BINARY collation, which matches Rust's byte-wise string order). Only blob ids
    /// are compared; bodies are loaded just for objects that differ, one change at a
    /// time, so memory does not grow with the number of changes.
    pub fn diff_each(
        &self,
        base: &str,
        compare: &str,
        f: impl FnMut(RawChange) -> Result<()>,
    ) -> Result<()> {
        self.diff_each_counted(base, compare, None, f)
    }

    /// [`Store::diff_each`], adding every row consumed from either run to `scanned`.
    pub fn diff_each_counted(
        &self,
        base: &str,
        compare: &str,
        scanned: Option<&AtomicU64>,
        mut f: impl FnMut(RawChange) -> Result<()>,
    ) -> Result<()> {
        let (base, compare) = (self.run(base)?.key, self.run(compare)?.key);
        let sql = "SELECT kind, identity, blob FROM objects WHERE run = ?1 ORDER BY kind, identity";
        let mut load = self.conn.prepare("SELECT data FROM blobs WHERE id = ?1")?;
        let mut sb = self.conn.prepare(sql)?;
        let mut sc = self.conn.prepare(sql)?;
        let mut b = Cursor::new(&mut sb, base, scanned)?;
        let mut c = Cursor::new(&mut sc, compare, scanned)?;

        let mut body = |id: Option<i64>| -> Result<Option<Value>> {
            let Some(id) = id else { return Ok(None) };
            let text: String = load.query_row([id], |r| r.get(0))?;
            Ok(Some(serde_json::from_str(&text)?))
        };
        loop {
            let order = match (&b.row, &c.row) {
                (None, None) => break,
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (Some(x), Some(y)) => (&x.0, &x.1).cmp(&(&y.0, &y.1)),
            };
            let (kind, identity, hb, hc) = match order {
                Ordering::Less => {
                    let (k, i, h) = b.take()?;
                    (k, i, Some(h), None)
                }
                Ordering::Greater => {
                    let (k, i, h) = c.take()?;
                    (k, i, None, Some(h))
                }
                Ordering::Equal => {
                    let (k, i, hb) = b.take()?;
                    let (_, _, hc) = c.take()?;
                    if hb == hc {
                        continue;
                    }
                    (k, i, Some(hb), Some(hc))
                }
            };
            let change = match (hb, hc) {
                (Some(_), Some(_)) => ChangeType::Modified,
                (Some(_), None) => ChangeType::Deleted,
                _ => ChangeType::Created,
            };
            f(RawChange {
                kind: kind.parse()?,
                identity,
                change,
                base: body(hb)?,
                compare: body(hc)?,
                base_blob: hb,
                compare_blob: hc,
            })?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn diff(&self, base: &str, compare: &str) -> Result<Vec<RawChange>> {
        let mut out = Vec::new();
        self.diff_each(base, compare, |c| {
            out.push(c);
            Ok(())
        })?;
        Ok(out)
    }
}

/// One side of the merge join, holding the current row.
struct Cursor<'s, 'p> {
    rows: rusqlite::Rows<'s>,
    row: Option<(String, String, i64)>,
    scanned: Option<&'p AtomicU64>,
}

impl<'s, 'p> Cursor<'s, 'p> {
    fn new(stmt: &'s mut Statement<'_>, run: i64, scanned: Option<&'p AtomicU64>) -> Result<Self> {
        let mut c = Cursor {
            rows: stmt.query([run])?,
            row: None,
            scanned,
        };
        c.advance()?;
        Ok(c)
    }

    fn advance(&mut self) -> Result<()> {
        self.row = match self.rows.next()? {
            Some(r) => Some((r.get(0)?, r.get(1)?, r.get(2)?)),
            None => None,
        };
        Ok(())
    }

    fn take(&mut self) -> Result<(String, String, i64)> {
        let row = self
            .row
            .take()
            .expect("take() is only called on a current row");
        if let Some(s) = self.scanned {
            s.fetch_add(1, AtomicOrdering::Relaxed);
        }
        self.advance()?;
        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec(kind: Kind, id: &str, v: Value) -> Record {
        Record {
            kind,
            identity: id.into(),
            data: v,
        }
    }

    fn snapshot(store: &mut Store, id: &str, recs: Vec<Record>) {
        store.begin_run(id).unwrap();
        store.ingest(id, recs).unwrap();
        store.finish_run(id, &["files".into()]).unwrap();
    }

    #[test]
    fn diff_dedup_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open(&dir.path().join("t.db")).unwrap();
        snapshot(
            &mut s,
            "a",
            vec![
                rec(Kind::File, "/same", json!({"v": 1})),
                rec(Kind::File, "/gone", json!({"v": 2})),
                rec(Kind::File, "/edit", json!({"v": 3})),
                rec(Kind::File, "tcp/22", json!({"v": 1})),
            ],
        );
        snapshot(
            &mut s,
            "b",
            vec![
                rec(Kind::File, "/same", json!({"v": 1})),
                rec(Kind::File, "/edit", json!({"v": 4})),
                rec(Kind::File, "/new", json!({"v": 5})),
                rec(Kind::File, "tcp/22", json!({"v": 1})),
                rec(Kind::File, "tcp/22", json!({"v": 9})), // duplicate identity is ignored
            ],
        );

        let mut got: Vec<(String, ChangeType)> = s
            .diff("a", "b")
            .unwrap()
            .into_iter()
            .map(|c| (c.identity, c.change))
            .collect();
        got.sort_by(|x, y| x.0.cmp(&y.0));
        assert_eq!(
            got,
            vec![
                ("/edit".into(), ChangeType::Modified),
                ("/gone".into(), ChangeType::Deleted),
                ("/new".into(), ChangeType::Created),
            ]
        );
        assert!(s.diff("a", "a").unwrap().is_empty());

        // {"v":1} is shared by both runs, so 5 distinct bodies in total.
        let blobs = |s: &Store| -> i64 {
            s.conn
                .query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(blobs(&s), 5);
        assert!(s.delete_run("b").unwrap());
        assert_eq!(blobs(&s), 3, "bodies only referenced by b are collected");
        assert!(!s.delete_run("b").unwrap());
    }

    #[test]
    fn rejects_duplicate_run_ids() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("t.db")).unwrap();
        s.begin_run("x").unwrap();
        assert!(s.begin_run("x").is_err());
    }
}
