//! `asa serve`: a local web UI over the database.
//!
//! Comparisons are materialized once (see `Store::comparison`); every list, count,
//! facet and export after that is an indexed SQL query, so result sets of hundreds of
//! thousands of items page and filter instantly. The page itself is one static file.

use crate::query::{self, Scope};
use crate::rules::RuleSet;
use crate::store::Store;
use anyhow::{Context, Result, anyhow};
use rusqlite::params_from_iter;
use rusqlite::types::Value as Sql;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

const INDEX_HTML: &str = include_str!("../web/index.html");
const MAX_PAGE: i64 = 500;

struct Job {
    base: String,
    compare: String,
    /// Rows the merge join will consume: the objects of both runs.
    total: u64,
    started: Instant,
    progress: Arc<crate::store::Progress>,
}

/// Clears the published job when the computation ends, even on error.
struct JobGuard<'a>(&'a Mutex<Option<Job>>);
impl Drop for JobGuard<'_> {
    fn drop(&mut self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

struct App {
    db: PathBuf,
    rules: RuleSet,
    rules_hash: String,
    /// Host header values we accept (defends against DNS rebinding).
    hosts: Vec<String>,
    /// Serializes comparison computation so two clicks don't compute it twice.
    computing: Mutex<()>,
    /// The comparison being computed right now, for `/api/progress`.
    job: Mutex<Option<Job>>,
    /// Serializes linking results to Procmon captures (see procmon.rs).
    attributing: Mutex<()>,
}

pub fn serve(
    db: PathBuf,
    rules_path: Option<PathBuf>,
    listen: &str,
    open_browser: bool,
) -> Result<()> {
    let (rules, rules_hash) = RuleSet::load_hashed(rules_path.as_deref())?;
    Store::open(&db)?; // fail fast on a bad database
    let server = Server::http(listen).map_err(|e| anyhow!("listening on {listen}: {e}"))?;
    let addr = server.server_addr().to_ip().context("server address")?;
    let port = addr.port();
    let mut hosts = vec![
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ];
    if !addr.ip().is_loopback() {
        eprintln!("warning: serving on {addr}, reachable from the network, without authentication");
        hosts.push(addr.to_string());
    }
    let url = format!("http://127.0.0.1:{port}/");
    eprintln!(
        "asa web UI on {url}  (database {}, Ctrl+C to stop)",
        db.display()
    );
    if open_browser {
        // `start` hands the URL to the default browser; the empty argument is the
        // window title `start` would otherwise take from the URL.
        let launched = if cfg!(windows) {
            std::process::Command::new("cmd")
                .args(["/C", "start", "", &url])
                .spawn()
        } else {
            std::process::Command::new("xdg-open").arg(&url).spawn()
        };
        if let Err(e) = launched {
            eprintln!("could not open a browser ({e}); open {url} manually");
        }
    }
    let app = Arc::new(App {
        db,
        rules,
        rules_hash,
        hosts,
        computing: Mutex::new(()),
        attributing: Mutex::new(()),
        job: Mutex::new(None),
    });
    for req in server.incoming_requests() {
        let app = Arc::clone(&app);
        std::thread::spawn(move || handle(&app, req));
    }
    Ok(())
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header")
}

fn json_response(status: u16, v: &Value) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(serde_json::to_vec(v).unwrap_or_default())
        .with_status_code(StatusCode(status))
        .with_header(header("Content-Type", "application/json; charset=utf-8"))
        .with_header(header("Cache-Control", "no-store"))
}

/// Errors the user can fix (bad query, unknown run) vs. server faults.
enum ApiError {
    Bad(anyhow::Error),
    NotFound(String),
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Internal(e)
    }
}
impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        ApiError::Internal(e.into())
    }
}

fn bad(e: impl Into<anyhow::Error>) -> ApiError {
    ApiError::Bad(e.into())
}

fn handle(app: &App, req: Request) {
    let host = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Host"))
        .map(|h| h.value.as_str().to_ascii_lowercase());
    if !host.as_ref().is_some_and(|h| app.hosts.contains(h)) {
        let _ = req.respond(Response::from_string("forbidden host").with_status_code(403));
        return;
    }
    let url = req.url().to_string();
    let (path, qs) = url.split_once('?').unwrap_or((&url, ""));
    let params = parse_query(qs);
    let method = req.method().clone();
    if method == Method::Post {
        let header_of = |name: &'static str| {
            req.headers()
                .iter()
                .find(|h| h.field.equiv(name))
                .map(|h| h.value.as_str().to_ascii_lowercase())
        };
        let origin_ok = header_of("Origin").is_none_or(|o| {
            o.strip_prefix("http://")
                .is_some_and(|h| app.hosts.iter().any(|a| a == h))
        });
        if header_of("X-Asa").is_none() || !origin_ok {
            let _ = req
                .respond(Response::from_string("cross-site request refused").with_status_code(403));
            return;
        }
    }

    if path == "/export" && method == Method::Get {
        export(app, req, &params);
        return;
    }
    let result = match (&method, path) {
        (Method::Get, "/") => {
            let resp = Response::from_string(INDEX_HTML)
                .with_header(header("Content-Type", "text/html; charset=utf-8"))
                .with_header(header(
                    "Content-Security-Policy",
                    "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'",
                ));
            let _ = req.respond(resp);
            return;
        }
        (Method::Get, "/api/info") => info(app),
        (Method::Get, "/api/runs") => runs(app),
        (Method::Post, "/api/compare") => compare(app, &params),
        (Method::Get, "/api/progress") => Ok(progress(app)),
        (Method::Get, "/api/results") => results(app, &params),
        (Method::Get, "/api/facets") => facets(app, &params),
        (Method::Get, "/api/tree") => tree(app, &params),
        (Method::Post, "/api/triage") => set_triage(app, &params),
        (Method::Get, "/api/result") => result_detail(app, &params),
        (Method::Get, "/api/objects") => objects(app, &params),
        (Method::Get, "/api/object") => object_detail(app, &params),
        _ => Err(ApiError::NotFound(format!("{method} {path}"))),
    };
    let resp = match result {
        Ok(v) => json_response(200, &v),
        Err(ApiError::Bad(e)) => json_response(400, &json!({ "error": format!("{e:#}") })),
        Err(ApiError::NotFound(what)) => {
            json_response(404, &json!({ "error": format!("not found: {what}") }))
        }
        Err(ApiError::Internal(e)) => {
            eprintln!("error handling {path}: {e:#}");
            json_response(500, &json!({ "error": format!("{e:#}") }))
        }
    };
    let _ = req.respond(resp);
}

fn parse_query(qs: &str) -> HashMap<String, String> {
    qs.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        out.push(v);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn get<'a>(p: &'a HashMap<String, String>, k: &str) -> Result<&'a str, ApiError> {
    p.get(k)
        .map(String::as_str)
        .ok_or_else(|| bad(anyhow!("missing parameter '{k}'")))
}

fn get_i64(p: &HashMap<String, String>, k: &str, default: i64) -> Result<i64, ApiError> {
    match p.get(k) {
        None => Ok(default),
        Some(v) => v
            .parse()
            .map_err(|_| bad(anyhow!("'{k}' must be a number"))),
    }
}

fn open(app: &App) -> Result<Store, ApiError> {
    Ok(Store::open(&app.db)?)
}

fn info(app: &App) -> Result<Value, ApiError> {
    Ok(json!({
        "db": app.db.display().to_string(),
        "version": env!("CARGO_PKG_VERSION"),
        "rules": app.rules.rules.len(),
        "captures": crate::procmon::captures(&open(app)?)?,
    }))
}

fn runs(app: &App) -> Result<Value, ApiError> {
    let store = open(app)?;
    Ok(json!({ "runs": store.runs()?, "comparisons": store.comparisons()? }))
}

fn compare(app: &App, p: &HashMap<String, String>) -> Result<Value, ApiError> {
    let (base, compare) = (get(p, "base")?, get(p, "compare")?);
    if base == compare {
        return Err(bad(anyhow!("pick two different runs")));
    }
    let _guard = app.computing.lock().unwrap_or_else(|e| e.into_inner());
    let mut store = open(app)?;
    let b = store.run(base).map_err(bad)?;
    let c = store.run(compare).map_err(bad)?;
    let progress = Arc::new(crate::store::Progress::default());
    *app.job.lock().unwrap_or_else(|e| e.into_inner()) = Some(Job {
        base: b.id.clone(),
        compare: c.id.clone(),
        total: (b.objects + c.objects).max(0) as u64,
        started: Instant::now(),
        progress: Arc::clone(&progress),
    });
    let _job = JobGuard(&app.job);
    let t = Instant::now();
    let info = store.comparison(base, compare, &app.rules, &app.rules_hash, Some(&progress))?;
    Ok(json!({ "comparison": info, "ms": t.elapsed().as_millis() }))
}

fn progress(app: &App) -> Value {
    use std::sync::atomic::Ordering::Relaxed;
    match &*app.job.lock().unwrap_or_else(|e| e.into_inner()) {
        None => json!({ "running": false }),
        Some(j) => json!({
            "running": true,
            "base": j.base,
            "compare": j.compare,
            "scanned": j.progress.scanned.load(Relaxed),
            "total": j.total,
            "changes": j.progress.changes.load(Relaxed),
            "elapsed_ms": j.started.elapsed().as_millis(),
        }),
    }
}

/// FROM/WHERE shared by result listing, counting, facets and export.
struct ResultFilter {
    from: String,
    filter: String,
    params: Vec<Sql>,
}

fn result_filter(app: &App, p: &HashMap<String, String>) -> Result<ResultFilter, ApiError> {
    let c = get_i64(p, "c", -1)?;
    {
        // `modified_by` and the process facet read the attribution of this comparison.
        let _guard = app.attributing.lock().unwrap_or_else(|e| e.into_inner());
        crate::procmon::ensure_attribution(&open(app)?, c)?;
    }
    let q = p.get("q").map(String::as_str).unwrap_or("");
    let compiled = query::compile(q, Scope::Results).map_err(bad)?;
    let mut params = compiled.params;
    params.push(Sql::Integer(c));
    // Accepted changes are hidden unless asked for, or unless the query is about triage.
    let hide = p.get("hide_accepted").is_some_and(|v| v == "1")
        && !q.to_ascii_lowercase().contains("triage");
    let hidden = if hide {
        format!(
            " AND COALESCE({}, '') != 'accepted'",
            crate::store::TRIAGE_STATUS_SQL
        )
    } else {
        String::new()
    };
    let from = if compiled.needs_body {
        "results r JOIN blobs b ON b.id = COALESCE(r.compare_blob, r.base_blob)".to_string()
    } else {
        "results r".to_string()
    };
    Ok(ResultFilter {
        from,
        filter: format!(
            "r.comparison = ?{} AND ({}){hidden}",
            params.len(),
            compiled.sql
        ),
        params,
    })
}

fn order_by(p: &HashMap<String, String>) -> &'static str {
    match p.get("sort").map(String::as_str) {
        Some("path") => "r.identity",
        Some("change") => "r.change, r.severity DESC, r.identity",
        _ => "r.severity DESC, r.identity",
    }
}

fn severity_name(rank: i64) -> &'static str {
    ["debug", "info", "warning", "error", "critical"]
        .get(rank as usize)
        .copied()
        .unwrap_or("info")
}

fn results(app: &App, p: &HashMap<String, String>) -> Result<Value, ApiError> {
    let t = Instant::now();
    let store = open(app)?;
    let f = result_filter(app, p)?;
    let limit = get_i64(p, "limit", 100)?.clamp(1, MAX_PAGE);
    let offset = get_i64(p, "offset", 0)?.max(0);
    let conn = store.conn();
    let total: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {} WHERE {}", f.from, f.filter),
            params_from_iter(f.params.iter()),
            |r| r.get(0),
        )
        .map_err(|e| bad(anyhow!("query failed: {e}")))?;
    let mut params = f.params.clone();
    params.push(Sql::Integer(limit));
    params.push(Sql::Integer(offset));
    let n = params.len();
    let sql = format!(
        "SELECT r.id, r.identity, r.kind, r.change, r.severity,
                (SELECT json_group_array(f.rule) FROM
                    (SELECT rule FROM findings f WHERE f.comparison = r.comparison AND f.result = r.id
                     ORDER BY severity DESC, rule) f),
                (SELECT json_group_array(t.process) FROM attribution t
                  WHERE t.comparison = r.comparison AND t.result = r.id),
                {}
         FROM {} WHERE {} ORDER BY {} LIMIT ?{} OFFSET ?{}",
        crate::store::TRIAGE_STATUS_SQL,
        f.from,
        f.filter,
        order_by(p),
        n - 1,
        n
    );
    let mut stmt = conn.prepare(&sql)?;
    let items: Vec<Value> = stmt
        .query_map(params_from_iter(params.iter()), |r| {
            let rules: String = r.get(5)?;
            let by: String = r.get(6)?;
            Ok(json!({
                "triage": r.get::<_, Option<String>>(7)?,
                "modified_by": serde_json::from_str::<Value>(&by).unwrap_or(json!([])),
                "id": r.get::<_, i64>(0)?,
                "identity": r.get::<_, String>(1)?,
                "kind": r.get::<_, String>(2)?,
                "change": r.get::<_, String>(3)?,
                "severity": severity_name(r.get(4)?),
                "rules": serde_json::from_str::<Value>(&rules).unwrap_or(json!([])),
            }))
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(json!({ "total": total, "offset": offset, "items": items, "ms": t.elapsed().as_millis() }))
}

fn facets(app: &App, p: &HashMap<String, String>) -> Result<Value, ApiError> {
    let store = open(app)?;
    let f = result_filter(app, p)?;
    let conn = store.conn();
    let group = |col: &str| -> Result<Vec<Value>, ApiError> {
        let mut stmt = conn.prepare(&format!(
            "SELECT {col}, COUNT(*) FROM {} WHERE {} GROUP BY 1 ORDER BY 1",
            f.from, f.filter
        ))?;
        let rows = stmt
            .query_map(params_from_iter(f.params.iter()), |r| {
                Ok((r.get::<_, rusqlite::types::Value>(0)?, r.get::<_, i64>(1)?))
            })
            .map_err(|e| bad(anyhow!("query failed: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let (k, n) = row?;
            let key = match k {
                Sql::Integer(i) if col == "r.severity" => json!(severity_name(i)),
                // Changes without a triage decision.
                Sql::Null => json!("new"),
                Sql::Text(s) => json!(s),
                other => json!(format!("{other:?}")),
            };
            out.push(json!([key, n]));
        }
        Ok(out)
    };
    let severity = group("r.severity")?;
    let triage = group(crate::store::TRIAGE_STATUS_SQL)?;
    let change = group("r.change")?;
    let kind = group("r.kind")?;
    let mut stmt = conn.prepare(&format!(
        "SELECT fr.rule, MAX(fr.severity), COUNT(*) FROM {} JOIN findings fr
           ON fr.comparison = r.comparison AND fr.result = r.id
         WHERE {} GROUP BY fr.rule ORDER BY 2 DESC, 3 DESC, 1",
        f.from, f.filter
    ))?;
    let rules: Vec<Value> = stmt
        .query_map(params_from_iter(f.params.iter()), |r| {
            Ok(json!([
                r.get::<_, String>(0)?,
                severity_name(r.get(1)?),
                r.get::<_, i64>(2)?
            ]))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut stmt = conn.prepare(&format!(
        "SELECT t.process, COUNT(*) FROM {} JOIN attribution t
           ON t.comparison = r.comparison AND t.result = r.id
         WHERE {} GROUP BY t.process ORDER BY 2 DESC, 1 LIMIT 30",
        f.from, f.filter
    ))?;
    let processes: Vec<Value> = stmt
        .query_map(params_from_iter(f.params.iter()), |r| {
            Ok(json!([r.get::<_, String>(0)?, r.get::<_, i64>(1)?]))
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(
        json!({ "severity": severity, "change": change, "kind": kind, "rules": rules,
               "processes": processes, "triage": triage }),
    )
}

/// One level of the matching results as a tree of their `\`-separated identities:
/// the children of `prefix` (empty for the top level) within `kind`, with counts,
/// so a folder of 100,000 changes is expanded one level at a time.
fn tree(app: &App, p: &HashMap<String, String>) -> Result<Value, ApiError> {
    let t = Instant::now();
    let store = open(app)?;
    let f = result_filter(app, p)?;
    let kind = get(p, "kind")?;
    let prefix = p.get("prefix").map(String::as_str).unwrap_or("");
    if !prefix.is_empty() && !prefix.ends_with('\\') {
        return Err(bad(anyhow!("prefix must end with a backslash")));
    }
    let limit = get_i64(p, "limit", MAX_PAGE)?.clamp(1, MAX_PAGE);
    let mut params = f.params.clone();
    params.push(Sql::Text(kind.to_string()));
    let k = params.len();
    params.push(Sql::Text(prefix.to_string()));
    let pre = params.len();
    let sql = format!(
        "WITH m AS (
           SELECT r.id, r.severity, r.change, substr(r.identity, length(?{pre}) + 1) AS rest
           FROM {from} WHERE {filter} AND r.kind = ?{k}
             AND substr(r.identity, 1, length(?{pre})) = ?{pre}),
         s AS (
           SELECT *, CASE instr(rest, '\\') WHEN 0 THEN rest
                     ELSE substr(rest, 1, instr(rest, '\\') - 1) END AS seg
           FROM m WHERE rest != '')
         SELECT seg, COUNT(*), MAX(severity),
                SUM(change = 'created'), SUM(change = 'modified'), SUM(change = 'deleted'),
                MAX(CASE WHEN instr(rest, '\\') = 0 THEN id END),
                SUM(instr(rest, '\\') > 0)
         FROM s GROUP BY seg ORDER BY 3 DESC, 2 DESC, seg",
        from = f.from,
        filter = f.filter,
    );
    let mut stmt = store.conn().prepare(&sql)?;
    let rows = stmt
        .query_map(params_from_iter(params.iter()), |r| {
            Ok(json!({
                "name": r.get::<_, String>(0)?,
                "count": r.get::<_, i64>(1)?,
                "severity": severity_name(r.get(2)?),
                "created": r.get::<_, i64>(3)?,
                "modified": r.get::<_, i64>(4)?,
                "deleted": r.get::<_, i64>(5)?,
                // The result at exactly prefix + name, if there is one.
                "id": r.get::<_, Option<i64>>(6)?,
                // Results below it, so the UI knows whether it expands.
                "below": r.get::<_, i64>(7)?,
            }))
        })
        .map_err(|e| bad(anyhow!("query failed: {e}")))?;
    let all: Vec<Value> = rows.collect::<rusqlite::Result<_>>()?;
    let more = all.len().saturating_sub(limit as usize);
    let children: Vec<Value> = all.into_iter().take(limit as usize).collect();
    Ok(
        json!({ "prefix": prefix, "children": children, "more": more,
               "ms": t.elapsed().as_millis() }),
    )
}

/// Marks result `id` of comparison `c` reviewed or accepted (with a note), or clears
/// its decision (`status=new`).
fn set_triage(app: &App, p: &HashMap<String, String>) -> Result<Value, ApiError> {
    let (c, id) = (get_i64(p, "c", -1)?, get_i64(p, "id", -1)?);
    let status = match get(p, "status")? {
        "new" => None,
        s => Some(s),
    };
    let note = p.get("note").map(String::as_str).unwrap_or("");
    if note.len() > 4000 {
        return Err(bad(anyhow!("note is too long (4000 bytes at most)")));
    }
    let store = open(app)?;
    let t = store.set_triage(c, id, status, note).map_err(bad)?;
    Ok(json!({ "triage": t }))
}

fn blob(store: &Store, id: Option<i64>) -> Result<Value, ApiError> {
    let Some(id) = id else { return Ok(Value::Null) };
    let text: String =
        store
            .conn()
            .query_row("SELECT data FROM blobs WHERE id = ?1", [id], |r| r.get(0))?;
    Ok(serde_json::from_str(&text).map_err(anyhow::Error::from)?)
}

fn result_detail(app: &App, p: &HashMap<String, String>) -> Result<Value, ApiError> {
    let store = open(app)?;
    let (c, id) = (get_i64(p, "c", -1)?, get_i64(p, "id", -1)?);
    let row = store
        .conn()
        .query_row(
            "SELECT identity, kind, change, severity, base_blob, compare_blob, diffs
             FROM results WHERE comparison = ?1 AND id = ?2",
            [c, id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, String>(6)?,
                ))
            },
        )
        .map_err(|_| ApiError::NotFound(format!("result {id}")))?;
    let mut stmt = store.conn().prepare(
        "SELECT rule, severity, description FROM findings WHERE comparison = ?1 AND result = ?2
         ORDER BY severity DESC, rule",
    )?;
    let findings: Vec<Value> = stmt
        .query_map([c, id], |r| {
            Ok(json!({
                "rule": r.get::<_, String>(0)?,
                "severity": severity_name(r.get(1)?),
                "description": r.get::<_, String>(2)?,
            }))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let activity = match row.1.parse::<crate::model::Kind>() {
        Ok(kind) => crate::procmon::events(&store, kind, &row.0)?,
        Err(_) => Vec::new(),
    };
    Ok(json!({
        "activity": activity,
        "id": id,
        "identity": row.0,
        "kind": row.1,
        "change": row.2,
        "severity": severity_name(row.3),
        "findings": findings,
        "triage": store.triage_of(c, id)?,
        "diffs": serde_json::from_str::<Value>(&row.6).unwrap_or(json!([])),
        "base": blob(&store, row.4)?,
        "compare": blob(&store, row.5)?,
    }))
}

fn objects(app: &App, p: &HashMap<String, String>) -> Result<Value, ApiError> {
    let t = Instant::now();
    let store = open(app)?;
    let run = store.run_key(get(p, "run")?).map_err(bad)?;
    let compiled = query::compile(p.get("q").map(String::as_str).unwrap_or(""), Scope::Objects)
        .map_err(bad)?;
    let limit = get_i64(p, "limit", 100)?.clamp(1, MAX_PAGE);
    let offset = get_i64(p, "offset", 0)?.max(0);
    let mut params = compiled.params;
    params.push(Sql::Integer(run));
    let where_ = format!("o.run = ?{} AND ({})", params.len(), compiled.sql);
    let from = "objects o JOIN blobs b ON b.id = o.blob";
    let conn = store.conn();
    let total: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {from} WHERE {where_}"),
            params_from_iter(params.iter()),
            |r| r.get(0),
        )
        .map_err(|e| bad(anyhow!("query failed: {e}")))?;
    params.push(Sql::Integer(limit));
    params.push(Sql::Integer(offset));
    let n = params.len();
    let mut stmt = conn.prepare(&format!(
        "SELECT o.identity, o.kind, b.data
         FROM {from} WHERE {where_} ORDER BY o.kind, o.identity LIMIT ?{} OFFSET ?{}",
        n - 1,
        n
    ))?;
    let items: Vec<Value> = stmt
        .query_map(params_from_iter(params.iter()), |r| {
            let kind: String = r.get(1)?;
            let data: Value = serde_json::from_str(&r.get::<_, String>(2)?).unwrap_or(Value::Null);
            Ok(json!({
                "identity": r.get::<_, String>(0)?,
                "summary": summary(&kind, &data),
                "kind": kind,
            }))
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(json!({ "total": total, "offset": offset, "items": items, "ms": t.elapsed().as_millis() }))
}

/// One line describing an object in the run browser, by kind.
fn summary(kind: &str, d: &Value) -> String {
    let s = |p: &str| -> Option<String> {
        let mut v = d;
        for seg in p.split('.') {
            v = v.get(seg)?;
        }
        match v {
            Value::Null => None,
            Value::String(x) => Some(x.clone()),
            Value::Array(a) if a.is_empty() => None,
            Value::Array(a) => Some(
                a.iter()
                    .map(|x| {
                        x.as_str()
                            .map(String::from)
                            .unwrap_or_else(|| x.to_string())
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            other => Some(other.to_string()),
        }
    };
    let flag =
        |p: &str, label: &str| (d.get(p) == Some(&Value::Bool(true))).then(|| label.to_string());
    let writable = |p: &str| s(p).map(|w| format!("writable by {w}"));
    let parts: Vec<Option<String>> = match kind {
        "file" => vec![
            s("file_type"),
            d.get("size").and_then(Value::as_u64).map(human_size),
            s("format"),
            s("signature.status"),
            writable("writable_by"),
        ],
        "service" | "driver" => vec![
            s("display_name").filter(|n| !n.starts_with('@')),
            s("start"),
            s("account"),
            s("binary_signature.status").map(|st| format!("binary {st}")),
            flag("unquoted_path", "unquoted path"),
            writable("binary_writable_by"),
            writable("key_writable_by").map(|w| format!("key {w}")),
        ],
        "firewall" if s("type").as_deref() == Some("profile") => vec![
            s("profile"),
            d.get("firewall_enabled")
                .and_then(Value::as_bool)
                .map(|e| if e { "on".into() } else { "OFF".into() }),
            s("default_inbound").map(|a| format!("inbound {a}")),
        ],
        "firewall" => vec![
            s("name").filter(|n| !n.starts_with('@')),
            Some(format!(
                "{} {}",
                s("direction").unwrap_or_default(),
                s("action").unwrap_or_default()
            )),
            s("protocol"),
            s("local_ports").map(|p| format!("port {p}")),
            s("program"),
            d.get("enabled")
                .and_then(Value::as_bool)
                .filter(|e| !e)
                .map(|_| "disabled".into()),
        ],
        "com" => vec![
            s("type"),
            s("name"),
            s("server"),
            flag("elevation", "elevation"),
            s("local_service").map(|x| format!("service {x}")),
            flag("shadows_machine", "SHADOWS MACHINE CLASS"),
            writable("server_writable_by"),
        ],
        "user" => vec![
            Some(if d.get("enabled") == Some(&Value::Bool(true)) {
                "enabled".into()
            } else {
                "disabled".into()
            }),
            flag("administrator", "ADMINISTRATOR"),
            s("privileged_groups").filter(|_| d.get("administrator") != Some(&Value::Bool(true))),
            (d.get("password_required") == Some(&Value::Bool(false)))
                .then(|| "no password required".to_string()),
            (d.get("password_expires") == Some(&Value::Bool(false)))
                .then(|| "password never expires".to_string()),
            s("builtin").map(|b| format!("built-in {b}")),
        ],
        "group" => vec![
            s("privilege").map(|p| format!("privileged ({p})")),
            d.get("members")
                .and_then(Value::as_array)
                .map(|m| format!("{} members", m.len())),
            s("members"),
        ],
        "certificate" => vec![
            s("subject"),
            s("issuer")
                .filter(|_| d.get("self_signed") != Some(&Value::Bool(true)))
                .map(|i| format!("issued by {i}")),
            Some(format!(
                "{}/{}",
                s("location").unwrap_or_default(),
                s("store").unwrap_or_default()
            )),
            d.get("not_after")
                .and_then(Value::as_i64)
                .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                .map(|t| format!("expires {}", t.format("%Y-%m-%d"))),
            flag("has_private_key", "private key"),
        ],
        "port" => vec![
            Some(s("process_name").unwrap_or_default()),
            s("services"),
            s("scope").map(|sc| match sc.as_str() {
                "any" => "ALL INTERFACES".into(),
                other => other.to_string(),
            }),
            s("process_signature.status").map(|st| format!("program {st}")),
            writable("process_writable_by"),
        ],
        "task" => vec![
            s("run_as").or_else(|| Some("registering user".into())),
            flag("privileged", "PRIVILEGED"),
            s("triggers").map(|t| format!("on {t}")),
            s("binary").or_else(|| s("com_handler").map(|c| format!("COM {c}"))),
            s("binary_signature.status").map(|st| format!("binary {st}")),
            (d.get("enabled") == Some(&Value::Bool(false))).then(|| "disabled".to_string()),
            flag("hidden", "hidden"),
            writable("binary_writable_by"),
        ],
        "defender" if s("type").as_deref() == Some("exclusion") => vec![
            Some(format!(
                "EXCLUSION ({} {})",
                s("source").unwrap_or_default(),
                s("category").unwrap_or_default()
            )),
            s("value"),
            writable("writable_by"),
        ],
        "defender" => {
            let off = |p: &str, label: &str| {
                (d.get(p) == Some(&Value::Bool(false))).then(|| format!("{label} OFF"))
            };
            vec![
                off("realtime_protection", "real-time protection"),
                off("behavior_monitoring", "behavior monitoring"),
                off("scan_downloads", "download scanning"),
                off("cloud_protection", "cloud protection"),
                off("tamper_protection", "tamper protection"),
                flag("disabled_by_policy", "DISABLED BY POLICY"),
                d.get("asr_rules")
                    .and_then(Value::as_object)
                    .map(|m| format!("{} ASR rules", m.len())),
            ]
        }
        "security" => {
            let weak = |p: &str, bad: bool, label: &str| {
                (d.get(p) == Some(&Value::Bool(bad))).then(|| label.to_string())
            };
            vec![
                weak("uac_enabled", false, "UAC OFF"),
                s("uac_admin_prompt")
                    .filter(|p| p == "elevate_without_prompt")
                    .map(|_| "elevates without prompt".into()),
                weak("remote_uac_filtering", false, "remote UAC filtering off"),
                weak("wdigest_plaintext", true, "WDIGEST PLAINTEXT"),
                weak("lsa_protection", true, "LSA protected"),
                weak("credential_guard", true, "Credential Guard"),
                d.get("lm_compatibility_level")
                    .and_then(Value::as_u64)
                    .map(|l| format!("LM level {l}")),
                weak("smb1_server", true, "SMBv1 server"),
                weak("smb1_client", true, "SMBv1 client"),
                weak("smb_insecure_guest_logons", true, "insecure SMB guest"),
                weak("remote_desktop", true, "RDP on"),
                weak("rdp_nla", false, "RDP without NLA"),
            ]
        }
        "wmi" => vec![
            s("type"),
            s("class"),
            s("query"),
            s("command_line").or_else(|| s("executable")),
            s("script_engine").map(|e| format!("{e} script")),
            s("target"),
            s("consumer").map(|c| format!("-> {c}")),
            writable("binary_writable_by"),
        ],
        "tpm" => vec![
            Some(if d.get("present") == Some(&Value::Bool(true)) {
                format!(
                    "TPM {} {}",
                    s("spec_version").unwrap_or_default(),
                    s("manufacturer").unwrap_or_default()
                )
            } else {
                "NO TPM".into()
            }),
            (d.get("enabled") == Some(&Value::Bool(false))).then(|| "DISABLED".to_string()),
            flag("owned", "owned"),
            d.get("secure_boot").and_then(Value::as_bool).map(|b| {
                if b {
                    "Secure Boot on".into()
                } else {
                    "SECURE BOOT OFF".into()
                }
            }),
        ],
        "key" => vec![
            s("provider"),
            Some(format!(
                "{} {}",
                s("algorithm").unwrap_or_default(),
                s("length").unwrap_or_default()
            )),
            flag("plaintext_exportable", "exportable in plain text"),
            s("readable_by").map(|r| format!("READABLE BY {r}")),
        ],
        "right" => vec![
            s("description"),
            flag("sensitive", "sensitive"),
            s("members").or_else(|| Some("nobody".into())),
            s("unexpected_members").map(|u| format!("UNEXPECTED: {u}")),
        ],
        "wifi" => vec![
            s("ssid"),
            Some(format!(
                "{} / {}",
                s("authentication").unwrap_or_default(),
                s("encryption").unwrap_or_default()
            )),
            s("connection_mode").map(|m| format!("{m}-connect")),
            flag("hidden_network", "hidden network"),
            (d.get("key_protected") == Some(&Value::Bool(false)))
                .then(|| "KEY IN CLEAR TEXT".to_string()),
        ],
        "registry" => vec![
            d.get("values")
                .and_then(Value::as_object)
                .map(|v| format!("{} values", v.len())),
            d.get("subkeys")
                .and_then(Value::as_array)
                .map(|v| format!("{} subkeys", v.len())),
            writable("writable_by"),
        ],
        _ => vec![],
    };
    parts
        .into_iter()
        .flatten()
        .filter(|p| !p.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" · ")
}

fn human_size(n: u64) -> String {
    let units = ["B", "KB", "MB", "GB"];
    let (mut v, mut i) = (n as f64, 0);
    while v >= 1024.0 && i < 3 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", units[i])
    }
}

fn object_detail(app: &App, p: &HashMap<String, String>) -> Result<Value, ApiError> {
    let store = open(app)?;
    let run = store.run_key(get(p, "run")?).map_err(bad)?;
    let identity = get(p, "identity")?;
    let blob_id: i64 = store
        .conn()
        .query_row(
            "SELECT blob FROM objects WHERE run = ?1 AND identity = ?2 AND (?3 IS NULL OR kind = ?3)",
            rusqlite::params![run, identity, p.get("kind")],
            |r| r.get(0),
        )
        .map_err(|_| ApiError::NotFound(identity.to_string()))?;
    Ok(json!({ "identity": identity, "data": blob(&store, Some(blob_id))? }))
}

/// Streams every result matching the query as JSON lines or CSV. Written through a
/// pipe so arbitrarily large exports never sit in memory.
fn export(app: &App, req: Request, p: &HashMap<String, String>) {
    let csv = p.get("format").is_some_and(|f| f == "csv");
    let f = match result_filter(app, p) {
        Ok(f) => f,
        Err(ApiError::Bad(e)) | Err(ApiError::Internal(e)) => {
            let _ = req.respond(Response::from_string(format!("{e:#}")).with_status_code(400));
            return;
        }
        Err(ApiError::NotFound(w)) => {
            let _ = req.respond(Response::from_string(w).with_status_code(404));
            return;
        }
    };
    let (reader, mut writer) = match std::io::pipe() {
        Ok(p) => p,
        Err(e) => {
            let _ = req.respond(Response::from_string(e.to_string()).with_status_code(500));
            return;
        }
    };
    let db = app.db.clone();
    let order = order_by(p);
    std::thread::spawn(move || {
        let mut run = || -> Result<()> {
            let store = Store::open(&db)?;
            let mut stmt = store.conn().prepare(&format!(
                "SELECT r.identity, r.kind, r.change, r.severity, r.diffs,
                        (SELECT json_group_array(rule) FROM findings f
                          WHERE f.comparison = r.comparison AND f.result = r.id),
                        (SELECT json_group_array(process) FROM attribution t
                          WHERE t.comparison = r.comparison AND t.result = r.id)
                 FROM {} WHERE {} ORDER BY {order}",
                f.from, f.filter
            ))?;
            let mut rows = stmt.query(params_from_iter(f.params.iter()))?;
            let mut out = std::io::BufWriter::new(&mut writer);
            if csv {
                writeln!(out, "severity,change,kind,path,rules,modified_by")?;
            }
            while let Some(r) = rows.next()? {
                let (identity, kind, change, sev): (String, String, String, i64) =
                    (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?);
                let rules: Value = serde_json::from_str(&r.get::<_, String>(5)?)?;
                let by: Value = serde_json::from_str(&r.get::<_, String>(6)?)?;
                if csv {
                    let join = |v: &Value| {
                        v.as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(Value::as_str)
                                    .collect::<Vec<_>>()
                                    .join("; ")
                            })
                            .unwrap_or_default()
                    };
                    writeln!(
                        out,
                        "{},{},{},{},{},{}",
                        severity_name(sev),
                        change,
                        kind,
                        csv_field(&identity),
                        csv_field(&join(&rules)),
                        csv_field(&join(&by))
                    )?;
                } else {
                    let diffs: Value = serde_json::from_str(&r.get::<_, String>(4)?)?;
                    serde_json::to_writer(
                        &mut out,
                        &json!({ "identity": identity, "kind": kind, "change": change,
                                 "severity": severity_name(sev), "rules": rules,
                                 "modified_by": by, "diffs": diffs }),
                    )?;
                    out.write_all(b"\n")?;
                }
            }
            out.flush()?;
            Ok(())
        };
        if let Err(e) = run() {
            eprintln!("export failed: {e:#}");
        }
    });
    let name = if csv {
        "asa-results.csv"
    } else {
        "asa-results.jsonl"
    };
    let resp = Response::new(
        StatusCode(200),
        vec![
            header(
                "Content-Type",
                if csv {
                    "text/csv; charset=utf-8"
                } else {
                    "application/x-ndjson"
                },
            ),
            header(
                "Content-Disposition",
                &format!("attachment; filename=\"{name}\""),
            ),
        ],
        reader,
        None,
        None,
    );
    let _ = req.respond(resp);
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_query_strings() {
        let p = parse_query("q=path+~+%22%5C%5CGoogle%5C%5C%22&c=3&bad=%zz&end=%4");
        assert_eq!(p["q"], r#"path ~ "\\Google\\""#);
        assert_eq!(p["c"], "3");
        assert_eq!(p["bad"], "%zz");
        assert_eq!(p["end"], "%4");
    }

    #[test]
    fn csv_quoting() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field(r#"C:\a,b "c""#), r#""C:\a,b ""c""""#);
    }

    #[test]
    fn tree_expands_one_level_at_a_time() {
        use crate::model::{Kind, Record};
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let mut store = Store::open(&db).unwrap();
        let snap = |store: &mut Store, id: &str, files: &[&str]| {
            store.begin_run(id).unwrap();
            let recs = files.iter().map(|f| Record {
                kind: Kind::File,
                identity: f.to_string(),
                data: json!({ "size": 1 }),
            });
            store.ingest(id, recs).unwrap();
            store
                .finish_run(id, &["files".into()], &Default::default(), 0)
                .unwrap();
        };
        snap(&mut store, "a", &[r"C:\old.txt"]);
        snap(
            &mut store,
            "b",
            &[
                r"C:\App\bin\a.exe",
                r"C:\App\bin\b.dll",
                r"C:\App\readme.txt",
                r"C:\new.txt",
            ],
        );
        let (rules, hash) = RuleSet::load_hashed(None).unwrap();
        let c = store.comparison("a", "b", &rules, &hash, None).unwrap();
        let app = App {
            db,
            rules,
            rules_hash: hash,
            hosts: vec![],
            computing: Mutex::new(()),
            attributing: Mutex::new(()),
            job: Mutex::new(None),
        };
        let level = |prefix: &str, q: &str| -> Vec<(String, i64, i64, bool)> {
            let p: HashMap<String, String> = [
                ("c", c.id.to_string()),
                ("kind", "file".into()),
                ("prefix", prefix.into()),
                ("q", q.into()),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
            let v = tree(&app, &p).map_err(|_| "tree failed").unwrap();
            let mut out: Vec<_> = v["children"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| {
                    (
                        c["name"].as_str().unwrap().to_string(),
                        c["count"].as_i64().unwrap(),
                        c["below"].as_i64().unwrap(),
                        c["id"].is_i64(),
                    )
                })
                .collect();
            out.sort();
            out
        };
        assert_eq!(level("", ""), vec![("C:".into(), 5, 5, false)]);
        assert_eq!(
            level(r"C:\", ""),
            vec![
                ("App".into(), 3, 3, false),
                ("new.txt".into(), 1, 0, true),
                ("old.txt".into(), 1, 0, true),
            ]
        );
        assert_eq!(
            level(r"C:\App\", ""),
            vec![
                ("bin".into(), 2, 2, false),
                ("readme.txt".into(), 1, 0, true)
            ]
        );
        // The query filters the tree.
        assert_eq!(
            level(r"C:\App\", "path ~ \"\\.exe$\""),
            vec![("bin".into(), 1, 1, false)]
        );
        let p: HashMap<String, String> = [
            ("c", c.id.to_string()),
            ("kind", "file".into()),
            ("prefix", "C:".into()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        assert!(tree(&app, &p).is_err(), "prefix without trailing backslash");
    }
}
