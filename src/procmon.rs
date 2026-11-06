//! Process Monitor import: attributes changes to the processes that made them.
//!
//! asa sees *what* changed between two runs; a Procmon capture recorded in between
//! says *who* changed it. `asa procmon import capture.csv` keeps only the events
//! that modify something (writes, creates, deletes, renames, security and registry
//! value changes) and stores them deduplicated per (process, operation, path). A
//! comparison then links each result to the events on its file or registry key, so
//! the web UI can show and filter by `modified_by`.

use crate::model::Kind;
use crate::store::Store;
use anyhow::{Context, Result, bail};
use rusqlite::{OptionalExtension, params};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

/// Events are committed in batches of this size while a capture is imported.
const BATCH_SIZE: usize = 5_000;

const SYSTEM_PID: i64 = 4;

/// Most events listed for one result.
pub const MAX_EVENTS: i64 = 100;

/// A capture as listed by `asa procmon list` and the web UI.
#[derive(Debug, Serialize)]
pub struct Capture {
    pub name: String,
    pub source: String,
    pub imported: String,
    /// Distinct (process, operation, path) events kept.
    pub events: i64,
    /// Rows read from the CSV.
    pub rows: i64,
}

/// One stored event, deduplicated: `count` is how many times it repeated.
#[derive(Debug, Serialize, PartialEq)]
pub struct Event {
    pub capture: String,
    pub time: String,
    pub process: String,
    pub pid: i64,
    pub operation: String,
    pub path: String,
    pub detail: String,
    pub user: String,
    pub command_line: String,
    pub count: i64,
}

/// Whether a Procmon event changed something asa may report. Reads and opens are
/// most of a capture and are dropped.
pub fn is_change(operation: &str, result: &str, detail: &str) -> bool {
    if result != "SUCCESS" {
        return false;
    }
    match operation {
        "WriteFile"
        | "SetRenameInformationFile"
        | "SetRenameInformationEx"
        | "SetSecurityFile"
        | "SetEndOfFileInformationFile"
        | "SetLinkInformationFile"
        | "RegSetValue"
        | "RegDeleteValue"
        | "RegDeleteKey"
        | "RegSetKeySecurity"
        | "RegRenameKey" => true,
        "SetDispositionInformationFile" | "SetDispositionInformationEx" => {
            detail.contains("Delete: True") || detail.contains("FILE_DISPOSITION_DELETE")
        }
        "CreateFile" => [
            "OpenResult: Created",
            "OpenResult: Overwritten",
            "OpenResult: Superseded",
        ]
        .iter()
        .any(|r| detail.contains(r)),
        "RegCreateKey" => detail.contains("REG_CREATED_NEW_KEY"),
        _ => false,
    }
}

/// A Procmon path in the form asa uses for identities (`C:\...`, `HKLM\...`), or
/// None for paths asa never reports (devices, pipes, network endpoints).
pub fn normalize(path: &str) -> Option<String> {
    let p = path.trim();
    let p = p
        .strip_prefix(r"\\?\")
        .or_else(|| p.strip_prefix(r"\??\"))
        .unwrap_or(p);
    let b = p.as_bytes();
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\' {
        return Some(p.to_string());
    }
    let (root, rest) = match p.split_once('\\') {
        Some((r, rest)) => (r, Some(rest)),
        None => (p, None),
    };
    let root = match root.to_ascii_uppercase().as_str() {
        "HKCR" => r"HKLM\SOFTWARE\Classes".to_string(),
        r @ ("HKLM" | "HKCU" | "HKU") => r.to_string(),
        _ => return None,
    };
    let mut rest = rest.unwrap_or("").to_string();
    // Procmon sometimes shows the control set asa reads through CurrentControlSet.
    if root == "HKLM" {
        let lower = rest.to_ascii_lowercase();
        if let Some(tail) = lower.strip_prefix(r"system\controlset00")
            && tail.as_bytes().first().is_some_and(u8::is_ascii_digit)
            && tail.as_bytes().get(1).is_none_or(|c| *c == b'\\')
        {
            rest = format!(
                r"SYSTEM\CurrentControlSet{}",
                &rest[r"system\controlset00".len() + 1..]
            );
        }
    }
    Some(if rest.is_empty() {
        root
    } else {
        format!(r"{root}\{rest}")
    })
}

/// Where Procmon would show changes to an object: (path, extra levels below it).
/// Registry values appear as `key\value`, so keys allow at least one level.
pub fn sources(kind: Kind, identity: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    match kind {
        Kind::File => out.push((identity.to_string(), 0)),
        Kind::Registry => {
            out.push((identity.to_string(), 1));
            if let Some(user) = hkcu_view(identity) {
                out.push((user, 1));
            }
        }
        Kind::Service | Kind::Driver => out.push((
            format!(r"{}\{identity}", crate::collectors::services::SERVICES_KEY),
            2,
        )),
        Kind::Firewall => {
            let mut it = identity.splitn(3, '\\');
            let (t, store, id) = (it.next(), it.next(), it.next());
            let base = match store {
                Some("local") => {
                    r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
                }
                Some("gpo") => r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall",
                _ => return out,
            };
            match (t, id) {
                (Some("rule"), Some(id)) => out.push((format!(r"{base}\FirewallRules\{id}"), 0)),
                (Some("profile"), Some(p)) => {
                    let key = match p {
                        "domain" => "DomainProfile",
                        "private" => "StandardProfile",
                        "public" => "PublicProfile",
                        _ => return out,
                    };
                    out.push((format!(r"{base}\{key}"), 1));
                }
                _ => {}
            }
        }
        Kind::Com => {
            let key = if let Some(rest) = identity.strip_prefix(r"user\") {
                // user\{sid}\clsid[32]\{id}
                let mut it = rest.splitn(3, '\\');
                match (it.next(), it.next(), it.next()) {
                    (Some(sid), Some("clsid"), Some(id)) => {
                        format!(r"HKU\{sid}_Classes\CLSID\{id}")
                    }
                    (Some(sid), Some("clsid32"), Some(id)) => {
                        format!(r"HKU\{sid}_Classes\WOW6432Node\CLSID\{id}")
                    }
                    _ => return out,
                }
            } else {
                let Some((prefix, id)) = identity.split_once('\\') else {
                    return out;
                };
                let root = match prefix {
                    "clsid" => r"HKLM\SOFTWARE\Classes\CLSID",
                    "clsid32" => r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID",
                    "appid" => r"HKLM\SOFTWARE\Classes\AppID",
                    "typelib" => r"HKLM\SOFTWARE\Classes\TypeLib",
                    "typelib32" => r"HKLM\SOFTWARE\WOW6432Node\Classes\TypeLib",
                    _ => return out,
                };
                format!(r"{root}\{id}")
            };
            if let Some(user) = hkcu_view(&key) {
                out.push((user, 4));
            }
            out.push((key, 4));
        }
        Kind::Certificate => {
            // cert\{location}\{store}\{thumbprint}
            let mut it = identity.splitn(4, '\\');
            if let (Some("cert"), Some(loc), Some(store), Some(thumb)) =
                (it.next(), it.next(), it.next(), it.next())
            {
                let root = match loc {
                    "machine" => r"HKLM\SOFTWARE\Microsoft\SystemCertificates",
                    "group_policy" => r"HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates",
                    "enterprise" => r"HKLM\SOFTWARE\Microsoft\EnterpriseCertificates",
                    "user" => r"HKCU\SOFTWARE\Microsoft\SystemCertificates",
                    _ => return out,
                };
                out.push((format!(r"{root}\{store}\Certificates\{thumb}"), 1));
            }
        }
        // Accounts live in the SAM (written by lsass on everyone's behalf), Wi-Fi
        // profile files are named by GUID, and listening sockets are not file or
        // registry events.
        Kind::User | Kind::Group | Kind::Wifi | Kind::Port => {}
    }
    out
}

/// `HKU\{sid}\X` as Procmon shows it for the logged-on user: `HKCU\X`.
fn hkcu_view(path: &str) -> Option<String> {
    let rest = path.strip_prefix(r"HKU\")?;
    let (sid, tail) = rest.split_once('\\')?;
    Some(match sid.strip_suffix("_Classes") {
        Some(_) => format!(r"HKCU\Software\Classes\{tail}"),
        None => format!(r"HKCU\{tail}"),
    })
}

/// Column positions in a Procmon CSV export (File > Save > CSV).
struct Columns {
    time: Option<usize>,
    process: usize,
    pid: Option<usize>,
    operation: usize,
    path: usize,
    result: usize,
    detail: Option<usize>,
    user: Option<usize>,
    command_line: Option<usize>,
}

impl Columns {
    fn from_header(h: &csv::ByteRecord) -> Result<Self> {
        let names: Vec<String> = h
            .iter()
            .map(|f| {
                String::from_utf8_lossy(f)
                    .trim_start_matches('\u{feff}')
                    .trim()
                    .to_string()
            })
            .collect();
        let find = |n: &str| names.iter().position(|x| x.eq_ignore_ascii_case(n));
        let need = |n: &str| {
            find(n).with_context(|| {
                format!(
                    "not a Procmon CSV export: no '{n}' column (found: {})",
                    names.join(", ")
                )
            })
        };
        Ok(Columns {
            time: find("Date & Time").or_else(|| find("Time of Day")),
            process: need("Process Name")?,
            pid: find("PID"),
            operation: need("Operation")?,
            path: need("Path")?,
            result: need("Result")?,
            detail: find("Detail"),
            user: find("User"),
            command_line: find("Command Line"),
        })
    }
}

/// Imports a Procmon CSV export as capture `name`. Returns (rows read, events kept).
pub fn import(store: &Store, csv_path: &Path, name: &str) -> Result<(u64, u64)> {
    let file =
        std::fs::File::open(csv_path).with_context(|| format!("opening {}", csv_path.display()))?;
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(std::io::BufReader::with_capacity(1 << 20, file));
    let mut rec = csv::ByteRecord::new();
    if !reader.read_byte_record(&mut rec)? {
        bail!("{} is empty", csv_path.display());
    }
    let cols = Columns::from_header(&rec)?;

    let conn = store.conn();
    if conn
        .query_row("SELECT 1 FROM captures WHERE name = ?1", [name], |_| Ok(()))
        .optional()?
        .is_some()
    {
        bail!(
            "a capture named '{name}' already exists (delete it with `asa procmon delete {name}`)"
        );
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "INSERT INTO captures (name, source, imported) VALUES (?1, ?2, ?3)",
        params![
            name,
            csv_path.display().to_string(),
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ],
    )?;
    let capture = tx.last_insert_rowid();
    tx.commit()?;
    let imported = read_events(store, &mut reader, &cols, capture);
    if imported.is_err() {
        // Don't leave half a capture behind.
        conn.execute("DELETE FROM captures WHERE id = ?1", [capture])?;
    }
    let (rows, kept) = imported?;
    conn.execute(
        "UPDATE captures SET events = ?2, rows = ?3 WHERE id = ?1",
        params![capture, kept as i64, rows as i64],
    )?;
    invalidate(store)?;
    Ok((rows, kept))
}

fn read_events(
    store: &Store,
    reader: &mut csv::Reader<impl std::io::Read>,
    cols: &Columns,
    capture: i64,
) -> Result<(u64, u64)> {
    let conn = store.conn();
    let mut rec = csv::ByteRecord::new();

    let field = |rec: &csv::ByteRecord, i: Option<usize>| -> String {
        i.and_then(|i| rec.get(i))
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default()
    };
    // (pid, operation, key) -> seq of its first event, so repeats only bump a count.
    let mut seen: HashMap<(i64, String, String), i64> = HashMap::new();
    let (mut rows, mut kept) = (0u64, 0u64);
    let mut pending: Vec<(i64, Option<(Event, String)>)> = Vec::new();
    let flush = |pending: &mut Vec<(i64, Option<(Event, String)>)>| -> Result<()> {
        let tx = conn.unchecked_transaction()?;
        {
            let mut ins = tx.prepare_cached(
                "INSERT INTO activity (capture, seq, time, process, pid, operation, path, key, detail, user, command_line, count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1)",
            )?;
            let mut bump = tx.prepare_cached(
                "UPDATE activity SET count = count + 1 WHERE capture = ?1 AND seq = ?2",
            )?;
            for (seq, ev) in pending.drain(..) {
                match ev {
                    Some((e, key)) => {
                        ins.execute(params![
                            capture,
                            seq,
                            e.time,
                            e.process,
                            e.pid,
                            e.operation,
                            e.path,
                            key,
                            e.detail,
                            e.user,
                            e.command_line
                        ])?;
                    }
                    None => {
                        bump.execute(params![capture, seq])?;
                    }
                }
            }
        }
        tx.commit()?;
        Ok(())
    };
    while reader.read_byte_record(&mut rec)? {
        rows += 1;
        let operation = field(&rec, Some(cols.operation));
        let result = field(&rec, Some(cols.result));
        let detail = field(&rec, cols.detail);
        if !is_change(&operation, &result, &detail) {
            continue;
        }
        let pid = field(&rec, cols.pid).trim().parse().unwrap_or(-1);
        // File I/O by System (PID 4) is the cache and memory managers flushing other
        // processes' writes; crediting it would hide the real author.
        if pid == SYSTEM_PID && !operation.starts_with("Reg") {
            continue;
        }
        let raw_path = field(&rec, Some(cols.path));
        // A rename also creates its destination, named at the end of the detail.
        let mut paths = vec![raw_path];
        if operation.starts_with("SetRenameInformation")
            && let Some((_, dest)) = detail.rsplit_once("FileName: ")
        {
            paths.push(dest.trim().to_string());
        }
        for raw in paths {
            let Some(path) = normalize(&raw) else {
                continue;
            };
            let key = path.to_lowercase();
            let id = (pid, operation.clone(), key.clone());
            if let Some(&seq) = seen.get(&id) {
                pending.push((seq, None));
            } else {
                kept += 1;
                let seq = kept as i64;
                seen.insert(id, seq);
                pending.push((
                    seq,
                    Some((
                        Event {
                            capture: String::new(),
                            time: field(&rec, cols.time),
                            process: field(&rec, Some(cols.process)),
                            pid,
                            operation: operation.clone(),
                            path,
                            detail: detail.clone(),
                            user: field(&rec, cols.user),
                            command_line: field(&rec, cols.command_line),
                            count: 1,
                        },
                        key,
                    )),
                ));
            }
        }
        if pending.len() >= BATCH_SIZE {
            flush(&mut pending)?;
        }
    }
    flush(&mut pending)?;
    Ok((rows, kept))
}

pub fn captures(store: &Store) -> Result<Vec<Capture>> {
    let mut stmt = store
        .conn()
        .prepare("SELECT name, source, imported, events, rows FROM captures ORDER BY id")?;
    let rows = stmt.query_map([], |r| {
        Ok(Capture {
            name: r.get(0)?,
            source: r.get(1)?,
            imported: r.get(2)?,
            events: r.get(3)?,
            rows: r.get(4)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn delete(store: &Store, name: &str) -> Result<bool> {
    let n = store
        .conn()
        .execute("DELETE FROM captures WHERE name = ?1", [name])?;
    if n > 0 {
        invalidate(store)?;
    }
    Ok(n > 0)
}

/// Attribution depends on the set of captures; recompute it lazily after a change.
fn invalidate(store: &Store) -> Result<()> {
    store
        .conn()
        .execute_batch("DELETE FROM attribution; DELETE FROM attributed;")?;
    Ok(())
}

/// Events on any of `sources`, newest capture first, at most `limit`.
fn events_for(store: &Store, sources: &[(String, usize)], limit: i64) -> Result<Vec<Event>> {
    let mut stmt = store.conn().prepare_cached(
        "SELECT c.name, a.time, a.process, a.pid, a.operation, a.path, a.detail, a.user,
                a.command_line, a.count, a.key
         FROM activity a JOIN captures c ON c.id = a.capture
         WHERE a.key = ?1 OR (a.key > ?2 AND a.key < ?3)
         ORDER BY a.capture DESC, a.seq",
    )?;
    let mut out = Vec::new();
    for (path, depth) in sources {
        let key = path.to_lowercase();
        let rows = stmt.query_map(params![key, format!(r"{key}\"), format!("{key}]")], |r| {
            Ok((
                Event {
                    capture: r.get(0)?,
                    time: r.get(1)?,
                    process: r.get(2)?,
                    pid: r.get(3)?,
                    operation: r.get(4)?,
                    path: r.get(5)?,
                    detail: r.get(6)?,
                    user: r.get(7)?,
                    command_line: r.get(8)?,
                    count: r.get(9)?,
                },
                r.get::<_, String>(10)?,
            ))
        })?;
        for row in rows {
            let (ev, k) = row?;
            let below = k.get(key.len() + 1..).unwrap_or("");
            let levels = if k == key {
                0
            } else {
                below.matches('\\').count() + 1
            };
            if levels <= *depth {
                out.push(ev);
                if out.len() as i64 >= limit {
                    return Ok(out);
                }
            }
        }
    }
    Ok(out)
}

/// Procmon events behind one comparison result.
pub fn events(store: &Store, kind: Kind, identity: &str) -> Result<Vec<Event>> {
    events_for(store, &sources(kind, identity), MAX_EVENTS)
}

/// Links every result of `comparison` to the processes that touched it, once per
/// set of captures. Cheap when there are no captures or it is already done.
pub fn ensure_attribution(store: &Store, comparison: i64) -> Result<()> {
    let conn = store.conn();
    let has_captures: bool =
        conn.query_row("SELECT EXISTS (SELECT 1 FROM captures)", [], |r| r.get(0))?;
    if !has_captures {
        return Ok(());
    }
    let done: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM attributed WHERE comparison = ?1)",
        [comparison],
        |r| r.get(0),
    )?;
    if done {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    {
        let mut results =
            tx.prepare("SELECT id, kind, identity FROM results WHERE comparison = ?1")?;
        let mut ins = tx.prepare(
            "INSERT OR IGNORE INTO attribution (comparison, result, process) VALUES (?1, ?2, ?3)",
        )?;
        let rows = results.query_map([comparison], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (id, kind, identity) = row?;
            let Ok(kind) = kind.parse::<Kind>() else {
                continue;
            };
            let src = sources(kind, &identity);
            if src.is_empty() {
                continue;
            }
            for ev in events_for(store, &src, i64::MAX)? {
                ins.execute(params![comparison, id, ev.process])?;
            }
        }
        tx.execute(
            "INSERT INTO attributed (comparison) VALUES (?1)",
            [comparison],
        )?;
    }
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_changes() {
        assert!(is_change("WriteFile", "SUCCESS", "Offset: 0, Length: 10"));
        assert!(!is_change("WriteFile", "ACCESS DENIED", ""));
        assert!(!is_change("ReadFile", "SUCCESS", ""));
        assert!(!is_change("RegQueryValue", "SUCCESS", ""));
        assert!(is_change(
            "CreateFile",
            "SUCCESS",
            "Desired Access: Generic Write, Disposition: OverwriteIf, OpenResult: Created"
        ));
        assert!(!is_change(
            "CreateFile",
            "SUCCESS",
            "Desired Access: Generic Read, OpenResult: Opened"
        ));
        assert!(is_change(
            "RegCreateKey",
            "SUCCESS",
            "Desired Access: All Access, Disposition: REG_CREATED_NEW_KEY"
        ));
        assert!(!is_change(
            "RegCreateKey",
            "SUCCESS",
            "Disposition: REG_OPENED_EXISTING_KEY"
        ));
        assert!(is_change(
            "SetDispositionInformationFile",
            "SUCCESS",
            "Delete: True"
        ));
        assert!(!is_change(
            "SetDispositionInformationFile",
            "SUCCESS",
            "Delete: False"
        ));
    }

    #[test]
    fn normalizes_paths_to_identities() {
        assert_eq!(
            normalize(r"C:\Windows\x.dll").as_deref(),
            Some(r"C:\Windows\x.dll")
        );
        assert_eq!(normalize(r"\\?\C:\x").as_deref(), Some(r"C:\x"));
        assert_eq!(
            normalize(r"HKCR\CLSID\{A}\InprocServer32").as_deref(),
            Some(r"HKLM\SOFTWARE\Classes\CLSID\{A}\InprocServer32")
        );
        assert_eq!(
            normalize(r"HKLM\System\ControlSet001\Services\X\ImagePath").as_deref(),
            Some(r"HKLM\SYSTEM\CurrentControlSet\Services\X\ImagePath")
        );
        assert_eq!(
            normalize(r"HKLM\System\ControlSet0010\X").as_deref(),
            Some(r"HKLM\System\ControlSet0010\X")
        );
        assert_eq!(normalize(r"\Device\HarddiskVolume3\x"), None);
        assert_eq!(normalize("10.0.0.1:445 -> 10.0.0.2:51234"), None);
        assert_eq!(normalize(r"\\server\share\x"), None);
    }

    #[test]
    fn maps_objects_to_their_registry_and_file_sources() {
        let s = |k, i| sources(k, i);
        assert_eq!(s(Kind::File, r"C:\a.exe"), vec![(r"C:\a.exe".into(), 0)]);
        assert_eq!(
            s(Kind::Service, "Spooler"),
            vec![(r"HKLM\SYSTEM\CurrentControlSet\Services\Spooler".into(), 2)]
        );
        assert_eq!(
            s(Kind::Firewall, r"rule\local\{R1}")[0].0,
            r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules\{R1}"
        );
        assert_eq!(
            s(Kind::Firewall, r"profile\gpo\public")[0].0,
            r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        );
        assert_eq!(
            s(Kind::Com, r"user\S-1-5-21-1\clsid\{C}"),
            vec![
                (r"HKCU\Software\Classes\CLSID\{C}".into(), 4),
                (r"HKU\S-1-5-21-1_Classes\CLSID\{C}".into(), 4)
            ]
        );
        assert_eq!(
            s(Kind::Certificate, r"cert\machine\Root\ABCD")[0].0,
            r"HKLM\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\ABCD"
        );
        assert_eq!(
            s(Kind::Registry, r"HKU\S-1-5-21-1\Software\Run"),
            vec![
                (r"HKU\S-1-5-21-1\Software\Run".into(), 1),
                (r"HKCU\Software\Run".into(), 1)
            ]
        );
        assert!(s(Kind::User, r"user\bob").is_empty());
    }

    const CSV: &str = "\u{feff}\"Time of Day\",\"Process Name\",\"PID\",\"Operation\",\"Path\",\"Result\",\"Detail\"
\"10:00:00.0000001 AM\",\"setup.exe\",\"100\",\"CreateFile\",\"C:\\App\\a.dll\",\"SUCCESS\",\"Desired Access: Generic Write, OpenResult: Created\"
\"10:00:00.0000002 AM\",\"setup.exe\",\"100\",\"WriteFile\",\"C:\\App\\a.dll\",\"SUCCESS\",\"Offset: 0, Length: 4096\"
\"10:00:00.0000003 AM\",\"setup.exe\",\"100\",\"WriteFile\",\"C:\\App\\a.dll\",\"SUCCESS\",\"Offset: 4096, Length: 4096\"
\"10:00:00.0000004 AM\",\"setup.exe\",\"100\",\"ReadFile\",\"C:\\App\\b.dll\",\"SUCCESS\",\"Offset: 0\"
\"10:00:00.0000005 AM\",\"services.exe\",\"700\",\"RegSetValue\",\"HKLM\\System\\CurrentControlSet\\Services\\AppSvc\\ImagePath\",\"SUCCESS\",\"Type: REG_EXPAND_SZ, Length: 40, Data: C:\\App\\svc.exe\"
\"10:00:00.0000006 AM\",\"setup.exe\",\"100\",\"SetRenameInformationFile\",\"C:\\App\\tmp1.tmp\",\"SUCCESS\",\"ReplaceIfExists: True, FileName: C:\\App\\svc.exe\"
\"10:00:00.0000007 AM\",\"other.exe\",\"200\",\"WriteFile\",\"C:\\App\\a.dll.log\",\"SUCCESS\",\"Offset: 0\"
\"10:00:00.0000009 AM\",\"System\",\"4\",\"WriteFile\",\"C:\\App\\a.dll\",\"SUCCESS\",\"Offset: 0, Length: 4096, I/O Flags: Non-cached, Paging I/O\"
\"10:00:00.0000008 AM\",\"setup.exe\",\"100\",\"RegSetValue\",\"HKLM\\SOFTWARE\\Deep\\A\\B\\C\",\"SUCCESS\",\"\"
";

    #[test]
    fn imports_and_attributes() {
        let dir = tempfile::tempdir().unwrap();
        let csv = dir.path().join("cap.csv");
        std::fs::write(&csv, CSV).unwrap();
        let store = Store::open(&dir.path().join("t.db")).unwrap();
        let (rows, kept) = import(&store, &csv, "install").unwrap();
        assert_eq!(rows, 9);
        // ReadFile and System's cache flush dropped; the second WriteFile on a.dll folded;
        // the rename adds its destination.
        assert_eq!(kept, 7);
        assert!(import(&store, &csv, "install").is_err(), "duplicate name");

        let a = events(&store, Kind::File, r"C:\App\A.DLL").unwrap();
        let ops: Vec<(&str, i64)> = a.iter().map(|e| (e.operation.as_str(), e.count)).collect();
        assert_eq!(ops, vec![("CreateFile", 1), ("WriteFile", 2)], "{a:?}");
        assert_eq!(a[0].capture, "install");

        let svc = events(&store, Kind::Service, "AppSvc").unwrap();
        assert_eq!(svc.len(), 1);
        assert_eq!(svc[0].process, "services.exe");
        let renamed = events(&store, Kind::File, r"C:\App\svc.exe").unwrap();
        assert_eq!(renamed[0].operation, "SetRenameInformationFile");
        // Too deep below a registry key to belong to it.
        assert!(
            events(&store, Kind::Registry, r"HKLM\SOFTWARE\Deep")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            events(&store, Kind::Registry, r"HKLM\SOFTWARE\Deep\A\B")
                .unwrap()
                .len(),
            1
        );

        assert_eq!(captures(&store).unwrap()[0].events, 7);
        assert!(delete(&store, "install").unwrap());
        assert!(
            events(&store, Kind::File, r"C:\App\a.dll")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejects_other_csv() {
        let dir = tempfile::tempdir().unwrap();
        let csv = dir.path().join("x.csv");
        std::fs::write(&csv, "a,b,c\n1,2,3\n").unwrap();
        let store = Store::open(&dir.path().join("t.db")).unwrap();
        let err = import(&store, &csv, "x").unwrap_err().to_string();
        assert!(err.contains("not a Procmon CSV"), "{err}");
        assert!(captures(&store).unwrap().is_empty());
    }

    #[test]
    fn comparison_results_are_filterable_by_process() {
        use crate::model::Record;
        use crate::query::{Scope, compile};
        use std::collections::BTreeMap;
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("t.db")).unwrap();
        let snap = |store: &mut Store, id: &str, files: &[&str]| {
            store.begin_run(id).unwrap();
            let recs = files.iter().map(|f| Record {
                kind: Kind::File,
                identity: f.to_string(),
                data: serde_json::json!({ "size": 1 }),
            });
            store.ingest(id, recs).unwrap();
            store
                .finish_run(id, &["files".into()], &BTreeMap::new(), 0)
                .unwrap();
        };
        snap(&mut store, "a", &[r"C:\keep.txt"]);
        snap(
            &mut store,
            "b",
            &[r"C:\keep.txt", r"C:\App\a.dll", r"C:\App\other.dll"],
        );
        let rules = crate::rules::RuleSet::load(None).unwrap();
        let c = store.comparison("a", "b", &rules, "h", None).unwrap();
        assert_eq!(c.total, 2);

        let csv = dir.path().join("cap.csv");
        std::fs::write(&csv, CSV).unwrap();
        import(&store, &csv, "install").unwrap();
        ensure_attribution(&store, c.id).unwrap();
        ensure_attribution(&store, c.id).unwrap(); // idempotent

        let count = |q: &str| -> i64 {
            let q = compile(q, Scope::Results).unwrap();
            let mut params = q.params;
            params.push(rusqlite::types::Value::Integer(c.id));
            let sql = format!(
                "SELECT COUNT(*) FROM results r WHERE r.comparison = ?{} AND ({})",
                params.len(),
                q.sql
            );
            store
                .conn()
                .query_row(&sql, rusqlite::params_from_iter(params.iter()), |r| {
                    r.get(0)
                })
                .unwrap()
        };
        assert_eq!(count("modified_by = SETUP.EXE"), 1);
        assert_eq!(count("modified_by ~ \"^setup\""), 1);
        assert_eq!(count("modified_by has setup"), 1);
        assert_eq!(count("modified_by != setup.exe"), 1);
        assert_eq!(count("modified_by exists"), 1);
        assert_eq!(count("modified_by missing"), 1);
        assert!(compile("modified_by > x", Scope::Results).is_err());

        // A new capture invalidates the cached attribution.
        delete(&store, "install").unwrap();
        ensure_attribution(&store, c.id).unwrap();
        assert_eq!(count("modified_by exists"), 0);
    }
}
