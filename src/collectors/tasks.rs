//! Scheduled tasks, parsed from their XML definitions under `%SystemRoot%\System32\Tasks`
//! (what the Task Scheduler service itself loads), so it works without the COM API.
//! For each task: who it runs as and with what rights, when it fires, and what it
//! runs, with the program's signature and who can overwrite it. Run history (last
//! run time, result) is left out: it changes constantly and is not attack surface.

// Only constructed on Windows; compiled everywhere so the logic is unit-tested.
#![cfg_attr(not(windows), allow(dead_code))]

use super::binaries;
use super::registry::expand_env;
use super::xml;
use super::{Collector, Sink, win};
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

pub const FIELDS: &[&str] = &[
    "path",
    "author",
    "description",
    "enabled",
    "hidden",
    "run_as",
    "run_level",
    "logon_type",
    "privileged",
    "triggers",
    "actions",
    "binary",
    "arguments",
    "working_directory",
    "com_handler",
    "script_host",
    "binary_missing",
    "binary_signature",
    "binary_writable_by",
];

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct TaskObject {
    /// Task path as Task Scheduler shows it (`\Vendor\Updater`).
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub enabled: bool,
    pub hidden: bool,
    /// Account or group the task runs as (well-known SIDs as names); absent when it
    /// runs as whoever registered it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_as: Option<String>,
    /// highest (elevated) or limited.
    pub run_level: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logon_type: Option<String>,
    /// Runs as SYSTEM, a service account or administrators, or elevated.
    pub privileged: bool,
    /// boot, logon, time, calendar, event, idle, registration, session, ...
    pub triggers: Vec<String>,
    /// Every action, readable: `exec: "C:\x.exe" -a`, `com: {CLSID}`.
    pub actions: Vec<String>,
    /// The program of the first exec action, resolved to a full path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    /// CLSID of the first COM handler action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub com_handler: Option<String>,
    /// The program is a shell or script host (cmd, PowerShell, mshta, rundll32, ...),
    /// so what it really runs is in the arguments.
    pub script_host: bool,
    pub binary_missing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_signature: Option<win::Signature>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub binary_writable_by: Vec<String>,
}

const SCRIPT_HOSTS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "bitsadmin.exe",
    "certutil.exe",
    "conhost.exe",
];

/// Well-known principals by SID, as task definitions often name them.
fn principal_name(id: &str) -> String {
    match id.to_ascii_uppercase().as_str() {
        "S-1-5-18" | "SYSTEM" | "NT AUTHORITY\\SYSTEM" | "LOCALSYSTEM" => "SYSTEM".into(),
        "S-1-5-19" => "LOCAL SERVICE".into(),
        "S-1-5-20" => "NETWORK SERVICE".into(),
        "S-1-5-32-544" => "Administrators".into(),
        "S-1-5-32-545" => "Users".into(),
        "S-1-5-4" => "INTERACTIVE".into(),
        "S-1-5-11" => "Authenticated Users".into(),
        "S-1-1-0" => "Everyone".into(),
        _ => id.to_string(),
    }
}

fn is_privileged(run_as: Option<&str>) -> bool {
    run_as.is_some_and(|r| {
        let r = r.to_ascii_uppercase();
        matches!(
            r.as_str(),
            "SYSTEM" | "LOCAL SERVICE" | "NETWORK SERVICE" | "ADMINISTRATORS"
        ) || r.ends_with("\\SYSTEM")
            || r.ends_with("\\ADMINISTRATORS")
    })
}

/// The program a task's `<Command>` runs: environment expanded, quotes removed, and
/// a bare name (`cmd`, `rundll32.exe`) found in System32 like the scheduler does.
pub fn resolve_command(command: &str) -> String {
    let c = expand_env(command.trim())
        .trim()
        .trim_matches('"')
        .to_string();
    if c.contains('\\') || c.contains('/') {
        return binaries::resolve(&c);
    }
    let name = if Path::new(&c).extension().is_some() {
        c
    } else {
        format!("{c}.exe")
    };
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    format!(r"{root}\System32\{name}")
}

/// Parses one task definition; `path` is its Task Scheduler path (`\A\B`).
pub fn parse_task(path: &str, xml_text: &str) -> Option<TaskObject> {
    let task = xml::first(xml_text, "Task")?;
    let info = xml::first(task, "RegistrationInfo").unwrap_or("");
    let settings = xml::first(task, "Settings").unwrap_or("");
    let principal = xml::first(task, "Principal").unwrap_or("");
    let run_as = xml::text(principal, "UserId")
        .or_else(|| xml::text(principal, "GroupId"))
        .map(|id| principal_name(&id));
    let run_level = match xml::text(principal, "RunLevel").as_deref() {
        Some("HighestAvailable") => "highest",
        _ => "limited",
    };

    let triggers: Vec<String> = xml::first(task, "Triggers")
        .map(xml::children)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|n| n.strip_suffix("Trigger"))
        .map(|n| match n {
            "SessionStateChange" => "session".to_string(),
            "WnfStateChange" => "wnf".to_string(),
            other => other.to_ascii_lowercase(),
        })
        .collect();

    let actions_xml = xml::first(task, "Actions").unwrap_or("");
    let mut actions = Vec::new();
    let mut first_exec: Option<(String, Option<String>, Option<String>)> = None;
    let mut com_handler = None;
    for name in xml::children(actions_xml) {
        match name {
            "Exec" => {}
            "ComHandler" => {}
            "SendEmail" => actions.push("email".to_string()),
            "ShowMessage" => actions.push("message".to_string()),
            other => actions.push(other.to_ascii_lowercase()),
        }
    }
    // Exec and COM actions in document order are what matter; list them in detail.
    for exec in xml::elements(actions_xml, "Exec") {
        let command = xml::text(exec, "Command").unwrap_or_default();
        let args = xml::text(exec, "Arguments").filter(|a| !a.is_empty());
        let wd = xml::text(exec, "WorkingDirectory").filter(|a| !a.is_empty());
        actions.push(match &args {
            Some(a) => format!("exec: {command} {a}"),
            None => format!("exec: {command}"),
        });
        if first_exec.is_none() {
            first_exec = Some((command, args, wd));
        }
    }
    for com in xml::elements(actions_xml, "ComHandler") {
        let clsid = xml::text(com, "ClassId").unwrap_or_default();
        actions.push(format!("com: {clsid}"));
        com_handler.get_or_insert(clsid);
    }
    actions.sort();

    let binary = first_exec
        .as_ref()
        .filter(|(c, _, _)| !c.is_empty())
        .map(|(c, _, _)| resolve_command(c));
    let script_host = binary.as_deref().is_some_and(|b| {
        let file = b.rsplit('\\').next().unwrap_or(b).to_ascii_lowercase();
        SCRIPT_HOSTS.contains(&file.as_str())
    });
    let (_, arguments, working_directory) = first_exec.unwrap_or_default();
    Some(TaskObject {
        path: path.to_string(),
        author: xml::text(info, "Author").filter(|s| !s.is_empty()),
        description: xml::text(info, "Description").filter(|s| !s.is_empty()),
        enabled: xml::text(settings, "Enabled").as_deref() != Some("false"),
        hidden: xml::text(settings, "Hidden").as_deref() == Some("true"),
        privileged: run_level == "highest" || is_privileged(run_as.as_deref()),
        run_as,
        run_level,
        logon_type: xml::text(principal, "LogonType"),
        triggers,
        actions,
        binary,
        arguments,
        working_directory,
        com_handler,
        script_host,
        ..Default::default()
    })
}

/// Some Windows task definitions deny administrators; read those with backup rights.
fn read(path: &Path) -> std::io::Result<Vec<u8>> {
    match std::fs::read(path) {
        #[cfg(windows)]
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => win::read_with_backup(path),
        other => other,
    }
}

pub fn default_root() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    Path::new(&root).join(r"System32\Tasks")
}

pub struct TasksCollector {
    pub root: PathBuf,
    pub threads: usize,
    pub signatures: bool,
}

impl TasksCollector {
    fn walk(&self, dir: &Path, rel: &str, out: &mut Vec<TaskObject>, sink: &Sink) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                sink.warn(|| format!("{}: {e}", dir.display()));
                return;
            }
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = format!(r"{rel}\{name}");
            match entry.file_type() {
                Ok(t) if t.is_dir() => self.walk(&entry.path(), &path, out, sink),
                Ok(_) => match read(&entry.path()) {
                    Ok(bytes) => match parse_task(&path, &xml::decode(&bytes)) {
                        Some(t) => out.push(t),
                        None => sink
                            .warn(|| format!("{}: not a task definition", entry.path().display())),
                    },
                    Err(e) => sink.warn(|| format!("{}: {e}", entry.path().display())),
                },
                Err(e) => sink.warn(|| format!("{}: {e}", entry.path().display())),
            }
        }
    }
}

impl Collector for TasksCollector {
    fn name(&self) -> &'static str {
        "tasks"
    }

    fn collect(&self, sink: &Sink) -> Result<()> {
        if !self.root.is_dir() {
            anyhow::bail!("{} not found", self.root.display());
        }
        let mut tasks = Vec::new();
        self.walk(&self.root, "", &mut tasks, sink);
        let paths: BTreeSet<String> = tasks.iter().filter_map(|t| t.binary.clone()).collect();
        let info: HashMap<String, binaries::BinaryInfo> =
            binaries::describe(paths, self.threads, self.signatures);
        for mut t in tasks {
            if let Some(b) = &t.binary {
                let i = info.get(&b.to_lowercase()).cloned().unwrap_or_default();
                t.binary_missing = !i.exists;
                t.binary_signature = i.signature;
                t.binary_writable_by = i.writable_by;
            }
            sink.emit(Record::new(Kind::Task, format!("task{}", t.path), &t));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UPDATER: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Vendor</Author>
    <URI>\Vendor\Updater</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
    <CalendarTrigger><StartBoundary>2026-01-01T03:00:00</StartBoundary><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings><Enabled>true</Enabled><Hidden>true</Hidden><ExecutionTimeLimit>PT1H</ExecutionTimeLimit></Settings>
  <Actions Context="Author">
    <Exec><Command>"C:\Program Files\Vendor\update.exe"</Command><Arguments>/silent &amp; /quiet</Arguments></Exec>
    <ComHandler><ClassId>{11111111-2222-3333-4444-555555555555}</ClassId></ComHandler>
  </Actions>
</Task>"#;

    const USER_PS: &str = r#"<Task><RegistrationInfo><Description>Sync</Description></RegistrationInfo>
<Triggers><LogonTrigger/></Triggers><Principals><Principal id="Author"><GroupId>S-1-5-32-545</GroupId></Principal></Principals>
<Settings><Enabled>false</Enabled></Settings>
<Actions Context="Author"><Exec><Command>powershell</Command><Arguments>-enc AAAA</Arguments></Exec></Actions></Task>"#;

    #[test]
    fn parses_task_definitions() {
        // SAFETY: tests that read SystemRoot all set the same value.
        unsafe { std::env::set_var("SystemRoot", r"C:\Windows") };
        let t = parse_task(r"\Vendor\Updater", UPDATER).unwrap();
        assert_eq!(t.author.as_deref(), Some("Vendor"));
        assert_eq!(t.run_as.as_deref(), Some("SYSTEM"));
        assert_eq!(t.run_level, "highest");
        assert!(t.privileged && t.enabled && t.hidden);
        assert_eq!(t.triggers, vec!["boot", "calendar"]);
        assert_eq!(
            t.binary.as_deref(),
            Some(r"C:\Program Files\Vendor\update.exe")
        );
        assert_eq!(t.arguments.as_deref(), Some("/silent & /quiet"));
        assert_eq!(
            t.com_handler.as_deref(),
            Some("{11111111-2222-3333-4444-555555555555}")
        );
        assert_eq!(t.actions.len(), 2);
        assert!(!t.script_host);

        let u = parse_task(r"\Sync", USER_PS).unwrap();
        assert_eq!(u.run_as.as_deref(), Some("Users"));
        assert!(!u.privileged && !u.enabled && !u.hidden);
        assert_eq!(u.triggers, vec!["logon"]);
        assert_eq!(
            u.binary.as_deref(),
            Some(r"C:\Windows\System32\powershell.exe")
        );
        assert!(u.script_host);
        assert_eq!(u.actions, vec!["exec: powershell -enc AAAA"]);
        assert!(parse_task(r"\x", "<NotATask/>").is_none());
    }

    #[test]
    fn collects_tree_with_task_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("Vendor")).unwrap();
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain(UPDATER.encode_utf16().flat_map(|c| c.to_le_bytes()))
            .collect();
        std::fs::write(dir.path().join("Vendor").join("Updater"), utf16).unwrap();
        std::fs::write(dir.path().join("Sync"), USER_PS).unwrap();
        std::fs::write(dir.path().join("junk"), "not xml").unwrap();
        let (tx, rx) = crossbeam_channel::unbounded();
        let sink = Sink::new(tx, false);
        TasksCollector {
            root: dir.path().into(),
            threads: 1,
            signatures: false,
        }
        .collect(&sink)
        .unwrap();
        assert_eq!(sink.warnings(), 1, "the junk file");
        drop(sink);
        let mut ids: Vec<String> = rx.iter().map(|r| r.identity).collect();
        ids.sort();
        assert_eq!(ids, vec![r"task\Sync", r"task\Vendor\Updater"]);
    }

    #[test]
    fn fields_in_sync() {
        let t = TaskObject {
            author: Some("a".into()),
            description: Some("d".into()),
            run_as: Some("x".into()),
            logon_type: Some("l".into()),
            binary: Some("b".into()),
            arguments: Some("a".into()),
            working_directory: Some("w".into()),
            com_handler: Some("c".into()),
            binary_signature: Some(win::Signature {
                status: "valid".into(),
                source: None,
                signer: None,
            }),
            binary_writable_by: vec!["Users".into()],
            ..Default::default()
        };
        crate::collectors::assert_fields(&t, FIELDS);
    }
}
