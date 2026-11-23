//! systemd services, read from the unit files themselves (no D-Bus, no systemctl),
//! so the same code inspects the live system, a fixture tree, or a mounted image.
//!
//! Covers what decides what runs and as whom: the effective unit file (search-path
//! precedence), drop-in overrides, enablement (`*.wants/` / `*.requires/` links),
//! masking, the commands and their binary, the account, hardening settings, and who
//! besides root can rewrite the unit or the binary. Runtime state (active/inactive)
//! is deliberately left out, as on Windows.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::collectors::unix::{self, Ids, under};
use crate::collectors::{Collector, Sink};
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// Unit search path for system units, highest precedence first. `/run` (transient,
/// regenerated each boot) is left out to keep snapshots stable.
pub const UNIT_DIRS: &[&str] = &[
    "etc/systemd/system",
    "usr/local/lib/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
];

/// Where a bare command name in Exec*= is looked up.
const EXEC_SEARCH: &[&str] = &[
    "usr/local/sbin",
    "usr/local/bin",
    "usr/sbin",
    "usr/bin",
    "sbin",
    "bin",
];

/// Exec*= settings, in the order they run.
const EXEC_KEYS: &[&str] = &[
    "ExecCondition",
    "ExecStartPre",
    "ExecStart",
    "ExecStartPost",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
];

/// [Service] settings that confine (or, when removed, unconfine) a service.
const HARDENING_KEYS: &[&str] = &[
    "NoNewPrivileges",
    "ProtectSystem",
    "ProtectHome",
    "PrivateTmp",
    "PrivateDevices",
    "PrivateNetwork",
    "ProtectKernelModules",
    "ProtectKernelTunables",
    "ProtectControlGroups",
    "RestrictSUIDSGID",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "SystemCallFilter",
    "RestrictAddressFamilies",
];

/// Settings where each line adds to a list and an empty value resets it.
fn is_list(key: &str) -> bool {
    key.starts_with("Exec")
        || matches!(
            key,
            "CapabilityBoundingSet" | "AmbientCapabilities" | "SystemCallFilter"
        )
}

pub const FIELDS: &[&str] = &[
    "name",
    "display_name",
    "type",
    "start",
    "account",
    "image_path",
    "binary",
    "binary_missing",
    "binary_writable_by",
    "unit_path",
    "drop_ins",
    "unit_writable_by",
    "commands",
    "hardening",
];

#[derive(Serialize, Default)]
struct UnitObject {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    /// Type= (simple, forking, oneshot, notify, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    r#type: Option<String>,
    /// enabled, disabled, static (no [Install] section), masked, or template.
    start: &'static str,
    /// User=, "dynamic" for DynamicUser=, root otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<String>,
    /// The (first) ExecStart= command line.
    #[serde(skip_serializing_if = "Option::is_none")]
    image_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binary: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    binary_missing: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    binary_writable_by: Vec<String>,
    /// The effective unit file (symlinks resolved).
    unit_path: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    drop_ins: Vec<String>,
    /// Non-root principals who can rewrite the unit file or a drop-in.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unit_writable_by: Vec<String>,
    /// Every Exec*= line, as `Key=command`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    commands: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    hardening: BTreeMap<String, String>,
}

/// Unit files, drop-ins and enablement links found on the search path.
#[derive(Default)]
struct Scan {
    /// unit name -> path of the unit file that wins (first on the search path)
    units: BTreeMap<String, String>,
    /// unit or template name -> drop-in file name -> path (first on the search path wins)
    dropins: HashMap<String, BTreeMap<String, String>>,
    /// names linked from a *.wants/ or *.requires/ directory
    wanted: BTreeSet<String>,
}

fn sorted_dir(path: &Path) -> Vec<std::fs::DirEntry> {
    let mut v: Vec<_> = std::fs::read_dir(path)
        .map(|rd| rd.flatten().collect())
        .unwrap_or_default();
    v.sort_by_key(|e| e.file_name());
    v
}

fn scan(root: &Path) -> Scan {
    let mut s = Scan::default();
    for dir in UNIT_DIRS {
        for e in sorted_dir(&under(root, dir)) {
            let name = e.file_name().to_string_lossy().into_owned();
            let path = format!("/{dir}/{name}");
            let is_dir = std::fs::metadata(e.path()).is_ok_and(|m| m.is_dir());
            if let Some(unit) = name.strip_suffix(".d").filter(|u| u.ends_with(".service")) {
                if is_dir {
                    let confs = s.dropins.entry(unit.to_string()).or_default();
                    for c in sorted_dir(&e.path()) {
                        let cname = c.file_name().to_string_lossy().into_owned();
                        if cname.ends_with(".conf") {
                            confs
                                .entry(cname.clone())
                                .or_insert_with(|| format!("{path}/{cname}"));
                        }
                    }
                }
            } else if name.ends_with(".wants") || name.ends_with(".requires") {
                for w in sorted_dir(&e.path()) {
                    let wname = w.file_name().to_string_lossy().into_owned();
                    if wname.ends_with(".service") {
                        s.wanted.insert(wname);
                    }
                }
            } else if name.ends_with(".service") && !is_dir {
                s.units.entry(name).or_insert(path);
            }
        }
    }
    s
}

/// `getty@tty1.service` -> `getty@.service`. Templates themselves give `None`.
fn template_of(name: &str) -> Option<String> {
    let (prefix, rest) = name.split_once('@')?;
    let (instance, suffix) = rest.rsplit_once('.')?;
    (!instance.is_empty()).then(|| format!("{prefix}@.{suffix}"))
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Unit-file settings as `Section.Key -> values`, applying systemd's override rules.
#[derive(Default)]
struct Settings(HashMap<String, Vec<String>>);

impl Settings {
    fn apply(&mut self, text: &str) {
        let mut section = String::new();
        let mut pending = String::new();
        for raw in text.lines() {
            let line = raw.trim();
            if pending.is_empty() && (line.starts_with('#') || line.starts_with(';')) {
                continue;
            }
            if let Some(cont) = line.strip_suffix('\\') {
                pending.push_str(cont);
                pending.push(' ');
                continue;
            }
            pending.push_str(line);
            let full = std::mem::take(&mut pending);
            let full = full.trim();
            if let Some(s) = full.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                section = s.to_string();
            } else if let Some((k, v)) = full.split_once('=') {
                let (k, v) = (k.trim(), v.trim());
                let values = self.0.entry(format!("{section}.{k}")).or_default();
                if v.is_empty() {
                    values.clear();
                } else if is_list(k) {
                    values.push(v.to_string());
                } else {
                    *values = vec![v.to_string()];
                }
            }
        }
    }

    fn last(&self, key: &str) -> Option<&String> {
        self.0.get(key).and_then(|v| v.last())
    }

    fn all(&self, key: &str) -> &[String] {
        self.0.get(key).map(Vec::as_slice).unwrap_or_default()
    }

    fn has_install(&self) -> bool {
        self.0
            .iter()
            .any(|(k, v)| k.starts_with("Install.") && !v.is_empty())
    }
}

fn truthy(v: Option<&String>) -> bool {
    v.is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on"))
}

/// The executable an Exec*= line runs: special prefixes stripped, a bare name
/// looked up on the fixed search path under `root`.
fn exec_binary(root: &Path, cmd: &str) -> Option<String> {
    let cmd = cmd
        .trim_start_matches(['@', '-', ':', '+', '!'])
        .trim_start();
    let first = if let Some(rest) = cmd.strip_prefix('"') {
        rest.split('"').next()?
    } else {
        cmd.split_whitespace().next()?
    };
    if first.is_empty() {
        return None;
    }
    if first.starts_with('/') || first.contains('%') {
        return Some(first.to_string());
    }
    EXEC_SEARCH
        .iter()
        .map(|d| format!("/{d}/{first}"))
        .find(|p| under(root, p).is_file())
        .or_else(|| Some(first.to_string()))
}

fn writable(root: &Path, path: &str, ids: &Ids) -> Vec<String> {
    unix::resolve_in(root, path)
        .and_then(|p| unix::path_writable_by(&under(root, &p), ids).ok())
        .unwrap_or_default()
}

/// Describes one unit, or `None` for aliases and unreadable files.
fn describe(root: &Path, name: &str, scan: &Scan, ids: &Ids, sink: &Sink) -> Option<UnitObject> {
    let template = template_of(name);
    let file = scan
        .units
        .get(name)
        .or_else(|| template.as_ref().and_then(|t| scan.units.get(t)))?;
    let Some(resolved) = unix::resolve_in(root, file) else {
        sink.warn(|| format!("{file}: symlink loop"));
        return None;
    };
    let mut obj = UnitObject {
        name: name.to_string(),
        unit_path: resolved.clone(),
        ..Default::default()
    };
    if resolved == "/dev/null" {
        obj.start = "masked";
        obj.unit_path = file.clone();
        return Some(obj);
    }
    // A link under another name is an alias (dbus-org.*.service): the real unit
    // is reported under its own name.
    if basename(&resolved) != basename(file) {
        return None;
    }
    let text = match std::fs::read_to_string(under(root, &resolved)) {
        Ok(t) => t,
        Err(e) => {
            sink.warn(|| format!("{resolved}: {e}"));
            return None;
        }
    };
    let mut settings = Settings::default();
    settings.apply(&text);

    // Template drop-ins apply to every instance; the instance's own override them.
    let mut dropins: BTreeMap<&String, &String> = BTreeMap::new();
    for key in template.iter().map(String::as_str).chain([name]) {
        if let Some(confs) = scan.dropins.get(key) {
            dropins.extend(confs.iter());
        }
    }
    let mut unit_writable_by: BTreeSet<String> = writable(root, file, ids).into_iter().collect();
    for path in dropins.values() {
        let Some(real) = unix::resolve_in(root, path) else {
            continue;
        };
        if real == "/dev/null" {
            continue;
        }
        match std::fs::read_to_string(under(root, &real)) {
            Ok(t) => settings.apply(&t),
            Err(e) => sink.warn(|| format!("{real}: {e}")),
        }
        unit_writable_by.extend(writable(root, path, ids));
        obj.drop_ins.push(path.to_string());
    }
    obj.unit_writable_by = unit_writable_by.into_iter().collect();

    obj.start = if name.contains("@.") {
        "template"
    } else if scan.wanted.contains(name) {
        "enabled"
    } else if !settings.has_install() {
        "static"
    } else {
        "disabled"
    };
    obj.display_name = settings.last("Unit.Description").cloned();
    obj.r#type = Some(
        settings
            .last("Service.Type")
            .cloned()
            .unwrap_or_else(|| "simple".into()),
    );
    obj.account = Some(if truthy(settings.last("Service.DynamicUser")) {
        "dynamic".into()
    } else {
        settings
            .last("Service.User")
            .cloned()
            .unwrap_or_else(|| "root".into())
    });
    for key in EXEC_KEYS {
        for v in settings.all(&format!("Service.{key}")) {
            obj.commands.push(format!("{key}={v}"));
        }
    }
    obj.image_path = settings.all("Service.ExecStart").first().cloned();
    if let Some(bin) = obj.image_path.as_deref().and_then(|c| exec_binary(root, c)) {
        if !bin.contains('%') {
            match unix::resolve_in(root, &bin) {
                Some(real) if under(root, &real).is_file() => {
                    obj.binary_writable_by =
                        unix::path_writable_by(&under(root, &real), ids).unwrap_or_default();
                }
                _ => obj.binary_missing = true,
            }
        }
        obj.binary = Some(bin);
    }
    for key in HARDENING_KEYS {
        let v = settings.all(&format!("Service.{key}"));
        if !v.is_empty() {
            obj.hardening.insert(key.to_string(), v.join(" "));
        }
    }
    Some(obj)
}

/// Every unit worth a record: unit files plus enabled instances of templates.
fn names(scan: &Scan) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = scan.units.keys().cloned().collect();
    for w in &scan.wanted {
        if template_of(w).is_some_and(|t| scan.units.contains_key(&t)) {
            names.insert(w.clone());
        }
    }
    names
}

pub struct SystemdCollector {
    pub root: PathBuf,
}

impl Collector for SystemdCollector {
    fn name(&self) -> &'static str {
        "services"
    }

    fn collect(&self, sink: &Sink) -> Result<()> {
        let scan = scan(&self.root);
        if scan.units.is_empty() {
            anyhow::bail!("no systemd unit files found (is this a systemd system?)");
        }
        let ids = Ids::load(&self.root);
        for name in names(&scan) {
            if let Some(obj) = describe(&self.root, &name, &scan, &ids, sink) {
                sink.emit(Record::new(Kind::Service, name, &obj));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn write(root: &Path, path: &str, text: &str) {
        let p = under(root, path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    #[cfg(unix)]
    fn link(root: &Path, target: &str, path: &str) {
        let p = under(root, path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, p).unwrap();
    }

    fn collect(root: &Path) -> HashMap<String, Value> {
        let (tx, rx) = crossbeam_channel::unbounded();
        let sink = Sink::new(tx, false);
        SystemdCollector { root: root.into() }
            .collect(&sink)
            .unwrap();
        drop(sink);
        rx.iter().map(|r| (r.identity, r.data)).collect()
    }

    #[cfg(unix)]
    #[test]
    fn reads_units_dropins_and_enablement() {
        use serde_json::json;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let lib = "/usr/lib/systemd/system";
        write(root, "/usr/sbin/sshd", "bin");
        std::fs::set_permissions(
            under(root, "/usr/sbin/sshd"),
            std::fs::Permissions::from_mode(0o757),
        )
        .unwrap();
        write(
            root,
            &format!("{lib}/ssh.service"),
            "[Unit]\nDescription=OpenBSD Secure Shell server\n\n[Service]\n\
             ExecStartPre=/usr/sbin/sshd -t\nExecStart=/usr/sbin/sshd -D $SSHD_OPTS\n\
             ExecReload=/bin/kill -HUP $MAINPID\nType=notify\nNoNewPrivileges=yes\n\n\
             [Install]\nWantedBy=multi-user.target\nAlias=sshd.service\n",
        );
        // Enabled with an absolute link, which must resolve inside the fixture.
        link(
            root,
            &format!("{lib}/ssh.service"),
            "/etc/systemd/system/multi-user.target.wants/ssh.service",
        );
        link(
            root,
            &format!("{lib}/ssh.service"),
            "/etc/systemd/system/sshd.service",
        );
        // An admin drop-in replaces ExecStart and drops the hardening.
        write(
            root,
            "/etc/systemd/system/ssh.service.d/override.conf",
            "[Service]\nExecStart=\nExecStart=-sshd -D \\\n  -o X=1\nNoNewPrivileges=no\n",
        );
        write(
            root,
            &format!("{lib}/cups.service"),
            "[Service]\nExecStart=/usr/sbin/cupsd -l\n[Install]\nWantedBy=multi-user.target\n",
        );
        link(root, "/dev/null", "/etc/systemd/system/cups.service");
        write(
            root,
            &format!("{lib}/getty@.service"),
            "[Service]\nExecStart=-/sbin/agetty -o '-p -- \\\\u' %I $TERM\n[Install]\nWantedBy=getty.target\n",
        );
        link(
            root,
            &format!("{lib}/getty@.service"),
            "/etc/systemd/system/getty.target.wants/getty@tty1.service",
        );
        write(
            root,
            &format!("{lib}/helper.service"),
            "[Service]\nType=oneshot\nDynamicUser=yes\nExecStart=/opt/gone/helper\n",
        );
        write(
            root,
            "/usr/local/lib/systemd/system/helper.service",
            "[Service]\nUser=nobody\nExecStart=/opt/local/helper\n[Install]\nWantedBy=x.target\n",
        );

        let r = collect(root);
        let ssh = &r["ssh.service"];
        assert_eq!(ssh["start"], "enabled");
        assert_eq!(ssh["display_name"], "OpenBSD Secure Shell server");
        assert_eq!(ssh["type"], "notify");
        assert_eq!(ssh["account"], "root");
        assert_eq!(ssh["unit_path"], format!("{lib}/ssh.service"));
        assert_eq!(ssh["image_path"], "-sshd -D  -o X=1");
        assert_eq!(ssh["binary"], "/usr/sbin/sshd");
        assert_eq!(
            ssh["commands"],
            json!([
                "ExecStartPre=/usr/sbin/sshd -t",
                "ExecStart=-sshd -D  -o X=1",
                "ExecReload=/bin/kill -HUP $MAINPID"
            ])
        );
        assert_eq!(ssh["hardening"], json!({"NoNewPrivileges": "no"}));
        assert_eq!(
            ssh["drop_ins"],
            json!(["/etc/systemd/system/ssh.service.d/override.conf"])
        );
        let bw = ssh["binary_writable_by"].as_array().unwrap();
        assert!(bw.contains(&json!("everyone")), "{bw:?}");
        assert!(!r.contains_key("sshd.service"), "aliases are skipped");

        assert_eq!(r["cups.service"]["start"], "masked");
        assert!(r["cups.service"].get("binary").is_none());

        let tty = &r["getty@tty1.service"];
        assert_eq!(tty["start"], "enabled");
        assert_eq!(tty["binary"], "/sbin/agetty");
        assert_eq!(tty["binary_missing"], true);
        assert_eq!(r["getty@.service"]["start"], "template");

        // /usr/local wins over /usr/lib.
        let helper = &r["helper.service"];
        assert_eq!(helper["account"], "nobody");
        assert_eq!(helper["start"], "disabled");
        assert_eq!(
            helper["unit_path"],
            "/usr/local/lib/systemd/system/helper.service"
        );
    }

    #[test]
    fn settings_and_helpers() {
        let mut s = Settings::default();
        s.apply("[Service]\n# ExecStart=/no\nExecStart=/a\nExecStart=/b\nUser=x\nUser=y\n");
        assert_eq!(s.all("Service.ExecStart"), ["/a", "/b"]);
        assert_eq!(s.last("Service.User").unwrap(), "y");
        assert!(!s.has_install());
        s.apply("[Service]\nExecStart=\n[Install]\nWantedBy=\n");
        assert!(s.all("Service.ExecStart").is_empty());
        assert!(!s.has_install(), "an emptied WantedBy= is no [Install]");
        assert_eq!(template_of("getty@tty1.service").unwrap(), "getty@.service");
        assert_eq!(template_of("getty@.service"), None);
        assert_eq!(template_of("ssh.service"), None);
    }

    #[test]
    fn missing_systemd_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = crossbeam_channel::unbounded();
        let sink = Sink::new(tx, false);
        assert!(
            SystemdCollector {
                root: dir.path().into()
            }
            .collect(&sink)
            .is_err()
        );
    }

    #[test]
    fn fields_in_sync() {
        let obj = UnitObject {
            name: "a".into(),
            display_name: Some("d".into()),
            r#type: Some("simple".into()),
            start: "enabled",
            account: Some("root".into()),
            image_path: Some("/a".into()),
            binary: Some("/a".into()),
            binary_missing: true,
            binary_writable_by: vec!["x".into()],
            unit_path: "/u".into(),
            drop_ins: vec!["/d".into()],
            unit_writable_by: vec!["x".into()],
            commands: vec!["ExecStart=/a".into()],
            hardening: BTreeMap::from([("PrivateTmp".into(), "yes".into())]),
        };
        crate::collectors::assert_fields(&obj, FIELDS);
    }
}
