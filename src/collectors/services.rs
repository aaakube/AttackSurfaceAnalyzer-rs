//! Services and drivers, read from `HKLM\SYSTEM\CurrentControlSet\Services` (the
//! service manager's own database), enriched with what their binaries are and who
//! can tamper with them. Runtime state (running/stopped) is deliberately left out:
//! it flips constantly and is not attack surface.

// Only constructed on Windows; compiled everywhere so the logic is unit-tested.
#![cfg_attr(not(windows), allow(dead_code))]

use super::binaries::{self, BinaryInfo};
use super::registry::{Registry, join};
use super::{Collector, Sink, win};
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};

pub const SERVICES_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services";

pub const FIELDS: &[&str] = &[
    "name",
    "display_name",
    "type",
    "start",
    "delayed_start",
    "account",
    "image_path",
    "binary",
    "unquoted_path",
    "service_dll",
    "failure_command",
    "binary_missing",
    "binary_signature",
    "binary_writable_by",
    "key_writable_by",
];

#[derive(Serialize, Default)]
struct ServiceObject {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    r#type: &'static str,
    start: &'static str,
    delayed_start: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image_path: Option<String>,
    /// Resolved executable or driver file.
    #[serde(skip_serializing_if = "Option::is_none")]
    binary: Option<String>,
    unquoted_path: bool,
    /// For svchost-hosted services, the DLL actually loaded.
    #[serde(skip_serializing_if = "Option::is_none")]
    service_dll: Option<String>,
    /// Program run when the service fails (a persistence spot).
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_command: Option<String>,
    binary_missing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    binary_signature: Option<win::Signature>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    binary_writable_by: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    key_writable_by: Vec<String>,
}

const TYPE_KERNEL_DRIVER: u64 = 0x1;
const TYPE_FS_DRIVER: u64 = 0x2;
const TYPE_ADAPTER: u64 = 0x4;
const TYPE_RECOGNIZER: u64 = 0x8;
const TYPE_OWN: u64 = 0x10;
const TYPE_SHARE: u64 = 0x20;
const TYPE_USER_TEMPLATE: u64 = 0x40;
const TYPE_USER_INSTANCE: u64 = 0x80;

fn type_name(t: u64) -> &'static str {
    if t & TYPE_KERNEL_DRIVER != 0 {
        "kernel_driver"
    } else if t & TYPE_FS_DRIVER != 0 {
        "fs_driver"
    } else if t & (TYPE_ADAPTER | TYPE_RECOGNIZER) != 0 {
        "driver"
    } else if t & TYPE_USER_TEMPLATE != 0 {
        "user_service"
    } else if t & TYPE_SHARE != 0 {
        "shared_process"
    } else if t & TYPE_OWN != 0 {
        "own_process"
    } else {
        "other"
    }
}

fn is_driver(t: u64) -> bool {
    t & (TYPE_KERNEL_DRIVER | TYPE_FS_DRIVER | TYPE_ADAPTER | TYPE_RECOGNIZER) != 0
}

fn start_name(s: u64) -> &'static str {
    match s {
        0 => "boot",
        1 => "system",
        2 => "auto",
        3 => "manual",
        4 => "disabled",
        _ => "unknown",
    }
}

pub struct ServicesCollector<R: Registry> {
    pub reg: R,
    pub signatures: bool,
    pub threads: usize,
}

impl<R: Registry> Collector for ServicesCollector<R> {
    fn name(&self) -> &'static str {
        "services"
    }

    fn collect(&self, sink: &Sink) -> Result<()> {
        let names = self
            .reg
            .subkeys(SERVICES_KEY)
            .ok_or_else(|| anyhow::anyhow!("cannot read {SERVICES_KEY}"))?;
        let mut found: Vec<(Kind, ServiceObject)> = Vec::new();
        for name in names {
            let key = join(SERVICES_KEY, &name);
            let Some(ty) = self.reg.value(&key, "Type").and_then(|v| v.as_num()) else {
                continue; // configuration-only key, not a service
            };
            // Per-logon instances of user services (e.g. CDPUserSvc_4a7b1) get a new
            // suffix on every logon; their template is collected instead.
            if ty & TYPE_USER_INSTANCE != 0 {
                continue;
            }
            let start = self
                .reg
                .value(&key, "Start")
                .and_then(|v| v.as_num())
                .unwrap_or(3);
            let image_path = self.reg.string(&key, "ImagePath");
            let (binary, unquoted) = match &image_path {
                Some(p) => binaries::parse_command(p),
                // Drivers without ImagePath load System32\drivers\<name>.sys.
                None if is_driver(ty) => (
                    Some(binaries::resolve(&format!(r"System32\drivers\{name}.sys"))),
                    false,
                ),
                None => (None, false),
            };
            let obj = ServiceObject {
                display_name: self.reg.string(&key, "DisplayName"),
                r#type: type_name(ty),
                start: start_name(start),
                delayed_start: start == 2
                    && self
                        .reg
                        .value(&key, "DelayedAutostart")
                        .and_then(|v| v.as_num())
                        == Some(1),
                account: self.reg.string(&key, "ObjectName"),
                // Drivers' paths have no arguments; a space there is not exploitable.
                unquoted_path: unquoted && !is_driver(ty),
                image_path,
                binary,
                service_dll: self
                    .reg
                    .string(&join(&key, "Parameters"), "ServiceDll")
                    .map(|d| binaries::resolve(&super::registry::expand_env(&d))),
                failure_command: self.reg.string(&key, "FailureCommand"),
                key_writable_by: self.reg.writable_by(&key),
                name,
                ..Default::default()
            };
            found.push((
                if is_driver(ty) {
                    Kind::Driver
                } else {
                    Kind::Service
                },
                obj,
            ));
        }

        let paths: BTreeSet<String> = found.iter().filter_map(|(_, o)| o.binary.clone()).collect();
        let info: HashMap<String, BinaryInfo> =
            binaries::describe(paths, self.threads, self.signatures);
        for (kind, mut obj) in found {
            if let Some(b) = &obj.binary {
                let i = info.get(&b.to_lowercase()).cloned().unwrap_or_default();
                obj.binary_missing = !i.exists;
                obj.binary_signature = i.signature;
                obj.binary_writable_by = i.writable_by;
            }
            sink.emit(Record::new(kind, obj.name.clone(), &obj));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::registry::{MemRegistry, RegValue};

    #[test]
    fn collects_services_and_drivers() {
        // SAFETY: same value as the other tests that set it.
        unsafe { std::env::set_var("SystemRoot", r"C:\Windows") };
        let mut reg = MemRegistry::default();
        let s = |v: &str| RegValue::Str(v.into());
        let n = RegValue::Num;
        reg.key(
            &join(SERVICES_KEY, "GoogleUpdater"),
            &[
                ("Type", n(0x10)),
                ("Start", n(2)),
                ("DelayedAutostart", n(1)),
                (
                    "ImagePath",
                    s(r#""C:\Program Files (x86)\Google\updater.exe" --system"#),
                ),
                ("ObjectName", s("LocalSystem")),
                ("DisplayName", s("Google Updater")),
            ],
        );
        reg.key(
            &join(SERVICES_KEY, "Vuln"),
            &[
                ("Type", n(0x10)),
                ("Start", n(3)),
                ("ImagePath", s(r"C:\Program Files\Vendor App\svc.exe")),
            ],
        );
        reg.key(
            &join(SERVICES_KEY, r"Netsvc\Parameters"),
            &[("ServiceDll", s(r"%SystemRoot%\System32\netsvc.dll"))],
        );
        reg.key(
            &join(SERVICES_KEY, "Netsvc"),
            &[
                ("Type", n(0x20)),
                ("Start", n(2)),
                (
                    "ImagePath",
                    s(r"%SystemRoot%\System32\svchost.exe -k netsvcs"),
                ),
            ],
        );
        reg.key(
            &join(SERVICES_KEY, "disk"),
            &[("Type", n(1)), ("Start", n(0))],
        );
        reg.key(
            &join(SERVICES_KEY, "CDPUserSvc_4a7b1"),
            &[("Type", n(0xe0)), ("Start", n(2))],
        );
        reg.key(&join(SERVICES_KEY, ".NET Data"), &[("Foo", n(1))]);

        let c = ServicesCollector {
            reg,
            signatures: false,
            threads: 2,
        };
        let (tx, rx) = crossbeam_channel::unbounded();
        let sink = Sink::new(tx, false);
        c.collect(&sink).unwrap();
        drop(sink);
        let recs: HashMap<String, (Kind, serde_json::Value)> =
            rx.iter().map(|r| (r.identity, (r.kind, r.data))).collect();

        assert_eq!(
            recs.len(),
            4,
            "user-service instance and config-only key skipped"
        );
        let g = &recs["GoogleUpdater"].1;
        assert_eq!(g["start"], "auto");
        assert_eq!(g["delayed_start"], true);
        assert_eq!(g["binary"], r"C:\Program Files (x86)\Google\updater.exe");
        assert_eq!(g["unquoted_path"], false);
        assert_eq!(
            g["binary_missing"], true,
            "path does not exist on the test host"
        );
        assert_eq!(recs["Vuln"].1["unquoted_path"], true);
        assert_eq!(
            recs["Netsvc"].1["service_dll"],
            r"C:\Windows\System32\netsvc.dll"
        );
        assert_eq!(recs["disk"].0, Kind::Driver);
        assert_eq!(
            recs["disk"].1["binary"],
            r"C:\Windows\System32\drivers\disk.sys"
        );
        assert_eq!(recs["disk"].1["start"], "boot");
    }

    #[test]
    fn fields_in_sync() {
        let obj = ServiceObject {
            display_name: Some(String::new()),
            account: Some(String::new()),
            image_path: Some(String::new()),
            binary: Some(String::new()),
            service_dll: Some(String::new()),
            failure_command: Some(String::new()),
            binary_signature: Some(win::Signature {
                status: "valid".into(),
                source: None,
                signer: None,
            }),
            binary_writable_by: vec!["Users".into()],
            key_writable_by: vec!["Users".into()],
            ..Default::default()
        };
        crate::collectors::assert_fields(&obj, FIELDS);
    }
}
