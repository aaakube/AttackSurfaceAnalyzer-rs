//! COM registrations: classes (machine 64/32-bit views and each loaded user's
//! classes), AppIDs and type libraries, with the server binaries described.
//!
//! Security-relevant facts are made explicit: service-hosted or run-as servers,
//! elevation-enabled classes (the COM elevation moniker auto-elevates them), and
//! per-user classes that shadow a machine class (COM hijacking: user registrations
//! win for that user's processes).

// Only constructed on Windows; compiled everywhere so the logic is unit-tested.
#![cfg_attr(not(windows), allow(dead_code))]

use super::binaries::{self, BinaryInfo};
use super::registry::{Registry, join, user_sids};
use super::{Collector, Sink, win};
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub const FIELDS: &[&str] = &[
    "type",
    "view",
    "user_sid",
    "id",
    "name",
    "progid",
    "inproc_server",
    "threading_model",
    "local_server",
    "treat_as",
    "appid",
    "elevation",
    "server",
    "server_missing",
    "server_signature",
    "server_writable_by",
    "shadows_machine",
    "local_service",
    "run_as",
    "dll_surrogate",
    "launch_permission",
    "access_permission",
    "versions",
];

#[derive(Serialize, Default)]
struct ComObject {
    r#type: &'static str,
    view: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_sid: Option<String>,
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    progid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inproc_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threading_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    treat_as: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    appid: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    elevation: bool,
    /// Resolved server binary (LocalServer32 executable, else InprocServer32 DLL).
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    server_missing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_signature: Option<win::Signature>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    server_writable_by: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    shadows_machine: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    run_as: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dll_surrogate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    launch_permission: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_permission: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    versions: BTreeMap<String, BTreeMap<String, String>>,
}

/// Where class registrations live: (view, identity prefix, key, wow64, user sid).
fn class_roots(reg: &dyn Registry) -> Vec<(&'static str, String, String, bool, Option<String>)> {
    let mut v = vec![
        (
            "64",
            "clsid".to_string(),
            r"HKLM\SOFTWARE\Classes\CLSID".to_string(),
            false,
            None,
        ),
        (
            "32",
            "clsid32".to_string(),
            r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID".to_string(),
            true,
            None,
        ),
    ];
    for sid in user_sids(reg) {
        v.push((
            "user",
            format!(r"user\{sid}\clsid"),
            format!(r"HKU\{sid}_Classes\CLSID"),
            false,
            Some(sid.clone()),
        ));
        v.push((
            "user32",
            format!(r"user\{sid}\clsid32"),
            format!(r"HKU\{sid}_Classes\WOW6432Node\CLSID"),
            true,
            Some(sid),
        ));
    }
    v
}

pub struct ComCollector<R: Registry> {
    pub reg: R,
    pub signatures: bool,
    pub threads: usize,
}

impl<R: Registry> Collector for ComCollector<R> {
    fn name(&self) -> &'static str {
        "com"
    }

    fn collect(&self, sink: &Sink) -> Result<()> {
        let reg = &self.reg;
        let mut found: Vec<(String, ComObject)> = Vec::new();
        let mut machine_ids: HashSet<String> = HashSet::new();

        for (view, prefix, root, wow64, sid) in class_roots(reg) {
            let Some(ids) = reg.subkeys(&root) else {
                continue;
            };
            for id in ids {
                let key = join(&root, &id);
                let subs: HashSet<String> = reg
                    .subkeys(&key)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|s| s.to_lowercase())
                    .collect();
                let has = |s: &str| subs.contains(&s.to_lowercase());
                let mut obj = ComObject {
                    r#type: "class",
                    view,
                    user_sid: sid.clone(),
                    name: reg.string(&key, ""),
                    appid: reg.string(&key, "AppID"),
                    ..Default::default()
                };
                if has("InprocServer32") {
                    let k = join(&key, "InprocServer32");
                    obj.inproc_server = reg.string(&k, "");
                    obj.threading_model = reg.string(&k, "ThreadingModel");
                }
                if has("LocalServer32") {
                    obj.local_server = reg.string(&join(&key, "LocalServer32"), "");
                }
                if has("ProgID") {
                    obj.progid = reg.string(&join(&key, "ProgID"), "");
                }
                if has("TreatAs") {
                    obj.treat_as = reg.string(&join(&key, "TreatAs"), "");
                }
                if has("Elevation") {
                    obj.elevation = reg
                        .value(&join(&key, "Elevation"), "Enabled")
                        .and_then(|v| v.as_num())
                        == Some(1);
                }
                obj.server = match (&obj.local_server, &obj.inproc_server) {
                    (Some(cmd), _) => binaries::parse_command(cmd).0,
                    (None, Some(dll)) => Some(binaries::resolve_dll(dll, wow64)),
                    _ => None,
                };
                if sid.is_none() && view == "64" {
                    machine_ids.insert(id.to_lowercase());
                }
                obj.id = id.clone();
                found.push((format!(r"{prefix}\{id}"), obj));
            }
        }
        // A user class with the same CLSID as a machine class overrides it for that user.
        for (_, obj) in found.iter_mut().filter(|(_, o)| o.user_sid.is_some()) {
            obj.shadows_machine = machine_ids.contains(&obj.id.to_lowercase());
        }

        let paths: BTreeSet<String> = found.iter().filter_map(|(_, o)| o.server.clone()).collect();
        let info: HashMap<String, BinaryInfo> =
            binaries::describe(paths, self.threads, self.signatures);
        for (identity, mut obj) in found {
            if let Some(s) = &obj.server {
                let i = info.get(&s.to_lowercase()).cloned().unwrap_or_default();
                obj.server_missing = !i.exists;
                obj.server_signature = i.signature;
                obj.server_writable_by = i.writable_by;
            }
            sink.emit(Record::new(Kind::Com, identity, &obj));
        }

        self.appids(sink);
        self.typelibs(sink);
        Ok(())
    }
}

impl<R: Registry> ComCollector<R> {
    fn appids(&self, sink: &Sink) {
        let reg = &self.reg;
        let root = r"HKLM\SOFTWARE\Classes\AppID";
        for id in reg.subkeys(root).unwrap_or_default() {
            let key = join(root, &id);
            let values: HashMap<String, super::registry::RegValue> = reg
                .values(&key)
                .unwrap_or_default()
                .into_iter()
                .map(|(k, v)| (k.to_lowercase(), v))
                .collect();
            let text = |n: &str| match values.get(&n.to_lowercase()) {
                Some(super::registry::RegValue::Str(s)) if !s.is_empty() => Some(s.clone()),
                _ => None,
            };
            // Security descriptors are binary; their (hex or digest) form still
            // changes whenever the permissions do.
            let blob = |n: &str| {
                values.get(&n.to_lowercase()).map(|v| match v {
                    super::registry::RegValue::Bin(b) => b.clone(),
                    other => format!("{other:?}"),
                })
            };
            let obj = ComObject {
                r#type: "appid",
                view: "64",
                id: id.clone(),
                name: text(super::registry::DEFAULT_VALUE),
                appid: text("AppID"),
                local_service: text("LocalService"),
                run_as: text("RunAs"),
                dll_surrogate: values.get("dllsurrogate").map(|v| match v {
                    super::registry::RegValue::Str(s) if !s.is_empty() => s.clone(),
                    _ => "(default surrogate)".into(),
                }),
                launch_permission: blob("LaunchPermission"),
                access_permission: blob("AccessPermission"),
                ..Default::default()
            };
            sink.emit(Record::new(Kind::Com, format!(r"appid\{id}"), &obj));
        }
    }

    fn typelibs(&self, sink: &Sink) {
        let reg = &self.reg;
        for (prefix, root) in [
            ("typelib", r"HKLM\SOFTWARE\Classes\TypeLib"),
            ("typelib32", r"HKLM\SOFTWARE\WOW6432Node\Classes\TypeLib"),
        ] {
            for id in reg.subkeys(root).unwrap_or_default() {
                let key = join(root, &id);
                let mut versions = BTreeMap::new();
                let mut name = None;
                for ver in reg.subkeys(&key).unwrap_or_default() {
                    let vkey = join(&key, &ver);
                    let mut entry = BTreeMap::new();
                    if let Some(n) = reg.string(&vkey, "") {
                        name.get_or_insert(n.clone());
                        entry.insert("name".to_string(), n);
                    }
                    // <ver>\<lcid>\win32|win64 -> path
                    for lcid in reg.subkeys(&vkey).unwrap_or_default() {
                        if !lcid.chars().all(|c| c.is_ascii_hexdigit()) {
                            continue;
                        }
                        for plat in reg.subkeys(&join(&vkey, &lcid)).unwrap_or_default() {
                            if let Some(p) = reg.string(&join(&join(&vkey, &lcid), &plat), "") {
                                entry.insert(plat.to_lowercase(), p);
                            }
                        }
                    }
                    versions.insert(ver, entry);
                }
                let obj = ComObject {
                    r#type: "typelib",
                    view: if prefix == "typelib" { "64" } else { "32" },
                    id: id.clone(),
                    name,
                    versions,
                    ..Default::default()
                };
                sink.emit(Record::new(Kind::Com, format!(r"{prefix}\{id}"), &obj));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::registry::{MemRegistry, RegValue};

    #[test]
    fn collects_classes_appids_typelibs_and_hijacks() {
        // SAFETY: same value as the other tests that set it.
        unsafe { std::env::set_var("SystemRoot", r"C:\Windows") };
        let s = |v: &str| RegValue::Str(v.into());
        let mut reg = MemRegistry::default();
        let elev = r"HKLM\SOFTWARE\Classes\CLSID\{708860E0-F641-4611-8895-7D867DD3675B}";
        reg.key(
            elev,
            &[
                ("(default)", s("GoogleChromeElevationService")),
                ("AppID", s("{708860E0-F641-4611-8895-7D867DD3675B}")),
            ],
        );
        reg.key(
            &join(elev, "LocalServer32"),
            &[(
                "(default)",
                s(r#""C:\Program Files\Google\elevation_service.exe""#),
            )],
        );
        reg.key(&join(elev, "Elevation"), &[("Enabled", RegValue::Num(1))]);
        let shell = r"HKLM\SOFTWARE\Classes\CLSID\{AAAA}";
        reg.key(
            &join(shell, "InprocServer32"),
            &[
                ("(default)", s("shell32.dll")),
                ("ThreadingModel", s("Apartment")),
            ],
        );
        reg.key(
            r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{BBBB}\InprocServer32",
            &[("(default)", s("x.dll"))],
        );
        let sid = "S-1-5-21-1-2-3-1001";
        reg.key(&format!(r"HKU\{sid}\Software"), &[]);
        reg.key(
            &format!(r"HKU\{sid}_Classes\CLSID\{{AAAA}}\InprocServer32"),
            &[("(default)", s(r"C:\Users\x\AppData\evil.dll"))],
        );
        reg.key(
            r"HKLM\SOFTWARE\Classes\AppID\{708860E0-F641-4611-8895-7D867DD3675B}",
            &[
                ("LocalService", s("GoogleChromeElevationService")),
                ("LaunchPermission", RegValue::Bin("hex:0102".into())),
            ],
        );
        reg.key(
            r"HKLM\SOFTWARE\Classes\TypeLib\{TTTT}\1.0\0\win64",
            &[("(default)", s(r"C:\x\t.dll"))],
        );
        reg.key(
            r"HKLM\SOFTWARE\Classes\TypeLib\{TTTT}\1.0",
            &[("(default)", s("Chrome TypeLib"))],
        );

        let (tx, rx) = crossbeam_channel::unbounded();
        let sink = Sink::new(tx, false);
        ComCollector {
            reg,
            signatures: false,
            threads: 2,
        }
        .collect(&sink)
        .unwrap();
        drop(sink);
        let r: BTreeMap<String, serde_json::Value> =
            rx.iter().map(|r| (r.identity, r.data)).collect();

        let e = &r[r"clsid\{708860E0-F641-4611-8895-7D867DD3675B}"];
        assert_eq!(e["elevation"], true);
        assert_eq!(
            e["server"],
            r"C:\Program Files\Google\elevation_service.exe"
        );
        assert_eq!(
            r[r"clsid\{AAAA}"]["server"],
            r"C:\Windows\System32\shell32.dll"
        );
        assert_eq!(r[r"clsid32\{BBBB}"]["server"], r"C:\Windows\SysWOW64\x.dll");
        let hijack = &r[&format!(r"user\{sid}\clsid\{{AAAA}}")];
        assert_eq!(hijack["shadows_machine"], true);
        assert_eq!(hijack["view"], "user");
        let a = &r[r"appid\{708860E0-F641-4611-8895-7D867DD3675B}"];
        assert_eq!(a["local_service"], "GoogleChromeElevationService");
        assert_eq!(a["launch_permission"], "hex:0102");
        let t = &r[r"typelib\{TTTT}"];
        assert_eq!(t["name"], "Chrome TypeLib");
        assert_eq!(t["versions"]["1.0"]["win64"], r"C:\x\t.dll");
    }

    #[test]
    fn fields_in_sync() {
        let s = || Some(String::new());
        let obj = ComObject {
            r#type: "class",
            view: "64",
            user_sid: s(),
            id: String::new(),
            name: s(),
            progid: s(),
            inproc_server: s(),
            threading_model: s(),
            local_server: s(),
            treat_as: s(),
            appid: s(),
            elevation: true,
            server: s(),
            server_missing: true,
            server_signature: Some(win::Signature {
                status: "valid".into(),
                source: None,
                signer: None,
            }),
            server_writable_by: vec!["Users".into()],
            shadows_machine: true,
            local_service: s(),
            run_as: s(),
            dll_surrogate: s(),
            launch_permission: s(),
            access_permission: s(),
            versions: BTreeMap::from([("1.0".into(), BTreeMap::new())]),
        };
        crate::collectors::assert_fields(&obj, FIELDS);
    }
}
