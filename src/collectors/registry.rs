//! Registry access shared by the services, firewall, COM and registry collectors,
//! plus the registry collector itself (persistence and policy locations).
//!
//! Paths are written `HKLM\SOFTWARE\...` or `HKU\<sid>\...` and always address the
//! native (64-bit) view; the 32-bit view is reached through its explicit
//! `WOW6432Node` path, so both appear under stable identities.

// Only constructed on Windows; compiled everywhere so the logic is unit-tested.
#![cfg_attr(not(windows), allow(dead_code))]

use super::{Collector, Sink};
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;

/// A registry value, decoded for JSON: strings stay strings, multi-strings become
/// lists, numbers become numbers and binary data becomes hex (or a digest if large).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum RegValue {
    Str(String),
    Multi(Vec<String>),
    Num(u64),
    Bin(String),
}

impl RegValue {
    pub fn as_num(&self) -> Option<u64> {
        match self {
            RegValue::Num(n) => Some(*n),
            _ => None,
        }
    }
}

/// Binary values longer than this are summarized by length and hash.
const MAX_BINARY: usize = 256;

pub fn decode(kind: u32, data: &[u8]) -> RegValue {
    let utf16 = |d: &[u8]| -> Vec<u16> {
        d.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect()
    };
    match kind {
        // REG_SZ, REG_EXPAND_SZ, REG_LINK
        1 | 2 | 6 => {
            let w = utf16(data);
            let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
            RegValue::Str(String::from_utf16_lossy(&w[..end]))
        }
        // REG_MULTI_SZ
        7 => RegValue::Multi(
            utf16(data)
                .split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .map(String::from_utf16_lossy)
                .collect(),
        ),
        // REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_QWORD
        4 if data.len() >= 4 => {
            RegValue::Num(u32::from_le_bytes(data[..4].try_into().unwrap()) as u64)
        }
        5 if data.len() >= 4 => {
            RegValue::Num(u32::from_be_bytes(data[..4].try_into().unwrap()) as u64)
        }
        11 if data.len() >= 8 => RegValue::Num(u64::from_le_bytes(data[..8].try_into().unwrap())),
        _ if data.len() > MAX_BINARY => RegValue::Bin(format!(
            "hex[{} bytes, blake3 {}]",
            data.len(),
            &blake3::hash(data).to_hex()[..16]
        )),
        _ => RegValue::Bin(format!(
            "hex:{}",
            data.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )),
    }
}

/// Read access to the registry. `None` means the key is missing or unreadable.
pub trait Registry: Sync {
    fn subkeys(&self, path: &str) -> Option<Vec<String>>;
    fn values(&self, path: &str) -> Option<Vec<(String, RegValue)>>;
    /// Low-privileged principals that can modify the key.
    fn writable_by(&self, _path: &str) -> Vec<String> {
        Vec::new()
    }

    /// A named value; `""` means the key's default value.
    fn value(&self, path: &str, name: &str) -> Option<RegValue> {
        let name = if name.is_empty() { DEFAULT_VALUE } else { name };
        self.values(path)?
            .into_iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }
    fn string(&self, path: &str, name: &str) -> Option<String> {
        match self.value(path, name)? {
            RegValue::Str(s) if !s.is_empty() => Some(s),
            _ => None,
        }
    }
}

/// The name a key's unnamed value is reported under.
pub const DEFAULT_VALUE: &str = "(default)";

pub fn join(a: &str, b: &str) -> String {
    format!("{a}\\{b}")
}

/// Expands `%VAR%` references from the process environment (unknown ones are kept).
pub fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) if end > 0 => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(v) => out.push_str(&v),
                    Err(_) => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Loaded user hives under HKU: real user SIDs, without the `_Classes` companions.
pub fn user_sids(reg: &dyn Registry) -> Vec<String> {
    reg.subkeys("HKU")
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.starts_with("S-1-5-21-") && !s.ends_with("_Classes"))
        .collect()
}

// ------------------------------------------------------------------ Windows

#[cfg(windows)]
pub use win_impl::WinRegistry;

#[cfg(windows)]
mod win_impl {
    use super::{RegValue, Registry, decode};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_64KEY, RegCloseKey,
        RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW,
    };

    pub struct WinRegistry;

    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open(path: &str) -> Option<Key> {
        let (root, sub) = path.split_once('\\').unwrap_or((path, ""));
        let root = match root {
            "HKLM" => HKEY_LOCAL_MACHINE,
            "HKU" => HKEY_USERS,
            _ => return None,
        };
        let w: Vec<u16> = sub.encode_utf16().chain(std::iter::once(0)).collect();
        let mut h: HKEY = null_mut();
        let rc = unsafe { RegOpenKeyExW(root, w.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut h) };
        (rc == ERROR_SUCCESS).then_some(Key(h))
    }

    struct Info {
        subkeys: u32,
        max_subkey: u32,
        values: u32,
        max_name: u32,
        max_data: u32,
    }

    fn info(k: &Key) -> Option<Info> {
        let mut i = Info {
            subkeys: 0,
            max_subkey: 0,
            values: 0,
            max_name: 0,
            max_data: 0,
        };
        let rc = unsafe {
            RegQueryInfoKeyW(
                k.0,
                null_mut(),
                null_mut(),
                null(),
                &mut i.subkeys,
                &mut i.max_subkey,
                null_mut(),
                &mut i.values,
                &mut i.max_name,
                &mut i.max_data,
                null_mut(),
                null_mut(),
            )
        };
        (rc == ERROR_SUCCESS).then_some(i)
    }

    impl Registry for WinRegistry {
        fn subkeys(&self, path: &str) -> Option<Vec<String>> {
            let k = open(path)?;
            let i = info(&k)?;
            let mut out = Vec::with_capacity(i.subkeys as usize);
            let mut buf = vec![0u16; i.max_subkey as usize + 1];
            for idx in 0..i.subkeys {
                let mut len = buf.len() as u32;
                let rc = unsafe {
                    RegEnumKeyExW(
                        k.0,
                        idx,
                        buf.as_mut_ptr(),
                        &mut len,
                        null(),
                        null_mut(),
                        null_mut(),
                        null_mut(),
                    )
                };
                if rc == ERROR_SUCCESS {
                    out.push(String::from_utf16_lossy(&buf[..len as usize]));
                }
            }
            out.sort_by_key(|s| s.to_lowercase());
            Some(out)
        }

        fn values(&self, path: &str) -> Option<Vec<(String, RegValue)>> {
            let k = open(path)?;
            let i = info(&k)?;
            let mut out = Vec::with_capacity(i.values as usize);
            let mut name = vec![0u16; i.max_name as usize + 1];
            let mut data = vec![0u8; i.max_data as usize + 2];
            for idx in 0..i.values {
                let mut nlen = name.len() as u32;
                let mut dlen = data.len() as u32;
                let mut kind = 0u32;
                let rc = unsafe {
                    RegEnumValueW(
                        k.0,
                        idx,
                        name.as_mut_ptr(),
                        &mut nlen,
                        null(),
                        &mut kind,
                        data.as_mut_ptr(),
                        &mut dlen,
                    )
                };
                if rc == ERROR_SUCCESS {
                    let n = String::from_utf16_lossy(&name[..nlen as usize]);
                    let n = if n.is_empty() {
                        super::DEFAULT_VALUE.to_string()
                    } else {
                        n
                    };
                    out.push((n, decode(kind, &data[..dlen as usize])));
                }
            }
            out.sort_by_key(|(n, _)| n.to_lowercase());
            Some(out)
        }

        fn writable_by(&self, path: &str) -> Vec<String> {
            crate::collectors::win::key_writable_by(path)
        }
    }
}

// ------------------------------------------------------------------ test double

/// In-memory registry for unit tests (and for collecting from an exported image).
#[cfg(test)]
#[derive(Default)]
pub struct MemRegistry {
    keys: BTreeMap<String, MemKey>,
}

/// A fake key: its values and subkey names.
#[cfg(test)]
type MemKey = (Vec<(String, RegValue)>, Vec<String>);

#[cfg(test)]
impl MemRegistry {
    /// Adds a key (and its ancestors) with values.
    pub fn key(&mut self, path: &str, values: &[(&str, RegValue)]) -> &mut Self {
        let parts: Vec<&str> = path.split('\\').collect();
        for i in 1..=parts.len() {
            self.keys.entry(parts[..i].join("\\")).or_default();
            if i > 1 {
                let parent = self.keys.get_mut(&parts[..i - 1].join("\\")).unwrap();
                if !parent
                    .1
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(parts[i - 1]))
                {
                    parent.1.push(parts[i - 1].to_string());
                }
            }
        }
        let entry = self.keys.get_mut(path).unwrap();
        entry
            .0
            .extend(values.iter().map(|(n, v)| (n.to_string(), v.clone())));
        self
    }

    fn find(&self, path: &str) -> Option<&MemKey> {
        self.keys
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(path))
            .map(|(_, v)| v)
    }
}

#[cfg(test)]
impl Registry for MemRegistry {
    fn subkeys(&self, path: &str) -> Option<Vec<String>> {
        let mut s = self.find(path)?.1.clone();
        s.sort_by_key(|x| x.to_lowercase());
        Some(s)
    }
    fn values(&self, path: &str) -> Option<Vec<(String, RegValue)>> {
        Some(self.find(path)?.0.clone())
    }
}

// ------------------------------------------------------------------ collector

/// A registry location to snapshot: every key down to `depth` levels below `path`
/// becomes one record with its values. Keys at the depth limit also list their
/// subkey names, so new children still show up.
pub struct Location {
    pub path: String,
    pub depth: u32,
}

fn loc(path: &str, depth: u32) -> Location {
    Location {
        path: path.to_string(),
        depth,
    }
}

/// Persistence, injection and policy locations (the "autoruns" set), in both views
/// where applicable, plus each loaded user's Run keys.
pub fn default_locations(reg: &dyn Registry) -> Vec<Location> {
    let mut v = vec![
        // Top-level vendor keys: a new product shows up as a new subkey name.
        loc(r"HKLM\SOFTWARE", 0),
        loc(r"HKLM\SOFTWARE\WOW6432Node", 0),
        loc(r"HKLM\SOFTWARE\Policies", 8),
        loc(r"HKLM\SOFTWARE\WOW6432Node\Policies", 8),
        loc(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            1,
        ),
        loc(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            0,
        ),
        loc(
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
            0,
        ),
        loc(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            1,
        ),
        loc(
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            1,
        ),
        loc(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
            1,
        ),
        loc(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList",
            0,
        ),
        loc(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
            1,
        ),
        loc(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjectDelayLoad",
            0,
        ),
        loc(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjects",
            1,
        ),
        loc(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
            0,
        ),
        loc(
            r"HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components",
            1,
        ),
        loc(
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components",
            1,
        ),
        loc(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            1,
        ),
        loc(
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            1,
        ),
        loc(r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager", 0),
        loc(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
            0,
        ),
        loc(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls",
            0,
        ),
        loc(r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", 0),
        loc(
            r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders",
            1,
        ),
        loc(r"HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors", 1),
        loc(
            r"HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order",
            0,
        ),
        loc(r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server", 0),
        loc(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            0,
        ),
    ];
    for view in [r"HKLM\SOFTWARE", r"HKLM\SOFTWARE\WOW6432Node"] {
        for k in [
            "Run",
            "RunOnce",
            "RunOnceEx",
            "RunServices",
            "Policies\\Explorer\\Run",
        ] {
            v.push(loc(
                &format!(r"{view}\Microsoft\Windows\CurrentVersion\{k}"),
                1,
            ));
        }
    }
    for sid in user_sids(reg) {
        for k in ["Run", "RunOnce", "Policies\\Explorer\\Run"] {
            v.push(loc(
                &format!(r"HKU\{sid}\SOFTWARE\Microsoft\Windows\CurrentVersion\{k}"),
                1,
            ));
        }
        v.push(loc(
            &format!(r"HKU\{sid}\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
            0,
        ));
        v.push(loc(&format!(r"HKU\{sid}\SOFTWARE\Policies"), 8));
    }
    v
}

pub const FIELDS: &[&str] = &["path", "hive", "values", "subkeys", "writable_by"];

#[derive(Serialize)]
struct KeyObject {
    path: String,
    hive: &'static str,
    values: BTreeMap<String, RegValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subkeys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    writable_by: Vec<String>,
}

pub struct RegistryCollector<R: Registry> {
    pub reg: R,
    /// Extra locations (`--registry-key`), walked after the defaults.
    pub locations: Vec<Location>,
    /// Walk the built-in persistence and policy locations too.
    pub defaults: bool,
}

/// Parses a `--registry-key` argument: `KEY` or `KEY:DEPTH` (subkey levels, default
/// 0), with `HKEY_LOCAL_MACHINE`/`HKEY_USERS` spelled out or abbreviated. `HKCU\X`
/// means `X` in every loaded user hive, like the built-in per-user locations.
pub fn parse_location(arg: &str, reg: &dyn Registry) -> Result<Vec<Location>, String> {
    let (path, depth) = match arg.rsplit_once(':') {
        Some((p, d)) if !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()) => (
            p,
            d.parse::<u32>()
                .map_err(|_| format!("bad depth in '{arg}'"))?,
        ),
        _ => (arg, 0),
    };
    if depth > 16 {
        return Err(format!("depth {depth} in '{arg}' is too deep (at most 16)"));
    }
    let path = path.trim().trim_end_matches('\\');
    let (root, rest) = path.split_once('\\').unwrap_or((path, ""));
    let join_rest = |base: &str| {
        if rest.is_empty() {
            base.to_string()
        } else {
            format!(r"{base}\{rest}")
        }
    };
    Ok(match root.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => vec![loc(&join_rest("HKLM"), depth)],
        "HKU" | "HKEY_USERS" => vec![loc(&join_rest("HKU"), depth)],
        "HKCU" | "HKEY_CURRENT_USER" => user_sids(reg)
            .into_iter()
            .map(|sid| loc(&join_rest(&format!(r"HKU\{sid}")), depth))
            .collect(),
        "HKCR" | "HKEY_CLASSES_ROOT" => {
            vec![loc(&join_rest(r"HKLM\SOFTWARE\Classes"), depth)]
        }
        _ => {
            return Err(format!(
                "'{arg}': registry keys start with HKLM, HKU, HKCU or HKCR"
            ));
        }
    })
}

impl<R: Registry> Collector for RegistryCollector<R> {
    fn name(&self) -> &'static str {
        "registry"
    }

    fn collect(&self, sink: &Sink) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        if self.defaults {
            for l in default_locations(&self.reg) {
                self.walk(&l.path, l.depth, sink, &mut seen);
            }
        }
        for l in &self.locations {
            if self.reg.values(&l.path).is_none() {
                sink.warn(|| format!("registry key {} not found", l.path));
                continue;
            }
            self.walk(&l.path, l.depth, sink, &mut seen);
        }
        Ok(())
    }
}

impl<R: Registry> RegistryCollector<R> {
    fn walk(
        &self,
        path: &str,
        depth: u32,
        sink: &Sink,
        seen: &mut std::collections::HashSet<String>,
    ) {
        let Some(values) = self.reg.values(path) else {
            return;
        };
        let subkeys = self.reg.subkeys(path).unwrap_or_default();
        if seen.insert(path.to_lowercase()) {
            let obj = KeyObject {
                path: path.to_string(),
                hive: if path.starts_with("HKU\\") {
                    "user"
                } else {
                    "machine"
                },
                values: values.into_iter().collect(),
                subkeys: (depth == 0).then(|| subkeys.clone()),
                writable_by: self.reg.writable_by(path),
            };
            sink.emit(Record::new(Kind::Registry, path, &obj));
        }
        if depth > 0 {
            for s in subkeys {
                self.walk(&join(path, &s), depth - 1, sink, seen);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(|c| c.to_le_bytes())
            .collect()
    }

    #[test]
    fn decodes_values() {
        assert_eq!(decode(1, &wide("hello")), RegValue::Str("hello".into()));
        let mut multi = wide("a");
        multi.extend(wide("bc"));
        multi.extend([0, 0]);
        assert_eq!(
            decode(7, &multi),
            RegValue::Multi(vec!["a".into(), "bc".into()])
        );
        assert_eq!(decode(4, &7u32.to_le_bytes()), RegValue::Num(7));
        assert_eq!(
            decode(11, &(1u64 << 40).to_le_bytes()),
            RegValue::Num(1 << 40)
        );
        assert_eq!(decode(3, &[0xde, 0xad]), RegValue::Bin("hex:dead".into()));
        assert!(
            matches!(decode(3, &[0u8; 1000]), RegValue::Bin(s) if s.starts_with("hex[1000 bytes"))
        );
    }

    #[test]
    fn expands_environment() {
        // SAFETY: tests in this module don't read this variable concurrently.
        unsafe { std::env::set_var("ASA_TEST_ROOT", r"C:\Windows") };
        assert_eq!(
            expand_env(r"%ASA_TEST_ROOT%\system32"),
            r"C:\Windows\system32"
        );
        assert_eq!(expand_env("100%"), "100%");
        assert_eq!(expand_env("%NOPE_ASA%\\x"), "%NOPE_ASA%\\x");
    }

    #[test]
    fn walks_locations_with_depth() {
        let mut reg = MemRegistry::default();
        reg.key(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            &[("Updater", RegValue::Str(r"C:\u.exe".into()))],
        );
        reg.key(r"HKLM\SOFTWARE\Vendor\Deep\Er", &[]);
        let c = RegistryCollector {
            reg,
            locations: vec![
                loc(r"HKLM\SOFTWARE", 0),
                loc(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 1),
            ],
            defaults: false,
        };
        let (tx, rx) = crossbeam_channel::unbounded();
        let sink = Sink::new(tx, false);
        c.collect(&sink).unwrap();
        drop(sink);
        let recs: BTreeMap<String, serde_json::Value> =
            rx.iter().map(|r| (r.identity, r.data)).collect();
        assert_eq!(recs.len(), 2);
        assert_eq!(
            recs[r"HKLM\SOFTWARE"]["subkeys"],
            serde_json::json!(["Microsoft", "Vendor"])
        );
        let run = &recs[r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"];
        assert_eq!(run["values"]["Updater"], r"C:\u.exe");
        assert!(run.get("subkeys").is_none());
    }

    #[test]
    fn fields_in_sync() {
        let obj = KeyObject {
            path: String::new(),
            hive: "machine",
            values: BTreeMap::new(),
            subkeys: Some(vec![]),
            writable_by: vec!["Users".into()],
        };
        crate::collectors::assert_fields(&obj, FIELDS);
    }

    #[test]
    fn parses_custom_locations() {
        let mut reg = MemRegistry::default();
        reg.key(r"HKU\S-1-5-21-1-1001\Software", &[]);
        reg.key(r"HKU\.DEFAULT\Software", &[]);
        let p = |a: &str| {
            parse_location(a, &reg)
                .map(|v| v.into_iter().map(|l| (l.path, l.depth)).collect::<Vec<_>>())
        };
        assert_eq!(
            p(r"HKLM\SOFTWARE\Vendor:2"),
            Ok(vec![(r"HKLM\SOFTWARE\Vendor".into(), 2)])
        );
        assert_eq!(
            p(r"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor\"),
            Ok(vec![(r"HKLM\SOFTWARE\Vendor".into(), 0)])
        );
        assert_eq!(
            p(r"HKCR\CLSID\{X}:1"),
            Ok(vec![(r"HKLM\SOFTWARE\Classes\CLSID\{X}".into(), 1)])
        );
        assert_eq!(
            p(r"HKCU\Software\Vendor"),
            Ok(vec![(r"HKU\S-1-5-21-1-1001\Software\Vendor".into(), 0)])
        );
        assert!(p(r"HKLM\X:99").is_err());
        assert!(p(r"C:\Windows").is_err());
    }

    #[test]
    fn custom_locations_add_to_defaults_and_warn_when_missing() {
        let mut reg = MemRegistry::default();
        reg.key(r"HKLM\SOFTWARE\Vendor\App", &[("Mode", RegValue::Num(1))]);
        let c = RegistryCollector {
            reg,
            locations: vec![
                loc(r"HKLM\SOFTWARE\Vendor", 1),
                loc(r"HKLM\SOFTWARE\Nope", 0),
            ],
            defaults: true,
        };
        let (tx, rx) = crossbeam_channel::unbounded();
        let sink = Sink::new(tx, false);
        c.collect(&sink).unwrap();
        assert_eq!(sink.warnings(), 1);
        drop(sink);
        let ids: Vec<String> = rx.iter().map(|r| r.identity).collect();
        assert!(
            ids.contains(&r"HKLM\SOFTWARE\Vendor\App".to_string()),
            "{ids:?}"
        );
        assert!(
            ids.contains(&r"HKLM\SOFTWARE".to_string()),
            "defaults walked too"
        );
    }
}
