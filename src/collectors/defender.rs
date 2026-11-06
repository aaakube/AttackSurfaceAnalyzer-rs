//! Microsoft Defender: every exclusion (paths, extensions, processes, IP addresses,
//! attack-surface-reduction and controlled-folder-access exceptions), local and from
//! policy, plus the protection settings an installer or attacker would turn down.
//! Read from Defender's registry configuration, which is what `Get-MpPreference`
//! reports, so it works offline and needs no WMI.

// Only constructed on Windows; compiled everywhere so the logic is unit-tested.
#![cfg_attr(not(windows), allow(dead_code))]

use super::registry::{RegValue, Registry};
use super::{Collector, Sink};
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;

pub const LOCAL: &str = r"HKLM\SOFTWARE\Microsoft\Windows Defender";
pub const POLICY: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender";

/// Fields of both object types (`type` = exclusion or settings).
pub const FIELDS: &[&str] = &[
    "type",
    "source",
    "category",
    "value",
    "writable_by",
    "realtime_protection",
    "behavior_monitoring",
    "scan_downloads",
    "script_scanning",
    "disabled_by_policy",
    "tamper_protection",
    "cloud_protection",
    "sample_submission",
    "pua_protection",
    "controlled_folder_access",
    "asr_rules",
];

#[derive(Serialize, Debug, PartialEq)]
pub struct Exclusion {
    pub r#type: &'static str,
    /// local (Set-MpPreference) or policy (Group Policy / MDM).
    pub source: &'static str,
    /// path, extension, process, ip, asr (excluded from attack surface reduction),
    /// cfa_app (allowed through controlled folder access).
    pub category: &'static str,
    pub value: String,
    /// For an existing path: low-privileged principals that can write there, i.e.
    /// drop files Defender will never scan.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub writable_by: Vec<String>,
}

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct Settings {
    pub r#type: &'static str,
    pub realtime_protection: bool,
    pub behavior_monitoring: bool,
    /// Scanning of downloaded files and attachments (IOAV).
    pub scan_downloads: bool,
    pub script_scanning: bool,
    /// DisableAntiSpyware / DisableAntiVirus set by policy.
    pub disabled_by_policy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tamper_protection: Option<bool>,
    pub cloud_protection: bool,
    /// prompt, safe, never or all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_submission: Option<&'static str>,
    /// off, block or audit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pua_protection: Option<&'static str>,
    /// off, block, audit, ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controlled_folder_access: Option<&'static str>,
    /// Attack surface reduction rule GUID -> off, block, audit or warn.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub asr_rules: BTreeMap<String, &'static str>,
}

/// Exclusion lists: (subkey under each base, category).
const LISTS: &[(&str, &str)] = &[
    (r"Exclusions\Paths", "path"),
    (r"Exclusions\Extensions", "extension"),
    (r"Exclusions\Processes", "process"),
    (r"Exclusions\IpAddresses", "ip"),
    (
        r"Windows Defender Exploit Guard\ASR\ASROnlyExclusions",
        "asr",
    ),
    (
        r"Windows Defender Exploit Guard\Controlled Folder Access\AllowedApplications",
        "cfa_app",
    ),
];

/// A DWORD, or a number stored as a string (policy values often are).
fn num(reg: &dyn Registry, key: &str, name: &str) -> Option<u64> {
    match reg.value(key, name)? {
        RegValue::Num(n) => Some(n),
        RegValue::Str(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Policy wins over the local setting, as in Defender itself.
fn setting(reg: &dyn Registry, sub: &str, name: &str) -> Option<u64> {
    let at = |base: &str| {
        if sub.is_empty() {
            base.to_string()
        } else {
            format!(r"{base}\{sub}")
        }
    };
    num(reg, &at(POLICY), name).or_else(|| num(reg, &at(LOCAL), name))
}

fn mode(n: u64) -> &'static str {
    match n {
        0 => "off",
        1 => "block",
        2 => "audit",
        6 => "warn",
        _ => "other",
    }
}

pub fn exclusions(reg: &dyn Registry) -> Vec<Exclusion> {
    let mut out = Vec::new();
    for (source, base) in [("local", LOCAL), ("policy", POLICY)] {
        for (sub, category) in LISTS {
            for (name, _) in reg.values(&format!(r"{base}\{sub}")).unwrap_or_default() {
                if name.is_empty() || name == super::registry::DEFAULT_VALUE {
                    continue;
                }
                out.push(Exclusion {
                    r#type: "exclusion",
                    source,
                    category,
                    value: name,
                    writable_by: Vec::new(),
                });
            }
        }
    }
    out
}

pub fn settings(reg: &dyn Registry) -> Settings {
    let off = |sub: &str, name: &str| setting(reg, sub, name) == Some(1);
    let mut asr = BTreeMap::new();
    // Local first, so policy overrides it.
    for base in [LOCAL, POLICY] {
        let key = format!(r"{base}\Windows Defender Exploit Guard\ASR\Rules");
        for (id, v) in reg.values(&key).unwrap_or_default() {
            let n = match v {
                RegValue::Num(n) => Some(n),
                RegValue::Str(s) => s.trim().parse().ok(),
                _ => None,
            };
            if let Some(n) = n {
                asr.insert(id.to_lowercase(), mode(n));
            }
        }
    }
    Settings {
        r#type: "settings",
        realtime_protection: !off("Real-Time Protection", "DisableRealtimeMonitoring"),
        behavior_monitoring: !off("Real-Time Protection", "DisableBehaviorMonitoring"),
        scan_downloads: !off("Real-Time Protection", "DisableIOAVProtection"),
        script_scanning: !off("Real-Time Protection", "DisableScriptScanning"),
        disabled_by_policy: num(reg, POLICY, "DisableAntiSpyware") == Some(1)
            || num(reg, POLICY, "DisableAntiVirus") == Some(1),
        // 5 = on, 4 = off; the low bit is the state.
        tamper_protection: num(reg, &format!(r"{LOCAL}\Features"), "TamperProtection")
            .map(|v| v & 1 == 1),
        cloud_protection: setting(reg, "Spynet", "SpynetReporting").is_none_or(|v| v != 0),
        sample_submission: setting(reg, "Spynet", "SubmitSamplesConsent").map(|v| match v {
            0 => "prompt",
            1 => "safe",
            2 => "never",
            3 => "all",
            _ => "other",
        }),
        pua_protection: setting(reg, "", "PUAProtection").map(|v| match v {
            0 => "off",
            1 => "block",
            2 => "audit",
            _ => "other",
        }),
        controlled_folder_access: setting(
            reg,
            r"Windows Defender Exploit Guard\Controlled Folder Access",
            "EnableControlledFolderAccess",
        )
        .map(mode),
        asr_rules: asr,
    }
}

pub struct DefenderCollector<R: Registry> {
    pub reg: R,
}

impl<R: Registry> Collector for DefenderCollector<R> {
    fn name(&self) -> &'static str {
        "defender"
    }

    fn collect(&self, sink: &Sink) -> Result<()> {
        if self.reg.values(LOCAL).is_none() {
            anyhow::bail!(r"{LOCAL} is not readable (Defender not installed, or not elevated)");
        }
        for mut e in exclusions(&self.reg) {
            if matches!(e.category, "path" | "process") {
                e.writable_by = writable_by(&e.value);
            }
            sink.emit(Record::new(
                Kind::Defender,
                format!(
                    r"defender\exclusion\{}\{}\{}",
                    e.source, e.category, e.value
                ),
                &e,
            ));
        }
        sink.emit(Record::new(
            Kind::Defender,
            r"defender\settings",
            &settings(&self.reg),
        ));
        Ok(())
    }
}

/// Who besides administrators can write to an excluded path (when it exists and has
/// no wildcard).
fn writable_by(value: &str) -> Vec<String> {
    let path = super::registry::expand_env(value);
    if path.contains('*') || path.contains('?') {
        return Vec::new();
    }
    #[cfg(windows)]
    {
        let p = std::path::Path::new(&path);
        if p.exists() {
            return super::win::security(p)
                .map(|s| s.writable_by)
                .unwrap_or_default();
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::registry::MemRegistry;

    fn reg() -> MemRegistry {
        let mut r = MemRegistry::default();
        r.key(LOCAL, &[("ProductStatus", RegValue::Num(0))])
            .key(
                &format!(r"{LOCAL}\Exclusions\Paths"),
                &[(r"C:\Tools", RegValue::Num(0))],
            )
            .key(
                &format!(r"{LOCAL}\Exclusions\Extensions"),
                &[("ps1", RegValue::Num(0))],
            )
            .key(&format!(r"{LOCAL}\Exclusions\Processes"), &[])
            .key(
                &format!(r"{POLICY}\Exclusions\Processes"),
                &[("agent.exe", RegValue::Str("0".into()))],
            )
            .key(
                &format!(r"{LOCAL}\Real-Time Protection"),
                &[("DisableRealtimeMonitoring", RegValue::Num(0))],
            )
            .key(
                &format!(r"{POLICY}\Real-Time Protection"),
                &[("DisableBehaviorMonitoring", RegValue::Num(1))],
            )
            .key(
                &format!(r"{LOCAL}\Features"),
                &[("TamperProtection", RegValue::Num(5))],
            )
            .key(
                &format!(r"{LOCAL}\Spynet"),
                &[
                    ("SpynetReporting", RegValue::Num(2)),
                    ("SubmitSamplesConsent", RegValue::Num(1)),
                ],
            )
            .key(
                &format!(r"{POLICY}\Spynet"),
                &[("SpynetReporting", RegValue::Str("0".into()))],
            )
            .key(
                &format!(r"{LOCAL}\Windows Defender Exploit Guard\ASR\Rules"),
                &[("D4F940AB-401B-4EFC-AADC-AD5F3C50688A", RegValue::Num(2))],
            )
            .key(
                &format!(r"{POLICY}\Windows Defender Exploit Guard\ASR\Rules"),
                &[(
                    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
                    RegValue::Str("1".into()),
                )],
            );
        r
    }

    #[test]
    fn reads_exclusions_from_both_sources() {
        let ex: Vec<(&str, &str, String)> = exclusions(&reg())
            .into_iter()
            .map(|e| (e.source, e.category, e.value))
            .collect();
        assert_eq!(
            ex,
            vec![
                ("local", "path", r"C:\Tools".to_string()),
                ("local", "extension", "ps1".to_string()),
                ("policy", "process", "agent.exe".to_string()),
            ]
        );
    }

    #[test]
    fn policy_overrides_local_settings() {
        let s = settings(&reg());
        assert!(s.realtime_protection);
        assert!(!s.behavior_monitoring, "turned off by policy");
        assert!(s.scan_downloads && s.script_scanning && !s.disabled_by_policy);
        assert_eq!(s.tamper_protection, Some(true));
        assert!(!s.cloud_protection, "policy 0 beats local 2");
        assert_eq!(s.sample_submission, Some("safe"));
        assert_eq!(
            s.asr_rules.get("d4f940ab-401b-4efc-aadc-ad5f3c50688a"),
            Some(&"block")
        );
        // Nothing configured: Defender's defaults (on).
        let mut bare = MemRegistry::default();
        bare.key(LOCAL, &[]);
        let d = settings(&bare);
        assert!(d.realtime_protection && d.cloud_protection);
        assert_eq!(d.tamper_protection, None);
    }

    #[test]
    fn collects_records_and_needs_the_key() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let sink = Sink::new(tx, false);
        DefenderCollector { reg: reg() }.collect(&sink).unwrap();
        assert!(
            DefenderCollector {
                reg: MemRegistry::default()
            }
            .collect(&sink)
            .is_err()
        );
        drop(sink);
        let ids: Vec<String> = rx.iter().map(|r| r.identity).collect();
        assert_eq!(
            ids,
            vec![
                r"defender\exclusion\local\path\C:\Tools",
                r"defender\exclusion\local\extension\ps1",
                r"defender\exclusion\policy\process\agent.exe",
                r"defender\settings",
            ]
        );
    }

    #[test]
    fn fields_in_sync() {
        let mut keys: Vec<String> = Vec::new();
        let e = Exclusion {
            r#type: "exclusion",
            source: "local",
            category: "path",
            value: "x".into(),
            writable_by: vec!["Users".into()],
        };
        let s = Settings {
            tamper_protection: Some(true),
            sample_submission: Some("safe"),
            pua_protection: Some("off"),
            controlled_folder_access: Some("off"),
            asr_rules: BTreeMap::from([("x".to_string(), "off")]),
            ..Default::default()
        };
        for v in [
            serde_json::to_value(&e).unwrap(),
            serde_json::to_value(&s).unwrap(),
        ] {
            keys.extend(v.as_object().unwrap().keys().cloned());
        }
        keys.sort();
        keys.dedup();
        let mut want: Vec<&str> = FIELDS.to_vec();
        want.sort();
        assert_eq!(keys, want);
    }
}
