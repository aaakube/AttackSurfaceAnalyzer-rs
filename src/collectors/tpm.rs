//! Hardware root of trust, as one object (`tpm`): whether a TPM is present, enabled,
//! activated and owned, its maker and version (Win32_Tpm), and whether UEFI Secure
//! Boot is on. Turning either off is a step attackers take before installing a
//! bootkit or reading BitLocker keys.

// Only constructed on Windows; compiled everywhere so the logic is unit-tested.
#![cfg_attr(not(windows), allow(dead_code, unused_imports))]

use super::registry::Registry;
use super::wmi::Row;
use super::{Collector, Sink};
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

pub const FIELDS: &[&str] = &[
    "present",
    "enabled",
    "activated",
    "owned",
    "manufacturer",
    "manufacturer_version",
    "spec_version",
    "secure_boot",
];

pub const TPM_NAMESPACE: &str = r"root\CIMV2\Security\MicrosoftTpm";
pub const TPM_PROPS: &[&str] = &[
    "IsEnabled_InitialValue",
    "IsActivated_InitialValue",
    "IsOwned_InitialValue",
    "ManufacturerIdTxt",
    "ManufacturerVersion",
    "SpecVersion",
];
const SECURE_BOOT: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State";

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct TpmObject {
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owned: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer_version: Option<String>,
    /// Highest TPM specification version supported (`2.0`, `1.2`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_version: Option<String>,
    /// None on legacy BIOS machines, where Secure Boot doesn't exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_boot: Option<bool>,
}

/// From the first Win32_Tpm instance (none: no TPM) and the Secure Boot state.
pub fn build(tpm: Option<&Row>, secure_boot: Option<bool>) -> TpmObject {
    let b = |r: &Row, k: &str| r.get(k).and_then(Value::as_bool);
    let s = |r: &Row, k: &str| {
        r.get(k)
            .and_then(Value::as_str)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    match tpm {
        None => TpmObject {
            present: false,
            secure_boot,
            ..Default::default()
        },
        Some(r) => TpmObject {
            present: true,
            enabled: b(r, "IsEnabled_InitialValue"),
            activated: b(r, "IsActivated_InitialValue"),
            owned: b(r, "IsOwned_InitialValue"),
            manufacturer: s(r, "ManufacturerIdTxt"),
            manufacturer_version: s(r, "ManufacturerVersion"),
            // "2.0, 0, 1.59": the first entry is the spec version.
            spec_version: s(r, "SpecVersion")
                .map(|v| v.split(',').next().unwrap_or("").trim().to_string()),
            secure_boot,
        },
    }
}

pub fn secure_boot(reg: &dyn Registry) -> Option<bool> {
    reg.value(SECURE_BOOT, "UEFISecureBootEnabled")
        .and_then(|v| v.as_num())
        .map(|n| n == 1)
}

pub struct TpmCollector<R: Registry> {
    pub reg: R,
}

impl<R: Registry> Collector for TpmCollector<R> {
    fn name(&self) -> &'static str {
        "tpm"
    }

    #[cfg(windows)]
    fn collect(&self, sink: &Sink) -> Result<()> {
        let rows = match super::wmi::com::query(TPM_NAMESPACE, "SELECT * FROM Win32_Tpm", TPM_PROPS)
        {
            Ok(r) => r,
            Err(e) => {
                // The namespace is missing when the TPM stack isn't installed.
                sink.warn(|| format!("Win32_Tpm: {e:#}"));
                Vec::new()
            }
        };
        let obj = build(rows.first(), secure_boot(&self.reg));
        sink.emit(Record::new(Kind::Tpm, "tpm", &obj));
        Ok(())
    }

    #[cfg(not(windows))]
    fn collect(&self, _sink: &Sink) -> Result<()> {
        anyhow::bail!("the TPM is read through Windows WMI")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::registry::{MemRegistry, RegValue};
    use serde_json::json;

    #[test]
    fn builds_from_wmi_and_registry() {
        let row: Row = serde_json::from_value(json!({
            "IsEnabled_InitialValue": true, "IsActivated_InitialValue": true, "IsOwned_InitialValue": false,
            "ManufacturerIdTxt": "MSFT", "ManufacturerVersion": "8215.0.0.0", "SpecVersion": "2.0, 0, 1.59"
        }))
        .unwrap();
        let mut reg = MemRegistry::default();
        reg.key(SECURE_BOOT, &[("UEFISecureBootEnabled", RegValue::Num(1))]);
        let t = build(Some(&row), secure_boot(&reg));
        assert!(t.present);
        assert_eq!(
            (t.enabled, t.activated, t.owned),
            (Some(true), Some(true), Some(false))
        );
        assert_eq!(t.spec_version.as_deref(), Some("2.0"));
        assert_eq!(t.manufacturer.as_deref(), Some("MSFT"));
        assert_eq!(t.secure_boot, Some(true));
        let none = build(None, secure_boot(&MemRegistry::default()));
        assert!(!none.present && none.enabled.is_none() && none.secure_boot.is_none());
    }

    #[test]
    fn fields_in_sync() {
        let t = TpmObject {
            present: true,
            enabled: Some(true),
            activated: Some(true),
            owned: Some(true),
            manufacturer: Some("m".into()),
            manufacturer_version: Some("v".into()),
            spec_version: Some("2.0".into()),
            secure_boot: Some(true),
        };
        crate::collectors::assert_fields(&t, FIELDS);
    }
}
