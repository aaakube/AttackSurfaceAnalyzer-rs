//! User rights assignments (privileges and logon rights) from the local security
//! policy, via LSA, which is what `secpol.msc` and `secedit` show. One object per
//! right, listing who holds it, so granting `SeDebugPrivilege` to an account shows as
//! a modified `right\SeDebugPrivilege`. Every right is emitted even when nobody holds
//! it, so a first grant is a modification rather than a new object.

// Only constructed on Windows; compiled everywhere so the logic is unit-tested.
#![cfg_attr(not(windows), allow(dead_code))]

use super::{Collector, Sink};
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;

pub const FIELDS: &[&str] = &[
    "name",
    "description",
    "sensitive",
    "members",
    "sids",
    "unexpected_members",
];

/// Every right, with a short description and whether holding it amounts to (or
/// nearly) full control of the machine.
pub const RIGHTS: &[(&str, &str, bool)] = &[
    (
        "SeAssignPrimaryTokenPrivilege",
        "Replace a process level token",
        true,
    ),
    ("SeAuditPrivilege", "Generate security audits", false),
    (
        "SeBackupPrivilege",
        "Back up files and directories (read any file)",
        true,
    ),
    ("SeChangeNotifyPrivilege", "Bypass traverse checking", false),
    ("SeCreateGlobalPrivilege", "Create global objects", false),
    ("SeCreatePagefilePrivilege", "Create a pagefile", false),
    (
        "SeCreatePermanentPrivilege",
        "Create permanent shared objects",
        false,
    ),
    (
        "SeCreateSymbolicLinkPrivilege",
        "Create symbolic links",
        false,
    ),
    ("SeCreateTokenPrivilege", "Create a token object", true),
    (
        "SeDebugPrivilege",
        "Debug programs (open any process)",
        true,
    ),
    (
        "SeDelegateSessionUserImpersonatePrivilege",
        "Obtain an impersonation token for another user in the same session",
        false,
    ),
    (
        "SeEnableDelegationPrivilege",
        "Enable accounts to be trusted for delegation",
        true,
    ),
    (
        "SeImpersonatePrivilege",
        "Impersonate a client after authentication",
        true,
    ),
    (
        "SeIncreaseBasePriorityPrivilege",
        "Increase scheduling priority",
        false,
    ),
    (
        "SeIncreaseQuotaPrivilege",
        "Adjust memory quotas for a process",
        false,
    ),
    (
        "SeIncreaseWorkingSetPrivilege",
        "Increase a process working set",
        false,
    ),
    (
        "SeLoadDriverPrivilege",
        "Load and unload device drivers",
        true,
    ),
    ("SeLockMemoryPrivilege", "Lock pages in memory", false),
    (
        "SeMachineAccountPrivilege",
        "Add workstations to domain",
        false,
    ),
    (
        "SeManageVolumePrivilege",
        "Perform volume maintenance tasks (raw disk access)",
        true,
    ),
    (
        "SeProfileSingleProcessPrivilege",
        "Profile single process",
        false,
    ),
    ("SeRelabelPrivilege", "Modify an object label", true),
    (
        "SeRemoteShutdownPrivilege",
        "Force shutdown from a remote system",
        false,
    ),
    (
        "SeRestorePrivilege",
        "Restore files and directories (write any file)",
        true,
    ),
    (
        "SeSecurityPrivilege",
        "Manage auditing and security log",
        true,
    ),
    ("SeShutdownPrivilege", "Shut down the system", false),
    (
        "SeSyncAgentPrivilege",
        "Synchronize directory service data",
        false,
    ),
    (
        "SeSystemEnvironmentPrivilege",
        "Modify firmware environment values",
        true,
    ),
    (
        "SeSystemProfilePrivilege",
        "Profile system performance",
        false,
    ),
    ("SeSystemtimePrivilege", "Change the system time", false),
    (
        "SeTakeOwnershipPrivilege",
        "Take ownership of files or other objects",
        true,
    ),
    (
        "SeTcbPrivilege",
        "Act as part of the operating system",
        true,
    ),
    ("SeTimeZonePrivilege", "Change the time zone", false),
    (
        "SeTrustedCredManAccessPrivilege",
        "Access Credential Manager as a trusted caller",
        true,
    ),
    (
        "SeUndockPrivilege",
        "Remove computer from docking station",
        false,
    ),
    ("SeInteractiveLogonRight", "Allow log on locally", false),
    (
        "SeNetworkLogonRight",
        "Access this computer from the network",
        false,
    ),
    ("SeBatchLogonRight", "Log on as a batch job", false),
    ("SeServiceLogonRight", "Log on as a service", false),
    (
        "SeRemoteInteractiveLogonRight",
        "Allow log on through Remote Desktop Services",
        false,
    ),
    ("SeDenyInteractiveLogonRight", "Deny log on locally", false),
    (
        "SeDenyNetworkLogonRight",
        "Deny access to this computer from the network",
        false,
    ),
    ("SeDenyBatchLogonRight", "Deny log on as a batch job", false),
    ("SeDenyServiceLogonRight", "Deny log on as a service", false),
    (
        "SeDenyRemoteInteractiveLogonRight",
        "Deny log on through Remote Desktop Services",
        false,
    ),
];

/// Principals Windows grants sensitive rights to by default: holding one is expected
/// for these, and suspicious for anyone else.
fn expected_holder(sid: &str) -> bool {
    matches!(
        sid,
        "S-1-5-18"            // SYSTEM
            | "S-1-5-19"      // LOCAL SERVICE
            | "S-1-5-20"      // NETWORK SERVICE
            | "S-1-5-6"       // SERVICE
            | "S-1-5-32-544"  // Administrators
            | "S-1-5-32-551"  // Backup Operators
            | "S-1-5-90-0"    // Window Manager group
    ) || sid.starts_with("S-1-5-80-") // NT SERVICE\* virtual accounts
        || sid.starts_with("S-1-5-83-") // NT VIRTUAL MACHINE\*
        || sid.starts_with("S-1-5-99-") // RESTRICTED SERVICES\*
}

/// Right name -> holders as (SID, resolved name).
pub type Assignments = std::collections::HashMap<String, Vec<(String, Option<String>)>>;

#[derive(Serialize, Debug, PartialEq)]
pub struct RightObject {
    pub name: &'static str,
    pub description: &'static str,
    pub sensitive: bool,
    /// Holders by name (`BUILTIN\Administrators`), or SID when it doesn't resolve.
    pub members: Vec<String>,
    pub sids: Vec<String>,
    /// For a sensitive right: holders other than the built-in ones that normally
    /// have it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unexpected_members: Vec<String>,
}

/// Builds one object per right from (sid, name) holders. Rights missing from
/// `held` get an empty object.
pub fn records(held: &Assignments) -> Vec<Record> {
    RIGHTS
        .iter()
        .map(|&(name, description, sensitive)| {
            let mut holders = held.get(name).cloned().unwrap_or_default();
            holders.sort();
            holders.dedup();
            let label =
                |(sid, n): &(String, Option<String>)| n.clone().unwrap_or_else(|| sid.clone());
            let mut members: Vec<String> = holders.iter().map(label).collect();
            members.sort_by_key(|m| m.to_lowercase());
            let mut unexpected: Vec<String> = if sensitive {
                holders
                    .iter()
                    .filter(|(sid, _)| !expected_holder(sid))
                    .map(label)
                    .collect()
            } else {
                Vec::new()
            };
            unexpected.sort_by_key(|m| m.to_lowercase());
            let obj = RightObject {
                name,
                description,
                sensitive,
                members,
                sids: holders.iter().map(|(s, _)| s.clone()).collect(),
                unexpected_members: unexpected,
            };
            Record::new(Kind::Right, format!(r"right\{name}"), &obj)
        })
        .collect()
}

pub struct RightsCollector;

impl Collector for RightsCollector {
    fn name(&self) -> &'static str {
        "rights"
    }

    #[cfg(windows)]
    fn collect(&self, sink: &Sink) -> Result<()> {
        let held = ffi::assignments(sink)?;
        for r in records(&held) {
            sink.emit(r);
        }
        Ok(())
    }

    #[cfg(not(windows))]
    fn collect(&self, _sink: &Sink) -> Result<()> {
        anyhow::bail!("user rights are read through Windows LSA")
    }
}

#[cfg(windows)]
mod ffi {
    use super::RIGHTS;
    use crate::collectors::Sink;
    use anyhow::{Result, bail};
    use std::collections::HashMap;
    use windows_sys::Win32::Security::Authentication::Identity::{
        LSA_ENUMERATION_INFORMATION, LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, LsaClose,
        LsaEnumerateAccountsWithUserRight, LsaFreeMemory, LsaNtStatusToWinError, LsaOpenPolicy,
        POLICY_LOOKUP_NAMES, POLICY_VIEW_LOCAL_INFORMATION,
    };

    /// No account holds the right.
    const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001A_u32 as i32;

    pub fn assignments(sink: &Sink) -> Result<super::Assignments> {
        let attrs = LSA_OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<LSA_OBJECT_ATTRIBUTES>() as u32,
            ..Default::default()
        };
        let mut policy = Default::default();
        let status = unsafe {
            LsaOpenPolicy(
                std::ptr::null(),
                &attrs,
                (POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES) as u32,
                &mut policy,
            )
        };
        if status != 0 {
            let err = unsafe { LsaNtStatusToWinError(status) };
            bail!(
                "opening the local security policy: {}",
                std::io::Error::from_raw_os_error(err as i32)
            );
        }
        let mut out = HashMap::new();
        for (name, _, _) in RIGHTS {
            let mut wide: Vec<u16> = name.encode_utf16().collect();
            let us = LSA_UNICODE_STRING {
                Length: (wide.len() * 2) as u16,
                MaximumLength: (wide.len() * 2) as u16,
                Buffer: wide.as_mut_ptr(),
            };
            let mut buf: *mut core::ffi::c_void = std::ptr::null_mut();
            let mut count = 0u32;
            let status =
                unsafe { LsaEnumerateAccountsWithUserRight(policy, &us, &mut buf, &mut count) };
            if status == STATUS_NO_MORE_ENTRIES {
                continue;
            }
            if status != 0 {
                let err = unsafe { LsaNtStatusToWinError(status) };
                sink.warn(|| format!("{name}: {}", std::io::Error::from_raw_os_error(err as i32)));
                continue;
            }
            let entries = unsafe {
                std::slice::from_raw_parts(
                    buf as *const LSA_ENUMERATION_INFORMATION,
                    count as usize,
                )
            };
            let holders: Vec<(String, Option<String>)> = entries
                .iter()
                .filter_map(|e| unsafe { crate::collectors::win::sid_and_name(e.Sid) })
                .collect();
            unsafe { LsaFreeMemory(buf) };
            out.insert(name.to_string(), holders);
        }
        unsafe { LsaClose(policy) };
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn one_object_per_right_with_unexpected_holders() {
        let held = HashMap::from([
            (
                "SeDebugPrivilege".to_string(),
                vec![
                    (
                        "S-1-5-32-544".to_string(),
                        Some(r"BUILTIN\Administrators".to_string()),
                    ),
                    (
                        "S-1-5-21-1-2-3-1001".to_string(),
                        Some(r"PC\bob".to_string()),
                    ),
                ],
            ),
            (
                "SeShutdownPrivilege".to_string(),
                vec![(
                    "S-1-5-32-545".to_string(),
                    Some(r"BUILTIN\Users".to_string()),
                )],
            ),
            (
                "SeImpersonatePrivilege".to_string(),
                vec![
                    (
                        "S-1-5-6".to_string(),
                        Some(r"NT AUTHORITY\SERVICE".to_string()),
                    ),
                    ("S-1-5-80-123".to_string(), None),
                ],
            ),
        ]);
        let recs = records(&held);
        assert_eq!(recs.len(), RIGHTS.len());
        let get = |n: &str| {
            recs.iter()
                .find(|r| r.identity == format!(r"right\{n}"))
                .unwrap()
        };
        let debug = &get("SeDebugPrivilege").data;
        assert_eq!(debug["sensitive"], true);
        assert_eq!(
            debug["members"],
            serde_json::json!([r"BUILTIN\Administrators", r"PC\bob"])
        );
        assert_eq!(debug["unexpected_members"], serde_json::json!([r"PC\bob"]));
        // Not sensitive: Users may shut down.
        assert!(
            get("SeShutdownPrivilege")
                .data
                .get("unexpected_members")
                .is_none()
        );
        // Service accounts are expected; an unresolved SID is shown as the SID.
        let imp = &get("SeImpersonatePrivilege").data;
        assert!(imp.get("unexpected_members").is_none());
        assert_eq!(
            imp["members"],
            serde_json::json!(["NT AUTHORITY\\SERVICE", "S-1-5-80-123"])
        );
        // Nobody holds it: still emitted, empty.
        assert_eq!(get("SeTcbPrivilege").data["members"], serde_json::json!([]));
    }

    #[test]
    fn fields_in_sync() {
        let obj = RightObject {
            name: "x",
            description: "d",
            sensitive: true,
            members: vec![],
            sids: vec![],
            unexpected_members: vec!["a".into()],
        };
        crate::collectors::assert_fields(&obj, FIELDS);
    }
}
