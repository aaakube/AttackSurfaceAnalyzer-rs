//! Local user accounts and groups (NetUserEnum / NetLocalGroup* APIs). Volatile
//! values (last logon, password age, lockout counters) are deliberately left out.
//! Group membership is keyed by SID: account names are localized and renameable.

// Only constructed on Windows; compiled everywhere so the logic is unit-tested.
#![cfg_attr(not(windows), allow(dead_code))]

use super::{Collector, Sink};
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;

/// Built-in groups whose members can take over the machine (or get very close),
/// with stable English labels.
pub const PRIVILEGED_GROUPS: &[(&str, &str)] = &[
    ("S-1-5-32-544", "Administrators"),
    ("S-1-5-32-548", "Account Operators"),
    ("S-1-5-32-549", "Server Operators"),
    ("S-1-5-32-550", "Print Operators"),
    ("S-1-5-32-551", "Backup Operators"),
    ("S-1-5-32-555", "Remote Desktop Users"),
    ("S-1-5-32-556", "Network Configuration Operators"),
    ("S-1-5-32-562", "Distributed COM Users"),
    ("S-1-5-32-569", "Cryptographic Operators"),
    ("S-1-5-32-578", "Hyper-V Administrators"),
    ("S-1-5-32-580", "Remote Management Users"),
];

pub fn privileged_label(sid: &str) -> Option<&'static str> {
    PRIVILEGED_GROUPS
        .iter()
        .find(|(s, _)| *s == sid)
        .map(|(_, l)| *l)
}

/// Well-known local accounts by relative ID.
pub fn builtin_account(sid: &str) -> Option<&'static str> {
    if !sid.starts_with("S-1-5-21-") {
        return None;
    }
    match sid.rsplit('-').next()? {
        "500" => Some("Administrator"),
        "501" => Some("Guest"),
        "503" => Some("DefaultAccount"),
        "504" => Some("WDAGUtilityAccount"),
        _ => None,
    }
}

const UF_ACCOUNTDISABLE: u32 = 0x0002;
const UF_PASSWD_NOTREQD: u32 = 0x0020;
const UF_PASSWD_CANT_CHANGE: u32 = 0x0040;
const UF_DONT_EXPIRE_PASSWD: u32 = 0x10000;

/// A raw account as read from the system, before group resolution.
pub struct RawUser {
    pub name: String,
    pub sid: String,
    pub full_name: String,
    pub comment: String,
    pub flags: u32,
}

pub struct RawGroup {
    pub name: String,
    pub sid: String,
    pub comment: String,
    /// (sid, DOMAIN\name)
    pub members: Vec<(String, String)>,
}

pub const USER_FIELDS: &[&str] = &[
    "name",
    "sid",
    "full_name",
    "comment",
    "enabled",
    "password_required",
    "password_expires",
    "password_changeable",
    "builtin",
    "groups",
    "group_sids",
    "administrator",
    "privileged_groups",
];
pub const GROUP_FIELDS: &[&str] = &[
    "name",
    "sid",
    "comment",
    "members",
    "member_sids",
    "privileged",
    "privilege",
];

#[derive(Serialize)]
struct UserObject {
    name: String,
    sid: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    full_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    comment: String,
    enabled: bool,
    password_required: bool,
    password_expires: bool,
    password_changeable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    builtin: Option<&'static str>,
    groups: Vec<String>,
    group_sids: Vec<String>,
    administrator: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    privileged_groups: Vec<&'static str>,
}

#[derive(Serialize)]
struct GroupObject {
    name: String,
    sid: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    comment: String,
    members: Vec<String>,
    member_sids: Vec<String>,
    privileged: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    privilege: Option<&'static str>,
}

/// Turns raw accounts and groups into records (pure, so it is unit-tested).
pub fn records(users: Vec<RawUser>, groups: Vec<RawGroup>) -> Vec<Record> {
    let mut out = Vec::new();
    // sid -> groups it is a direct member of
    let mut member_of: BTreeMap<String, Vec<(&str, &str)>> = BTreeMap::new();
    for g in &groups {
        for (sid, _) in &g.members {
            member_of
                .entry(sid.clone())
                .or_default()
                .push((&g.name, &g.sid));
        }
    }
    for u in &users {
        let mine = member_of.get(&u.sid).cloned().unwrap_or_default();
        let mut groups: Vec<String> = mine.iter().map(|(n, _)| n.to_string()).collect();
        let mut group_sids: Vec<String> = mine.iter().map(|(_, s)| s.to_string()).collect();
        groups.sort();
        group_sids.sort();
        let mut privileged: Vec<&'static str> = group_sids
            .iter()
            .filter_map(|s| privileged_label(s))
            .collect();
        privileged.sort();
        let obj = UserObject {
            name: u.name.clone(),
            sid: u.sid.clone(),
            full_name: u.full_name.clone(),
            comment: u.comment.clone(),
            enabled: u.flags & UF_ACCOUNTDISABLE == 0,
            password_required: u.flags & UF_PASSWD_NOTREQD == 0,
            password_expires: u.flags & UF_DONT_EXPIRE_PASSWD == 0,
            password_changeable: u.flags & UF_PASSWD_CANT_CHANGE == 0,
            builtin: builtin_account(&u.sid),
            administrator: group_sids.iter().any(|s| s == "S-1-5-32-544"),
            groups,
            group_sids,
            privileged_groups: privileged,
        };
        out.push(Record::new(Kind::User, format!(r"user\{}", u.name), &obj));
    }
    for g in groups {
        let mut members: Vec<String> = g.members.iter().map(|(_, n)| n.clone()).collect();
        let mut member_sids: Vec<String> = g.members.iter().map(|(s, _)| s.clone()).collect();
        members.sort();
        member_sids.sort();
        let privilege = privileged_label(&g.sid);
        let obj = GroupObject {
            privileged: privilege.is_some(),
            privilege,
            name: g.name.clone(),
            sid: g.sid,
            comment: g.comment,
            members,
            member_sids,
        };
        out.push(Record::new(Kind::Group, format!(r"group\{}", g.name), &obj));
    }
    out
}

pub struct AccountsCollector;

impl Collector for AccountsCollector {
    fn name(&self) -> &'static str {
        "users"
    }

    fn collect(&self, sink: &Sink) -> Result<()> {
        #[cfg(windows)]
        {
            let users = ffi::users()?;
            let groups = ffi::groups(sink)?;
            for r in records(users, groups) {
                sink.emit(r);
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = sink;
            anyhow::bail!("the users collector reads the Windows account database")
        }
    }
}

#[cfg(windows)]
mod ffi {
    use super::{RawGroup, RawUser};
    use crate::collectors::Sink;
    use anyhow::{Result, bail};
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        FILTER_NORMAL_ACCOUNT, LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_2, MAX_PREFERRED_LENGTH,
        NetApiBufferFree, NetLocalGroupEnum, NetLocalGroupGetMembers, NetUserEnum, USER_INFO_20,
    };
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{LookupAccountNameW, PSID, SID_NAME_USE};

    unsafe fn wstr(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut n = 0;
        unsafe {
            while *p.add(n) != 0 {
                n += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
        }
    }

    unsafe fn sid_string(sid: PSID) -> String {
        let mut out: *mut u16 = null_mut();
        unsafe {
            if sid.is_null() || ConvertSidToStringSidW(sid, &mut out) == 0 {
                return String::new();
            }
            let s = wstr(out);
            LocalFree(out as *mut c_void);
            s
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Frees a NetApi buffer on drop.
    struct NetBuf(*mut u8);
    impl Drop for NetBuf {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { NetApiBufferFree(self.0 as *const c_void) };
            }
        }
    }

    pub fn users() -> Result<Vec<RawUser>> {
        // Level 20 (NetUserEnum does not support the SID-carrying level 23); SIDs
        // are resolved per account, qualified with the computer name so a domain
        // account with the same name is never picked up.
        let mut buf: *mut u8 = null_mut();
        let (mut read, mut total, mut resume) = (0u32, 0u32, 0u32);
        let rc = unsafe {
            NetUserEnum(
                null(),
                20,
                FILTER_NORMAL_ACCOUNT,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            )
        };
        let _guard = NetBuf(buf);
        if rc != 0 {
            bail!("NetUserEnum failed: {rc}");
        }
        let computer = std::env::var("COMPUTERNAME").unwrap_or_default();
        let rows = unsafe { std::slice::from_raw_parts(buf as *const USER_INFO_20, read as usize) };
        Ok(rows
            .iter()
            .map(|u| {
                let name = unsafe { wstr(u.usri20_name) };
                RawUser {
                    sid: account_sid(&format!("{computer}\\{name}")),
                    full_name: unsafe { wstr(u.usri20_full_name) },
                    comment: unsafe { wstr(u.usri20_comment) },
                    flags: u.usri20_flags,
                    name,
                }
            })
            .collect())
    }

    fn account_sid(name: &str) -> String {
        let w = wide(name);
        let mut sid = vec![0u8; 256];
        let mut domain = vec![0u16; 256];
        let (mut cb, mut cch) = (sid.len() as u32, domain.len() as u32);
        let mut use_: SID_NAME_USE = 0;
        let ok = unsafe {
            LookupAccountNameW(
                null(),
                w.as_ptr(),
                sid.as_mut_ptr() as PSID,
                &mut cb,
                domain.as_mut_ptr(),
                &mut cch,
                &mut use_,
            )
        };
        if ok == 0 {
            String::new()
        } else {
            unsafe { sid_string(sid.as_mut_ptr() as PSID) }
        }
    }

    fn members(name: &str, sink: &Sink) -> Vec<(String, String)> {
        let w = wide(name);
        let mut buf: *mut u8 = null_mut();
        let (mut read, mut total) = (0u32, 0u32);
        let mut resume: usize = 0;
        let rc = unsafe {
            NetLocalGroupGetMembers(
                null(),
                w.as_ptr(),
                2,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            )
        };
        let _guard = NetBuf(buf);
        if rc != 0 {
            sink.warn(|| format!("members of group {name}: error {rc}"));
            return Vec::new();
        }
        let rows = unsafe {
            std::slice::from_raw_parts(buf as *const LOCALGROUP_MEMBERS_INFO_2, read as usize)
        };
        rows.iter()
            .map(|m| unsafe { (sid_string(m.lgrmi2_sid), wstr(m.lgrmi2_domainandname)) })
            .collect()
    }

    pub fn groups(sink: &Sink) -> Result<Vec<RawGroup>> {
        let mut buf: *mut u8 = null_mut();
        let (mut read, mut total) = (0u32, 0u32);
        let mut resume: usize = 0;
        let rc = unsafe {
            NetLocalGroupEnum(
                null(),
                1,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            )
        };
        let _guard = NetBuf(buf);
        if rc != 0 {
            bail!("NetLocalGroupEnum failed: {rc}");
        }
        let rows =
            unsafe { std::slice::from_raw_parts(buf as *const LOCALGROUP_INFO_1, read as usize) };
        Ok(rows
            .iter()
            .map(|g| {
                let name = unsafe { wstr(g.lgrpi1_name) };
                RawGroup {
                    sid: account_sid(&name),
                    comment: unsafe { wstr(g.lgrpi1_comment) },
                    members: members(&name, sink),
                    name,
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn resolves_membership_and_flags() {
        let users = vec![
            RawUser {
                name: "Administrator".into(),
                sid: "S-1-5-21-1-2-3-500".into(),
                full_name: String::new(),
                comment: String::new(),
                flags: UF_ACCOUNTDISABLE,
            },
            RawUser {
                name: "asa".into(),
                sid: "S-1-5-21-1-2-3-1000".into(),
                full_name: String::new(),
                comment: String::new(),
                flags: UF_DONT_EXPIRE_PASSWD,
            },
            RawUser {
                name: "svc".into(),
                sid: "S-1-5-21-1-2-3-1001".into(),
                full_name: String::new(),
                comment: String::new(),
                flags: UF_PASSWD_NOTREQD,
            },
        ];
        let groups = vec![
            RawGroup {
                name: "Administrators".into(),
                sid: "S-1-5-32-544".into(),
                comment: String::new(),
                members: vec![
                    ("S-1-5-21-1-2-3-500".into(), r"PC\Administrator".into()),
                    ("S-1-5-21-1-2-3-1000".into(), r"PC\asa".into()),
                ],
            },
            RawGroup {
                name: "Remote Desktop Users".into(),
                sid: "S-1-5-32-555".into(),
                comment: String::new(),
                members: vec![("S-1-5-21-1-2-3-1001".into(), r"PC\svc".into())],
            },
            RawGroup {
                name: "Users".into(),
                sid: "S-1-5-32-545".into(),
                comment: String::new(),
                members: vec![],
            },
        ];
        let r: HashMap<String, serde_json::Value> = records(users, groups)
            .into_iter()
            .map(|r| (r.identity, r.data))
            .collect();
        let admin = &r[r"user\Administrator"];
        assert_eq!(admin["enabled"], false);
        assert_eq!(admin["builtin"], "Administrator");
        assert_eq!(admin["administrator"], true);
        let asa = &r[r"user\asa"];
        assert_eq!(asa["password_expires"], false);
        assert_eq!(asa["groups"], serde_json::json!(["Administrators"]));
        let svc = &r[r"user\svc"];
        assert_eq!(svc["password_required"], false);
        assert_eq!(
            svc["privileged_groups"],
            serde_json::json!(["Remote Desktop Users"])
        );
        assert_eq!(svc["administrator"], false);
        assert_eq!(r[r"group\Administrators"]["privileged"], true);
        assert_eq!(
            r[r"group\Administrators"]["member_sids"],
            serde_json::json!(["S-1-5-21-1-2-3-1000", "S-1-5-21-1-2-3-500"])
        );
        assert_eq!(r[r"group\Users"]["privileged"], false);
    }

    #[test]
    fn fields_in_sync() {
        let u = UserObject {
            name: "a".into(),
            sid: "s".into(),
            full_name: "f".into(),
            comment: "c".into(),
            enabled: true,
            password_required: true,
            password_expires: true,
            password_changeable: true,
            builtin: Some("Guest"),
            groups: vec![],
            group_sids: vec![],
            administrator: false,
            privileged_groups: vec!["Administrators"],
        };
        crate::collectors::assert_fields(&u, USER_FIELDS);
        let g = GroupObject {
            name: "g".into(),
            sid: "s".into(),
            comment: "c".into(),
            members: vec![],
            member_sids: vec![],
            privileged: true,
            privilege: Some("Administrators"),
        };
        crate::collectors::assert_fields(&g, GROUP_FIELDS);
    }
}
