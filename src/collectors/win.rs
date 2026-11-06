//! Windows security metadata: owner / DACL and Authenticode signatures.
//! The Win32 calls are only compiled on Windows; the interpretation logic is
//! portable so it can be unit-tested anywhere.

// The interpretation helpers are only called from the Windows FFI layer.
#![cfg_attr(not(windows), allow(dead_code))]

use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Security {
    pub owner: Option<String>,
    pub owner_sid: Option<String>,
    /// DACL in SDDL form, for change detection.
    pub sddl: Option<String>,
    /// Low-privileged principals granted write access (see [`LOW_PRIV_SIDS`]).
    pub writable_by: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Signature {
    /// valid, unsigned, invalid, untrusted, expired, revoked, distrusted,
    /// unsupported, or error:0x........
    pub status: String,
    /// embedded or catalog; absent when unsigned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

/// Well-known SIDs of principals any ordinary user belongs to. Labels are fixed
/// English names so reports and rules don't depend on the OS display language.
pub const LOW_PRIV_SIDS: &[(&str, &str)] = &[
    ("S-1-1-0", "Everyone"),
    ("S-1-5-7", "Anonymous"),
    ("S-1-5-4", "Interactive"),
    ("S-1-5-11", "Authenticated Users"),
    ("S-1-5-32-545", "Users"),
    ("S-1-5-32-546", "Guests"),
];

pub fn low_priv_label(sid: &str) -> Option<&'static str> {
    if let Some((_, label)) = LOW_PRIV_SIDS.iter().find(|(s, _)| *s == sid) {
        return Some(label);
    }
    // Domain Users / Domain Guests: S-1-5-21-<domain>-513 / -514
    if sid.starts_with("S-1-5-21-") {
        if sid.ends_with("-513") {
            return Some("Domain Users");
        }
        if sid.ends_with("-514") {
            return Some("Domain Guests");
        }
    }
    None
}

/// Access bits that let a principal modify or replace an object (files and dirs:
/// WRITE_DATA/ADD_FILE, APPEND_DATA/ADD_SUBDIRECTORY, WRITE_DAC, WRITE_OWNER,
/// GENERIC_WRITE, GENERIC_ALL).
pub const WRITE_MASK: u32 = 0x2 | 0x4 | 0x0004_0000 | 0x0008_0000 | 0x4000_0000 | 0x1000_0000;

pub enum Ace<'a> {
    Allow { sid: &'a str, mask: u32 },
    Deny { sid: &'a str, mask: u32 },
}

/// Evaluates a canonical DACL (deny ACEs first) per low-privileged SID.
/// Only exact SID matches are considered; group nesting is not expanded.
pub fn writable_by(aces: &[Ace]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut state: Vec<(&str, u32, u32)> = Vec::new(); // (sid, denied, granted)
    for ace in aces {
        let (sid, mask, deny) = match ace {
            Ace::Allow { sid, mask } => (*sid, *mask, false),
            Ace::Deny { sid, mask } => (*sid, *mask, true),
        };
        if low_priv_label(sid).is_none() {
            continue;
        }
        let idx = match state.iter().position(|(s, _, _)| *s == sid) {
            Some(i) => i,
            None => {
                state.push((sid, 0, 0));
                state.len() - 1
            }
        };
        let (_, denied, granted) = &mut state[idx];
        if deny {
            *denied |= mask;
        } else {
            *granted |= mask & !*denied;
        }
    }
    for (sid, _, granted) in state {
        if granted & WRITE_MASK != 0 {
            out.push(low_priv_label(sid).unwrap().to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Maps a WinVerifyTrust HRESULT to a stable status string.
pub fn trust_status(hr: i32) -> String {
    match hr as u32 {
        0 => "valid".into(),
        0x800B_0100 => "unsigned".into(),    // TRUST_E_NOSIGNATURE
        0x800B_0003 => "unsupported".into(), // TRUST_E_SUBJECT_FORM_UNKNOWN
        0x8009_6010 => "invalid".into(),     // TRUST_E_BAD_DIGEST
        0x8009_6004 => "invalid".into(),     // TRUST_E_CERT_SIGNATURE
        0x800B_0109 => "untrusted".into(),   // CERT_E_UNTRUSTEDROOT
        0x800B_0004 => "untrusted".into(),   // TRUST_E_SUBJECT_NOT_TRUSTED
        0x800B_010A => "untrusted".into(),   // CERT_E_CHAINING
        0x8009_2026 => "untrusted".into(),   // CRYPT_E_SECURITY_SETTINGS
        0x800B_0101 => "expired".into(),     // CERT_E_EXPIRED
        0x800B_010C => "revoked".into(),     // CERT_E_REVOKED
        0x800B_0111 => "distrusted".into(),  // TRUST_E_EXPLICIT_DISTRUST
        other => format!("error:0x{other:08X}"),
    }
}

/// File extensions WinVerifyTrust has subject interface packages for.
pub fn signable(lower_path: &str) -> bool {
    [
        ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv", ".efi", ".msi", ".ps1", ".psm1",
    ]
    .iter()
    .any(|e| lower_path.ends_with(e))
}

#[cfg(windows)]
pub use ffi::{key_writable_by, security, signature};

#[cfg(windows)]
mod ffi {
    use super::{Ace, Security, Signature, trust_status, writable_by};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT, SE_REGISTRY_KEY,
    };
    use windows_sys::Win32::Security::Cryptography::Catalog::{
        CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
        CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
        CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
    };
    use windows_sys::Win32::Security::Cryptography::{
        CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
        WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
        WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, LookupAccountSidW,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE,
    };

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;
    const INHERIT_ONLY_ACE: u8 = 0x08;
    const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100_u32 as i32;

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Reads a NUL-terminated UTF-16 string and frees it with LocalFree.
    unsafe fn take_local_wstr(p: *mut u16) -> String {
        let mut len = 0;
        unsafe {
            while *p.add(len) != 0 {
                len += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
            LocalFree(p as *mut c_void);
            s
        }
    }

    unsafe fn sid_string(sid: PSID) -> Option<String> {
        let mut out: *mut u16 = null_mut();
        unsafe {
            if ConvertSidToStringSidW(sid, &mut out) == 0 {
                return None;
            }
            Some(take_local_wstr(out))
        }
    }

    thread_local! {
        // SID -> DOMAIN\name. Lookups can hit a domain controller, so cache them.
        static NAMES: RefCell<HashMap<String, Option<String>>> = RefCell::new(HashMap::new());
    }

    unsafe fn account_name(sid: PSID, sid_str: &str) -> Option<String> {
        if let Some(hit) = NAMES.with(|n| n.borrow().get(sid_str).cloned()) {
            return hit;
        }
        let mut name = [0u16; 256];
        let mut domain = [0u16; 256];
        let (mut nlen, mut dlen) = (name.len() as u32, domain.len() as u32);
        let mut use_: SID_NAME_USE = 0;
        let ok = unsafe {
            LookupAccountSidW(
                null(),
                sid,
                name.as_mut_ptr(),
                &mut nlen,
                domain.as_mut_ptr(),
                &mut dlen,
                &mut use_,
            )
        } != 0;
        let result = ok.then(|| {
            let n = String::from_utf16_lossy(&name[..nlen as usize]);
            let d = String::from_utf16_lossy(&domain[..dlen as usize]);
            if d.is_empty() { n } else { format!("{d}\\{n}") }
        });
        NAMES.with(|n| n.borrow_mut().insert(sid_str.to_string(), result.clone()));
        result
    }

    /// Low-privileged principals that can modify a registry key (`HKLM\...` or
    /// `HKU\...`): set values, create subkeys, or change its permissions or owner.
    pub fn key_writable_by(path: &str) -> Vec<String> {
        let object = if let Some(rest) = path.strip_prefix("HKLM\\") {
            format!("MACHINE\\{rest}")
        } else if let Some(rest) = path.strip_prefix("HKU\\") {
            format!("USERS\\{rest}")
        } else {
            return Vec::new();
        };
        let w = wide(std::ffi::OsStr::new(&object));
        let mut dacl: *mut ACL = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let err = unsafe {
            GetNamedSecurityInfoW(
                w.as_ptr(),
                SE_REGISTRY_KEY,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            )
        };
        if err != ERROR_SUCCESS {
            return Vec::new();
        }
        let out = if dacl.is_null() {
            vec!["Everyone".into()]
        } else {
            unsafe { dacl_writers(dacl) }
        };
        unsafe { LocalFree(sd) };
        out
    }

    pub fn security(path: &Path) -> Result<Security, String> {
        let w = wide(path.as_os_str());
        let mut owner: PSID = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let err = unsafe {
            GetNamedSecurityInfoW(
                w.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            )
        };
        if err != ERROR_SUCCESS {
            return Err(format!("reading security descriptor: win32 error {err}"));
        }
        let mut out = Security::default();
        unsafe {
            if !owner.is_null() {
                out.owner_sid = sid_string(owner);
                if let Some(s) = &out.owner_sid {
                    out.owner = account_name(owner, s);
                }
            }
            let mut sddl: *mut u16 = null_mut();
            if ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut sddl,
                null_mut(),
            ) != 0
            {
                out.sddl = Some(take_local_wstr(sddl));
            }
            out.writable_by = if dacl.is_null() {
                // A NULL DACL grants everyone full control.
                vec!["Everyone".into()]
            } else {
                dacl_writers(dacl)
            };
            LocalFree(sd);
        }
        Ok(out)
    }

    unsafe fn dacl_writers(dacl: *mut ACL) -> Vec<String> {
        let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            GetAclInformation(
                dacl,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        };
        if ok == 0 {
            return Vec::new();
        }
        let mut sids: Vec<(String, u32, bool)> = Vec::new();
        for i in 0..info.AceCount {
            let mut ace: *mut c_void = null_mut();
            if unsafe { GetAce(dacl, i, &mut ace) } == 0 {
                continue;
            }
            let header = unsafe { &*(ace as *const ACE_HEADER) };
            if header.AceFlags & INHERIT_ONLY_ACE != 0 {
                continue; // applies to children only
            }
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE && header.AceType != ACCESS_DENIED_ACE_TYPE
            {
                continue;
            }
            // ACCESS_DENIED_ACE has the same layout as ACCESS_ALLOWED_ACE.
            let a = ace as *const ACCESS_ALLOWED_ACE;
            let sid = unsafe { &(*a).SidStart as *const u32 as PSID };
            if let Some(s) = unsafe { sid_string(sid) } {
                let mask = unsafe { (*a).Mask };
                sids.push((s, mask, header.AceType == ACCESS_DENIED_ACE_TYPE));
            }
        }
        let aces: Vec<Ace> = sids
            .iter()
            .map(|(sid, mask, deny)| {
                if *deny {
                    Ace::Deny { sid, mask: *mask }
                } else {
                    Ace::Allow { sid, mask: *mask }
                }
            })
            .collect();
        writable_by(&aces)
    }

    /// Runs WinVerifyTrust, returning the HRESULT and the leaf signer's name.
    unsafe fn verify(data: &mut WINTRUST_DATA) -> (i32, Option<String>) {
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        // Offline: revocation checks would make collection depend on the network.
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        let hr = unsafe { WinVerifyTrust(null_mut(), &mut action, data as *mut _ as *mut c_void) };
        let mut signer = None;
        if data.hWVTStateData.is_null() {
            return (hr, signer);
        }
        unsafe {
            let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
            if !prov.is_null() {
                let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
                if !sgnr.is_null() && (*sgnr).csCertChain > 0 && !(*sgnr).pasCertChain.is_null() {
                    let cert = (*(*sgnr).pasCertChain).pCert;
                    let mut buf = [0u16; 256];
                    let n = CertGetNameStringW(
                        cert,
                        CERT_NAME_SIMPLE_DISPLAY_TYPE,
                        0,
                        null(),
                        buf.as_mut_ptr(),
                        buf.len() as u32,
                    );
                    if n > 1 {
                        signer = Some(String::from_utf16_lossy(&buf[..n as usize - 1]));
                    }
                }
            }
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(null_mut(), &mut action, data as *mut _ as *mut c_void);
        }
        (hr, signer)
    }

    struct CatAdmin(isize);
    impl Drop for CatAdmin {
        fn drop(&mut self) {
            unsafe { CryptCATAdminReleaseContext(self.0, 0) };
        }
    }

    thread_local! {
        // One catalog admin context per hash algorithm per thread; acquiring one
        // per file is expensive. SHA256 first (modern catalogs), then SHA1.
        static CAT_ADMINS: Vec<(CatAdmin, Vec<u16>)> = ["SHA256", "SHA1"]
            .iter()
            .filter_map(|alg| {
                let walg = wide(std::ffi::OsStr::new(alg));
                let mut h: isize = 0;
                let ok = unsafe {
                    CryptCATAdminAcquireContext2(&mut h, null(), walg.as_ptr(), null(), 0)
                };
                (ok != 0).then_some((CatAdmin(h), walg))
            })
            .collect();
    }

    fn catalog_signature(path: &Path, wpath: &[u16]) -> Option<(i32, Option<String>)> {
        let file = std::fs::OpenOptions::new().read(true).open(path).ok()?;
        CAT_ADMINS.with(|admins| {
            for (admin, _) in admins {
                let mut hash = [0u8; 64];
                let mut len = hash.len() as u32;
                let ok = unsafe {
                    CryptCATAdminCalcHashFromFileHandle2(
                        admin.0,
                        file.as_raw_handle() as _,
                        &mut len,
                        hash.as_mut_ptr(),
                        0,
                    )
                };
                if ok == 0 {
                    continue;
                }
                let cat = unsafe {
                    CryptCATAdminEnumCatalogFromHash(admin.0, hash.as_ptr(), len, 0, null_mut())
                };
                if cat == 0 {
                    continue;
                }
                let mut info: CATALOG_INFO = unsafe { std::mem::zeroed() };
                info.cbStruct = std::mem::size_of::<CATALOG_INFO>() as u32;
                let got = unsafe { CryptCATCatalogInfoFromContext(cat, &mut info, 0) } != 0;
                let result = got.then(|| {
                    let tag: Vec<u16> = hash[..len as usize]
                        .iter()
                        .flat_map(|b| format!("{b:02X}").encode_utf16().collect::<Vec<_>>())
                        .chain(std::iter::once(0))
                        .collect();
                    let mut ci: WINTRUST_CATALOG_INFO = unsafe { std::mem::zeroed() };
                    ci.cbStruct = std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32;
                    ci.pcwszCatalogFilePath = info.wszCatalogFile.as_ptr();
                    ci.pcwszMemberTag = tag.as_ptr();
                    ci.pcwszMemberFilePath = wpath.as_ptr();
                    // No handle: the hash calculation moved its file pointer, and the
                    // hash is supplied anyway, so let WinVerifyTrust open by path.
                    ci.hMemberFile = null_mut();
                    ci.pbCalculatedFileHash = hash.as_mut_ptr();
                    ci.cbCalculatedFileHash = len;
                    ci.hCatAdmin = admin.0;
                    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
                    data.dwUnionChoice = WTD_CHOICE_CATALOG;
                    data.Anonymous.pCatalog = &mut ci;
                    unsafe { verify(&mut data) }
                });
                unsafe { CryptCATAdminReleaseCatalogContext(admin.0, cat, 0) };
                if result.is_some() {
                    return result;
                }
            }
            None
        })
    }

    pub fn signature(path: &Path) -> Signature {
        let wpath = wide(path.as_os_str());
        let mut fi: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
        fi.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        fi.pcwszFilePath = wpath.as_ptr();
        let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous.pFile = &mut fi;
        let (hr, signer) = unsafe { verify(&mut data) };

        if hr == 0 {
            return Signature {
                status: trust_status(hr),
                source: Some("embedded"),
                signer,
            };
        }
        // Windows trusts a file if either its embedded signature or a catalog
        // signature verifies. Most OS binaries are catalog-only, and some also carry
        // an embedded signature that fails on its own (internal chains, 16-bit
        // stubs), so consult the catalog whenever the embedded check fails.
        match catalog_signature(path, &wpath) {
            Some((chr, csigner)) if chr == 0 || hr == TRUST_E_NOSIGNATURE => Signature {
                status: trust_status(chr),
                source: Some("catalog"),
                signer: csigner,
            },
            _ if hr == TRUST_E_NOSIGNATURE => Signature {
                status: trust_status(hr),
                source: None,
                signer: None,
            },
            _ => Signature {
                status: trust_status(hr),
                source: Some("embedded"),
                signer,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_low_priv_sids() {
        assert_eq!(low_priv_label("S-1-1-0"), Some("Everyone"));
        assert_eq!(low_priv_label("S-1-5-21-1-2-3-513"), Some("Domain Users"));
        assert_eq!(low_priv_label("S-1-5-32-544"), None); // Administrators
        assert_eq!(low_priv_label("S-1-5-18"), None); // SYSTEM
    }

    #[test]
    fn dacl_evaluation() {
        let read_exec = 0x1200a9;
        let modify = 0x1301bf;
        // Typical Program Files: Users can only read.
        assert!(
            writable_by(&[
                Ace::Allow {
                    sid: "S-1-5-18",
                    mask: 0x1f01ff
                },
                Ace::Allow {
                    sid: "S-1-5-32-544",
                    mask: 0x1f01ff
                },
                Ace::Allow {
                    sid: "S-1-5-32-545",
                    mask: read_exec
                },
            ])
            .is_empty()
        );
        // Users granted modify: flagged.
        assert_eq!(
            writable_by(&[Ace::Allow {
                sid: "S-1-5-32-545",
                mask: modify
            }]),
            vec!["Users"]
        );
        // Deny write first (canonical order) neutralises a later allow.
        assert!(
            writable_by(&[
                Ace::Deny {
                    sid: "S-1-1-0",
                    mask: WRITE_MASK
                },
                Ace::Allow {
                    sid: "S-1-1-0",
                    mask: modify
                },
            ])
            .is_empty()
        );
        // GENERIC_ALL counts as write.
        assert_eq!(
            writable_by(&[Ace::Allow {
                sid: "S-1-5-11",
                mask: 0x1000_0000
            }]),
            vec!["Authenticated Users"]
        );
    }

    #[test]
    fn maps_trust_results() {
        assert_eq!(trust_status(0), "valid");
        assert_eq!(trust_status(0x800B0100u32 as i32), "unsigned");
        assert_eq!(trust_status(0x80096010u32 as i32), "invalid");
        assert_eq!(trust_status(0x12345678), "error:0x12345678");
    }
}
