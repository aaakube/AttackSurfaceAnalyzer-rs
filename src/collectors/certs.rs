//! Certificate stores (machine, Group Policy, Enterprise and current user). Private
//! keys are never read: only whether a certificate has one.
//!
//! Windows' logical stores merge physical ones (the machine Root store includes the
//! Group Policy and Enterprise roots; the user Root store includes the machine's).
//! Stores are read most-specific first and each certificate is attributed to the
//! first location it appears in, so a GPO-pushed root is reported as `group_policy`.

// Only constructed on Windows; compiled everywhere so the logic is unit-tested.
#![cfg_attr(not(windows), allow(dead_code))]

use super::{Collector, Sink};
#[cfg(windows)]
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;

/// (location label, CertOpenStore location flags, stores), most specific first.
pub const LOCATIONS: &[(&str, u32, &[&str])] = &[
    (
        "group_policy",
        8 << 16,
        &[
            "Root",
            "CA",
            "TrustedPublisher",
            "Disallowed",
            "TrustedPeople",
        ],
    ),
    (
        "enterprise",
        9 << 16,
        &[
            "Root",
            "CA",
            "TrustedPublisher",
            "Disallowed",
            "TrustedPeople",
        ],
    ),
    (
        "machine",
        2 << 16,
        &[
            "Root",
            "AuthRoot",
            "CA",
            "My",
            "TrustedPublisher",
            "Disallowed",
            "TrustedPeople",
            "Remote Desktop",
            "WebHosting",
            "SmartCardRoot",
        ],
    ),
    (
        "user",
        1 << 16,
        &[
            "Root",
            "CA",
            "My",
            "TrustedPublisher",
            "Disallowed",
            "TrustedPeople",
        ],
    ),
];

pub const FIELDS: &[&str] = &[
    "location",
    "store",
    "thumbprint",
    "subject",
    "issuer",
    "serial",
    "not_before",
    "not_after",
    "self_signed",
    "has_private_key",
    "key_algorithm",
    "key_bits",
    "signature_algorithm",
    "purposes",
];

#[derive(Serialize, Debug, Clone)]
pub struct CertObject {
    pub location: &'static str,
    pub store: String,
    pub thumbprint: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    pub self_signed: bool,
    pub has_private_key: bool,
    pub key_algorithm: String,
    pub key_bits: u32,
    pub signature_algorithm: String,
    /// Extended key usages; empty means the certificate is valid for every purpose.
    pub purposes: Vec<String>,
}

pub fn signature_algorithm(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.4" => "md5RSA",
        "1.2.840.113549.1.1.5" => "sha1RSA",
        "1.2.840.113549.1.1.11" => "sha256RSA",
        "1.2.840.113549.1.1.12" => "sha384RSA",
        "1.2.840.113549.1.1.13" => "sha512RSA",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10040.4.3" => "sha1DSA",
        "1.2.840.10045.4.1" => "sha1ECDSA",
        "1.2.840.10045.4.3.2" => "sha256ECDSA",
        "1.2.840.10045.4.3.3" => "sha384ECDSA",
        "1.2.840.10045.4.3.4" => "sha512ECDSA",
        other => return other.to_string(),
    }
    .to_string()
}

pub fn key_algorithm(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.10045.2.1" => "ECC",
        "1.2.840.10040.4.1" => "DSA",
        other => return other.to_string(),
    }
    .to_string()
}

pub fn purpose(oid: &str) -> String {
    match oid {
        "1.3.6.1.5.5.7.3.1" => "server_auth",
        "1.3.6.1.5.5.7.3.2" => "client_auth",
        "1.3.6.1.5.5.7.3.3" => "code_signing",
        "1.3.6.1.5.5.7.3.4" => "email_protection",
        "1.3.6.1.5.5.7.3.8" => "time_stamping",
        "1.3.6.1.5.5.7.3.9" => "ocsp_signing",
        "1.3.6.1.4.1.311.10.3.6" => "windows_system_component",
        "1.3.6.1.4.1.311.61.1.1" => "kernel_mode_code_signing",
        "1.3.6.1.4.1.311.10.3.4" => "encrypting_file_system",
        "1.3.6.1.4.1.311.20.2.2" => "smart_card_logon",
        "2.5.29.37.0" => "any",
        other => return other.to_string(),
    }
    .to_string()
}

/// Windows FILETIME (100 ns since 1601) to Unix seconds.
pub fn filetime_to_unix(ft: u64) -> i64 {
    (ft / 10_000_000) as i64 - 11_644_473_600
}

pub struct CertsCollector;

impl Collector for CertsCollector {
    fn name(&self) -> &'static str {
        "certificates"
    }

    fn collect(&self, sink: &Sink) -> Result<()> {
        #[cfg(windows)]
        {
            // (store, thumbprint) already attributed to a more specific location
            let mut seen = std::collections::HashSet::new();
            for &(location, flags, stores) in LOCATIONS {
                for store in stores {
                    for cert in ffi::store(location, flags, store) {
                        if !seen.insert((store.to_string(), cert.thumbprint.clone())) {
                            continue;
                        }
                        let id = format!(r"cert\{location}\{store}\{}", cert.thumbprint);
                        sink.emit(Record::new(Kind::Certificate, id, &cert));
                    }
                }
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = sink;
            anyhow::bail!("the certificates collector reads Windows certificate stores")
        }
    }
}

#[cfg(windows)]
mod ffi {
    use super::{CertObject, filetime_to_unix, key_algorithm, purpose, signature_algorithm};
    use std::ffi::{CStr, c_void};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_KEY_PROV_INFO_PROP_ID, CERT_NAME_ISSUER_FLAG,
        CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_SHA1_HASH_PROP_ID, CERT_STORE_OPEN_EXISTING_FLAG,
        CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CTL_USAGE, CertCloseStore,
        CertCompareCertificateName, CertEnumCertificatesInStore, CertGetCertificateContextProperty,
        CertGetEnhancedKeyUsage, CertGetNameStringW, CertGetPublicKeyLength, CertOpenStore,
        PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    unsafe fn oid(p: *const u8) -> String {
        if p.is_null() {
            return String::new();
        }
        unsafe {
            CStr::from_ptr(p as *const i8)
                .to_string_lossy()
                .into_owned()
        }
    }

    unsafe fn name(ctx: *const CERT_CONTEXT, flags: u32) -> String {
        let mut buf = [0u16; 512];
        let n = unsafe {
            CertGetNameStringW(
                ctx,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                flags,
                null(),
                buf.as_mut_ptr(),
                buf.len() as u32,
            )
        };
        if n > 1 {
            String::from_utf16_lossy(&buf[..n as usize - 1])
        } else {
            String::new()
        }
    }

    unsafe fn purposes(ctx: *const CERT_CONTEXT) -> Vec<String> {
        let mut len = 0u32;
        unsafe {
            if CertGetEnhancedKeyUsage(ctx, 0, null_mut(), &mut len) == 0 || len == 0 {
                return Vec::new();
            }
            let mut buf = vec![0u8; len as usize];
            let usage = buf.as_mut_ptr() as *mut CTL_USAGE;
            if CertGetEnhancedKeyUsage(ctx, 0, usage, &mut len) == 0 {
                return Vec::new();
            }
            let u = &*usage;
            let mut out: Vec<String> = (0..u.cUsageIdentifier as usize)
                .map(|i| purpose(&oid(*u.rgpszUsageIdentifier.add(i))))
                .collect();
            out.sort();
            out
        }
    }

    pub fn store(location: &'static str, flags: u32, name_: &str) -> Vec<CertObject> {
        let w: Vec<u16> = name_.encode_utf16().chain(std::iter::once(0)).collect();
        let store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                0,
                0,
                flags | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG,
                w.as_ptr() as *const c_void,
            )
        };
        if store.is_null() {
            return Vec::new(); // store absent at this location
        }
        let enc = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
        let mut out = Vec::new();
        let mut ctx: *const CERT_CONTEXT = null();
        loop {
            ctx = unsafe { CertEnumCertificatesInStore(store, ctx) };
            if ctx.is_null() {
                break;
            }
            unsafe {
                let info = &*(*ctx).pCertInfo;
                let mut hash = [0u8; 20];
                let mut hlen = hash.len() as u32;
                CertGetCertificateContextProperty(
                    ctx,
                    CERT_SHA1_HASH_PROP_ID,
                    hash.as_mut_ptr() as *mut c_void,
                    &mut hlen,
                );
                let mut klen = 0u32;
                let has_key = CertGetCertificateContextProperty(
                    ctx,
                    CERT_KEY_PROV_INFO_PROP_ID,
                    null_mut(),
                    &mut klen,
                ) != 0;
                let serial = std::slice::from_raw_parts(
                    info.SerialNumber.pbData,
                    info.SerialNumber.cbData as usize,
                );
                let ft = |f: windows_sys::Win32::Foundation::FILETIME| {
                    ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64
                };
                out.push(CertObject {
                    location,
                    store: name_.to_string(),
                    thumbprint: hash[..hlen as usize]
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect(),
                    subject: name(ctx, 0),
                    issuer: name(ctx, CERT_NAME_ISSUER_FLAG),
                    serial: serial.iter().rev().map(|b| format!("{b:02X}")).collect(),
                    not_before: filetime_to_unix(ft(info.NotBefore)),
                    not_after: filetime_to_unix(ft(info.NotAfter)),
                    self_signed: CertCompareCertificateName(enc, &info.Issuer, &info.Subject) != 0,
                    has_private_key: has_key,
                    key_algorithm: key_algorithm(&oid(info
                        .SubjectPublicKeyInfo
                        .Algorithm
                        .pszObjId)),
                    key_bits: CertGetPublicKeyLength(enc, &info.SubjectPublicKeyInfo),
                    signature_algorithm: signature_algorithm(&oid(info
                        .SignatureAlgorithm
                        .pszObjId)),
                    purposes: purposes(ctx),
                });
            }
        }
        unsafe { CertCloseStore(store, 0) };
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_oids_and_times() {
        assert_eq!(signature_algorithm("1.2.840.113549.1.1.5"), "sha1RSA");
        assert_eq!(signature_algorithm("9.9"), "9.9");
        assert_eq!(key_algorithm("1.2.840.10045.2.1"), "ECC");
        assert_eq!(purpose("1.3.6.1.5.5.7.3.3"), "code_signing");
        // 2000-01-01T00:00:00Z
        assert_eq!(filetime_to_unix(125_911_584_000_000_000), 946_684_800);
    }

    #[test]
    fn group_policy_and_enterprise_read_before_machine() {
        let order: Vec<&str> = LOCATIONS.iter().map(|l| l.0).collect();
        assert_eq!(order, vec!["group_policy", "enterprise", "machine", "user"]);
    }

    #[test]
    fn fields_in_sync() {
        let c = CertObject {
            location: "machine",
            store: "Root".into(),
            thumbprint: "AB".into(),
            subject: "s".into(),
            issuer: "i".into(),
            serial: "01".into(),
            not_before: 0,
            not_after: 1,
            self_signed: true,
            has_private_key: false,
            key_algorithm: "RSA".into(),
            key_bits: 2048,
            signature_algorithm: "sha256RSA".into(),
            purposes: vec![],
        };
        crate::collectors::assert_fields(&c, FIELDS);
    }
}
