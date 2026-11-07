//! Machine private keys in the CNG key storage providers: the software provider
//! (keys on disk under `ProgramData\Microsoft\Crypto`) and the TPM-backed Platform
//! Crypto Provider. For each key: algorithm, size, whether it can be exported (in
//! plain text), and, for keys on disk, which low-privileged users can read the key
//! file, which means they can steal it. Key material is never read. Per-user keys
//! are left out: only the account running asa could see its own.

// Only constructed on Windows; compiled everywhere so the logic is unit-tested.
#![cfg_attr(not(windows), allow(dead_code, unused_imports))]

use super::{Collector, Sink};
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;

pub const FIELDS: &[&str] = &[
    "provider",
    "name",
    "algorithm",
    "length",
    "legacy",
    "exportable",
    "plaintext_exportable",
    "file",
    "readable_by",
];

#[derive(Serialize, Debug, Default, PartialEq, Clone)]
pub struct KeyObject {
    /// software or tpm.
    pub provider: &'static str,
    /// Key container name.
    pub name: String,
    pub algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    /// A CryptoAPI (pre-CNG) key container.
    pub legacy: bool,
    pub exportable: bool,
    pub plaintext_exportable: bool,
    /// The key file, for keys stored on disk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub readable_by: Vec<String>,
}

pub const ALLOW_EXPORT: u32 = 1;
pub const ALLOW_PLAINTEXT_EXPORT: u32 = 2;

impl KeyObject {
    pub fn set_export_policy(&mut self, policy: u32) {
        self.exportable = policy & (ALLOW_EXPORT | ALLOW_PLAINTEXT_EXPORT) != 0;
        self.plaintext_exportable = policy & ALLOW_PLAINTEXT_EXPORT != 0;
    }

    pub fn identity(&self) -> String {
        format!(r"key\machine\{}\{}", self.provider, self.name)
    }
}

/// The machine key file with this unique name, and whether it is a CryptoAPI
/// (legacy) container. The provider's legacy key spec can't tell: CNG keys made for
/// certificates report one too. So look where the file is: CNG keys live in
/// `Crypto\Keys`, CryptoAPI containers in `Crypto\RSA\MachineKeys`.
pub fn locate_key_file(
    unique_name: &str,
    exists: impl Fn(&std::path::Path) -> bool,
) -> Option<(std::path::PathBuf, bool)> {
    let pd = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    let base = std::path::Path::new(&pd).join("Microsoft").join("Crypto");
    [
        (base.join("Keys"), false),
        (base.join("RSA").join("MachineKeys"), true),
    ]
    .into_iter()
    .map(|(dir, legacy)| (dir.join(unique_name), legacy))
    .find(|(path, _)| exists(path))
}

pub struct KeysCollector;

impl Collector for KeysCollector {
    fn name(&self) -> &'static str {
        "keys"
    }

    #[cfg(windows)]
    fn collect(&self, sink: &Sink) -> Result<()> {
        for (provider, label) in [
            (
                windows_sys::Win32::Security::Cryptography::MS_KEY_STORAGE_PROVIDER,
                "software",
            ),
            (
                windows_sys::Win32::Security::Cryptography::MS_PLATFORM_CRYPTO_PROVIDER,
                "tpm",
            ),
        ] {
            match ffi::keys(provider, label) {
                Ok(keys) => {
                    for k in keys {
                        sink.emit(Record::new(Kind::Key, k.identity(), &k));
                    }
                }
                // No TPM: the platform provider doesn't open.
                Err(e) => sink.warn(|| format!("{label} key storage provider: {e}")),
            }
        }
        Ok(())
    }

    #[cfg(not(windows))]
    fn collect(&self, _sink: &Sink) -> Result<()> {
        anyhow::bail!("key storage providers are a Windows API")
    }
}

#[cfg(windows)]
mod ffi {
    use super::{KeyObject, locate_key_file};
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::Cryptography::{
        NCRYPT_KEY_HANDLE, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
        NCryptEnumKeys, NCryptFreeBuffer, NCryptFreeObject, NCryptGetProperty, NCryptKeyName,
        NCryptOpenKey, NCryptOpenStorageProvider,
    };
    use windows_sys::core::PCWSTR;

    const NTE_NO_MORE_ITEMS: i32 = 0x8009_002A_u32 as i32;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    unsafe fn pwstr(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        unsafe {
            let mut n = 0;
            while *p.add(n) != 0 {
                n += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
        }
    }

    unsafe fn prop(key: NCRYPT_KEY_HANDLE, name: &str) -> Option<Vec<u8>> {
        let n = wide(name);
        let mut size = 0u32;
        unsafe {
            if NCryptGetProperty(
                key,
                n.as_ptr(),
                null_mut(),
                0,
                &mut size,
                NCRYPT_SILENT_FLAG,
            ) != 0
                || size == 0
            {
                return None;
            }
            let mut buf = vec![0u8; size as usize];
            if NCryptGetProperty(
                key,
                n.as_ptr(),
                buf.as_mut_ptr(),
                size,
                &mut size,
                NCRYPT_SILENT_FLAG,
            ) != 0
            {
                return None;
            }
            buf.truncate(size as usize);
            Some(buf)
        }
    }

    fn u32_of(b: &[u8]) -> Option<u32> {
        b.get(..4)
            .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
    }

    fn string_of(b: &[u8]) -> String {
        let w: Vec<u16> = b
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        String::from_utf16_lossy(&w)
    }

    pub fn keys(
        provider_name: PCWSTR,
        label: &'static str,
    ) -> Result<Vec<KeyObject>, std::io::Error> {
        let mut prov: NCRYPT_PROV_HANDLE = 0;
        let hr = unsafe { NCryptOpenStorageProvider(&mut prov, provider_name, 0) };
        if hr != 0 {
            return Err(std::io::Error::from_raw_os_error(hr));
        }
        let mut out = Vec::new();
        let mut state: *mut core::ffi::c_void = null_mut();
        loop {
            let mut name: *mut NCryptKeyName = null_mut();
            let hr = unsafe {
                NCryptEnumKeys(
                    prov,
                    std::ptr::null(),
                    &mut name,
                    &mut state,
                    NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG,
                )
            };
            if hr == NTE_NO_MORE_ITEMS {
                break;
            }
            if hr != 0 {
                unsafe { NCryptFreeObject(prov) };
                return Err(std::io::Error::from_raw_os_error(hr));
            }
            let (key_name, alg, spec) = unsafe {
                (
                    pwstr((*name).pszName),
                    pwstr((*name).pszAlgid),
                    (*name).dwLegacyKeySpec,
                )
            };
            unsafe { NCryptFreeBuffer(name as *mut _) };
            let mut k = KeyObject {
                provider: label,
                name: key_name.clone(),
                algorithm: alg,
                ..Default::default()
            };
            let mut key: NCRYPT_KEY_HANDLE = 0;
            let w = wide(&key_name);
            let opened = unsafe {
                NCryptOpenKey(
                    prov,
                    &mut key,
                    w.as_ptr(),
                    spec,
                    NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG,
                )
            } == 0;
            if opened {
                unsafe {
                    k.length = prop(key, "Length").as_deref().and_then(u32_of);
                    if let Some(p) = prop(key, "Export Policy").as_deref().and_then(u32_of) {
                        k.set_export_policy(p);
                    }
                    if label == "software"
                        && let Some(u) = prop(key, "Unique Name").map(|b| string_of(&b))
                        && let Some((file, legacy)) = locate_key_file(&u, |p| p.is_file())
                    {
                        k.legacy = legacy;
                        if let Ok(sec) = crate::collectors::win::security(&file) {
                            k.readable_by = sec.readable_by;
                        }
                        k.file = Some(file.display().to_string());
                    }
                    NCryptFreeObject(key);
                }
            }
            out.push(k);
        }
        if !state.is_null() {
            unsafe { NCryptFreeBuffer(state) };
        }
        unsafe { NCryptFreeObject(prov) };
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_policy_and_identity() {
        let mut k = KeyObject {
            provider: "software",
            name: "te-WebServer-1234".into(),
            ..Default::default()
        };
        k.set_export_policy(ALLOW_EXPORT);
        assert!(k.exportable && !k.plaintext_exportable);
        k.set_export_policy(ALLOW_EXPORT | ALLOW_PLAINTEXT_EXPORT);
        assert!(k.plaintext_exportable);
        k.set_export_policy(0);
        assert!(!k.exportable);
        assert_eq!(k.identity(), r"key\machine\software\te-WebServer-1234");
        // SAFETY: only this test reads ProgramData.
        unsafe { std::env::set_var("ProgramData", r"C:\ProgramData") };
        let crypto = std::path::Path::new(r"C:\ProgramData")
            .join("Microsoft")
            .join("Crypto");
        let cng = crypto.join("Keys").join("abc_123");
        let capi = crypto.join("RSA").join("MachineKeys").join("abc_123");
        // A CNG key is found as such even when the provider reports a legacy key spec.
        assert_eq!(
            locate_key_file("abc_123", |p| p == cng),
            Some((cng.clone(), false))
        );
        assert_eq!(
            locate_key_file("abc_123", |p| p == capi),
            Some((capi.clone(), true))
        );
        assert_eq!(locate_key_file("abc_123", |_| false), None);
    }

    #[test]
    fn fields_in_sync() {
        let k = KeyObject {
            length: Some(2048),
            file: Some("f".into()),
            readable_by: vec!["Users".into()],
            ..Default::default()
        };
        crate::collectors::assert_fields(&k, FIELDS);
    }
}
