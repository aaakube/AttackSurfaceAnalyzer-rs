//! Security options as one object (`security\options`): the machine-wide settings
//! that decide how hard credential theft and lateral movement are. UAC, WDigest, LSA
//! protection and Credential Guard, LM/NTLM, anonymous access, SMBv1 and signing, and
//! RDP authentication. Values are effective: policy wins, and an unset value takes
//! Windows' default, so a rule sees `wdigest_plaintext: false` rather than a missing
//! registry value.

// Only constructed on Windows; compiled everywhere so the logic is unit-tested.
#![cfg_attr(not(windows), allow(dead_code))]

use super::registry::{RegValue, Registry};
use super::{Collector, Sink};
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;

pub const FIELDS: &[&str] = &[
    "uac_enabled",
    "uac_admin_prompt",
    "uac_secure_desktop",
    "remote_uac_filtering",
    "builtin_admin_approval",
    "wdigest_plaintext",
    "lsa_protection",
    "credential_guard",
    "lm_compatibility_level",
    "lm_hash_stored",
    "ntlm_outgoing",
    "restrict_anonymous",
    "restrict_anonymous_sam",
    "everyone_includes_anonymous",
    "smb1_server",
    "smb1_client",
    "smb_server_signing_required",
    "smb_client_signing_required",
    "smb_insecure_guest_logons",
    "remote_desktop",
    "rdp_nla",
];

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct SecurityOptions {
    /// EnableLUA: off means every administrator process runs elevated.
    pub uac_enabled: bool,
    /// How administrators are asked to elevate: elevate_without_prompt, credentials_secure_desktop,
    /// consent_secure_desktop, credentials, consent, consent_non_windows (the default).
    pub uac_admin_prompt: &'static str,
    pub uac_secure_desktop: bool,
    /// Off (LocalAccountTokenFilterPolicy = 1) gives local administrators full
    /// rights over the network: pass-the-hash with any local admin account.
    pub remote_uac_filtering: bool,
    /// Admin Approval Mode for the built-in Administrator account.
    pub builtin_admin_approval: bool,
    /// UseLogonCredential: WDigest keeps clear-text passwords in LSASS memory.
    pub wdigest_plaintext: bool,
    /// RunAsPPL: LSASS runs as a protected process.
    pub lsa_protection: bool,
    /// LsaCfgFlags: credentials isolated by virtualization-based security.
    pub credential_guard: bool,
    /// 0-5; below 3 the machine still sends LM or NTLMv1 responses.
    pub lm_compatibility_level: u64,
    /// NoLMHash = 0: LM hashes of new passwords are stored.
    pub lm_hash_stored: bool,
    /// Outgoing NTLM: allow, audit or deny.
    pub ntlm_outgoing: &'static str,
    pub restrict_anonymous: bool,
    pub restrict_anonymous_sam: bool,
    pub everyone_includes_anonymous: bool,
    pub smb1_server: bool,
    pub smb1_client: bool,
    pub smb_server_signing_required: bool,
    pub smb_client_signing_required: bool,
    pub smb_insecure_guest_logons: bool,
    pub remote_desktop: bool,
    /// Network Level Authentication required for RDP.
    pub rdp_nla: bool,
}

const UAC: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const LSA: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";
const WDIGEST: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
const DEVICE_GUARD: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard";
const SERVICES: &str = r"HKLM\SYSTEM\CurrentControlSet\Services";
const LANMAN_POLICY: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation";
const TS: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";
const TS_POLICY: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

fn num(reg: &dyn Registry, key: &str, name: &str) -> Option<u64> {
    match reg.value(key, name)? {
        RegValue::Num(n) => Some(n),
        RegValue::Str(s) => s.trim().parse().ok(),
        _ => None,
    }
}

pub fn read(reg: &dyn Registry) -> SecurityOptions {
    let n = |key: &str, name: &str, default: u64| num(reg, key, name).unwrap_or(default);
    let server = format!(r"{SERVICES}\LanmanServer\Parameters");
    let workstation = format!(r"{SERVICES}\LanmanWorkstation\Parameters");
    // SMBv1 ships as an optional feature; its client driver's service exists only when
    // the feature is installed.
    let smb1_driver = format!(r"{SERVICES}\mrxsmb10");
    let smb1_installed = reg.values(&smb1_driver).is_some();
    SecurityOptions {
        uac_enabled: n(UAC, "EnableLUA", 1) != 0,
        uac_admin_prompt: match n(UAC, "ConsentPromptBehaviorAdmin", 5) {
            0 => "elevate_without_prompt",
            1 => "credentials_secure_desktop",
            2 => "consent_secure_desktop",
            3 => "credentials",
            4 => "consent",
            _ => "consent_non_windows",
        },
        uac_secure_desktop: n(UAC, "PromptOnSecureDesktop", 1) != 0,
        remote_uac_filtering: n(UAC, "LocalAccountTokenFilterPolicy", 0) != 1,
        builtin_admin_approval: n(UAC, "FilterAdministratorToken", 0) == 1,
        wdigest_plaintext: n(WDIGEST, "UseLogonCredential", 0) == 1,
        lsa_protection: matches!(n(LSA, "RunAsPPL", 0), 1 | 2),
        credential_guard: matches!(
            num(reg, DEVICE_GUARD, "LsaCfgFlags").unwrap_or(n(LSA, "LsaCfgFlags", 0)),
            1 | 2
        ),
        lm_compatibility_level: n(LSA, "LmCompatibilityLevel", 3),
        lm_hash_stored: n(LSA, "NoLMHash", 1) == 0,
        ntlm_outgoing: match n(&format!(r"{LSA}\MSV1_0"), "RestrictSendingNTLMTraffic", 0) {
            1 => "audit",
            2 => "deny",
            _ => "allow",
        },
        restrict_anonymous: n(LSA, "RestrictAnonymous", 0) != 0,
        restrict_anonymous_sam: n(LSA, "RestrictAnonymousSAM", 1) != 0,
        everyone_includes_anonymous: n(LSA, "EveryoneIncludesAnonymous", 0) != 0,
        smb1_server: n(&server, "SMB1", if smb1_installed { 1 } else { 0 }) != 0,
        smb1_client: smb1_installed && n(&smb1_driver, "Start", 4) != 4,
        smb_server_signing_required: n(&server, "RequireSecuritySignature", 0) == 1,
        smb_client_signing_required: n(&workstation, "RequireSecuritySignature", 0) == 1,
        smb_insecure_guest_logons: num(reg, LANMAN_POLICY, "AllowInsecureGuestAuth").unwrap_or(n(
            &workstation,
            "AllowInsecureGuestAuth",
            0,
        )) == 1,
        remote_desktop: num(reg, TS_POLICY, "fDenyTSConnections").unwrap_or(n(
            TS,
            "fDenyTSConnections",
            1,
        )) == 0,
        rdp_nla: num(reg, TS_POLICY, "UserAuthentication").unwrap_or(n(
            &format!(r"{TS}\WinStations\RDP-Tcp"),
            "UserAuthentication",
            1,
        )) == 1,
    }
}

pub struct SecurityCollector<R: Registry> {
    pub reg: R,
}

impl<R: Registry> Collector for SecurityCollector<R> {
    fn name(&self) -> &'static str {
        "security"
    }

    fn collect(&self, sink: &Sink) -> Result<()> {
        if self.reg.values(LSA).is_none() {
            anyhow::bail!(r"{LSA} is not readable");
        }
        sink.emit(Record::new(
            Kind::Security,
            r"security\options",
            &read(&self.reg),
        ));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::registry::MemRegistry;

    #[test]
    fn defaults_when_nothing_is_set() {
        let mut r = MemRegistry::default();
        r.key(LSA, &[]);
        let s = read(&r);
        assert!(s.uac_enabled && s.uac_secure_desktop && s.remote_uac_filtering);
        assert_eq!(s.uac_admin_prompt, "consent_non_windows");
        assert!(!s.wdigest_plaintext && !s.lsa_protection && !s.credential_guard);
        assert_eq!(s.lm_compatibility_level, 3);
        assert!(!s.lm_hash_stored && s.restrict_anonymous_sam && !s.everyone_includes_anonymous);
        assert!(!s.smb1_server && !s.smb1_client && !s.smb_insecure_guest_logons);
        assert!(!s.remote_desktop && s.rdp_nla);
        assert_eq!(s.ntlm_outgoing, "allow");
    }

    #[test]
    fn weakened_settings_and_policy_precedence() {
        let mut r = MemRegistry::default();
        r.key(
            UAC,
            &[
                ("EnableLUA", RegValue::Num(0)),
                ("ConsentPromptBehaviorAdmin", RegValue::Num(0)),
                ("LocalAccountTokenFilterPolicy", RegValue::Num(1)),
            ],
        )
        .key(
            LSA,
            &[
                ("RunAsPPL", RegValue::Num(1)),
                ("LmCompatibilityLevel", RegValue::Num(1)),
                ("NoLMHash", RegValue::Num(0)),
                ("RestrictAnonymousSAM", RegValue::Num(0)),
            ],
        )
        .key(WDIGEST, &[("UseLogonCredential", RegValue::Num(1))])
        .key(
            &format!(r"{SERVICES}\mrxsmb10"),
            &[("Start", RegValue::Num(2))],
        )
        .key(&format!(r"{SERVICES}\LanmanServer\Parameters"), &[])
        .key(
            &format!(r"{SERVICES}\LanmanWorkstation\Parameters"),
            &[("AllowInsecureGuestAuth", RegValue::Num(1))],
        )
        .key(
            LANMAN_POLICY,
            &[("AllowInsecureGuestAuth", RegValue::Num(0))],
        )
        .key(TS, &[("fDenyTSConnections", RegValue::Num(0))])
        .key(
            &format!(r"{TS}\WinStations\RDP-Tcp"),
            &[("UserAuthentication", RegValue::Num(0))],
        );
        let s = read(&r);
        assert!(!s.uac_enabled && !s.remote_uac_filtering);
        assert_eq!(s.uac_admin_prompt, "elevate_without_prompt");
        assert!(s.wdigest_plaintext && s.lsa_protection && s.lm_hash_stored);
        assert_eq!(s.lm_compatibility_level, 1);
        assert!(!s.restrict_anonymous_sam);
        assert!(
            s.smb1_server && s.smb1_client,
            "feature installed, no SMB1=0"
        );
        assert!(!s.smb_insecure_guest_logons, "policy 0 beats local 1");
        assert!(s.remote_desktop && !s.rdp_nla);
    }

    #[test]
    fn fields_in_sync() {
        crate::collectors::assert_fields(&SecurityOptions::default(), FIELDS);
    }
}
