//! Saved Wi-Fi profiles, read from the WLAN service's profile files
//! (`%ProgramData%\Microsoft\Wlansvc\Profiles\Interfaces\{adapter}\*.xml`), so it
//! works offline and without the WLAN service running. Keys are never collected:
//! only whether one is stored and whether it is protected (encrypted).

use super::{Collector, Sink};
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;
use std::path::{Path, PathBuf};

pub const FIELDS: &[&str] = &[
    "interface",
    "name",
    "ssid",
    "connection_type",
    "connection_mode",
    "hidden_network",
    "authentication",
    "encryption",
    "uses_802_1x",
    "key_type",
    "key_protected",
];

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct WifiObject {
    pub interface: String,
    pub name: String,
    pub ssid: String,
    pub connection_type: String,
    /// auto or manual.
    pub connection_mode: String,
    pub hidden_network: bool,
    pub authentication: String,
    pub encryption: String,
    pub uses_802_1x: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    /// false means the key is stored in clear text in the profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_protected: Option<bool>,
}

/// Text of the first `<tag>` element inside `xml` (namespace-agnostic, no nesting
/// of the same tag needed for WLAN profiles).
fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{name}>"))? + start;
    Some(xml[start..end].trim())
}

fn section<'a>(xml: &'a str, name: &str) -> &'a str {
    tag(xml, name).unwrap_or("")
}

pub fn parse_profile(interface: &str, xml: &str) -> Option<WifiObject> {
    let name = tag(xml, "name")?.to_string();
    let ssid_cfg = section(xml, "SSIDConfig");
    let ssid = section(ssid_cfg, "SSID");
    let security = section(section(xml, "MSM"), "security");
    let auth = section(security, "authEncryption");
    let shared = tag(security, "sharedKey");
    Some(WifiObject {
        interface: interface.to_string(),
        ssid: tag(ssid, "name")
            .map(String::from)
            .or_else(|| tag(ssid, "hex").map(String::from))
            .unwrap_or_default(),
        connection_type: tag(xml, "connectionType").unwrap_or("").to_string(),
        connection_mode: tag(xml, "connectionMode").unwrap_or("manual").to_string(),
        hidden_network: tag(ssid_cfg, "nonBroadcast") == Some("true"),
        authentication: tag(auth, "authentication").unwrap_or("").to_string(),
        encryption: tag(auth, "encryption").unwrap_or("").to_string(),
        uses_802_1x: tag(auth, "useOneX") == Some("true"),
        key_type: shared.and_then(|s| tag(s, "keyType")).map(String::from),
        key_protected: shared.map(|s| tag(s, "protected") != Some("false")),
        name,
    })
}

pub fn default_root() -> PathBuf {
    let pd = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    Path::new(&pd).join(r"Microsoft\Wlansvc\Profiles\Interfaces")
}

pub struct WifiCollector {
    /// The `Interfaces` directory; one subdirectory per wireless adapter.
    pub root: PathBuf,
}

impl Collector for WifiCollector {
    fn name(&self) -> &'static str {
        "wifi"
    }

    fn collect(&self, sink: &Sink) -> Result<()> {
        let Ok(adapters) = std::fs::read_dir(&self.root) else {
            return Ok(()); // no wireless adapter has ever stored a profile
        };
        for adapter in adapters.flatten() {
            let iface = adapter.file_name().to_string_lossy().into_owned();
            let Ok(files) = std::fs::read_dir(adapter.path()) else {
                continue;
            };
            for f in files.flatten() {
                let path = f.path();
                if path.extension().and_then(|e| e.to_str()) != Some("xml") {
                    continue;
                }
                match std::fs::read(&path) {
                    Ok(bytes) => {
                        let text = super::xml::decode(&bytes);
                        match parse_profile(&iface, &text) {
                            Some(p) => sink.emit(Record::new(
                                Kind::Wifi,
                                format!(r"wifi\{iface}\{}", p.name),
                                &p,
                            )),
                            None => sink.warn(|| format!("{}: not a WLAN profile", path.display())),
                        }
                    }
                    Err(e) => sink.warn(|| format!("{}: {e}", path.display())),
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WPA2: &str = r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>Office</name>
  <SSIDConfig><SSID><hex>4F6666696365</hex><name>Office</name></SSID><nonBroadcast>true</nonBroadcast></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM><security>
    <authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption><useOneX>false</useOneX></authEncryption>
    <sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>SuperSecret!</keyMaterial></sharedKey>
  </security></MSM>
</WLANProfile>"#;

    const OPEN: &str = r#"<WLANProfile><name>Cafe</name><SSIDConfig><SSID><name>Cafe WiFi</name></SSID></SSIDConfig>
<connectionType>ESS</connectionType><connectionMode>auto</connectionMode>
<MSM><security><authEncryption><authentication>open</authentication><encryption>none</encryption><useOneX>false</useOneX></authEncryption></security></MSM></WLANProfile>"#;

    #[test]
    fn parses_profiles_without_keeping_keys() {
        let p = parse_profile("{IF}", WPA2).unwrap();
        assert_eq!(p.name, "Office");
        assert_eq!(p.ssid, "Office");
        assert!(p.hidden_network);
        assert_eq!(p.authentication, "WPA2PSK");
        assert_eq!(p.key_protected, Some(false));
        let json = serde_json::to_string(&p).unwrap();
        assert!(
            !json.contains("SuperSecret"),
            "key material must never be collected"
        );
        let o = parse_profile("{IF}", OPEN).unwrap();
        assert_eq!(
            (o.authentication.as_str(), o.encryption.as_str()),
            ("open", "none")
        );
        assert_eq!(o.key_protected, None);
        assert_eq!(o.connection_mode, "auto");
    }

    #[test]
    fn collects_from_profile_directory() {
        let dir = tempfile::tempdir().unwrap();
        let iface = dir.path().join("{11111111-2222-3333-4444-555555555555}");
        std::fs::create_dir(&iface).unwrap();
        std::fs::write(iface.join("a.xml"), OPEN).unwrap();
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain(WPA2.encode_utf16().flat_map(|c| c.to_le_bytes()))
            .collect();
        std::fs::write(iface.join("b.xml"), utf16).unwrap();
        let (tx, rx) = crossbeam_channel::unbounded();
        let sink = Sink::new(tx, false);
        WifiCollector {
            root: dir.path().into(),
        }
        .collect(&sink)
        .unwrap();
        drop(sink);
        let mut ids: Vec<String> = rx.iter().map(|r| r.identity).collect();
        ids.sort();
        assert_eq!(
            ids,
            vec![
                r"wifi\{11111111-2222-3333-4444-555555555555}\Cafe".to_string(),
                r"wifi\{11111111-2222-3333-4444-555555555555}\Office".to_string(),
            ]
        );
    }

    #[test]
    fn fields_in_sync() {
        let p = WifiObject {
            key_type: Some("x".into()),
            key_protected: Some(true),
            ..Default::default()
        };
        crate::collectors::assert_fields(&p, FIELDS);
    }
}
