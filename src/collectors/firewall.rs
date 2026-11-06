//! Windows Firewall rules and profile settings, from the local store and from Group
//! Policy, read from the registry where the firewall service keeps them.

// Only constructed on Windows; compiled everywhere so the logic is unit-tested.
#![cfg_attr(not(windows), allow(dead_code))]

use super::registry::{RegValue, Registry, expand_env, join};
use super::{Collector, Sink};
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;

const STORES: &[(&str, &str)] = &[
    (
        "local",
        r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy",
    ),
    ("gpo", r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall"),
];
const PROFILES: &[(&str, &str)] = &[
    ("DomainProfile", "domain"),
    ("StandardProfile", "private"),
    ("PublicProfile", "public"),
];

pub const FIELDS: &[&str] = &[
    "type",
    "store",
    "id",
    "name",
    "description",
    "group",
    "action",
    "direction",
    "enabled",
    "profiles",
    "protocol",
    "local_ports",
    "remote_ports",
    "local_addresses",
    "remote_addresses",
    "program",
    "service",
    "package",
    "profile",
    "firewall_enabled",
    "default_inbound",
    "default_outbound",
];

/// One rule or one profile's settings; fields not relevant to the type are omitted.
#[derive(Serialize, Default)]
struct FirewallObject {
    r#type: &'static str,
    store: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    profiles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    local_ports: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    remote_ports: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    local_addresses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    remote_addresses: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    firewall_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_inbound: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_outbound: Option<&'static str>,
}

/// Splits `v2.33|Action=Allow|LPort=80|LPort=443|...|` into key -> values.
fn parse_rule_string(s: &str) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for part in s.split('|') {
        if let Some((k, v)) = part.split_once('=') {
            out.entry(k.to_string()).or_default().push(v.to_string());
        }
    }
    out
}

fn protocol_name(p: &str) -> String {
    match p {
        "1" => "icmpv4".into(),
        "6" => "tcp".into(),
        "17" => "udp".into(),
        "58" => "icmpv6".into(),
        other => other.to_string(),
    }
}

fn rule_object(store: &'static str, id: &str, raw: &str) -> FirewallObject {
    let f = parse_rule_string(raw);
    let one = |k: &str| f.get(k).and_then(|v| v.first()).cloned();
    // Port and address keys come in variants (LPort, LPort2_10, RA4, RA42, ...).
    let many = |prefixes: &[&str]| -> Vec<String> {
        let mut v: Vec<String> = f
            .iter()
            .filter(|(k, _)| prefixes.iter().any(|p| k.starts_with(p)))
            .flat_map(|(_, vals)| vals.iter().cloned())
            .collect();
        v.sort();
        v.dedup();
        v
    };
    let mut profiles = f.get("Profile").cloned().unwrap_or_default();
    profiles.sort();
    FirewallObject {
        r#type: "rule",
        store,
        id: Some(id.to_string()),
        name: one("Name"),
        description: one("Desc"),
        group: one("EmbedCtxt"),
        action: one("Action").map(|a| a.to_lowercase()),
        direction: one("Dir").map(|d| d.to_lowercase()),
        enabled: Some(one("Active").is_none_or(|a| a.eq_ignore_ascii_case("TRUE"))),
        profiles: if profiles.is_empty() {
            vec!["any".into()]
        } else {
            profiles.iter().map(|p| p.to_lowercase()).collect()
        },
        protocol: Some(
            one("Protocol")
                .map(|p| protocol_name(&p))
                .unwrap_or_else(|| "any".into()),
        ),
        local_ports: many(&["LPort"]),
        remote_ports: many(&["RPort"]),
        local_addresses: many(&["LA4", "LA6"]),
        remote_addresses: many(&["RA4", "RA6", "RA42", "RA62"]),
        program: one("App").map(|a| expand_env(&a)),
        service: one("Svc"),
        package: one("AppPkgId"),
        ..Default::default()
    }
}

pub struct FirewallCollector<R: Registry> {
    pub reg: R,
}

impl<R: Registry> Collector for FirewallCollector<R> {
    fn name(&self) -> &'static str {
        "firewall"
    }

    fn collect(&self, sink: &Sink) -> Result<()> {
        for &(store, base) in STORES {
            for &(key, profile) in PROFILES {
                let path = join(base, key);
                let Some(values) = self.reg.values(&path) else {
                    continue;
                };
                let num = |n: &str| {
                    values
                        .iter()
                        .find(|(k, _)| k == n)
                        .and_then(|(_, v)| v.as_num())
                };
                // Local defaults apply when a value is absent; for GPO, absent means
                // "not configured", which is reported as missing.
                let local = store == "local";
                let enabled = num("EnableFirewall")
                    .map(|v| v != 0)
                    .or(local.then_some(true));
                let action = |v: Option<u64>, default: &'static str| -> Option<&'static str> {
                    match v {
                        Some(0) => Some("allow"),
                        Some(_) => Some("block"),
                        None => local.then_some(default),
                    }
                };
                let obj = FirewallObject {
                    r#type: "profile",
                    store,
                    profile: Some(profile),
                    firewall_enabled: enabled,
                    default_inbound: action(num("DefaultInboundAction"), "block"),
                    default_outbound: action(num("DefaultOutboundAction"), "allow"),
                    ..Default::default()
                };
                sink.emit(Record::new(
                    Kind::Firewall,
                    format!(r"profile\{store}\{profile}"),
                    &obj,
                ));
            }
            for (id, value) in self
                .reg
                .values(&join(base, "FirewallRules"))
                .unwrap_or_default()
            {
                if let RegValue::Str(raw) = value {
                    let obj = rule_object(store, &id, &raw);
                    sink.emit(Record::new(
                        Kind::Firewall,
                        format!(r"rule\{store}\{id}"),
                        &obj,
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::registry::MemRegistry;

    const CHROME_MDNS: &str = r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=5353|App=C:\Program Files\Google\Chrome\Application\chrome.exe|Name=Google Chrome (mDNS-In)|Desc=Inbound rule for Google Chrome to allow mDNS traffic.|EmbedCtxt=Google Chrome|";

    #[test]
    fn parses_rules() {
        let r = rule_object("local", "{55BA6CF6}", CHROME_MDNS);
        assert_eq!(r.action.as_deref(), Some("allow"));
        assert_eq!(r.direction.as_deref(), Some("in"));
        assert_eq!(r.protocol.as_deref(), Some("udp"));
        assert_eq!(r.local_ports, vec!["5353"]);
        assert_eq!(r.profiles, vec!["any"]);
        assert_eq!(r.enabled, Some(true));
        assert_eq!(
            r.program.as_deref(),
            Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
        );
        let m = rule_object(
            "gpo",
            "x",
            "v2.30|Action=Block|Active=FALSE|Dir=Out|Profile=Public|Profile=Private|RA4=10.0.0.0/8|RA6=fe80::/64|LPort=80|LPort=443|",
        );
        assert_eq!(m.profiles, vec!["private", "public"]);
        assert_eq!(m.local_ports, vec!["443", "80"]);
        assert_eq!(m.remote_addresses, vec!["10.0.0.0/8", "fe80::/64"]);
        assert_eq!(m.enabled, Some(false));
        assert_eq!(m.protocol.as_deref(), Some("any"));
    }

    #[test]
    fn collects_profiles_and_rules() {
        let mut reg = MemRegistry::default();
        let base = STORES[0].1;
        reg.key(
            &join(base, "PublicProfile"),
            &[("EnableFirewall", RegValue::Num(0))],
        );
        reg.key(
            &join(base, "StandardProfile"),
            &[("DefaultInboundAction", RegValue::Num(0))],
        );
        reg.key(
            &join(base, "FirewallRules"),
            &[("{55BA6CF6}", RegValue::Str(CHROME_MDNS.into()))],
        );
        let (tx, rx) = crossbeam_channel::unbounded();
        let sink = Sink::new(tx, false);
        FirewallCollector { reg }.collect(&sink).unwrap();
        drop(sink);
        let recs: BTreeMap<String, serde_json::Value> =
            rx.iter().map(|r| (r.identity, r.data)).collect();
        assert_eq!(recs[r"profile\local\public"]["firewall_enabled"], false);
        assert_eq!(recs[r"profile\local\public"]["default_inbound"], "block");
        assert_eq!(recs[r"profile\local\private"]["default_inbound"], "allow");
        assert_eq!(
            recs[r"rule\local\{55BA6CF6}"]["name"],
            "Google Chrome (mDNS-In)"
        );
        assert!(
            !recs.keys().any(|k| k.contains("domain")),
            "absent profile key is skipped"
        );
    }

    #[test]
    fn fields_in_sync() {
        let s = || Some(String::new());
        let obj = FirewallObject {
            r#type: "rule",
            store: "local",
            id: s(),
            name: s(),
            description: s(),
            group: s(),
            action: s(),
            direction: s(),
            enabled: Some(true),
            profiles: vec!["any".into()],
            protocol: s(),
            local_ports: vec!["1".into()],
            remote_ports: vec!["1".into()],
            local_addresses: vec!["a".into()],
            remote_addresses: vec!["a".into()],
            program: s(),
            service: s(),
            package: s(),
            profile: Some("public"),
            firewall_enabled: Some(true),
            default_inbound: Some("block"),
            default_outbound: Some("allow"),
        };
        crate::collectors::assert_fields(&obj, FIELDS);
    }
}
