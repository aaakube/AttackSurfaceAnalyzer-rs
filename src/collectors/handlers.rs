//! URL protocol handlers: registry keys (under `SOFTWARE\Classes`) that carry a
//! `URL Protocol` value, so a `scheme:` link launches a program. A handler is a
//! one-click attack path — a link in a browser or document opens the registered
//! program with attacker-controlled input — and a hijack target: whoever can write
//! the key chooses what runs. The launch command's binary is described like any
//! other (signature, writability).

// Only constructed on Windows; compiled everywhere so the logic is unit-tested.
#![cfg_attr(not(windows), allow(dead_code))]

use super::binaries::{self, BinaryInfo};
use super::registry::{Registry, join, user_sids};
use super::{Collector, Sink};
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};

pub const FIELDS: &[&str] = &[
    "scheme",
    "store",
    "name",
    "command",
    "binary",
    "delegate_execute",
    "binary_missing",
    "binary_signature",
    "binary_writable_by",
    "writable_by",
];

#[derive(Serialize, Default)]
struct HandlerObject {
    scheme: String,
    /// machine, wow64, or user (a per-user Classes hive).
    store: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    /// The raw `shell\open\command` the scheme launches.
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    /// Resolved executable from the command.
    #[serde(skip_serializing_if = "Option::is_none")]
    binary: Option<String>,
    /// CLSID invoked instead of a command line (DelegateExecute), when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    delegate_execute: Option<String>,
    binary_missing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    binary_signature: Option<super::win::Signature>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    binary_writable_by: Vec<String>,
    /// Low-privileged principals who can rewrite the handler key (hijack the scheme).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    writable_by: Vec<String>,
}

pub struct HandlersCollector<R: Registry> {
    pub reg: R,
    pub signatures: bool,
    pub threads: usize,
}

/// The `SOFTWARE\Classes` roots to scan: machine, 32-bit, and each loaded user's
/// own class hive (`HKU\<sid>_Classes`, where per-user registrations live).
fn class_roots(reg: &dyn Registry) -> Vec<(&'static str, String, Option<String>)> {
    let mut roots = vec![
        ("machine", r"HKLM\SOFTWARE\Classes".to_string(), None),
        (
            "wow64",
            r"HKLM\SOFTWARE\WOW6432Node\Classes".to_string(),
            None,
        ),
    ];
    for sid in user_sids(reg) {
        roots.push(("user", format!(r"HKU\{sid}_Classes"), Some(sid)));
    }
    roots
}

impl<R: Registry> Collector for HandlersCollector<R> {
    fn name(&self) -> &'static str {
        "handlers"
    }

    fn collect(&self, sink: &Sink) -> Result<()> {
        let mut found: Vec<(String, HandlerObject)> = Vec::new();
        for (store, root, sid) in class_roots(&self.reg) {
            let Some(schemes) = self.reg.subkeys(&root) else {
                continue;
            };
            for scheme in schemes {
                let key = join(&root, &scheme);
                // A URL protocol handler is marked by a (usually empty) URL Protocol
                // value; without it the key is an ordinary class or file association.
                if self.reg.value(&key, "URL Protocol").is_none() {
                    continue;
                }
                let cmd_key = join(&key, r"shell\open\command");
                let command = self.reg.string(&cmd_key, "");
                let binary = command
                    .as_deref()
                    .and_then(|c| binaries::parse_command(c).0);
                let identity = match &sid {
                    Some(s) => format!(r"user\{s}\handler\{scheme}"),
                    None if store == "wow64" => format!(r"handler\wow64\{scheme}"),
                    None => format!(r"handler\{scheme}"),
                };
                found.push((
                    identity,
                    HandlerObject {
                        name: self.reg.string(&key, ""),
                        delegate_execute: self.reg.string(&cmd_key, "DelegateExecute"),
                        writable_by: self.reg.writable_by(&key),
                        command,
                        binary,
                        store,
                        scheme,
                        ..Default::default()
                    },
                ));
            }
        }

        let paths: BTreeSet<String> = found.iter().filter_map(|(_, o)| o.binary.clone()).collect();
        let info: HashMap<String, BinaryInfo> =
            binaries::describe(paths, self.threads, self.signatures);
        for (identity, mut obj) in found {
            if let Some(b) = &obj.binary {
                let i = info.get(&b.to_lowercase()).cloned().unwrap_or_default();
                obj.binary_missing = !i.exists;
                obj.binary_signature = i.signature;
                obj.binary_writable_by = i.writable_by;
            }
            sink.emit(Record::new(Kind::Handler, identity, &obj));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::registry::{MemRegistry, RegValue};

    #[test]
    fn collects_url_protocol_handlers() {
        // SAFETY: same value the other collector tests set.
        unsafe { std::env::set_var("SystemRoot", r"C:\Windows") };
        let mut reg = MemRegistry::default();
        let s = |v: &str| RegValue::Str(v.into());
        // A real URL protocol handler.
        reg.key(
            r"HKLM\SOFTWARE\Classes\vnd.libreoffice.command",
            &[
                ("(default)", s("URL:LibreOffice command")),
                ("URL Protocol", s("")),
            ],
        );
        reg.key(
            r"HKLM\SOFTWARE\Classes\vnd.libreoffice.command\shell\open\command",
            &[(
                "(default)",
                s(r#""C:\Program Files\LibreOffice\program\soffice.exe" "%1""#),
            )],
        );
        // An ordinary class without URL Protocol is ignored.
        reg.key(
            r"HKLM\SOFTWARE\Classes\.odt",
            &[("(default)", s("LibreOffice.WriterDocument.1"))],
        );

        let c = HandlersCollector {
            reg,
            signatures: false,
            threads: 2,
        };
        let (tx, rx) = crossbeam_channel::unbounded();
        let sink = Sink::new(tx, false);
        c.collect(&sink).unwrap();
        drop(sink);
        let recs: HashMap<String, serde_json::Value> =
            rx.iter().map(|r| (r.identity, r.data)).collect();

        assert_eq!(recs.len(), 1, "only the URL protocol handler is collected");
        let h = &recs[r"handler\vnd.libreoffice.command"];
        assert_eq!(h["scheme"], "vnd.libreoffice.command");
        assert_eq!(h["store"], "machine");
        assert_eq!(h["name"], "URL:LibreOffice command");
        assert_eq!(
            h["binary"],
            r"C:\Program Files\LibreOffice\program\soffice.exe"
        );
    }

    #[test]
    fn fields_in_sync() {
        let obj = HandlerObject {
            name: Some(String::new()),
            command: Some(String::new()),
            binary: Some(String::new()),
            delegate_execute: Some(String::new()),
            binary_signature: Some(super::super::win::Signature {
                status: "valid".into(),
                source: None,
                signer: None,
            }),
            binary_writable_by: vec!["Users".into()],
            writable_by: vec!["Users".into()],
            ..Default::default()
        };
        crate::collectors::assert_fields(&obj, FIELDS);
    }
}
