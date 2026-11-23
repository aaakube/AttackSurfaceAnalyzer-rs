pub mod accounts;
pub mod binaries;
pub mod certs;
pub mod com;
pub mod defender;
pub mod files;
pub mod firewall;
pub mod handlers;
pub mod keys;
pub mod linux;
pub mod pe;
pub mod ports;
pub mod registry;
pub mod rights;
pub mod security;
pub mod services;
pub mod tasks;
pub mod tpm;
pub mod unix;
pub mod wifi;
pub mod win;
pub mod wmi;
pub mod xml;

use crate::model::Record;
use anyhow::Result;
use crossbeam_channel::Sender;
use std::sync::atomic::{AtomicU64, Ordering};

/// Shared by all collectors of a run: where records go, and a count of
/// non-fatal problems (unreadable files, access denied, ...).
pub struct Sink {
    tx: Sender<Record>,
    warnings: AtomicU64,
    verbose: bool,
}

impl Sink {
    pub fn new(tx: Sender<Record>, verbose: bool) -> Self {
        Sink {
            tx,
            warnings: AtomicU64::new(0),
            verbose,
        }
    }

    pub fn emit(&self, record: Record) {
        // The receiver only goes away if ingestion failed; that error is reported there.
        let _ = self.tx.send(record);
    }

    pub fn warn(&self, msg: impl FnOnce() -> String) {
        self.warnings.fetch_add(1, Ordering::Relaxed);
        if self.verbose {
            eprintln!("warning: {}", msg());
        }
    }

    pub fn warnings(&self) -> u64 {
        self.warnings.load(Ordering::Relaxed)
    }
}

pub trait Collector: Sync {
    fn name(&self) -> &'static str;
    fn collect(&self, sink: &Sink) -> Result<()>;
}

/// Top-level fields of each kind's objects, used to lint rules for typos. A kind
/// collected on several platforms (users, services, ports) has the union of the
/// fields of each platform's objects.
pub fn known_fields() -> std::collections::HashMap<crate::model::Kind, Vec<&'static str>> {
    use crate::model::Kind;
    let mut out: std::collections::HashMap<Kind, Vec<&'static str>> = [
        (Kind::File, files::FIELDS),
        (Kind::Service, services::FIELDS),
        (Kind::Driver, services::FIELDS),
        (Kind::Firewall, firewall::FIELDS),
        (Kind::Com, com::FIELDS),
        (Kind::Registry, registry::FIELDS),
        (Kind::User, accounts::USER_FIELDS),
        (Kind::Group, accounts::GROUP_FIELDS),
        (Kind::Certificate, certs::FIELDS),
        (Kind::Port, ports::FIELDS),
        (Kind::Wifi, wifi::FIELDS),
        (Kind::Task, tasks::FIELDS),
        (Kind::Defender, defender::FIELDS),
        (Kind::Right, rights::FIELDS),
        (Kind::Security, security::FIELDS),
        (Kind::Wmi, wmi::FIELDS),
        (Kind::Tpm, tpm::FIELDS),
        (Kind::Key, keys::FIELDS),
        (Kind::Handler, handlers::FIELDS),
    ]
    .into_iter()
    .map(|(k, f)| (k, f.to_vec()))
    .collect();
    for (kind, fields) in [
        (Kind::User, linux::accounts::USER_FIELDS),
        (Kind::Group, linux::accounts::GROUP_FIELDS),
        (Kind::Service, linux::systemd::FIELDS),
    ] {
        let all = out.entry(kind).or_default();
        for f in fields {
            if !all.contains(f) {
                all.push(f);
            }
        }
    }
    out
}

/// Asserts a fully-populated object serializes to exactly the advertised fields.
#[cfg(test)]
pub fn assert_fields<T: serde::Serialize>(obj: &T, fields: &[&str]) {
    let v = serde_json::to_value(obj).unwrap();
    let mut got: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    let mut want = fields.to_vec();
    got.sort();
    want.sort();
    assert_eq!(got, want, "FIELDS out of sync with the serialized object");
}
