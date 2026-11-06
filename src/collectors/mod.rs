pub mod accounts;
pub mod binaries;
pub mod certs;
pub mod com;
pub mod files;
pub mod firewall;
pub mod pe;
pub mod ports;
pub mod registry;
pub mod services;
pub mod wifi;
pub mod win;

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

/// Top-level fields of each kind's objects, used to lint rules for typos.
pub fn known_fields() -> std::collections::HashMap<crate::model::Kind, &'static [&'static str]> {
    use crate::model::Kind;
    std::collections::HashMap::from([
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
    ])
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
