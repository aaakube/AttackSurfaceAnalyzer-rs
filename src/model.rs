use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::str::FromStr;

/// The category of a collected object. Every object belongs to exactly one kind,
/// and `(kind, identity)` is unique within a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    File,
    Service,
    Driver,
    Firewall,
    Com,
    Registry,
    User,
    Group,
    Certificate,
    Port,
    Wifi,
}

impl Kind {
    pub const ALL: [Kind; 11] = [
        Kind::File,
        Kind::Service,
        Kind::Driver,
        Kind::Firewall,
        Kind::Com,
        Kind::Registry,
        Kind::User,
        Kind::Group,
        Kind::Certificate,
        Kind::Port,
        Kind::Wifi,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::Service => "service",
            Kind::Driver => "driver",
            Kind::Firewall => "firewall",
            Kind::Com => "com",
            Kind::Registry => "registry",
            Kind::User => "user",
            Kind::Group => "group",
            Kind::Certificate => "certificate",
            Kind::Port => "port",
            Kind::Wifi => "wifi",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Kind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        Kind::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| anyhow::anyhow!("unknown kind '{s}'"))
    }
}

/// A single collected object, already serialized to JSON so the store and the
/// rules engine can treat every kind uniformly.
#[derive(Debug, Clone)]
pub struct Record {
    pub kind: Kind,
    pub identity: String,
    pub data: Value,
}

impl Record {
    pub fn new<T: Serialize>(kind: Kind, identity: impl Into<String>, obj: &T) -> Self {
        Record {
            kind,
            identity: identity.into(),
            data: serde_json::to_value(obj).expect("collector objects always serialize"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeType {
    Created,
    Deleted,
    Modified,
}

impl fmt::Display for ChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ChangeType::Created => "created",
            ChangeType::Deleted => "deleted",
            ChangeType::Modified => "modified",
        })
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Debug,
    #[default]
    Info,
    Warning,
    Error,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Debug => "debug",
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Critical => "critical",
        })
    }
}

impl FromStr for Severity {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        serde_json::from_value(Value::String(s.to_ascii_lowercase()))
            .map_err(|_| anyhow::anyhow!("unknown severity '{s}'"))
    }
}

/// One leaf-level difference between the base and compare versions of an object.
#[derive(Debug, Clone, Serialize)]
pub struct FieldDiff {
    pub field: String,
    pub before: Value,
    pub after: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub kind: Kind,
    pub identity: String,
    pub change: ChangeType,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diffs: Vec<FieldDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compare: Option<Value>,
}

impl Change {
    /// The version of the object rules are evaluated against: the new state,
    /// or the old one if the object was deleted.
    pub fn subject(&self) -> &Value {
        self.compare
            .as_ref()
            .or(self.base.as_ref())
            .expect("a change always has at least one side")
    }
}
