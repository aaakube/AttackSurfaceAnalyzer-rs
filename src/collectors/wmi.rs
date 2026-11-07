//! Permanent WMI event subscriptions: an event filter (a WQL query, e.g. "every
//! boot" or "when this process starts") bound to a consumer that runs a command
//! line or a script, which the WMI service then runs as SYSTEM. A classic fileless
//! persistence spot that neither the file nor the registry collectors see, because
//! it lives in the WMI repository. Read through the WMI COM API from
//! `root\subscription` and `root\default`.
//!
//! Also hosts the small WMI query helper the TPM collector uses.

// Only constructed on Windows; compiled everywhere so the logic is unit-tested.
#![cfg_attr(not(windows), allow(dead_code, unused_imports))]

use super::{Collector, Sink, binaries, win};
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const NAMESPACES: &[&str] = &[r"root\subscription", r"root\default"];

pub const FIELDS: &[&str] = &[
    "type",
    "namespace",
    "name",
    "class",
    "query",
    "query_language",
    "event_namespace",
    "command_line",
    "executable",
    "working_directory",
    "script_engine",
    "script_text",
    "script_file",
    "target",
    "filter",
    "consumer",
    "binary",
    "binary_missing",
    "binary_signature",
    "binary_writable_by",
];

/// A filter, a consumer or a binding. Only the fields of its type are set.
#[derive(Serialize, Debug, Default, PartialEq)]
pub struct WmiObject {
    /// filter, consumer or binding.
    pub r#type: &'static str,
    pub namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Consumer class: CommandLineEventConsumer, ActiveScriptEventConsumer, ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_engine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_file: Option<String>,
    /// Log file, event log source or mail recipient of the other consumer types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Binding: the filter and consumer it ties together (WMI object paths).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<String>,
    /// Command-line consumer: the program it runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub binary_missing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_signature: Option<win::Signature>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub binary_writable_by: Vec<String>,
}

/// One WMI instance: property name -> value.
pub type Row = BTreeMap<String, Value>;

fn text(row: &Row, name: &str) -> Option<String> {
    match row.get(name)? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Null => None,
        Value::String(_) => None,
        other => Some(other.to_string()),
    }
}

pub const FILTER_PROPS: &[&str] = &["Name", "Query", "QueryLanguage", "EventNamespace"];
pub const CONSUMER_PROPS: &[&str] = &[
    "__CLASS",
    "Name",
    "CommandLineTemplate",
    "ExecutablePath",
    "WorkingDirectory",
    "ScriptingEngine",
    "ScriptText",
    "ScriptFileName",
    "Filename",
    "SourceName",
    "ToLine",
];
pub const BINDING_PROPS: &[&str] = &["Filter", "Consumer"];

/// Builds (identity, object) pairs from the rows of one namespace.
pub fn objects(
    ns: &str,
    filters: &[Row],
    consumers: &[Row],
    bindings: &[Row],
) -> Vec<(String, WmiObject)> {
    let mut out = Vec::new();
    for f in filters {
        let name = text(f, "Name").unwrap_or_default();
        out.push((
            format!(r"wmi\{ns}\filter\{name}"),
            WmiObject {
                r#type: "filter",
                namespace: ns.to_string(),
                name: Some(name),
                query: text(f, "Query"),
                query_language: text(f, "QueryLanguage"),
                event_namespace: text(f, "EventNamespace"),
                ..Default::default()
            },
        ));
    }
    for c in consumers {
        let name = text(c, "Name").unwrap_or_default();
        let class = text(c, "__CLASS").unwrap_or_else(|| "__EventConsumer".into());
        let command_line = text(c, "CommandLineTemplate");
        let executable = text(c, "ExecutablePath");
        // The program: ExecutablePath if set, else the start of the command line.
        let binary = executable
            .as_deref()
            .and_then(|e| binaries::parse_command(&format!("\"{}\"", e.trim_matches('"'))).0)
            .or_else(|| {
                command_line
                    .as_deref()
                    .and_then(|c| binaries::parse_command(c).0)
            })
            .map(|b| super::tasks::resolve_command(&b));
        out.push((
            format!(r"wmi\{ns}\consumer\{class}\{name}"),
            WmiObject {
                r#type: "consumer",
                namespace: ns.to_string(),
                name: Some(name),
                class: Some(class),
                command_line,
                executable,
                working_directory: text(c, "WorkingDirectory"),
                script_engine: text(c, "ScriptingEngine"),
                script_text: text(c, "ScriptText"),
                script_file: text(c, "ScriptFileName"),
                target: text(c, "Filename")
                    .or_else(|| text(c, "SourceName"))
                    .or_else(|| text(c, "ToLine")),
                binary,
                ..Default::default()
            },
        ));
    }
    for b in bindings {
        let filter = text(b, "Filter").unwrap_or_default();
        let consumer = text(b, "Consumer").unwrap_or_default();
        out.push((
            format!(r"wmi\{ns}\binding\{filter} -> {consumer}"),
            WmiObject {
                r#type: "binding",
                namespace: ns.to_string(),
                filter: Some(filter),
                consumer: Some(consumer),
                ..Default::default()
            },
        ));
    }
    out
}

pub struct WmiCollector {
    pub threads: usize,
    pub signatures: bool,
}

impl Collector for WmiCollector {
    fn name(&self) -> &'static str {
        "wmi"
    }

    #[cfg(windows)]
    fn collect(&self, sink: &Sink) -> Result<()> {
        let mut all = Vec::new();
        for ns in NAMESPACES {
            let q = |class: &str, props: &[&str]| {
                com::query(ns, &format!("SELECT * FROM {class}"), props)
            };
            match (
                q("__EventFilter", FILTER_PROPS),
                q("__EventConsumer", CONSUMER_PROPS),
                q("__FilterToConsumerBinding", BINDING_PROPS),
            ) {
                (Ok(f), Ok(c), Ok(b)) => all.extend(objects(ns, &f, &c, &b)),
                (f, c, b) => {
                    let err = [f.err(), c.err(), b.err()].into_iter().flatten().next();
                    sink.warn(|| {
                        format!(
                            r"WMI {ns}: {}",
                            err.map(|e| e.to_string()).unwrap_or_default()
                        )
                    });
                }
            }
        }
        let paths: BTreeSet<String> = all.iter().filter_map(|(_, o)| o.binary.clone()).collect();
        let info: HashMap<String, binaries::BinaryInfo> =
            binaries::describe(paths, self.threads, self.signatures);
        for (id, mut o) in all {
            if let Some(b) = &o.binary {
                let i = info.get(&b.to_lowercase()).cloned().unwrap_or_default();
                o.binary_missing = !i.exists;
                o.binary_signature = i.signature;
                o.binary_writable_by = i.writable_by;
            }
            sink.emit(Record::new(Kind::Wmi, id, &o));
        }
        Ok(())
    }

    #[cfg(not(windows))]
    fn collect(&self, _sink: &Sink) -> Result<()> {
        anyhow::bail!("WMI is only available on Windows")
    }
}

/// Minimal WMI client: one query, selected properties of each instance as JSON.
#[cfg(windows)]
pub mod com {
    use super::Row;
    use anyhow::{Context, Result};
    use serde_json::Value;
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoInitializeSecurity, CoSetProxyBlanket, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Variant::{
        VARIANT, VT_BOOL, VT_BSTR, VT_EMPTY, VT_I1, VT_I2, VT_I4, VT_I8, VT_NULL, VT_UI1, VT_UI2,
        VT_UI4, VT_UI8, VariantClear,
    };
    use windows::Win32::System::Wmi::{
        IWbemClassObject, IWbemLocator, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY,
        WBEM_INFINITE, WbemLocator,
    };
    use windows::core::{BSTR, HSTRING, PCWSTR};

    fn init() {
        static SECURITY: std::sync::Once = std::sync::Once::new();
        unsafe {
            // Each collector thread joins the multithreaded apartment; S_FALSE (already
            // initialized) is fine.
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            SECURITY.call_once(|| {
                let _ = CoInitializeSecurity(
                    None,
                    -1,
                    None,
                    None,
                    RPC_C_AUTHN_LEVEL_DEFAULT,
                    RPC_C_IMP_LEVEL_IMPERSONATE,
                    None,
                    EOAC_NONE,
                    None,
                );
            });
        }
    }

    unsafe fn json(v: &VARIANT) -> Value {
        unsafe {
            let inner = &v.Anonymous.Anonymous;
            let vt = inner.vt;
            let u = &inner.Anonymous;
            match vt {
                VT_EMPTY | VT_NULL => Value::Null,
                VT_BSTR => Value::String(u.bstrVal.to_string()),
                VT_BOOL => Value::Bool(u.boolVal.as_bool()),
                VT_I1 => Value::from(u.cVal),
                VT_UI1 => Value::from(u.bVal),
                VT_I2 => Value::from(u.iVal),
                VT_UI2 => Value::from(u.uiVal),
                VT_I4 => Value::from(u.lVal),
                VT_UI4 => Value::from(u.ulVal),
                VT_I8 => Value::from(u.llVal),
                VT_UI8 => Value::from(u.ullVal),
                // Arrays and embedded objects are not needed by any collector.
                _ => Value::Null,
            }
        }
    }

    pub fn query(namespace: &str, wql: &str, props: &[&str]) -> Result<Vec<Row>> {
        init();
        unsafe {
            let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
                .context("creating the WMI locator")?;
            let server = locator
                .ConnectServer(
                    &BSTR::from(namespace),
                    &BSTR::new(),
                    &BSTR::new(),
                    &BSTR::new(),
                    0,
                    &BSTR::new(),
                    None,
                )
                .with_context(|| format!("connecting to {namespace}"))?;
            CoSetProxyBlanket(
                &server,
                10, // RPC_C_AUTHN_WINNT
                0,  // RPC_C_AUTHZ_NONE
                PCWSTR::null(),
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
            )?;
            let rows = server
                .ExecQuery(
                    &BSTR::from("WQL"),
                    &BSTR::from(wql),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    None,
                )
                .with_context(|| format!("{wql} in {namespace}"))?;
            let mut out = Vec::new();
            loop {
                let mut objs: [Option<IWbemClassObject>; 1] = [None];
                let mut returned = 0u32;
                rows.Next(WBEM_INFINITE, &mut objs, &mut returned).ok()?;
                if returned == 0 {
                    break;
                }
                let Some(obj) = objs[0].take() else { break };
                let mut row = Row::new();
                for p in props {
                    let mut v = VARIANT::default();
                    let name = HSTRING::from(*p);
                    // A property the instance's class doesn't have is just absent.
                    if obj.Get(&name, 0, &mut v, None, None).is_ok() {
                        row.insert(p.to_string(), json(&v));
                        let _ = VariantClear(&mut v);
                    }
                }
                out.push(row);
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(v: Value) -> Row {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn builds_filters_consumers_and_bindings() {
        // SAFETY: tests that read SystemRoot all set the same value.
        unsafe { std::env::set_var("SystemRoot", r"C:\Windows") };
        let f = [row(
            json!({"Name": "AtBoot", "Query": "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'", "QueryLanguage": "WQL", "EventNamespace": "root\\cimv2"}),
        )];
        let c = [
            row(
                json!({"__CLASS": "CommandLineEventConsumer", "Name": "Updater", "CommandLineTemplate": "powershell.exe -nop -w hidden -enc AAAA", "ExecutablePath": null}),
            ),
            row(
                json!({"__CLASS": "ActiveScriptEventConsumer", "Name": "Js", "ScriptingEngine": "JScript", "ScriptText": "new ActiveXObject('WScript.Shell').Run('calc')"}),
            ),
            row(
                json!({"__CLASS": "NTEventLogEventConsumer", "Name": "SCM Event Log Consumer", "SourceName": "Service Control Manager"}),
            ),
        ];
        let b = [row(
            json!({"Filter": "__EventFilter.Name=\"AtBoot\"", "Consumer": "CommandLineEventConsumer.Name=\"Updater\""}),
        )];
        let objs = objects(r"root\subscription", &f, &c, &b);
        let ids: Vec<&str> = objs.iter().map(|(i, _)| i.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                r"wmi\root\subscription\filter\AtBoot",
                r"wmi\root\subscription\consumer\CommandLineEventConsumer\Updater",
                r"wmi\root\subscription\consumer\ActiveScriptEventConsumer\Js",
                r"wmi\root\subscription\consumer\NTEventLogEventConsumer\SCM Event Log Consumer",
                r#"wmi\root\subscription\binding\__EventFilter.Name="AtBoot" -> CommandLineEventConsumer.Name="Updater""#,
            ]
        );
        let cmd = &objs[1].1;
        assert_eq!(
            cmd.binary.as_deref(),
            Some(r"C:\Windows\System32\powershell.exe")
        );
        assert_eq!(objs[2].1.script_engine.as_deref(), Some("JScript"));
        assert!(objs[2].1.binary.is_none());
        assert_eq!(objs[3].1.target.as_deref(), Some("Service Control Manager"));
        assert_eq!(objs[0].1.query_language.as_deref(), Some("WQL"));
    }

    #[test]
    fn fields_in_sync() {
        let o = WmiObject {
            name: Some("n".into()),
            class: Some("c".into()),
            query: Some("q".into()),
            query_language: Some("q".into()),
            event_namespace: Some("e".into()),
            command_line: Some("c".into()),
            executable: Some("e".into()),
            working_directory: Some("w".into()),
            script_engine: Some("s".into()),
            script_text: Some("s".into()),
            script_file: Some("s".into()),
            target: Some("t".into()),
            filter: Some("f".into()),
            consumer: Some("c".into()),
            binary: Some("b".into()),
            binary_missing: true,
            binary_signature: Some(win::Signature {
                status: "valid".into(),
                source: None,
                signer: None,
            }),
            binary_writable_by: vec!["Users".into()],
            ..Default::default()
        };
        crate::collectors::assert_fields(&o, FIELDS);
    }
}
