//! Listening TCP ports and bound UDP ports, with the owning program, the Windows
//! services it hosts, and that program's signature and permissions.
//!
//! Many Windows components listen on a random port from the dynamic range
//! (49152-65535) that changes on every boot. Keying those by port number would make
//! each reboot look like ports opening and closing, so dynamic-range sockets are
//! grouped per program (or per hosted service) without the port number. Process IDs
//! are never stored, for the same reason.

// Only constructed on Windows; compiled everywhere so the logic is unit-tested.
#![cfg_attr(not(windows), allow(dead_code))]

use super::binaries;
use super::{Collector, Sink, win};
use crate::model::{Kind, Record};
use anyhow::Result;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

/// Start of the default Windows dynamic (ephemeral) port range.
pub const DYNAMIC_START: u16 = 49152;

pub struct Socket {
    pub protocol: &'static str,
    pub address: IpAddr,
    pub port: u16,
    pub pid: u32,
}

/// What we know about a process: image path and hosted services.
#[derive(Default, Clone)]
pub struct Owner {
    pub image: Option<String>,
    pub services: Vec<String>,
}

pub const FIELDS: &[&str] = &[
    "protocol",
    "family",
    "address",
    "port",
    "dynamic",
    "scope",
    "process",
    "process_name",
    "services",
    "process_signature",
    "process_writable_by",
];

#[derive(Serialize, Default)]
struct PortObject {
    protocol: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    family: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    dynamic: bool,
    /// any (all interfaces), loopback, or specific.
    scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    process: Option<String>,
    process_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    services: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_signature: Option<win::Signature>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    process_writable_by: Vec<String>,
}

fn scope(a: &IpAddr) -> &'static str {
    if a.is_unspecified() {
        "any"
    } else if a.is_loopback() {
        "loopback"
    } else {
        "specific"
    }
}

/// The wider of two scopes: listening anywhere beats listening locally.
fn wider(a: &'static str, b: &'static str) -> &'static str {
    let rank = |s| match s {
        "any" => 2,
        "specific" => 1,
        _ => 0,
    };
    if rank(b) > rank(a) { b } else { a }
}

fn process_name(pid: u32, owner: &Owner) -> String {
    match pid {
        0 => "Idle".into(),
        4 => "System".into(),
        _ => owner
            .image
            .as_deref()
            .and_then(|p| p.rsplit('\\').next())
            .map(String::from)
            .unwrap_or_else(|| "unknown".into()),
    }
}

/// Groups sockets into records (pure, so it is unit-tested). `describe` supplies
/// signature and permissions for each process image.
pub fn records(
    sockets: Vec<Socket>,
    owners: &HashMap<u32, Owner>,
    describe: impl Fn(&BTreeSet<String>) -> HashMap<String, binaries::BinaryInfo>,
) -> Vec<Record> {
    let mut objs: BTreeMap<String, PortObject> = BTreeMap::new();
    for s in sockets {
        let owner = owners.get(&s.pid).cloned().unwrap_or_default();
        let name = process_name(s.pid, &owner);
        let mut services = owner.services.clone();
        services.sort();
        let dynamic = s.port >= DYNAMIC_START;
        let identity = if dynamic {
            // Per hosting unit: the services if any (svchost hosts many), else the program.
            let who = if services.is_empty() {
                name.to_lowercase()
            } else {
                services.join("+").to_lowercase()
            };
            format!(r"{}\dynamic\{who}", s.protocol)
        } else {
            match s.address {
                IpAddr::V4(a) => format!(r"{}\{a}:{}", s.protocol, s.port),
                IpAddr::V6(a) => format!(r"{}\[{a}]:{}", s.protocol, s.port),
            }
        };
        let entry = objs.entry(identity).or_insert_with(|| PortObject {
            protocol: s.protocol,
            family: (!dynamic).then_some(if s.address.is_ipv4() { "ipv4" } else { "ipv6" }),
            address: (!dynamic).then(|| s.address.to_string()),
            port: (!dynamic).then_some(s.port),
            dynamic,
            scope: scope(&s.address),
            process: owner.image.clone(),
            process_name: name,
            services: services.clone(),
            ..Default::default()
        });
        entry.scope = wider(entry.scope, scope(&s.address));
        for svc in services {
            if !entry.services.contains(&svc) {
                entry.services.push(svc);
                entry.services.sort();
            }
        }
    }
    let images: BTreeSet<String> = objs.values().filter_map(|o| o.process.clone()).collect();
    let info = describe(&images);
    objs.into_iter()
        .map(|(id, mut o)| {
            if let Some(i) = o.process.as_ref().and_then(|p| info.get(&p.to_lowercase())) {
                o.process_signature = i.signature.clone();
                o.process_writable_by = i.writable_by.clone();
            }
            Record::new(Kind::Port, id, &o)
        })
        .collect()
}

pub struct PortsCollector {
    pub signatures: bool,
    pub threads: usize,
}

impl Collector for PortsCollector {
    fn name(&self) -> &'static str {
        "ports"
    }

    fn collect(&self, sink: &Sink) -> Result<()> {
        #[cfg(windows)]
        {
            let sockets = ffi::sockets()?;
            let mut owners: HashMap<u32, Owner> = HashMap::new();
            let services = ffi::services_by_pid(sink);
            for s in &sockets {
                owners.entry(s.pid).or_insert_with(|| Owner {
                    image: ffi::image(s.pid),
                    services: services.get(&s.pid).cloned().unwrap_or_default(),
                });
            }
            let (signatures, threads) = (self.signatures, self.threads);
            for r in records(sockets, &owners, |paths| {
                binaries::describe(paths.clone(), threads, signatures)
            }) {
                sink.emit(r);
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = sink;
            anyhow::bail!("the ports collector reads the Windows TCP/UDP tables")
        }
    }
}

#[cfg(windows)]
mod ffi {
    use super::Socket;
    use crate::collectors::Sink;
    use anyhow::{Result, bail};
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
        UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
        SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_WIN32,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };

    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    /// Port fields hold the port in network byte order in their low 16 bits.
    fn port(dw: u32) -> u16 {
        u16::from_be((dw & 0xFFFF) as u16)
    }

    /// Calls a Get*Table function with a growing buffer; returns the table bytes.
    fn table(call: impl Fn(*mut c_void, &mut u32) -> u32) -> Result<Vec<u8>> {
        let mut size = 0u32;
        let mut buf: Vec<u8> = Vec::new();
        for _ in 0..5 {
            buf.resize(size as usize + 1024, 0);
            size = buf.len() as u32;
            match call(buf.as_mut_ptr() as *mut c_void, &mut size) {
                0 => return Ok(buf),
                ERROR_INSUFFICIENT_BUFFER => continue,
                rc => bail!("reading the socket table failed: {rc}"),
            }
        }
        bail!("socket table kept growing")
    }

    /// Rows after the leading u32 count (4-byte aligned for all row types used here).
    fn rows<T: Copy>(buf: &[u8]) -> Vec<T> {
        let n = u32::from_ne_bytes(buf[..4].try_into().unwrap()) as usize;
        let base = unsafe { buf.as_ptr().add(4) } as *const T;
        (0..n)
            .map(|i| unsafe { std::ptr::read_unaligned(base.add(i)) })
            .collect()
    }

    pub fn sockets() -> Result<Vec<Socket>> {
        let mut out = Vec::new();
        let tcp4 = table(|p, s| unsafe {
            GetExtendedTcpTable(p, s, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_LISTENER, 0)
        })?;
        for r in rows::<MIB_TCPROW_OWNER_PID>(&tcp4) {
            out.push(Socket {
                protocol: "tcp",
                address: IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())),
                port: port(r.dwLocalPort),
                pid: r.dwOwningPid,
            });
        }
        let tcp6 = table(|p, s| unsafe {
            GetExtendedTcpTable(p, s, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_LISTENER, 0)
        })?;
        for r in rows::<MIB_TCP6ROW_OWNER_PID>(&tcp6) {
            out.push(Socket {
                protocol: "tcp",
                address: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                port: port(r.dwLocalPort),
                pid: r.dwOwningPid,
            });
        }
        let udp4 = table(|p, s| unsafe {
            GetExtendedUdpTable(p, s, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0)
        })?;
        for r in rows::<MIB_UDPROW_OWNER_PID>(&udp4) {
            out.push(Socket {
                protocol: "udp",
                address: IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())),
                port: port(r.dwLocalPort),
                pid: r.dwOwningPid,
            });
        }
        let udp6 = table(|p, s| unsafe {
            GetExtendedUdpTable(p, s, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0)
        })?;
        for r in rows::<MIB_UDP6ROW_OWNER_PID>(&udp6) {
            out.push(Socket {
                protocol: "udp",
                address: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                port: port(r.dwLocalPort),
                pid: r.dwOwningPid,
            });
        }
        Ok(out)
    }

    pub fn image(pid: u32) -> Option<String> {
        if pid == 0 || pid == 4 {
            return None;
        }
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let ok =
                QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) != 0;
            CloseHandle(h);
            ok.then(|| String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    unsafe fn wstr(p: *const u16) -> String {
        let mut n = 0;
        unsafe {
            while *p.add(n) != 0 {
                n += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
        }
    }

    /// Running Win32 services by hosting process ID.
    pub fn services_by_pid(sink: &Sink) -> HashMap<u32, Vec<String>> {
        let mut out: HashMap<u32, Vec<String>> = HashMap::new();
        unsafe {
            let scm = OpenSCManagerW(
                std::ptr::null(),
                std::ptr::null(),
                SC_MANAGER_ENUMERATE_SERVICE,
            );
            if scm.is_null() {
                sink.warn(|| "cannot open the service manager; ports lack service names".into());
                return out;
            }
            let (mut needed, mut count, mut resume) = (0u32, 0u32, 0u32);
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                null_mut(),
                0,
                &mut needed,
                &mut count,
                &mut resume,
                std::ptr::null(),
            );
            let mut buf = vec![0u8; needed as usize + 4096];
            resume = 0;
            if EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut needed,
                &mut count,
                &mut resume,
                std::ptr::null(),
            ) != 0
            {
                let rows = std::slice::from_raw_parts(
                    buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                    count as usize,
                );
                for r in rows {
                    out.entry(r.ServiceStatusProcess.dwProcessId)
                        .or_default()
                        .push(wstr(r.lpServiceName));
                }
            }
            CloseServiceHandle(scm);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sock(p: &'static str, a: &str, port: u16, pid: u32) -> Socket {
        Socket {
            protocol: p,
            address: a.parse().unwrap(),
            port,
            pid,
        }
    }

    #[test]
    fn groups_dynamic_ports_and_keys_static_ones() {
        let owners = HashMap::from([
            (
                900,
                Owner {
                    image: Some(r"C:\Windows\System32\svchost.exe".into()),
                    services: vec!["RpcSs".into()],
                },
            ),
            (
                700,
                Owner {
                    image: Some(r"C:\Windows\System32\lsass.exe".into()),
                    services: vec![],
                },
            ),
            (
                800,
                Owner {
                    image: Some(r"C:\Tools\app.exe".into()),
                    services: vec![],
                },
            ),
        ]);
        let socks = vec![
            sock("tcp", "0.0.0.0", 135, 900),
            sock("tcp", "::", 135, 900),
            sock("tcp", "127.0.0.1", 49670, 700),
            sock("tcp", "0.0.0.0", 49664, 700),
            sock("udp", "0.0.0.0", 58000, 900),
            sock("tcp", "0.0.0.0", 445, 4),
            sock("tcp", "127.0.0.1", 8080, 800),
        ];
        let r: HashMap<String, serde_json::Value> = records(socks, &owners, |_| HashMap::new())
            .into_iter()
            .map(|r| (r.identity, r.data))
            .collect();
        assert_eq!(r.len(), 6, "{:?}", r.keys().collect::<Vec<_>>());
        assert_eq!(
            r[r"tcp\0.0.0.0:135"]["services"],
            serde_json::json!(["RpcSs"])
        );
        assert_eq!(r[r"tcp\[::]:135"]["family"], "ipv6");
        // lsass's two dynamic listeners merge into one record with the widest scope.
        let l = &r[r"tcp\dynamic\lsass.exe"];
        assert_eq!(l["scope"], "any");
        assert_eq!(l["dynamic"], true);
        assert!(l.get("port").is_none());
        assert!(r.contains_key(r"udp\dynamic\rpcss"));
        assert_eq!(r[r"tcp\0.0.0.0:445"]["process_name"], "System");
        assert_eq!(r[r"tcp\127.0.0.1:8080"]["scope"], "loopback");
    }

    #[test]
    fn fields_in_sync() {
        let o = PortObject {
            protocol: "tcp",
            family: Some("ipv4"),
            address: Some("x".into()),
            port: Some(1),
            dynamic: false,
            scope: "any",
            process: Some("p".into()),
            process_name: "n".into(),
            services: vec!["s".into()],
            process_signature: Some(win::Signature {
                status: "valid".into(),
                source: None,
                signer: None,
            }),
            process_writable_by: vec!["Users".into()],
        };
        crate::collectors::assert_fields(&o, FIELDS);
    }
}
