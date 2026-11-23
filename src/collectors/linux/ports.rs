//! Listening TCP and bound (unconnected) UDP sockets from `/proc/net/*`, attributed
//! to a program through `/proc/<pid>/fd` socket inodes and to a systemd service
//! through `/proc/<pid>/cgroup`. Grouping and record shape are shared with the
//! Windows collector (`collectors::ports::records`): ephemeral-range sockets are
//! grouped per program, and pids are never stored.
//!
//! Without root, other users' `/proc/<pid>/fd` is unreadable: those sockets are
//! still reported, with an unknown program.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::collectors::ports::{Convention, Owner, Socket, records};
use crate::collectors::unix::under;
use crate::collectors::{Collector, Sink, binaries};
use anyhow::Result;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

const TCP_LISTEN: &str = "0A";
const TCP_CLOSE: &str = "07";

/// A row of /proc/net/{tcp,udp}{,6}: address, port, socket inode.
#[derive(Debug, PartialEq)]
pub struct NetEntry {
    pub address: IpAddr,
    pub port: u16,
    pub inode: u64,
}

/// `0100007F:0016` -> 127.0.0.1, 22. Addresses are printed as host-order 32-bit
/// words over network-order bytes, hence `to_ne_bytes`.
fn parse_endpoint(s: &str) -> Option<(IpAddr, u16)> {
    let (addr, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |i: usize| -> Option<[u8; 4]> {
        Some(
            u32::from_str_radix(addr.get(i * 8..i * 8 + 8)?, 16)
                .ok()?
                .to_ne_bytes(),
        )
    };
    let ip = match addr.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word(i)?);
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    Some((ip, port))
}

/// Listening (TCP) or unconnected (UDP) sockets in one /proc/net table.
pub fn parse_net(text: &str, protocol: &str) -> Vec<NetEntry> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let wanted = match protocol {
                "tcp" => f[3] == TCP_LISTEN,
                // An unconnected UDP socket accepts datagrams from anyone.
                _ => f[3] == TCP_CLOSE && f[2].ends_with(":0000"),
            };
            if !wanted {
                return None;
            }
            let (address, port) = parse_endpoint(f[1])?;
            Some(NetEntry {
                address,
                port,
                inode: f[9].parse().ok()?,
            })
        })
        .collect()
}

/// The ephemeral range from `ip_local_port_range` (Linux default 32768-60999).
pub fn dynamic_range(text: &str) -> std::ops::RangeInclusive<u16> {
    let mut it = text.split_whitespace().filter_map(|n| n.parse().ok());
    match (it.next(), it.next()) {
        (Some(a), Some(b)) if a <= b => a..=b,
        _ => 32768..=60999,
    }
}

/// System services a process belongs to, from its cgroup path. Processes in a
/// user session (`user.slice`, including `user@1000.service`) are not services.
pub fn cgroup_services(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .lines()
        .filter_map(|l| l.rsplit(':').next())
        .filter_map(|path| path.split_once("/system.slice/").map(|(_, rest)| rest))
        .filter_map(|rest| {
            rest.split('/')
                .rfind(|seg| seg.ends_with(".service"))
                .map(String::from)
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn pids(root: &Path) -> Vec<u32> {
    let mut v: Vec<u32> = std::fs::read_dir(under(root, "/proc"))
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// socket inode -> lowest pid holding it, and how many processes' fds were unreadable.
fn socket_pids(root: &Path) -> (HashMap<u64, u32>, usize) {
    let mut map = HashMap::new();
    let mut denied = 0;
    for pid in pids(root) {
        let Ok(rd) = std::fs::read_dir(under(root, &format!("/proc/{pid}/fd"))) else {
            denied += 1;
            continue;
        };
        for e in rd.flatten() {
            let Ok(target) = std::fs::read_link(e.path()) else {
                continue;
            };
            let t = target.to_string_lossy();
            if let Some(inode) = t
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse().ok())
            {
                // pids are visited in increasing order, so the first is the lowest.
                map.entry(inode).or_insert(pid);
            }
        }
    }
    (map, denied)
}

fn owner(root: &Path, pid: u32) -> Owner {
    let image = std::fs::read_link(under(root, &format!("/proc/{pid}/exe")))
        .ok()
        .map(|p| {
            let s = p.to_string_lossy();
            // A binary replaced on disk (an upgrade) shows as "(deleted)"; the
            // program is still the same.
            s.strip_suffix(" (deleted)").unwrap_or(&s).to_string()
        });
    let services = std::fs::read_to_string(under(root, &format!("/proc/{pid}/cgroup")))
        .map(|t| cgroup_services(&t))
        .unwrap_or_default();
    Owner { image, services }
}

pub struct PortsCollector {
    pub root: PathBuf,
    pub threads: usize,
}

impl Collector for PortsCollector {
    fn name(&self) -> &'static str {
        "ports"
    }

    fn collect(&self, sink: &Sink) -> Result<()> {
        let root = &self.root;
        let mut entries = Vec::new();
        let mut tables = 0;
        for (file, protocol) in [
            ("tcp", "tcp"),
            ("tcp6", "tcp"),
            ("udp", "udp"),
            ("udp6", "udp"),
        ] {
            match std::fs::read_to_string(under(root, &format!("/proc/net/{file}"))) {
                Ok(t) => {
                    tables += 1;
                    entries.extend(parse_net(&t, protocol).into_iter().map(|e| (protocol, e)));
                }
                // tcp6/udp6 are absent when IPv6 is disabled.
                Err(e) => sink.warn(|| format!("/proc/net/{file}: {e}")),
            }
        }
        if tables == 0 {
            anyhow::bail!("no /proc/net socket tables found");
        }
        let (by_inode, denied) = socket_pids(root);
        if denied > 0 {
            sink.warn(|| {
                format!("{denied} processes' open files were unreadable (run as root to attribute every socket)")
            });
        }
        let mut owners: HashMap<u32, Owner> = HashMap::new();
        let sockets: Vec<Socket> = entries
            .into_iter()
            .map(|(protocol, e)| {
                // pid 0: owner unknown.
                let pid = by_inode.get(&e.inode).copied().unwrap_or(0);
                if pid != 0 {
                    owners.entry(pid).or_insert_with(|| owner(root, pid));
                }
                Socket {
                    protocol,
                    address: e.address,
                    port: e.port,
                    pid,
                }
            })
            .collect();
        let conv = Convention {
            dynamic: dynamic_range(
                &std::fs::read_to_string(under(root, "/proc/sys/net/ipv4/ip_local_port_range"))
                    .unwrap_or_default(),
            ),
            windows_pids: false,
        };
        let threads = self.threads;
        for r in records(sockets, &owners, &conv, |paths| {
            // Describe the binaries where they are under root, keyed by their real path.
            let mapped: HashMap<String, String> = paths
                .iter()
                .map(|p| (under(root, p).to_string_lossy().into_owned(), p.clone()))
                .collect();
            let info = binaries::describe(
                mapped.keys().cloned().collect::<BTreeSet<_>>(),
                threads,
                false,
            );
            info.into_iter()
                .filter_map(|(k, v)| Some((binaries::key(mapped.get(&k)?), v)))
                .collect()
        }) {
            sink.emit(r);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0 100 0 0 10 0\n\
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0 100 0 0 10 0\n\
   2: 0100007F:0016 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 333 1 0 100 0 0 10 0\n\
   3: 00000000:8CA1 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 444 1 0 100 0 0 10 0\n";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 555 1 0 100 0 0 10 0\n\
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 666 1 0 100 0 0 10 0\n";
    const UDP: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
  1: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   104        0 777 2 0 0\n\
  2: 0A00020F:A2B3 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 888 2 0 0\n";

    #[test]
    fn parses_proc_net_tables() {
        let t = parse_net(TCP, "tcp");
        assert_eq!(
            t,
            [
                NetEntry {
                    address: "127.0.0.1".parse().unwrap(),
                    port: 631,
                    inode: 111
                },
                NetEntry {
                    address: "0.0.0.0".parse().unwrap(),
                    port: 22,
                    inode: 222
                },
                NetEntry {
                    address: "0.0.0.0".parse().unwrap(),
                    port: 36001,
                    inode: 444
                },
            ]
        );
        let t6 = parse_net(TCP6, "tcp");
        assert_eq!(t6[0].address, "::".parse::<IpAddr>().unwrap());
        assert_eq!(t6[1].address, "::1".parse::<IpAddr>().unwrap());
        let u = parse_net(UDP, "udp");
        assert_eq!(u.len(), 1, "connected UDP sockets are left out");
        assert_eq!(u[0].port, 5353);
        assert_eq!(dynamic_range("32768\t60999\n"), 32768..=60999);
        assert_eq!(dynamic_range("garbage"), 32768..=60999);
        assert_eq!(
            cgroup_services("0::/system.slice/ssh.service\n"),
            ["ssh.service"]
        );
        assert!(cgroup_services("0::/user.slice/user-1000.slice/session-2.scope").is_empty());
        assert!(
            cgroup_services("0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope")
                .is_empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn attributes_sockets_to_programs_and_services() {
        use serde_json::{Value, json};
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let w = |p: &str, t: &str| {
            let p = under(root, p);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, t).unwrap();
        };
        w("/proc/net/tcp", TCP);
        w("/proc/net/tcp6", TCP6);
        w("/proc/net/udp", UDP);
        w("/proc/sys/net/ipv4/ip_local_port_range", "32768 60999\n");
        let proc_ = |pid: u32, exe: &str, cgroup: &str, inodes: &[u64]| {
            let base = under(root, &format!("/proc/{pid}"));
            std::fs::create_dir_all(base.join("fd")).unwrap();
            symlink(exe, base.join("exe")).unwrap();
            std::fs::write(base.join("cgroup"), cgroup).unwrap();
            for (i, n) in inodes.iter().enumerate() {
                symlink(format!("socket:[{n}]"), base.join("fd").join(i.to_string())).unwrap();
            }
            symlink("/dev/null", base.join("fd").join("99")).unwrap();
        };
        proc_(
            812,
            "/usr/sbin/sshd",
            "0::/system.slice/ssh.service\n",
            &[222, 555],
        );
        proc_(
            900,
            "/usr/sbin/cupsd (deleted)",
            "0::/system.slice/cups.service\n",
            &[111, 666],
        );
        proc_(
            4000,
            "/home/alice/bin/dev-server",
            "0::/user.slice/user-1000.slice/session-2.scope\n",
            &[444],
        );
        // Not a process directory.
        std::fs::create_dir_all(under(root, "/proc/sys/kernel")).unwrap();

        let (tx, rx) = crossbeam_channel::unbounded();
        let sink = Sink::new(tx, false);
        PortsCollector {
            root: root.into(),
            threads: 2,
        }
        .collect(&sink)
        .unwrap();
        drop(sink);
        let r: HashMap<String, Value> = rx.iter().map(|r| (r.identity, r.data)).collect();
        assert_eq!(r.len(), 6, "{:?}", r.keys().collect::<Vec<_>>());
        let ssh = &r[r"tcp\0.0.0.0:22"];
        assert_eq!(ssh["process"], "/usr/sbin/sshd");
        assert_eq!(ssh["process_name"], "sshd");
        assert_eq!(ssh["services"], json!(["ssh.service"]));
        assert_eq!(ssh["scope"], "any");
        assert_eq!(r[r"tcp\[::]:22"]["family"], "ipv6");
        assert_eq!(r[r"tcp\127.0.0.1:631"]["process"], "/usr/sbin/cupsd");
        assert_eq!(r[r"tcp\[::1]:631"]["scope"], "loopback");
        let dev = &r[r"tcp\dynamic\dev-server"];
        assert_eq!(dev["dynamic"], true);
        assert!(dev.get("port").is_none());
        // Nobody in the fixture holds the mDNS socket: reported, owner unknown.
        assert_eq!(r[r"udp\0.0.0.0:5353"]["process_name"], "unknown");
    }
}
