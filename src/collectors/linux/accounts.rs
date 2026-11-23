//! Local users and groups from `/etc/passwd`, `/etc/group` and `/etc/shadow`.
//! Password hashes are never stored: only whether a password is set, empty or
//! locked, and which hash algorithm it uses. Volatile shadow fields (last change,
//! aging counters) are left out.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::collectors::unix::{self, GroupEntry, PasswdEntry};
use crate::collectors::{Collector, Sink};
use crate::model::{Kind, Record};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

/// Groups whose members hold root or close to it, with what they grant.
pub const PRIVILEGED_GROUPS: &[(&str, &str)] = &[
    ("root", "root group"),
    ("sudo", "sudo"),
    ("wheel", "sudo (wheel)"),
    ("admin", "sudo (admin)"),
    ("docker", "docker daemon (root-equivalent)"),
    ("lxd", "lxd daemon (root-equivalent)"),
    ("disk", "raw disk access"),
    ("shadow", "reads password hashes"),
    ("libvirt", "virtual machine management"),
];

/// Groups that grant sudo on stock distribution sudoers files.
const SUDO_GROUPS: &[&str] = &["sudo", "wheel", "admin"];

fn privilege(group: &str) -> Option<&'static str> {
    PRIVILEGED_GROUPS
        .iter()
        .find(|(g, _)| *g == group)
        .map(|(_, p)| *p)
}

pub const USER_FIELDS: &[&str] = &[
    "name",
    "uid",
    "gid",
    "primary_group",
    "comment",
    "home",
    "shell",
    "login_shell",
    "password",
    "password_hash",
    "hash_in_passwd",
    "system",
    "groups",
    "administrator",
    "privileged_groups",
    "duplicate_uid",
];

pub const GROUP_FIELDS: &[&str] = &["name", "gid", "members", "privileged", "privilege"];

#[derive(Serialize)]
struct UserObject {
    name: String,
    uid: u32,
    gid: u32,
    primary_group: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    comment: String,
    home: String,
    shell: String,
    /// The shell lets the account log in (not nologin/false).
    login_shell: bool,
    /// set, empty (logs in without a password), locked, or unknown (shadow unreadable).
    password: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_hash: Option<&'static str>,
    /// The hash is in world-readable /etc/passwd instead of /etc/shadow.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    hash_in_passwd: bool,
    /// uid below UID_MIN (a system account).
    system: bool,
    /// All groups, primary included, sorted.
    groups: Vec<String>,
    /// uid 0, or a member of a group stock sudoers grants sudo to.
    administrator: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    privileged_groups: Vec<String>,
    /// Another account has the same uid (they are the same user to the kernel).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    duplicate_uid: bool,
}

#[derive(Serialize)]
struct GroupObject {
    name: String,
    gid: u32,
    /// Supplementary members plus users whose primary group this is.
    members: Vec<String>,
    privileged: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    privilege: Option<&'static str>,
}

/// set / empty / locked, and the hash algorithm, of a passwd or shadow field.
fn password_state(field: &str) -> (&'static str, Option<&'static str>) {
    if field.is_empty() {
        return ("empty", None);
    }
    let (locked, hash) = match field.strip_prefix('!') {
        Some(rest) => (true, rest.trim_start_matches('!')),
        None => (field.starts_with('*'), field),
    };
    let algorithm = if hash.is_empty() || hash.starts_with('*') {
        None
    } else if let Some(rest) = hash.strip_prefix('$') {
        Some(match rest.split('$').next().unwrap_or("") {
            "1" => "md5",
            "2a" | "2b" | "2x" | "2y" => "bcrypt",
            "5" => "sha256",
            "6" => "sha512",
            "y" => "yescrypt",
            "gy" => "gost-yescrypt",
            "7" => "scrypt",
            _ => "other",
        })
    } else if hash.starts_with('_') {
        Some("bsdi-des")
    } else if hash.len() == 13 {
        Some("des")
    } else {
        Some("other")
    };
    (if locked { "locked" } else { "set" }, algorithm)
}

fn login_shell(shell: &str) -> bool {
    // An empty shell field means /bin/sh.
    !["nologin", "false", "sync", "shutdown", "halt"]
        .iter()
        .any(|s| shell.rsplit('/').next() == Some(s))
}

/// UID_MIN from login.defs (default 1000).
pub fn uid_min(login_defs: &str) -> u32 {
    login_defs
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            (it.next()? == "UID_MIN").then(|| it.next()?.parse().ok())?
        })
        .next_back()
        .unwrap_or(1000)
}

/// Turns parsed account files into records (pure, so it is unit-tested).
/// `shadow` is `None` when /etc/shadow could not be read.
pub fn records(
    users: &[PasswdEntry],
    groups: &[GroupEntry],
    shadow: Option<&HashMap<String, String>>,
    uid_min: u32,
) -> Vec<Record> {
    let ids = unix::Ids::from_entries(users, groups);
    let mut uid_count: HashMap<u32, usize> = HashMap::new();
    for u in users {
        *uid_count.entry(u.uid).or_default() += 1;
    }
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for u in users {
        // Duplicate names: the first entry is the one logins use.
        if !seen.insert(u.name.as_str()) {
            continue;
        }
        let primary_group = ids.group(u.gid);
        let mut all: BTreeSet<String> = groups
            .iter()
            .filter(|g| g.members.contains(&u.name))
            .map(|g| g.name.clone())
            .collect();
        all.insert(primary_group.clone());
        let (password, password_hash, hash_in_passwd) = match u.password.as_str() {
            "x" => match shadow.map(|s| s.get(&u.name)) {
                Some(Some(f)) => {
                    let (s, h) = password_state(f);
                    (s, h, false)
                }
                // No shadow entry: the account cannot authenticate with a password.
                Some(None) => ("locked", None, false),
                None => ("unknown", None, false),
            },
            f => {
                let (s, h) = password_state(f);
                (s, h, h.is_some())
            }
        };
        let privileged_groups: Vec<String> = all
            .iter()
            .filter(|g| privilege(g).is_some())
            .cloned()
            .collect();
        let obj = UserObject {
            name: u.name.clone(),
            uid: u.uid,
            gid: u.gid,
            primary_group,
            comment: u.gecos.clone(),
            home: u.home.clone(),
            shell: u.shell.clone(),
            login_shell: login_shell(&u.shell),
            password,
            password_hash,
            hash_in_passwd,
            system: u.uid < uid_min,
            administrator: u.uid == 0 || all.iter().any(|g| SUDO_GROUPS.contains(&g.as_str())),
            groups: all.into_iter().collect(),
            privileged_groups,
            duplicate_uid: uid_count[&u.uid] > 1,
        };
        out.push(Record::new(Kind::User, format!(r"user\{}", u.name), &obj));
    }
    let mut seen = BTreeSet::new();
    for g in groups {
        if !seen.insert(g.name.as_str()) {
            continue;
        }
        let members: BTreeSet<String> = g
            .members
            .iter()
            .cloned()
            .chain(
                users
                    .iter()
                    .filter(|u| u.gid == g.gid)
                    .map(|u| u.name.clone()),
            )
            .collect();
        let privilege = privilege(&g.name);
        let obj = GroupObject {
            name: g.name.clone(),
            gid: g.gid,
            members: members.into_iter().collect(),
            privileged: privilege.is_some(),
            privilege,
        };
        out.push(Record::new(Kind::Group, format!(r"group\{}", g.name), &obj));
    }
    out
}

pub struct AccountsCollector {
    pub root: PathBuf,
}

impl Collector for AccountsCollector {
    fn name(&self) -> &'static str {
        "users"
    }

    fn collect(&self, sink: &Sink) -> Result<()> {
        let read = |p: &str| std::fs::read_to_string(self.root.join(p));
        let passwd = read("etc/passwd").context("reading /etc/passwd")?;
        let group = read("etc/group").unwrap_or_else(|e| {
            sink.warn(|| format!("reading /etc/group: {e}"));
            String::new()
        });
        let shadow = match read("etc/shadow") {
            Ok(t) => Some(unix::parse_shadow(&t)),
            Err(e) => {
                sink.warn(|| {
                    format!("reading /etc/shadow: {e} (password state is reported as unknown)")
                });
                None
            }
        };
        let min = uid_min(&read("etc/login.defs").unwrap_or_default());
        for r in records(
            &unix::parse_passwd(&passwd),
            &unix::parse_group(&group),
            shadow.as_ref(),
            min,
        ) {
            sink.emit(r);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(
            etc.join("passwd"),
            "root:x:0:0:root:/root:/bin/bash\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
             toor:x:0:0::/root:/bin/sh\n\
             alice:x:1000:1000:Alice:/home/alice:/bin/bash\n\
             guest:x:1001:1001::/home/guest:/bin/bash\n\
             legacy:abcdefghijklm:1002:1002::/home/legacy:/bin/sh\n\
             svc:x:500:500::/:/usr/sbin/nologin\n",
        )
        .unwrap();
        std::fs::write(
            etc.join("group"),
            "root:x:0:\ndaemon:x:1:\nsudo:x:27:alice\ndocker:x:998:guest\n\
             alice:x:1000:\nguest:x:1001:\nlegacy:x:1002:\nsvc:x:500:\n",
        )
        .unwrap();
        std::fs::write(
            etc.join("shadow"),
            "root:!:19000:0:99999:7:::\ndaemon:*:19000::::::\ntoor:$6$s$h:19000::::::\n\
             alice:$y$j9T$s$h:19000::::::\nguest::19000::::::\n",
        )
        .unwrap();
        std::fs::write(etc.join("login.defs"), "# c\nUID_MIN\t\t\t 600\n").unwrap();
        dir
    }

    fn collect(root: &std::path::Path) -> HashMap<String, Value> {
        let (tx, rx) = crossbeam_channel::unbounded();
        let sink = Sink::new(tx, false);
        AccountsCollector { root: root.into() }
            .collect(&sink)
            .unwrap();
        drop(sink);
        rx.iter().map(|r| (r.identity, r.data)).collect()
    }

    #[test]
    fn reports_accounts_and_risky_states() {
        let dir = fixture();
        let r = collect(dir.path());
        let root = &r[r"user\root"];
        assert_eq!(root["password"], "locked");
        assert_eq!(root["administrator"], true);
        assert_eq!(root["duplicate_uid"], true);
        let toor = &r[r"user\toor"];
        assert_eq!(toor["uid"], 0);
        assert_eq!(toor["password_hash"], "sha512");
        let alice = &r[r"user\alice"];
        assert_eq!(alice["password"], "set");
        assert_eq!(alice["password_hash"], "yescrypt");
        assert_eq!(alice["groups"], serde_json::json!(["alice", "sudo"]));
        assert_eq!(alice["administrator"], true);
        assert_eq!(alice["system"], false);
        assert!(alice.get("duplicate_uid").is_none());
        let guest = &r[r"user\guest"];
        assert_eq!(guest["password"], "empty");
        assert_eq!(guest["privileged_groups"], serde_json::json!(["docker"]));
        assert_eq!(guest["administrator"], false);
        let legacy = &r[r"user\legacy"];
        assert_eq!(legacy["hash_in_passwd"], true);
        assert_eq!(legacy["password_hash"], "des");
        // No shadow line: no password login.
        assert_eq!(r[r"user\svc"]["password"], "locked");
        assert_eq!(r[r"user\svc"]["system"], true);
        assert_eq!(r[r"user\svc"]["login_shell"], false);
        assert_eq!(r[r"user\daemon"]["password"], "locked");
        assert!(r[r"user\daemon"].get("password_hash").is_none());

        let root_group = &r[r"group\root"];
        assert_eq!(root_group["members"], serde_json::json!(["root", "toor"]));
        assert_eq!(r[r"group\docker"]["privileged"], true);
        assert_eq!(r[r"group\alice"]["privileged"], false);
    }

    #[test]
    fn unreadable_shadow_is_unknown_not_an_error() {
        let dir = fixture();
        std::fs::remove_file(dir.path().join("etc/shadow")).unwrap();
        let r = collect(dir.path());
        assert_eq!(r[r"user\alice"]["password"], "unknown");
        // A hash in passwd is still visible.
        assert_eq!(r[r"user\legacy"]["password"], "set");
    }

    #[test]
    fn password_states() {
        assert_eq!(password_state(""), ("empty", None));
        assert_eq!(password_state("*"), ("locked", None));
        assert_eq!(password_state("!!"), ("locked", None));
        assert_eq!(password_state("!$6$a$b"), ("locked", Some("sha512")));
        assert_eq!(password_state("$1$a$b"), ("set", Some("md5")));
        assert_eq!(password_state("$2b$10$x"), ("set", Some("bcrypt")));
        assert_eq!(uid_min(""), 1000);
    }

    #[test]
    fn fields_in_sync() {
        let u = UserObject {
            name: "a".into(),
            uid: 1,
            gid: 1,
            primary_group: "a".into(),
            comment: "c".into(),
            home: "/".into(),
            shell: "/bin/sh".into(),
            login_shell: true,
            password: "set",
            password_hash: Some("sha512"),
            hash_in_passwd: true,
            system: false,
            groups: vec!["a".into()],
            administrator: false,
            privileged_groups: vec!["docker".into()],
            duplicate_uid: true,
        };
        crate::collectors::assert_fields(&u, USER_FIELDS);
        let g = GroupObject {
            name: "a".into(),
            gid: 1,
            members: vec![],
            privileged: true,
            privilege: Some("x"),
        };
        crate::collectors::assert_fields(&g, GROUP_FIELDS);
    }
}
