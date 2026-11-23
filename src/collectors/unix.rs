//! Unix account databases and file permissions, shared by the Linux collectors and
//! the file collector: parsing `/etc/passwd` and `/etc/group`, naming uids and gids,
//! and deciding which non-root principals can write a file from its mode bits.
//!
//! POSIX ACLs (the `system.posix_acl_access` xattr) are not read: `writable_by` is
//! what the mode bits grant, which is what nearly every system relies on.

// Compiled everywhere so the parsing is unit-tested; only used at runtime on Unix.
#![cfg_attr(not(unix), allow(dead_code))]

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

/// One line of `/etc/passwd`.
#[derive(Debug, Clone, PartialEq)]
pub struct PasswdEntry {
    pub name: String,
    /// `x` when the hash lives in `/etc/shadow`.
    pub password: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

/// One line of `/etc/group`.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    /// Supplementary members only; users whose primary group this is are not listed.
    pub members: Vec<String>,
}

fn records(text: &str) -> impl Iterator<Item = Vec<&str>> {
    text.lines()
        .map(str::trim_end)
        // NIS compat entries (`+`, `-user`) are not local accounts.
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(['+', '-']))
        .map(|l| l.split(':').collect())
}

pub fn parse_passwd(text: &str) -> Vec<PasswdEntry> {
    records(text)
        .filter_map(|f| {
            if f.len() < 7 {
                return None;
            }
            Some(PasswdEntry {
                name: f[0].to_string(),
                password: f[1].to_string(),
                uid: f[2].parse().ok()?,
                gid: f[3].parse().ok()?,
                gecos: f[4].to_string(),
                home: f[5].to_string(),
                shell: f[6].to_string(),
            })
        })
        .collect()
}

pub fn parse_group(text: &str) -> Vec<GroupEntry> {
    records(text)
        .filter_map(|f| {
            if f.len() < 4 {
                return None;
            }
            Some(GroupEntry {
                name: f[0].to_string(),
                gid: f[2].parse().ok()?,
                members: f[3]
                    .split(',')
                    .map(str::trim)
                    .filter(|m| !m.is_empty())
                    .map(String::from)
                    .collect(),
            })
        })
        .collect()
}

/// `name -> password field` from `/etc/shadow`.
pub fn parse_shadow(text: &str) -> HashMap<String, String> {
    records(text)
        .filter(|f| f.len() >= 2)
        .map(|f| (f[0].to_string(), f[1].to_string()))
        .collect()
}

/// uid and gid names. Unknown ids are shown as numbers, the way `ls -l` does.
#[derive(Default)]
pub struct Ids {
    users: HashMap<u32, String>,
    groups: HashMap<u32, String>,
}

impl Ids {
    /// Reads `<root>/etc/passwd` and `<root>/etc/group`; missing files leave ids unnamed.
    pub fn load(root: &Path) -> Ids {
        let read = |p: &str| std::fs::read_to_string(root.join(p)).unwrap_or_default();
        Ids::from_entries(
            &parse_passwd(&read("etc/passwd")),
            &parse_group(&read("etc/group")),
        )
    }

    pub fn from_entries(users: &[PasswdEntry], groups: &[GroupEntry]) -> Ids {
        let mut ids = Ids::default();
        // The first entry for an id wins, as with getpwuid.
        for u in users {
            ids.users.entry(u.uid).or_insert_with(|| u.name.clone());
        }
        for g in groups {
            ids.groups.entry(g.gid).or_insert_with(|| g.name.clone());
        }
        ids
    }

    pub fn user(&self, uid: u32) -> String {
        self.users
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| uid.to_string())
    }

    pub fn group(&self, gid: u32) -> String {
        self.groups
            .get(&gid)
            .cloned()
            .unwrap_or_else(|| gid.to_string())
    }
}

/// The running system's ids, loaded once.
pub fn system_ids() -> &'static Ids {
    static IDS: OnceLock<Ids> = OnceLock::new();
    IDS.get_or_init(|| Ids::load(Path::new("/")))
}

/// Non-root principals the mode bits let write the file: the owning user, the
/// owning group as `%group` (the sudoers spelling), and `everyone` for the other
/// bits. root can write anything anyway, so it is never listed.
pub fn writable_by(mode: u32, uid: u32, gid: u32, ids: &Ids) -> Vec<String> {
    let mut out = Vec::new();
    if mode & 0o200 != 0 && uid != 0 {
        out.push(ids.user(uid));
    }
    if mode & 0o020 != 0 && gid != 0 {
        out.push(format!("%{}", ids.group(gid)));
    }
    if mode & 0o002 != 0 {
        out.push("everyone".to_string());
    }
    out
}

/// `writable_by` for a path, following symlinks.
#[cfg(unix)]
pub fn path_writable_by(path: &Path, ids: &Ids) -> std::io::Result<Vec<String>> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path)?;
    Ok(writable_by(md.mode(), md.uid(), md.gid(), ids))
}

#[cfg(not(unix))]
pub fn path_writable_by(_: &Path, _: &Ids) -> std::io::Result<Vec<String>> {
    Ok(Vec::new())
}

/// Maps an absolute path on the inspected system to where it is under `root`
/// (`/` for the live system, a fixture or mounted image otherwise).
pub fn under(root: &Path, path: &str) -> std::path::PathBuf {
    root.join(path.trim_start_matches('/'))
}

/// Resolves symlinks under `root`, so absolute link targets stay inside a fixture
/// or mounted image instead of escaping to the host. Returns the final path on the
/// inspected system (not prefixed by `root`), or `None` past 16 hops.
pub fn resolve_in(root: &Path, path: &str) -> Option<String> {
    let mut cur = path.to_string();
    for _ in 0..16 {
        match std::fs::read_link(under(root, &cur)) {
            Ok(target) => {
                let t = target.to_string_lossy();
                cur = if t.starts_with('/') {
                    t.into_owned()
                } else {
                    let parent = Path::new(&cur).parent().unwrap_or(Path::new("/"));
                    normalize(&parent.join(&*t).to_string_lossy())
                };
            }
            Err(_) => return Some(cur),
        }
    }
    None
}

/// Collapses `.` and `..` lexically.
fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
        # comment\n\
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
        +nisuser::::::\n\
        broken:x:notanumber:1::/:/bin/sh\n\
        alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash\n";
    const GROUP: &str = "root:x:0:\nsudo:x:27:alice,bob\nalice:x:1000:\n";

    #[test]
    fn parses_account_files() {
        let users = parse_passwd(PASSWD);
        assert_eq!(
            users.iter().map(|u| u.name.as_str()).collect::<Vec<_>>(),
            ["root", "daemon", "alice"]
        );
        assert_eq!(users[2].gecos, "Alice,,,");
        let groups = parse_group(GROUP);
        assert_eq!(groups[1].members, ["alice", "bob"]);
        assert!(groups[0].members.is_empty());
        let shadow = parse_shadow("root:$6$x:19000:0:99999:7:::\nnobody::1:::::\n");
        assert_eq!(shadow["root"], "$6$x");
        assert_eq!(shadow["nobody"], "");
    }

    #[test]
    fn writable_by_ignores_root_and_names_groups() {
        let ids = Ids::from_entries(&parse_passwd(PASSWD), &parse_group(GROUP));
        assert!(writable_by(0o755, 0, 0, &ids).is_empty());
        assert_eq!(writable_by(0o644, 1000, 0, &ids), ["alice"]);
        assert_eq!(writable_by(0o664, 0, 27, &ids), ["%sudo"]);
        assert_eq!(writable_by(0o1777, 0, 0, &ids), ["everyone"]);
        assert_eq!(
            writable_by(0o666, 4242, 4343, &ids),
            ["4242", "%4343", "everyone"]
        );
    }

    #[test]
    fn resolves_symlinks_inside_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("usr/lib/real"), "x").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/usr/lib/real", root.join("etc/abs")).unwrap();
            std::os::unix::fs::symlink("../usr/lib/real", root.join("etc/rel")).unwrap();
            assert_eq!(resolve_in(root, "/etc/abs").unwrap(), "/usr/lib/real");
            assert_eq!(resolve_in(root, "/etc/rel").unwrap(), "/usr/lib/real");
        }
        assert_eq!(resolve_in(root, "/usr/lib/real").unwrap(), "/usr/lib/real");
    }
}
