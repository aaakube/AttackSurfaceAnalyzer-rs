//! Best-effort, offline translation of an SDDL string into a readable ACL.
//!
//! This mirrors the decoder in the web UI (`web/index.html`), so `asa sddl <string>`
//! and JSON/report consumers get the same human-readable breakdown the detail view
//! shows. It parses the owner (`O:`), group (`G:`) and DACL (`D:`) and maps the
//! well-known SID aliases, access-mask tokens and common hex masks. Anything it cannot
//! classify (object ACEs, conditional ACEs, raw domain SIDs) falls back to the raw
//! token or SID — it never fails, it just degrades.

/// A decoded access-control list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acl {
    pub owner: Option<String>,
    pub group: Option<String>,
    pub aces: Vec<Ace>,
}

/// One decoded access-control entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    pub kind: String,
    pub inherited: bool,
    pub who: String,
    pub rights: String,
}

/// Map a 2-letter SID alias or raw SID string to a readable principal.
fn principal(s: &str) -> String {
    let alias = match s {
        "AN" => "Anonymous",
        "AU" => "Authenticated Users",
        "BA" => "Administrators",
        "BG" => "Guests",
        "BO" => "Backup Operators",
        "BU" => "Users",
        "CG" => "Creator Group",
        "CO" => "Creator Owner",
        "IU" => "Interactive Users",
        "LA" => "Local Administrator",
        "LG" => "Local Guest",
        "LS" => "Local Service",
        "NS" => "Network Service",
        "NU" => "Network",
        "PU" => "Power Users",
        "RC" => "Restricted Code",
        "RD" => "Remote Desktop Users",
        "RE" => "Replicator",
        "SO" => "Server Operators",
        "SU" => "Service Logons",
        "SY" => "Local System",
        "WD" => "Everyone",
        "WR" => "Write Restricted",
        "AC" => "All Application Packages",
        "PS" => "Self",
        "LW" => "Low Integrity",
        "ME" => "Medium Integrity",
        "HI" => "High Integrity",
        "SI" => "System Integrity",
        _ => "",
    };
    if !alias.is_empty() {
        return alias.to_string();
    }
    let full = match s {
        "S-1-1-0" => "Everyone",
        "S-1-3-0" => "Creator Owner",
        "S-1-3-1" => "Creator Group",
        "S-1-5-7" => "Anonymous",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-18" => "Local System",
        "S-1-5-19" => "Local Service",
        "S-1-5-20" => "Network Service",
        "S-1-5-32-544" => "Administrators",
        "S-1-5-32-545" => "Users",
        "S-1-5-32-546" => "Guests",
        "S-1-5-32-547" => "Power Users",
        "S-1-5-32-555" => "Remote Desktop Users",
        "S-1-15-2-1" => "All Application Packages",
        _ => "",
    };
    if full.is_empty() {
        s.to_string()
    } else {
        full.to_string()
    }
}

fn right_token(t: &str) -> &str {
    match t {
        "GA" => "Generic All",
        "GR" => "Generic Read",
        "GW" => "Generic Write",
        "GX" => "Generic Execute",
        "RC" => "Read Control",
        "SD" => "Delete",
        "WD" => "Write DAC",
        "WO" => "Write Owner",
        "FA" | "KA" => "Full control",
        "FR" | "KR" => "Read",
        "FW" | "KW" => "Write",
        "FX" | "KX" => "Execute",
        "CC" => "Create Child",
        "DC" => "Delete Child",
        "LC" => "List Children",
        "SW" => "Self Write",
        "RP" => "Read Property",
        "WP" => "Write Property",
        "DT" => "Delete Tree",
        "LO" => "List Object",
        "CR" => "Control Access",
        other => other,
    }
}

fn known_mask(n: u32) -> Option<&'static str> {
    Some(match n {
        0x1f01ff => "Full control",
        0x1301bf => "Modify",
        0x1200a9 => "Read & execute",
        0x120089 => "Read",
        0x100116 => "Write",
        0x1f0000 => "Standard rights",
        0x10000000 => "Generic All",
        _ => return None,
    })
}

fn decode_rights(r: &str) -> String {
    if r.is_empty() {
        return "(none)".to_string();
    }
    if let Some(hex) = r.strip_prefix("0x").or_else(|| r.strip_prefix("0X")) {
        if let Ok(n) = u32::from_str_radix(hex, 16) {
            if let Some(name) = known_mask(n) {
                return name.to_string();
            }
            const BITS: &[(u32, &str)] = &[
                (0x80000000, "Generic Read"),
                (0x40000000, "Generic Write"),
                (0x20000000, "Generic Execute"),
                (0x10000000, "Generic All"),
                (0x80000, "Write Owner"),
                (0x40000, "Write DAC"),
                (0x20000, "Read Control"),
                (0x10000, "Delete"),
                (0x100, "Write Attributes"),
                (0x80, "Read Attributes"),
                (0x40, "Delete Child"),
                (0x20, "Execute/Traverse"),
                (0x10, "Write EA"),
                (0x8, "Read EA"),
                (0x4, "Append"),
                (0x2, "Write"),
                (0x1, "Read"),
            ];
            let names: Vec<&str> = BITS
                .iter()
                .filter(|(bit, _)| n & bit != 0)
                .map(|(_, name)| *name)
                .collect();
            if names.is_empty() {
                return r.to_string();
            }
            return names.join(", ");
        }
        return r.to_string();
    }
    // Otherwise a run of 2-letter tokens.
    r.as_bytes()
        .chunks(2)
        .map(|c| right_token(std::str::from_utf8(c).unwrap_or("")))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Extract the value after `O:` or `G:`: either a full `S-...` SID or a 2-letter alias.
fn owner_group(s: &str, tag: char) -> Option<String> {
    let at = s.find(&format!("{tag}:")[..])? + 2;
    let rest = &s[at..];
    if let Some(sid) = rest.strip_prefix("S-") {
        let end = sid
            .find(|c: char| !(c.is_ascii_digit() || c == '-'))
            .unwrap_or(sid.len());
        Some(format!("S-{}", &sid[..end]))
    } else {
        let alias: String = rest
            .chars()
            .take_while(|c| c.is_ascii_uppercase())
            .take(2)
            .collect();
        (alias.len() == 2).then_some(alias)
    }
}

/// Decode an SDDL string, or `None` if nothing recognisable is present.
pub fn decode(s: &str) -> Option<Acl> {
    let owner = owner_group(s, 'O').map(|x| principal(&x));
    let group = owner_group(s, 'G').map(|x| principal(&x));

    // The DACL runs from `D:` (after its flag letters) through its parenthesised ACEs.
    let mut aces = Vec::new();
    if let Some(d) = s.find("D:") {
        let after = &s[d + 2..];
        let start = after.find('(').unwrap_or(after.len());
        let body = &after[start..];
        for group_str in parenthesised(body) {
            let f: Vec<&str> = group_str.split(';').collect();
            if f.is_empty() {
                continue;
            }
            aces.push(Ace {
                kind: ace_type(f.first().copied().unwrap_or("")).to_string(),
                inherited: f.get(1).copied().unwrap_or("").contains("ID"),
                who: principal(f.get(5).copied().unwrap_or("")),
                rights: decode_rights(f.get(2).copied().unwrap_or("")),
            });
        }
    }

    if owner.is_none() && group.is_none() && aces.is_empty() {
        return None;
    }
    Some(Acl { owner, group, aces })
}

fn ace_type(t: &str) -> &str {
    match t {
        "A" | "OA" => "Allow",
        "D" | "OD" => "Deny",
        "AU" => "Audit",
        "AL" => "Alarm",
        "ML" => "Label",
        other => other,
    }
}

/// The inner text of each top-level `(...)` group, in order.
fn parenthesised(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(open) = rest.find('(') {
        let after = &rest[open + 1..];
        if let Some(close) = after.find(')') {
            out.push(&after[..close]);
            rest = &after[close + 1..];
        } else {
            break;
        }
    }
    out
}

impl Acl {
    /// A readable multi-line rendering, as the CLI prints it.
    pub fn render(&self) -> String {
        let mut out = String::new();
        if let Some(o) = &self.owner {
            out.push_str(&format!("Owner: {o}\n"));
        }
        if let Some(g) = &self.group {
            out.push_str(&format!("Group: {g}\n"));
        }
        if self.aces.is_empty() {
            out.push_str("(no DACL entries)\n");
        }
        // Column widths for a tidy table.
        let kw = self
            .aces
            .iter()
            .map(|a| a.kind.len() + if a.inherited { 12 } else { 0 })
            .max()
            .unwrap_or(0);
        let ww = self.aces.iter().map(|a| a.who.len()).max().unwrap_or(0);
        for a in &self.aces {
            let verb = if a.inherited {
                format!("{} (inherited)", a.kind)
            } else {
                a.kind.clone()
            };
            out.push_str(&format!("  {verb:<kw$}  {:<ww$}  {}\n", a.who, a.rights));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_typical_file_descriptor() {
        let acl =
            decode("O:SYG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)(D;;0x80000;;;WD)")
                .unwrap();
        assert_eq!(acl.owner.as_deref(), Some("Local System"));
        assert_eq!(acl.group.as_deref(), Some("Local System"));
        assert_eq!(acl.aces.len(), 4);
        assert_eq!(
            acl.aces[0],
            Ace {
                kind: "Allow".into(),
                inherited: true,
                who: "Local System".into(),
                rights: "Full control".into()
            }
        );
        assert_eq!(acl.aces[2].rights, "Read & execute");
        assert_eq!(
            acl.aces[3],
            Ace {
                kind: "Deny".into(),
                inherited: false,
                who: "Everyone".into(),
                rights: "Write Owner".into()
            }
        );
    }

    #[test]
    fn maps_full_sids_and_token_runs() {
        let acl = decode("O:S-1-5-32-544D:(A;;FRFW;;;S-1-5-11)").unwrap();
        assert_eq!(acl.owner.as_deref(), Some("Administrators"));
        assert_eq!(acl.aces[0].who, "Authenticated Users");
        assert_eq!(acl.aces[0].rights, "Read, Write");
    }

    #[test]
    fn unknown_hex_mask_decodes_to_bits() {
        let acl = decode("D:(A;;0x120089;;;BU)").unwrap();
        assert_eq!(acl.aces[0].rights, "Read");
        let acl2 = decode("D:(A;;0x60;;;BU)").unwrap();
        assert_eq!(acl2.aces[0].rights, "Delete Child, Execute/Traverse");
    }

    #[test]
    fn garbage_returns_none() {
        assert!(decode("not an sddl string").is_none());
        assert!(decode("").is_none());
    }

    #[test]
    fn render_is_multiline() {
        let r = decode("O:SYD:(A;;FA;;;BA)").unwrap().render();
        assert!(r.contains("Owner: Local System"));
        assert!(r.contains("Administrators"));
        assert!(r.contains("Full control"));
    }
}
