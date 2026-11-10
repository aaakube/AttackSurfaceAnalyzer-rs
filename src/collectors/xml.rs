//! Just enough XML for the small, machine-written documents Windows keeps on disk
//! (scheduled task definitions, WLAN profiles): element text by name, ignoring
//! namespaces and attributes. Not a general parser: elements of the same name must
//! not nest, which holds for these schemas.

/// Text files Windows writes as UTF-8, or as UTF-16 with a byte-order mark.
pub fn decode(b: &[u8]) -> String {
    if let Some(rest) = b.strip_prefix(&[0xFF, 0xFE]) {
        let w: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16_lossy(&w)
    } else {
        String::from_utf8_lossy(b.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(b)).into_owned()
    }
}

/// Raw contents of every `<name ...>...</name>` (or `<name/>`, as "") in `xml`.
pub fn elements<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let open = format!("<{name}");
    let close = format!("</{name}>");
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        // `<Exec` must not match `<ExecutionTimeLimit`.
        match after.chars().next() {
            Some('>' | '/' | ' ' | '\t' | '\r' | '\n') => {}
            _ => {
                rest = after;
                continue;
            }
        }
        let Some(gt) = after.find('>') else { break };
        if after[..gt].ends_with('/') {
            out.push("");
            rest = &after[gt + 1..];
            continue;
        }
        let body = &after[gt + 1..];
        let Some(end) = body.find(&close) else { break };
        out.push(&body[..end]);
        rest = &body[end + close.len()..];
    }
    out
}

/// Contents of the first `<name>` element.
pub fn first<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    elements(xml, name).into_iter().next()
}

/// Trimmed, unescaped text of the first `<name>` element.
pub fn text(xml: &str, name: &str) -> Option<String> {
    first(xml, name).map(|s| unescape(s.trim()))
}

/// Names of the child elements directly inside `xml` (first level only).
pub fn children(xml: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut rest = xml;
    while let Some(i) = rest.find('<') {
        let tag = &rest[i + 1..];
        let Some(gt) = tag.find('>') else { break };
        let inner = &tag[..gt];
        if let Some(_closing) = inner.strip_prefix('/') {
            depth = depth.saturating_sub(1);
        } else if !inner.starts_with('?') && !inner.starts_with('!') {
            let name = inner
                .split(|c: char| c.is_whitespace() || c == '/')
                .next()
                .unwrap_or("");
            if depth == 0 && !name.is_empty() {
                out.push(name);
            }
            if !inner.ends_with('/') {
                depth += 1;
            }
        }
        rest = &tag[gt + 1..];
    }
    out
}

pub fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_elements_and_children() {
        let x = r#"<A><Exec><Command>a &amp; b</Command></Exec><ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
<Exec x="1"><Command>c</Command></Exec><BootTrigger/><LogonTrigger id="t"><Enabled>true</Enabled></LogonTrigger></A>"#;
        let execs = elements(x, "Exec");
        assert_eq!(execs.len(), 2);
        assert_eq!(text(execs[0], "Command").as_deref(), Some("a & b"));
        assert_eq!(text(execs[1], "Command").as_deref(), Some("c"));
        assert_eq!(elements(x, "BootTrigger"), vec![""]);
        assert_eq!(
            children(first(x, "A").unwrap()),
            vec![
                "Exec",
                "ExecutionTimeLimit",
                "Exec",
                "BootTrigger",
                "LogonTrigger"
            ]
        );
        assert!(first(x, "Missing").is_none());
    }

    #[test]
    fn decodes_utf16_and_utf8() {
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("<a>é</a>".encode_utf16().flat_map(|c| c.to_le_bytes()))
            .collect();
        assert_eq!(decode(&utf16), "<a>é</a>");
        assert_eq!(decode(b"\xEF\xBB\xBF<a/>"), "<a/>");
    }
}
