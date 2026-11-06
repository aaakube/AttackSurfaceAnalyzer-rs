//! Resolving the executables behind services and COM servers, and describing them
//! (existence, signature, who can overwrite them) once per unique path.

// Only constructed on Windows; compiled everywhere so the logic is unit-tested.
#![cfg_attr(not(windows), allow(dead_code))]

use super::registry::expand_env;
use super::win;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())
}

/// The executable a command line (service ImagePath, COM LocalServer32) runs, and
/// whether it is an unquoted path containing spaces: `C:\Program Files\A B\svc.exe`
/// unquoted lets anyone who can write `C:\Program.exe` hijack it.
pub fn parse_command(raw: &str) -> (Option<String>, bool) {
    let s = expand_env(raw.trim());
    let s = s.strip_prefix(r"\??\").unwrap_or(&s).to_string();
    if s.is_empty() {
        return (None, false);
    }
    let (path, quoted) = if let Some(rest) = s.strip_prefix('"') {
        (rest.split('"').next().unwrap_or(rest).to_string(), true)
    } else {
        // Up to the first executable extension followed by an argument boundary.
        let lower = s.to_ascii_lowercase();
        let end = [".exe", ".sys", ".dll", ".com", ".scr"]
            .iter()
            .filter_map(|ext| {
                lower
                    .match_indices(ext)
                    .map(|(i, _)| i + ext.len())
                    .find(|&e| {
                        matches!(
                            lower.as_bytes().get(e),
                            None | Some(b' ') | Some(b'\t') | Some(b'"')
                        )
                    })
            })
            .min();
        match end {
            Some(e) => (s[..e].to_string(), false),
            None => (s.split(' ').next().unwrap_or(&s).to_string(), false),
        }
    };
    let path = resolve(&path);
    let unquoted_spaces = !quoted && path.contains(' ');
    (Some(path), unquoted_spaces)
}

/// Normalizes the path forms the service manager and COM accept.
pub fn resolve(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix(r"\systemroot\") {
        return format!(r"{}\{}", system_root(), &path[path.len() - rest.len()..]);
    }
    // Drivers commonly use paths relative to the Windows directory.
    if lower.starts_with(r"system32\") || lower.starts_with(r"syswow64\") {
        return format!(r"{}\{path}", system_root());
    }
    path.to_string()
}

/// A bare DLL name (`ole32.dll`) as a COM InprocServer32 resolves through the
/// system directory of the matching view.
pub fn resolve_dll(name: &str, wow64: bool) -> String {
    let name = expand_env(name.trim().trim_matches('"'));
    if name.contains('\\') || name.contains('/') {
        return resolve(&name);
    }
    let dir = if wow64 { "SysWOW64" } else { "System32" };
    format!(r"{}\{dir}\{name}", system_root())
}

#[derive(Debug, Clone, Default)]
pub struct BinaryInfo {
    pub exists: bool,
    pub signature: Option<win::Signature>,
    pub writable_by: Vec<String>,
}

/// Describes each unique path once, spread over `threads` workers. Keys are
/// lowercased paths.
pub fn describe(
    paths: BTreeSet<String>,
    threads: usize,
    signatures: bool,
) -> HashMap<String, BinaryInfo> {
    let paths: Vec<String> = paths.into_iter().collect();
    if paths.is_empty() {
        return HashMap::new();
    }
    let chunk = paths.len().div_ceil(threads.max(1));
    std::thread::scope(|s| {
        let handles: Vec<_> = paths
            .chunks(chunk)
            .map(|part| {
                s.spawn(move || {
                    part.iter()
                        .map(|p| (p.to_lowercase(), describe_one(p, signatures)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("binary describer panicked"))
            .collect()
    })
}

fn describe_one(path: &str, signatures: bool) -> BinaryInfo {
    let p = Path::new(path);
    if !p.is_file() {
        return BinaryInfo::default();
    }
    #[cfg(windows)]
    {
        BinaryInfo {
            exists: true,
            signature: signatures.then(|| win::signature(p)),
            writable_by: win::security(p).map(|s| s.writable_by).unwrap_or_default(),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = signatures;
        BinaryInfo {
            exists: true,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_root() {
        // SAFETY: all tests in this module set the same value.
        unsafe { std::env::set_var("SystemRoot", r"C:\Windows") };
    }

    #[test]
    fn parses_service_command_lines() {
        set_root();
        let p = |s| parse_command(s);
        assert_eq!(
            p(r#""C:\Program Files\Google\updater.exe" --system"#),
            (Some(r"C:\Program Files\Google\updater.exe".into()), false)
        );
        assert_eq!(
            p(r"C:\Program Files\Vendor App\svc.exe -k run"),
            (Some(r"C:\Program Files\Vendor App\svc.exe".into()), true)
        );
        assert_eq!(
            p(r"C:\Windows\system32\svchost.exe -k netsvcs -p"),
            (Some(r"C:\Windows\system32\svchost.exe".into()), false)
        );
        assert_eq!(
            p(r"%SystemRoot%\System32\svchost.exe -k LocalService"),
            (Some(r"C:\Windows\System32\svchost.exe".into()), false)
        );
        assert_eq!(
            p(r"\SystemRoot\System32\drivers\tcpip.sys"),
            (Some(r"C:\Windows\System32\drivers\tcpip.sys".into()), false)
        );
        assert_eq!(
            p(r"System32\drivers\disk.sys"),
            (Some(r"C:\Windows\System32\drivers\disk.sys".into()), false)
        );
        assert_eq!(
            p(r"\??\C:\ProgramData\drv\x.sys"),
            (Some(r"C:\ProgramData\drv\x.sys".into()), false)
        );
        // ".exe" inside a directory name is not the end of the path.
        assert_eq!(
            p(r"C:\tools\my.exe.d\run.exe /q"),
            (Some(r"C:\tools\my.exe.d\run.exe".into()), false)
        );
        assert_eq!(p(""), (None, false));
    }

    #[test]
    fn resolves_bare_com_dlls() {
        set_root();
        assert_eq!(
            resolve_dll("ole32.dll", false),
            r"C:\Windows\System32\ole32.dll"
        );
        assert_eq!(
            resolve_dll("ole32.dll", true),
            r"C:\Windows\SysWOW64\ole32.dll"
        );
        assert_eq!(resolve_dll(r#""C:\x\a.dll""#, false), r"C:\x\a.dll");
    }
}
