use super::{Collector, Sink, pe, win};
use crate::model::{Kind, Record};
use anyhow::Result;
use ignore::{WalkBuilder, WalkState};
use serde::Serialize;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

pub struct FilesCollector {
    pub roots: Vec<PathBuf>,
    pub exclude: Vec<PathBuf>,
    /// Compute a BLAKE3 content hash of every regular file (slower, but detects
    /// content changes that keep size and mtime).
    pub hash: bool,
    /// Read owner and DACL of every file and directory.
    pub acls: bool,
    /// Verify Authenticode signatures of signable files.
    pub signatures: bool,
    pub threads: usize,
}

/// `%SystemDrive%\`, normally `C:\`.
pub fn default_roots() -> Vec<PathBuf> {
    vec![PathBuf::from(format!("{}\\", system_drive()))]
}

/// Locations that are inaccessible even to administrators, or pure churn.
pub fn default_excludes() -> Vec<PathBuf> {
    let drive = system_drive();
    [
        "System Volume Information",
        "$Recycle.Bin",
        "Windows\\SoftwareDistribution\\Download",
    ]
    .iter()
    .map(|d| PathBuf::from(format!("{drive}\\{d}")))
    .collect()
}

fn system_drive() -> String {
    std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())
}

pub const FIELDS: &[&str] = &[
    "path",
    "file_type",
    "size",
    "modified",
    "hidden",
    "system",
    "readonly",
    "owner",
    "owner_sid",
    "sddl",
    "writable_by",
    "executable",
    "format",
    "pe",
    "signature",
    "target",
    "hash",
];

#[derive(Serialize)]
struct FileObject {
    path: String,
    file_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    /// Unix seconds. Omitted for directories, whose mtime changes on every
    /// entry creation and would drown real changes in noise.
    #[serde(skip_serializing_if = "Option::is_none")]
    modified: Option<i64>,
    hidden: bool,
    system: bool,
    readonly: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sddl: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    writable_by: Vec<String>,
    executable: bool,
    /// pe, msi or script.
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pe: Option<pe::PeInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<win::Signature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
}

const PE_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv", ".efi", ".com",
];
const SCRIPT_EXTENSIONS: &[&str] = &[
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".hta",
];

/// Windows paths are case-insensitive; compare lowercased, on component boundaries.
fn is_excluded(path: &Path, exclude: &[String]) -> bool {
    let p = path.to_string_lossy().to_lowercase();
    exclude.iter().any(|x| {
        p.starts_with(x.as_str())
            && matches!(p.as_bytes().get(x.len()), None | Some(b'\\') | Some(b'/'))
    })
}

impl Collector for FilesCollector {
    fn name(&self) -> &'static str {
        "files"
    }

    fn collect(&self, sink: &Sink) -> Result<()> {
        let Some((first, rest)) = self.roots.split_first() else {
            return Ok(());
        };
        let exclude: Vec<String> = self
            .exclude
            .iter()
            .map(|x| {
                x.to_string_lossy()
                    .trim_end_matches(['\\', '/'])
                    .to_lowercase()
            })
            .collect();
        let mut builder = WalkBuilder::new(first);
        for root in rest {
            builder.add(root);
        }
        // Visitors run on the walker threads and block when the sink's bounded channel
        // is full, so the walk never runs ahead of the database writer.
        builder
            .standard_filters(false)
            .follow_links(false)
            .threads(self.threads)
            .filter_entry(move |e| !is_excluded(e.path(), &exclude))
            .build_parallel()
            .run(|| {
                Box::new(|entry| {
                    match entry {
                        Ok(e) => match fs::symlink_metadata(e.path()) {
                            Ok(md) => sink.emit(self.describe(e.path(), &md, sink)),
                            Err(err) => sink.warn(|| format!("{}: {err}", e.path().display())),
                        },
                        Err(err) => sink.warn(|| err.to_string()),
                    }
                    WalkState::Continue
                })
            });
        Ok(())
    }
}

impl FilesCollector {
    fn describe(&self, path: &Path, md: &Metadata, sink: &Sink) -> Record {
        let ft = md.file_type();
        let file_type = if ft.is_symlink() {
            "symlink"
        } else if ft.is_dir() {
            "dir"
        } else if ft.is_file() {
            "file"
        } else {
            "other"
        };
        let path_str = path.to_string_lossy().into_owned();
        let lower = path_str.to_lowercase();
        let (hidden, system, readonly) = attributes(md);
        let mut obj = FileObject {
            path: path_str.clone(),
            file_type,
            size: ft.is_file().then_some(md.len()),
            modified: None,
            hidden,
            system,
            readonly,
            owner: None,
            owner_sid: None,
            sddl: None,
            writable_by: Vec::new(),
            executable: false,
            format: None,
            pe: None,
            signature: None,
            target: None,
            hash: None,
        };

        if !ft.is_dir() {
            obj.modified = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64);
        }
        if ft.is_symlink() {
            obj.target = fs::read_link(path)
                .ok()
                .map(|t| t.to_string_lossy().into_owned());
        }

        // Reparse points are skipped: querying them would describe the target.
        if self.acls && !ft.is_symlink() {
            apply_security(&mut obj, path, sink);
        }

        if ft.is_file() {
            if PE_EXTENSIONS.iter().any(|e| lower.ends_with(e)) {
                match read_header(path) {
                    Ok(h) if h.starts_with(b"MZ") => {
                        obj.format = Some("pe");
                        obj.pe = pe::parse(&h);
                    }
                    Ok(_) => {}
                    Err(err) => sink.warn(|| format!("reading {}: {err}", path.display())),
                }
            } else if lower.ends_with(".msi") {
                obj.format = Some("msi");
            } else if SCRIPT_EXTENSIONS.iter().any(|e| lower.ends_with(e)) {
                obj.format = Some("script");
            }
            obj.executable = obj.format.is_some();
            if self.signatures && obj.executable && win::signable(&lower) {
                obj.signature = signature(path);
            }
            if self.hash {
                match hash_file(path) {
                    Ok(h) => obj.hash = Some(h),
                    Err(err) => sink.warn(|| format!("hashing {}: {err}", path.display())),
                }
            }
        }

        Record::new(Kind::File, path_str, &obj)
    }
}

#[cfg(windows)]
fn apply_security(obj: &mut FileObject, path: &Path, sink: &Sink) {
    match win::security(path) {
        Ok(s) => {
            obj.owner = s.owner;
            obj.owner_sid = s.owner_sid;
            obj.sddl = s.sddl;
            obj.writable_by = s.writable_by;
        }
        Err(err) => sink.warn(|| format!("{}: {err}", path.display())),
    }
}

#[cfg(not(windows))]
fn apply_security(_: &mut FileObject, _: &Path, _: &Sink) {}

#[cfg(windows)]
fn signature(path: &Path) -> Option<win::Signature> {
    Some(win::signature(path))
}

#[cfg(not(windows))]
fn signature(_: &Path) -> Option<win::Signature> {
    None
}

#[cfg(windows)]
fn attributes(md: &Metadata) -> (bool, bool, bool) {
    use std::os::windows::fs::MetadataExt;
    let a = md.file_attributes();
    (a & 0x2 != 0, a & 0x4 != 0, a & 0x1 != 0)
}

#[cfg(not(windows))]
fn attributes(md: &Metadata) -> (bool, bool, bool) {
    (false, false, md.permissions().readonly())
}

fn read_header(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(pe::HEADER_BYTES);
    File::open(path)?
        .take(pe::HEADER_BYTES as u64)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(File::open(path)?)?;
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusion_is_case_insensitive_and_component_aware() {
        let ex = vec![
            r"c:\system volume information".to_string(),
            r"c:\temp".to_string(),
        ];
        assert!(is_excluded(Path::new(r"C:\System Volume Information"), &ex));
        assert!(is_excluded(Path::new(r"C:\TEMP\x.txt"), &ex));
        assert!(!is_excluded(Path::new(r"C:\Temporary\x.txt"), &ex));
        assert!(!is_excluded(Path::new(r"C:\Windows"), &ex));
    }

    #[test]
    fn describes_pe_and_script_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tool.exe");
        fs::write(&p, pe::build(true, 0x8664, 0x22, 0x0160, false)).unwrap();
        fs::write(dir.path().join("run.ps1"), "Write-Host hi").unwrap();
        let c = FilesCollector {
            roots: vec![dir.path().into()],
            exclude: vec![],
            hash: true,
            acls: true,
            signatures: true,
            threads: 2,
        };
        let (tx, rx) = crossbeam_channel::unbounded();
        let sink = Sink::new(tx, false);
        c.collect(&sink).unwrap();
        drop(sink);
        let recs: std::collections::HashMap<String, serde_json::Value> =
            rx.iter().map(|r| (r.identity, r.data)).collect();
        assert_eq!(recs.len(), 3, "root dir + 2 files");
        let exe = &recs[&p.to_string_lossy().into_owned()];
        assert_eq!(exe["format"], "pe");
        assert_eq!(exe["executable"], true);
        assert_eq!(exe["pe"]["aslr"], true);
        assert_eq!(exe["pe"]["cfg"], false);
        assert!(exe["hash"].is_string());
        let ps1 = &recs[&dir.path().join("run.ps1").to_string_lossy().into_owned()];
        assert_eq!(ps1["format"], "script");
    }

    #[test]
    fn fields_in_sync() {
        let s = || Some(String::new());
        let obj = FileObject {
            path: String::new(),
            file_type: "file",
            size: Some(0),
            modified: Some(0),
            hidden: false,
            system: false,
            readonly: false,
            owner: s(),
            owner_sid: s(),
            sddl: s(),
            writable_by: vec!["Users".into()],
            executable: true,
            format: Some("pe"),
            pe: pe::parse(&pe::build(true, 0x8664, 0, 0, false)),
            signature: Some(win::Signature {
                status: "valid".into(),
                source: None,
                signer: None,
            }),
            target: s(),
            hash: s(),
        };
        crate::collectors::assert_fields(&obj, FIELDS);
    }
}
