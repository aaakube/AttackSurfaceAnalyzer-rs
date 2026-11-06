//! Minimal PE header parser: just enough to report exploit-mitigation flags.
//! Pure Rust so it can be unit-tested on any host.

use serde::Serialize;

/// Bytes read from the start of a file; PE headers virtually always fit.
pub const HEADER_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeInfo {
    pub machine: String,
    pub subsystem: String,
    pub dll: bool,
    /// Has a CLR header (managed .NET assembly).
    pub dotnet: bool,
    /// DYNAMIC_BASE set *and* relocations present; without relocations the loader
    /// cannot actually rebase the image.
    pub aslr: bool,
    pub high_entropy_va: bool,
    pub dep: bool,
    pub cfg: bool,
    pub force_integrity: bool,
    pub appcontainer: bool,
}

const RELOCS_STRIPPED: u16 = 0x0001;
const FILE_DLL: u16 = 0x2000;

const HIGH_ENTROPY_VA: u16 = 0x0020;
const DYNAMIC_BASE: u16 = 0x0040;
const FORCE_INTEGRITY: u16 = 0x0080;
const NX_COMPAT: u16 = 0x0100;
const APPCONTAINER: u16 = 0x1000;
const GUARD_CF: u16 = 0x4000;

const CLR_DIRECTORY: usize = 14;

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

pub fn parse(b: &[u8]) -> Option<PeInfo> {
    if b.get(..2)? != b"MZ" {
        return None;
    }
    let pe = u32_at(b, 0x3c)? as usize;
    if b.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = pe + 4;
    let machine = u16_at(b, coff)?;
    let characteristics = u16_at(b, coff + 18)?;
    let opt = coff + 20;
    let magic = u16_at(b, opt)?;
    let (rva_count_off, dirs_off) = match magic {
        0x10b => (opt + 92, opt + 96),   // PE32
        0x20b => (opt + 108, opt + 112), // PE32+
        _ => return None,
    };
    let subsystem = u16_at(b, opt + 68)?;
    let dll_chars = u16_at(b, opt + 70)?;
    let dotnet = u32_at(b, rva_count_off).is_some_and(|n| n as usize > CLR_DIRECTORY)
        && u32_at(b, dirs_off + CLR_DIRECTORY * 8 + 4).is_some_and(|size| size != 0);

    Some(PeInfo {
        machine: match machine {
            0x014c => "x86".into(),
            0x8664 => "x64".into(),
            0xaa64 => "arm64".into(),
            0x01c4 => "arm".into(),
            other => format!("0x{other:04x}"),
        },
        subsystem: match subsystem {
            1 => "native".into(),
            2 => "gui".into(),
            3 => "console".into(),
            10..=13 => "efi".into(),
            16 => "boot".into(),
            other => other.to_string(),
        },
        dll: characteristics & FILE_DLL != 0,
        dotnet,
        aslr: dll_chars & DYNAMIC_BASE != 0 && characteristics & RELOCS_STRIPPED == 0,
        high_entropy_va: dll_chars & HIGH_ENTROPY_VA != 0,
        dep: dll_chars & NX_COMPAT != 0,
        cfg: dll_chars & GUARD_CF != 0,
        force_integrity: dll_chars & FORCE_INTEGRITY != 0,
        appcontainer: dll_chars & APPCONTAINER != 0,
    })
}

#[cfg(test)]
pub fn build(pe32_plus: bool, machine: u16, coff_chars: u16, dll_chars: u16, clr: bool) -> Vec<u8> {
    let mut b = vec![0u8; 1024];
    b[..2].copy_from_slice(b"MZ");
    let pe = 0x80usize;
    b[0x3c..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
    b[pe..pe + 4].copy_from_slice(b"PE\0\0");
    let coff = pe + 4;
    b[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
    b[coff + 18..coff + 20].copy_from_slice(&coff_chars.to_le_bytes());
    let opt = coff + 20;
    let magic: u16 = if pe32_plus { 0x20b } else { 0x10b };
    b[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
    b[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
    b[opt + 70..opt + 72].copy_from_slice(&dll_chars.to_le_bytes());
    let (cnt, dirs) = if pe32_plus {
        (opt + 108, opt + 112)
    } else {
        (opt + 92, opt + 96)
    };
    b[cnt..cnt + 4].copy_from_slice(&16u32.to_le_bytes());
    if clr {
        let off = dirs + CLR_DIRECTORY * 8;
        b[off..off + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        b[off + 4..off + 8].copy_from_slice(&0x48u32.to_le_bytes());
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardened_x64_exe() {
        let pe = parse(&build(true, 0x8664, 0x0022, 0x4160, false)).unwrap();
        assert_eq!(pe.machine, "x64");
        assert_eq!(pe.subsystem, "console");
        assert!(pe.aslr && pe.high_entropy_va && pe.dep && pe.cfg);
        assert!(!pe.dll && !pe.dotnet);
    }

    #[test]
    fn stripped_relocs_defeat_aslr() {
        let pe = parse(&build(false, 0x014c, RELOCS_STRIPPED, DYNAMIC_BASE, false)).unwrap();
        assert!(!pe.aslr);
        assert!(!pe.dep);
    }

    #[test]
    fn dotnet_dll() {
        let pe = parse(&build(
            false,
            0x014c,
            FILE_DLL,
            DYNAMIC_BASE | NX_COMPAT,
            true,
        ))
        .unwrap();
        assert!(pe.dll && pe.dotnet && pe.aslr && pe.dep);
    }

    #[test]
    fn rejects_garbage_and_truncation() {
        assert!(parse(b"MZ").is_none());
        assert!(parse(b"hello world").is_none());
        let mut b = build(true, 0x8664, 0, 0, false);
        b.truncate(0x90);
        assert!(parse(&b).is_none());
    }
}
