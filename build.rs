//! Stamp the git commit into the binary so `asa --version` identifies exactly what
//! was built — important for a bundle hand-carried onto an air-gapped workstation.
//! Falls back to "unknown" when built outside a git checkout (e.g. from a tarball).

use std::process::Command;

fn main() {
    let commit = run(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let dirty = run(&["status", "--porcelain"]).is_some_and(|s| !s.is_empty());
    let stamp = if dirty {
        format!("{commit}-dirty")
    } else {
        commit
    };
    println!("cargo:rustc-env=ASA_GIT_COMMIT={stamp}");
    // Rebuild the stamp when the checked-out commit changes.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
}

fn run(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
