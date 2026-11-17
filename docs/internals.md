# Internals

## Built for large diffs

Collection and reporting are both streamed, so memory does not grow with the number of files
or changes.

- **Collection:** walker threads feed a bounded channel into a batched SQLite writer, and the
  walk slows down when the writer falls behind. Measured: 5.4 M files at about 170 MB peak.
- **Storage:** objects are content-addressed. Each distinct body is stored once, so a repeat
  snapshot mostly costs only its paths.
- **Diff:** a single merge join over both runs compares integer blob ids. Bodies are loaded
  only for objects that differ, one change at a time; then the rules run and the change is
  written out. Measured: 150,000 changes in under 1 s at about 74 MB peak, the same for every
  output format.
- **Web UI:** a comparison is computed once and stored, so the UI pages, filters and counts
  with SQL instead of holding results in memory. The tree view loads one folder level at a
  time.

## Design choices

- **One static binary, no runtime.** Only DLLs that ship with Windows.
- **Direct reads.** Collectors use the registry, files and Win32 APIs, not PowerShell or
  WMI (except where nothing else has the data).
- **Less noise.** Volatile values (directory mtimes, run state, PIDs, dynamic ports, last
  logon) are left out of snapshots, so two idle snapshots compare as identical.
- **Permissions as answers.** Instead of raw ACL dumps, `writable_by` and `readable_by` list
  the low-privileged principals that actually have access, honouring deny and inherit-only
  ACEs.
- **Catalog-aware signatures**, verified offline, like Windows does.

## Development

asa runs on Windows only. It is developed on Linux and cross-compiled
(`rust-toolchain.toml` pins the latest stable Rust and the `x86_64-pc-windows-gnu` target;
install mingw-w64):

```bash
cargo test                                          # unit tests on the build host
cargo build --release --target x86_64-pc-windows-gnu
scripts/package.sh                                  # dist/asa-<version>-windows-x64.zip + .sha256
```

## Continuous integration

Every push runs `.github/workflows/rust.yml`:

1. **lint:** `cargo fmt --check`, clippy for the Windows target with warnings as errors, and
   `asa rules check` on the default rules.
2. **test-windows:** `cargo test` on a Windows runner.
3. **package:** builds the release zip and attaches it to the run as `asa-windows-x64`.
4. **release** (tags only): pushing a tag `vX.Y.Z` that matches the version in `Cargo.toml`
   publishes a GitHub release with the zip and its `.sha256`:

   ```bash
   git tag v0.2.0 && git push origin v0.2.0
   ```

Changes are also verified on a fresh Windows 11 machine with an attack scenario covering the
default rules, the CLI, the web API and the web UI. Replaying a Chrome install detects all
58 ground-truth changes (3 services, 1 firewall rule, 8 COM classes, 7 AppIDs, 36 type
libraries, 1 scheduled task, the vendor key and the uninstall entry), plus Chrome's Active
Setup hook, without reporting the services the installer merely started.
