# Air-gapped deployment

## Build and transfer

On a connected machine with Rust and mingw-w64:

```bash
scripts/package.sh      # runs the tests, builds dist/asa-<version>-windows-x64.zip
```

Or download the `asa-windows-x64` artifact from a CI run. Copy the zip and its `.sha256` file
across, then on the workstation:

```powershell
(Get-FileHash .\asa-<version>-windows-x64.zip -Algorithm SHA256).Hash   # must match the .sha256 file
Expand-Archive .\asa-<version>-windows-x64.zip 'C:\Program Files\asa'
```

## Where to install

Install under `C:\Program Files` (or another folder only administrators can write to),
**not** in a new folder directly under `C:\`.

Folders created at the root of the system drive inherit a permission that lets every
authenticated user modify their files. Anyone could then replace `asa.exe` and have the next
administrator run their code. asa itself reports exactly this as "Executable writable by
non-admins".

## Offline behaviour

- **Signatures** are verified without revocation lookups or certificate downloads. Results are
  identical online and offline, with no network timeouts. A publisher whose root certificate
  isn't in the machine's trust store shows as `untrusted`, which is accurate for that machine.
- **Dependencies:** only DLLs that ship with Windows (kernel32, advapi32, wintrust, crypt32,
  msvcrt, ...).
- **Unsigned asa.exe:** the binary itself isn't code-signed. Files copied from removable media
  normally carry no "downloaded from the internet" mark. If Windows still blocks it, run
  `Unblock-File .\asa.exe` after verifying the hash.
- **Web UI:** listens on loopback only, loads nothing from the internet, and rejects
  cross-site requests.
