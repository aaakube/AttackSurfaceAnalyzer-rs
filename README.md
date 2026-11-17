# asa — attack surface analysis for Windows

Take a snapshot of a Windows machine, install or change something, take a second snapshot:
asa tells you what changed in the attack surface and whether it matters.

A rewrite in Rust inspired by Microsoft's
[Attack Surface Analyzer](https://github.com/microsoft/AttackSurfaceAnalyzer).

> asa is an independent project. It is not affiliated with, endorsed by or supported by
> Microsoft.

- **One file, no install.** `asa.exe` needs no runtime and never uses the network.
- **Covers what attackers use:** files, services, drivers, firewall, COM, registry persistence,
  users, rights, certificates, ports, scheduled tasks, Defender, WMI, security options, keys,
  TPM and Wi-Fi.
- **Fast on real machines:** about 4× faster end to end and 20× less memory than the original
  (see the [comparison](docs/comparison.md)).

## Quick start

From an **elevated** PowerShell:

```powershell
.\asa.exe collect --run-id before
# ... install or change something ...
.\asa.exe collect --run-id after
.\asa.exe serve --open          # web UI
.\asa.exe diff before after     # or a report in the terminal
```

Download `asa-windows-x64` from the latest successful
[CI run](https://github.com/aaakube/AttackSurfaceAnalyzer-rs/actions), or build it yourself:

```bash
scripts/package.sh              # dist/asa-<version>-windows-x64.zip + .sha256
```

## Documentation

| | |
|---|---|
| [Usage](docs/usage.md) | Commands, web UI, query language, triage |
| [What is collected](docs/collectors.md) | Every collector and its fields |
| [Rules](docs/rules.md) | Writing and checking detection rules |
| [Deployment](docs/deployment.md) | Installing and verifying the release bundle |
| [Process Monitor](docs/procmon.md) | Seeing which process made each change |
| [Internals](docs/internals.md) | Storage, scaling, development and CI |
| [Comparison with the original](docs/comparison.md) | Features and measured speed |
| [Roadmap](docs/roadmap.md) | Planned improvements and ideas |

## License

MIT, see [LICENSE](LICENSE). Some default rules are adapted from Microsoft Attack Surface
Analyzer (© Microsoft Corporation, MIT); see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
