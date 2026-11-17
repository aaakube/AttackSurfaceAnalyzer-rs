# asa compared with Microsoft Attack Surface Analyzer

Both tools do the same job: snapshot a machine, change it, snapshot again, and report what
changed in the attack surface. This page compares asa with the last release of the original,
**Attack Surface Analyzer 2.3.321** (.NET 9), on features and on measured speed.

## Summary

| | Attack Surface Analyzer 2.3 | asa |
|---|---|---|
| Platforms | Windows, Linux, macOS | Windows only |
| Distribution | .NET 9 application (needs the .NET and ASP.NET Core runtimes) | one `asa.exe`, Windows DLLs only |
| Network use | none required | none, by design |
| End-to-end time, whole system | 479 s | **113 s** (4.3× faster) |
| Peak memory, whole system | 2,745 MB | **142 MB** (19× less) |
| Database for two snapshots | 3,276 MB in 7 shard files | **151 MB** in 1 file (22× smaller) |
| Compare two snapshots | 165 s | **3.3 s** (50× faster) |
| Rules | OAT `analyses.json` (labelled clauses + expression string), `asa verify` | YAML `all/any/not` trees, linted by `asa rules check` |
| Results UI | Blazor GUI | local web UI with query language, facets, tree view, triage |
| Output formats | JSON, SARIF | table, JSON, JSONL, SARIF, CSV; `--fail-on` for CI |
| Status | no longer maintained | maintained |

## Speed

### Method

[`scripts/bench.ps1`](../scripts/bench.ps1) runs both tools under the same conditions, one
after the other, on the same machine:

1. warm the file cache (`dir /s C:\Windows`) and create 2,000 files;
2. **snapshot 1**: asa, then the original;
3. modify 200 of those files;
4. **snapshot 2**: the original, then asa (reversed, so neither tool always goes first);
5. **compare** the two snapshots with the default rules applied (`asa diff` /
   `export-collect`).

For each step it records wall time, the process' peak working set and the exit code. Both
executables were excluded from Defender real-time scanning so that the antivirus does not
favour one of them.

Two scenarios:

- **files:** the file collector only, on `C:\Windows` (`--path C:\Windows` / `--directories
  C:\Windows`).
- **full:** every collector the two tools have in common, on the whole system:
  - original: `-c -C -d -F -f -k -p -r -s -t -u -w`;
  - asa: `files,services,firewall,com,registry,users,certificates,ports,wifi,tpm,keys`.

Test machine: Windows 11 24H2 (build 26100), 4 virtual CPUs, about 122,000 files under
`C:\Windows` and 145,000 asa objects for the whole system. This machine was slow (high
interrupt load even when idle), so **absolute times are pessimistic for both tools; the
ratios are what matter.**

### Results: files on `C:\Windows`

| Step | Original | asa | asa advantage |
|---|---:|---:|---:|
| Snapshot 1 | 71.6 s | 51.4 s | 1.4× |
| Snapshot 2 | 51.7 s | 35.4 s | 1.5× |
| Compare (rules applied) | 18.4 s | 2.5 s | 7.4× |
| **Total** | **141.7 s** | **89.3 s** | **1.6×** |
| Peak memory | 1,257 MB | 131 MB | 9.6× less |
| Database (two snapshots) | 348 MB | 134 MB | 2.6× smaller |

### Results: whole system

| Step | Original | asa | asa advantage |
|---|---:|---:|---:|
| Snapshot 1 | 158.3 s | 58.3 s | 2.7× |
| Snapshot 2 | 155.6 s | 51.1 s | 3.0× |
| Compare (rules applied) | 165.4 s | 3.3 s | 50× |
| **Total** | **479.3 s** | **112.7 s** | **4.3×** |
| Peak memory | 2,745 MB | 142 MB | 19× less |
| Database (two snapshots) | 3,276 MB | 151 MB | 22× smaller |

### Why the gap

- **File walk:** both tools are I/O bound on the file walk, so the gap is smallest there
  (1.4–1.5×). asa reads PE headers, signatures and ACLs on worker threads and streams objects
  to a batched writer.
- **Memory:** the original's memory grows with what it collects (1.3 GB for `C:\Windows`,
  2.7 GB for the whole system, with default options; it has a `--lowmemoryusage` switch that
  was not used). asa streams objects through a bounded channel, so its memory stays flat
  whatever the machine size.
- **Storage:** asa stores each distinct object body once (content addressing), so the second
  snapshot costs little more than its paths. The original stores every object of every run.
- **Compare:** asa merge-joins the two runs on integer content ids and only deserializes the
  objects that differ. The original's compare grows with the size of the snapshots: 18 s for
  `C:\Windows`, 165 s for the whole system.
- **Scope differs on the registry.** By default the original's registry collector walks the
  whole registry (most of its 3.3 GB; `--hives` narrows it). asa collects persistence and policy locations plus any
  `--registry-key` you add. This explains part of the whole-system gap, and is also why the
  original reports far more registry noise (below).

### What each tool reported

Same change for both tools: 200 files modified between the snapshots.

| | Original | asa |
|---|---|---|
| files scenario | 218 file modifications (all WARNING) | 302 file changes (298 modified, 3 created, 1 deleted) |
| whole system | 897 changes: 345 file, 533 registry (all DEBUG or VERBOSE), 14 port, 5 service | 341 changes: 335 file, 4 registry, 2 certificate |

Both tools found the 200 modified files. The other changes are background activity of
Windows during the run (logs, caches, updates). The original's port and service changes come
from ephemeral ports and run state, which asa deliberately leaves out of snapshots.

## Real install: LibreOffice 26.8.3

A larger test: each tool snapshots the machine, LibreOffice 26.8.3 is installed silently from
its 376 MB MSI (`msiexec /qn`), and each tool snapshots and compares again. asa ran all its
collectors; the original ran the same collector set as above.

### Time and size

| | Original | asa |
|---|---:|---:|
| Snapshot before | 160.9 s | 110.6 s (first run, cold cache) |
| Snapshot after | 172.7 s | 60.3 s |
| Compare | 196.4 s | 4.6 s |
| **Total** | **530 s** | **175 s** (3× faster) |
| Database | 4,088 MB in 7 files | 168 MB |
| Changes reported | 22,911 | 15,347 |

### What each tool found

| What changed | Original | asa |
|---|---|---|
| Files installed | 13,845 files | the same 13,845, plus 161 more (109 TrueType and 18 OpenType fonts, 9 Start Menu shortcuts, ...) and 1,162 new folders |
| Unsigned executables | 18 (15 from LibreOffice + 3 Windows files changed by background servicing) | the same 15 from LibreOffice (pip launchers, `fbintl.dll`, ...) |
| "Expired signature" | 21 warnings | none: 19 of these binaries (Visual C++ runtime, drivers) are correctly timestamped and verify as **valid**; the other 2 did not change |
| Service `LibreOfficeMaintenance` (`update_service.exe`, LocalSystem, manual start) | ✓ (information) | ✓ (warning: new service running as SYSTEM; the binary is validly signed by The Document Foundation) |
| Other services | 3 warnings (`gpsvc`, `smphost`, `msiserver`): only their running state changed | none (run state is not collected) |
| COM registrations | none from the COM collector | 21 classes, 2 AppIDs, 2 type libraries, and the shell extension approval (warning) |
| Registry | 8,974 raw key changes, all at DEBUG level | the uninstall entry, the vendor key, the shell extension approval |
| Trusted roots | 1 root (Certum Trusted Network CA 2), counted twice (current user and machine views) | 2 roots (Certum Trusted Network CA and CA 2), each in Root and AuthRoot (critical) |
| Ports | 4 ephemeral UDP ports closed | 1 mDNS listener changed, 1 dynamic DNS port group gone |

Notes:

- **The new roots most likely come from Windows, not LibreOffice.** LibreOffice is signed
  through Certum, and the roots appeared in `AuthRoot`, the store Windows' automatic root
  update fills when it verifies a signature chaining to a root of the Microsoft program. It
  is still a real change to what the machine trusts, so it is right to report it, but
  telling these apart from roots added by software is on the [roadmap](roadmap.md).
- **Both tools found every LibreOffice binary.** The original missed fonts, shortcuts and
  folders, and buried the COM and registry changes in 8,974 DEBUG-level registry rows. asa
  reported them as typed COM objects with rules.
- **False alarms:** the original raised 24 warnings that asa does not: 21 expired-signature
  warnings on timestamped binaries and 3 run-state changes.

## Features

### Collectors

| Area | Original | asa |
|---|:---:|:---:|
| Files (signatures, PE mitigations, permissions) | ✓ | ✓ (catalog-aware signatures, `writable_by`) |
| Services, drivers | ✓ | ✓ (unquoted paths, writable binaries and keys) |
| Firewall | ✓ | ✓ (local and Group Policy stores) |
| COM | ✓ | ✓ (AppIDs, type libraries, per-user hijacks) |
| Registry | whole registry, or chosen hives (`--hives`) | persistence locations + custom keys (`--registry-key`) |
| Users and groups | ✓ | ✓ |
| Certificates | ✓ | ✓ (Group Policy and enterprise stores, weak signatures) |
| Open ports | ✓ | ✓ (dynamic ports grouped per program) |
| Wi-Fi profiles | ✓ | ✓ |
| TPM | ✓ | ✓ (plus Secure Boot) |
| Cryptographic keys | ✓ | ✓ (machine keys readable by non-admins) |
| Event logs | ✓ | — |
| Processes | ✓ | — (run state is deliberately not collected) |
| Scheduled tasks | — | ✓ |
| Defender exclusions and settings | — | ✓ |
| User rights (privileges) | — | ✓ |
| Security options (UAC, WDigest, LSA, NTLM, SMB, RDP) | — | ✓ |
| WMI event subscriptions | — | ✓ |

### Analysis and workflow

| | Original | asa |
|---|:---:|:---:|
| Rules with severities | ✓ | ✓ (137 built-in) |
| Rule validation | ✓ (`verify`) | ✓ (plus unknown fields and dead regexes) |
| Query language over results | — | ✓ |
| Tree view of changed paths | — | ✓ |
| Triage (accept / reviewed, follows object state) | — | ✓ |
| Coverage notices (failed or missing collectors) | — | ✓ |
| Which process made the change | — | ✓ (Procmon CSV import) |
| SARIF output | ✓ | ✓ |
| CI gating (`--fail-on`) | — | ✓ |
| Linux and macOS | ✓ | — |
| Real-time file system monitoring (`monitor`) | ✓ | — |
| Archive crawling, cloud-file download | ✓ | — |

## When to use which

- **Use asa** on Windows, on large machines or when you need to review
  findings quickly: it is faster, lighter, covers more Windows persistence techniques, and its
  results are easier to filter and triage.
- **Use the original** if you need Linux or macOS, event-log or process snapshots, a complete
  registry diff, or its built-in real-time file system monitoring.

## Reproducing

On a Windows machine, put the original in `C:\bench\ASA_win_2.3.321`, the .NET 9 and ASP.NET
Core 9 runtimes in `C:\bench\dotnet`, and `asa.exe` in `C:\asa`, then from an elevated
PowerShell:

```powershell
.\scripts\bench.ps1 -Scenario files
.\scripts\bench.ps1 -Scenario full
```

Results are written to `C:\bench\results-<scenario>.json`.
