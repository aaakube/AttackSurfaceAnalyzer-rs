# asa — Attack Surface Analyzer for Windows, reborn

A rewrite in Rust of Microsoft's [Attack Surface Analyzer](https://github.com/microsoft/AttackSurfaceAnalyzer),
which is no longer maintained.

You take a snapshot of a Windows machine, install or configure something, and take a second
snapshot. `asa` then reports what changed in the attack surface:

- **files:** unsigned or tampered binaries, missing ASLR/DEP/CFG, anything non-admins can
  write to
- **services and drivers:** new SYSTEM services, unquoted paths, writable binaries or
  service keys, unsigned drivers
- **firewall:** new inbound openings, disabled profiles, allow-by-default
- **COM:** elevation-enabled classes, service-hosted servers, per-user hijacks of machine
  classes
- **registry persistence:** Run keys, IFEO debuggers, AppInit/AppCert DLLs, Winlogon, LSA
  packages, policies, installed programs, and more
- **users and groups:** new accounts, privileged group membership, Guest enabled, no password
- **certificates:** rogue trusted roots (including via Group Policy), trusted publishers, removed
  distrust, weak signatures
- **open ports:** new listeners on all interfaces, unsigned or user-writable listening programs
- **Wi-Fi:** open or weak networks, auto-connect, keys stored in clear text

## Quick start (on the Windows machine)

`asa.exe` is a single self-contained executable. It never uses the network, so it works
on air-gapped machines. Run it from an **elevated** PowerShell, because many ACLs and
protected files can't be read otherwise.

```powershell
.\asa.exe collect --run-id before
# ... install / change something ...
.\asa.exe collect --run-id after
.\asa.exe serve --open          # web UI in the default browser
.\asa.exe diff before after     # or a report in the terminal
```

Everything is stored in `.\asa.db` (use `--db PATH` or `ASA_DB` to change it).

## Web UI

`asa serve` starts a local web UI on `http://127.0.0.1:8740/`. It listens on loopback only
and loads nothing from the internet.

- **Compare:** pick two runs and press *Compare*. The comparison is computed once and stored
  in the database, so filtering, sorting and paging stay instant even with hundreds of
  thousands of changes.
- **List or tree:** the results show as a sortable list, or as a tree of their paths
  (`C:\Program Files\Vendor\...`, `HKLM\SOFTWARE\...`, one root per kind) with change
  counts per folder. Folders open one level at a time, so even 100,000 changes stay fast,
  and chains of single folders collapse into one row.
- **Coverage notices:** if a run did not finish, a collector failed, a kind was collected in
  only one of the two runs, or collection hit access-denied warnings, the comparison says so
  above the results (and `asa diff` prints the same notes). That way a missing change is never
  taken for "nothing changed".
- **Browse run:** query the objects of a single snapshot, for example every unsigned PE on
  the machine.
- **Detail panel:** findings with explanations, a before/after table of changed fields,
  the Procmon events behind the change (see [Live monitoring](#live-monitoring)), and
  the full object. Click any field to add it to the query.
- **Facets and cards** (severity, kind, change type, rule, and the process that made the
  change) count what matches the current query. Clicking one toggles its term: once to add
  it, again to remove it (active ones are highlighted). Picking another kind, change type
  or severity replaces the current one instead of adding an impossible `kind = a and
  kind = b`, and those three are counted as if their own term weren't set, so the
  alternatives stay visible.
- **Export:** JSONL or CSV of everything matching the query, including `modified_by`.
- **The URL keeps the state** (query, comparison, selected item), so a bookmark reopens a
  finding exactly.

### Query language

```text
severity >= warning
signature.status = unsigned and format = pe
rule = "Executable writable by non-admins"
writable_by has Users
path ~ "\\Program Files( \(x86\))?\\Google\\" and change = created
not pe.aslr or not pe.dep
signature.signer changed
size > 50000000
modified_by = msiexec.exe                (needs an imported Procmon capture)
chrome                                   (a bare word searches paths)
```

Operators: `=` `!=` `<` `<=` `>` `>=`, `~` (regex, case-insensitive), `has` (substring, or
an item of a list), `exists`, `missing`, `changed` (the field differs between the two
snapshots). Combine with `and`, `or`, `not` and parentheses. Adjacent terms are and-ed.
String comparisons ignore case. Strings take no escapes, so write Windows paths as-is; to
include a quote character, delimit the string with the other kind of quote.

Fields: `path`, `kind`, `change`, `severity`, `rule`, `modified_by`, plus any object field (see below), with
dots for nested ones (`signature.status`, `pe.cfg`).

## Air-gapped deployment

On a connected machine with Rust and mingw-w64:

```bash
scripts/package.sh      # runs the tests, builds dist/asa-<version>-windows-x64.zip
```

Copy the zip and its `.sha256` file across, then on the workstation:

```powershell
(Get-FileHash .\asa-<version>-windows-x64.zip -Algorithm SHA256).Hash   # must match the .sha256 file
Expand-Archive .\asa-<version>-windows-x64.zip 'C:\Program Files\asa'
```

Install it under `C:\Program Files` (or another folder only administrators can write
to), **not** in a new folder directly under `C:\`. Folders created at the root of the
system drive inherit a permission that lets every authenticated user modify their
files, so anyone could replace `asa.exe` and have the next administrator run their code.
asa itself reports exactly this as "Executable writable by non-admins".

Offline behaviour:

- **Signatures** are verified without revocation lookups or certificate downloads. Results
  are identical online and offline, with no network timeouts. A publisher whose root
  certificate isn't in the machine's trust store shows as `untrusted`, which is accurate for
  that machine.
- **Dependencies:** only DLLs that ship with Windows (kernel32, advapi32, wintrust, crypt32,
  msvcrt, ...).
- **Unsigned asa.exe:** the binary itself isn't code-signed. Files copied from removable
  media normally carry no "downloaded from the internet" mark. If Windows still blocks it,
  run `Unblock-File .\asa.exe` after verifying the hash.

## Commands

| Command | Purpose |
|---|---|
| `asa collect` | Take a snapshot (all collectors by default; `--collectors files,services,firewall,com,registry` picks some). `--path DIR` (repeatable) sets the file roots (default: system drive), `--exclude DIR` skips directories, `--hash` adds BLAKE3 content hashes, `--no-acls` and `--no-signatures` trade detail for speed. |
| `asa serve [--open]` | Web UI (see above). `--rules FILE` uses custom rules, `--listen ADDR` changes the address. |
| `asa diff BASE COMPARE` | Compare two runs in the terminal or to a file. `--format table\|json\|jsonl\|sarif`, `-o FILE`, `--min-severity LEVEL`, `--rules FILE`. `--fail-on LEVEL` exits with status 1 if a change reaches that level. |
| `asa runs list\|delete ID\|export ID` | Manage runs. `export` dumps a snapshot as JSON lines. |
| `asa procmon import FILE.csv\|list\|delete NAME` | Import a Process Monitor capture so each change shows which process made it. `--name` names the capture. |
| `asa rules check [FILE]` | Validate a rules file and lint it for unknown fields and regexes that can never match. |
| `asa rules default` | Print the built-in rules, as a starting point for your own. |

## What is collected

`asa collect` runs every collector by default (`files, services, firewall, com, registry, users,
certificates, ports, wifi, tasks, defender, rights`); `--collectors files,services,...` picks some.
All collectors read files, the registry and Win32 APIs directly (no PowerShell or WMI), so they are
fast and work offline. Runtime state (running/stopped) is deliberately not collected: it
changes constantly and is not attack surface.

| Kind | Identity | Main fields |
|---|---|---|
| `file` | path | see below |
| `service`, `driver` | service name | `display_name`, `type`, `start`, `delayed_start`, `account`, `image_path`, `binary`, `unquoted_path`, `service_dll`, `failure_command`, `binary_missing`, `binary_signature.*`, `binary_writable_by`, `key_writable_by` |
| `firewall` | `rule\<store>\<id>`, `profile\<store>\<profile>` | rules: `name`, `action`, `direction`, `enabled`, `profiles`, `protocol`, `local_ports`, `remote_ports`, `remote_addresses`, `program`, `service`; profiles: `firewall_enabled`, `default_inbound`, `default_outbound`. Store is `local` or `gpo`. |
| `com` | `clsid\{..}`, `clsid32\{..}`, `user\<sid>\clsid\{..}`, `appid\{..}`, `typelib\{..}` | classes: `name`, `progid`, `inproc_server`, `local_server`, `server`, `server_signature.*`, `server_writable_by`, `elevation`, `shadows_machine`; AppIDs: `local_service`, `run_as`, `dll_surrogate`, `launch_permission`, `access_permission`; type libraries: `versions` |
| `registry` | key path (`HKLM\...`, `HKU\<sid>\...`) | `values.<name>`, `subkeys` (at the depth limit), `writable_by` |
| `user` | `user\<name>` | `sid`, `enabled`, `password_required`, `password_expires`, `password_changeable`, `builtin`, `groups`, `group_sids`, `administrator`, `privileged_groups` (no last-logon or password-age: they change constantly) |
| `group` | `group\<name>` | `sid`, `members`, `member_sids`, `privileged`, `privilege` |
| `certificate` | `cert\<location>\<store>\<thumbprint>` | `location` (group_policy, enterprise, machine, user — most specific origin), `store`, `subject`, `issuer`, `serial`, `not_before`, `not_after`, `self_signed`, `has_private_key` (the key itself is never read), `key_algorithm`, `key_bits`, `signature_algorithm`, `purposes` |
| `port` | `tcp\<address>:<port>`, or `tcp\dynamic\<program>` | `protocol`, `address`, `port`, `scope` (any, loopback, specific), `process`, `services`, `process_signature.*`, `process_writable_by`. Listeners on the dynamic range (49152+) get a new port each boot, so they are grouped per program without the port number; PIDs are never stored. |
| `task` | `task\<task path>` | `path`, `author`, `description`, `enabled`, `hidden`, `run_as` (well-known SIDs as names; absent when it runs as whoever registered it), `run_level` (highest / limited), `logon_type`, `privileged` (SYSTEM, a service account, administrators, or elevated), `triggers` (boot, logon, time, calendar, event, idle, registration, session, ...), `actions`, `binary`, `arguments`, `working_directory`, `com_handler`, `script_host` (cmd, PowerShell, mshta, rundll32, ... where the arguments are what runs), `binary_missing`, `binary_signature.*`, `binary_writable_by`. Parsed from the definitions in `System32\Tasks`; the few that deny administrators are read with backup rights. Run history is left out. |
| `defender` | `defender\exclusion\<source>\<category>\<value>`, `defender\settings` | exclusions: `source` (local / policy), `category` (path, extension, process, ip, asr, cfa_app), `value`, `writable_by` (for an existing path: who can drop unscanned files there); settings: `realtime_protection`, `behavior_monitoring`, `scan_downloads`, `script_scanning`, `disabled_by_policy`, `tamper_protection`, `cloud_protection`, `sample_submission`, `pua_protection`, `controlled_folder_access`, `asr_rules` (rule GUID → off / block / audit / warn). Policy overrides local, as in Defender. |
| `right` | `right\<SeXxx>` | `name`, `description`, `sensitive` (amounts to full control: debug, impersonate, backup/restore, load driver, take ownership, act as OS, ...), `members`, `sids`, `unexpected_members` (holders of a sensitive right other than the built-in ones that normally have it). Every right is listed, held or not, so a first grant is a modification. |
| `wifi` | `wifi\<adapter>\<profile>` | `ssid`, `connection_mode`, `hidden_network`, `authentication`, `encryption`, `uses_802_1x`, `key_type`, `key_protected` (keys are never collected) |

The registry collector covers persistence and policy locations: Run/RunOnce (machine, 32-bit
and every loaded user), Winlogon, Windows (AppInit_DLLs), Image File Execution Options,
SilentProcessExit, Session Manager (BootExecute, KnownDLLs, AppCertDlls), LSA, security
providers, print monitors, network providers, Terminal Server, Active Setup, Browser Helper
Objects, shell extensions, the COM auto-approval list, Policies (machine and user), uninstall
entries, and the top-level vendor keys of `HKLM\SOFTWARE`.

Per file:

| Field | Notes |
|---|---|
| `path`, `file_type`, `size`, `modified`, `target` | `modified` is left out for directories (it changes whenever an entry is added). |
| `hidden`, `system`, `readonly` | File attributes. |
| `owner`, `owner_sid`, `sddl` | Owner and DACL. Rules should match on SIDs, because account names are localized. |
| `writable_by` | Low-privileged principals (Everyone, Users, Authenticated Users, Interactive, Guests, Anonymous, Domain Users) that can write, append, change permissions or take ownership. Inherit-only ACEs are ignored, and deny ACEs are honoured. The same model applies to service binaries, COM servers and registry keys. |
| `executable`, `format` | `pe` (confirmed by the MZ header), `msi` or `script`. |
| `pe.*` | `machine`, `subsystem`, `dll`, `dotnet`, `aslr`, `high_entropy_va`, `dep`, `cfg`, `force_integrity`, `appcontainer`. `aslr` is false when relocations are stripped. |
| `signature.*` | `status` (valid / unsigned / invalid / untrusted / expired / revoked / distrusted), `source` (embedded / catalog), `signer`. Like Windows, a file is valid if either its embedded or a catalog signature verifies. Checks run offline (no revocation lookups). |
| `hash` | With `--hash`. |

## Rules

Rules are YAML. A condition is `all: [...]`, `any: [...]`, `not: {...}`, or a leaf
`{ field: <dotted.path>, <op>: <value> }`.

```yaml
defaults:            # severity when no rule matches
  file: info
rules:
  - name: Unsigned driver
    severity: critical         # debug | info | warning | error | critical
    kinds: [file]
    changes: [created, modified]   # omit = all
    when:
      all:
        - { field: pe.subsystem, eq: native }
        - not: { field: signature.status, eq: valid }
```

Operators: `eq ne in lt le gt ge contains starts_with ends_with regex exists changed`.
A list value for `contains`, `starts_with`, `ends_with` or `regex` means "any of".
`changed: true` matches when that field differs between the two snapshots.
Windows paths are case-insensitive, so start path regexes with `(?i)`.

## Built for large diffs

Collection and reporting are both streamed, so memory does not grow with the number of
files or changes:

- **Collection:** walker threads feed a bounded channel into a batched SQLite writer, and the
  walk slows down when the writer falls behind. Measured: 5.4 M files at ~170 MB peak.
- **Storage:** objects are content-addressed. Each distinct body is stored once, so a repeat
  snapshot mostly costs only its paths.
- **Diff:** a single merge join over both runs compares integer blob ids. Bodies are loaded
  only for objects that differ, one change at a time, then the rules run and the change is
  written out. Measured: 150 000 changes in < 1 s at ~74 MB peak, the same for every output
  format.
- **Output:** the table lists the `--limit` (default 200) most severe changes and counts the
  rest per rule. `jsonl` writes one change per line, ready for `findstr`, `jq` or a SIEM. JSON
  output omits full before/after objects for modified items unless you pass `--objects`
  (the field diffs are always included).

## Differences from the original

- **One static binary, no runtime.** No .NET, no Blazor GUI.
- **Simpler rules.** Nested `all/any/not` trees replace OAT's labelled clauses plus a separate
  boolean expression string. `asa rules check` catches typo'd field names and regexes that can
  never match, both of which the original's built-in rules contained.
- **Catalog-aware signatures and a `writable_by` permission model**, instead of raw ACL dumps.
- **Less noise.** Volatile values like directory mtimes are left out of snapshots.

## Development

The project is developed on Linux and cross-compiled to Windows
(`rustup target add x86_64-pc-windows-gnu`, mingw-w64). `vm/` holds a local Windows 11 test
VM (QEMU/KVM) that is air-gapped by default, like the production workstation:

```bash
vm/vm.sh install            # unattended install from the Windows 11 Enterprise LTSC evaluation ISO
vm/test.sh [--full]         # unit tests on Windows + end-to-end scenario (+ full-drive benchmark)
vm/features.sh              # every feature: attack scenario for the default rules, CLI, API, web UI
                            # (Edge driven over DevTools), bundle, regressions -> feature-report.md
vm/procmon-test.sh PROCMON64.EXE   # real Procmon capture -> attribution, notices, tree (API + Edge)
vm/acceptance-chrome.sh     # replay a Chrome install on the 'clean' checkpoint and check every
                            # service/firewall/COM/registry change PowerShell sees is reported
vm/vm.sh run SCRIPT.ps1     # run a script in a visible window on the VM desktop
vm/vm.sh ssh                # PowerShell in the VM (background session)
vm/vm.sh tunnel 8740        # reach `asa serve` running in the VM
vm/vm.sh checkpoint NAME / restore NAME
```

Test runs happen in visible PowerShell windows on the VM desktop, so you can follow them on
VNC (`127.0.0.1:5955`). `vm.sh run` also records a transcript and returns the script's
exit status, so scripts stay automatable.

Measured in the VM (fresh Windows 11, all collectors): about 142,700 objects in roughly 92 s.
A diff between two idle snapshots shows nothing at warning level. The Chrome acceptance test
detects all 58 ground-truth changes (3 services, 1 firewall rule, 8 COM classes, 7 AppIDs,
36 type libraries, 1 scheduled task, the vendor key and the uninstall entry). It also catches
Chrome's Active Setup hook, and it does not report the services the installer merely
started.

## Live monitoring

asa compares snapshots: it tells you *what* changed and whether it matters. To also see
*which process* made each change, run Sysinternals Process Monitor (`Procmon64.exe`, a
single signed binary that works offline) between the two snapshots, and import its trace:

```powershell
asa collect --run-id before
Procmon64.exe /AcceptEula /Quiet /Minimized /BackingFile C:\trace.pml
# ... install ...
Procmon64.exe /Terminate
Procmon64.exe /OpenLog C:\trace.pml /SaveAs C:\trace.csv
asa collect --run-id after
asa procmon import C:\trace.csv
asa serve --open
```

The import keeps only events that modify something (successful writes, creates,
deletes, renames, security changes and registry value or key changes). Repeated events are
folded into one per process, operation and path, so a multi-gigabyte trace becomes a small
table. File I/O by `System` is dropped: that is the cache manager flushing other
processes' writes. Changes are then matched to events on their file, or on the registry
key behind the object (services, firewall rules and profiles, COM classes, AppIDs and type
libraries, certificates, registry keys). Users, groups, Wi-Fi profiles and ports cannot be
attributed this way.

In the web UI each row says who changed it ("by msiexec.exe"), the *Modified by* facet
counts changes per process, the detail panel lists the events, and `modified_by` works in
queries. Some changes are made by a service on the caller's behalf. In the test VM, `sc
create` shows up as `services.exe` and `netsh advfirewall` as `svchost.exe`, which is what
really wrote them.

## Roadmap

WMI event subscriptions, security options (UAC, WDigest, SMBv1, NTLM levels) as one
object, triage (mark findings reviewed or accepted), TPM and key-storage inventory, and
custom registry locations from the command line.

## License

MIT. The default rules are adapted from the original project's `analyses.json`
(© Microsoft Corporation, MIT).
