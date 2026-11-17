# Worked example: assessing two thick clients with asa

Two small product security assessments driven by asa, kept as a worked example of the
workflow in [usage](usage.md): **LibreOffice 26.8.3** and **VLC 3.0.24**, each installed
from its MSI on a clean Windows 11 24H2 VM. Neither is an audit of the product — the
point is the method (snapshot, install, diff, then spend the testing effort where the
diff points) and how the *same* method surfaces *different* attack surface in two
different thick clients.

Jump to: [LibreOffice](#libreoffice-2683) · [VLC](#vlc-3024) · [side by side](#the-two-side-by-side).

## LibreOffice 26.8.3

The target is LibreOffice 26.8.3 (the 64-bit MSI). It is not a LibreOffice audit — the
point is the method: snapshot, install, diff, then spend the testing effort where the
diff points.

> Scope: a single `clean → installed` transition, machine-wide, all collectors, plus
> manual checks for the things asa does not collect (service DACLs before they were a
> collector, IPC, component versions). No dynamic instrumentation (Process Monitor was
> not available on the test box) and no fuzzing. Findings are from configuration and
> static evidence; the one item that needs dynamic analysis is called out as untested.

## Method

```powershell
asa collect --run-id before
msiexec /i LibreOffice_26.8.3_Win_x86-64.msi /qn
asa collect --run-id after
asa diff before after --format jsonl -o diff.jsonl
asa serve --open
```

The install produced **15,347 changes**. Marking the understood background noise
(Windows telemetry, fonts, help files) as accepted in the web UI left a short findings
list, which the sections below work through. Each was then confirmed by hand.

## Findings

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | SYSTEM maintenance service any user can start | Medium | Confirmed; residual update-path risk untested |
| 2 | One-click and zero-click document parsing paths registered | Medium | Confirmed (by design) |
| 3 | No Control Flow Guard on any shipped binary | Low–Medium | Confirmed |
| 4 | Bundled third-party libraries (OpenSSL, curl, NSS, …) | Informational | All current at release |
| 5 | 15 unsigned helper executables | Low | Confirmed, low reachability |

No new listening ports and no firewall rules were added, at install time or after — no
remote attack surface is introduced.

### 1. SYSTEM maintenance service a standard user can start

`asa diff` reported a new service, which the service collector now annotates directly:

```
service  LibreOfficeMaintenance
  account            LocalSystem
  binary             C:\Program Files\LibreOffice\program\update_service.exe  (signed, The Document Foundation)
  startable_by       Interactive          <- any logged-on user
  reconfigurable_by  (none)
```

`updater.ini` identifies this as the **Mozilla maintenance service** architecture
(MPL 2.0, "MozillaMaintenanceDescription"): a SYSTEM service a normal user can invoke so
updates apply without a UAC prompt. The installer deliberately widens the service DACL to
grant `INTERACTIVE` start (`maintenanceservice-install.log`: "User access was set
successfully on the service").

**Checked and safe:**
- The install folder and `update_service.exe` are **not** user-writable
  (`BUILTIN\Users:(RX)` only) — no DLL planting or binary replacement.
- `reconfigurable_by` is empty — a user cannot repoint the service binary.
- All update binaries (`update_service.exe`, `updater.exe`, `unopkg.exe`) are validly
  signed by The Document Foundation.

**Residual risk (untested):** the whole security of this design rests on how
`update_service.exe` validates the update package (a MAR file) and the staging directory
before running `updater.exe` as SYSTEM. The Mozilla updater this is derived from has had
privilege-escalation CVEs in exactly that area (staging-directory ACLs, path handling,
TOCTOU on the update directory). Confirming it needs dynamic analysis: run Process
Monitor while a standard user starts the service, find the staging directory, and test
whether a user-supplied package or a planted DLL in that directory is executed before its
signature is checked. That was out of scope here (no Procmon on the test box).

**Recommendation:** if LibreOffice updates are deployed some other way, the service is pure
attack surface. Install without it, or disable it:
`sc.exe config LibreOfficeMaintenance start= disabled`. The MSI also supports omitting the
online-update feature.

### 2. Document-parsing launch paths

Opening an attacker's file is the realistic entry point for a desktop office suite. The
install registers several:

- **URL handler** `vnd.libreoffice.command → soffice.exe "%1"` (asa's new `handler`
  collector). A link can launch LibreOffice with a controlled argument. It also declares
  handlers for `ms-word:`/`ms-excel:`/`ms-powerpoint:`/`ms-visio:`, effective only if it
  becomes the default for them.
- **Windows Search IFilter** `ooofilt.dll` for `.odt/.ods/.odp`: the indexer parses ODF
  files dropped in an indexed folder with **no click**. It runs in Windows' isolated
  filter host, which limits impact.
- **Five Explorer shell extensions** (infotip, thumbnail, property, property-sheet,
  column) that parse ODF files when a folder is merely browsed.

All are validly signed and their handler keys are not user-writable (asa's handler rules
would flag it otherwise), so they cannot be hijacked. They are legitimate functionality,
but they define the parsers worth fuzzing in a deeper engagement: `soffice.bin`, the ODF
import filters, `ooofilt.dll`, and the thumbnail provider.

### 3. Missing exploit mitigations

Of the parsers above, mitigation coverage is thin:

- **Control Flow Guard: absent on all 192 shipped binaries**, including `soffice.bin`
  (parses untrusted documents) and the SYSTEM `update_service.exe`.
- **ASLR:** present everywhere except `libpq.dll` (PostgreSQL client, loaded only when
  Base connects to PostgreSQL).
- DEP and high-entropy ASLR are on.

CFG is not a vulnerability by itself, but its absence means a memory-corruption bug in the
document parsers is more readily exploitable. This raises the priority of fuzzing finding #2.

### 4. Bundled third-party libraries

LibreOffice ships its own copies of several security-sensitive libraries. At the time of
this release each was the **current, fully patched** version — good hygiene:

| Component | Bundled | Status |
|---|---|---|
| OpenSSL | 3.5.9 | Latest 3.5 LTS; fixes 14 CVEs (2026-09-29 advisory) |
| curl / libcurl | 8.23.0 | Latest; fixes CVE-2026-92392 (HTTP/2 UAF, High), 2026-10-14 |
| libxml2 | 2.15.4 | Latest; fixes 9 CVEs (2026-09-01) |
| NSS | 3.133 | Recent; no known unpatched exposure found |
| Python (full runtime + pip) | 3.13.18 | Latest security release (2026-10-25) |
| PostgreSQL client (libpq) | 15.19 | Not individually verified; low exposure (Base→PostgreSQL only) |
| ICU | 78 | Recent |

**The risk is time, not the current state.** Because these are bundled, the machine is only
as patched as its LibreOffice build,
so these libraries go stale while new CVEs land upstream. This is the same fact as finding
#1 from the other side: the update service exists to fix exactly this. Otherwise,
track LibreOffice releases out-of-band and re-image on a schedule; re-run this
same `asa diff` against each new version to review only what changed.

### 5. Unsigned helper executables

15 unsigned PE files ship in the bundle: 14 are pip/setuptools launcher stubs under
`python-core-3.13.18\lib\…` (templates, not run in normal use) and one is
`program\intl\fbintl.dll`. Low reachability; worth asking the vendor why they ship
unsigned, as it weakens any "all code is signed" allow-listing policy.

## VLC 3.0.24

Same method, a different thick client: VLC 3.0.24 (64-bit MSI, `msiexec /qn`). The install
produced **972 file changes**, 2 COM registrations, 2 registry changes and no new service.
Where LibreOffice's risk was a local privilege boundary, VLC's is **remote** — it exposes
its media parsers to the browser.

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Browser-scriptable ActiveX control over the media engine | Medium–High | Confirmed |
| 2 | No Control Flow Guard on any of 365 binaries | Medium | Confirmed |
| 3 | 113 media file associations → one-click parser entry | Low–Medium | Confirmed (by design) |
| 4 | No new service, no new listeners, install dir not user-writable | — | Confirmed clean |

### 1. Browser-scriptable ActiveX control

asa's COM collector reported two new classes, both served by `axvlc.dll` (validly signed by
VideoLAN): "VLC ActiveX Plugin and IE Web Plugin" v1 and v2. A manual look at each CLSID's
`Implemented Categories` shows both are marked **Safe for Scripting** and **Safe for
Initialization**, with **no kill-bit** set:

```
CLSID {9BE31822-…} / {E23FE9C6-…}  (axvlc.dll, signed)
  category: SAFE FOR SCRIPTING
  category: SAFE FOR INITIALIZATION
  kill-bit: not set
```

That combination means any web page rendered in a legacy ActiveX host — Internet Explorer,
Edge's IE mode, or any application embedding the WebBrowser/MSHTML control — can instantiate
VLC's control, hand it a media URL or data, and script it, reaching VLC's demuxers and
decoders remotely. VLC's ActiveX plugin has a history of memory-corruption CVEs, and (finding
#2) none of VLC's binaries have CFG, so a parser bug reached this way is more readily
exploitable. **Recommendation:** if IE-mode is in use anywhere, set the kill-bit for these
CLSIDs by policy, or install VLC without the ActiveX plugin feature (the MSI exposes it).

### 2. No Control Flow Guard

All **365** of VLC's PE binaries lack CFG, including the demuxers and codecs whose entire job
is parsing untrusted media. Only `vlc-cache-gen.exe` also lacks ASLR; DEP and ASLR are
otherwise on. For a media player this is the central mitigation gap — it governs the
exploitability of every finding above.

### 3. File associations and clean negatives

VLC registers **113** media file associations (`VLC.mkv.Document`, `.mp4`, … →
`vlc.exe … "%1"`), so double-clicking or drive-by-downloading a crafted media file opens
VLC's parser — the one-click counterpart to the ActiveX path. The handler collector found
**no** URL protocol handler (VLC registers file types, not a `scheme:`), and the service
collector found **no** new service — both true negatives worth recording. The install
directory is not user-writable (`Users:(RX)`), so there is no binary-planting surface.
No new listening ports or firewall rules were added.

## The two side by side

The same three-command workflow surfaced two different risk profiles:

| | LibreOffice 26.8.3 | VLC 3.0.24 |
|---|---|---|
| Headline surface | **local**: SYSTEM service any user can start | **remote**: browser-scriptable ActiveX control |
| New service | `LibreOfficeMaintenance` (SYSTEM, user-startable) | none |
| Browser surface | — | `axvlc.dll`, safe-for-scripting, no kill-bit |
| Entry via a file | shell extensions + URL handler | 113 file associations |
| CFG coverage | 0 / 192 binaries | 0 / 365 binaries |
| Install dir writable by users | no | no |
| New trusted roots (Windows root-update) | 2 (Certum) | 2 (USERTrust, DigiCert) |
| New listeners / firewall rules | none | none |

The trusted-root rows are the same Windows behaviour seen from two vendors: verifying either
signed installer made Windows pull roots from its automatic-root-update program into
`AuthRoot`/`Root`. asa reports them as critical; distinguishing them from software-added roots
is on the [roadmap](roadmap.md).

## What asa could not answer

An honest assessment names its blind spots. Other tools are still needed for: the dynamic
behaviour of LibreOffice's update service (its residual risk), IPC surfaces (named pipes /
LPC), fuzzing the document and media parsers, and code review. asa maps the attack surface
and ranks where to look; it does not prove exploitability.

Each target also exposed a gap in asa itself, which is part of why they are kept here:

- LibreOffice → the service collector now records `startable_by`/`reconfigurable_by`, and a
  `handler` collector now covers URL protocol handlers (both produced findings the first pass
  missed).
- VLC → the COM collector sees the ActiveX class but not its **safety flags** (safe-for-
  scripting / -initialization) or **kill-bit**, which decide whether a web page can script it.
  Recording those on COM objects is the natural next collector enhancement (on the
  [roadmap](roadmap.md)); here it was a manual registry check.

## Reproducing

Both assessments are reproducible with the commands in [Method](#method) against each MSI,
plus the manual checks quoted in the findings (`sc.exe sdshow`, `icacls`, and the ActiveX
`Implemented Categories` / kill-bit registry reads). The bundled-component versions come from
each DLL's `ProductVersion`; the CVE status from the upstream advisories current at the
release date. VLC installs cleanly only from its MSI under `msiexec /qn`; its NSIS `.exe`
returns before its elevated child finishes writing, which splits the install across the two
snapshots.
