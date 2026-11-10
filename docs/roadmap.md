# asa roadmap

Two lists: improvements to what asa already does (no new features), then ideas for
new capabilities that would help a security assessor. Each entry says why it matters
and what it would take. Nothing here is scheduled yet.

## Part 1: improvements without new features

### 1. Performance at real scale *(highest priority)*

Several recent features have only been tested on small comparisons, not at the
100,000+ changes a real workstation produces:

- **Hide accepted.** Every list, facet, tree and export query recomputes each row's
  triage state with a correlated subquery (content hash → triage table).
- **Facet counts.** Kind, change and severity are each counted without their own
  term, so one refresh can send up to four facet requests, each running several
  `GROUP BY`s.
- **Procmon attribution.** The first time a comparison is opened, every result is
  matched against the capture with one index lookup per source path.

**Plan:** benchmark all three on the 150k-change test database (`big.db`). Likely
fixes:

- store the triage state key on each result row when the comparison is built, so
  hiding becomes a plain join;
- compute all facets in one request;
- match Procmon events with a single join instead of a lookup per result.

### 2. Robustness *(highest priority)*

- **Collector crashes.** A crash in one collector currently aborts the whole run.
  Catch it, record the collector as failed (the coverage notices already explain
  that to the reader), and let the others finish.
- **Database permissions.** `asa.db` is a detailed map of the machine's weaknesses:
  writable service binaries, Defender exclusions, WMI script text, user rights. On
  Windows, create it readable only by Administrators and SYSTEM, and warn when an
  existing database is more open than that.
- **Field size caps.** Cap unusually large fields (WMI script text, command lines,
  registry values) so one odd object can't bloat the database or the UI.

### 3. Code health

- **Duplicated code.**
  - "Resolve the program, check its signature and who can overwrite it" is repeated
    in five collectors (services, COM, tasks, WMI, ports); factor it into one helper.
  - The registry number-reading helper exists twice (Defender, security options).
  - Test fixtures such as signatures and fake registries are rebuilt in many tests.
- **Schema migrations.** Additive `ALTER TABLE … if missing` blocks are spread
  through `Store::open`. Replace them with one ordered, versioned migration list.
- **Web layer.**
  - Split SQL building out of the HTTP handlers in `web.rs`.
  - Split `index.html`'s script into modules (state, query editing, list, tree,
    detail), still served offline from the binary.

### 4. Faster, broader tests

- **API tests on Linux.** Most API checks don't need Windows: run them in seconds
  against a synthetic database, instead of only in the hour-long Windows suite.
- **JS unit tests.** The query-editing logic (toggling, replacing, and parenthesising
  an `or` query) was tested with throwaway Node scripts and never committed. Commit
  them and run them with `cargo test` or a small script.
- **CI.** *Done:* fmt, clippy (Linux and Windows targets), unit tests on Linux and
  Windows, and the release zip as a downloadable artifact on every push.

### 5. Rule quality on a busy machine

So far, false positives have only been measured on a clean Windows install with Chrome.
Take a few days of snapshots from a machine with real-world churn (Windows Update,
Office, drivers, Defender platform updates) and tune the rules that cry wolf. Keep
the idle-diff check: an untouched machine must show nothing at warning level.

### 6. Web UI accessibility

Facets, severity cards and tree nodes are clickable `div`s, so they can't be reached
with the keyboard. Make them real buttons with visible focus, add arrow-key
navigation in the tree, and make long paths wrap or truncate sensibly in narrow
panels.

### 7. Documentation

The README has grown long. Split it into a short README (what it is, quick start)
plus pages for the collectors, the rules and query language, and the web UI.

### 8. Trustworthy releases

- Sign `asa.exe` (Authenticode).
- Stamp the version and git commit into `asa --version`.
- Make the build reproducible, so the release can be checked byte for byte against
  what the test suite verified.

This matters most on an air-gapped workstation, where the bundle arrives by hand.

## Part 2: ideas for security assessors

### 1. Privilege-escalation paths

asa already knows, for every privileged thing that runs code (services, tasks, WMI
consumers, COM servers, listeners), who can write its binary, its folder and its
registry key. Chain those facts into paths a standard user could take, for example:

```text
Users can write C:\Tools  →  C:\Tools is in the system PATH
                          →  service X (LocalSystem) loads foo.dll by bare name
```

Show each path with its steps and evidence. Rank paths by the account they end in
and how few steps they take.

### 2. Phantom DLL hijacking from a Procmon capture

A Procmon trace already records every `CreateFile … NAME NOT FOUND` on `.dll` paths.
Do this:

1. Keep the misses made by privileged processes.
2. Keep only those whose directory a non-admin can write to.
3. Report each as a DLL-planting opportunity: the process, the DLL name, the
   writable folder, and who can write there.

This finds hijacks that static analysis misses. It reuses `asa procmon import` and
the existing permission checks.

### 3. Secrets left on disk and in configuration

Scan what asa already collects, plus a few known files, for credentials:

- `AutoAdminLogon` with `DefaultPassword`;
- passwords in scheduled-task arguments, service command lines and WMI consumer
  scripts;
- leftover `unattend.xml`, `sysprep.inf` and Group Policy Preferences
  `cpassword` files;
- Wi-Fi keys stored unprotected (already detected).

Report where each secret is and who can read it. Never store the secret itself.

### 4. Code-execution trust inventory

One view answering "whose code runs with high privileges on this machine?". Group
every binary run as SYSTEM, a service account, or elevated, by signer:

- Microsoft;
- each third-party vendor;
- unsigned;
- invalid signature.

For each group, list how the binaries get started (service, task, driver, WMI, COM,
Run key). Assessors use this to argue for removing vendors or for an allow-list
policy.

### 5. Remote attack surface view

Join the data asa already has: listening sockets and their scope, the firewall rules
and profiles that allow them, the owning program's signature and permissions, and
the account it runs as. Show what is actually reachable from the network:

> port 8080 on all interfaces → allowed inbound on Public → unsigned, Users-writable
> program → runs as LocalSystem

### 6. Machine-to-machine comparison

Compare a workstation against a reference "golden" machine instead of against its
own past. Identities that legitimately differ between machines (user SIDs,
per-machine GUIDs, computer names) need normalizing first. This answers "how does
this box deviate from the hardened build?", which helps when no "before" snapshot
exists.

### 7. MITRE ATT&CK mapping and report-ready evidence

- Tag each rule with ATT&CK technique IDs, for example T1053.005 for scheduled
  tasks, T1546.003 for WMI subscriptions, and T1562.001 for Defender exclusions.
- Group findings by tactic.
- Export an evidence pack for the report: the findings, before/after values, the
  Procmon events behind each change, the run metadata, and SHA-256 hashes of the
  runs. The pack should be self-contained and suitable for pasting into an
  assessment report.

### 8. A "standard user's view" run

Run collection a second time as a non-administrator, and compare what that user can
read and change with the administrator's run. The difference is concrete:

- which secrets a standard user can read;
- which privileged configuration they can modify;
- which collectors give them a blind spot.

The result is evidence in the attacker's own terms rather than inferred from
ACLs.

### 9. Change attribution to installers and updates

Group the changes in a comparison by the installation that caused them. Use the
signer, the vendor folder, the uninstall entry created at the same time, and the
Procmon process tree when a capture exists. The comparison then reads as "Chrome
installer: 3 services, 1 firewall rule, 36 type libraries" instead of 150 separate
rows, and anything left over is what deserves a closer look.

### 10. Hardening scorecard from the security options

Turn the `security`, `defender`, `rights`, `tpm` and `firewall` data into a short
scorecard against a chosen baseline: Microsoft's security baseline or a CIS
benchmark level, shipped as a rules file. Show pass/fail per setting with the
evidence value, and track it across runs. That gives a quick hardening picture even
with a single snapshot, and shows whether a change made it better or worse.

### 11. Run asa and import data from the web UI

Today the web UI only reads: you collect and import Procmon captures from a
terminal. Make the UI the single place to work:

- **Import a Procmon CSV by upload** *(the minimum)*. Drop a file on the page and see
  how many changes were kept. Captures can be gigabytes, so the upload must stream
  to disk and into the existing importer. Captures can also be listed and deleted
  from the UI.
- **Start a collection** with a chosen run ID, set of collectors, file paths and extra
  registry keys. Show live progress per collector, reusing the comparison progress
  card. When it finishes, offer to compare the new run with the previous one.
- **Manage runs:** delete, export as JSON lines.

Constraints:

- Collection needs an elevated `asa serve`. The UI must say so, rather than
  silently producing a partial run.
- Every action is a write, so it goes through the existing CSRF guard (the `X-Asa`
  header and the Origin check). The server stays on loopback.
- Only one collection runs at a time.

This is not a one-shot "snapshot, install, snapshot" wrapper: each step stays
separate and explicit.

