# Seeing which process made a change

asa compares snapshots: it tells you *what* changed and whether it matters. To also see
*which process* made each change, run Sysinternals Process Monitor (`Procmon64.exe`, a single
signed binary that works offline) between the two snapshots and import its trace:

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

## What is kept

The import keeps only events that modify something: successful writes, creates, deletes,
renames, security changes, and registry value or key changes. Repeated events are folded into
one per process, operation and path, so a multi-gigabyte trace becomes a small table.

File I/O by `System` is dropped: that is the cache manager flushing other processes' writes.

## How changes are matched

Changes are matched to events on their file, or on the registry key behind the object:
services, firewall rules and profiles, COM classes, AppIDs, type libraries, certificates,
registry keys, scheduled tasks, Defender settings and security options. Users, groups, Wi-Fi
profiles and ports cannot be attributed this way.

In the web UI, each row says who changed it ("by msiexec.exe"), the *Modified by* facet counts
changes per process, the detail panel lists the events, and `modified_by` works in queries.

Some changes are made by a service on the caller's behalf: `sc create` shows up as
`services.exe` and `netsh advfirewall` as `svchost.exe`, which is what really wrote them.

## Managing captures

```powershell
asa procmon list
asa procmon delete NAME
asa procmon import FILE.csv --name install-v2
```
