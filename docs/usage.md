# Usage

Run asa from an **elevated** PowerShell: many ACLs and protected files can't be read
otherwise. Everything is stored in `.\asa.db` (use `--db PATH` or the `ASA_DB` variable to
change it).

```powershell
.\asa.exe collect --run-id before
# ... install / change something ...
.\asa.exe collect --run-id after
.\asa.exe serve --open
.\asa.exe diff before after
```

## Commands

| Command | Purpose |
|---|---|
| `asa collect` | Take a snapshot. All collectors run by default; `--collectors files,services,...` picks some (see [collectors](collectors.md)). `--path DIR` (repeatable) sets the file roots (default: system drive), `--exclude DIR` skips directories, `--hash` adds BLAKE3 content hashes, `--no-acls` and `--no-signatures` trade detail for speed. `--registry-key KEY[:DEPTH]` adds registry locations, `--no-default-registry` collects only those. |
| `asa serve [--open]` | Web UI. `--rules FILE` uses custom rules, `--listen ADDR` changes the address. |
| `asa diff BASE COMPARE` | Compare two runs. `--format table\|json\|jsonl\|sarif`, `-o FILE`, `--min-severity LEVEL`, `--rules FILE`, `--include-accepted`. `--fail-on LEVEL` exits with status 1 if a change reaches that level. |
| `asa runs list\|delete ID\|export ID` | Manage runs. `export` dumps a snapshot as JSON lines. |
| `asa procmon import FILE.csv\|list\|delete NAME` | Import a Process Monitor capture (see [procmon](procmon.md)). |
| `asa triage list\|clear` | List triage decisions, or clear them (`--kind`, `--identity`). |
| `asa rules check [FILE]` | Validate a rules file (see [rules](rules.md)). |
| `asa rules default` | Print the built-in rules. |

The terminal table lists the `--limit` (default 200) most severe changes and counts the rest
per rule. `jsonl` writes one change per line, ready for `findstr`, `jq` or a SIEM. JSON output
omits full before/after objects for modified items unless you pass `--objects` (field diffs
are always included).

## Web UI

`asa serve` starts a web UI on `http://127.0.0.1:8740/`. It listens on loopback only and
loads nothing from the internet.

- **Compare:** pick two runs and press *Compare*. The comparison is computed once and stored,
  so filtering, sorting and paging stay instant even with hundreds of thousands of changes.
- **List or tree:** results show as a sortable list, or as a tree of their paths with change
  counts per folder. Folders open one level at a time, and chains of single folders collapse
  into one row.
- **Coverage notices:** if a run did not finish, a collector failed, a kind was collected in
  only one of the two runs, or collection hit access-denied warnings, the comparison says so
  above the results (`asa diff` prints the same notes). A missing change is never taken for
  "nothing changed".
- **Browse run:** query the objects of a single snapshot, for example every unsigned PE.
- **Detail panel:** findings with explanations, a before/after table of changed fields, the
  Procmon events behind the change, and the full object. Click any field to add it to the
  query.
- **Facets and cards** (severity, kind, change type, rule, modifying process, triage) count what
  matches the current query. Clicking one toggles its term. Picking another kind, change type
  or severity replaces the current one, and those three are counted without their own term so
  the alternatives stay visible.
- **Export:** JSONL or CSV of everything matching the query.
- **The URL keeps the state** (query, comparison, selected item), so a bookmark reopens a
  finding exactly.

## Triage

In a change's detail, *Mark reviewed* or *Accept* it, with a note. A decision covers that
object in that exact state (its content hash): it carries over to every comparison showing the
same change and lapses as soon as the object changes again.

Accepted changes are hidden unless you untick *Hide accepted*. The *Triage* facet and the
`triage` query field (`triage = accepted`, `triage missing`) filter on it. `asa diff` leaves
accepted changes out too (`--include-accepted` shows them).

## Query language

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

- **Operators:** `=` `!=` `<` `<=` `>` `>=`, `~` (regex, case-insensitive), `has` (substring, or
  an item of a list), `exists`, `missing`, `changed` (the field differs between the two
  snapshots).
- **Combining:** `and`, `or`, `not` and parentheses; adjacent terms are and-ed.
- **Strings** ignore case and take no escapes, so write Windows paths as-is. To include a
  quote, delimit the string with the other kind of quote.
- **Fields:** `path`, `kind`, `change`, `severity`, `rule`, `modified_by`, `triage`, plus any
  object field from [collectors](collectors.md), with dots for nested ones
  (`signature.status`, `pe.cfg`).
