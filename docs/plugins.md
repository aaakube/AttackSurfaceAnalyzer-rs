# Analyzer plugins

asa produces a diff first — every change materialized into a comparison you can read,
filter and export the moment it finishes. **Analyzers** are a second, separate phase:
passes that run *over the diff that already exists* and add findings. They never block
the diff, and they never touch the live machine — they read the snapshot asa already
captured, so they are offline, deterministic, and safe to re-run against old
comparisons. (This is the same shape as Procmon attribution, which has always run as a
lazy pass after the diff.)

Because an analyzer is just data over the captured snapshot, you can add
technology-specific checks for a product you are assessing **without rebuilding asa** —
drop a YAML file next to the others on the machine.

## Running them

Analyzers run automatically the first time you open a comparison's results in
`asa serve`, and their findings appear in the normal severity list and facets. Each
analyzer runs once per comparison (recorded in the `analysis` table) and is skipped
cheaply afterwards.

```
asa serve --plugins C:\asa\plugins
```

The built-in analyzers are compiled into the binary, so the default behaviour needs no
files. `--plugins` adds every `*.yaml` in that directory on top. `GET /api/analysis?c=<id>`
reports which analyzers exist and which have finished.

## Writing one

An analyzer is a small manifest: a name and a list of checks. Each check is a boolean
SQL expression (`match`) evaluated against **one result row** of the comparison. Rows the
expression matches become findings under the check's `rule` and `severity`.

```yaml
name: service-escalation
description: Services a standard user can take over.
checks:
  - rule: service-reconfigurable-by-standard-user
    severity: critical        # debug | info | warning | error | critical
    description: A standard user can change this service's binary path.
    match: >
      kind = 'service'
      AND json_array_length(json_extract(obj, '$.reconfigurable_by')) > 0
```

Inside `match` these columns are in scope:

| column     | meaning                                                            |
|------------|-------------------------------------------------------------------|
| `kind`     | the object kind (`service`, `com`, `file`, `handler`, …)           |
| `identity` | the object's identity (path, CLSID, service name, …)              |
| `change`   | `added`, `modified` or `removed`                                  |
| `obj`      | the captured object as JSON — read fields with `json_extract(obj, '$.field')` |

`obj` is the *compare* version of the object, falling back to the *base* version for
removals. The field names are whatever the collector recorded; see
[collectors.md](collectors.md) (for example services expose `account`,
`reconfigurable_by`, `startable_by`, `binary_writable_by`; files expose `signature`,
`writable_by`, `pe.cfg`). Arrays like `writable_by` are JSON arrays — test them with
`json_array_length(json_extract(obj, '$.writable_by')) > 0`, and test membership with
`EXISTS (SELECT 1 FROM json_each(obj, '$.writable_by') WHERE value = 'Users')`.

## What analyzers are for (vs. rules)

- **Rules** (`rules/default.yaml`) fire per object *during* the diff, on that object's own
  fields. Use them for "this single object looks wrong".
- **Analyzers** run *after* the diff, with full SQL over the whole comparison — joins,
  aggregation, cross-object relationships. Use them for things a per-object rule cannot
  express, and for **technology-specific** bundles you add per assessment (for example
  the `activex-exploitability` analyzer, which flags a safe-for-scripting ActiveX control
  with no kill-bit — the check that was run by hand during the VLC assessment).

## Trust and the sandbox

A `match` expression is SQL you write, so an analyzer is *trusted code you place
deliberately*, like the rules file. The sandbox keeps a buggy or hostile one contained:

- the expression is spliced only into the `WHERE` of a single prepared `SELECT`;
- the statement is rejected unless SQLite reports it **read-only**;
- the database connection has no extension loading or file-access functions;
- a predicate containing `;`, `--` or `/*` is refused at load.

The worst a bad analyzer can do is match nothing, raise a finding a human then dismisses,
or run a slow query — never write the database, the machine, or the network. That
containment is exactly why analyzers are SQL over the snapshot rather than arbitrary
scripts (PowerShell, executables) run against the live system: on a
high-value workstation, a plugin that can only *read captured data* is the safe shape.
