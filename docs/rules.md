# Rules

Rules decide the severity of each change. asa ships with built-in rules for each platform:
`rules/default.yaml` (Windows, 170 rules) and `rules/linux.yaml` (Linux). The set for the
platform asa runs on is used by default, and `asa rules default` prints it. Pass your own
file with `--rules FILE` to `diff` or `serve`, for example `--rules rules/linux.yaml` to
review Linux snapshots on another machine.

## Format

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

- **Operators:** `eq ne in lt le gt ge contains starts_with ends_with regex exists changed`.
- **Lists:** a list value for `contains`, `starts_with`, `ends_with` or `regex` means "any of".
- **`changed: true`** matches when that field differs between the two snapshots.
- **Paths:** Windows paths are case-insensitive, so start path regexes with `(?i)`.
- **Fields:** see [collectors](collectors.md).

## Checking a rules file

```powershell
asa rules check my-rules.yaml
```

This validates the file and lints it for unknown field names and regexes that can never
match. Both mistakes are silent otherwise: the rule just never fires.
