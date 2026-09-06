# Output contract

ProcSentinel-C provides human-readable console output and JSON intended for analyst tooling and lab automation.

## Version 1 behavior

The `file` and `pid` commands emit one JSON object when `--json` is supplied. `scan --json` emits an array of process objects.

The v1 JSON output is intentionally compact and has no external schema dependency.

## File object

Key fields include:

- `path` — UTF-8 executable path
- `sha256` — lowercase SHA-256 hex when available
- `signature` — `trusted`, `unsigned`, `invalid`, or `unknown`
- `score` — integer from 0 through 100
- `pe.valid` — whether a valid PE image was parsed
- `pe.is_64bit` — PE32+ flag
- `pe.machine` — numeric COFF machine field
- `pe.entry_rva` — entry-point RVA
- `pe.sections[]` — bounded section metadata
- `pe.findings` — explainable Boolean/count signals

## Process object

A detailed `pid --json` object includes:

- `pid`
- `parent_pid`
- `image`
- `path`
- `user`
- `integrity`
- `architecture`
- `accessible`
- `file`
- `tcp[]`

Each TCP item contains a state plus local/remote endpoint strings.

## Scan output

`scan --quick --json` is an inventory representation containing PID, PPID and image name only.

`scan --json` adds path, score and accessibility information while keeping the system-wide output compact.

## Compatibility

The project follows these rules for future releases:

1. Existing field meanings should not silently change within a major version.
2. New fields may be added in minor versions.
3. A future schema-version field will be introduced before incompatible structural changes.
4. Inaccessible or unavailable values should be represented explicitly rather than fabricated.

## UTF-8 and escaping

Wide Windows paths and account names are converted to UTF-8. JSON strings are escaped for quotes, backslashes and control characters.
