# Architecture

ProcSentinel-C separates collection, parsing, scoring and presentation so that detection logic can evolve without coupling it to the CLI.

```text
                  +----------------------+
                  |       CLI / JSON     |
                  +----------+-----------+
                             |
             +---------------+----------------+
             |                                |
     +-------v--------+               +-------v--------+
     | Process triage |               |   File triage  |
     +-------+--------+               +-------+--------+
             |                                |
   +---------+----------+           +---------+----------+
   | Win32 process data |           | PE parser           |
   | token metadata     |           | Authenticode        |
   | TCP owner table    |           | SHA-256             |
   +---------+----------+           +---------+----------+
             |                                |
             +---------------+----------------+
                             |
                    +--------v--------+
                    |  Scoring engine |
                    +-----------------+
```

## Modules

- `process.c` — read-only process metadata and token inspection
- `network.c` — IPv4 TCP ownership through `GetExtendedTcpTable`
- `pe.c` — bounded PE32/PE32+ parsing and import extraction
- `sha256.c` — SHA-256 using Windows CNG
- `signature.c` — cache-only Authenticode verification
- `scoring.c` — deterministic triage score
- `report.c` — console and JSON presentation

## Data flow

A deep endpoint scan takes one Toolhelp process snapshot, attempts limited-information access to each process, reuses file-analysis results for repeated executable paths, and then correlates one TCP owner-table snapshot across the resulting process records.

This reduces repeated hashing, signature verification and PE parsing when the same executable has multiple running instances.

## Design choices

### No process-memory inspection in v1

The first release intentionally avoids reading or modifying remote process memory. This keeps the security boundary narrow and makes the project useful as a file/process triage tool without becoming an injection or memory-manipulation framework.

### Offline signature verification

`WinVerifyTrust` uses cache-only retrieval. A host without required revocation/certificate data may therefore return `unknown`; the tool prefers uncertainty over unexpected network access.

### Bounded parsing

The PE parser validates offsets against the file buffer, limits sections and captured imports, bounds descriptor/thunk traversal, and refuses files larger than 512 MiB. These limits reduce parser attack surface when inspecting malformed inputs.

### Explainable scoring

The scoring layer consumes a small set of explicit evidence flags rather than opaque statistical classification. This makes every point in the score auditable by an analyst.
