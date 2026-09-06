# Security policy

## Project boundary

ProcSentinel-C is a read-only Windows endpoint and PE triage utility.

It intentionally does **not** implement:

- process injection
- remote thread creation
- arbitrary process-memory writes
- credential collection
- persistence
- exploit delivery
- remote command execution
- stealth or security-control bypasses

The tool queries process metadata, reads executable files from disk, inspects PE metadata, validates digital signatures, computes SHA-256 hashes, and reads the operating system TCP ownership table.

## Reporting a vulnerability

Please report memory-safety problems, parser crashes, integer-overflow conditions, path-handling bugs, or incorrect trust/scoring behavior through a private GitHub security advisory when available.

Do not attach live malware samples to public issues. A minimal synthetic reproducer is preferred.

## Triage philosophy

A high score is an analyst prioritization signal, not a malware verdict. Unsigned files, high entropy, executable+writable sections and dual-use APIs can occur in legitimate software. Findings must be correlated with context and additional telemetry.
