# Changelog

All notable changes to ProcSentinel-C are documented here.

## [1.0.0] - 2026-09-06

### Added
- Windows process enumeration with PID and parent PID
- process image path, account, integrity level and architecture metadata
- SHA-256 hashing through Windows CNG (`BCrypt`)
- cache-only Authenticode trust verification through `WinVerifyTrust`
- PE32/PE32+ parser for headers, sections, entry point and imports
- bounded PE parsing and a 512 MiB parser input limit
- section entropy calculation
- triage findings for writable+executable sections, high-entropy executable sections and writable entry-point sections
- informational correlation of selected dual-use WinAPI imports
- per-process IPv4 TCP ownership data
- full-scan file-analysis reuse for repeated executable paths
- one-pass TCP owner-table correlation for endpoint scans
- bounded 0-100 analyst triage score
- human-readable and JSON output
- CMake build and Windows/MSVC CI
- self-PE, malformed/non-PE, entropy, scoring and helper tests
- CLI smoke tests for version, self-analysis and quick process inventory
- architecture, scoring, output-contract and threat-model documentation
- terminal preview assets for the README
