# Triage scoring

The score is intended to prioritize analyst review. It is **not** a malware classifier.

| Signal | Points | Rationale |
| --- | ---: | --- |
| Unsigned executable | 10 | Weak signal; many legitimate programs are unsigned |
| Invalid/untrusted signature | 20 | Stronger trust anomaly |
| Signature status unknown | 5 | Low-confidence uncertainty |
| Writable + executable PE section | 35 | High-signal memory-permission anomaly |
| High-entropy executable section | 20 | Possible packing/compression; can be legitimate |
| Entry point inside writable section | 25 | Unusual PE layout requiring review |

The score is capped at 100.

Selected APIs such as `VirtualAllocEx`, `WriteProcessMemory` and `CreateRemoteThread` are displayed as **informational dual-use imports only**. They do not add points because legitimate debuggers, security products and administration tools can import the same APIs.

## Risk bands

- `0-14`: INFO
- `15-39`: LOW
- `40-69`: MEDIUM
- `70-100`: HIGH

## Interpretation

A score is a prioritization aid, not a verdict. Analysts should correlate it with signer identity, process ancestry, path, network state, prevalence, endpoint telemetry and threat intelligence.

Examples of expected false-positive sources include:

- software packers and protectors
- debuggers
- EDR/security products
- anti-cheat software
- installers and self-extracting packages
- internal utilities that are not Authenticode signed

## Why dual-use imports are not scored

Imports such as `OpenProcess` and `WriteProcessMemory` are semantically interesting but individually weak. Static imports do not prove that an API is called, what target is used, or whether the behavior is legitimate. ProcSentinel therefore exposes this evidence without pretending it is a reliable malware signal by itself.
