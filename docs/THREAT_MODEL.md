# Threat model

ProcSentinel-C consumes endpoint metadata and potentially untrusted PE files. Its primary security concern is therefore **safe observation of attacker-controlled or malformed inputs**.

## Assets to protect

- analyst workstation stability
- integrity of the inspected endpoint
- correctness of triage output
- analyst trust in scores and signature state

## Trust boundaries

### PE file input

A file being inspected may be malformed intentionally. The parser therefore:

- validates offsets before dereferencing file-buffer regions
- bounds section and import capture
- limits import traversal loops
- refuses PE analysis above 512 MiB
- does not execute or load the inspected image

### Process access

Windows may deny access to protected or higher-privilege processes. ProcSentinel uses `PROCESS_QUERY_LIMITED_INFORMATION` and reports inaccessible processes. It does not escalate privileges or attempt security-control bypasses.

### Signature verification

Authenticode is delegated to Windows `WinVerifyTrust`. Cache-only URL retrieval avoids unexpected certificate-network traffic during triage. `unknown` is a valid result when trust cannot be established with available local data.

### Network metadata

TCP information comes from the operating-system owner table. ProcSentinel does not connect to discovered endpoints, scan remote hosts or transmit collected data.

## Non-goals

The project is not an EDR replacement and does not attempt to provide:

- malware verdicts
- kernel visibility
- memory forensics
- exploit prevention
- process blocking or termination
- remote response actions
- reputation-service lookups

## Abuse-resistance boundary

ProcSentinel deliberately omits process injection, remote memory writes, remote thread creation, shellcode loaders, persistence and credential-access features. This keeps the codebase focused on defensive endpoint visibility.

## Residual risk

Native parsers can still contain implementation bugs. Malformed-PE regression tests and fuzzing are appropriate future hardening work. Security bugs should be reported through the process described in `SECURITY.md`.
