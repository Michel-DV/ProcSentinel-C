# Contributing

Contributions that improve defensive Windows endpoint visibility, parser robustness, test coverage, documentation or output quality are welcome.

## Build before submitting

```powershell
cmake -S . -B build -A x64 -DBUILD_TESTING=ON
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

## Project boundary

Changes must preserve ProcSentinel's read-only security boundary. Contributions should not add process injection, arbitrary remote-memory modification, credential collection, persistence, exploit delivery, remote command execution or evasion features.

## C style

- C11
- explicit error handling
- bounded parsing for untrusted input
- prefer fixed project limits where output structures are fixed-size
- close Windows handles on every path
- avoid hidden network access
- keep analyst-facing findings explainable

## Tests

Bug fixes should include a regression test when practical. Parser changes should prefer synthetic/non-malicious fixtures rather than live malware samples.
