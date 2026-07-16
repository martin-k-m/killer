# Introduction

**Killer is a Rust security platform.** It does four things:

1. **Static analysis** (`killer scan`) — walks a project, detects its languages,
   and runs security/quality rules over every file, printing a scored report.
2. **A security test framework** (`killer test`) — runs `.klr` files, a small
   DSL for describing attacks and static code rules, against a live target.
3. **Project intelligence** (`killer history`) — records every scan and shows how
   the security score moves over time.
4. **Workflow integration** (`killer review` / `killer ci`) — reviews a git diff
   and provides a single CI gate.

## Design principles

- **Zero heavy runtime dependencies.** The HTTP client is hand-rolled on
  `std::net` behind a trait; storage is JSON files, not a database. This keeps
  the build small and portable.
- **A library first.** Everything lives in a reusable library crate
  (`killer::…`); the CLI is a thin wrapper. You can embed the engine.
- **Honest scope.** Killer ships a real, tested subset of a larger vision.
  Unbuilt work (TLS attacks, a data-flow graph, fuzzing/chaos subsystems,
  plugins) is on the roadmap, not stubbed.

## When to use it

- In development, run `killer scan` to catch secrets and dangerous patterns.
- Write `.klr` suites to prove your service defends against injection, path
  traversal, missing rate limits, and session reuse.
- Drop `killer ci` into your pipeline to gate merges on new findings.

Next: [Installation](installation.md).
