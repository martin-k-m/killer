# Changelog

All notable changes to Killer are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-07-16

First public release. Killer is a Rust security platform with a static analysis
engine, a `.klr` test framework, project intelligence, code review, and a CI
gate. It builds from source and passes its full test suite (unit + integration
+ real-socket end-to-end + doc tests).

### Added

- **`killer scan`** — static analysis across Rust, JavaScript, TypeScript,
  Python, Go, Ruby, Java, C/C++, and Shell. Detects hardcoded secrets (including
  AWS/GitHub/Slack/OpenAI token formats), dangerous command execution,
  oversized files, `TODO`/`FIXME`/`HACK`/`XXX` markers, and duplicate code.
  Prints a color-coded report with a 0–100 health score.
- **The `.klr` language** — a lexer, recursive-descent parser (with coded
  `KLR###` diagnostics), and an interpreter. Supports `project`, `suite`,
  `attack`/`test`, `target`/`endpoint`/`request`, `send`, `header`, `payload`,
  `repeat` (per-request and as a block loop), `check`, `mutate`, `fuzz`
  (shorthand), `expect`, `severity`, `message`, and static `rule` definitions.
- **`killer test`** — runs `.klr` attacks against a live target with a parallel
  worker pool (`--parallel`), built-in suites (`--suite web|api|authentication`),
  a Jest-like grouped report, and JSON/HTML output.
- **Attack executors** — a zero-dependency HTTP client behind an `HttpClient`
  trait, plus SQL-injection, path-traversal, rate-limit, and session helpers.
- **`killer history`** — persistent project intelligence: every scan is recorded
  under `.killer/`, and the security score's trend is shown over time.
- **`killer review`** — reviews only the lines a `git diff` changed, including a
  concurrency/transaction heuristic (e.g. an unguarded `balance -= amount`).
- **`killer ci`** and **`killer github enable`** — a single CI gate with a
  non-zero exit, and a generated GitHub Actions workflow.
- **`killer report`** — renders the last run to the terminal or a self-contained
  HTML report.
- **`killer explain <ISSUE_ID>`** — a knowledge base for issue ids (`KLR-SQLI`,
  `KLR-PATH-TRAVERSAL`, `KLR-RATE-LIMIT`, `KLR-SESSION`, `KLR-GENERIC`).
- **`killer init`** — writes a documented `.killer.toml`.
- Documentation under [`docs/`](docs/), example `.klr` files under
  [`examples/`](examples/), and built-in suites under `suites/`.

### Notes on scope

Killer ships a real, tested subset of a much larger vision. The following are
**not** in 1.0 and are tracked on the roadmap rather than stubbed:

- TLS transport for attacking `https://` targets (the built-in client is
  `http://` only, behind a trait so a TLS backend can drop in).
- AST parsing (Tree-sitter) and a dependency / data-flow graph — the static
  `.klr` rule engine uses line-level heuristics today.
- Fuzzing/chaos as their own subsystems, an interactive `ratatui` TUI, `watch`
  mode, a plugin system, and a package marketplace.

[1.0.0]: https://github.com/martin-k-m/killer/releases/tag/v1.0.0
