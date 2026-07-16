# Changelog

All notable changes to Killer are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] — 2026-07-16

Developer-workflow release. No breaking changes; all existing commands and
`.klr` semantics are unchanged.

### Added

- **`killer graph [--json]`** — a structural project-graph engine. Parses
  per-file imports (Rust, JavaScript/TypeScript, Python, Go, Java, Ruby) and
  declared dependencies from manifests (`Cargo.toml`, `package.json`,
  `requirements.txt`, `go.mod`), then reports the most-imported modules, import
  hotspots, and **possibly-unused declared dependencies** — a supply-chain
  signal. Dependency usage is matched best-effort (hyphen/underscore
  normalization, plus an inline `crate::path` scan for Rust). `--json` emits the
  full node/edge graph.
- **`killer benchmark [--runs N]`** — times repeated scans and reports min/avg
  latency and files-per-second / lines-per-second throughput.
- **`killer fuzz`** — surfaces the `.klr` `mutate`/`fuzz` generators as a
  first-class command. Without `--url` it previews the adversarial inputs it
  would send; with `--url` it fires each one at a target (using the same
  zero-dependency HTTP client and request encoding as `.klr` `mutate`) and
  flags any input that triggers a 5xx server fault or an unreachable target.
  `--list` prints the generator catalog; `--generators` selects a subset;
  `--field` sets the mutated key; `--fail-on-issues` gates CI.
- **`killer watch`** — re-runs a scan whenever a source file changes, using a
  dependency-free polling watcher (periodic mtime snapshots, diffed between
  ticks) that honors the same ignore rules as `killer scan`. `--interval`
  tunes the poll period.
- **`killer init --scaffold`** — in addition to writing `.killer.toml`, creates
  a `security-tests/` directory with a runnable starter `.klr` file so a new
  project can run its first test immediately.

### Changed

- The fuzz-generator table now lives in a single `fuzz` module and is shared by
  both the `.klr` runner and `killer fuzz`, so the two can never drift.

### Notes on scope

`killer fuzz` is a CLI surface over the existing input generators — not a
coverage-guided fuzzing engine — and `killer watch` polls rather than
subscribing to OS file events. `killer graph` is a *structural* graph
(imports + declared dependencies with heuristic usage matching), not a semantic
or data-flow graph. A standalone fuzzing/chaos subsystem, a true multi-language
IR / data-flow engine, a `ratatui` TUI, and a plugin marketplace remain on the
roadmap, not shipped.

## [1.1.0] — 2026-07-16

Ecosystem and release-infrastructure release. No breaking changes.

### Added

- **`killer doctor [--fix]`** — diagnoses a project's setup (git, `.killer.toml`,
  the configured `.klr` directory, a writable `.killer/`) and repairs what it
  can with `--fix`.
- **Built-in suites** expanded to six: added `database`, `crypto`, and
  `filesystem` alongside `web`, `api`, and `authentication`.
- A **severity bar chart** in the scan report summary.
- **Release automation** — a GitHub Actions workflow that, on a `vX.Y.Z` tag,
  builds Linux/macOS/Windows binaries, attaches checksummed archives, and
  publishes a GitHub Release with notes from this changelog.
- **Community & governance** — `CODE_OF_CONDUCT.md`, `SUPPORT.md`,
  `GOVERNANCE.md`, issue templates, and a pull-request template.

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

[1.2.0]: https://github.com/martin-k-m/killer/releases/tag/v1.2.0
[1.1.0]: https://github.com/martin-k-m/killer/releases/tag/v1.1.0
[1.0.0]: https://github.com/martin-k-m/killer/releases/tag/v1.0.0
