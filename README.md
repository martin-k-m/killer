# Killer

[![CI](https://github.com/martin-k-m/killer/actions/workflows/ci.yml/badge.svg)](https://github.com/martin-k-m/killer/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Rust 1.74+](https://img.shields.io/badge/rust-1.74%2B-orange.svg)
![Version 1.2.0](https://img.shields.io/badge/version-1.2.0-brightgreen.svg)

**A Rust security testing framework with a custom language for writing
vulnerability attacks and code-analysis rules.**

> *"The software that tries to destroy your software before attackers do."*

Killer does four things:

1. **Static analysis** (`killer scan`) — walks a project, detects its languages,
   and runs security/quality rules over every file: hardcoded secrets, dangerous
   command execution, oversized files, `TODO`/`FIXME` markers, and duplicate
   code. Prints a color-coded report with a 0–100 health score.

2. **A security test framework** (`killer test`) — runs `.klr` files written in
   the **Killer Rule Language**, a real DSL with `suite`/`test` blocks, `repeat`
   loops, and `mutate` fuzz-generators. Tests run in parallel across worker
   threads, with Jest-like output, built-in suites (`--suite web`), and
   JSON/HTML reports.

3. **Project intelligence** (`killer history`) — Killer *remembers*. Every scan
   is recorded, so it can show how a project's security score moves over time
   ("Improved +16, fixed 23 findings").

4. **Workflow integration** (`killer review` / `killer ci`) — reviews only the
   lines a change touched (including concurrency/transaction bugs like an
   unguarded `balance -= amount`), and provides a single CI gate you can drop
   into GitHub Actions.

```sh
killer scan .                         # static analysis (records a snapshot)
killer test auth.klr --url http://localhost:3000   # run attacks
killer history .                      # score trend over time
killer review --base origin/main      # review a diff
killer ci                             # the full gate, for pipelines
```

> **Status:** v1.2.0 — available now. Builds and passes its full test suite;
> install from source (a crates.io release is coming). The static engine, the
> `.klr` test framework, project intelligence, code review, and the CI gate are
> all implemented and tested; see [Roadmap](#roadmap) for what's intentionally
> deferred, [docs/](docs/) for guides, and [CHANGELOG.md](CHANGELOG.md) for
> what shipped.

---

## Features

- **Zero-config scanning** — run `killer scan .` and get results immediately.
- **Language detection** — Rust, JavaScript, TypeScript, Python, Go, Ruby,
  Java, C/C++, and Shell (by file extension).
- **Smart directory pruning** — automatically skips `.git`, `node_modules`,
  `target`, `dist`, `build`, virtualenvs, caches, and other noise.
- **Extensible rule engine** — every rule implements a single `Rule` trait.
- **Security rules**
  - **Hardcoded secrets** — API keys, passwords, tokens, plus known provider
    formats (AWS keys, GitHub PATs, Slack tokens, private-key blocks). Ignores
    placeholders and `process.env` / `std::env` lookups to keep noise down.
  - **Dangerous commands** — `os.system`, `subprocess(..., shell=True)`,
    `eval`/`exec`, Rust `Command::new`, JS `child_process`/`execSync`, etc.
- **Quality rules**
  - **Large files** — flags files over a configurable line threshold.
  - **TODO / FIXME tracker** — surfaces `TODO`, `FIXME`, `HACK`, `XXX`.
  - **Duplicate code** — detects repeated blocks of consecutive lines.
- **Health score** — a single 0–100 number, weighted by severity.
- **Configurable** — a `.killer.toml` file tunes ignores, thresholds, and which
  rules run.

---

## Installation

From source (the supported path today):

```sh
git clone https://github.com/martin-k-m/killer
cd killer
cargo install --path .
```

Once a release is published to crates.io this will also work:

```sh
cargo install killer   # planned — not yet on crates.io
```

Requires a stable Rust toolchain (1.74+). On Windows with the GNU toolchain,
see the build note under [Development](#development) if `dlltool` errors appear.

---

## Usage

```sh
killer scan <path>              # static analysis (defaults to ".")
killer test [path]              # run .klr tests & rules (--suite, --parallel)
killer fuzz [--url URL]         # generate adversarial inputs & fire them
killer graph [path]             # structural project graph (--json)
killer benchmark [path]         # scan throughput (--runs N)
killer watch [path]             # re-scan on file change (--interval)
killer report [path] --html     # render the last run (terminal or HTML)
killer history [path]           # security-score trend over time
killer review [path]            # review changed lines (git diff)
killer ci [path]                # full gate: scan + rules + review
killer github enable [path]     # write a GitHub Actions workflow
killer explain <ISSUE_ID>       # explain an issue, e.g. KLR-SQLI
killer init [path] --scaffold   # write .killer.toml (+ starter .klr)
killer doctor [path]            # diagnose setup (--fix to repair)
killer version                  # version + rules, issue ids & suites
```

### `scan` flags

| Flag              | Description                                                        |
| ----------------- | ----------------------------------------------------------------- |
| `--quiet`         | Print a single summary line instead of the full report.           |
| `--fail-on-issues`| Exit non-zero if any **critical** or **high** issue is found (CI). |

### `test` flags

| Flag                | Description                                                            |
| ------------------- | --------------------------------------------------------------------- |
| `--suite <NAME>`    | Run a built-in suite (`web`, `api`, `authentication`, `database`, `crypto`, `filesystem`) instead of files.|
| `--url <URL>`       | Base URL relative attack targets resolve against.                     |
| `--parallel [N]`    | Run tests across N worker threads (omit N to auto-size to the CPU).   |
| `--format <FMT>`    | `terminal` (default) or `json` (for CI).                              |
| `--project <DIR>`   | Project directory to run static `.klr` rules over (default `.`).      |
| `--no-save`         | Do not write results to `.killer/results/`.                           |
| `--fail-on-issues`  | Exit non-zero if any vulnerability is found (CI).                     |

---

## Example

Scanning a project that contains a couple of deliberately vulnerable files:

```text
$ killer scan tests/vulnerable_project

====================================================

KILLER REPORT

Project:  vulnerable_project
Files scanned:  2
Lines of code:  27
Languages:  JavaScript, Python
Issues found:  8

Security
  ❌ Hardcoded secret detected  bad.py:15
      AWS access key id found in source. Move it to an environment variable or secret manager.
  ❌ Hardcoded secret detected  secret.js:4
      OpenAI-style secret key found in source. Move it to an environment variable or secret manager.
  ❌ Hardcoded secret detected  secret.js:5
      Hardcoded credential found in source. Move it to an environment variable or secret manager.
  ⚠ Dangerous command execution  bad.py:7
      os.system() shell execution detected. Validate/sanitize inputs and avoid passing user data to a shell.
  ⚠ Dangerous command execution  bad.py:8
      subprocess call detected. Validate/sanitize inputs and avoid passing user data to a shell.
  ⚠ Dangerous command execution  bad.py:12
      eval() of dynamic input detected. Validate/sanitize inputs and avoid passing user data to a shell.

Quality
  ⚠ FIXME comment  bad.py:6
      FIXME: this passes untrusted input straight to the shell
  • TODO comment  secret.js:8
      TODO: move these into environment variables

Summary
  Critical:  3
  High:      3
  Warning:   1
  Info:      1

Score:  0/100

====================================================
```

A clean project scores 100:

```text
$ killer scan tests/clean_project

KILLER REPORT

Project:  clean_project
Files scanned:  1
Lines of code:  22
Languages:  Rust
Issues found:  0

No issues found. Clean scan!
...
Score:  100/100
```

---

## The Killer Rule Language (`.klr`)

`.klr` is a small domain-specific language for describing **attacks** (dynamic
security tests) and **rules** (static code checks). The compiler pipeline is a
classic one:

```text
.klr text ──▶ lexer ──▶ tokens ──▶ parser ──▶ Program (AST)
                                                  │
                         ┌────────────────────────┴───────────────┐
                         ▼                                          ▼
                interpreter (attacks)                     rule_engine (static rules)
                         │                                          │
                         ▼                                          ▼
                  AttackOutcome                              RuleFinding
```

### Attacks

An attack describes how a **secure** system should behave. If every expectation
holds, the system defended itself (`PASSED`). If any expectation fails, a
vulnerability is indicated (`FAILED`).

```klr
project "MyApplication"

attack authentication {
    target "/api/login"

    send {
        username = "' OR 1=1"
        password = "anything"
    }

    expect {
        status != 200
        response does_not_contain "token"
    }

    severity critical
    message: "SQL injection vulnerability detected"
}
```

Run it against a target:

```text
$ killer test examples/auth_security.klr --url http://localhost:8080

╭────────────────────────────────────────────╮
│                                            │
│    K I L L E R                             │
│    Software Security Engine                │
│                                            │
╰────────────────────────────────────────────╯

====================================================

KILLER TEST REPORT

Project:  MyApplication
Sources:  examples/auth_security.klr

Tests
  ✗ authentication
      ✗ status != 200  observed status 200
      ✗ response does_not_contain "token"  "token" leaked in response
      → killer explain KLR-SQLI
  ✗ api_rate_limit
      ✗ blocked_after 10  no rate limiting after 100 requests
      → killer explain KLR-RATE-LIMIT

Tests:
  0  passed
  2  failed
  2 total

Time:  0.05s

2 vulnerabilities found

====================================================
```

### More attack shapes

Both brace-blocks and colon-forms are accepted:

```klr
# Rate limiting: the endpoint should block abusive clients.
attack api_rate_limit {
    request: POST "/login"
    repeat: 1000 times
    expect: blocked_after 10
    severity medium
}

# Path traversal: an uploaded "../../etc/passwd" must not be exposed.
attack upload {
    endpoint "/upload"
    payload: "../../etc/passwd"
    expect { file_not_exposed true }
}

# Session reuse: a stolen cookie must be rejected on reuse.
attack session {
    target "/account"
    login user "test"
    steal cookie
    attempt reuse
    expect { session_invalidated true }
}
```

### Static rules

A `rule` runs against your **source code** (via `--project`), not a live server:

```klr
rule "unsafe database query"
when function contains "query"
and input reaches query
without sanitization
severity high
report: "User input reaches database directly"
```

```text
$ killer test examples/database_rules.klr --project .

Static Rule Findings
  • unsafe database query  dao.py:4
      User input reaches database directly
```

> The static-rule engine uses **line-level heuristics** (does the line hit the
> sink, read input or build a dynamic string, and skip sanitization?). It is a
> pragmatic first pass — full dataflow analysis via Tree-sitter is a later phase.

### Language reference

| Construct | Forms | Notes |
| --------- | ----- | ----- |
| `project "Name"` | — | Optional display name. |
| `suite "Name" { … }` | — | Groups `attack`/`test`/`repeat` blocks. |
| `attack <name> { … }` / `test <name> { … }` | — | A dynamic test (`test` is a friendly alias). |
| `target` / `endpoint` / `url` | `target "/path"` | Relative to `--url`, or an absolute `http://…`. |
| `method` / `request` | `method POST` · `request: POST "/x"` | Defaults to `POST` when a body is present, else `GET`. |
| `send { k = v … }` | — | JSON request body. |
| `header { k = v … }` | — | Extra request headers. |
| `payload "…"` | `payload: "…"` | Raw request body (e.g. traversal string). |
| `repeat N times` | `repeat: N` | Repeats the request within one test. |
| `repeat N { … }` | — | **Loop:** repeats the contained tests N times. |
| `check <name>` | `check authentication` | Expands to built-in expectations (`authentication`, `injection`, `rate_limit`). |
| `mutate <field> { … }` | — | **Fuzzing:** expands the test into one variant per generator value. |
| `fuzz <field>` | `fuzz amount` | Shorthand for `mutate` with a broad default generator set. |
| `expect { … }` | `expect: <cond>` | One or more conditions. |
| `severity` | `critical`/`high`/`medium`/`low` | — |
| `message: "…"` | `message "…"` | Shown when the attack fails. |

**Expectations:** `status <op> <n>` (`==` `!=` `<` `>` `<=` `>=`),
`response contains "…"`, `response does_not_contain "…"`, `blocked_after <n>`,
and named booleans `file_not_exposed true` / `session_invalidated true`.

**Mutation generators:** `negative_numbers`, `huge_values`, `decimals`, `zero`,
`empty`, `sql_injection`, `xss`, `null_bytes`, `long_strings`, `unicode`. An
unknown generator injects its own name as the value.

Comments start with `#` or `//`. Parse errors carry a stable code (`KLR001…`)
plus `File` / `Line` / `Expected` / `Found` fields.

### Test framework: suites, fuzzing & parallelism

```klr
suite "Payment Security" {
    attack duplicate_payment {
        request POST "/payment"
        send { amount = 100 }
        mutate amount {
            negative_numbers   # -1, -999999
            huge_values        # 999999999999999, ...
            decimals           # 0.0001, 3.14159
        }
        expect { status != 200 }
    }
}
```

That one `mutate` block expands into six concrete tests. Run built-in suites or
your own, across worker threads, with a Jest-like report:

```text
$ killer test --suite api --url http://localhost:8090 --parallel 8

KILLER TEST REPORT
Sources:  builtin:api
Workers:  8

API
  ✓ input_injection_fuzz [id=sql_injection]
  ✓ input_injection_fuzz [id=negative_numbers#1]
  ...
  ✗ rate_limit
      ✗ blocked_after 30  no rate limiting after 100 requests
      → killer explain KLR-RATE-LIMIT

Tests:
  6  passed
  1  failed
  7 total

Time:  0.06s
```

- **Built-in suites:** `--suite web | api | authentication | database | crypto | filesystem` (embedded in the binary).
- **Parallel:** `--parallel [N]` runs across scoped worker threads (omit N to auto-size).
- **Reports:** `--format json` for CI, or `killer report --html` for a
  self-contained dashboard (`killer-report.html`).

### Issue ids & `explain`

Every attack is tagged with a stable issue id — `KLR-SQLI`,
`KLR-PATH-TRAVERSAL`, `KLR-RATE-LIMIT`, `KLR-SESSION`, `KLR-GENERIC`. Look one up:

```text
$ killer explain KLR-SQLI

KLR-SQLI  SQL Injection

What it is
  Untrusted input is incorporated into a SQL query, letting an attacker alter
  the query's logic (e.g. ' OR 1=1).

Impact
  Authentication bypass, reading or modifying arbitrary data, ...

How to fix it
  Use parameterized queries / prepared statements. ...
```

### Results storage

Unless `--no-save` is passed, each run is written to
`.killer/results/run-<timestamp>.json` for later review or diffing.

> **Transport note:** the built-in HTTP client speaks plain `http://` with zero
> dependencies, behind an `HttpClient` trait. TLS (`https://`) is a planned
> drop-in backend; until then, point `--url` at an `http://` target (e.g. a
> local dev server or a proxy).

---

## Project intelligence, review & CI

### `killer history` — Killer remembers

Every `killer scan` records a snapshot under `.killer/history/`. Over time,
`killer history` shows the trend:

```text
$ killer history .

KILLER SCORE

Security:  100/100
Current:  0 findings (0 critical, 0 high)

Since first scan (2 snapshots)
  Change:   +39
  Fixed:    4 findings

  Trend:  ▅█
```

Storage is plain JSON (`.killer/project.json` + `.killer/history/*.json`) — no
database engine, so it stays portable and diffable. Pass `--no-record` to
`scan` to skip recording.

### `killer review` — review only what changed

`killer review` diffs the working tree (or `--staged`, or `--base <ref>`) and
reviews **only the added lines**. It runs the existing rules plus review-specific
heuristics — including concurrency/transaction safety:

```text
$ killer review .

KILLER CODE REVIEW

Reviewed:  1 changed file

  ❌ Hardcoded secret detected  payment.rs:3
      OpenAI-style secret key found in source. ...
      → Load secrets from the environment or a secrets vault.
  ⚠ Possible race condition  payment.rs:2
      `balance` is updated with a non-atomic read-modify-write and no visible lock/transaction.
      → Guard the update with a Mutex, use an atomic type (fetch_add/fetch_sub), or a DB transaction.

✗ REVIEW FAILED — 1 blocking issue(s)
```

### `killer ci` + `killer github enable` — the gate

`killer ci` runs the whole gate (scan + static `.klr` rules + review) and exits
non-zero on any blocking issue:

```text
$ killer ci .
▶ Killer CI gate
  ✗ scan — score 75/100, 1 critical, 0 high
  ✓ klr rules — 0 finding(s)
  ✗ review — 2 finding(s), 1 blocking

✗ Killer gate FAILED    # exit code 1
```

`killer github enable` writes `.github/workflows/killer.yml` so the gate runs on
every push and pull request.

> **Scope.** Killer ships the local-first, testable core of a larger security
> platform — **persistent intelligence, code review, and a CI gate** among
> them. The bigger vision (a semantic data-flow engine, a networked rule &
> attack marketplace, a multi-language IR, a web dashboard, live
> GitHub/GitLab/Jenkins apps) is on the [roadmap](#roadmap), intentionally
> deferred rather than stubbed. In the same spirit, `killer fuzz` is a CLI
> surface over the existing `.klr` input generators, not a standalone
> coverage-guided fuzzing engine, and `killer graph` is structural, not
> data-flow.

---

## Configuration

Generate a starter config with `killer init`, then edit `.killer.toml`:

```toml
[project]
# Display name for reports. Defaults to the directory name.
name = "my-app"

[scan]
# Extra paths to ignore, on top of the built-in defaults.
ignore = ["tests", "vendor"]

# Files longer than this many lines are flagged as "large".
large_file_threshold = 1000

[rules]
# Toggle individual rules on or off.
secret_detection = true
dangerous_commands = true
large_files = true
todo_tracker = true
duplicate_code = true

[languages]
# Languages to focus on (informational in this phase).
rust = true
typescript = true
python = true

[security]
# Security posture: relaxed | standard | strict.
level = "standard"

[klr]
# Where `killer test` looks for .klr files when no path is given.
directory = "./security-tests"

# Base URL that relative attack targets resolve against.
base_url = "http://127.0.0.1:8080"
```

All fields are optional — a project with no config file still gets a full scan.

---

## How the health score works

Each finding deducts points from a starting score of 100:

| Severity   | Points |
| ---------- | ------ |
| Critical   | 25     |
| High       | 10     |
| Warning    | 3      |
| Info       | 1      |

The score is clamped to the `0–100` range. `--fail-on-issues` fails the run when
any critical or high finding is present, which makes Killer easy to drop into CI.

---

## Architecture

Killer is split into a reusable library crate (`src/lib.rs`) and a thin CLI
binary (`src/main.rs`).

```
src/
├── main.rs        # CLI entry point (scan / test / fuzz / graph / benchmark / watch / …)
├── lib.rs         # public library surface
├── cli.rs         # clap command/flag definitions
├── scanner.rs     # directory walk, language detection, file loading
├── analyzer.rs    # Rule trait, Finding/Severity types, the Analyzer
├── config.rs      # .killer.toml loading
├── report.rs      # scan/attack/review/history/graph/fuzz rendering
├── results.rs     # TestRun/AttackOutcome types + JSON storage
├── explain.rs     # knowledge base behind `killer explain`
├── intelligence.rs # persistent snapshots + score trends
├── fuzz.rs        # fuzz generator catalog (shared with .klr) + `killer fuzz`
├── graph.rs       # structural project graph behind `killer graph`
├── watch.rs       # dependency-free polling watcher behind `killer watch`
├── git.rs         # git-diff parsing for the review engine
├── review.rs      # code review over changed lines (+ concurrency heuristics)
├── ci.rs          # CI gate helpers + GitHub Actions workflow
├── rules/         # static scan rules
│   ├── security.rs    # hardcoded secrets, dangerous commands
│   ├── quality.rs     # large files, TODO/FIXME, duplicate code
│   └── dependencies.rs # reserved for future dependency rules
├── suites.rs      # built-in test suites (embedded .klr)
├── klr/           # the Killer Rule Language
│   ├── lexer.rs       # text → tokens
│   ├── parser.rs      # tokens → AST (recursive descent, coded errors)
│   ├── ast.rs         # AST types (suite/attack/mutate/…)
│   ├── interpreter.rs # executes one attack → AttackOutcome
│   ├── runner.rs      # check/mutate expansion + parallel execution
│   └── rule_engine.rs # executes static .klr rules → RuleFinding
├── attacks/       # attack executors
│   ├── http.rs        # zero-dep HTTP client behind an HttpClient trait
│   ├── filesystem.rs  # path-traversal / file-exposure helpers
│   └── database.rs    # SQLi signatures + rule heuristics
└── suites/        # embedded .klr suites (web, api, authentication, database, crypto, filesystem)
```

> **Note on layout:** a `core/ scanner/ analyzer/ …` multi-crate split was
> considered and deliberately not done — for a single crate it would be churn
> without benefit. The `klr/` and `attacks/` module trees live alongside the
> core modules instead. See [docs/architecture.md](docs/architecture.md).

### Adding a rule

1. Implement the `Rule` trait:

   ```rust
   use killer::analyzer::{Category, Finding, Rule, Severity};
   use killer::scanner::FileData;

   pub struct MyRule;

   impl Rule for MyRule {
       fn id(&self) -> &str { "my-rule" }
       fn name(&self) -> &str { "My Rule" }
       fn description(&self) -> &str { "Explains what it detects." }
       fn category(&self) -> Category { Category::Quality }

       fn check(&self, file: &FileData) -> Vec<Finding> {
           // inspect file.content / file.numbered_lines() ...
           Vec::new()
       }
   }
   ```

2. Register it in [`src/rules/mod.rs`](src/rules/mod.rs) `default_rules()`.

That's the whole extension surface — the scanner, analyzer, and report layers
need no changes. Adding a `.klr` expectation or attack transport is similarly
localized: extend the AST + parser and add an arm in the interpreter, or
implement the `HttpClient` trait for a new transport.

---

## Development

```sh
cargo build            # build
cargo test             # run unit + integration tests
cargo clippy           # lint
cargo run -- scan .    # static analysis
cargo run -- test examples/auth_security.klr --url http://localhost:8080
```

Tests live alongside each module (`#[cfg(test)]`) plus two integration suites:
[`tests/integration.rs`](tests/integration.rs) (static analysis over the
`vulnerable_project` / `clean_project` fixtures) and
[`tests/klr_e2e.rs`](tests/klr_e2e.rs), which stands up a real TCP server and
drives the actual HTTP client end-to-end.

> **Note (Windows GNU toolchain):** the default `x86_64-pc-windows-gnu`
> toolchain needs `dlltool` + `as` on `PATH` to build crates that use
> `windows-sys`. If you hit a `dlltool`/`CreateProcess` error, add a MinGW-w64
> `bin` directory (e.g. from WinLibs or MSYS2) to your `PATH`, or switch to the
> `x86_64-pc-windows-msvc` toolchain with the Visual Studio Build Tools.

---

## What's shipped

Everything below is implemented, tested, and available now:

- **Static analysis engine** — scanner, language detection, an extensible rule
  engine, security/quality rules, and a scored terminal report.
- **The `.klr` language** — lexer, parser, AST, and interpreter with coded
  diagnostics; `suite`/`test`/`repeat`/`mutate`/`fuzz`, static `rule`
  definitions, and HTTP/filesystem/database attack executors.
- **`killer test`** — a parallel runner, six built-in suites, and JSON/HTML
  reports.
- **`killer fuzz`** — the `.klr` input generators as a command (preview inputs,
  or fire them at a target and flag faults).
- **`killer graph`** — a structural import/dependency graph.
- **`killer benchmark`** — scan-throughput measurement.
- **`killer watch`** — dependency-free re-scan on file change.
- **Project intelligence** (`history`), **code review** (`review`), and the
  **CI gate** (`ci` / `github enable`).

## Roadmap

Genuinely future work — listed so scope stays honest, never stubbed in code:

- TLS transport for attacking `https://` targets (the client is `http://` only,
  behind a trait so a TLS backend can drop in).
- A semantic data-flow graph and a Tree-sitter multi-language IR (today's
  `killer graph` is structural).
- A coverage-guided fuzzing engine and chaos testing as their own subsystems.
- An interactive `ratatui` TUI (`killer ui`), a plugin SDK, a package manager
  (`killer add` / imports), and a networked rule & attack marketplace.
- Live GitHub/GitLab/Jenkins apps and a hosted, distributed security lab.

---

## Documentation & community

- **[docs/](docs/)** — [introduction](docs/introduction.md),
  [installation](docs/installation.md), [quickstart](docs/quickstart.md),
  [CLI reference](docs/cli.md), [`.klr` guide](docs/klr-guide.md),
  [writing tests](docs/writing-tests.md), [architecture](docs/architecture.md),
  and [examples](docs/examples.md).
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — how to build, test, and extend Killer.
- **[SECURITY.md](SECURITY.md)** — how to report a vulnerability in Killer itself.
- **[CHANGELOG.md](CHANGELOG.md)** — release history.
- Website: [killer.blinkdev.me](https://killer.blinkdev.me)

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
