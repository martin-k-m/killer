# CLAUDE.md

Guidance for Claude (and humans) working in this repository.

## What Killer is

Killer is a Rust security platform with two halves:

- **Static analysis** (`killer scan`) — walks a project, detects languages, runs
  security/quality rules, prints a scored report.
- **A security test framework** (`killer test`) — runs the **`.klr`** DSL
  (Killer Rule Language): `suite`/`test`/`repeat`/`mutate` blocks that describe
  attacks and static code rules, executed against a target in parallel.

Plus: project intelligence (`history`), code review over a git diff (`review`),
a CI gate (`ci` / `github enable`), and `explain`/`report` helpers.

Single Cargo crate exposing a **library** (`src/lib.rs`) + a thin **binary**
(`src/main.rs`). Everything testable lives in the library.

## Build & test — READ THIS FIRST (Windows toolchain trap)

This machine's Rust setup is fragile. Builds only work with a specific PATH:

- Default toolchain is `stable-x86_64-pc-windows-gnu`. Its bundled `dlltool`
  needs an assembler (`as.exe`) that the rustup dir lacks, so any crate using
  `windows-sys` (pulled in by `clap`, `colored`, `walkdir`) fails with a
  `dlltool` / `CreateProcess` error.
- The MSVC toolchain is installed but has **no linker** (no VS Build Tools).

**Fix:** prepend the WinLibs MinGW-w64 `bin` to `PATH`, and call `cargo` by full
path (it isn't on PowerShell's PATH). Use **PowerShell**, not the Bash tool
(Git Bash's `link` shadows the MSVC linker and breaks things):

```powershell
$mingw = "C:\Users\comma\AppData\Local\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin"
$env:PATH = "$mingw;$env:USERPROFILE\.cargo\bin;" + $env:PATH
& "$env:USERPROFILE\.cargo\bin\cargo.exe" build     # test / clippy / fmt all work once PATH is set
```

On a normal machine with a working linker, plain `cargo build` / `cargo test`
just work — this is a local environment issue, not a project one.

### Standard checks (run before finishing any change)

```
cargo fmt            # then `cargo fmt --check` should be clean
cargo clippy --all-targets   # keep it warning-free
cargo test           # unit + integration + doc tests
```

## Architecture (module map)

```
src/
├── main.rs        # CLI dispatch (scan/test/report/history/review/ci/github/explain/init/version)
├── cli.rs         # clap definitions
├── lib.rs         # public library surface
├── scanner.rs     # dir walk, language detection, FileData/ProjectStats
├── analyzer.rs    # Rule trait, Finding/Severity/Category, the Analyzer
├── report.rs      # ALL terminal + HTML rendering (scan/test/review/history/banner)
├── results.rs     # TestRun/AttackOutcome + JSON persistence (.killer/results)
├── intelligence.rs# score-history snapshots + trend (.killer/history)
├── git.rs         # `git diff` parsing for review
├── review.rs      # code review over changed lines (+ concurrency heuristics)
├── ci.rs          # CI gate helpers + GitHub Actions workflow text
├── explain.rs     # knowledge base for `killer explain <ISSUE_ID>`
├── config.rs      # .killer.toml loading
├── suites.rs      # built-in suites, embedded from ../suites/*.klr via include_str!
├── rules/         # static scan rules (security.rs, quality.rs, dependencies.rs)
├── attacks/       # http.rs (zero-dep client behind HttpClient trait), filesystem.rs, database.rs
└── klr/           # the .klr language
    ├── lexer.rs   parser.rs   ast.rs
    ├── interpreter.rs  # runs ONE attack -> AttackOutcome
    ├── runner.rs       # check/mutate expansion + parallel (thread::scope) execution
    └── rule_engine.rs  # static .klr rules over source
```

## Conventions

- **Zero heavy runtime deps.** The HTTP client is hand-rolled on `std::net`
  (http:// only) behind the `HttpClient` trait; storage is JSON files, not a DB.
  This is deliberate — it keeps the build portable on the broken toolchain
  above. Don't add `reqwest`/`tokio`/`rusqlite` without a very good reason.
- **Tests live next to the code** (`#[cfg(test)] mod tests`) plus integration
  suites in `tests/`. `tests/klr_e2e.rs` stands up a real TCP server.
- **Match surrounding style**: doc comments on public items, `anyhow` for
  binary-level errors, typed errors (`ParseError`, `HttpError`) in the library.
- **Extension points**: a new scan rule = implement `Rule` + register in
  `rules/mod.rs`; a new `.klr` construct = AST + parser + an interpreter arm; a
  new transport = implement `HttpClient`.

## Honesty policy (important)

The specs Killer was built from are platform-scale; each phase shipped a real,
tested subset and **explicitly deferred** the rest rather than stubbing it.
Keep that up: don't claim capabilities that aren't implemented and tested.
Notably still deferred — TLS for attacks, a real dependency/data-flow graph,
Tree-sitter multi-language IR, the interactive `ratatui` TUI (`killer ui`),
`watch` mode, a package manager/marketplace, a web dashboard served by the CLI,
and Phase 3 (fuzzing/chaos) as its own phase.

## Repo / website

- Repo: `https://github.com/martin-k-m/killer` (use this org everywhere).
- Marketing site lives in the sibling repo `killer-web` (Next.js). Its
  `lib/site.ts` is the content source of truth and must stay verifiable against
  what is actually **pushed** to the public repo.
