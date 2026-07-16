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
a CI gate (`ci` / `github enable`), a health check (`doctor`), and
`explain`/`report`/`init` helpers.

Single Cargo crate exposing a **library** (`src/lib.rs`) + a thin **binary**
(`src/main.rs`). Everything testable lives in the library.

**Current status: v1.1.0, released and usable** — builds from source and passes
its full test suite (87 tests). It is **not yet on crates.io**, so installation
is from source (`cargo install --path .`) and `cargo install killer` is still
"coming soon". The whole implementation is on the public `main` branch. See
`CHANGELOG.md` for what shipped and the README roadmap for what's deferred.

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

Input **fuzzing exists** as the `.klr` `mutate`/`fuzz` generators. Still
**deferred** (roadmap, not built — don't advertise as shipped): TLS for
attacking `https://` targets, a real dependency/data-flow graph, Tree-sitter
multi-language IR, chaos testing as its own subsystem, an interactive `ratatui`
TUI (`killer ui`), `watch` mode, a plugin SDK, and a networked package
manager/marketplace (`killer install`; the "standard library" is just the
built-in embedded suites — six of them: web, api, authentication, database,
crypto, filesystem). A multi-crate workspace is intentionally NOT done — keep
the single crate (rationale in `docs/architecture.md`).

## Repo / website — where everything stands

Use the `martin-k-m` org everywhere. Two repos, both public, both released at
v1.1.0, both with the implementation on `main`:

**Tool — `github.com/martin-k-m/killer`** (this repo)
- `main` has the full implementation (tagged `v1.0.0` and `v1.1.0`). Local work
  happens on branch `claude/killer-phase-1-core-81f540`; the workflow so far has
  been: commit on the branch, push the branch, then `git push origin HEAD:main`
  (fast-forward), and tag `vX.Y.Z` to fire the release pipeline.
- CI runs on push/PR (`.github/workflows/ci.yml`: fmt, clippy `-D warnings`,
  test, cargo audit). Tagging `v*` runs `release.yml` (cross-platform binaries +
  GitHub Release with notes from `CHANGELOG.md`).
- OSS files present: README (with badges), CHANGELOG, CONTRIBUTING, SECURITY,
  CODE_OF_CONDUCT, GOVERNANCE, SUPPORT, issue/PR templates, and `docs/` (9
  guides). Keep these in sync when the CLI/`.klr`/features change.

**Website — sibling repo `killer-web`** (Next.js 16, static export)
- Location on this machine: `C:\Users\comma\Documents\Github\killer-web` (a
  sibling of the killer repo, NOT inside a worktree). Deployed to
  **https://killer.blinkdev.me** via GitHub Pages on push to `main`
  (`.github/workflows/deploy.yml`; `public/CNAME` holds the domain). Node is at
  `C:\Program Files\nodejs` (not on the shell PATH by default).
- `lib/site.ts` is the **content source of truth** and carries an accuracy rule:
  every claim must be verifiable against what's on the tool repo's `main`. The
  roadmap array there drives the on-site roadmap + progress bar; mark an item
  `Shipped` only once its code is public. The site is framed as **released /
  "available now · v1.1.0"** (crates.io still "coming soon" — that's accurate).
- Favicon is `app/icon.svg`; HTTPS metadata (metadataBase/canonical/OG) points
  at the https domain. Verify with `npm run build` before pushing.

**Cross-repo sync obligation:** when a CLI command, `.klr` construct, or feature
changes in the tool, update BOTH the tool docs (README, `docs/`, CHANGELOG) AND
`killer-web` (`lib/site.ts`, and the demo components `KLRDemo`/`TerminalDemo`/
`DocumentationPreview` which mirror real CLI output). Push tool changes to
`main` first so the site's claims stay verifiable.

**Not done via git (needs the maintainer / GitHub UI):** setting the repo
description & topics, enabling "Enforce HTTPS" on Pages, creating the GitHub
Release from a tag if the workflow didn't, publishing to crates.io (needs a
token), and an open Dependabot alert on `killer-web`.
