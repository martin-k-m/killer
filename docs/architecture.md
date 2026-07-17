# Architecture

Killer is a single Cargo crate exposing a reusable **library** (`src/lib.rs`)
plus a thin **binary** (`src/main.rs`). Nearly all logic lives in the library so
it can be tested directly and embedded.

## Module map

```
src/
├── main.rs        # CLI dispatch (scan/test/fuzz/dependencies/compliance/graph/benchmark/watch/report/…)
├── cli.rs         # clap definitions
├── lib.rs         # public library surface
├── scanner.rs     # dir walk, language detection, FileData/ProjectStats
├── analyzer.rs    # Rule trait, Finding/Severity/Category, the Analyzer
├── report.rs      # terminal + HTML rendering (scan/test/review/history/graph/deps/compliance/fuzz)
├── results.rs     # TestRun/AttackOutcome + JSON persistence (.killer/results)
├── intelligence.rs# score-history snapshots + trend (.killer/history)
├── fuzz.rs        # fuzz generator catalog (shared with .klr) + `killer fuzz`
├── dependencies.rs# dependency intelligence across 6 ecosystems (`killer dependencies`)
├── compliance.rs  # OWASP/CWE mapping (`killer compliance`; data in ../mappings/compliance.toml)
├── graph.rs       # structural import/dependency graph (`killer graph`)
├── watch.rs       # dependency-free polling watcher (`killer watch`)
├── git.rs         # `git diff` parsing for review
├── review.rs      # code review over changed lines (+ concurrency heuristics)
├── ci.rs          # CI gate helpers + GitHub Actions workflow text
├── explain.rs     # knowledge base for `killer explain`
├── config.rs      # .killer.toml loading
├── suites.rs      # built-in suites, embedded from ../suites/*.klr
├── rules/         # static scan rules (security, quality, dependencies)
├── attacks/       # http (zero-dep client behind HttpClient), filesystem, database
└── klr/           # the .klr language
    ├── lexer.rs   parser.rs   ast.rs
    ├── interpreter.rs  # runs ONE attack -> AttackOutcome
    ├── runner.rs       # check/mutate/fuzz expansion + parallel execution
    └── rule_engine.rs  # static .klr rules over source
```

## Data flow

**Static analysis**

```
directory ─▶ scanner (FileData) ─▶ Analyzer + rules ─▶ Findings ─▶ report + snapshot
```

**Dynamic testing**

```
.klr text ─▶ lexer ─▶ parser ─▶ Program (AST)
                                    │
              ┌─────────────────────┴───────────────┐
              ▼                                       ▼
     runner: expand + parallel                rule_engine (static rules)
              │                                       │
              ▼                                       ▼
     interpreter ─▶ HttpClient ─▶ AttackOutcome   RuleFinding
                                    │
                                    ▼
                        report (terminal / JSON / HTML)
```

## Why a single crate (not a workspace)

The Phase-scale specs sketch a multi-crate workspace (`killer-core`,
`killer-scanner`, …). For the current size that would add churn without user
benefit, and it risks the fragile Windows/GNU build. The module boundaries above
already separate concerns cleanly, and the library API is stable enough to split
into crates later if the project grows.

## Extension points

- **Scan rule:** implement `analyzer::Rule`, register in `rules/mod.rs`.
- **`.klr` construct:** extend `klr/ast.rs` + `klr/parser.rs`, add an
  interpreter/runner arm.
- **Transport:** implement `attacks::http::HttpClient`.
- **Built-in suite:** add `suites/<name>.klr`, register in `suites.rs`.
