# Contributing to Killer

Thanks for your interest in Killer! Contributions of all kinds are welcome —
bug reports, new scan rules, `.klr` language features, docs, and built-in suites.

## Getting started

```sh
git clone https://github.com/martin-k-m/killer
cd killer
cargo build
cargo test
```

Killer is a single Cargo crate exposing a **library** (`src/lib.rs`) plus a thin
**binary** (`src/main.rs`). Almost all logic lives in the library so it can be
tested directly. See [`docs/architecture.md`](docs/architecture.md) for the
module map.

> **Windows / GNU toolchain note:** the default `x86_64-pc-windows-gnu`
> toolchain needs `dlltool` and an assembler (`as`) on `PATH` to build crates
> that use `windows-sys`. If you hit a `dlltool` / `CreateProcess` error, put a
> MinGW-w64 `bin` directory (WinLibs or MSYS2) on your `PATH`, or use the MSVC
> toolchain with the Visual Studio Build Tools.

## Before you open a PR

Run the full check suite — CI runs the same:

```sh
cargo fmt --all              # then `cargo fmt --check` should be clean
cargo clippy --all-targets   # keep it warning-free
cargo test                   # unit + integration + doc tests
```

## Conventions

- **Zero heavy runtime dependencies.** The HTTP client is hand-rolled on
  `std::net` behind the `HttpClient` trait; storage is JSON files. Please don't
  add `reqwest`/`tokio`/`rusqlite`-style dependencies without discussing it in
  an issue first.
- **Tests live next to the code** (`#[cfg(test)] mod tests`), plus integration
  suites in `tests/`.
- Doc comments on public items; `anyhow` for binary-level errors and typed
  errors (`ParseError`, `HttpError`) in the library.
- **Honesty policy:** don't claim capabilities that aren't implemented and
  tested. If a feature is partial, land the real subset and note the rest in the
  README roadmap and `CHANGELOG.md`.

## Extension points

- **A new scan rule:** implement the `Rule` trait (`src/analyzer.rs`) and
  register it in `src/rules/mod.rs`.
- **A new `.klr` construct:** extend the AST (`src/klr/ast.rs`), the parser
  (`src/klr/parser.rs`), and add an arm to the interpreter/runner.
- **A new attack transport:** implement the `HttpClient` trait
  (`src/attacks/http.rs`).
- **A new built-in suite:** add a `.klr` file under `suites/` and register it in
  `src/suites.rs`.

## Reporting bugs

Open an issue with the `killer version`, the command you ran, and a minimal
project or `.klr` file that reproduces the problem. For **security** issues, see
[`SECURITY.md`](SECURITY.md) — please don't file those publicly.

## License

By contributing, you agree that your contributions are licensed under the
project's [Apache 2.0 license](LICENSE).
