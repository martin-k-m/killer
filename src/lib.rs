//! Killer — a fast, extensible code quality and security analysis engine.
//!
//! This library crate exposes the analysis engine so it can be embedded and
//! tested independently of the `killer` command-line binary.
//!
//! # Overview
//!
//! **Static analysis** — the `killer scan` pipeline:
//!
//! - [`scanner`] walks a directory, detects languages, and loads file contents.
//! - [`analyzer`] defines the [`analyzer::Rule`] trait and runs rules over files.
//! - [`rules`] contains the built-in security and quality rules.
//! - [`report`] turns findings into a scored terminal, JSON, Markdown, or HTML
//!   report.
//! - [`config`] loads `.killer.toml` settings.
//!
//! **The `.klr` language and test framework** — `killer test`:
//!
//! - [`klr`] is the language itself: lexer, parser, AST, interpreter, the
//!   parallel runner, and the static rule engine.
//! - [`attacks`] holds the executors, including a zero-dependency HTTP client
//!   behind the [`attacks::http::HttpClient`] trait.
//! - [`suites`] exposes the six built-in suites, embedded at compile time.
//! - [`results`] models a test run and persists it under `.killer/results/`.
//! - [`fuzz`] is the mutation-generator catalog shared by `.klr` `mutate` and
//!   the `killer fuzz` command.
//!
//! **Project analysis and workflow** — everything else:
//!
//! - [`graph`] builds a structural import/dependency graph (not a data-flow one).
//! - [`dependencies`] inventories declared dependencies from local manifests
//!   across six ecosystems — no CVE or advisory lookup.
//! - [`compliance`] maps detected findings onto OWASP Top 10 (2021) and CWE.
//! - [`intelligence`] records score snapshots and computes the trend.
//! - [`git`] parses `git diff` output for [`review`], which analyzes only the
//!   lines a change touched.
//! - [`ci`] provides the gate helpers behind `killer ci` / `killer github enable`.
//! - [`watch`] is a dependency-free polling file watcher.
//! - [`explain`] is the knowledge base behind `killer explain <ISSUE_ID>`.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use killer::{analyzer::Analyzer, config::Config, report::Report, scanner};
//!
//! let root = Path::new(".");
//! let config = Config::load(root).unwrap();
//! let scan = scanner::scan(root, &config);
//! let findings = Analyzer::with_default_rules(&config).analyze(&scan);
//! let report = Report::new("demo".into(), scan.stats, findings);
//! print!("{}", report.render_terminal());
//! ```

pub mod analyzer;
pub mod attacks;
pub mod ci;
pub mod compliance;
pub mod config;
pub mod dependencies;
pub mod explain;
pub mod fuzz;
pub mod git;
pub mod graph;
pub mod intelligence;
pub mod klr;
pub mod report;
pub mod results;
pub mod review;
pub mod rules;
pub mod scanner;
pub mod suites;
pub mod watch;
