//! Killer — a fast, extensible code quality and security analysis engine.
//!
//! This library crate exposes the analysis engine so it can be embedded and
//! tested independently of the `killer` command-line binary.
//!
//! # Overview
//!
//! - [`scanner`] walks a directory, detects languages, and loads file contents.
//! - [`analyzer`] defines the [`analyzer::Rule`] trait and runs rules over files.
//! - [`rules`] contains the built-in security and quality rules.
//! - [`report`] turns findings into a scored, terminal-friendly report.
//! - [`config`] loads `.killer.toml` settings.
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
pub mod config;
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
