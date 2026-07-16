//! Killer — a fast, extensible code quality and security analysis engine.
//!
//! Phase 1: CLI, project scanner, language detection, an extensible rule
//! engine, an initial set of security/quality rules, and a terminal report.
//!
//! Phase 2: the Killer Rule Language (`.klr`) — a DSL for writing vulnerability
//! attacks and static code rules, executed by `killer test`.
//!
//! This binary is a thin wrapper over the `killer` library crate.

mod cli;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;

use cli::{Cli, Command, GithubAction};
use killer::analyzer::Analyzer;
use killer::attacks::http::StdHttpClient;
use killer::config::{self, Config};
use killer::git::{self, DiffTarget};
use killer::intelligence::{IntelStore, Snapshot};
use killer::klr::interpreter::RunConfig;
use killer::report::{self, Report};
use killer::results::{RuleFinding, TestRun};
use killer::{ci, explain, klr, review, rules, scanner, suites};

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Scan {
            path,
            quiet,
            fail_on_issues,
            no_record,
        } => run_scan(&path, quiet, fail_on_issues, no_record),
        Command::History { path } => run_history(&path),
        Command::Review {
            path,
            staged,
            base,
            fail_on_issues,
        } => run_review(&path, staged, base, fail_on_issues),
        Command::Ci { path, base } => run_ci(&path, base),
        Command::Github { action } => run_github(action),
        Command::Test {
            path,
            suite,
            url,
            project,
            parallel,
            format,
            no_save,
            fail_on_issues,
        } => run_test(TestArgs {
            path,
            suite,
            url,
            project,
            parallel,
            format,
            no_save,
            fail_on_issues,
        }),
        Command::Report { path, html, out } => run_report(&path, html, &out),
        Command::Explain { issue_id } => run_explain(&issue_id),
        Command::Init { path, force } => run_init(&path, force).map(|_| ExitCode::SUCCESS),
        Command::Version => {
            print_version();
            Ok(ExitCode::SUCCESS)
        }
    };

    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{} {:#}", "error:".red().bold(), err);
            ExitCode::FAILURE
        }
    }
}

/// Run the analysis for a directory and return the report (shared by `scan`,
/// `ci`, and snapshot recording).
fn perform_scan(root: &Path, config: &Config) -> Report {
    let scan = scanner::scan(root, config);
    let findings = Analyzer::with_default_rules(config).analyze(&scan);
    let project_name = config
        .project
        .name
        .clone()
        .unwrap_or_else(|| directory_name(root));
    Report::new(project_name, scan.stats, findings)
}

/// Record a scan snapshot in the project intelligence history (best effort).
fn record_snapshot(root: &Path, report: &Report) {
    let (timestamp, slug) = timestamp_now();
    let snapshot = Snapshot::from_report(&slug, &timestamp, report);
    let store = IntelStore::new(root);
    if let Err(e) = store.record(&snapshot, Some(&report.project_name)) {
        eprintln!("{} could not record snapshot: {e}", "warning:".yellow());
    }
}

/// Run `killer scan`.
fn run_scan(path: &Path, quiet: bool, fail_on_issues: bool, no_record: bool) -> Result<ExitCode> {
    let root = path
        .canonicalize()
        .with_context(|| format!("cannot access path '{}'", path.display()))?;

    if !root.is_dir() {
        anyhow::bail!("'{}' is not a directory", path.display());
    }

    let config = Config::load(&root)?;
    let report = perform_scan(&root, &config);

    if quiet {
        let c = report.severity_counts();
        println!(
            "{}: {} issues ({} critical, {} high, {} warning, {} info) — score {}/100",
            report.project_name,
            c.total(),
            c.critical,
            c.high,
            c.warning,
            c.info,
            report.score()
        );
    } else {
        print!("{}", report::banner());
        print!("{}", report.render_terminal());
    }

    if !no_record {
        record_snapshot(&root, &report);
    }

    if fail_on_issues && report.has_blocking_issues() {
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// Run `killer history`.
fn run_history(path: &Path) -> Result<ExitCode> {
    let root = path
        .canonicalize()
        .with_context(|| format!("cannot access path '{}'", path.display()))?;
    let store = IntelStore::new(&root);
    let history = store.load_history()?;
    let trend = killer::intelligence::compute_trend(&history);
    print!("{}", report::render_score_history(&history, trend.as_ref()));
    Ok(ExitCode::SUCCESS)
}

/// Run `killer review`.
fn run_review(
    path: &Path,
    staged: bool,
    base: Option<String>,
    fail_on_issues: bool,
) -> Result<ExitCode> {
    let root = path
        .canonicalize()
        .with_context(|| format!("cannot access path '{}'", path.display()))?;
    let config = Config::load(&root)?;

    let target = diff_target(staged, base);
    let changed = git::changed_files(&root, &target)?;

    let findings = review::review(&root, &changed, &config);
    print!("{}", report::render_review(&findings, changed.len()));

    let blocking = findings.iter().any(|f| {
        matches!(
            f.severity,
            killer::analyzer::Severity::Critical | killer::analyzer::Severity::High
        )
    });
    if fail_on_issues && blocking {
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// Run `killer ci`: scan + `.klr` tests + review, with a non-zero exit on any
/// failure. Designed for pipelines.
fn run_ci(path: &Path, base: Option<String>) -> Result<ExitCode> {
    let root = path
        .canonicalize()
        .with_context(|| format!("cannot access path '{}'", path.display()))?;
    let config = Config::load(&root)?;
    let mut failed = false;

    println!("{}", "▶ Killer CI gate".bold());

    // 1. Static scan.
    let report = perform_scan(&root, &config);
    record_snapshot(&root, &report);
    let sc = report.severity_counts();
    let scan_ok = !report.has_blocking_issues();
    failed |= !scan_ok;
    println!(
        "  {} scan — score {}/100, {} critical, {} high",
        status_mark(scan_ok),
        report.score(),
        sc.critical,
        sc.high
    );

    // 2. Static `.klr` rules (attacks need a live target, so CI runs rules only).
    if let Some(dir) = klr_dir_if_present(&root, &config) {
        match run_klr_rules(&root, &config, &dir) {
            Ok(n) => {
                let ok = n == 0;
                failed |= !ok;
                println!("  {} klr rules — {} finding(s)", status_mark(ok), n);
            }
            Err(e) => println!("  {} klr rules — skipped ({e})", "•".dimmed()),
        }
    }

    // 3. Review of the diff (best effort — no diff is fine).
    let target = diff_target(false, base);
    match git::changed_files(&root, &target) {
        Ok(changed) if !changed.is_empty() => {
            let findings = review::review(&root, &changed, &config);
            let blocking = findings
                .iter()
                .filter(|f| {
                    matches!(
                        f.severity,
                        killer::analyzer::Severity::Critical | killer::analyzer::Severity::High
                    )
                })
                .count();
            let ok = blocking == 0;
            failed |= !ok;
            println!(
                "  {} review — {} finding(s), {} blocking",
                status_mark(ok),
                findings.len(),
                blocking
            );
        }
        Ok(_) => println!("  {} review — no changes to review", "•".dimmed()),
        Err(e) => println!("  {} review — skipped ({e})", "•".dimmed()),
    }

    println!();
    if failed {
        println!("{}", "✗ Killer gate FAILED".red().bold());
        Ok(ExitCode::FAILURE)
    } else {
        println!("{}", "✓ Killer gate PASSED".green().bold());
        Ok(ExitCode::SUCCESS)
    }
}

/// Run `killer github <action>`.
fn run_github(action: GithubAction) -> Result<ExitCode> {
    match action {
        GithubAction::Enable { path, force } => {
            let root = path
                .canonicalize()
                .with_context(|| format!("cannot access path '{}'", path.display()))?;
            let written = ci::write_github_workflow(&root, force)?;
            println!(
                "{} Wrote {}",
                "✓".green().bold(),
                file_display(&root, &written).bold()
            );
            println!("  Commit it and Killer will run on every push and pull request.");
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Build a [`DiffTarget`] from the CLI flags.
fn diff_target(staged: bool, base: Option<String>) -> DiffTarget {
    match (staged, base) {
        (_, Some(b)) => DiffTarget::Base(b),
        (true, None) => DiffTarget::Staged,
        (false, None) => DiffTarget::WorkingTree,
    }
}

/// Resolve the `.klr` directory to run rules from during CI, if it exists.
fn klr_dir_if_present(root: &Path, config: &Config) -> Option<PathBuf> {
    let dir = config
        .klr
        .directory
        .as_ref()
        .map(|d| root.join(d))
        .unwrap_or_else(|| root.to_path_buf());
    dir.exists().then_some(dir)
}

/// Parse the `.klr` files under `dir`, run their static rules over the project,
/// and return the number of findings.
fn run_klr_rules(root: &Path, config: &Config, dir: &Path) -> Result<usize> {
    let files = collect_klr_files(dir)?;
    let mut rules = Vec::new();
    for file in &files {
        let src = std::fs::read_to_string(file)?;
        let program = klr::parse(&src).map_err(|e| anyhow::anyhow!("{}: {e}", file.display()))?;
        rules.extend(program.rules);
    }
    if rules.is_empty() {
        return Ok(0);
    }
    let scan = scanner::scan(root, config);
    Ok(klr::rule_engine::run_rules(&rules, &scan.files).len())
}

fn status_mark(ok: bool) -> colored::ColoredString {
    if ok {
        "✓".green()
    } else {
        "✗".red()
    }
}

/// Run `killer test`.
/// Arguments for `killer test` (grouped to keep the signature readable).
struct TestArgs {
    path: Option<PathBuf>,
    suite: Option<String>,
    url: Option<String>,
    project: PathBuf,
    parallel: Option<usize>,
    format: String,
    no_save: bool,
    fail_on_issues: bool,
}

fn run_test(args: TestArgs) -> Result<ExitCode> {
    let json_output = args.format.eq_ignore_ascii_case("json");
    if !json_output {
        print!("{}", report::banner());
    }
    let project_root = args
        .project
        .canonicalize()
        .with_context(|| format!("cannot access project path '{}'", args.project.display()))?;
    let config = Config::load(&project_root)?;

    let mut project_name = config.project.name.clone();
    let mut attacks = Vec::new();
    let mut klr_rules = Vec::new();
    let mut sources = Vec::new();

    // Source of tests: a built-in suite, or `.klr` files.
    if let Some(suite_name) = &args.suite {
        let suite = suites::get(suite_name).ok_or_else(|| {
            let names: Vec<_> = suites::all().iter().map(|s| s.name).collect();
            anyhow::anyhow!(
                "unknown suite '{suite_name}'. Available: {}",
                names.join(", ")
            )
        })?;
        let program = parse_klr(suite.source, &format!("<builtin:{}>", suite.name))?;
        project_name = project_name.or(program.project.clone());
        attacks.extend(program.all_attacks());
        klr_rules.extend(program.rules);
        sources.push(format!("builtin:{}", suite.name));
    } else {
        let klr_path = match args.path {
            Some(p) => p,
            None => match &config.klr.directory {
                Some(dir) => project_root.join(dir),
                None => project_root.clone(),
            },
        };
        let files = collect_klr_files(&klr_path)?;
        if files.is_empty() {
            anyhow::bail!("no .klr files found at '{}'", klr_path.display());
        }
        for file in &files {
            let src = std::fs::read_to_string(file)
                .with_context(|| format!("failed to read {}", file.display()))?;
            let program = parse_klr(&src, &file_display(&project_root, file))?;
            if project_name.is_none() {
                project_name = program.project.clone();
            }
            attacks.extend(program.all_attacks());
            klr_rules.extend(program.rules);
            sources.push(file_display(&project_root, file));
        }
    }

    // Resolve base URL and worker count.
    let base_url = args
        .url
        .or_else(|| config.klr.base_url.clone())
        .unwrap_or_else(|| RunConfig::default().base_url);
    let workers = resolve_workers(args.parallel);

    let run_config = RunConfig {
        base_url,
        ..RunConfig::default()
    };
    let client = StdHttpClient::new();

    let started = Instant::now();
    let outcomes = klr::runner::run_all(&attacks, &client, &run_config, workers);
    let elapsed_ms = started.elapsed().as_millis();

    // Run static rules over the project source.
    let rule_findings: Vec<RuleFinding> = if klr_rules.is_empty() {
        Vec::new()
    } else {
        let scan = scanner::scan(&project_root, &config);
        klr::rule_engine::run_rules(&klr_rules, &scan.files)
    };

    let (timestamp, slug) = timestamp_now();
    let run = TestRun {
        project: project_name,
        timestamp,
        sources,
        attacks: outcomes,
        rule_findings,
        workers,
        elapsed_ms,
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&run)?);
    } else {
        print!("{}", report::render_attack_report(&run));
    }

    if !args.no_save {
        match run.save(&project_root, &slug) {
            Ok(path) if !json_output => println!(
                "{} results saved to {}",
                "✓".green(),
                file_display(&project_root, &path).dimmed()
            ),
            Ok(_) => {}
            Err(e) => eprintln!("{} could not save results: {e}", "warning:".yellow()),
        }
    }

    if args.fail_on_issues && run.has_vulnerabilities() {
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// Parse `.klr` source, turning a parse error into a nicely-formatted report.
fn parse_klr(src: &str, source_name: &str) -> Result<killer::klr::ast::Program> {
    klr::parse(src).map_err(|e| anyhow::anyhow!("{}", format_klr_error(source_name, &e)))
}

/// Format a `.klr` parse error in the KLR#### diagnostic style.
fn format_klr_error(source_name: &str, err: &killer::klr::parser::ParseError) -> String {
    let mut s = String::new();
    s.push_str(&format!("\n{}\n\n", err.code.red().bold()));
    s.push_str(&format!("{}\n\n", err.message));
    s.push_str(&format!("  {}  {}\n", "File:".bold(), source_name));
    s.push_str(&format!("  {}  {}\n", "Line:".bold(), err.line));
    if let (Some(expected), Some(found)) = (&err.expected, &err.found) {
        s.push_str(&format!(
            "\n  {}  {}\n",
            "Expected:".bold(),
            expected.green()
        ));
        s.push_str(&format!("  {}  {}\n", "Found:".bold(), found.red()));
    }
    s
}

/// Resolve the worker count: `Some(0)`/auto → cpu-based; `Some(n)` → n; None → 1.
fn resolve_workers(parallel: Option<usize>) -> usize {
    match parallel {
        None => 1,
        Some(0) => std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(1, 16),
        Some(n) => n.max(1),
    }
}

/// Run `killer report [--html]`.
fn run_report(path: &Path, html: bool, out: &Path) -> Result<ExitCode> {
    let root = path
        .canonicalize()
        .with_context(|| format!("cannot access path '{}'", path.display()))?;
    let run = load_latest_result(&root)?;

    if html {
        let doc = report::render_html(&run);
        std::fs::write(out, doc).with_context(|| format!("failed to write {}", out.display()))?;
        println!(
            "{} Wrote {}",
            "✓".green().bold(),
            out.display().to_string().bold()
        );
    } else {
        print!("{}", report::render_attack_report(&run));
    }
    Ok(ExitCode::SUCCESS)
}

/// Load the most recent saved [`TestRun`] from `.killer/results/`.
fn load_latest_result(root: &Path) -> Result<TestRun> {
    let dir = root.join(".killer").join("results");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .with_context(|| {
            format!(
                "no results found in {} (run `killer test` first)",
                dir.display()
            )
        })?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
        .collect();
    files.sort();
    let latest = files
        .last()
        .ok_or_else(|| anyhow::anyhow!("no saved results in {}", dir.display()))?;
    let text = std::fs::read_to_string(latest)?;
    Ok(serde_json::from_str(&text)?)
}

/// Run `killer explain <ISSUE_ID>`.
fn run_explain(issue_id: &str) -> Result<ExitCode> {
    match explain::lookup(issue_id) {
        Some(e) => {
            println!("\n{}  {}\n", e.id.bold(), e.title.bold().underline());
            println!("{}", "What it is".bold());
            println!("  {}\n", e.summary);
            println!("{}", "Impact".bold());
            println!("  {}\n", e.impact);
            println!("{}", "How to fix it".bold());
            println!("  {}\n", e.remediation);
            if !e.references.is_empty() {
                println!("{}", "References".bold());
                for r in e.references {
                    println!("  • {r}");
                }
                println!();
            }
            Ok(ExitCode::SUCCESS)
        }
        None => {
            eprintln!(
                "{} unknown issue id '{}'.\n\nKnown ids:",
                "error:".red().bold(),
                issue_id
            );
            for id in explain::all_ids() {
                eprintln!("  • {id}");
            }
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Collect `.klr` files from a path (a single file or a directory tree).
fn collect_klr_files(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        anyhow::bail!("'{}' does not exist", path.display());
    }
    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("klr"))
        .collect();
    files.sort();
    Ok(files)
}

/// A path shown relative to `root` where possible, with forward slashes.
fn file_display(root: &Path, path: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(rel) => rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/"),
        // Not under the project root: show the native path as-is.
        Err(_) => path.display().to_string(),
    }
}

/// A `(human_timestamp, filename_slug)` pair from the system clock.
fn timestamp_now() -> (String, String) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // Human timestamp uses seconds; the slug uses zero-padded nanoseconds so
    // that back-to-back runs get distinct, correctly-sorting ids.
    (
        format!("epoch-{}", now.as_secs()),
        format!("{:020}", now.as_nanos()),
    )
}

/// Run `killer init`.
fn run_init(path: &Path, force: bool) -> Result<()> {
    if !path.is_dir() {
        anyhow::bail!("'{}' is not a directory", path.display());
    }
    let target = path.join(config::CONFIG_FILE_NAME);

    if target.exists() && !force {
        anyhow::bail!(
            "{} already exists (use --force to overwrite)",
            target.display()
        );
    }

    std::fs::write(&target, Config::default_file_contents())
        .with_context(|| format!("failed to write {}", target.display()))?;

    println!(
        "{} Created {}",
        "✓".green().bold(),
        target.display().to_string().bold()
    );
    Ok(())
}

/// Run `killer version`.
fn print_version() {
    println!("{} {}", "killer".bold(), env!("CARGO_PKG_VERSION"));
    println!("{}", env!("CARGO_PKG_DESCRIPTION").dimmed());
    println!();
    println!("{}", "Active scan rules:".bold());
    for id in rules::all_rule_ids() {
        println!("  • {id}");
    }
    println!();
    println!("{}", "Known .klr issue ids:".bold());
    for id in explain::all_ids() {
        println!("  • {id}");
    }
    println!();
    println!("{}", "Built-in test suites:".bold());
    for suite in suites::all() {
        println!("  • {}  {}", suite.name, suite.description.dimmed());
    }
}

/// The final path component of `root`, used as a fallback project name.
fn directory_name(root: &Path) -> String {
    root.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| root.to_string_lossy().into_owned())
}
