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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;

use cli::{Cli, Command, GithubAction};
use killer::analyzer::Analyzer;
use killer::attacks::http::{StdHttpClient, Url};
use killer::config::{self, Config};
use killer::fuzz::{self, FuzzOptions};
use killer::git::{self, DiffTarget};
use killer::intelligence::{IntelStore, Snapshot};
use killer::klr::interpreter::RunConfig;
use killer::report::{self, Report};
use killer::results::{RuleFinding, TestRun, Verdict};
use killer::{
    ci, compliance, dependencies, explain, graph, klr, review, rules, scanner, suites, watch,
};

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
        Command::Fuzz {
            list,
            field,
            generators,
            url,
            method,
            project,
            fail_on_issues,
        } => run_fuzz(FuzzArgs {
            list,
            field,
            generators,
            url,
            method,
            project,
            fail_on_issues,
        }),
        Command::Dependencies {
            path,
            details,
            json,
        } => run_dependencies(&path, details, json),
        Command::Compliance { path, json } => run_compliance(&path, json),
        Command::Graph { path, json } => run_graph(&path, json),
        Command::Benchmark { path, runs } => run_benchmark(&path, runs),
        Command::Watch { path, interval } => run_watch(&path, interval),
        Command::Report {
            path,
            html,
            out,
            executive,
            technical,
            json,
            markdown,
        } => run_report(ReportArgs {
            path,
            html,
            out,
            executive,
            technical,
            json,
            markdown,
        }),
        Command::Explain { issue_id } => run_explain(&issue_id),
        Command::Init {
            path,
            force,
            scaffold,
        } => run_init(&path, force, scaffold).map(|_| ExitCode::SUCCESS),
        Command::Doctor { path, fix } => run_doctor(&path, fix),
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

/// Run `killer compliance`.
fn run_compliance(path: &Path, json: bool) -> Result<ExitCode> {
    let root = path
        .canonicalize()
        .with_context(|| format!("cannot access path '{}'", path.display()))?;
    let config = Config::load(&root)?;

    // Detected finding ids: scan rule ids, plus issue ids from any confirmed
    // vulnerabilities in the latest saved test run.
    let report = perform_scan(&root, &config);
    let mut keys: Vec<String> = report.findings.iter().map(|f| f.rule.clone()).collect();
    if let Ok(run) = load_latest_result(&root) {
        for a in &run.attacks {
            if a.verdict == Verdict::Vulnerable {
                if let Some(id) = &a.issue_id {
                    keys.push(id.clone());
                }
            }
        }
    }

    let assessment = compliance::assess(&keys);
    if json {
        println!("{}", serde_json::to_string_pretty(&assessment)?);
    } else {
        print!("{}", report::banner());
        print!("{}", report::render_compliance(&assessment));
    }
    Ok(ExitCode::SUCCESS)
}

/// Run `killer dependencies`.
fn run_dependencies(path: &Path, details: bool, json: bool) -> Result<ExitCode> {
    let root = path
        .canonicalize()
        .with_context(|| format!("cannot access path '{}'", path.display()))?;
    let config = Config::load(&root)?;
    let scan = scanner::scan(&root, &config);
    let report = dependencies::DependencyReport::build(&scan.files);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", report::banner());
        print!("{}", report::render_dependencies(&report, details));
    }
    Ok(ExitCode::SUCCESS)
}

/// Run `killer graph`.
fn run_graph(path: &Path, json: bool) -> Result<ExitCode> {
    let root = path
        .canonicalize()
        .with_context(|| format!("cannot access path '{}'", path.display()))?;
    let config = Config::load(&root)?;
    let scan = scanner::scan(&root, &config);
    let project_graph = graph::ProjectGraph::build(&scan);

    if json {
        println!("{}", serde_json::to_string_pretty(&project_graph)?);
    } else {
        print!("{}", report::banner());
        print!("{}", report::render_graph(&project_graph));
    }
    Ok(ExitCode::SUCCESS)
}

/// Run `killer benchmark`.
fn run_benchmark(path: &Path, runs: usize) -> Result<ExitCode> {
    let root = path
        .canonicalize()
        .with_context(|| format!("cannot access path '{}'", path.display()))?;
    let config = Config::load(&root)?;
    let runs = runs.max(1);

    print!("{}", report::banner());
    println!(
        "{}  {} run(s) over {}\n",
        "Benchmark".bold(),
        runs,
        root.display()
    );

    let mut durations: Vec<Duration> = Vec::with_capacity(runs);
    let mut stats = scanner::ProjectStats::default();
    for i in 1..=runs {
        let start = Instant::now();
        let scan = scanner::scan(&root, &config);
        let elapsed = start.elapsed();
        stats = scan.stats;
        durations.push(elapsed);
        println!("  run {i:>2}  {:>8.2} ms", elapsed.as_secs_f64() * 1000.0);
    }

    let total: Duration = durations.iter().sum();
    let avg = total / runs as u32;
    let min = durations.iter().min().copied().unwrap_or_default();
    let avg_secs = avg.as_secs_f64();

    println!();
    println!("{}", "Results".bold().underline());
    println!("  {}  {}", "Files:".bold(), stats.files);
    println!("  {}  {}", "Lines:".bold(), stats.lines_of_code);
    println!("  {}  {:.2} ms", "Min:".bold(), min.as_secs_f64() * 1000.0);
    println!("  {}  {:.2} ms", "Avg:".bold(), avg_secs * 1000.0);
    if avg_secs > 0.0 {
        println!(
            "  {}  {:.0} files/s · {:.0} lines/s",
            "Throughput:".bold(),
            stats.files as f64 / avg_secs,
            stats.lines_of_code as f64 / avg_secs
        );
    }
    println!();
    Ok(ExitCode::SUCCESS)
}

/// Run `killer watch`: re-scan whenever a source file changes.
fn run_watch(path: &Path, interval_secs: u64) -> Result<ExitCode> {
    let root = path
        .canonicalize()
        .with_context(|| format!("cannot access path '{}'", path.display()))?;
    if !root.is_dir() {
        anyhow::bail!("'{}' is not a directory", path.display());
    }
    let interval = Duration::from_secs(interval_secs.max(1));

    print!("{}", report::banner());
    println!("{}  {}", "Watching".bold(), root.display());
    println!(
        "  {}",
        format!("re-scanning on change every {interval_secs}s — press Ctrl-C to stop").dimmed()
    );

    // Initial scan establishes the baseline snapshot.
    let config = Config::load(&root)?;
    scan_once(&root, &config);
    let mut prev = watch::snapshot(&root, &config);

    loop {
        std::thread::sleep(interval);
        // Reload config each cycle so edits to .killer.toml take effect live.
        let config = Config::load(&root).unwrap_or_default();
        let next = watch::snapshot(&root, &config);
        let changes = watch::diff(&prev, &next);
        if !changes.is_empty() {
            println!();
            println!(
                "{} {} file{} changed:",
                "▶".cyan().bold(),
                changes.count(),
                if changes.count() == 1 { "" } else { "s" }
            );
            for p in changes.all_paths() {
                println!("  {} {}", "·".dimmed(), p);
            }
            scan_once(&root, &config);
        }
        prev = next;
    }
}

/// Run a scan and print a one-line summary (used by `watch`).
fn scan_once(root: &Path, config: &Config) {
    let report = perform_scan(root, config);
    record_snapshot(root, &report);
    let c = report.severity_counts();
    println!(
        "  {} score {}/100 — {} critical, {} high, {} warning, {} info",
        status_mark(!report.has_blocking_issues()),
        report.score(),
        c.critical,
        c.high,
        c.warning,
        c.info
    );
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

/// Arguments for `killer fuzz`.
struct FuzzArgs {
    list: bool,
    field: String,
    generators: Option<String>,
    url: Option<String>,
    method: String,
    project: PathBuf,
    fail_on_issues: bool,
}

/// Run `killer fuzz`.
fn run_fuzz(args: FuzzArgs) -> Result<ExitCode> {
    if args.list {
        print!("{}", report::render_fuzz_catalog());
        return Ok(ExitCode::SUCCESS);
    }

    print!("{}", report::banner());

    // Resolve the generator list: an explicit CSV, or the whole catalog.
    let generators: Vec<String> = match &args.generators {
        Some(csv) => csv
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        None => fuzz::catalog().iter().map(|g| g.name.to_string()).collect(),
    };
    if generators.is_empty() {
        anyhow::bail!("no generators selected (use --list to see the available ones)");
    }

    // Resolve the target URL against the project's configured base_url, if any.
    let target = match &args.url {
        Some(u) => {
            let project_root = args.project.canonicalize().with_context(|| {
                format!("cannot access project path '{}'", args.project.display())
            })?;
            let config = Config::load(&project_root)?;
            let base = config
                .klr
                .base_url
                .unwrap_or_else(|| killer::klr::interpreter::RunConfig::default().base_url);
            let resolved =
                Url::resolve(&base, u).map_err(|e| anyhow::anyhow!("invalid target '{u}': {e}"))?;
            Some(resolved.to_absolute())
        }
        None => None,
    };

    let opts = FuzzOptions {
        field: args.field,
        method: args.method.to_uppercase(),
        generators,
        target,
    };

    let client = StdHttpClient::new();
    let report = fuzz::run(&client, &opts);
    print!("{}", report::render_fuzz(&report));

    if args.fail_on_issues && report.anomalies().next().is_some() {
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// Run `killer report [--html]`.
/// Arguments for `killer report`.
struct ReportArgs {
    path: PathBuf,
    html: bool,
    out: PathBuf,
    executive: bool,
    technical: bool,
    json: bool,
    markdown: bool,
}

fn run_report(args: ReportArgs) -> Result<ExitCode> {
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("cannot access path '{}'", args.path.display()))?;
    let run = load_latest_result(&root)?;

    if args.html {
        let doc = report::render_html(&run);
        std::fs::write(&args.out, doc)
            .with_context(|| format!("failed to write {}", args.out.display()))?;
        println!(
            "{} Wrote {}",
            "✓".green().bold(),
            args.out.display().to_string().bold()
        );
    } else if args.json {
        println!("{}", serde_json::to_string_pretty(&run)?);
    } else if args.markdown {
        print!("{}", report::render_markdown(&run));
    } else if args.executive {
        let score = latest_score(&root);
        print!("{}", report::render_report_executive(&run, score));
    } else if args.technical {
        print!("{}", report::render_report_technical(&run));
    } else {
        print!("{}", report::render_attack_report(&run));
    }
    Ok(ExitCode::SUCCESS)
}

/// The most recent recorded scan score for a project, if any.
fn latest_score(root: &Path) -> Option<u32> {
    IntelStore::new(root)
        .load_history()
        .ok()
        .and_then(|h| h.last().map(|s| s.security_score))
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
fn run_init(path: &Path, force: bool, scaffold: bool) -> Result<()> {
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

    if scaffold {
        let dir = path.join(config::SCAFFOLD_DIR);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
        let starter = dir.join(config::SCAFFOLD_FILE);
        if starter.exists() && !force {
            println!(
                "{} {} already exists — left unchanged (use --force to overwrite)",
                "•".yellow(),
                file_display(path, &starter)
            );
        } else {
            std::fs::write(&starter, Config::starter_klr())
                .with_context(|| format!("failed to write {}", starter.display()))?;
            println!(
                "{} Created {}",
                "✓".green().bold(),
                starter.display().to_string().bold()
            );
        }
        println!(
            "\nNext: run {} to try the static rules,",
            "killer ci".bold()
        );
        println!(
            "  or start a server and run {} against it.",
            "killer test".bold()
        );
    }

    Ok(())
}

/// Run `killer doctor`.
fn run_doctor(path: &Path, fix: bool) -> Result<ExitCode> {
    let root = path
        .canonicalize()
        .with_context(|| format!("cannot access path '{}'", path.display()))?;

    println!("\n{}\n", "KILLER DOCTOR".bold());
    let mut problems = 0usize;

    // 1. git — required for `review` and `ci`.
    let git_ok = std::process::Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    check(
        if git_ok { Status::Ok } else { Status::Warn },
        "git available",
        if git_ok {
            "found on PATH"
        } else {
            "not found — `review` and `ci` need git"
        },
    );

    // 2. Configuration file.
    let cfg_path = root.join(config::CONFIG_FILE_NAME);
    if cfg_path.exists() {
        match Config::load(&root) {
            Ok(_) => check(Status::Ok, ".killer.toml", "present and valid"),
            Err(e) => {
                problems += 1;
                check(Status::Fail, ".killer.toml", &format!("invalid: {e}"));
            }
        }
    } else if fix {
        std::fs::write(&cfg_path, Config::default_file_contents())
            .with_context(|| format!("failed to write {}", cfg_path.display()))?;
        check(Status::Ok, ".killer.toml", "created (--fix)");
    } else {
        check(
            Status::Warn,
            ".killer.toml",
            "not found — defaults are used (run `killer init` or `doctor --fix`)",
        );
    }

    let config = Config::load(&root).unwrap_or_default();

    // 3. Configured .klr directory, if any.
    if let Some(dir) = &config.klr.directory {
        let d = root.join(dir);
        if d.exists() {
            check(Status::Ok, "klr directory", dir);
        } else if fix {
            std::fs::create_dir_all(&d)
                .with_context(|| format!("failed to create {}", d.display()))?;
            check(Status::Ok, "klr directory", &format!("{dir} (created)"));
        } else {
            check(
                Status::Warn,
                "klr directory",
                &format!("configured '{dir}' does not exist"),
            );
        }
    }

    // 4. The .killer/ state directory is writable.
    let killer_dir = root.join(".killer").join("history");
    match std::fs::create_dir_all(&killer_dir) {
        Ok(_) => check(
            Status::Ok,
            ".killer/ writable",
            "results & history can be saved",
        ),
        Err(e) => {
            problems += 1;
            check(
                Status::Fail,
                ".killer/ writable",
                &format!("cannot write: {e}"),
            );
        }
    }

    // 5. Rule set and suites sanity (always available; a self-check).
    check(
        Status::Ok,
        "rules & suites",
        &format!(
            "{} scan rules, {} built-in suites",
            rules::all_rule_ids().len(),
            suites::all().len()
        ),
    );

    // 6. Detected project ecosystems (informational).
    let config = Config::load(&root).unwrap_or_default();
    let scan = scanner::scan(&root, &config);
    let ecosystems = dependencies::DependencyReport::build(&scan.files).ecosystem_counts();
    if ecosystems.is_empty() {
        check(
            Status::Warn,
            "project type",
            "no supported manifest found (Cargo.toml, package.json, requirements.txt, go.mod, pom.xml, *.csproj)",
        );
    } else {
        let list = ecosystems
            .iter()
            .map(|(e, n)| format!("{e} ({n})"))
            .collect::<Vec<_>>()
            .join(", ");
        check(Status::Ok, "project type", &list);
    }

    println!();
    if problems == 0 {
        println!("{}", "✓ Killer is healthy.".green().bold());
        Ok(ExitCode::SUCCESS)
    } else {
        println!(
            "{}",
            format!("✗ {problems} problem(s) found — see above.")
                .red()
                .bold()
        );
        Ok(ExitCode::FAILURE)
    }
}

/// Status of a single doctor check.
enum Status {
    Ok,
    Warn,
    Fail,
}

/// Print one doctor check line.
fn check(status: Status, label: &str, detail: &str) {
    let mark = match status {
        Status::Ok => "✓".green(),
        Status::Warn => "⚠".yellow(),
        Status::Fail => "✗".red().bold(),
    };
    println!("  {mark} {}  {}", label.bold(), detail.dimmed());
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
