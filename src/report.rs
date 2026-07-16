//! Report generation and terminal rendering.

use std::collections::BTreeMap;

use colored::Colorize;

use crate::analyzer::{Category, Finding, Severity};
use crate::intelligence::{Snapshot, Trend};
use crate::results::{TestRun, Verdict};
use crate::scanner::ProjectStats;

/// A complete analysis report: project stats plus findings.
pub struct Report {
    pub project_name: String,
    pub stats: ProjectStats,
    pub findings: Vec<Finding>,
}

/// Counts of findings by severity.
#[derive(Debug, Default, Clone, Copy)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub warning: usize,
    pub info: usize,
}

impl SeverityCounts {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.warning + self.info
    }
}

impl Report {
    pub fn new(project_name: String, stats: ProjectStats, findings: Vec<Finding>) -> Self {
        Report {
            project_name,
            stats,
            findings,
        }
    }

    /// Tally findings by severity.
    pub fn severity_counts(&self) -> SeverityCounts {
        let mut c = SeverityCounts::default();
        for f in &self.findings {
            match f.severity {
                Severity::Critical => c.critical += 1,
                Severity::High => c.high += 1,
                Severity::Warning => c.warning += 1,
                Severity::Info => c.info += 1,
            }
        }
        c
    }

    /// Compute a 0–100 health score by deducting weighted points per finding.
    pub fn score(&self) -> u32 {
        let deduction: u32 = self
            .findings
            .iter()
            .map(|f| f.severity.score_weight())
            .sum();
        100u32.saturating_sub(deduction)
    }

    /// Whether the run should be considered a failure (any critical/high issue).
    pub fn has_blocking_issues(&self) -> bool {
        self.findings
            .iter()
            .any(|f| matches!(f.severity, Severity::Critical | Severity::High))
    }

    /// Render the full report to a colored string for the terminal.
    pub fn render_terminal(&self) -> String {
        let mut out = String::new();
        let counts = self.severity_counts();

        let rule = "=".repeat(52);
        out.push_str(&format!("\n{}\n\n", rule.dimmed()));
        out.push_str(&format!("{}\n\n", "KILLER REPORT".bold()));

        // Summary block.
        out.push_str(&format!("{}  {}\n", "Project:".bold(), self.project_name));
        out.push_str(&format!(
            "{}  {}\n",
            "Files scanned:".bold(),
            self.stats.files
        ));
        out.push_str(&format!(
            "{}  {}\n",
            "Lines of code:".bold(),
            self.stats.lines_of_code
        ));
        let langs = if self.stats.languages.is_empty() {
            "—".to_string()
        } else {
            self.stats.languages.join(", ")
        };
        out.push_str(&format!("{}  {}\n", "Languages:".bold(), langs));
        out.push_str(&format!(
            "{}  {}\n\n",
            "Issues found:".bold(),
            counts.total()
        ));

        // Findings grouped by category.
        if self.findings.is_empty() {
            out.push_str(&format!(
                "{}\n\n",
                "No issues found. Clean scan!".green().bold()
            ));
        } else {
            let mut by_category: BTreeMap<Category, Vec<&Finding>> = BTreeMap::new();
            for f in &self.findings {
                by_category.entry(f.category).or_default().push(f);
            }

            for (category, findings) in &by_category {
                out.push_str(&format!("{}\n", category.title().bold().underline()));
                for f in findings {
                    out.push_str(&render_finding(f));
                }
                out.push('\n');
            }
        }

        // Severity breakdown, as a small horizontal bar chart.
        out.push_str(&format!("{}\n", "Summary".bold()));
        let max = counts
            .critical
            .max(counts.high)
            .max(counts.warning)
            .max(counts.info)
            .max(1);
        let bar = |n: usize| -> String {
            let w = if n == 0 { 0 } else { ((n * 24) / max).max(1) };
            "█".repeat(w)
        };
        out.push_str(&format!(
            "  {:<9}{} {}\n",
            "Critical",
            bar(counts.critical).red().bold(),
            counts.critical
        ));
        out.push_str(&format!(
            "  {:<9}{} {}\n",
            "High",
            bar(counts.high).red(),
            counts.high
        ));
        out.push_str(&format!(
            "  {:<9}{} {}\n",
            "Warning",
            bar(counts.warning).yellow(),
            counts.warning
        ));
        out.push_str(&format!(
            "  {:<9}{} {}\n\n",
            "Info",
            bar(counts.info).blue(),
            counts.info
        ));

        // Score.
        let score = self.score();
        let score_str = format!("{score}/100");
        let colored_score = if score >= 80 {
            score_str.green().bold()
        } else if score >= 50 {
            score_str.yellow().bold()
        } else {
            score_str.red().bold()
        };
        out.push_str(&format!("{}  {}\n\n", "Score:".bold(), colored_score));
        out.push_str(&format!("{}\n", rule.dimmed()));

        out
    }
}

/// Render a single finding line, e.g. `  ❌ Hardcoded secret  config.js:12`.
fn render_finding(f: &Finding) -> String {
    let (symbol, colored_title) = match f.severity {
        Severity::Critical => ("❌", f.title.red().bold()),
        Severity::High => ("⚠", f.title.red()),
        Severity::Warning => ("⚠", f.title.yellow()),
        Severity::Info => ("•", f.title.blue()),
    };

    let location = if f.line > 0 {
        format!("{}:{}", f.file, f.line)
    } else {
        f.file.clone()
    };

    let mut s = format!("  {} {}  {}\n", symbol, colored_title, location.dimmed());
    s.push_str(&format!("      {}\n", f.message.dimmed()));
    s
}

/// Render a [`TestRun`] as a Jest-like "KILLER TEST REPORT" for the terminal,
/// grouping attacks by suite and listing pass/fail per test.
pub fn render_attack_report(run: &TestRun) -> String {
    let mut out = String::new();
    let rule = "=".repeat(52);

    out.push_str(&format!("\n{}\n\n", rule.dimmed()));
    out.push_str(&format!("{}\n\n", "KILLER TEST REPORT".bold()));

    if let Some(project) = &run.project {
        out.push_str(&format!("{}  {}\n", "Project:".bold(), project));
    }
    if !run.sources.is_empty() {
        out.push_str(&format!(
            "{}  {}\n",
            "Sources:".bold(),
            run.sources.join(", ")
        ));
    }
    if run.workers > 1 {
        out.push_str(&format!("{}  {}\n", "Workers:".bold(), run.workers));
    }
    out.push('\n');

    // Group attacks by suite, preserving order; unsuited attacks go under "Tests".
    let mut order: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, Vec<&crate::results::AttackOutcome>> = BTreeMap::new();
    for a in &run.attacks {
        let key = a.suite.clone().unwrap_or_else(|| "Tests".to_string());
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(a);
    }

    for suite in &order {
        out.push_str(&format!("{}\n", suite.bold().underline()));
        for a in &groups[suite] {
            let (mark, name_col) = match a.verdict {
                Verdict::Secure => ("✓".green(), a.name.normal()),
                Verdict::Vulnerable => ("✗".red().bold(), a.name.red()),
                Verdict::Errored => ("!".yellow(), a.name.yellow()),
            };
            out.push_str(&format!("  {mark} {name_col}\n"));

            if a.verdict == Verdict::Vulnerable {
                // Show the failing checks and the issue hint.
                for c in a.checks.iter().filter(|c| c.evaluated && !c.passed) {
                    out.push_str(&format!(
                        "      {} {}  {}\n",
                        "✗".red(),
                        c.description,
                        c.detail.dimmed()
                    ));
                }
                if let Some(id) = &a.issue_id {
                    out.push_str(&format!(
                        "      {}\n",
                        format!("→ killer explain {id}").dimmed()
                    ));
                }
            }
            if let Some(err) = &a.error {
                out.push_str(&format!(
                    "      {} {}\n",
                    "could not run:".yellow(),
                    err.dimmed()
                ));
            }
        }
        out.push('\n');
    }

    // Static rule findings.
    if !run.rule_findings.is_empty() {
        out.push_str(&format!("{}\n", "Static Rule Findings".bold().underline()));
        for f in &run.rule_findings {
            out.push_str(&format!(
                "  {} {}  {}\n",
                "•".yellow(),
                f.rule.bold(),
                format!("{}:{}", f.file, f.line).dimmed()
            ));
            out.push_str(&format!("      {}\n", f.message.dimmed()));
        }
        out.push('\n');
    }

    // Summary.
    let total = run.attacks.len();
    let vuln = run.vulnerable_count();
    let errored = run.error_count();
    let passed = total - vuln - errored;

    out.push_str(&format!("{}\n", "Tests:".bold()));
    out.push_str(&format!(
        "  {}  {}\n",
        passed.to_string().green().bold(),
        "passed".green()
    ));
    if vuln > 0 {
        out.push_str(&format!(
            "  {}  {}\n",
            vuln.to_string().red().bold(),
            "failed".red()
        ));
    }
    if errored > 0 {
        out.push_str(&format!(
            "  {}  {}\n",
            errored.to_string().yellow().bold(),
            "errored".yellow()
        ));
    }
    out.push_str(&format!("  {} total\n", total));
    if run.elapsed_ms > 0 {
        out.push_str(&format!(
            "\n{}  {:.2}s\n",
            "Time:".bold(),
            run.elapsed_ms as f64 / 1000.0
        ));
    }
    out.push('\n');

    let verdict_line = if vuln > 0 {
        format!(
            "{} vulnerabilit{} found",
            vuln,
            if vuln == 1 { "y" } else { "ies" }
        )
        .red()
        .bold()
    } else if errored > 0 {
        "No vulnerabilities found (some tests could not run)"
            .yellow()
            .bold()
    } else {
        "All tests passed — no vulnerabilities".green().bold()
    };
    out.push_str(&format!("{verdict_line}\n\n"));
    out.push_str(&format!("{}\n", rule.dimmed()));

    out
}

/// Render a code-review report over a set of findings on changed lines.
pub fn render_review(findings: &[Finding], files_reviewed: usize) -> String {
    let mut out = String::new();
    let rule = "=".repeat(52);

    out.push_str(&format!("\n{}\n\n", rule.dimmed()));
    out.push_str(&format!("{}\n\n", "KILLER CODE REVIEW".bold()));
    out.push_str(&format!(
        "{}  {} changed file{}\n\n",
        "Reviewed:".bold(),
        files_reviewed,
        if files_reviewed == 1 { "" } else { "s" }
    ));

    if findings.is_empty() {
        out.push_str(&format!(
            "{}\n\n",
            "No issues in the changed lines.".green().bold()
        ));
    } else {
        for f in findings {
            out.push_str(&render_finding(f));
            if let Some(s) = &f.suggestion {
                out.push_str(&format!("      {} {}\n", "→".cyan(), s.cyan()));
            }
        }
        out.push('\n');
    }

    let blocking = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
        .count();
    out.push_str(&format!("{}\n", "Summary".bold()));
    out.push_str(&format!("  {}  {}\n", "Findings:".bold(), findings.len()));
    out.push_str(&format!("  {}  {}\n\n", "Blocking:".bold(), blocking));

    let verdict = if blocking > 0 {
        format!("✗ REVIEW FAILED — {blocking} blocking issue(s)")
            .red()
            .bold()
    } else if findings.is_empty() {
        "✓ REVIEW PASSED".green().bold()
    } else {
        "✓ REVIEW PASSED (with advisories)".green().bold()
    };
    out.push_str(&format!("{verdict}\n\n"));
    out.push_str(&format!("{}\n", rule.dimmed()));
    out
}

/// Render the score-trend report (`killer history`).
pub fn render_score_history(history: &[Snapshot], trend: Option<&Trend>) -> String {
    let mut out = String::new();
    let rule = "=".repeat(52);

    out.push_str(&format!("\n{}\n\n", rule.dimmed()));
    out.push_str(&format!("{}\n\n", "KILLER SCORE".bold()));

    let Some(latest) = history.last() else {
        out.push_str("No history yet. Run `killer scan` to record the first snapshot.\n\n");
        out.push_str(&format!("{}\n", rule.dimmed()));
        return out;
    };

    let score_str = format!("{}/100", latest.security_score);
    let colored = if latest.security_score >= 80 {
        score_str.green().bold()
    } else if latest.security_score >= 50 {
        score_str.yellow().bold()
    } else {
        score_str.red().bold()
    };
    out.push_str(&format!("{}  {}\n", "Security:".bold(), colored));
    out.push_str(&format!(
        "{}  {} findings ({} critical, {} high)\n\n",
        "Current:".bold(),
        latest.total_findings,
        latest.critical,
        latest.high
    ));

    if let Some(t) = trend {
        out.push_str(&format!(
            "{} ({} snapshots)\n",
            "Since first scan".bold(),
            t.snapshot_count
        ));
        let change = if t.score_change >= 0 {
            format!("+{}", t.score_change).green().bold()
        } else {
            t.score_change.to_string().red().bold()
        };
        out.push_str(&format!("  {}   {}\n", "Change:".bold(), change));
        if t.findings_fixed > 0 {
            out.push_str(&format!(
                "  {}    {}\n",
                "Fixed:".bold(),
                format!("{} findings", t.findings_fixed).green()
            ));
        }
        if t.findings_added > 0 {
            out.push_str(&format!(
                "  {}    {}\n",
                "Added:".bold(),
                format!("{} findings", t.findings_added).red()
            ));
        }
        out.push('\n');

        // A compact score trend line.
        let spark: String = history
            .iter()
            .map(|s| sparkline_char(s.security_score))
            .collect();
        out.push_str(&format!("  {}  {}\n\n", "Trend:".bold(), spark));
    } else {
        out.push_str("Only one snapshot so far — scan again later to see a trend.\n\n");
    }

    out.push_str(&format!("{}\n", rule.dimmed()));
    out
}

/// Map a 0–100 score to a block-height sparkline character.
fn sparkline_char(score: u32) -> char {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let idx = ((score.min(100) as usize) * (BARS.len() - 1)) / 100;
    BARS[idx]
}

/// The Killer security-console banner.
/// Render a [`crate::graph::ProjectGraph`] as a terminal summary.
pub fn render_graph(graph: &crate::graph::ProjectGraph) -> String {
    let mut out = String::new();
    let rule = "=".repeat(52);
    out.push_str(&format!("\n{}\n\n", rule.dimmed()));
    out.push_str(&format!("{}\n\n", "KILLER PROJECT GRAPH".bold()));

    let used = graph.dependencies.iter().filter(|d| d.used).count();
    let unused = graph.dependencies.len() - used;
    out.push_str(&format!(
        "{}  {} importing files · {} external modules\n",
        "Imports:".bold(),
        graph.files.len(),
        graph.module_count()
    ));
    out.push_str(&format!(
        "{}  {} declared · {} used · {} possibly unused\n\n",
        "Dependencies:".bold(),
        graph.dependencies.len(),
        used,
        unused
    ));

    let top = graph.top_modules(10);
    if !top.is_empty() {
        out.push_str(&format!("{}\n", "Most-imported modules".bold().underline()));
        let width = top.iter().map(|(m, _)| m.len()).max().unwrap_or(0);
        for (module, count) in &top {
            out.push_str(&format!(
                "  {:<width$}  {} file{}\n",
                module.bold(),
                count,
                if *count == 1 { "" } else { "s" },
                width = width
            ));
        }
        out.push('\n');
    }

    let hotspots = graph.import_hotspots(5);
    if !hotspots.is_empty() {
        out.push_str(&format!("{}\n", "Import hotspots".bold().underline()));
        for (path, count) in &hotspots {
            out.push_str(&format!(
                "  {} {}  {}\n",
                "·".dimmed(),
                path,
                format!("{count} imports").dimmed()
            ));
        }
        out.push('\n');
    }

    let unused_deps = graph.unused_dependencies();
    if !unused_deps.is_empty() {
        out.push_str(&format!(
            "{}\n",
            "Possibly unused dependencies".yellow().bold().underline()
        ));
        for d in &unused_deps {
            let tag = if d.dev { " (dev)" } else { "" };
            out.push_str(&format!(
                "  {} {}{}  {}\n",
                "⚠".yellow(),
                d.name.bold(),
                tag.dimmed(),
                format!("declared in {}", d.manifest).dimmed()
            ));
        }
        out.push_str(&format!(
            "\n  {}\n",
            "Heuristic: import names are matched to declared names best-effort.".dimmed()
        ));
        out.push('\n');
    }

    if graph.files.is_empty() && graph.dependencies.is_empty() {
        out.push_str(&format!(
            "{}\n\n",
            "No imports or manifests found to graph.".dimmed()
        ));
    }

    out.push_str(&format!("{}\n", rule.dimmed()));
    out
}

/// Render the catalog of fuzz generators (`killer fuzz --list`).
pub fn render_fuzz_catalog() -> String {
    let mut out = String::new();
    out.push_str(&format!("\n{}\n\n", "FUZZ GENERATORS".bold()));
    for g in crate::fuzz::catalog() {
        out.push_str(&format!(
            "  {}  {}\n      {}\n",
            g.name.bold(),
            format!("[{}]", g.category).dimmed(),
            g.description.dimmed()
        ));
    }
    out.push_str(&format!(
        "\n{}\n",
        "Use several with: killer fuzz --generators sql_injection,huge_values --url URL".dimmed()
    ));
    out
}

/// Truncate a fuzz value for display, escaping control characters.
fn fuzz_display_value(value: &str) -> String {
    const MAX: usize = 48;
    let cleaned: String = value
        .chars()
        .map(|c| if c.is_control() { '·' } else { c })
        .collect();
    if cleaned.chars().count() > MAX {
        let head: String = cleaned.chars().take(MAX).collect();
        format!("{head}… ({} chars)", value.chars().count())
    } else if cleaned.is_empty() {
        "(empty)".to_string()
    } else {
        cleaned
    }
}

/// Render a [`crate::fuzz::FuzzReport`] as a terminal report.
pub fn render_fuzz(report: &crate::fuzz::FuzzReport) -> String {
    use crate::fuzz::HitOutcome;

    let mut out = String::new();
    let rule = "=".repeat(52);
    out.push_str(&format!("\n{}\n\n", rule.dimmed()));
    out.push_str(&format!("{}\n\n", "KILLER FUZZ REPORT".bold()));
    out.push_str(&format!("{}  {}\n", "Field:".bold(), report.field));
    match &report.target {
        Some(t) => out.push_str(&format!("{}  {} {}\n", "Target:".bold(), report.method, t)),
        None => out.push_str(&format!(
            "{}  {}\n",
            "Target:".bold(),
            "(none — dry run, inputs generated only)".dimmed()
        )),
    }
    out.push_str(&format!(
        "{}  {}\n\n",
        "Inputs:".bold(),
        report.total_inputs()
    ));

    // Generated inputs, grouped by generator.
    for preview in &report.previews {
        out.push_str(&format!(
            "{} {}\n",
            preview.generator.bold(),
            format!("[{}]", preview.category).dimmed()
        ));
        for v in &preview.values {
            out.push_str(&format!("  {} {}\n", "·".dimmed(), fuzz_display_value(v)));
        }
    }
    out.push('\n');

    // When fired at a target, summarize outcomes and list anomalies.
    if report.target.is_some() {
        let faults = report
            .hits
            .iter()
            .filter(|h| matches!(h.outcome, HitOutcome::Fault(_)))
            .count();
        let unreachable = report
            .hits
            .iter()
            .filter(|h| matches!(h.outcome, HitOutcome::Unreachable(_)))
            .count();
        let handled = report.hits.len() - faults - unreachable;

        out.push_str(&format!("{}\n", "Results".bold().underline()));
        out.push_str(&format!(
            "  {}  {}\n",
            handled.to_string().green().bold(),
            "handled cleanly".green()
        ));
        if faults > 0 {
            out.push_str(&format!(
                "  {}  {}\n",
                faults.to_string().red().bold(),
                "server faults (5xx)".red()
            ));
        }
        if unreachable > 0 {
            out.push_str(&format!(
                "  {}  {}\n",
                unreachable.to_string().yellow().bold(),
                "unreachable".yellow()
            ));
        }
        out.push('\n');

        let anomalies: Vec<_> = report.anomalies().collect();
        if !anomalies.is_empty() {
            out.push_str(&format!("{}\n", "Anomalies".bold().underline()));
            for h in anomalies {
                let (mark, detail) = match &h.outcome {
                    HitOutcome::Fault(s) => ("✗".red().bold(), format!("status {s}")),
                    HitOutcome::Unreachable(e) => ("!".yellow(), e.clone()),
                    HitOutcome::Handled(_) => continue,
                };
                out.push_str(&format!(
                    "  {mark} {}={} {}  {}\n",
                    report.field,
                    fuzz_display_value(&h.value),
                    format!("({})", h.generator).dimmed(),
                    detail.dimmed()
                ));
            }
            out.push('\n');
        }

        if report.elapsed_ms > 0 {
            out.push_str(&format!(
                "{}  {:.2}s\n\n",
                "Time:".bold(),
                report.elapsed_ms as f64 / 1000.0
            ));
        }

        let verdict = if faults > 0 || unreachable > 0 {
            format!("{} anomal{} found", faults + unreachable, {
                if faults + unreachable == 1 {
                    "y"
                } else {
                    "ies"
                }
            })
            .red()
            .bold()
        } else {
            "No anomalies — the target handled every input"
                .green()
                .bold()
        };
        out.push_str(&format!("{verdict}\n\n"));
    }

    out.push_str(&format!("{}\n", rule.dimmed()));
    out
}

pub fn banner() -> String {
    // Interior width between the vertical borders.
    const W: usize = 44;
    let bar = "│".red();

    // Build one interior row: 4-space indent + `text`, padded to width W.
    let row = |text: &str| {
        let content = format!("    {text}");
        let pad = W.saturating_sub(content.chars().count());
        (content, " ".repeat(pad))
    };

    let (l1, p1) = row("K I L L E R");
    let (l2, p2) = row(&format!(
        "Software Security Engine · v{}",
        env!("CARGO_PKG_VERSION")
    ));

    let mut s = String::new();
    s.push_str(&format!("{}\n", format!("╭{}╮", "─".repeat(W)).red()));
    s.push_str(&format!("{bar}{}{bar}\n", " ".repeat(W)));
    s.push_str(&format!("{bar}{}{p1}{bar}\n", l1.red().bold()));
    s.push_str(&format!("{bar}{}{p2}{bar}\n", l2.dimmed()));
    s.push_str(&format!("{bar}{}{bar}\n", " ".repeat(W)));
    s.push_str(&format!("{}\n", format!("╰{}╯", "─".repeat(W)).red()));
    s
}

/// Render a self-contained HTML report for a [`TestRun`]. No external assets.
pub fn render_html(run: &TestRun) -> String {
    let total = run.attacks.len();
    let vuln = run.vulnerable_count();
    let errored = run.error_count();
    let passed = total - vuln - errored;
    let project = run
        .project
        .clone()
        .unwrap_or_else(|| "Killer Project".to_string());

    let mut rows = String::new();
    let mut current_suite = String::new();
    for a in &run.attacks {
        let suite = a.suite.clone().unwrap_or_else(|| "Tests".to_string());
        if suite != current_suite {
            rows.push_str(&format!(
                "<tr class=\"suite\"><td colspan=\"3\">{}</td></tr>",
                esc(&suite)
            ));
            current_suite = suite;
        }
        let (cls, label) = match a.verdict {
            crate::results::Verdict::Secure => ("pass", "PASS"),
            crate::results::Verdict::Vulnerable => ("fail", "FAIL"),
            crate::results::Verdict::Errored => ("err", "ERROR"),
        };
        let detail = a
            .checks
            .iter()
            .filter(|c| c.evaluated && !c.passed)
            .map(|c| format!("{} ({})", esc(&c.description), esc(&c.detail)))
            .collect::<Vec<_>>()
            .join("<br>");
        rows.push_str(&format!(
            "<tr><td class=\"{cls}\">{label}</td><td>{}</td><td>{}</td></tr>",
            esc(&a.name),
            detail
        ));
    }

    let findings = if run.rule_findings.is_empty() {
        String::new()
    } else {
        let items = run
            .rule_findings
            .iter()
            .map(|f| {
                format!(
                    "<li><code>{}:{}</code> — {}</li>",
                    esc(&f.file),
                    f.line,
                    esc(&f.message)
                )
            })
            .collect::<String>();
        format!("<h2>Static rule findings</h2><ul>{items}</ul>")
    };

    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>Killer Report — {project}</title><style>\
:root{{color-scheme:light dark}}\
body{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;padding:2rem;background:#0d1117;color:#e6edf3}}\
h1{{color:#ff5c57;margin:0 0 .25rem}} .sub{{color:#8b949e;margin-bottom:1.5rem}}\
.cards{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem}}\
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem 1.5rem;min-width:120px}}\
.card .n{{font-size:2rem;font-weight:700}} .card .l{{color:#8b949e;font-size:.85rem}}\
.pass{{color:#3fb950}} .fail{{color:#f85149}} .err{{color:#d29922}}\
table{{width:100%;border-collapse:collapse;margin-top:1rem}}\
td{{padding:.5rem .75rem;border-bottom:1px solid #21262d;vertical-align:top}}\
tr.suite td{{background:#161b22;font-weight:700;color:#58a6ff}}\
td:first-child{{font-weight:700;white-space:nowrap}} code{{color:#79c0ff}}\
</style></head><body>\
<h1>KILLER TEST REPORT</h1><div class=\"sub\">{project} · {ts}</div>\
<div class=\"cards\">\
<div class=\"card\"><div class=\"n pass\">{passed}</div><div class=\"l\">passed</div></div>\
<div class=\"card\"><div class=\"n fail\">{vuln}</div><div class=\"l\">vulnerable</div></div>\
<div class=\"card\"><div class=\"n err\">{errored}</div><div class=\"l\">errored</div></div>\
<div class=\"card\"><div class=\"n\">{total}</div><div class=\"l\">total</div></div>\
</div>\
<table>{rows}</table>{findings}\
</body></html>",
        ts = esc(&run.timestamp),
    )
}

/// Minimal HTML escaping.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Category;

    fn finding(sev: Severity) -> Finding {
        Finding {
            rule: "r".into(),
            title: "t".into(),
            category: Category::Security,
            severity: sev,
            file: "f".into(),
            line: 1,
            message: "m".into(),
            suggestion: None,
        }
    }

    #[test]
    fn perfect_score_with_no_findings() {
        let r = Report::new("p".into(), ProjectStats::default(), vec![]);
        assert_eq!(r.score(), 100);
        assert!(!r.has_blocking_issues());
    }

    #[test]
    fn score_deducts_by_severity() {
        let r = Report::new(
            "p".into(),
            ProjectStats::default(),
            vec![finding(Severity::Critical)],
        );
        assert_eq!(r.score(), 75); // 100 - 25
        assert!(r.has_blocking_issues());
    }

    #[test]
    fn score_never_below_zero() {
        let findings = (0..10).map(|_| finding(Severity::Critical)).collect();
        let r = Report::new("p".into(), ProjectStats::default(), findings);
        assert_eq!(r.score(), 0);
    }

    #[test]
    fn counts_are_accurate() {
        let r = Report::new(
            "p".into(),
            ProjectStats::default(),
            vec![
                finding(Severity::Critical),
                finding(Severity::Warning),
                finding(Severity::Warning),
                finding(Severity::Info),
            ],
        );
        let c = r.severity_counts();
        assert_eq!(c.critical, 1);
        assert_eq!(c.warning, 2);
        assert_eq!(c.info, 1);
        assert_eq!(c.total(), 4);
    }
}
