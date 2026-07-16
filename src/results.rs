//! Test-result types and on-disk storage.
//!
//! A [`TestRun`] captures the outcome of executing one or more `.klr` files:
//! each attack's verdict plus any static-rule findings. Runs are serialized to
//! JSON under `.killer/results/` so they can be reviewed or diffed over time.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The verdict for a single attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// The system behaved as a secure system should (all expectations held).
    Secure,
    /// At least one expectation failed — a vulnerability is indicated.
    Vulnerable,
    /// The attack could not be executed (e.g. connection refused).
    Errored,
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Secure => "PASSED",
            Verdict::Vulnerable => "FAILED",
            Verdict::Errored => "ERROR",
        }
    }
}

/// The result of evaluating a single expectation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Human-readable description of the expectation, e.g. `status != 200`.
    pub description: String,
    /// Whether the secure behavior held.
    pub passed: bool,
    /// Whether this check was actually evaluated (vs. skipped/unsupported).
    pub evaluated: bool,
    /// Detail about what was observed.
    pub detail: String,
}

/// The outcome of one attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackOutcome {
    pub name: String,
    /// The suite this attack belonged to, if any.
    #[serde(default)]
    pub suite: Option<String>,
    pub severity: String,
    /// Resolved request line, e.g. `POST http://127.0.0.1:8080/api/login`.
    pub target: String,
    pub verdict: Verdict,
    pub message: Option<String>,
    pub checks: Vec<CheckResult>,
    /// Set when `verdict == Errored`.
    pub error: Option<String>,
    /// A short id used with `killer explain`, e.g. `KLR-SQLI`.
    pub issue_id: Option<String>,
}

/// A finding produced by a static `.klr` rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFinding {
    pub rule: String,
    pub severity: String,
    pub file: String,
    pub line: usize,
    pub message: String,
}

/// The full result of a `killer test` invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRun {
    pub project: Option<String>,
    /// Human-readable timestamp (UTC-ish, from the system clock).
    pub timestamp: String,
    /// The `.klr` files that were executed.
    pub sources: Vec<String>,
    pub attacks: Vec<AttackOutcome>,
    pub rule_findings: Vec<RuleFinding>,
    /// Number of worker threads used to run the attacks.
    #[serde(default = "one")]
    pub workers: usize,
    /// Wall-clock time spent executing attacks, in milliseconds.
    #[serde(default)]
    pub elapsed_ms: u128,
}

fn one() -> usize {
    1
}

impl TestRun {
    /// Number of attacks with a vulnerable verdict.
    pub fn vulnerable_count(&self) -> usize {
        self.attacks
            .iter()
            .filter(|a| a.verdict == Verdict::Vulnerable)
            .count()
    }

    /// Number of attacks that errored.
    pub fn error_count(&self) -> usize {
        self.attacks
            .iter()
            .filter(|a| a.verdict == Verdict::Errored)
            .count()
    }

    /// Whether any attack indicated a vulnerability.
    pub fn has_vulnerabilities(&self) -> bool {
        self.vulnerable_count() > 0
    }

    /// Persist this run as JSON under `<root>/.killer/results/`.
    ///
    /// The file name is derived from `slug`, which the caller keeps
    /// deterministic (e.g. a timestamp) so results sort chronologically.
    pub fn save(&self, root: &Path, slug: &str) -> Result<PathBuf> {
        let dir = root.join(".killer").join("results");
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
        let safe: String = slug
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        let path = dir.join(format!("{safe}.json"));
        let json = serde_json::to_string_pretty(self).context("failed to serialize results")?;
        std::fs::write(&path, json)
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(path)
    }
}
