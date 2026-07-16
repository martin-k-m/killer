//! The analysis core: the [`Rule`] trait, the [`Finding`] type, and the
//! [`Analyzer`] that runs a set of rules over scanned files.

use std::fmt;

use crate::config::Config;
use crate::scanner::{FileData, ScanResult};

/// Severity of a finding, ordered from most to least serious.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// A serious issue that should block a release (e.g. an exposed secret).
    Critical,
    /// A likely-dangerous issue worth reviewing.
    High,
    /// A quality concern.
    Warning,
    /// Informational; low priority.
    Info,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Warning => "WARNING",
            Severity::Info => "INFO",
        }
    }

    /// Parse a severity word as used in `.klr` files and config.
    ///
    /// Recognizes `critical`, `high`, `medium`/`warning`, and `low`/`info`
    /// (case-insensitive). Unknown words map to `None`.
    pub fn from_word(word: &str) -> Option<Severity> {
        match word.to_ascii_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" | "warning" | "warn" => Some(Severity::Warning),
            "low" | "info" | "informational" => Some(Severity::Info),
            _ => None,
        }
    }

    /// Points deducted from the 100-point health score per occurrence.
    pub fn score_weight(&self) -> u32 {
        match self {
            Severity::Critical => 25,
            Severity::High => 10,
            Severity::Warning => 3,
            Severity::Info => 1,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The broad category a rule belongs to, used to group report output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    Security,
    Quality,
    Dependencies,
}

impl Category {
    pub fn title(&self) -> &'static str {
        match self {
            Category::Security => "Security",
            Category::Quality => "Quality",
            Category::Dependencies => "Dependencies",
        }
    }
}

/// A single issue reported by a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The stable id of the rule that produced this finding.
    pub rule: String,
    /// A short human-readable title for the finding.
    pub title: String,
    pub category: Category,
    pub severity: Severity,
    /// File path relative to the scan root.
    pub file: String,
    /// 1-indexed line number (0 if not line-specific).
    pub line: usize,
    /// Detailed message explaining the finding.
    pub message: String,
    /// Optional remediation suggestion.
    pub suggestion: Option<String>,
}

/// A lint/security rule. Implementations inspect a single file and return any
/// findings. Rules must be stateless and cheap to construct so the analyzer can
/// run them across every file.
pub trait Rule: Send + Sync {
    /// Stable identifier (kebab-case), used in config toggles and output.
    fn id(&self) -> &str;

    /// Human-readable name.
    fn name(&self) -> &str;

    /// One-line description of what the rule detects.
    fn description(&self) -> &str;

    /// The category this rule reports under.
    fn category(&self) -> Category;

    /// Inspect a file and return any findings.
    fn check(&self, file: &FileData) -> Vec<Finding>;
}

/// Runs a collection of rules over a set of scanned files.
pub struct Analyzer {
    rules: Vec<Box<dyn Rule>>,
}

impl Analyzer {
    /// Build an analyzer with the given rules.
    pub fn new(rules: Vec<Box<dyn Rule>>) -> Self {
        Analyzer { rules }
    }

    /// Build the default analyzer, honoring which rules are enabled in `config`.
    pub fn with_default_rules(config: &Config) -> Self {
        let rules = crate::rules::default_rules(config);
        Analyzer::new(rules)
    }

    /// Number of active rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Run every rule over every file and collect all findings, sorted by
    /// severity (most serious first), then file, then line.
    pub fn analyze(&self, scan: &ScanResult) -> Vec<Finding> {
        self.analyze_files(&scan.files)
    }

    /// Run every rule over the given files and collect all findings, sorted by
    /// severity (most serious first), then file, then line.
    pub fn analyze_files(&self, files: &[FileData]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for file in files {
            for rule in &self.rules {
                findings.extend(rule.check(file));
            }
        }
        findings.sort_by(|a, b| {
            a.severity
                .cmp(&b.severity)
                .then_with(|| a.file.cmp(&b.file))
                .then_with(|| a.line.cmp(&b.line))
        });
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Warning);
        assert!(Severity::Warning < Severity::Info);
    }

    #[test]
    fn score_weights_decrease_with_severity() {
        assert!(Severity::Critical.score_weight() > Severity::High.score_weight());
        assert!(Severity::High.score_weight() > Severity::Warning.score_weight());
        assert!(Severity::Warning.score_weight() > Severity::Info.score_weight());
    }
}
