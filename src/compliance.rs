//! The compliance-mapping engine behind `killer compliance`.
//!
//! This maps the findings Killer actually produces onto security frameworks —
//! today OWASP Top 10 (2021), with a CWE reference per mapped finding. It is a
//! *mapping*, not an audit: a category is only marked `Passed` when Killer has
//! a rule that covers it and that rule found nothing; categories Killer cannot
//! detect are reported as `NotAssessed` rather than silently "passing".
//!
//! The mapping table lives in `mappings/compliance.toml`, embedded at build
//! time. Extend coverage by editing that file — no code change required.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// The embedded mapping table.
const MAPPINGS_TOML: &str = include_str!("../mappings/compliance.toml");

#[derive(Debug, Deserialize)]
struct MappingFile {
    #[serde(default)]
    category: Vec<OwaspCategory>,
    #[serde(default)]
    mapping: Vec<Mapping>,
}

/// One framework category (e.g. an OWASP Top 10 entry).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OwaspCategory {
    pub id: String,
    pub title: String,
}

/// A mapping from a Killer finding id to a framework reference.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Mapping {
    /// A scan rule id (`hardcoded-secret`) or a `.klr` issue id (`KLR-SQLI`).
    pub key: String,
    pub owasp: String,
    pub cwe: String,
    pub cwe_title: String,
}

/// How a framework category came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CategoryStatus {
    /// A mapped finding was detected.
    Warning,
    /// Killer covers this category and found nothing.
    Passed,
    /// Killer has no rule that maps to this category.
    NotAssessed,
}

impl CategoryStatus {
    pub fn label(self) -> &'static str {
        match self {
            CategoryStatus::Warning => "Warning",
            CategoryStatus::Passed => "Passed",
            CategoryStatus::NotAssessed => "Not assessed",
        }
    }
}

/// The outcome for one framework category.
#[derive(Debug, Clone, Serialize)]
pub struct CategoryResult {
    pub id: String,
    pub title: String,
    pub status: CategoryStatus,
    /// Human-readable reasons for a `Warning`.
    pub reasons: Vec<String>,
}

/// A CWE reference surfaced by the detected findings.
#[derive(Debug, Clone, Serialize)]
pub struct CweRef {
    pub id: String,
    pub title: String,
    pub count: usize,
}

/// The full compliance report.
#[derive(Debug, Clone, Serialize)]
pub struct ComplianceReport {
    pub framework: String,
    pub categories: Vec<CategoryResult>,
    pub cwes: Vec<CweRef>,
    /// How many finding ids were considered.
    pub findings_considered: usize,
}

impl ComplianceReport {
    pub fn warnings(&self) -> usize {
        self.categories
            .iter()
            .filter(|c| c.status == CategoryStatus::Warning)
            .count()
    }
}

/// Parse the embedded mapping table. The parse is validated by a test, so a
/// failure here means the embedded file was edited into an invalid state.
fn load() -> MappingFile {
    toml::from_str(MAPPINGS_TOML).expect("embedded mappings/compliance.toml must be valid TOML")
}

/// Assess a set of detected finding ids against the framework.
///
/// `finding_keys` are scan rule ids and/or `.klr` issue ids; duplicates are
/// meaningful for CWE counts (three SQLi findings → CWE-89 count 3).
pub fn assess(finding_keys: &[String]) -> ComplianceReport {
    let data = load();

    // Categories Killer can actually cover (some mapping targets them).
    let coverable: BTreeSet<&str> = data.mapping.iter().map(|m| m.owasp.as_str()).collect();
    let present: BTreeSet<&str> = finding_keys.iter().map(String::as_str).collect();

    let mut categories = Vec::new();
    for cat in &data.category {
        let mut reasons = Vec::new();
        for m in &data.mapping {
            if m.owasp == cat.id && present.contains(m.key.as_str()) {
                reasons.push(format!("{} ({})", m.cwe_title, m.key));
            }
        }
        let status = if !reasons.is_empty() {
            CategoryStatus::Warning
        } else if coverable.contains(cat.id.as_str()) {
            CategoryStatus::Passed
        } else {
            CategoryStatus::NotAssessed
        };
        categories.push(CategoryResult {
            id: cat.id.clone(),
            title: cat.title.clone(),
            status,
            reasons,
        });
    }

    // CWE references, counted across every detected finding.
    let mut cwe_counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    for key in finding_keys {
        if let Some(m) = data.mapping.iter().find(|m| &m.key == key) {
            *cwe_counts
                .entry((m.cwe.clone(), m.cwe_title.clone()))
                .or_default() += 1;
        }
    }
    let cwes = cwe_counts
        .into_iter()
        .map(|((id, title), count)| CweRef { id, title, count })
        .collect();

    ComplianceReport {
        framework: "OWASP Top 10 (2021)".to_string(),
        categories,
        cwes,
        findings_considered: finding_keys.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mappings_file_parses_and_has_ten_categories() {
        let data = load();
        assert_eq!(data.category.len(), 10);
        assert!(data.mapping.iter().any(|m| m.key == "KLR-SQLI"));
    }

    #[test]
    fn detected_injection_marks_a03_warning_with_cwe() {
        let report = assess(&["KLR-SQLI".to_string(), "dangerous-command".to_string()]);
        let a03 = report
            .categories
            .iter()
            .find(|c| c.id == "A03:2021")
            .unwrap();
        assert_eq!(a03.status, CategoryStatus::Warning);
        assert_eq!(a03.reasons.len(), 2); // SQLi + OS command
        assert!(report.cwes.iter().any(|c| c.id == "CWE-89"));
    }

    #[test]
    fn covered_but_clean_category_passes() {
        // No injection findings → A03 is covered by Killer and clean → Passed.
        let report = assess(&["hardcoded-secret".to_string()]);
        let a03 = report
            .categories
            .iter()
            .find(|c| c.id == "A03:2021")
            .unwrap();
        assert_eq!(a03.status, CategoryStatus::Passed);
        // A07 (hard-coded creds) should warn.
        let a07 = report
            .categories
            .iter()
            .find(|c| c.id == "A07:2021")
            .unwrap();
        assert_eq!(a07.status, CategoryStatus::Warning);
    }

    #[test]
    fn uncoverable_category_is_not_assessed_not_passed() {
        // A10 (SSRF) has no Killer rule → must never be reported as Passed.
        let report = assess(&[]);
        let a10 = report
            .categories
            .iter()
            .find(|c| c.id == "A10:2021")
            .unwrap();
        assert_eq!(a10.status, CategoryStatus::NotAssessed);
    }

    #[test]
    fn cwe_counts_reflect_repeat_findings() {
        let report = assess(&[
            "hardcoded-secret".to_string(),
            "hardcoded-secret".to_string(),
        ]);
        let cwe = report.cwes.iter().find(|c| c.id == "CWE-798").unwrap();
        assert_eq!(cwe.count, 2);
    }
}
