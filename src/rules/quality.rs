//! Quality rules: large files, TODO/FIXME tracking, and basic duplicate code.

use std::collections::HashMap;

use crate::analyzer::{Category, Finding, Rule, Severity};
use crate::scanner::FileData;

/// Flags files that exceed a configurable line-count threshold.
pub struct LargeFileRule {
    threshold: usize,
}

impl LargeFileRule {
    pub fn new(threshold: usize) -> Self {
        LargeFileRule {
            threshold: threshold.max(1),
        }
    }
}

impl Rule for LargeFileRule {
    fn id(&self) -> &str {
        "large-file"
    }

    fn name(&self) -> &str {
        "Large File"
    }

    fn description(&self) -> &str {
        "Flags files that are large enough to be worth splitting into modules."
    }

    fn category(&self) -> Category {
        Category::Quality
    }

    fn check(&self, file: &FileData) -> Vec<Finding> {
        if file.lines <= self.threshold {
            return Vec::new();
        }
        vec![Finding {
            rule: self.id().to_string(),
            title: "Large file detected".to_string(),
            category: Category::Quality,
            severity: Severity::Warning,
            file: file.path.clone(),
            line: 0,
            message: format!(
                "{} lines (threshold {}). Large files are harder to navigate and review.",
                file.lines, self.threshold
            ),
            suggestion: Some(
                "Split into smaller modules with focused responsibilities.".to_string(),
            ),
        }]
    }
}

// ---------------------------------------------------------------------------

/// Tracks `TODO` and `FIXME` markers left in the code.
pub struct TodoTrackerRule;

impl TodoTrackerRule {
    pub fn new() -> Self {
        TodoTrackerRule
    }
}

impl Default for TodoTrackerRule {
    fn default() -> Self {
        Self::new()
    }
}

const MARKERS: &[(&str, Severity)] = &[
    ("FIXME", Severity::Warning),
    ("XXX", Severity::Warning),
    ("HACK", Severity::Warning),
    ("TODO", Severity::Info),
];

impl Rule for TodoTrackerRule {
    fn id(&self) -> &str {
        "todo-tracker"
    }

    fn name(&self) -> &str {
        "TODO / FIXME"
    }

    fn description(&self) -> &str {
        "Surfaces TODO, FIXME, HACK, and XXX markers so they aren't forgotten."
    }

    fn category(&self) -> Category {
        Category::Quality
    }

    fn check(&self, file: &FileData) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (line_no, line) in file.numbered_lines() {
            for (marker, severity) in MARKERS {
                if let Some(pos) = find_marker(line, marker) {
                    let note = line[pos + marker.len()..]
                        .trim_start_matches([':', ' ', '-', ')'])
                        .trim();
                    let message = if note.is_empty() {
                        format!("{marker} marker")
                    } else {
                        format!("{marker}: {note}")
                    };
                    findings.push(Finding {
                        rule: self.id().to_string(),
                        title: format!("{marker} comment"),
                        category: Category::Quality,
                        severity: *severity,
                        file: file.path.clone(),
                        line: line_no,
                        message,
                        suggestion: None,
                    });
                    break; // report the highest-priority marker on the line once
                }
            }
        }
        findings
    }
}

/// Find a marker as a standalone token (bounded by non-alphanumeric chars).
fn find_marker(line: &str, marker: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mlen = marker.len();
    let mut from = 0;
    while let Some(rel) = line[from..].find(marker) {
        let idx = from + rel;
        let before_ok = idx == 0 || !bytes[idx - 1].is_ascii_alphanumeric();
        let after_idx = idx + mlen;
        let after_ok = after_idx >= bytes.len() || !bytes[after_idx].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return Some(idx);
        }
        from = idx + mlen;
    }
    None
}

// ---------------------------------------------------------------------------

/// Basic duplicate-code detection: finds blocks of consecutive, non-trivial
/// lines that appear more than once within the same file.
pub struct DuplicateCodeRule {
    block_size: usize,
}

impl DuplicateCodeRule {
    pub fn new() -> Self {
        DuplicateCodeRule { block_size: 6 }
    }

    /// Construct with a custom block size (number of lines per window).
    pub fn with_block_size(block_size: usize) -> Self {
        DuplicateCodeRule {
            block_size: block_size.max(2),
        }
    }
}

impl Default for DuplicateCodeRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DuplicateCodeRule {
    fn id(&self) -> &str {
        "duplicate-code"
    }

    fn name(&self) -> &str {
        "Duplicate Code"
    }

    fn description(&self) -> &str {
        "Detects repeated blocks of consecutive lines that may be worth extracting."
    }

    fn category(&self) -> Category {
        Category::Quality
    }

    fn check(&self, file: &FileData) -> Vec<Finding> {
        // Normalize lines: trim whitespace and drop blank / trivial lines while
        // remembering the original 1-indexed line number of each kept line.
        let kept: Vec<(usize, String)> = file
            .content
            .lines()
            .enumerate()
            .map(|(i, l)| (i + 1, l.trim().to_string()))
            .filter(|(_, l)| is_significant(l))
            .collect();

        if kept.len() < self.block_size * 2 {
            return Vec::new();
        }

        // Map a normalized block signature -> the line number of its first
        // occurrence. When we see the same signature again, report a duplicate.
        let mut first_seen: HashMap<String, usize> = HashMap::new();
        let mut reported: Vec<(usize, usize)> = Vec::new();
        let mut findings = Vec::new();

        for window in kept.windows(self.block_size) {
            let signature = window
                .iter()
                .map(|(_, l)| l.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            let start_line = window[0].0;

            if let Some(&orig) = first_seen.get(&signature) {
                // Avoid reporting heavily overlapping windows repeatedly.
                if reported
                    .iter()
                    .any(|&(_, s)| start_line.abs_diff(s) < self.block_size)
                {
                    continue;
                }
                reported.push((orig, start_line));
                findings.push(Finding {
                    rule: self.id().to_string(),
                    title: "Duplicate code block".to_string(),
                    category: Category::Quality,
                    severity: Severity::Info,
                    file: file.path.clone(),
                    line: start_line,
                    message: format!(
                        "{}-line block duplicates one starting at line {orig}. Consider extracting a shared function.",
                        self.block_size
                    ),
                    suggestion: Some("Extract the repeated logic into a reusable function.".to_string()),
                });
            } else {
                first_seen.insert(signature, start_line);
            }
        }

        findings
    }
}

/// Whether a normalized line is meaningful enough to count toward duplication.
/// Filters out blank lines, lone braces/brackets, and short punctuation.
fn is_significant(line: &str) -> bool {
    if line.len() < 4 {
        return false;
    }
    // Ignore lines that are only structural punctuation.
    line.chars().any(|c| c.is_alphanumeric())
        && !matches!(line, "{" | "}" | "()" | "();" | "});" | "})")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Language;

    fn file(content: &str) -> FileData {
        FileData {
            path: "test".into(),
            content: content.into(),
            lines: content.lines().count(),
            language: Language::Rust,
        }
    }

    #[test]
    fn large_file_triggers_over_threshold() {
        let content = "x\n".repeat(1500);
        let f = file(&content);
        let findings = LargeFileRule::new(1000).check(&f);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn small_file_is_fine() {
        let f = file("fn main() {}\n");
        assert!(LargeFileRule::new(1000).check(&f).is_empty());
    }

    #[test]
    fn finds_todo_and_fixme() {
        let f = file("// TODO: refactor this\nlet x = 1; // FIXME broken\n");
        let findings = TodoTrackerRule::new().check(&f);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn todo_requires_word_boundary() {
        // "TODOMATIC" should not match.
        let f = file("let TODOMATIC = 1;\n");
        assert!(TodoTrackerRule::new().check(&f).is_empty());
    }

    #[test]
    fn detects_duplicate_block() {
        let block = "let alpha = compute_value(1);\nlet beta = compute_value(2);\nlet gamma = combine(alpha, beta);\nprintln!(\"result {}\", gamma);\nlog_metric(gamma);\nsave_to_disk(gamma);\n";
        let content = format!("{block}\n// separator line here\n\n{block}");
        let f = file(&content);
        let findings = DuplicateCodeRule::with_block_size(6).check(&f);
        assert!(!findings.is_empty(), "expected a duplicate block finding");
    }

    #[test]
    fn no_duplicate_in_unique_code() {
        let content = (0..40)
            .map(|i| format!("let variable_{i} = compute({i});"))
            .collect::<Vec<_>>()
            .join("\n");
        let f = file(&content);
        assert!(DuplicateCodeRule::new().check(&f).is_empty());
    }
}
