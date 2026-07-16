//! Executes static `.klr` rules over scanned source files.
//!
//! The rule language is intentionally high-level ("when a line contains a query
//! and input reaches it without sanitization"). This engine implements those
//! clauses as line-level heuristics: it is a pragmatic first pass, not a full
//! dataflow analysis (that arrives with Tree-sitter in a later phase).

use crate::attacks::database;
use crate::klr::ast::KlrRule;
use crate::results::RuleFinding;
use crate::scanner::FileData;

/// Run every rule over every file and collect findings.
pub fn run_rules(rules: &[KlrRule], files: &[FileData]) -> Vec<RuleFinding> {
    let mut findings = Vec::new();
    for rule in rules {
        // A rule with no matching criteria would flag everything; skip it.
        if rule.contains.is_empty() && rule.reaches.is_none() {
            continue;
        }
        for file in files {
            for (line_no, line) in file.numbered_lines() {
                if is_comment_only(line) {
                    continue;
                }
                if line_matches(rule, line) {
                    findings.push(RuleFinding {
                        rule: rule.name.clone(),
                        severity: rule.severity.label().to_string(),
                        file: file.path.clone(),
                        line: line_no,
                        message: rule.report.clone().unwrap_or_else(|| rule.name.clone()),
                    });
                }
            }
        }
    }
    findings
}

/// Whether a line is entirely a comment (best-effort, language-agnostic).
fn is_comment_only(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with('#') || t.starts_with("//") || t.starts_with('*') || t.starts_with("/*")
}

/// Whether a single line satisfies a rule's clauses.
fn line_matches(rule: &KlrRule, line: &str) -> bool {
    let lower = line.to_ascii_lowercase();

    // `when ... contains "X"` — all needles must be present.
    for needle in &rule.contains {
        if !lower.contains(&needle.to_ascii_lowercase()) {
            return false;
        }
    }

    // `input reaches Y` — the sink must be present *and* untrusted data must
    // reach it (a direct input source or dynamic string construction).
    if let Some(sink) = &rule.reaches {
        if !lower.contains(&sink.to_ascii_lowercase()) {
            return false;
        }
        if !database::line_reaches_sink(line) {
            return false;
        }
    }

    // `without sanitization` — the line must not look sanitized/parameterized.
    if !rule.without.is_empty() && database::line_is_sanitized(line) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::klr::parser::parse;
    use crate::scanner::Language;

    fn file(content: &str) -> FileData {
        FileData {
            path: "db.py".into(),
            content: content.into(),
            lines: content.lines().count(),
            language: Language::Python,
        }
    }

    fn unsafe_rule() -> Vec<KlrRule> {
        let src = r#"
rule "unsafe database query"
when function contains "query"
and input reaches query
without sanitization
severity high
report: "User input reaches database directly"
"#;
        parse(src).unwrap().rules
    }

    #[test]
    fn flags_unsanitized_query_with_input() {
        let rules = unsafe_rule();
        let f = file("cursor.query(\"SELECT * FROM u WHERE id=\" + request.params['id'])\n");
        let findings = run_rules(&rules, std::slice::from_ref(&f));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].message, "User input reaches database directly");
    }

    #[test]
    fn ignores_sanitized_query() {
        let rules = unsafe_rule();
        let f = file("cursor.query(\"SELECT * FROM u WHERE id=?\", [request.params['id']])\n");
        assert!(run_rules(&rules, std::slice::from_ref(&f)).is_empty());
    }

    #[test]
    fn ignores_query_without_input() {
        let rules = unsafe_rule();
        let f = file("cursor.query(\"SELECT 1\")\n");
        assert!(run_rules(&rules, std::slice::from_ref(&f)).is_empty());
    }
}
