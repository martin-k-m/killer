//! The Code Review Engine.
//!
//! `killer review` looks at what a change *added* (via `git diff`) and reviews
//! only those lines. It combines two sources of findings:
//!
//! 1. the existing Phase 1 rules (secrets, dangerous commands, …), restricted
//!    to added lines, and
//! 2. review-specific heuristics — currently concurrency/transaction safety,
//!    e.g. an unguarded `balance -= amount` that can race.

use std::collections::HashSet;
use std::path::Path;

use crate::analyzer::{Analyzer, Category, Finding, Severity};
use crate::config::Config;
use crate::git::ChangedFile;
use crate::scanner::{FileData, Language};

/// Review the added lines of `changed` files under `root`.
pub fn review(root: &Path, changed: &[ChangedFile], config: &Config) -> Vec<Finding> {
    let analyzer = Analyzer::with_default_rules(config);
    let mut findings = Vec::new();

    for cf in changed {
        let full = root.join(&cf.path);
        let content = match std::fs::read_to_string(&full) {
            Ok(c) => c,
            Err(_) => continue, // deleted, binary, or unreadable
        };

        let added_lines: HashSet<usize> = cf.added.iter().map(|(n, _)| *n).collect();
        let file = FileData {
            path: cf.path.clone(),
            lines: content.lines().count(),
            language: Language::from_path(&full),
            content,
        };

        // 1. Existing rules, but only findings landing on added lines.
        for f in analyzer.analyze_files(std::slice::from_ref(&file)) {
            if f.line > 0 && added_lines.contains(&f.line) {
                findings.push(f);
            }
        }

        // 2. Review heuristics over each added line.
        for (line_no, text) in &cf.added {
            if let Some(f) = concurrency_check(text, file.language, &cf.path, *line_no) {
                findings.push(f);
            }
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

/// Identifiers whose in-place mutation is state that typically needs a lock or
/// a transaction (money, inventory, counters, …).
const STATEFUL_NAMES: &[&str] = &[
    "balance",
    "amount",
    "funds",
    "wallet",
    "credit",
    "credits",
    "quantity",
    "qty",
    "stock",
    "inventory",
    "count",
    "counter",
    "total",
    "points",
    "score",
    "supply",
];

/// Keywords indicating the mutation is already synchronized/transactional.
const SYNC_MARKERS: &[&str] = &[
    "lock",
    "mutex",
    "atomic",
    "transaction",
    "begin",
    "commit",
    "synchronized",
    "fetch_sub",
    "fetch_add",
    "with_lock",
    "select for update",
];

/// Detect an unguarded read-modify-write on a stateful variable.
fn concurrency_check(line: &str, lang: Language, path: &str, line_no: usize) -> Option<Finding> {
    let lower = line.to_ascii_lowercase();

    // If the line itself shows synchronization, assume it is handled.
    if SYNC_MARKERS.iter().any(|m| lower.contains(m)) {
        return None;
    }

    let mutated = mutated_stateful_var(&lower)?;

    Some(Finding {
        rule: "race-condition".to_string(),
        title: "Possible race condition".to_string(),
        category: Category::Security,
        severity: Severity::Warning,
        file: path.to_string(),
        line: line_no,
        message: format!(
            "`{mutated}` is updated with a non-atomic read-modify-write and no visible lock/transaction. Concurrent updates can be lost."
        ),
        suggestion: Some(match lang {
            Language::Rust => {
                "Guard the update with a Mutex, use an atomic type (fetch_add/fetch_sub), or a DB transaction.".to_string()
            }
            _ => "Wrap the update in a lock or an atomic database transaction (e.g. SELECT ... FOR UPDATE).".to_string(),
        }),
    })
}

/// If the line performs `<name> -=/+= …` or `<name> = <name> -/+ …` on a
/// stateful variable, return the variable name.
fn mutated_stateful_var(lower: &str) -> Option<String> {
    // Compound assignment: `name -= ...` / `name += ...`
    for op in ["-=", "+=", "*=", "/="] {
        if let Some(idx) = lower.find(op) {
            if let Some(name) = trailing_identifier(&lower[..idx]) {
                if is_stateful(&name) {
                    return Some(name);
                }
            }
        }
    }

    // Self-referential assignment: `name = name - ...` / `name = name + ...`
    if let Some(eq) = find_plain_assignment(lower) {
        let lhs = trailing_identifier(&lower[..eq])?;
        let rhs = &lower[eq + 1..];
        if is_stateful(&lhs) && rhs.contains(&lhs) && (rhs.contains('-') || rhs.contains('+')) {
            return Some(lhs);
        }
    }

    None
}

/// The identifier ending a string slice (e.g. `"    self.balance "` -> `balance`).
fn trailing_identifier(s: &str) -> Option<String> {
    let s = s.trim_end();
    let ident: String = s
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    if ident.is_empty() {
        None
    } else {
        Some(ident)
    }
}

fn is_stateful(name: &str) -> bool {
    STATEFUL_NAMES.contains(&name)
}

/// Find a single `=` that is a plain assignment (not `==`, `<=`, `>=`, `!=`,
/// `+=`, `-=`, etc.).
fn find_plain_assignment(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] != b'=' {
            continue;
        }
        let prev = if i > 0 { bytes[i - 1] } else { b' ' };
        let next = if i + 1 < bytes.len() {
            bytes[i + 1]
        } else {
            b' '
        };
        if next == b'=' || matches!(prev, b'=' | b'!' | b'<' | b'>' | b'+' | b'-' | b'*' | b'/') {
            continue;
        }
        return Some(i);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_unguarded_balance_mutation() {
        let f = concurrency_check("    balance -= amount;", Language::Rust, "pay.rs", 12).unwrap();
        assert_eq!(f.rule, "race-condition");
        assert_eq!(f.line, 12);
        assert_eq!(f.severity, Severity::Warning);
    }

    #[test]
    fn flags_self_referential_assignment() {
        let f = concurrency_check("stock = stock - qty", Language::Python, "s.py", 3);
        assert!(f.is_some());
    }

    #[test]
    fn ignores_locked_mutation() {
        assert!(concurrency_check(
            "let _g = lock.lock(); balance -= amount;",
            Language::Rust,
            "p.rs",
            1
        )
        .is_none());
        assert!(concurrency_check(
            "balance.fetch_sub(amount, Ordering::SeqCst);",
            Language::Rust,
            "p.rs",
            1
        )
        .is_none());
    }

    #[test]
    fn ignores_non_stateful_variables() {
        assert!(concurrency_check("i += 1;", Language::Rust, "p.rs", 1).is_none());
        assert!(concurrency_check("index -= 1;", Language::Rust, "p.rs", 1).is_none());
    }
}
