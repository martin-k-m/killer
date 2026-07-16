//! A thin wrapper over `git` for the code-review engine.
//!
//! We shell out to `git diff --unified=0` and parse the unified diff to learn
//! which lines were *added* in each file. The parser is separated from the
//! process invocation so it can be tested without a repository.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

/// A file with the lines that were added to it, as `(new_line_number, text)`.
#[derive(Debug, Clone, PartialEq)]
pub struct ChangedFile {
    pub path: String,
    pub added: Vec<(usize, String)>,
}

/// What to diff against.
#[derive(Debug, Clone)]
pub enum DiffTarget {
    /// Working tree vs. `HEAD` (unstaged + staged changes).
    WorkingTree,
    /// Staged changes only (`--cached`).
    Staged,
    /// A base ref, e.g. `origin/main` (diffs `HEAD` against it).
    Base(String),
}

/// Run `git diff` for `target` in `repo_root` and return the changed files.
pub fn changed_files(repo_root: &Path, target: &DiffTarget) -> Result<Vec<ChangedFile>> {
    let mut args = vec![
        "-C".to_string(),
        repo_root.to_string_lossy().into_owned(),
        "diff".to_string(),
        "--unified=0".to_string(),
        "--no-color".to_string(),
    ];
    match target {
        DiffTarget::WorkingTree => {}
        DiffTarget::Staged => args.push("--cached".to_string()),
        DiffTarget::Base(base) => args.push(base.clone()),
    }

    let output = Command::new("git")
        .args(&args)
        .output()
        .context("failed to run `git` (is it installed and on PATH?)")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git diff failed: {}", stderr.trim());
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_unified_diff(&text))
}

/// Parse a `--unified=0` diff into per-file added lines.
pub fn parse_unified_diff(diff: &str) -> Vec<ChangedFile> {
    let mut files: Vec<ChangedFile> = Vec::new();
    let mut current: Option<ChangedFile> = None;
    let mut new_line = 0usize;

    for line in diff.lines() {
        if let Some(path) = line.strip_prefix("+++ ") {
            // Flush the previous file.
            if let Some(f) = current.take() {
                if !f.added.is_empty() {
                    files.push(f);
                }
            }
            if path == "/dev/null" {
                current = None;
            } else {
                let clean = path
                    .strip_prefix("b/")
                    .unwrap_or(path)
                    .split('\t')
                    .next()
                    .unwrap_or(path)
                    .to_string();
                current = Some(ChangedFile {
                    path: clean,
                    added: Vec::new(),
                });
            }
            continue;
        }

        if line.starts_with("--- ") || line.starts_with("diff --git") {
            continue;
        }

        if let Some(rest) = line.strip_prefix("@@") {
            // e.g. "@@ -12,0 +13,2 @@ optional context"
            new_line = parse_hunk_new_start(rest).unwrap_or(new_line);
            continue;
        }

        let Some(file) = current.as_mut() else {
            continue;
        };

        if let Some(added) = line.strip_prefix('+') {
            file.added.push((new_line, added.to_string()));
            new_line += 1;
        } else if line.starts_with('-') {
            // Removed line: does not advance the new-file counter.
        } else if line.starts_with(' ') {
            // Context line (rare with --unified=0).
            new_line += 1;
        }
    }

    if let Some(f) = current.take() {
        if !f.added.is_empty() {
            files.push(f);
        }
    }
    files
}

/// Parse the `+<start>[,<count>]` field from a hunk header remainder.
fn parse_hunk_new_start(rest: &str) -> Option<usize> {
    // rest looks like " -12,0 +13,2 @@ ..."
    let plus = rest.split('+').nth(1)?;
    let num: String = plus.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_added_lines_with_line_numbers() {
        let diff = "\
diff --git a/src/pay.rs b/src/pay.rs
index 111..222 100644
--- a/src/pay.rs
+++ b/src/pay.rs
@@ -10,0 +11,2 @@ fn withdraw() {
+    balance -= amount;
+    save(balance);
@@ -20,1 +22,1 @@ fn other() {
+    let x = 1;
";
        let files = parse_unified_diff(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "src/pay.rs");
        assert_eq!(
            files[0].added,
            vec![
                (11, "    balance -= amount;".to_string()),
                (12, "    save(balance);".to_string()),
                (22, "    let x = 1;".to_string()),
            ]
        );
    }

    #[test]
    fn skips_deleted_files() {
        let diff = "\
diff --git a/gone.rs b/gone.rs
--- a/gone.rs
+++ /dev/null
@@ -1,2 +0,0 @@
-old line
-another
";
        assert!(parse_unified_diff(diff).is_empty());
    }

    #[test]
    fn handles_multiple_files() {
        let diff = "\
--- a/a.rs
+++ b/a.rs
@@ -0,0 +1 @@
+fn a() {}
--- a/b.rs
+++ b/b.rs
@@ -0,0 +1 @@
+fn b() {}
";
        let files = parse_unified_diff(diff);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "a.rs");
        assert_eq!(files[1].path, "b.rs");
    }
}
