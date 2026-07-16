//! Project scanner: recursively walks a directory, detects languages, and
//! collects the file contents that the rule engine analyzes.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use walkdir::{DirEntry, WalkDir};

use crate::config::Config;

/// A detected source language.
///
/// New languages can be added here and wired into [`Language::from_path`]
/// without touching any rule code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Language {
    Rust,
    JavaScript,
    TypeScript,
    Python,
    Go,
    Ruby,
    Java,
    C,
    Cpp,
    Shell,
    Other,
}

impl Language {
    /// Detect a language from a file path's extension.
    pub fn from_path(path: &Path) -> Language {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        match ext.as_str() {
            "rs" => Language::Rust,
            "js" | "jsx" | "mjs" | "cjs" => Language::JavaScript,
            "ts" | "tsx" => Language::TypeScript,
            "py" | "pyw" => Language::Python,
            "go" => Language::Go,
            "rb" => Language::Ruby,
            "java" => Language::Java,
            "c" | "h" => Language::C,
            "cc" | "cpp" | "cxx" | "hpp" | "hxx" => Language::Cpp,
            "sh" | "bash" | "zsh" => Language::Shell,
            _ => Language::Other,
        }
    }

    /// Human-readable name, used in reports.
    pub fn name(&self) -> &'static str {
        match self {
            Language::Rust => "Rust",
            Language::JavaScript => "JavaScript",
            Language::TypeScript => "TypeScript",
            Language::Python => "Python",
            Language::Go => "Go",
            Language::Ruby => "Ruby",
            Language::Java => "Java",
            Language::C => "C",
            Language::Cpp => "C++",
            Language::Shell => "Shell",
            Language::Other => "Other",
        }
    }

    /// Whether this is a recognized source language (i.e. not `Other`).
    pub fn is_recognized(&self) -> bool {
        !matches!(self, Language::Other)
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A single scanned file, with its contents loaded into memory.
#[derive(Debug, Clone)]
pub struct FileData {
    /// Path relative to the scan root, using forward slashes for stable
    /// reporting across platforms.
    pub path: String,
    /// The full source of the file.
    pub content: String,
    /// Number of lines in the file.
    pub lines: usize,
    /// Detected language.
    pub language: Language,
}

impl FileData {
    /// Iterate over `(line_number, line_text)` pairs, 1-indexed.
    pub fn numbered_lines(&self) -> impl Iterator<Item = (usize, &str)> {
        self.content.lines().enumerate().map(|(i, l)| (i + 1, l))
    }
}

/// Aggregate statistics collected during a scan.
#[derive(Debug, Default, Clone)]
pub struct ProjectStats {
    pub files: usize,
    pub languages: Vec<String>,
    pub lines_of_code: usize,
}

/// The result of scanning a directory tree.
#[derive(Debug, Default)]
pub struct ScanResult {
    pub files: Vec<FileData>,
    pub stats: ProjectStats,
}

/// Directory names that are always skipped, regardless of configuration.
const DEFAULT_IGNORES: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "out",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "vendor",
    ".idea",
    ".vscode",
    "coverage",
];

/// Maximum size of a file we will read into memory (5 MiB). Anything larger is
/// almost certainly a generated artifact or binary blob.
const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// Scan `root`, honoring ignore rules from `config`.
pub fn scan(root: &Path, config: &Config) -> ScanResult {
    let mut files = Vec::new();
    let mut languages: BTreeSet<Language> = BTreeSet::new();
    let mut lines_of_code = 0usize;

    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_ignored(e, root, config));

    for entry in walker.filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();

        // Skip files that are too large or unreadable.
        match entry.metadata() {
            Ok(meta) if meta.len() > MAX_FILE_BYTES => continue,
            Ok(_) => {}
            Err(_) => continue,
        }

        let content = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        // Skip binary files (crude but effective: a NUL byte in the first 8 KiB).
        if is_probably_binary(&content) {
            continue;
        }

        let content = String::from_utf8_lossy(&content).into_owned();
        let language = Language::from_path(path);
        let line_count = content.lines().count();

        lines_of_code += line_count;
        if language.is_recognized() {
            languages.insert(language);
        }

        files.push(FileData {
            path: relative_display(root, path),
            content,
            lines: line_count,
            language,
        });
    }

    let stats = ProjectStats {
        files: files.len(),
        languages: languages.iter().map(|l| l.name().to_string()).collect(),
        lines_of_code,
    };

    ScanResult { files, stats }
}

/// Whether a walked entry should be pruned from the scan.
fn is_ignored(entry: &DirEntry, root: &Path, config: &Config) -> bool {
    let name = entry.file_name().to_string_lossy();

    // Never descend into default-ignored directories.
    if entry.file_type().is_dir() && DEFAULT_IGNORES.contains(&name.as_ref()) {
        return true;
    }

    // Hidden files/dirs (starting with '.') other than the root itself.
    if name.starts_with('.') && name != "." && entry.depth() > 0 {
        return true;
    }

    // User-configured ignore patterns match against the relative path.
    let rel = relative_display(root, entry.path());
    for pattern in &config.scan.ignore {
        if matches_ignore(&rel, pattern) {
            return true;
        }
    }

    false
}

/// Simple ignore matching: matches if any path component equals the pattern,
/// or if the relative path starts with the pattern.
fn matches_ignore(rel_path: &str, pattern: &str) -> bool {
    let pattern = pattern.trim_matches('/');
    if pattern.is_empty() {
        return false;
    }
    if rel_path == pattern || rel_path.starts_with(&format!("{pattern}/")) {
        return true;
    }
    rel_path.split('/').any(|component| component == pattern)
}

/// Render a path relative to `root` with forward slashes.
fn relative_display(root: &Path, path: &Path) -> String {
    let rel: &Path = path.strip_prefix(root).unwrap_or(path);
    let mut out = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    if out.is_empty() {
        out = path.to_string_lossy().into_owned();
    }
    out
}

/// Heuristic binary detection: a NUL byte within the first 8 KiB.
fn is_probably_binary(bytes: &[u8]) -> bool {
    let window = &bytes[..bytes.len().min(8192)];
    window.contains(&0)
}

// Kept for potential external callers that want the default ignore list.
#[allow(dead_code)]
pub fn default_ignores() -> Vec<PathBuf> {
    DEFAULT_IGNORES.iter().map(PathBuf::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detects_languages_by_extension() {
        assert_eq!(Language::from_path(Path::new("main.rs")), Language::Rust);
        assert_eq!(
            Language::from_path(Path::new("app.tsx")),
            Language::TypeScript
        );
        assert_eq!(Language::from_path(Path::new("main.py")), Language::Python);
        assert_eq!(
            Language::from_path(Path::new("index.js")),
            Language::JavaScript
        );
        assert_eq!(Language::from_path(Path::new("README.md")), Language::Other);
    }

    #[test]
    fn ignore_matching() {
        assert!(matches_ignore("tests/foo.rs", "tests"));
        assert!(matches_ignore("a/vendor/b.rs", "vendor"));
        assert!(matches_ignore("vendor", "vendor"));
        assert!(!matches_ignore("src/main.rs", "tests"));
    }

    #[test]
    fn binary_detection() {
        assert!(is_probably_binary(&[0x00, 0x01, 0x02]));
        assert!(!is_probably_binary(b"hello world"));
    }
}
