//! The project graph engine.
//!
//! `killer graph` builds a *structural* map of a project: which source files
//! import which external modules, and which dependencies the project declares
//! in its manifests. From those two views it derives a supply-chain signal —
//! declared dependencies that no source file appears to import ("possibly
//! unused").
//!
//! This is deliberately a structural graph, not a semantic/data-flow one. Import
//! extraction is line-level and per-language; dependency-usage matching is a
//! best-effort name normalization (so `pretty-env-logger` in `Cargo.toml`
//! matches `use pretty_env_logger`). A true multi-language IR and data-flow
//! graph remain on the roadmap.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::scanner::{Language, ScanResult};

/// A source file node.
#[derive(Debug, Clone, Serialize)]
pub struct FileNode {
    pub path: String,
    pub language: String,
    /// External modules this file imports (deduped, sorted).
    pub imports: Vec<String>,
}

/// A declared dependency (from a manifest) plus whether the project uses it.
#[derive(Debug, Clone, Serialize)]
pub struct DependencyNode {
    pub name: String,
    /// The manifest that declared it, e.g. `Cargo.toml`.
    pub manifest: String,
    /// A dev/test-only dependency.
    pub dev: bool,
    /// Whether any source file appears to import it.
    pub used: bool,
    /// Number of files that import it.
    pub importing_files: usize,
}

/// A file → module import edge.
#[derive(Debug, Clone, Serialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
}

/// The complete project graph.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectGraph {
    pub files: Vec<FileNode>,
    pub dependencies: Vec<DependencyNode>,
    pub edges: Vec<Edge>,
}

impl ProjectGraph {
    /// Build a graph from a completed scan.
    pub fn build(scan: &ScanResult) -> ProjectGraph {
        let mut files = Vec::new();
        let mut edges = Vec::new();
        // module name -> set of files importing it
        let mut importers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for file in &scan.files {
            let imports = extract_imports(file.language, &file.content);
            for m in &imports {
                edges.push(Edge {
                    from: file.path.clone(),
                    to: m.clone(),
                });
                importers
                    .entry(m.clone())
                    .or_default()
                    .insert(file.path.clone());
            }
            if !imports.is_empty() {
                files.push(FileNode {
                    path: file.path.clone(),
                    language: file.language.name().to_string(),
                    imports,
                });
            }
        }

        // Parse declared dependencies from any manifests in the scan.
        let mut dependencies = Vec::new();
        for file in &scan.files {
            for (name, dev) in parse_manifest(&file.path, &file.content) {
                let norm = normalize(&name);
                let importing: usize = importers
                    .iter()
                    .filter(|(m, _)| normalize(m) == norm)
                    .map(|(_, s)| s.len())
                    .sum();
                // A crate can be used via a fully-qualified path (`serde_json::…`)
                // with no `use` statement, so fall back to an inline path scan.
                let used = importing > 0 || rust_crate_referenced(&scan.files, &name);
                dependencies.push(DependencyNode {
                    name,
                    manifest: basename(&file.path).to_string(),
                    dev,
                    used,
                    importing_files: importing,
                });
            }
        }
        dependencies.sort_by(|a, b| a.name.cmp(&b.name));
        dependencies.dedup_by(|a, b| a.name == b.name && a.manifest == b.manifest);

        ProjectGraph {
            files,
            dependencies,
            edges,
        }
    }

    /// Distinct external modules imported anywhere in the project.
    pub fn module_count(&self) -> usize {
        self.edges
            .iter()
            .map(|e| e.to.as_str())
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Declared dependencies that no file appears to import.
    pub fn unused_dependencies(&self) -> Vec<&DependencyNode> {
        self.dependencies.iter().filter(|d| !d.used).collect()
    }

    /// Modules ranked by how many files import them (descending).
    pub fn top_modules(&self, limit: usize) -> Vec<(String, usize)> {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for e in &self.edges {
            *counts.entry(e.to.clone()).or_default() += 1;
        }
        let mut ranked: Vec<(String, usize)> = counts.into_iter().collect();
        // Most-imported first; ties broken alphabetically for stable output.
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        ranked.truncate(limit);
        ranked
    }

    /// Files ranked by number of external imports (descending).
    pub fn import_hotspots(&self, limit: usize) -> Vec<(String, usize)> {
        let mut ranked: Vec<(String, usize)> = self
            .files
            .iter()
            .map(|f| (f.path.clone(), f.imports.len()))
            .collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        ranked.truncate(limit);
        ranked
    }
}

// --- Import extraction -------------------------------------------------------

/// Extract the external modules a file imports (deduped, sorted).
pub fn extract_imports(language: Language, content: &str) -> Vec<String> {
    let mut set = BTreeSet::new();
    for raw in content.lines() {
        let line = raw.trim();
        let module = match language {
            Language::Rust => rust_import(line),
            Language::JavaScript | Language::TypeScript => js_import(line),
            Language::Python => python_import(line),
            Language::Go => go_import(line),
            Language::Java => java_import(line),
            Language::Ruby => ruby_import(line),
            // C/C++/Shell/Other: includes are overwhelmingly system headers;
            // extracting them would add noise, so they are skipped by design.
            _ => None,
        };
        if let Some(m) = module {
            if !m.is_empty() {
                set.insert(m);
            }
        }
    }
    set.into_iter().collect()
}

/// The first path segment of `s`, split on `sep`.
fn first_segment(s: &str, sep: char) -> &str {
    s.split(sep).next().unwrap_or(s)
}

/// Whether any Rust file references a crate via a fully-qualified path
/// (`crate_ident::…`) — the idiomatic way to use a crate without a `use`.
/// Cargo crate names use hyphens; the Rust identifier uses underscores.
pub fn rust_crate_referenced(files: &[crate::scanner::FileData], dep_name: &str) -> bool {
    let ident = dep_name.replace('-', "_");
    if ident.is_empty() {
        return false;
    }
    let pattern = format!("{ident}::");
    files
        .iter()
        .filter(|f| f.language == Language::Rust)
        .any(|f| contains_path_ident(&f.content, &pattern))
}

/// Whether `content` contains `pattern` (e.g. `serde_json::`) at an identifier
/// boundary, so `my_serde_json::` does not falsely match `serde_json::`.
fn contains_path_ident(content: &str, pattern: &str) -> bool {
    let mut from = 0;
    while let Some(rel) = content[from..].find(pattern) {
        let abs = from + rel;
        let boundary = abs == 0
            || content[..abs]
                .chars()
                .next_back()
                .map_or(true, |c| !c.is_alphanumeric() && c != '_');
        if boundary {
            return true;
        }
        from = abs + 1;
    }
    false
}

fn rust_import(line: &str) -> Option<String> {
    // `use foo::bar;`  or  `extern crate foo;`
    let rest = line
        .strip_prefix("pub use ")
        .or_else(|| line.strip_prefix("use "))?;
    let head = first_segment(rest.trim(), ':').trim();
    let head = head.trim_end_matches(';').trim_end_matches('{').trim();
    // Local/std references are not external dependencies.
    if matches!(
        head,
        "crate" | "self" | "super" | "std" | "core" | "alloc" | ""
    ) {
        return None;
    }
    Some(head.to_string())
}

fn js_import(line: &str) -> Option<String> {
    // `import x from 'mod'`, `import 'mod'`, or `require('mod')`.
    let quoted = extract_between_quotes(line, "from ")
        .or_else(|| extract_between_quotes(line, "require("))
        .or_else(|| {
            if line.starts_with("import ") {
                extract_first_quote(line)
            } else {
                None
            }
        })?;
    // Relative imports are project-internal, not dependencies.
    if quoted.starts_with('.') || quoted.starts_with('/') {
        return None;
    }
    Some(package_root(&quoted))
}

fn python_import(line: &str) -> Option<String> {
    let head = if let Some(rest) = line.strip_prefix("from ") {
        first_segment(rest.trim(), ' ')
    } else {
        // `import a.b as c` / `import a, b`
        let rest = line.strip_prefix("import ")?;
        first_segment(first_segment(rest.trim(), ','), ' ')
    };
    let top = first_segment(head, '.').trim();
    // `from . import x` (relative) yields an empty top module.
    if top.is_empty() || top == "." {
        return None;
    }
    Some(top.to_string())
}

fn go_import(line: &str) -> Option<String> {
    // Inside or outside an `import ( ... )` block: a quoted path.
    let path = extract_first_quote(line)?;
    // Standard-library packages have no dot in their first segment.
    if !first_segment(&path, '/').contains('.') {
        return None;
    }
    Some(path)
}

fn java_import(line: &str) -> Option<String> {
    let rest = line
        .strip_prefix("import static ")
        .or_else(|| line.strip_prefix("import "))?;
    let path = rest.trim().trim_end_matches(';').trim();
    if path.starts_with("java.") || path.starts_with("javax.") {
        return None;
    }
    // Group by the top two segments, e.g. `com.google`.
    let mut it = path.split('.');
    match (it.next(), it.next()) {
        (Some(a), Some(b)) => Some(format!("{a}.{b}")),
        (Some(a), None) => Some(a.to_string()),
        _ => None,
    }
}

fn ruby_import(line: &str) -> Option<String> {
    if !line.starts_with("require ") && !line.starts_with("require_relative ") {
        return None;
    }
    if line.starts_with("require_relative") {
        return None;
    }
    let path = extract_first_quote(line)?;
    Some(package_root(&path))
}

/// The installable package root of a module path: `@scope/pkg` keeps two
/// segments, `lodash/merge` collapses to `lodash`.
fn package_root(module: &str) -> String {
    if let Some(scoped) = module.strip_prefix('@') {
        let mut it = scoped.split('/');
        match (it.next(), it.next()) {
            (Some(scope), Some(pkg)) => return format!("@{scope}/{pkg}"),
            _ => return module.to_string(),
        }
    }
    first_segment(module, '/').to_string()
}

/// The substring between the first pair of quotes that follow `marker`.
fn extract_between_quotes(line: &str, marker: &str) -> Option<String> {
    let idx = line.find(marker)? + marker.len();
    extract_first_quote(&line[idx..])
}

/// The substring inside the first single/double-quoted region of `s`.
fn extract_first_quote(s: &str) -> Option<String> {
    let bytes = s.char_indices();
    let mut start: Option<usize> = None;
    for (i, c) in bytes {
        if c == '\'' || c == '"' {
            match start {
                None => start = Some(i + c.len_utf8()),
                Some(begin) => return Some(s[begin..i].to_string()),
            }
        }
    }
    None
}

// --- Manifest parsing --------------------------------------------------------

/// Parse a manifest file into `(dependency_name, is_dev)` pairs. Non-manifest
/// files yield nothing.
pub fn parse_manifest(path: &str, content: &str) -> Vec<(String, bool)> {
    match basename(path) {
        "Cargo.toml" => parse_cargo_toml(content),
        "package.json" => parse_package_json(content),
        "requirements.txt" => parse_requirements_txt(content),
        "go.mod" => parse_go_mod(content),
        _ => Vec::new(),
    }
}

fn parse_cargo_toml(content: &str) -> Vec<(String, bool)> {
    let value: toml::Value = match toml::from_str(content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for (table, dev) in [
        ("dependencies", false),
        ("dev-dependencies", true),
        ("build-dependencies", true),
    ] {
        if let Some(toml::Value::Table(t)) = value.get(table) {
            for name in t.keys() {
                out.push((name.clone(), dev));
            }
        }
    }
    out
}

fn parse_package_json(content: &str) -> Vec<(String, bool)> {
    let value: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for (key, dev) in [("dependencies", false), ("devDependencies", true)] {
        if let Some(serde_json::Value::Object(map)) = value.get(key) {
            for name in map.keys() {
                out.push((name.clone(), dev));
            }
        }
    }
    out
}

fn parse_requirements_txt(content: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        // Strip version specifiers and extras: `pkg[extra]>=1.0` -> `pkg`.
        let name: String = line
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
            .collect();
        if !name.is_empty() {
            out.push((name, false));
        }
    }
    out
}

fn parse_go_mod(content: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut in_block = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.starts_with("require (") {
            in_block = true;
            continue;
        }
        if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            if let Some(name) = line.split_whitespace().next() {
                out.push((name.to_string(), false));
            }
        } else if let Some(rest) = line.strip_prefix("require ") {
            if let Some(name) = rest.split_whitespace().next() {
                out.push((name.to_string(), false));
            }
        }
    }
    out
}

// --- Helpers -----------------------------------------------------------------

/// The final `/`-separated component of a path.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Normalize a dependency/module name for matching: lowercase, `_`→`-`.
fn normalize(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{FileData, ProjectStats};

    fn file(path: &str, lang: Language, content: &str) -> FileData {
        FileData {
            path: path.to_string(),
            content: content.to_string(),
            lines: content.lines().count(),
            language: lang,
        }
    }

    #[test]
    fn rust_imports_skip_std_and_local() {
        let src = "use serde::Serialize;\nuse crate::foo;\nuse std::io;\nextern crate legacy;\npub use anyhow::Result;";
        let imports = extract_imports(Language::Rust, src);
        assert!(imports.contains(&"serde".to_string()));
        assert!(imports.contains(&"anyhow".to_string()));
        assert!(!imports.contains(&"crate".to_string()));
        assert!(!imports.contains(&"std".to_string()));
    }

    #[test]
    fn js_imports_handle_scopes_and_relatives() {
        let src = "import x from 'lodash/merge';\nimport './local';\nconst y = require('@scope/pkg');\nimport 'react';";
        let imports = extract_imports(Language::JavaScript, src);
        assert!(imports.contains(&"lodash".to_string()));
        assert!(imports.contains(&"@scope/pkg".to_string()));
        assert!(imports.contains(&"react".to_string()));
        assert!(!imports.iter().any(|m| m.contains("local")));
    }

    #[test]
    fn python_imports_take_top_module() {
        let src =
            "import os\nfrom requests import get\nimport numpy.linalg as la\nfrom . import sibling";
        let imports = extract_imports(Language::Python, src);
        assert!(imports.contains(&"requests".to_string()));
        assert!(imports.contains(&"numpy".to_string()));
        assert!(imports.contains(&"os".to_string()));
        assert!(!imports.iter().any(|m| m == "sibling" || m.is_empty()));
    }

    #[test]
    fn go_imports_skip_stdlib() {
        let src = "import (\n\t\"fmt\"\n\t\"github.com/gin-gonic/gin\"\n)";
        let imports = extract_imports(Language::Go, src);
        assert!(imports.contains(&"github.com/gin-gonic/gin".to_string()));
        assert!(!imports.contains(&"fmt".to_string()));
    }

    #[test]
    fn cargo_manifest_parses_dev_flag() {
        let toml = "[dependencies]\nserde = \"1\"\n[dev-dependencies]\ntempfile = \"3\"";
        let deps = parse_manifest("Cargo.toml", toml);
        assert!(deps.contains(&("serde".to_string(), false)));
        assert!(deps.contains(&("tempfile".to_string(), true)));
    }

    #[test]
    fn package_json_parses() {
        let json = r#"{"dependencies":{"react":"^18"},"devDependencies":{"jest":"^29"}}"#;
        let deps = parse_manifest("package.json", json);
        assert!(deps.contains(&("react".to_string(), false)));
        assert!(deps.contains(&("jest".to_string(), true)));
    }

    #[test]
    fn requirements_and_gomod_parse() {
        let reqs = parse_manifest(
            "requirements.txt",
            "# c\nflask>=2.0\nrequests[security]==2.28\n",
        );
        assert!(reqs.contains(&("flask".to_string(), false)));
        assert!(reqs.contains(&("requests".to_string(), false)));

        let gomod = parse_manifest(
            "go.mod",
            "module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n)\n",
        );
        assert!(gomod.iter().any(|(n, _)| n == "github.com/gin-gonic/gin"));
    }

    #[test]
    fn build_detects_used_and_unused_dependencies() {
        let scan = ScanResult {
            files: vec![
                file(
                    "Cargo.toml",
                    Language::Other,
                    "[dependencies]\nserde = \"1\"\nunused_dep = \"1\"",
                ),
                file(
                    "src/main.rs",
                    Language::Rust,
                    "use serde::Serialize;\nfn main() {}",
                ),
            ],
            stats: ProjectStats::default(),
        };
        let graph = ProjectGraph::build(&scan);

        let serde = graph
            .dependencies
            .iter()
            .find(|d| d.name == "serde")
            .unwrap();
        assert!(serde.used);
        assert_eq!(serde.importing_files, 1);

        let unused = graph.unused_dependencies();
        assert_eq!(unused.len(), 1);
        assert_eq!(unused[0].name, "unused_dep");

        assert_eq!(graph.module_count(), 1); // only `serde`
        assert_eq!(graph.import_hotspots(10)[0].0, "src/main.rs");
    }

    #[test]
    fn inline_path_use_counts_as_used() {
        // `serde_json::to_string` with no `use serde_json;` must still count.
        let scan = ScanResult {
            files: vec![
                file(
                    "Cargo.toml",
                    Language::Other,
                    "[dependencies]\nserde_json = \"1\"",
                ),
                file(
                    "src/main.rs",
                    Language::Rust,
                    "fn main() { let s = serde_json::to_string(&1).unwrap(); }",
                ),
            ],
            stats: ProjectStats::default(),
        };
        let graph = ProjectGraph::build(&scan);
        assert!(
            graph
                .dependencies
                .iter()
                .find(|d| d.name == "serde_json")
                .unwrap()
                .used
        );
        assert!(graph.unused_dependencies().is_empty());
    }

    #[test]
    fn inline_path_respects_identifier_boundary() {
        // `my_serde::` must not mark `serde` as used.
        assert!(contains_path_ident("use serde::Serialize;", "serde::"));
        assert!(!contains_path_ident("let x = my_serde::foo();", "serde::"));
    }

    #[test]
    fn hyphen_underscore_normalization_matches() {
        let scan = ScanResult {
            files: vec![
                file(
                    "Cargo.toml",
                    Language::Other,
                    "[dependencies]\npretty-env-logger = \"0.5\"",
                ),
                file("src/lib.rs", Language::Rust, "use pretty_env_logger;"),
            ],
            stats: ProjectStats::default(),
        };
        let graph = ProjectGraph::build(&scan);
        assert!(graph.dependencies.iter().all(|d| d.used));
        assert!(graph.unused_dependencies().is_empty());
    }
}
