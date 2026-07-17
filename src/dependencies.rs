//! The dependency-intelligence engine behind `killer dependencies`.
//!
//! Everything here is derived from the project's own manifest files — nothing
//! is fetched, and there is no vulnerability database. It answers questions the
//! local files can answer: what is declared, in which ecosystem, at what
//! version, whether a dependency looks unused, and whether the same package is
//! pinned to conflicting versions.
//!
//! Supported manifests: `Cargo.toml`, `package.json`, `requirements.txt`,
//! `go.mod`, `pom.xml`, and `*.csproj`. "Possibly unused" and CVE/reputation
//! signals are explicitly *not* claimed here — the former is a best-effort
//! import heuristic (only for ecosystems where import names track package
//! names), and the latter needs a dataset Killer deliberately does not ship.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::graph;
use crate::scanner::FileData;

/// A package ecosystem, identified by its manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Cargo,
    Npm,
    PyPI,
    Go,
    Maven,
    NuGet,
}

impl Ecosystem {
    /// Human-readable label used in reports and JSON.
    pub fn label(self) -> &'static str {
        match self {
            Ecosystem::Cargo => "Rust (Cargo)",
            Ecosystem::Npm => "Node (npm)",
            Ecosystem::PyPI => "Python (PyPI)",
            Ecosystem::Go => "Go (modules)",
            Ecosystem::Maven => "Java (Maven)",
            Ecosystem::NuGet => "C# (NuGet)",
        }
    }

    /// Detect the ecosystem from a manifest's file path.
    fn from_path(path: &str) -> Option<Ecosystem> {
        let base = path.rsplit('/').next().unwrap_or(path);
        match base {
            "Cargo.toml" => Some(Ecosystem::Cargo),
            "package.json" => Some(Ecosystem::Npm),
            "requirements.txt" => Some(Ecosystem::PyPI),
            "go.mod" => Some(Ecosystem::Go),
            "pom.xml" => Some(Ecosystem::Maven),
            _ if base.ends_with(".csproj") => Some(Ecosystem::NuGet),
            _ => None,
        }
    }

    /// Whether import-based usage detection is reliable for this ecosystem.
    ///
    /// Import names track package names closely for these four; Maven and NuGet
    /// use group/artifact and namespace forms that Killer's import extraction
    /// does not model, so their usage is reported as unknown rather than guessed.
    fn usage_detectable(self) -> bool {
        matches!(
            self,
            Ecosystem::Cargo | Ecosystem::Npm | Ecosystem::PyPI | Ecosystem::Go
        )
    }
}

/// A single declared dependency.
#[derive(Debug, Clone, Serialize)]
pub struct Dependency {
    pub name: String,
    pub version: Option<String>,
    /// Ecosystem label (e.g. `Rust (Cargo)`).
    pub ecosystem: String,
    /// The manifest that declared it (basename).
    pub manifest: String,
    /// A dev/test-only dependency.
    pub dev: bool,
    /// `Some(false)` = declared but not seen imported; `None` = can't tell.
    pub used: Option<bool>,
}

/// The full dependency-analysis result.
#[derive(Debug, Clone, Serialize)]
pub struct DependencyReport {
    pub dependencies: Vec<Dependency>,
}

impl DependencyReport {
    /// Build the report from a project's scanned files.
    pub fn build(files: &[FileData]) -> DependencyReport {
        // Parse every manifest into (name, version, ecosystem, dev).
        let mut parsed: Vec<(String, Option<String>, Ecosystem, String, bool)> = Vec::new();
        for f in files {
            let Some(eco) = Ecosystem::from_path(&f.path) else {
                continue;
            };
            let base = f.path.rsplit('/').next().unwrap_or(&f.path).to_string();
            for (name, version, dev) in parse_manifest(eco, &f.content) {
                parsed.push((name, version, eco, base.clone(), dev));
            }
        }

        // Set of every external module imported anywhere (normalized), used to
        // flag "possibly unused" dependencies where the ecosystem allows it.
        let mut imported: BTreeSet<String> = BTreeSet::new();
        for f in files {
            for m in graph::extract_imports(f.language, &f.content) {
                imported.insert(normalize(&m));
            }
        }

        let dependencies = parsed
            .into_iter()
            .map(|(name, version, eco, manifest, dev)| {
                let used = if eco.usage_detectable() {
                    let norm = normalize(&name);
                    let seen = imported.contains(&norm)
                        || (eco == Ecosystem::Cargo && graph::rust_crate_referenced(files, &name));
                    Some(seen)
                } else {
                    None
                };
                Dependency {
                    name,
                    version,
                    ecosystem: eco.label().to_string(),
                    manifest,
                    dev,
                    used,
                }
            })
            .collect();

        DependencyReport { dependencies }
    }

    pub fn total(&self) -> usize {
        self.dependencies.len()
    }

    pub fn production(&self) -> usize {
        self.dependencies.iter().filter(|d| !d.dev).count()
    }

    pub fn development(&self) -> usize {
        self.dependencies.iter().filter(|d| d.dev).count()
    }

    /// `(ecosystem, count)` pairs, most-populated first.
    pub fn ecosystem_counts(&self) -> Vec<(String, usize)> {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for d in &self.dependencies {
            *counts.entry(d.ecosystem.clone()).or_default() += 1;
        }
        let mut v: Vec<(String, usize)> = counts.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    /// Packages declared at more than one distinct version.
    pub fn duplicates(&self) -> Vec<(String, Vec<String>)> {
        let mut versions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for d in &self.dependencies {
            if let Some(v) = &d.version {
                versions
                    .entry(d.name.clone())
                    .or_default()
                    .insert(v.clone());
            }
        }
        versions
            .into_iter()
            .filter(|(_, set)| set.len() > 1)
            .map(|(name, set)| (name, set.into_iter().collect()))
            .collect()
    }

    /// Dependencies that appear declared but never imported (best-effort).
    pub fn unused_candidates(&self) -> Vec<&Dependency> {
        self.dependencies
            .iter()
            .filter(|d| d.used == Some(false))
            .collect()
    }
}

/// Normalize a name for comparison: lowercase, `_` → `-`.
fn normalize(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

/// Parse one manifest into `(name, version, dev)` triples.
fn parse_manifest(eco: Ecosystem, content: &str) -> Vec<(String, Option<String>, bool)> {
    match eco {
        Ecosystem::Cargo => parse_cargo(content),
        Ecosystem::Npm => parse_package_json(content),
        Ecosystem::PyPI => parse_requirements(content),
        Ecosystem::Go => parse_go_mod(content),
        Ecosystem::Maven => parse_pom(content),
        Ecosystem::NuGet => parse_csproj(content),
    }
}

fn parse_cargo(content: &str) -> Vec<(String, Option<String>, bool)> {
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
            for (name, spec) in t {
                let version = match spec {
                    toml::Value::String(s) => Some(s.clone()),
                    toml::Value::Table(tt) => {
                        tt.get("version").and_then(|v| v.as_str()).map(String::from)
                    }
                    _ => None,
                };
                out.push((name.clone(), version, dev));
            }
        }
    }
    out
}

fn parse_package_json(content: &str) -> Vec<(String, Option<String>, bool)> {
    let value: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for (key, dev) in [("dependencies", false), ("devDependencies", true)] {
        if let Some(serde_json::Value::Object(map)) = value.get(key) {
            for (name, spec) in map {
                let version = spec.as_str().map(String::from);
                out.push((name.clone(), version, dev));
            }
        }
    }
    out
}

fn parse_requirements(content: &str) -> Vec<(String, Option<String>, bool)> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        let name: String = line
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
            .collect();
        if name.is_empty() {
            continue;
        }
        // Everything after the name (and any `[extras]`) is the version spec.
        let rest = line[name.len()..].trim_start();
        let rest = rest.strip_prefix(|c| c == '[').map_or(rest, |after| {
            after.split_once(']').map_or(rest, |(_, r)| r.trim_start())
        });
        let version = if rest.is_empty() {
            None
        } else {
            Some(rest.to_string())
        };
        out.push((name, version, false));
    }
    out
}

fn parse_go_mod(content: &str) -> Vec<(String, Option<String>, bool)> {
    let mut out = Vec::new();
    let mut in_block = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.starts_with("require (") {
            in_block = true;
            continue;
        }
        let spec = if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            line
        } else if let Some(rest) = line.strip_prefix("require ") {
            rest
        } else {
            continue;
        };
        let mut parts = spec.split_whitespace();
        if let Some(name) = parts.next() {
            let version = parts.next().map(String::from);
            out.push((name.to_string(), version, false));
        }
    }
    out
}

fn parse_pom(content: &str) -> Vec<(String, Option<String>, bool)> {
    let mut out = Vec::new();
    for block in xml_blocks(content, "<dependency>", "</dependency>") {
        let Some(artifact) = xml_tag(block, "artifactId") else {
            continue;
        };
        let group = xml_tag(block, "groupId");
        let name = match group {
            Some(g) => format!("{g}:{artifact}"),
            None => artifact,
        };
        let version = xml_tag(block, "version");
        let scope = xml_tag(block, "scope").unwrap_or_default();
        let dev = matches!(scope.as_str(), "test" | "provided");
        out.push((name, version, dev));
    }
    out
}

fn parse_csproj(content: &str) -> Vec<(String, Option<String>, bool)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = content[from..].find("<PackageReference") {
        let start = from + rel;
        // The element head runs to the first `>`.
        let head_end = match content[start..].find('>') {
            Some(i) => start + i,
            None => break,
        };
        let head = &content[start..head_end];
        from = head_end + 1;

        let Some(name) = attr_value(head, "Include") else {
            continue;
        };
        // Version can be an attribute or a child <Version> element.
        let version = attr_value(head, "Version").or_else(|| {
            content[head_end..]
                .find("</PackageReference>")
                .and_then(|end| xml_tag(&content[head_end..head_end + end], "Version"))
        });
        out.push((name, version, false));
    }
    out
}

// --- Tiny hand-rolled XML/attribute helpers (no XML dependency) --------------

/// Substrings between each `open`/`close` pair (non-nested).
fn xml_blocks<'a>(s: &'a str, open: &str, close: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(a) = s[from..].find(open) {
        let start = from + a + open.len();
        match s[start..].find(close) {
            Some(b) => {
                out.push(&s[start..start + b]);
                from = start + b + close.len();
            }
            None => break,
        }
    }
    out
}

/// The text inside the first `<tag>…</tag>` in `block`.
fn xml_tag(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let i = block.find(&open)? + open.len();
    let j = block[i..].find(&close)? + i;
    Some(block[i..j].trim().to_string())
}

/// The value of a `name="…"` attribute in an element head.
fn attr_value(elem: &str, name: &str) -> Option<String> {
    let pat = format!("{name}=\"");
    let i = elem.find(&pat)? + pat.len();
    let rest = &elem[i..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Language, ProjectStats, ScanResult};

    fn file(path: &str, lang: Language, content: &str) -> FileData {
        FileData {
            path: path.to_string(),
            content: content.to_string(),
            lines: content.lines().count(),
            language: lang,
        }
    }

    #[test]
    fn cargo_versions_and_dev_flag() {
        let toml = "[dependencies]\nserde = \"1.0\"\nanyhow = { version = \"1\", features = [] }\n[dev-dependencies]\ntempfile = \"3\"";
        let deps = parse_cargo(toml);
        assert_eq!(
            deps.iter().find(|(n, ..)| n == "serde").unwrap().1,
            Some("1.0".to_string())
        );
        assert_eq!(
            deps.iter().find(|(n, ..)| n == "anyhow").unwrap().1,
            Some("1".to_string())
        );
        assert!(deps.iter().find(|(n, ..)| n == "tempfile").unwrap().2);
    }

    #[test]
    fn npm_versions_and_dev() {
        let json = r#"{"dependencies":{"react":"^18.2.0"},"devDependencies":{"jest":"^29"}}"#;
        let deps = parse_package_json(json);
        assert_eq!(
            deps.iter().find(|(n, ..)| n == "react").unwrap().1,
            Some("^18.2.0".to_string())
        );
        assert!(deps.iter().find(|(n, ..)| n == "jest").unwrap().2);
    }

    #[test]
    fn requirements_strip_specifiers_and_extras() {
        let deps = parse_requirements("flask>=2.0\nrequests[security]==2.28\n# comment\n");
        let flask = deps.iter().find(|(n, ..)| n == "flask").unwrap();
        assert_eq!(flask.1, Some(">=2.0".to_string()));
        let reqs = deps.iter().find(|(n, ..)| n == "requests").unwrap();
        assert_eq!(reqs.1, Some("==2.28".to_string()));
    }

    #[test]
    fn go_mod_versions() {
        let deps = parse_go_mod("module x\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n)\n");
        let gin = deps
            .iter()
            .find(|(n, ..)| n == "github.com/gin-gonic/gin")
            .unwrap();
        assert_eq!(gin.1, Some("v1.9.0".to_string()));
    }

    #[test]
    fn pom_and_csproj_parse() {
        let pom = "<project><dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>32.0</version></dependency><dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13</version><scope>test</scope></dependency></dependencies></project>";
        let deps = parse_pom(pom);
        let guava = deps
            .iter()
            .find(|(n, ..)| n == "com.google.guava:guava")
            .unwrap();
        assert_eq!(guava.1, Some("32.0".to_string()));
        assert!(!guava.2);
        let junit = deps.iter().find(|(n, ..)| n == "junit:junit").unwrap();
        assert!(junit.2); // test scope → dev

        let csproj = r#"<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /><PackageReference Include="Serilog"><Version>3.0.0</Version></PackageReference></ItemGroup></Project>"#;
        let deps = parse_csproj(csproj);
        assert_eq!(
            deps.iter()
                .find(|(n, ..)| n == "Newtonsoft.Json")
                .unwrap()
                .1,
            Some("13.0.1".to_string())
        );
        assert_eq!(
            deps.iter().find(|(n, ..)| n == "Serilog").unwrap().1,
            Some("3.0.0".to_string())
        );
    }

    fn scan(files: Vec<FileData>) -> ScanResult {
        ScanResult {
            files,
            stats: ProjectStats::default(),
        }
    }

    #[test]
    fn report_counts_ecosystems_prod_dev_and_unused() {
        let s = scan(vec![
            file(
                "Cargo.toml",
                Language::Other,
                "[dependencies]\nserde = \"1\"\nunused_dep = \"1\"\n[dev-dependencies]\ntempfile = \"3\"",
            ),
            file("src/main.rs", Language::Rust, "use serde::Serialize;"),
        ]);
        let report = DependencyReport::build(&s.files);
        assert_eq!(report.total(), 3);
        assert_eq!(report.production(), 2); // serde, unused_dep
        assert_eq!(report.development(), 1); // tempfile
        assert_eq!(report.ecosystem_counts()[0].0, "Rust (Cargo)");

        let unused: Vec<_> = report
            .unused_candidates()
            .iter()
            .map(|d| d.name.clone())
            .collect();
        assert!(unused.contains(&"unused_dep".to_string()));
        assert!(!unused.contains(&"serde".to_string()));
    }

    #[test]
    fn duplicate_versions_are_flagged() {
        let s = scan(vec![
            file(
                "a/package.json",
                Language::Other,
                r#"{"dependencies":{"react":"18.2.0"}}"#,
            ),
            file(
                "b/package.json",
                Language::Other,
                r#"{"dependencies":{"react":"18.3.1"}}"#,
            ),
        ]);
        let report = DependencyReport::build(&s.files);
        let dups = report.duplicates();
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0].0, "react");
        assert_eq!(dups[0].1.len(), 2);
    }

    #[test]
    fn nuget_and_maven_usage_is_unknown_not_guessed() {
        let s = scan(vec![file(
            "App.csproj",
            Language::Other,
            r#"<Project><PackageReference Include="Dapper" Version="2.0" /></Project>"#,
        )]);
        let report = DependencyReport::build(&s.files);
        assert_eq!(report.dependencies[0].used, None);
        assert!(report.unused_candidates().is_empty());
    }
}
