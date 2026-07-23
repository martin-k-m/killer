//! Configuration loaded from a `.killer.toml` file at the scan root.
//!
//! All fields are optional; missing values fall back to sensible defaults so a
//! project with no config file still gets a full scan.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The top-level configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub project: ProjectConfig,
    pub scan: ScanConfig,
    pub rules: RulesConfig,
    pub languages: LanguagesConfig,
    pub security: SecurityConfig,
    pub klr: KlrConfig,
}

/// Language enable flags, e.g. `rust = true`. Unknown languages are preserved.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LanguagesConfig {
    #[serde(flatten)]
    pub enabled: BTreeMap<String, bool>,
}

/// Global security posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// One of `relaxed`, `standard`, or `strict`. Reserved for tuning rule
    /// sensitivity in later phases; currently informational.
    pub level: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            level: "standard".to_string(),
        }
    }
}

/// Configuration for the `.klr` test runner.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct KlrConfig {
    /// Directory that `killer test` scans for `.klr` files when no path is given.
    pub directory: Option<String>,
    /// Base URL that relative attack targets resolve against.
    pub base_url: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectConfig {
    /// Optional display name; falls back to the scan directory name.
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Extra path patterns to ignore, on top of the built-in defaults.
    pub ignore: Vec<String>,
    /// Files longer than this many lines are flagged as "large".
    pub large_file_threshold: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            ignore: Vec::new(),
            large_file_threshold: 1000,
        }
    }
}

/// Per-rule enable/disable switches. Every rule defaults to enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RulesConfig {
    pub secret_detection: bool,
    pub dangerous_commands: bool,
    pub large_files: bool,
    pub todo_tracker: bool,
    pub duplicate_code: bool,
}

impl Default for RulesConfig {
    fn default() -> Self {
        RulesConfig {
            secret_detection: true,
            dangerous_commands: true,
            large_files: true,
            todo_tracker: true,
            duplicate_code: true,
        }
    }
}

/// The canonical config file name.
pub const CONFIG_FILE_NAME: &str = ".killer.toml";

impl Config {
    /// Load config from `<root>/.killer.toml` if present, otherwise return
    /// defaults. A malformed file is a hard error so the user notices.
    pub fn load(root: &Path) -> Result<Config> {
        let path = root.join(CONFIG_FILE_NAME);
        if !path.exists() {
            return Ok(Config::default());
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let config: Config =
            toml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))?;
        Ok(config)
    }

    /// A commented default config, written by `killer init`.
    pub fn default_file_contents() -> &'static str {
        DEFAULT_CONFIG_TEMPLATE
    }

    /// A runnable starter `.klr` file, written by `killer init --scaffold`.
    pub fn starter_klr() -> &'static str {
        STARTER_KLR_TEMPLATE
    }
}

/// The directory `killer init --scaffold` creates for `.klr` tests. Matches the
/// `[klr] directory` in the template returned by [`Config::default_file_contents`].
pub const SCAFFOLD_DIR: &str = "security-tests";

/// The starter test file name written into [`SCAFFOLD_DIR`].
pub const SCAFFOLD_FILE: &str = "getting-started.klr";

const STARTER_KLR_TEMPLATE: &str = r#"# Starter Killer security tests.
#
# Run the dynamic attacks against a live server:   killer test
# Run only the static code rules (no server):       killer ci
#
# A .klr file describes how a SECURE system should behave: a test PASSES when
# the target defends itself and FAILS when an attack succeeds.

suite "Getting Started" {

    # A dynamic attack — needs a server running at the configured base_url.
    attack sql_login_bypass {
        request POST "/login"
        send {
            username = "' OR 1=1 --"
            password = "x"
        }
        expect {
            status != 200
            response does_not_contain "token"
        }
        severity critical
        message: "SQL injection authentication bypass"
    }
}

# A static code rule — runs against your source, no server required.
rule "Possible hard-coded credential"
when function contains "password ="
without sanitization
severity high
report: "Move secrets to environment variables or a secret manager"
"#;

const DEFAULT_CONFIG_TEMPLATE: &str = r#"# Killer configuration
# https://github.com/martin-k-m/killer

[project]
# Display name for reports. Defaults to the directory name.
# name = "my-app"

[scan]
# Extra paths to ignore, on top of the built-in defaults
# (.git, node_modules, target, dist, build, and other common folders).
ignore = [
    "tests",
    "vendor",
]

# Files longer than this many lines are flagged as "large".
large_file_threshold = 1000

[rules]
# Toggle individual rules on or off.
secret_detection = true
dangerous_commands = true
large_files = true
todo_tracker = true
duplicate_code = true

[languages]
# Languages to focus on (informational in this phase).
rust = true
typescript = true
python = true

[security]
# Security posture: relaxed | standard | strict.
level = "standard"

[klr]
# Where `killer test` looks for .klr files when no path is given.
directory = "./security-tests"

# Base URL that relative attack targets (e.g. "/api/login") resolve against.
base_url = "http://127.0.0.1:8080"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_enable_all_rules() {
        let c = Config::default();
        assert!(c.rules.secret_detection);
        assert!(c.rules.duplicate_code);
        assert_eq!(c.scan.large_file_threshold, 1000);
    }

    #[test]
    fn parses_partial_config() {
        let text = r#"
            [project]
            name = "demo"

            [rules]
            duplicate_code = false
        "#;
        let c: Config = toml::from_str(text).unwrap();
        assert_eq!(c.project.name.as_deref(), Some("demo"));
        assert!(!c.rules.duplicate_code);
        // Unspecified rule keeps its default.
        assert!(c.rules.secret_detection);
        // Unspecified section keeps its default.
        assert_eq!(c.scan.large_file_threshold, 1000);
    }

    #[test]
    fn default_template_parses() {
        let c: Config = toml::from_str(Config::default_file_contents()).unwrap();
        assert!(c.rules.secret_detection);
    }

    #[test]
    fn starter_klr_parses() {
        // The scaffolded starter file must be valid .klr out of the box.
        let program = crate::klr::parse(Config::starter_klr()).unwrap();
        assert_eq!(program.all_attacks().len(), 1);
        assert_eq!(program.rules.len(), 1);
    }
}
