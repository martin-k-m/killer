//! Security rules: hardcoded secret detection and dangerous command execution.

use crate::analyzer::{Category, Finding, Rule, Severity};
use crate::scanner::{FileData, Language};

/// Detects credentials committed directly into source code.
pub struct HardcodedSecretRule;

impl HardcodedSecretRule {
    pub fn new() -> Self {
        HardcodedSecretRule
    }
}

impl Default for HardcodedSecretRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Identifier fragments that suggest a variable holds a secret.
const SECRET_KEYWORDS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "secret",
    "password",
    "passwd",
    "pwd",
    "token",
    "access_key",
    "accesskey",
    "private_key",
    "privatekey",
    "client_secret",
    "auth_token",
    "authtoken",
    "credential",
    "encryption_key",
];

/// Values that are obviously not real secrets.
const PLACEHOLDER_VALUES: &[&str] = &[
    "",
    "x",
    "xx",
    "xxx",
    "xxxx",
    "changeme",
    "change_me",
    "your_key_here",
    "your-key-here",
    "yourkeyhere",
    "todo",
    "none",
    "null",
    "example",
    "placeholder",
    "test",
    "password",
    "secret",
    "redacted",
];

impl Rule for HardcodedSecretRule {
    fn id(&self) -> &str {
        "hardcoded-secret"
    }

    fn name(&self) -> &str {
        "Hardcoded Secret"
    }

    fn description(&self) -> &str {
        "Detects API keys, passwords, and tokens committed directly into source code."
    }

    fn category(&self) -> Category {
        Category::Security
    }

    fn check(&self, file: &FileData) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_no, line) in file.numbered_lines() {
            if is_comment_only(line, file.language) {
                // Comments still get scanned for provider-token patterns below,
                // but skip the "keyword = value" heuristic to cut noise.
                if let Some(kind) = provider_token(line) {
                    findings.push(self.finding(file, line_no, kind));
                }
                continue;
            }

            // Known provider token formats (highest confidence).
            if let Some(kind) = provider_token(line) {
                findings.push(self.finding(file, line_no, kind));
                continue;
            }

            // Heuristic: `secretish_name = "value"`.
            if let Some(value) = secret_assignment(line) {
                if looks_like_real_secret(&value) {
                    findings.push(self.finding(file, line_no, "Hardcoded credential"));
                }
            }
        }

        findings
    }
}

impl HardcodedSecretRule {
    fn finding(&self, file: &FileData, line: usize, what: &str) -> Finding {
        Finding {
            rule: self.id().to_string(),
            title: "Hardcoded secret detected".to_string(),
            category: Category::Security,
            severity: Severity::Critical,
            file: file.path.clone(),
            line,
            message: format!("{what} found in source. Move it to an environment variable or secret manager."),
            suggestion: Some(
                "Load secrets from the environment (e.g. std::env::var / process.env) or a secrets vault."
                    .to_string(),
            ),
        }
    }
}

/// Detect a `keyword <assign> "value"` pattern and return the quoted value.
fn secret_assignment(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    // The identifier must appear before the assignment operator.
    let assign_pos = find_assignment(line)?;
    let (lhs, _rhs) = line.split_at(assign_pos);
    let lhs_lower = lower[..assign_pos].to_string();

    let has_keyword = SECRET_KEYWORDS.iter().any(|kw| lhs_lower.contains(kw));
    if !has_keyword {
        return None;
    }
    // Guard against matching a keyword that is only part of a larger word we
    // don't care about is acceptable here — false positives are cheap to mute.
    let _ = lhs;

    extract_string_literal(&line[assign_pos..])
}

/// Find the byte index of an assignment operator (`=`, `:`, `=>`), skipping
/// `==`, `!=`, `<=`, `>=` comparisons.
fn find_assignment(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'=' => {
                let prev = if i > 0 { bytes[i - 1] } else { b' ' };
                let next = if i + 1 < bytes.len() {
                    bytes[i + 1]
                } else {
                    b' '
                };
                // Skip comparison / arrow operators.
                if next == b'=' || matches!(prev, b'=' | b'!' | b'<' | b'>') {
                    i += 1;
                    continue;
                }
                return Some(i);
            }
            b':' => {
                // Avoid `::` (Rust paths) and ternary-ish uses.
                let next = if i + 1 < bytes.len() {
                    bytes[i + 1]
                } else {
                    b' '
                };
                if next == b':' {
                    i += 2;
                    continue;
                }
                return Some(i);
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Extract the first single- or double-quoted string literal from `s`.
fn extract_string_literal(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let q = bytes[i];
        if q == b'"' || q == b'\'' || q == b'`' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() {
                if bytes[j] == b'\\' {
                    j += 2;
                    continue;
                }
                if bytes[j] == q {
                    return Some(s[start..j].to_string());
                }
                j += 1;
            }
            return None;
        }
        i += 1;
    }
    None
}

/// Whether a string literal looks like an actual secret rather than a
/// placeholder or an environment lookup.
fn looks_like_real_secret(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < 6 {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if PLACEHOLDER_VALUES.contains(&lower.as_str()) {
        return false;
    }
    // Environment / interpolation references are not literal secrets.
    if trimmed.contains("process.env")
        || trimmed.contains("os.environ")
        || trimmed.contains("std::env")
        || trimmed.contains("${")
        || trimmed.contains("{{")
        || trimmed.starts_with("$")
    {
        return false;
    }
    // Require a reasonable mix of characters: at least one digit or symbol, or
    // sufficient length, to avoid flagging ordinary words.
    let has_digit = trimmed.chars().any(|c| c.is_ascii_digit());
    let has_symbol = trimmed
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !c.is_whitespace());
    has_digit || has_symbol || trimmed.len() >= 16
}

/// Recognize well-known provider token formats. Returns a label if matched.
fn provider_token(line: &str) -> Option<&'static str> {
    if contains_token_with_prefix(line, "AKIA", 16, true) {
        return Some("AWS access key id");
    }
    if contains_token_with_prefix(line, "ghp_", 30, false)
        || contains_token_with_prefix(line, "github_pat_", 20, false)
    {
        return Some("GitHub personal access token");
    }
    if contains_token_with_prefix(line, "xoxb-", 10, false)
        || contains_token_with_prefix(line, "xoxp-", 10, false)
    {
        return Some("Slack token");
    }
    if contains_token_with_prefix(line, "sk-", 20, false) {
        return Some("OpenAI-style secret key");
    }
    if line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") {
        return Some("Private key block");
    }
    None
}

/// Whether `line` contains a token starting with `prefix`, followed by at least
/// `min_suffix` token characters. If `upper_only`, the suffix must be uppercase
/// alphanumeric (as with AWS key ids).
fn contains_token_with_prefix(
    line: &str,
    prefix: &str,
    min_suffix: usize,
    upper_only: bool,
) -> bool {
    let mut search_from = 0;
    while let Some(rel) = line[search_from..].find(prefix) {
        let start = search_from + rel + prefix.len();
        let suffix: String = line[start..]
            .chars()
            .take_while(|c| {
                if upper_only {
                    c.is_ascii_uppercase() || c.is_ascii_digit()
                } else {
                    c.is_ascii_alphanumeric() || *c == '_' || *c == '-'
                }
            })
            .collect();
        if suffix.len() >= min_suffix {
            return true;
        }
        search_from = start.max(search_from + rel + 1);
    }
    false
}

// ---------------------------------------------------------------------------

/// Detects execution of shell commands built from potentially untrusted input.
pub struct DangerousCommandRule;

impl DangerousCommandRule {
    pub fn new() -> Self {
        DangerousCommandRule
    }
}

impl Default for DangerousCommandRule {
    fn default() -> Self {
        Self::new()
    }
}

/// `(needle, language filter, message)` triples describing dangerous sinks.
/// A `None` language means "any language".
struct Sink {
    needle: &'static str,
    lang: Option<Language>,
    what: &'static str,
}

const SINKS: &[Sink] = &[
    // Python
    Sink {
        needle: "os.system(",
        lang: Some(Language::Python),
        what: "os.system() shell execution",
    },
    Sink {
        needle: "subprocess.call(",
        lang: Some(Language::Python),
        what: "subprocess call",
    },
    Sink {
        needle: "subprocess.Popen(",
        lang: Some(Language::Python),
        what: "subprocess Popen",
    },
    Sink {
        needle: "shell=True",
        lang: Some(Language::Python),
        what: "subprocess with shell=True",
    },
    Sink {
        needle: "eval(",
        lang: Some(Language::Python),
        what: "eval() of dynamic input",
    },
    Sink {
        needle: "exec(",
        lang: Some(Language::Python),
        what: "exec() of dynamic input",
    },
    // Rust
    Sink {
        needle: "Command::new(",
        lang: Some(Language::Rust),
        what: "std::process::Command execution",
    },
    // JavaScript / TypeScript
    Sink {
        needle: "child_process",
        lang: None,
        what: "child_process usage",
    },
    Sink {
        needle: "exec(",
        lang: Some(Language::JavaScript),
        what: "exec() shell execution",
    },
    Sink {
        needle: "execSync(",
        lang: None,
        what: "execSync() shell execution",
    },
    Sink {
        needle: "eval(",
        lang: Some(Language::JavaScript),
        what: "eval() of dynamic input",
    },
    Sink {
        needle: "eval(",
        lang: Some(Language::TypeScript),
        what: "eval() of dynamic input",
    },
    // Shell
    Sink {
        needle: "eval ",
        lang: Some(Language::Shell),
        what: "eval of dynamic input",
    },
];

impl Rule for DangerousCommandRule {
    fn id(&self) -> &str {
        "dangerous-command"
    }

    fn name(&self) -> &str {
        "Dangerous Command"
    }

    fn description(&self) -> &str {
        "Detects shell/command execution and dynamic evaluation that can enable injection."
    }

    fn category(&self) -> Category {
        Category::Security
    }

    fn check(&self, file: &FileData) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_no, line) in file.numbered_lines() {
            if is_comment_only(line, file.language) {
                continue;
            }
            for sink in SINKS {
                if let Some(lang) = sink.lang {
                    if lang != file.language {
                        continue;
                    }
                }
                if line.contains(sink.needle) {
                    findings.push(Finding {
                        rule: self.id().to_string(),
                        title: "Dangerous command execution".to_string(),
                        category: Category::Security,
                        severity: Severity::High,
                        file: file.path.clone(),
                        line: line_no,
                        message: format!(
                            "{} detected. Validate/sanitize inputs and avoid passing user data to a shell.",
                            sink.what
                        ),
                        suggestion: Some(
                            "Prefer argument arrays over shell strings and never interpolate untrusted input."
                                .to_string(),
                        ),
                    });
                    break; // one finding per line is enough
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------

/// Whether a line is entirely a comment for the given language (best-effort).
fn is_comment_only(line: &str, lang: Language) -> bool {
    let t = line.trim_start();
    if t.is_empty() {
        return false;
    }
    match lang {
        Language::Python | Language::Ruby | Language::Shell => t.starts_with('#'),
        _ => t.starts_with("//") || t.starts_with('*') || t.starts_with("/*"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(content: &str, lang: Language) -> FileData {
        FileData {
            path: "test".into(),
            content: content.into(),
            lines: content.lines().count(),
            language: lang,
        }
    }

    #[test]
    fn flags_hardcoded_api_key() {
        let f = file("const API_KEY = \"abc123def456\";", Language::JavaScript);
        let findings = HardcodedSecretRule::new().check(&f);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn ignores_env_lookup() {
        let f = file("const API_KEY = process.env.API_KEY;", Language::JavaScript);
        assert!(HardcodedSecretRule::new().check(&f).is_empty());
    }

    #[test]
    fn ignores_placeholder() {
        let f = file("password = \"changeme\"", Language::Python);
        assert!(HardcodedSecretRule::new().check(&f).is_empty());
    }

    #[test]
    fn flags_aws_key() {
        let f = file("id = AKIAIOSFODNN7EXAMPLE", Language::Python);
        let findings = HardcodedSecretRule::new().check(&f);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_python_os_system() {
        let f = file("os.system(user_input)", Language::Python);
        let findings = DangerousCommandRule::new().check(&f);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn flags_rust_command() {
        let f = file("Command::new(user_input).spawn();", Language::Rust);
        assert_eq!(DangerousCommandRule::new().check(&f).len(), 1);
    }

    #[test]
    fn language_filter_prevents_cross_language_hits() {
        // os.system is a Python sink; should not fire on Rust.
        let f = file("os.system(x)", Language::Rust);
        assert!(DangerousCommandRule::new().check(&f).is_empty());
    }
}
