//! Built-in security test suites, embedded in the binary at compile time.
//!
//! `killer test --suite <name>` runs one of these without needing any `.klr`
//! files in the project. They are ordinary `.klr` source, parsed and executed
//! by the same runtime as user suites.

/// A built-in suite: its short name and embedded `.klr` source.
pub struct BuiltinSuite {
    pub name: &'static str,
    pub description: &'static str,
    pub source: &'static str,
}

const SUITES: &[BuiltinSuite] = &[
    BuiltinSuite {
        name: "authentication",
        description: "Login bypass, brute-force, and protected-route checks.",
        source: include_str!("../suites/authentication.klr"),
    },
    BuiltinSuite {
        name: "web",
        description: "Reflected XSS and path traversal.",
        source: include_str!("../suites/web.klr"),
    },
    BuiltinSuite {
        name: "api",
        description: "Input-injection fuzzing and rate limiting.",
        source: include_str!("../suites/api.klr"),
    },
];

/// Look up a built-in suite by name (case-insensitive).
pub fn get(name: &str) -> Option<&'static BuiltinSuite> {
    let name = name.trim().to_ascii_lowercase();
    SUITES.iter().find(|s| s.name.eq_ignore_ascii_case(&name))
}

/// All built-in suites.
pub fn all() -> &'static [BuiltinSuite] {
    SUITES
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::klr::parse;

    #[test]
    fn all_builtin_suites_parse() {
        for suite in all() {
            let program = parse(suite.source)
                .unwrap_or_else(|e| panic!("suite {} failed to parse: {e}", suite.name));
            assert!(
                !program.suites.is_empty() || !program.attacks.is_empty(),
                "suite {} has no tests",
                suite.name
            );
        }
    }

    #[test]
    fn lookup_is_case_insensitive() {
        assert!(get("AUTHENTICATION").is_some());
        assert!(get("web").is_some());
        assert!(get("nonexistent").is_none());
    }
}
