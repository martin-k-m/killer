//! The knowledge base behind `killer explain <ISSUE_ID>`.
//!
//! Each attack outcome carries a stable `issue_id` (e.g. `KLR-SQLI`). This
//! module maps those ids to a human explanation, impact, and remediation.

/// A knowledge-base entry for one issue class.
pub struct Explanation {
    pub id: &'static str,
    pub title: &'static str,
    pub summary: &'static str,
    pub impact: &'static str,
    pub remediation: &'static str,
    pub references: &'static [&'static str],
}

const ENTRIES: &[Explanation] = &[
    Explanation {
        id: "KLR-SQLI",
        title: "SQL Injection",
        summary: "Untrusted input is incorporated into a SQL query, letting an attacker alter the query's logic (e.g. `' OR 1=1`).",
        impact: "Authentication bypass, reading or modifying arbitrary data, and in some cases full database or host compromise.",
        remediation: "Use parameterized queries / prepared statements. Never build SQL by string concatenation with user input. Apply least-privilege database accounts.",
        references: &[
            "OWASP: SQL Injection",
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        ],
    },
    Explanation {
        id: "KLR-PATH-TRAVERSAL",
        title: "Path Traversal",
        summary: "A file path derived from user input (e.g. `../../etc/passwd`) escapes the intended directory and reaches sensitive files.",
        impact: "Disclosure of configuration, credentials, or system files; sometimes arbitrary file write leading to code execution.",
        remediation: "Canonicalize and validate paths against an allow-listed base directory. Reject `..` segments. Prefer opaque identifiers over raw file names.",
        references: &[
            "OWASP: Path Traversal",
            "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
        ],
    },
    Explanation {
        id: "KLR-RATE-LIMIT",
        title: "Missing Rate Limiting",
        summary: "An endpoint accepts unlimited requests, so it never blocks abusive clients.",
        impact: "Credential stuffing and brute-force attacks, resource exhaustion, and denial of service.",
        remediation: "Enforce per-IP and per-account rate limits, exponential backoff, and account lockout or CAPTCHA after repeated failures.",
        references: &[
            "OWASP: Blocking Brute Force Attacks",
            "CWE-307: Improper Restriction of Excessive Authentication Attempts",
        ],
    },
    Explanation {
        id: "KLR-SESSION",
        title: "Session Management Weakness",
        summary: "A session identifier remains valid when it should not — for example a stolen cookie is still accepted after logout or reuse.",
        impact: "Session hijacking and impersonation of authenticated users.",
        remediation: "Invalidate sessions server-side on logout and on privilege changes, rotate identifiers after login, and set `HttpOnly`, `Secure`, and `SameSite` cookie attributes.",
        references: &[
            "OWASP: Session Management Cheat Sheet",
            "CWE-384: Session Fixation",
        ],
    },
    Explanation {
        id: "KLR-GENERIC",
        title: "Security Expectation Failed",
        summary: "An attack's expectations were not met, indicating the target behaved insecurely under the tested conditions.",
        impact: "Varies with the specific check that failed; review the attack report for the exact expectation and observed behavior.",
        remediation: "Inspect the failing expectation, reproduce it manually, and apply the appropriate input validation, authorization, or hardening.",
        references: &["OWASP Top 10"],
    },
];

/// Look up an explanation by id (case-insensitive).
pub fn lookup(id: &str) -> Option<&'static Explanation> {
    let id = id.trim().to_ascii_uppercase();
    ENTRIES.iter().find(|e| e.id.eq_ignore_ascii_case(&id))
}

/// All known issue ids, for help text.
pub fn all_ids() -> Vec<&'static str> {
    ENTRIES.iter().map(|e| e.id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_up_case_insensitively() {
        assert!(lookup("klr-sqli").is_some());
        assert_eq!(lookup("KLR-SQLI").unwrap().title, "SQL Injection");
    }

    #[test]
    fn unknown_id_returns_none() {
        assert!(lookup("KLR-DOES-NOT-EXIST").is_none());
    }
}
