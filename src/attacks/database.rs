//! Database attack helpers: SQL-injection response signatures and the
//! heuristics used to evaluate static `.klr` rules like
//! `input reaches query without sanitization`.

/// SQL error strings that commonly leak when an injection reaches the database.
const SQL_ERROR_SIGNATURES: &[&str] = &[
    "sql syntax",
    "syntax error at or near",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "you have an error in your sql syntax",
    "sqlite3.operationalerror",
    "psql:",
    "pg::",
    "ora-00933",
    "odbc sql",
    "mysql_fetch",
    "warning: mysql",
];

/// Whether a response body contains a database error signature.
pub fn response_indicates_sqli(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    SQL_ERROR_SIGNATURES.iter().any(|sig| lower.contains(sig))
}

/// Tokens that suggest a line reads untrusted input.
const INPUT_SOURCES: &[&str] = &[
    "input",
    "req.",
    "request.",
    "params",
    "query_params",
    "body",
    "argv",
    "user_input",
    "form",
    ".get(",
    ".post(",
    "getparameter",
    "read_line",
    "stdin",
    "$_get",
    "$_post",
    "$_request",
];

/// Tokens that suggest a query is parameterized / sanitized.
const SANITIZERS: &[&str] = &[
    "sanitize",
    "escape",
    "prepared",
    "prepare(",
    "parameterized",
    "bind_param",
    "bindparam",
    "placeholder",
    "?",
    "$1",
    "%s",
    ":param",
];

/// Whether a line appears to read untrusted input.
pub fn line_reads_input(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    INPUT_SOURCES.iter().any(|s| l.contains(s))
}

/// Signals that a line builds a string dynamically (concatenation or
/// interpolation) — the hallmark of an injectable query.
const DYNAMIC_STRING_SIGNALS: &[&str] = &[
    "\" +", "+ \"", "' +", "+ '", // concatenation
    "f\"", "f'",       // Python f-strings
    ".format(", // str.format
    "${",       // template interpolation
    "format!",  // Rust format!
    "%(",       // printf-style / Python %
];

/// Whether a line appears to build a string dynamically.
pub fn line_builds_dynamic_string(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    DYNAMIC_STRING_SIGNALS.iter().any(|s| l.contains(s))
}

/// Whether a line looks like untrusted data reaches a sink on that line —
/// either a direct input source or dynamic string construction.
pub fn line_reaches_sink(line: &str) -> bool {
    line_reads_input(line) || line_builds_dynamic_string(line)
}

/// Whether a line appears to sanitize / parameterize its query.
pub fn line_is_sanitized(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    SANITIZERS.iter().any(|s| l.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sql_errors() {
        assert!(response_indicates_sqli(
            "You have an error in your SQL syntax near ..."
        ));
        assert!(!response_indicates_sqli("login failed"));
    }

    #[test]
    fn input_and_sanitizer_detection() {
        assert!(line_reads_input(
            "let q = format!(\"SELECT * WHERE u={}\", req.user_input);"
        ));
        assert!(line_is_sanitized(
            "stmt = conn.prepare(\"SELECT * WHERE u=?\");"
        ));
        assert!(!line_is_sanitized("let q = \"SELECT 1\";"));
    }
}
