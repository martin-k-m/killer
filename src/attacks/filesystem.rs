//! Filesystem attack helpers: path-traversal payload detection and response
//! inspection for exposed sensitive files.

/// Whether a payload looks like a path-traversal attempt.
pub fn is_path_traversal(payload: &str) -> bool {
    let p = payload.to_ascii_lowercase();
    p.contains("../")
        || p.contains("..\\")
        || p.contains("%2e%2e")
        || p.contains("/etc/passwd")
        || p.contains("\\windows\\")
        || p.contains("boot.ini")
}

/// Signatures that indicate a sensitive file leaked into a response body.
const EXPOSURE_SIGNATURES: &[&str] = &[
    "root:x:0:0",             // /etc/passwd
    "root:*:0:0",             // /etc/passwd (BSD)
    "daemon:x:",              // /etc/passwd entries
    "[boot loader]",          // boot.ini
    "for 16-bit app support", // win.ini
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
];

/// Whether a response body appears to contain the contents of a sensitive file.
pub fn response_exposes_file(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    EXPOSURE_SIGNATURES
        .iter()
        .any(|sig| lower.contains(&sig.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_traversal_payloads() {
        assert!(is_path_traversal("../../etc/passwd"));
        assert!(is_path_traversal("..\\..\\windows\\system32"));
        assert!(is_path_traversal("%2e%2e/secret"));
        assert!(!is_path_traversal("avatar.png"));
    }

    #[test]
    fn detects_exposed_passwd() {
        assert!(response_exposes_file("root:x:0:0:root:/root:/bin/bash\n"));
        assert!(!response_exposes_file("upload succeeded"));
    }
}
