//! A small, clean module with no findings.

/// Add two numbers.
pub fn add(a: i64, b: i64) -> i64 {
    a + b
}

/// Multiply two numbers.
pub fn mul(a: i64, b: i64) -> i64 {
    a * b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic() {
        assert_eq!(add(2, 3), 5);
        assert_eq!(mul(2, 3), 6);
    }
}
