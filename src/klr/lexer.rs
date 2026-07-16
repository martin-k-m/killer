//! The `.klr` lexer: turns source text into a stream of [`Token`]s.
//!
//! The language is line-oriented, so newlines are emitted as [`Token::Newline`]
//! (with consecutive blank lines collapsed) and used by the parser as soft
//! statement separators. Comments start with `#` or `//` and run to end of line.

use std::fmt;

/// A lexical token with its 1-indexed source line.
#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub line: usize,
}

/// The kinds of tokens the lexer produces.
#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    /// A bare word (keywords are not distinguished here — the parser matches
    /// them by string, which keeps the keyword set open and easy to extend).
    Ident(String),
    /// A double-quoted string literal (unescaped).
    Str(String),
    /// An integer literal.
    Num(i64),

    LBrace,
    RBrace,
    Colon,
    /// `=`
    Assign,
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `>`
    Gt,
    /// `<=`
    Le,
    /// `>=`
    Ge,

    /// A statement separator (one or more source newlines).
    Newline,
    /// End of input.
    Eof,
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenKind::Ident(s) => write!(f, "identifier `{s}`"),
            TokenKind::Str(s) => write!(f, "string \"{s}\""),
            TokenKind::Num(n) => write!(f, "number {n}"),
            TokenKind::LBrace => f.write_str("`{`"),
            TokenKind::RBrace => f.write_str("`}`"),
            TokenKind::Colon => f.write_str("`:`"),
            TokenKind::Assign => f.write_str("`=`"),
            TokenKind::Eq => f.write_str("`==`"),
            TokenKind::Ne => f.write_str("`!=`"),
            TokenKind::Lt => f.write_str("`<`"),
            TokenKind::Gt => f.write_str("`>`"),
            TokenKind::Le => f.write_str("`<=`"),
            TokenKind::Ge => f.write_str("`>=`"),
            TokenKind::Newline => f.write_str("end of line"),
            TokenKind::Eof => f.write_str("end of file"),
        }
    }
}

/// An error encountered while lexing.
#[derive(Debug, Clone, PartialEq)]
pub struct LexError {
    pub message: String,
    pub line: usize,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for LexError {}

/// Tokenize `src` into a vector of tokens terminated by [`TokenKind::Eof`].
pub fn tokenize(src: &str) -> Result<Vec<Token>, LexError> {
    // Skip a leading UTF-8 BOM (common in Windows-edited files).
    let src = src.strip_prefix('\u{feff}').unwrap_or(src);

    let chars: Vec<char> = src.chars().collect();
    let mut tokens: Vec<Token> = Vec::new();
    let mut i = 0;
    let mut line = 1usize;

    // Whether the last emitted token was a Newline, to collapse runs.
    let mut pending_newline = false;

    macro_rules! push {
        ($kind:expr) => {{
            tokens.push(Token { kind: $kind, line });
            pending_newline = false;
        }};
    }

    while i < chars.len() {
        let c = chars[i];

        match c {
            '\n' => {
                // Collapse consecutive newlines; never lead with one.
                if !pending_newline && !tokens.is_empty() {
                    tokens.push(Token {
                        kind: TokenKind::Newline,
                        line,
                    });
                    pending_newline = true;
                }
                line += 1;
                i += 1;
            }
            ' ' | '\t' | '\r' => {
                i += 1;
            }
            '#' => {
                // Comment to end of line.
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if i + 1 < chars.len() && chars[i + 1] == '/' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '{' => {
                push!(TokenKind::LBrace);
                i += 1;
            }
            '}' => {
                push!(TokenKind::RBrace);
                i += 1;
            }
            ':' => {
                push!(TokenKind::Colon);
                i += 1;
            }
            '=' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    push!(TokenKind::Eq);
                    i += 2;
                } else {
                    push!(TokenKind::Assign);
                    i += 1;
                }
            }
            '!' if i + 1 < chars.len() && chars[i + 1] == '=' => {
                push!(TokenKind::Ne);
                i += 2;
            }
            '<' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    push!(TokenKind::Le);
                    i += 2;
                } else {
                    push!(TokenKind::Lt);
                    i += 1;
                }
            }
            '>' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    push!(TokenKind::Ge);
                    i += 2;
                } else {
                    push!(TokenKind::Gt);
                    i += 1;
                }
            }
            '"' => {
                let (s, next) = lex_string(&chars, i, line)?;
                push!(TokenKind::Str(s));
                i = next;
            }
            c if c.is_ascii_digit() => {
                let (n, next) = lex_number(&chars, i);
                push!(TokenKind::Num(n));
                i = next;
            }
            // A leading '-' followed by a digit is a negative number.
            '-' if i + 1 < chars.len() && chars[i + 1].is_ascii_digit() => {
                let (n, next) = lex_number(&chars, i + 1);
                push!(TokenKind::Num(-n));
                i = next;
            }
            c if is_ident_start(c) => {
                let (s, next) = lex_ident(&chars, i);
                push!(TokenKind::Ident(s));
                i = next;
            }
            other => {
                return Err(LexError {
                    message: format!("unexpected character '{other}'"),
                    line,
                });
            }
        }
    }

    // Trailing newline (if any) then Eof.
    tokens.push(Token {
        kind: TokenKind::Eof,
        line,
    });
    Ok(tokens)
}

fn lex_string(chars: &[char], start: usize, line: usize) -> Result<(String, usize), LexError> {
    // chars[start] == '"'
    let mut out = String::new();
    let mut i = start + 1;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' if i + 1 < chars.len() => {
                let esc = chars[i + 1];
                out.push(match esc {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '\\' => '\\',
                    '"' => '"',
                    '0' => '\0',
                    other => other,
                });
                i += 2;
            }
            '"' => {
                return Ok((out, i + 1));
            }
            '\n' => {
                return Err(LexError {
                    message: "unterminated string literal".to_string(),
                    line,
                });
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    Err(LexError {
        message: "unterminated string literal".to_string(),
        line,
    })
}

fn lex_number(chars: &[char], start: usize) -> (i64, usize) {
    let mut i = start;
    let mut n: i64 = 0;
    while i < chars.len() && chars[i].is_ascii_digit() {
        n = n
            .saturating_mul(10)
            .saturating_add((chars[i] as u8 - b'0') as i64);
        i += 1;
    }
    (n, i)
}

fn lex_ident(chars: &[char], start: usize) -> (String, usize) {
    let mut i = start;
    let mut out = String::new();
    while i < chars.len() && is_ident_continue(chars[i]) {
        out.push(chars[i]);
        i += 1;
    }
    (out, i)
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_continue(c: char) -> bool {
    // Allow common code-ish characters inside identifiers so that rule targets
    // like `get(` or `user_input` tokenize as a single word where sensible.
    c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '/' || c == '-'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<TokenKind> {
        tokenize(src).unwrap().into_iter().map(|t| t.kind).collect()
    }

    #[test]
    fn lexes_operators() {
        let k = kinds("status != 200");
        assert_eq!(
            k,
            vec![
                TokenKind::Ident("status".into()),
                TokenKind::Ne,
                TokenKind::Num(200),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn lexes_assignment_and_string() {
        let k = kinds("username = \"' OR 1=1\"");
        assert_eq!(
            k,
            vec![
                TokenKind::Ident("username".into()),
                TokenKind::Assign,
                TokenKind::Str("' OR 1=1".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn collapses_newlines_and_skips_comments() {
        let src = "a\n\n# comment\n\nb\n";
        let k = kinds(src);
        assert_eq!(
            k,
            vec![
                TokenKind::Ident("a".into()),
                TokenKind::Newline,
                TokenKind::Ident("b".into()),
                TokenKind::Newline,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn lexes_braces_and_colon() {
        let k = kinds("send { }: ");
        assert_eq!(
            k,
            vec![
                TokenKind::Ident("send".into()),
                TokenKind::LBrace,
                TokenKind::RBrace,
                TokenKind::Colon,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn comparison_variants() {
        assert_eq!(
            kinds("<= >= == < >"),
            vec![
                TokenKind::Le,
                TokenKind::Ge,
                TokenKind::Eq,
                TokenKind::Lt,
                TokenKind::Gt,
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn error_on_unterminated_string() {
        let err = tokenize("x = \"oops\n").unwrap_err();
        assert!(err.message.contains("unterminated"));
    }

    #[test]
    fn skips_leading_bom() {
        let k = kinds("\u{feff}attack");
        assert_eq!(k, vec![TokenKind::Ident("attack".into()), TokenKind::Eof]);
    }
}
