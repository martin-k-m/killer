//! The `.klr` parser: a hand-written recursive-descent parser that turns the
//! token stream from [`crate::klr::lexer`] into a [`Program`] AST.
//!
//! The grammar is line-oriented. Newlines separate statements; `{ }` blocks
//! group key/value pairs (`send`, `header`) and expectation lists (`expect`).
//! A leading `:` after a keyword is accepted but optional, so both the
//! brace-form and colon-form shown in the language docs parse.

use std::fmt;

use crate::analyzer::Severity;
use crate::klr::ast::*;
use crate::klr::lexer::{tokenize, Token, TokenKind};

/// An error encountered while parsing a `.klr` file, with a stable code
/// (e.g. `KLR001`) and, where known, structured `expected` / `found` fields
/// for rich diagnostics.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub code: &'static str,
    pub message: String,
    pub line: usize,
    pub expected: Option<String>,
    pub found: Option<String>,
}

impl ParseError {
    pub fn new(code: &'static str, message: impl Into<String>, line: usize) -> ParseError {
        ParseError {
            code,
            message: message.into(),
            line,
            expected: None,
            found: None,
        }
    }

    /// An "expected X, found Y" error with structured fields.
    pub fn expected(
        code: &'static str,
        expected: impl Into<String>,
        found: impl Into<String>,
        line: usize,
    ) -> ParseError {
        let expected = expected.into();
        let found = found.into();
        ParseError {
            code,
            message: format!("expected {expected}, found {found}"),
            line,
            expected: Some(expected),
            found: Some(found),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] line {}: {}", self.code, self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Parse `.klr` source into a [`Program`].
pub fn parse(src: &str) -> Result<Program, ParseError> {
    let tokens = tokenize(src).map_err(|e| ParseError::new("KLR010", e.message, e.line))?;
    Parser::new(tokens).parse_program()
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Parser { tokens, pos: 0 }
    }

    // --- token helpers -----------------------------------------------------

    fn peek(&self) -> &TokenKind {
        &self.tokens[self.pos].kind
    }

    fn peek_line(&self) -> usize {
        self.tokens[self.pos].line
    }

    fn advance(&mut self) -> Token {
        let t = self.tokens[self.pos].clone();
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        t
    }

    fn at_eof(&self) -> bool {
        matches!(self.peek(), TokenKind::Eof)
    }

    fn err<T>(&self, message: impl Into<String>) -> Result<T, ParseError> {
        Err(ParseError::new("KLR001", message, self.peek_line()))
    }

    /// An "expected X, found <current token>" error (code KLR001).
    fn err_expected<T>(&self, what: &str) -> Result<T, ParseError> {
        Err(ParseError::expected(
            "KLR001",
            what,
            self.peek().to_string(),
            self.peek_line(),
        ))
    }

    /// Skip any run of newline separators.
    fn skip_newlines(&mut self) {
        while matches!(self.peek(), TokenKind::Newline) {
            self.advance();
        }
    }

    /// Consume the end of a statement: a newline, or the end of a block/file.
    fn end_statement(&mut self) -> Result<(), ParseError> {
        match self.peek() {
            TokenKind::Newline => {
                self.advance();
                Ok(())
            }
            TokenKind::RBrace | TokenKind::Eof => Ok(()),
            other => Err(ParseError::expected(
                "KLR001",
                "end of line",
                other.to_string(),
                self.peek_line(),
            )),
        }
    }

    /// Consume an optional leading colon (both `send:` and `send` are allowed).
    fn eat_optional_colon(&mut self) {
        if matches!(self.peek(), TokenKind::Colon) {
            self.advance();
        }
    }

    fn expect_ident(&mut self, what: &str) -> Result<String, ParseError> {
        match self.peek().clone() {
            TokenKind::Ident(s) => {
                self.advance();
                Ok(s)
            }
            _ => self.err_expected(what),
        }
    }

    fn expect_string(&mut self, what: &str) -> Result<String, ParseError> {
        match self.peek().clone() {
            TokenKind::Str(s) => {
                self.advance();
                Ok(s)
            }
            _ => self.err_expected(what),
        }
    }

    fn expect_num(&mut self, what: &str) -> Result<i64, ParseError> {
        match self.peek().clone() {
            TokenKind::Num(n) => {
                self.advance();
                Ok(n)
            }
            _ => self.err_expected(what),
        }
    }

    fn expect(&mut self, kind: TokenKind, what: &str) -> Result<(), ParseError> {
        if *self.peek() == kind {
            self.advance();
            Ok(())
        } else {
            self.err_expected(what)
        }
    }

    // --- grammar -----------------------------------------------------------

    fn parse_program(&mut self) -> Result<Program, ParseError> {
        let mut program = Program::default();

        loop {
            self.skip_newlines();
            if self.at_eof() {
                break;
            }
            match self.peek().clone() {
                TokenKind::Ident(kw) => match kw.as_str() {
                    "project" => {
                        self.advance();
                        program.project = Some(self.expect_string("a project name string")?);
                        self.end_statement()?;
                    }
                    "attack" | "test" => {
                        let attack = self.parse_attack()?;
                        program.attacks.push(attack);
                    }
                    "suite" => {
                        let suite = self.parse_suite()?;
                        program.suites.push(suite);
                    }
                    "repeat" => {
                        let attacks = self.parse_repeat_block()?;
                        program.attacks.extend(attacks);
                    }
                    "rule" => {
                        let rule = self.parse_rule()?;
                        program.rules.push(rule);
                    }
                    other => {
                        return Err(ParseError::new(
                            "KLR002",
                            format!("expected `project`, `suite`, `attack`, `test`, or `rule`, found `{other}`"),
                            self.peek_line(),
                        ));
                    }
                },
                _ => {
                    return self.err_expected("a top-level declaration");
                }
            }
        }

        Ok(program)
    }

    /// Parse an `attack <name> { ... }` or `test <name> { ... }` block. The
    /// leading keyword has not yet been consumed.
    fn parse_attack(&mut self) -> Result<Attack, ParseError> {
        let line = self.peek_line();
        self.advance(); // `attack` or `test`
        let name = self.expect_ident("an attack/test name")?;
        self.skip_newlines();
        self.expect(TokenKind::LBrace, "`{` to open the body")?;

        let mut attack = Attack::empty(name, line);

        loop {
            self.skip_newlines();
            if matches!(self.peek(), TokenKind::RBrace) {
                break;
            }
            if self.at_eof() {
                return self.err("unterminated body: expected `}`");
            }
            self.parse_attack_stmt(&mut attack)?;
            self.end_statement()?;
        }
        self.expect(TokenKind::RBrace, "`}` to close the body")?;

        Ok(attack)
    }

    /// Parse `suite "name" { <attack|test|repeat>* }`.
    fn parse_suite(&mut self) -> Result<Suite, ParseError> {
        let line = self.peek_line();
        self.advance(); // `suite`
        let name = self.expect_string("a suite name string")?;
        self.skip_newlines();
        self.expect(TokenKind::LBrace, "`{` to open the suite")?;

        let mut attacks = Vec::new();
        loop {
            self.skip_newlines();
            if matches!(self.peek(), TokenKind::RBrace) {
                break;
            }
            if self.at_eof() {
                return self.err("unterminated suite: expected `}`");
            }
            match self.peek().clone() {
                TokenKind::Ident(kw) if kw == "attack" || kw == "test" => {
                    attacks.push(self.parse_attack()?);
                }
                TokenKind::Ident(kw) if kw == "repeat" => {
                    attacks.extend(self.parse_repeat_block()?);
                }
                _ => return self.err_expected("`attack`, `test`, or `repeat` inside the suite"),
            }
        }
        self.expect(TokenKind::RBrace, "`}` to close the suite")?;
        Ok(Suite {
            name,
            attacks,
            line,
        })
    }

    /// Parse `repeat N { <attack|test>* }`, expanding the loop by multiplying
    /// each inner attack's request repeat-count by N.
    fn parse_repeat_block(&mut self) -> Result<Vec<Attack>, ParseError> {
        self.advance(); // `repeat`
        let n = self.expect_num("a repeat count")?.max(1) as usize;
        self.skip_newlines();
        self.expect(TokenKind::LBrace, "`{` to open the repeat block")?;

        let mut attacks = Vec::new();
        loop {
            self.skip_newlines();
            if matches!(self.peek(), TokenKind::RBrace) {
                break;
            }
            if self.at_eof() {
                return self.err("unterminated repeat block: expected `}`");
            }
            match self.peek().clone() {
                TokenKind::Ident(kw) if kw == "attack" || kw == "test" => {
                    let mut a = self.parse_attack()?;
                    a.repeat = Some(a.repeat.unwrap_or(1).saturating_mul(n).max(n));
                    attacks.push(a);
                }
                _ => return self.err_expected("`attack` or `test` inside the repeat block"),
            }
        }
        self.expect(TokenKind::RBrace, "`}` to close the repeat block")?;
        Ok(attacks)
    }

    fn parse_attack_stmt(&mut self, attack: &mut Attack) -> Result<(), ParseError> {
        let kw = match self.peek().clone() {
            TokenKind::Ident(s) => s,
            other => return self.err(format!("expected a statement, found {other}")),
        };

        match kw.as_str() {
            "target" | "endpoint" | "url" => {
                self.advance();
                attack.target = Some(self.expect_string("a target path or URL")?);
            }
            "method" => {
                self.advance();
                attack.method = Some(self.expect_ident("an HTTP method")?.to_uppercase());
            }
            "request" => {
                self.advance();
                self.eat_optional_colon();
                attack.method = Some(self.expect_ident("an HTTP method")?.to_uppercase());
                attack.target = Some(self.expect_string("a request path")?);
            }
            "send" => {
                self.advance();
                self.eat_optional_colon();
                attack.send = self.parse_kv_block()?;
            }
            "header" | "headers" => {
                self.advance();
                self.eat_optional_colon();
                attack.headers = self.parse_kv_block()?;
            }
            "payload" => {
                self.advance();
                self.eat_optional_colon();
                attack.payload = Some(self.expect_string("a payload string")?);
            }
            "repeat" => {
                self.advance();
                self.eat_optional_colon();
                let n = self.expect_num("a repeat count")?;
                attack.repeat = Some(n.max(0) as usize);
                // Optional trailing `times`.
                if matches!(self.peek(), TokenKind::Ident(w) if w == "times") {
                    self.advance();
                }
            }
            "expect" => {
                self.advance();
                self.eat_optional_colon();
                if matches!(self.peek(), TokenKind::LBrace) {
                    let exps = self.parse_expect_block()?;
                    attack.expectations.extend(exps);
                } else {
                    let exp = self.parse_expectation()?;
                    attack.expectations.push(exp);
                }
            }
            "severity" => {
                self.advance();
                let word = self.expect_ident("a severity level")?;
                attack.severity = Severity::from_word(&word).ok_or_else(|| {
                    ParseError::new(
                        "KLR003",
                        format!("unknown severity `{word}`"),
                        self.peek_line(),
                    )
                })?;
            }
            "message" => {
                self.advance();
                self.eat_optional_colon();
                attack.message = Some(self.expect_string("a message string")?);
            }
            "check" => {
                self.advance();
                // One or more check names on the line (`check authentication`).
                while let TokenKind::Ident(name) = self.peek().clone() {
                    self.advance();
                    attack.checks.push(name);
                }
            }
            "mutate" => {
                self.advance();
                let field = match self.peek().clone() {
                    TokenKind::Ident(s) | TokenKind::Str(s) => {
                        self.advance();
                        s
                    }
                    _ => return self.err_expected("a field name to mutate"),
                };
                self.eat_optional_colon();
                self.expect(TokenKind::LBrace, "`{` to open the mutate block")?;
                let mut generators = Vec::new();
                loop {
                    self.skip_newlines();
                    if matches!(self.peek(), TokenKind::RBrace) {
                        break;
                    }
                    if self.at_eof() {
                        return self.err("unterminated mutate block: expected `}`");
                    }
                    match self.peek().clone() {
                        TokenKind::Ident(g) => {
                            self.advance();
                            generators.push(g);
                        }
                        _ => return self.err_expected("a mutation generator name"),
                    }
                }
                self.expect(TokenKind::RBrace, "`}` to close the mutate block")?;
                attack.mutations.push(Mutation { field, generators });
            }
            _ => {
                // Generic action statement: verb followed by value arguments.
                let verb = self.expect_ident("an action verb")?;
                let mut args = Vec::new();
                while let Some(v) = self.try_parse_value() {
                    args.push(v);
                }
                attack.actions.push(Action { verb, args });
            }
        }
        Ok(())
    }

    /// Parse a `{ key = value ... }` block.
    fn parse_kv_block(&mut self) -> Result<Vec<(String, Value)>, ParseError> {
        self.expect(TokenKind::LBrace, "`{` to open the block")?;
        let mut entries = Vec::new();
        loop {
            self.skip_newlines();
            if matches!(self.peek(), TokenKind::RBrace) {
                break;
            }
            if self.at_eof() {
                return self.err("unterminated block: expected `}`");
            }
            // Key may be an identifier or a quoted string (e.g. header names).
            let key = match self.peek().clone() {
                TokenKind::Ident(s) => {
                    self.advance();
                    s
                }
                TokenKind::Str(s) => {
                    self.advance();
                    s
                }
                other => return self.err(format!("expected a key, found {other}")),
            };
            self.expect(TokenKind::Assign, "`=` after the key")?;
            let value = self.parse_value()?;
            entries.push((key, value));
            // Entries may be separated by newlines or simply by whitespace, so
            // we do not require an explicit end-of-line here.
        }
        self.expect(TokenKind::RBrace, "`}` to close the block")?;
        Ok(entries)
    }

    fn parse_expect_block(&mut self) -> Result<Vec<Expectation>, ParseError> {
        self.expect(TokenKind::LBrace, "`{` to open the expect block")?;
        let mut exps = Vec::new();
        loop {
            self.skip_newlines();
            if matches!(self.peek(), TokenKind::RBrace) {
                break;
            }
            if self.at_eof() {
                return self.err("unterminated expect block: expected `}`");
            }
            exps.push(self.parse_expectation()?);
            // Expectations may be newline- or whitespace-separated.
        }
        self.expect(TokenKind::RBrace, "`}` to close the expect block")?;
        Ok(exps)
    }

    fn parse_expectation(&mut self) -> Result<Expectation, ParseError> {
        let head = match self.peek().clone() {
            TokenKind::Ident(s) => s,
            other => return self.err(format!("expected an expectation, found {other}")),
        };

        match head.as_str() {
            "status" => {
                self.advance();
                let op = self.parse_compare_op()?;
                let value = self.expect_num("a status code")?;
                Ok(Expectation::Status { op, value })
            }
            "response" | "body" => {
                self.advance();
                let verb = self.expect_ident("`contains` or `does_not_contain`")?;
                let needle = self.expect_string("a string to look for")?;
                match verb.as_str() {
                    "contains" => Ok(Expectation::ResponseContains(needle)),
                    "does_not_contain" | "not_contains" | "excludes" => {
                        Ok(Expectation::ResponseNotContains(needle))
                    }
                    other => self.err(format!(
                        "expected `contains` or `does_not_contain`, found `{other}`"
                    )),
                }
            }
            "blocked_after" => {
                self.advance();
                let n = self.expect_num("a request count")?;
                Ok(Expectation::BlockedAfter(n.max(0) as usize))
            }
            _ => {
                // Named boolean expectation, e.g. `session_invalidated true`.
                let name = self.expect_ident("an expectation name")?;
                let expected = match self.peek().clone() {
                    TokenKind::Ident(b) if b == "true" => {
                        self.advance();
                        true
                    }
                    TokenKind::Ident(b) if b == "false" => {
                        self.advance();
                        false
                    }
                    // Bare `file_not_exposed` means it should hold.
                    _ => true,
                };
                Ok(Expectation::Named { name, expected })
            }
        }
    }

    fn parse_compare_op(&mut self) -> Result<CompareOp, ParseError> {
        let op = match self.peek() {
            TokenKind::Eq | TokenKind::Assign => CompareOp::Eq,
            TokenKind::Ne => CompareOp::Ne,
            TokenKind::Lt => CompareOp::Lt,
            TokenKind::Gt => CompareOp::Gt,
            TokenKind::Le => CompareOp::Le,
            TokenKind::Ge => CompareOp::Ge,
            other => {
                let other = other.clone();
                return self.err(format!("expected a comparison operator, found {other}"));
            }
        };
        self.advance();
        Ok(op)
    }

    fn parse_value(&mut self) -> Result<Value, ParseError> {
        self.try_parse_value()
            .ok_or(())
            .or_else(|_| self.err("expected a value (string, number, or word)"))
    }

    /// Parse a value if the next token is one; otherwise leave the cursor.
    fn try_parse_value(&mut self) -> Option<Value> {
        match self.peek().clone() {
            TokenKind::Str(s) => {
                self.advance();
                Some(Value::Str(s))
            }
            TokenKind::Num(n) => {
                self.advance();
                Some(Value::Num(n))
            }
            TokenKind::Ident(s) => {
                self.advance();
                Some(match s.as_str() {
                    "true" => Value::Bool(true),
                    "false" => Value::Bool(false),
                    _ => Value::Ident(s),
                })
            }
            _ => None,
        }
    }

    fn parse_rule(&mut self) -> Result<KlrRule, ParseError> {
        let line = self.peek_line();
        self.advance(); // `rule`
        let name = self.expect_string("a rule description string")?;

        let mut rule = KlrRule {
            name,
            contains: Vec::new(),
            reaches: None,
            without: Vec::new(),
            severity: Severity::Warning,
            report: None,
            line,
        };

        loop {
            self.skip_newlines();
            if self.at_eof() {
                break;
            }
            // Stop when the next top-level declaration begins.
            if let TokenKind::Ident(kw) = self.peek() {
                if matches!(kw.as_str(), "project" | "attack" | "rule") {
                    break;
                }
            }
            self.parse_rule_clause(&mut rule)?;
            self.end_statement()?;
        }

        Ok(rule)
    }

    fn parse_rule_clause(&mut self, rule: &mut KlrRule) -> Result<(), ParseError> {
        let kw = match self.peek().clone() {
            TokenKind::Ident(s) => s,
            other => return self.err(format!("expected a rule clause, found {other}")),
        };

        match kw.as_str() {
            "when" | "and" => {
                self.advance();
                self.collect_condition_clause(rule);
            }
            "without" => {
                self.advance();
                // Collect one or more protection identifiers on the line.
                while let TokenKind::Ident(_) | TokenKind::Str(_) = self.peek() {
                    if let Some(v) = self.try_parse_value() {
                        rule.without.push(v.as_string());
                    }
                }
            }
            "severity" => {
                self.advance();
                let word = self.expect_ident("a severity level")?;
                rule.severity = Severity::from_word(&word).ok_or_else(|| {
                    ParseError::new(
                        "KLR003",
                        format!("unknown severity `{word}`"),
                        self.peek_line(),
                    )
                })?;
            }
            "report" => {
                self.advance();
                self.eat_optional_colon();
                rule.report = Some(self.expect_string("a report message string")?);
            }
            other => {
                return self.err(format!(
                    "expected `when`, `and`, `without`, `severity`, or `report`, found `{other}`"
                ));
            }
        }
        Ok(())
    }

    /// Read the rest of a `when`/`and` line and extract `contains "X"` and
    /// `reaches Y` fragments.
    fn collect_condition_clause(&mut self, rule: &mut KlrRule) {
        // Gather the line's tokens as values.
        let mut items: Vec<(String, Value)> = Vec::new();
        loop {
            match self.peek().clone() {
                TokenKind::Ident(s) => {
                    self.advance();
                    items.push((s.clone(), Value::Ident(s)));
                }
                TokenKind::Str(s) => {
                    self.advance();
                    items.push((String::new(), Value::Str(s)));
                }
                TokenKind::Num(n) => {
                    self.advance();
                    items.push((String::new(), Value::Num(n)));
                }
                _ => break,
            }
        }

        for (idx, (word, _)) in items.iter().enumerate() {
            match word.as_str() {
                "contains" => {
                    if let Some((_, Value::Str(s))) = items.get(idx + 1) {
                        rule.contains.push(s.clone());
                    }
                }
                "reaches" => {
                    if let Some((_, v)) = items.get(idx + 1) {
                        rule.reaches = Some(v.as_string());
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_authentication_attack() {
        let src = r#"
project "MyApplication"

attack authentication {
    target "/api/login"
    send {
        username = "' OR 1=1"
        password = "anything"
    }
    expect {
        status != 200
        response does_not_contain "token"
    }
    severity critical
    message: "SQL injection vulnerability detected"
}
"#;
        let program = parse(src).expect("should parse");
        assert_eq!(program.project.as_deref(), Some("MyApplication"));
        assert_eq!(program.attacks.len(), 1);

        let a = &program.attacks[0];
        assert_eq!(a.name, "authentication");
        assert_eq!(a.target.as_deref(), Some("/api/login"));
        assert_eq!(a.severity, Severity::Critical);
        assert_eq!(
            a.message.as_deref(),
            Some("SQL injection vulnerability detected")
        );
        assert_eq!(a.send.len(), 2);
        assert_eq!(a.send[0].0, "username");
        assert_eq!(a.send[0].1, Value::Str("' OR 1=1".into()));
        assert_eq!(a.expectations.len(), 2);
        assert_eq!(
            a.expectations[0],
            Expectation::Status {
                op: CompareOp::Ne,
                value: 200
            }
        );
        assert_eq!(
            a.expectations[1],
            Expectation::ResponseNotContains("token".into())
        );
    }

    #[test]
    fn parses_rate_limit_attack_with_colon_forms() {
        let src = r#"
attack api_rate_limit {
    request: POST "/login"
    repeat: 1000 times
    expect: blocked_after 10
    severity medium
}
"#;
        let program = parse(src).unwrap();
        let a = &program.attacks[0];
        assert_eq!(a.method.as_deref(), Some("POST"));
        assert_eq!(a.target.as_deref(), Some("/login"));
        assert_eq!(a.repeat, Some(1000));
        assert_eq!(a.severity, Severity::Warning);
        assert_eq!(a.expectations, vec![Expectation::BlockedAfter(10)]);
    }

    #[test]
    fn parses_session_attack_actions() {
        let src = r#"
attack session {
    login user "test"
    steal cookie
    attempt reuse
    expect {
        session_invalidated true
    }
}
"#;
        let a = &parse(src).unwrap().attacks[0];
        assert_eq!(a.actions.len(), 3);
        assert_eq!(a.actions[0].verb, "login");
        assert_eq!(a.actions[0].args[0], Value::Ident("user".into()));
        assert_eq!(a.actions[0].args[1], Value::Str("test".into()));
        assert_eq!(a.actions[1].verb, "steal");
        assert_eq!(
            a.expectations[0],
            Expectation::Named {
                name: "session_invalidated".into(),
                expected: true
            }
        );
    }

    #[test]
    fn parses_upload_attack() {
        let src = r#"
attack upload {
    endpoint "/upload"
    payload: "../../etc/passwd"
    expect {
        file_not_exposed true
    }
}
"#;
        let a = &parse(src).unwrap().attacks[0];
        assert_eq!(a.target.as_deref(), Some("/upload"));
        assert_eq!(a.payload.as_deref(), Some("../../etc/passwd"));
    }

    #[test]
    fn parses_static_rule() {
        let src = r#"
rule "unsafe database query"
when function contains "query"
and input reaches query
without sanitization
severity high
report: "User input reaches database directly"
"#;
        let program = parse(src).unwrap();
        assert_eq!(program.rules.len(), 1);
        let r = &program.rules[0];
        assert_eq!(r.name, "unsafe database query");
        assert_eq!(r.contains, vec!["query".to_string()]);
        assert_eq!(r.reaches.as_deref(), Some("query"));
        assert_eq!(r.without, vec!["sanitization".to_string()]);
        assert_eq!(r.severity, Severity::High);
        assert_eq!(
            r.report.as_deref(),
            Some("User input reaches database directly")
        );
    }

    #[test]
    fn reports_error_with_line_number() {
        let src = "attack {\n}"; // missing name
        let err = parse(src).unwrap_err();
        assert_eq!(err.line, 1);
    }
}
