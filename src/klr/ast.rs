//! The abstract syntax tree for the Killer Rule Language (`.klr`).
//!
//! A `.klr` file parses into a [`Program`]: an optional project name plus a set
//! of [`Attack`] definitions (dynamic security tests) and [`KlrRule`]
//! definitions (static code rules).

use crate::analyzer::Severity;

/// A parsed `.klr` program.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Program {
    /// The `project "..."` declaration, if present.
    pub project: Option<String>,
    /// Top-level attack/test definitions (not inside a suite).
    pub attacks: Vec<Attack>,
    /// Named suites grouping attacks/tests.
    pub suites: Vec<Suite>,
    /// Static code-rule definitions.
    pub rules: Vec<KlrRule>,
}

impl Program {
    /// All attacks in the program: top-level ones plus every suite's attacks,
    /// each tagged with its suite name.
    pub fn all_attacks(&self) -> Vec<Attack> {
        let mut out: Vec<Attack> = self.attacks.clone();
        for suite in &self.suites {
            for attack in &suite.attacks {
                let mut a = attack.clone();
                a.suite = Some(suite.name.clone());
                out.push(a);
            }
        }
        out
    }
}

/// A named group of attacks/tests (`suite "Payment Security" { ... }`).
#[derive(Debug, Clone, PartialEq)]
pub struct Suite {
    pub name: String,
    pub attacks: Vec<Attack>,
    pub line: usize,
}

/// A fuzz-mutation of a request field (`mutate amount { negative_numbers ... }`).
#[derive(Debug, Clone, PartialEq)]
pub struct Mutation {
    /// The `send` field to mutate.
    pub field: String,
    /// Named value generators, e.g. `negative_numbers`, `huge_values`.
    pub generators: Vec<String>,
}

/// A literal value in the source: string, number, boolean, or bare identifier.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Num(i64),
    Bool(bool),
    Ident(String),
}

impl Value {
    /// Render the value as a plain string (for request bodies, reports, etc.).
    pub fn as_string(&self) -> String {
        match self {
            Value::Str(s) => s.clone(),
            Value::Num(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Ident(s) => s.clone(),
        }
    }
}

/// A comparison operator used in `expect` conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

impl CompareOp {
    /// Apply the operator to two integers.
    pub fn apply(&self, lhs: i64, rhs: i64) -> bool {
        match self {
            CompareOp::Eq => lhs == rhs,
            CompareOp::Ne => lhs != rhs,
            CompareOp::Lt => lhs < rhs,
            CompareOp::Gt => lhs > rhs,
            CompareOp::Le => lhs <= rhs,
            CompareOp::Ge => lhs >= rhs,
        }
    }

    pub fn symbol(&self) -> &'static str {
        match self {
            CompareOp::Eq => "==",
            CompareOp::Ne => "!=",
            CompareOp::Lt => "<",
            CompareOp::Gt => ">",
            CompareOp::Le => "<=",
            CompareOp::Ge => ">=",
        }
    }
}

/// A generic action statement, e.g. `login user "test"`, `steal cookie`,
/// `attempt reuse`. The `verb` is the leading keyword; `args` are the rest.
#[derive(Debug, Clone, PartialEq)]
pub struct Action {
    pub verb: String,
    pub args: Vec<Value>,
}

/// A dynamic attack definition.
#[derive(Debug, Clone, PartialEq)]
pub struct Attack {
    pub name: String,
    /// The endpoint path or full URL to target.
    pub target: Option<String>,
    /// HTTP method (defaults applied by the interpreter).
    pub method: Option<String>,
    /// Request body fields (`send { ... }`).
    pub send: Vec<(String, Value)>,
    /// Request headers (`header { ... }`).
    pub headers: Vec<(String, Value)>,
    /// A raw payload string (`payload "..."`), e.g. a path-traversal string.
    pub payload: Option<String>,
    /// Number of times to repeat the request (`repeat N times`).
    pub repeat: Option<usize>,
    /// Generic action statements (login/steal/attempt/...).
    pub actions: Vec<Action>,
    /// Conditions the response is expected to satisfy.
    pub expectations: Vec<Expectation>,
    /// Built-in checks (`check authentication`), expanded by the interpreter.
    pub checks: Vec<String>,
    /// Fuzz mutations (`mutate <field> { ... }`), expanded into variants.
    pub mutations: Vec<Mutation>,
    pub severity: Severity,
    pub message: Option<String>,
    /// The suite this attack belongs to, if any (filled in by `all_attacks`).
    pub suite: Option<String>,
    /// 1-indexed source line of the `attack` keyword.
    pub line: usize,
}

impl Attack {
    /// A fresh attack with only a name and line set; all else empty/default.
    pub fn empty(name: String, line: usize) -> Attack {
        Attack {
            name,
            target: None,
            method: None,
            send: Vec::new(),
            headers: Vec::new(),
            payload: None,
            repeat: None,
            actions: Vec::new(),
            expectations: Vec::new(),
            checks: Vec::new(),
            mutations: Vec::new(),
            severity: Severity::High,
            message: None,
            suite: None,
            line,
        }
    }
}

/// A single expectation inside an `expect` block.
#[derive(Debug, Clone, PartialEq)]
pub enum Expectation {
    /// `status <op> <n>`
    Status { op: CompareOp, value: i64 },
    /// `response contains "..."`
    ResponseContains(String),
    /// `response does_not_contain "..."`
    ResponseNotContains(String),
    /// `blocked_after <n>`
    BlockedAfter(usize),
    /// A named boolean expectation, e.g. `session_invalidated true`,
    /// `file_not_exposed true`.
    Named { name: String, expected: bool },
}

/// A static code rule (the `rule "..."` construct).
#[derive(Debug, Clone, PartialEq)]
pub struct KlrRule {
    /// The rule description / name from `rule "..."`.
    pub name: String,
    /// Substrings a line must contain to match (`when function contains "X"`).
    pub contains: Vec<String>,
    /// If set, the line must also reference an input source (`input reaches X`).
    pub reaches: Option<String>,
    /// Protections whose absence is required (`without sanitization`).
    pub without: Vec<String>,
    pub severity: Severity,
    /// The `report: "..."` message.
    pub report: Option<String>,
    /// 1-indexed source line of the `rule` keyword.
    pub line: usize,
}
