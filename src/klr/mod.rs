//! The Killer Rule Language (`.klr`).
//!
//! The pipeline is:
//!
//! ```text
//! .klr text ──▶ lexer ──▶ tokens ──▶ parser ──▶ Program (AST)
//!                                                   │
//!                          ┌────────────────────────┴───────────────┐
//!                          ▼                                          ▼
//!                 interpreter (attacks)                     rule_engine (static rules)
//!                          │                                          │
//!                          ▼                                          ▼
//!                   AttackOutcome                              RuleFinding
//! ```

pub mod ast;
pub mod interpreter;
pub mod lexer;
pub mod parser;
pub mod rule_engine;
pub mod runner;

pub use parser::parse;
