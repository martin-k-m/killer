//! The rule registry.
//!
//! Rules are grouped into submodules by category. [`default_rules`] assembles
//! the active rule set, respecting the enable/disable switches in the config.
//! Adding a new rule is a matter of implementing [`crate::analyzer::Rule`] and
//! registering it here.

pub mod dependencies;
pub mod quality;
pub mod security;

use crate::analyzer::Rule;
use crate::config::Config;

/// Build the list of enabled rules from configuration.
pub fn default_rules(config: &Config) -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = Vec::new();
    let r = &config.rules;

    if r.secret_detection {
        rules.push(Box::new(security::HardcodedSecretRule::new()));
    }
    if r.dangerous_commands {
        rules.push(Box::new(security::DangerousCommandRule::new()));
    }
    if r.large_files {
        rules.push(Box::new(quality::LargeFileRule::new(
            config.scan.large_file_threshold,
        )));
    }
    if r.todo_tracker {
        rules.push(Box::new(quality::TodoTrackerRule::new()));
    }
    if r.duplicate_code {
        rules.push(Box::new(quality::DuplicateCodeRule::new()));
    }

    rules
}

/// Every rule id known to Killer, for documentation and `killer version`.
pub fn all_rule_ids() -> Vec<&'static str> {
    vec![
        "hardcoded-secret",
        "dangerous-command",
        "large-file",
        "todo-tracker",
        "duplicate-code",
    ]
}
