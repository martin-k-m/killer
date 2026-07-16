//! The test runner: expands attacks (checks + fuzz mutations) into concrete
//! tests and executes them, optionally across a pool of worker threads.

use std::thread;

use crate::attacks::http::HttpClient;
use crate::klr::ast::{Attack, Expectation, Value};
use crate::klr::interpreter::{Interpreter, RunConfig};
use crate::results::AttackOutcome;

/// Expand a list of attacks into concrete tests: `check` clauses become
/// expectations, and each `mutate` generator becomes one or more variants.
pub fn expand_all(attacks: &[Attack]) -> Vec<Attack> {
    attacks.iter().flat_map(expand_attack).collect()
}

/// Expand a single attack into one or more concrete tests.
pub fn expand_attack(attack: &Attack) -> Vec<Attack> {
    // 1. Fold `check <name>` clauses into expectations.
    let mut base = attack.clone();
    for c in &attack.checks {
        base.expectations.extend(check_expectations(c));
    }
    base.checks.clear();

    // 2. Expand `mutate <field> { generators }` into variants.
    if base.mutations.is_empty() {
        return vec![base];
    }
    let mutations = std::mem::take(&mut base.mutations);
    let mut variants = Vec::new();
    for m in &mutations {
        for generator in &m.generators {
            let values = crate::fuzz::generate(generator);
            let multi = values.len() > 1;
            for (i, val) in values.into_iter().enumerate() {
                let mut v = base.clone();
                set_send_field(&mut v.send, &m.field, &val);
                let label = if multi {
                    format!("{generator}#{}", i + 1)
                } else {
                    generator.clone()
                };
                v.name = format!("{} [{}={}]", base.name, m.field, label);
                variants.push(v);
            }
        }
    }
    if variants.is_empty() {
        vec![base]
    } else {
        variants
    }
}

/// Run all attacks (after expansion) and return their outcomes in order.
///
/// `workers` > 1 splits the work across scoped threads; the client must be
/// `Sync` (the built-in [`crate::attacks::http::StdHttpClient`] is).
pub fn run_all<C: HttpClient + Sync>(
    attacks: &[Attack],
    client: &C,
    config: &RunConfig,
    workers: usize,
) -> Vec<AttackOutcome> {
    let expanded = expand_all(attacks);

    if workers <= 1 || expanded.len() <= 1 {
        let interp = Interpreter::new(client, config.clone());
        return interp.run(&expanded);
    }

    let worker_count = workers.min(expanded.len());
    let chunks = split_indexed(&expanded, worker_count);

    let mut indexed: Vec<(usize, AttackOutcome)> = thread::scope(|scope| {
        let handles: Vec<_> = chunks
            .into_iter()
            .map(|chunk| {
                scope.spawn(move || {
                    let interp = Interpreter::new(client, config.clone());
                    chunk
                        .into_iter()
                        .map(|(idx, attack)| {
                            (idx, interp.run(std::slice::from_ref(attack)).remove(0))
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();

        handles
            .into_iter()
            .flat_map(|h| h.join().expect("worker thread panicked"))
            .collect()
    });

    indexed.sort_by_key(|(i, _)| *i);
    indexed.into_iter().map(|(_, o)| o).collect()
}

/// Split items into `n` contiguous chunks, each carrying original indices.
fn split_indexed(items: &[Attack], n: usize) -> Vec<Vec<(usize, &Attack)>> {
    let n = n.max(1);
    let mut chunks: Vec<Vec<(usize, &Attack)>> = vec![Vec::new(); n];
    for (i, item) in items.iter().enumerate() {
        chunks[i % n].push((i, item));
    }
    chunks
}

/// Map a `check <name>` clause to the expectations it implies.
fn check_expectations(name: &str) -> Vec<Expectation> {
    match name.to_ascii_lowercase().as_str() {
        "authentication" | "auth" => vec![Expectation::Named {
            name: "requires_auth".to_string(),
            expected: true,
        }],
        "rate_limit" | "rate_limiting" | "ratelimit" => vec![Expectation::BlockedAfter(50)],
        "injection" | "sql_injection" | "sqli" => vec![Expectation::Named {
            name: "no_sql_error".to_string(),
            expected: true,
        }],
        // Unknown checks become a named expectation, evaluated best-effort.
        other => vec![Expectation::Named {
            name: other.to_string(),
            expected: true,
        }],
    }
}

/// Set (or insert) a `send` field to a string value.
fn set_send_field(send: &mut Vec<(String, Value)>, field: &str, value: &str) {
    let v = Value::Str(value.to_string());
    if let Some(entry) = send.iter_mut().find(|(k, _)| k == field) {
        entry.1 = v;
    } else {
        send.push((field.to_string(), v));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::klr::parser::parse;

    #[test]
    fn mutation_expands_into_variants() {
        let src = r#"
attack duplicate_payment {
    request POST "/payment"
    send { amount = 100 }
    mutate amount {
        negative_numbers
        huge_values
        decimals
    }
}
"#;
        let program = parse(src).unwrap();
        let expanded = expand_all(&program.attacks);
        // 2 negatives + 2 huge + 2 decimals = 6 variants.
        assert_eq!(expanded.len(), 6);
        // Each variant mutates the `amount` field.
        for v in &expanded {
            let amount = v.send.iter().find(|(k, _)| k == "amount").unwrap();
            assert!(matches!(amount.1, Value::Str(_)));
            assert!(v.name.contains("amount="));
        }
    }

    #[test]
    fn check_becomes_expectation() {
        let src = r#"
test login_security {
    endpoint "/login"
    check authentication
}
"#;
        let program = parse(src).unwrap();
        let expanded = expand_all(&program.attacks);
        assert_eq!(expanded.len(), 1);
        assert!(expanded[0].checks.is_empty());
        assert_eq!(
            expanded[0].expectations,
            vec![Expectation::Named {
                name: "requires_auth".to_string(),
                expected: true
            }]
        );
    }

    #[test]
    fn repeat_block_multiplies_request_count() {
        let src = r#"
repeat 100 {
    attack login {
        target "/login"
    }
}
"#;
        let program = parse(src).unwrap();
        assert_eq!(program.attacks.len(), 1);
        assert_eq!(program.attacks[0].repeat, Some(100));
    }

    #[test]
    fn split_covers_all_items_once() {
        // Build 10 trivial attacks and ensure chunking preserves every index.
        let attacks: Vec<Attack> = (0..10).map(|i| Attack::empty(format!("a{i}"), 1)).collect();
        let chunks = split_indexed(&attacks, 3);
        let mut seen: Vec<usize> = chunks
            .iter()
            .flat_map(|c| c.iter().map(|(i, _)| *i))
            .collect();
        seen.sort();
        assert_eq!(seen, (0..10).collect::<Vec<_>>());
    }
}
