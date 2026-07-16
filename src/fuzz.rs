//! Fuzz generators — the shared mutation catalog behind the `.klr` `mutate`
//! construct and the `killer fuzz` command.
//!
//! A *generator* is a named family of adversarial inputs (boundary numbers,
//! injection payloads, oversized strings, …). The `.klr` runner expands
//! `mutate <field> { <generator> }` clauses through [`generate`], and
//! `killer fuzz` surfaces the same catalog directly so inputs can be previewed
//! or fired at a live target without writing a `.klr` file first.
//!
//! This is deliberately the single source of fuzz values: [`crate::klr::runner`]
//! calls [`generate`] rather than keeping its own table, so the two never drift.

/// One entry in the fuzz-generator catalog.
#[derive(Debug, Clone, Copy)]
pub struct Generator {
    /// Canonical name, used both in `.klr` (`mutate f { <name> }`) and on the CLI.
    pub name: &'static str,
    /// The class of weakness this generator probes.
    pub category: &'static str,
    /// A one-line description of what the values look like or target.
    pub description: &'static str,
}

/// Every generator, in a stable order suitable for `killer fuzz --list`.
const CATALOG: &[Generator] = &[
    Generator {
        name: "negative_numbers",
        category: "boundary",
        description: "negative values where a non-negative number is expected",
    },
    Generator {
        name: "huge_values",
        category: "overflow",
        description: "very large integers that may overflow fixed-width types",
    },
    Generator {
        name: "decimals",
        category: "type-confusion",
        description: "fractional values where an integer is expected",
    },
    Generator {
        name: "zero",
        category: "boundary",
        description: "the zero value, a common off-by-one / divide-by-zero trigger",
    },
    Generator {
        name: "empty",
        category: "empty-input",
        description: "an empty string, exercising missing-input handling",
    },
    Generator {
        name: "sql_injection",
        category: "injection",
        description: "a classic tautology payload (' OR 1=1 --)",
    },
    Generator {
        name: "xss",
        category: "injection",
        description: "a reflected-script payload",
    },
    Generator {
        name: "null_bytes",
        category: "injection",
        description: "an embedded NUL byte that can truncate strings",
    },
    Generator {
        name: "long_strings",
        category: "resource",
        description: "an oversized string to probe length limits and buffers",
    },
    Generator {
        name: "unicode",
        category: "encoding",
        description: "multi-byte and astral-plane characters",
    },
];

/// The full generator catalog.
pub fn catalog() -> &'static [Generator] {
    CATALOG
}

/// Look up a generator's catalog metadata by name or alias.
///
/// Returns `None` for unknown names — [`generate`] still produces a value for
/// those (it echoes the name), but there is no catalog entry to describe.
pub fn lookup(name: &str) -> Option<&'static Generator> {
    let canonical = canonical_name(name);
    CATALOG.iter().find(|g| g.name == canonical)
}

/// The category label for a generator name, or `"custom"` if it is not in the
/// catalog (an arbitrary literal passed through by [`generate`]).
pub fn category_of(name: &str) -> &'static str {
    lookup(name).map(|g| g.category).unwrap_or("custom")
}

/// The concrete values a fuzz generator produces.
///
/// Unknown names are echoed back as a single literal value, so a `.klr` author
/// can write `mutate role { admin }` to inject the literal `admin`.
pub fn generate(generator: &str) -> Vec<String> {
    let s = |v: &str| v.to_string();
    match generator.to_ascii_lowercase().as_str() {
        "negative_numbers" | "negatives" => vec![s("-1"), s("-999999")],
        "huge_values" | "huge" | "overflow" => {
            vec![s("999999999999999"), s("99999999999999999999999999")]
        }
        "decimals" | "floats" => vec![s("0.0001"), s("3.14159")],
        "zero" => vec![s("0")],
        "empty" => vec![s("")],
        "sql_injection" | "sqli" => vec![s("' OR 1=1 --")],
        "xss" => vec![s("<script>alert(1)</script>")],
        "null_bytes" => vec![s("a%00b")],
        "long_strings" | "long" => vec!["A".repeat(5000)],
        "unicode" => vec![s("𝕏𝕏𝕏"), s("🔥🔥🔥")],
        // Unknown generator: use its own name as the injected value.
        other => vec![other.to_string()],
    }
}

// --- Firing inputs at a live target -----------------------------------------

use std::time::Instant;

use crate::attacks::http::{HttpClient, HttpRequest};
use crate::klr::ast::{Attack, Value};

/// What to fuzz and where.
#[derive(Debug, Clone)]
pub struct FuzzOptions {
    /// The request field to mutate (the fuzz values are sent as this key).
    pub field: String,
    /// HTTP method to use when a target is set.
    pub method: String,
    /// Generator names to run, in order (already resolved/deduped by the caller).
    pub generators: Vec<String>,
    /// Absolute `http://` URL to fire at, or `None` for a dry preview.
    pub target: Option<String>,
}

/// The values produced by one generator, for the preview section.
#[derive(Debug, Clone)]
pub struct GeneratorPreview {
    pub generator: String,
    pub category: String,
    pub values: Vec<String>,
}

/// How the target responded to one fuzz input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HitOutcome {
    /// The server answered with a non-error status (< 500).
    Handled(u16),
    /// The server answered with a 5xx — the input tripped a server-side fault.
    Fault(u16),
    /// The request could not be completed (connection refused, timeout, …).
    Unreachable(String),
}

/// One fired fuzz input and its outcome.
#[derive(Debug, Clone)]
pub struct FuzzHit {
    pub generator: String,
    pub category: String,
    pub value: String,
    pub outcome: HitOutcome,
}

impl FuzzHit {
    /// Whether this hit is worth surfacing (a fault or an unreachable target).
    pub fn is_anomaly(&self) -> bool {
        !matches!(self.outcome, HitOutcome::Handled(_))
    }
}

/// The result of a `killer fuzz` run.
#[derive(Debug, Clone)]
pub struct FuzzReport {
    pub field: String,
    pub method: String,
    /// The resolved target, or `None` when this was a dry preview.
    pub target: Option<String>,
    /// The values every requested generator produced (always populated).
    pub previews: Vec<GeneratorPreview>,
    /// Per-input outcomes; empty for a dry preview.
    pub hits: Vec<FuzzHit>,
    pub elapsed_ms: u128,
}

impl FuzzReport {
    /// Total number of inputs generated.
    pub fn total_inputs(&self) -> usize {
        self.previews.iter().map(|p| p.values.len()).sum()
    }

    /// Inputs that produced a server fault or an unreachable target.
    pub fn anomalies(&self) -> impl Iterator<Item = &FuzzHit> {
        self.hits.iter().filter(|h| h.is_anomaly())
    }
}

/// Generate inputs for every requested generator and, if a target is set, fire
/// each one and record how the server responded.
///
/// Requests are byte-for-byte identical to a `.klr` `mutate` (same JSON body),
/// so `killer fuzz` and a `.klr` file exercise the target the same way.
pub fn run<C: HttpClient>(client: &C, opts: &FuzzOptions) -> FuzzReport {
    let started = Instant::now();

    let previews: Vec<GeneratorPreview> = opts
        .generators
        .iter()
        .map(|g| GeneratorPreview {
            generator: g.clone(),
            category: category_of(g).to_string(),
            values: generate(g),
        })
        .collect();

    let mut hits = Vec::new();
    if let Some(target) = &opts.target {
        for preview in &previews {
            for value in &preview.values {
                let outcome = fire(client, &opts.method, target, &opts.field, value);
                hits.push(FuzzHit {
                    generator: preview.generator.clone(),
                    category: preview.category.clone(),
                    value: value.clone(),
                    outcome,
                });
            }
        }
    }

    FuzzReport {
        field: opts.field.clone(),
        method: opts.method.clone(),
        target: opts.target.clone(),
        previews,
        hits,
        elapsed_ms: started.elapsed().as_millis(),
    }
}

/// Send a single fuzz value and classify the response.
fn fire<C: HttpClient>(
    client: &C,
    method: &str,
    url: &str,
    field: &str,
    value: &str,
) -> HitOutcome {
    let mut attack = Attack::empty("fuzz".to_string(), 0);
    attack.send = vec![(field.to_string(), Value::Str(value.to_string()))];
    let (body, headers) = crate::klr::interpreter::build_body(&attack);

    let req = HttpRequest {
        method: method.to_string(),
        url: url.to_string(),
        headers,
        body,
    };

    match client.execute(&req) {
        Ok(resp) if resp.status >= 500 => HitOutcome::Fault(resp.status),
        Ok(resp) => HitOutcome::Handled(resp.status),
        Err(e) => HitOutcome::Unreachable(e.message),
    }
}

/// Map an alias to its canonical catalog name (or return the input unchanged).
fn canonical_name(name: &str) -> String {
    match name.to_ascii_lowercase().as_str() {
        "negatives" => "negative_numbers".to_string(),
        "huge" | "overflow" => "huge_values".to_string(),
        "floats" => "decimals".to_string(),
        "sqli" => "sql_injection".to_string(),
        "long" => "long_strings".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_names_are_generatable_and_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for g in catalog() {
            assert!(seen.insert(g.name), "duplicate generator {}", g.name);
            // Every catalog entry must actually produce at least one value.
            assert!(!generate(g.name).is_empty(), "{} produced nothing", g.name);
            // And it must resolve back to itself via lookup.
            assert_eq!(lookup(g.name).unwrap().name, g.name);
        }
    }

    #[test]
    fn aliases_resolve_to_canonical_entries() {
        assert_eq!(lookup("sqli").unwrap().name, "sql_injection");
        assert_eq!(lookup("negatives").unwrap().name, "negative_numbers");
        assert_eq!(category_of("huge"), "overflow");
    }

    #[test]
    fn unknown_generator_is_echoed_as_literal() {
        assert_eq!(generate("admin"), vec!["admin".to_string()]);
        assert!(lookup("admin").is_none());
        assert_eq!(category_of("admin"), "custom");
    }

    #[test]
    fn known_generators_match_documented_counts() {
        assert_eq!(generate("negative_numbers").len(), 2);
        assert_eq!(generate("zero").len(), 1);
        assert_eq!(generate("long_strings")[0].len(), 5000);
    }

    use crate::attacks::http::{HttpClient, HttpError, HttpRequest, HttpResponse};

    /// A client that returns a 500 whenever the request body contains `trigger`,
    /// and 200 otherwise — enough to exercise fault detection.
    struct FaultyClient {
        trigger: &'static str,
    }

    impl HttpClient for FaultyClient {
        fn execute(&self, req: &HttpRequest) -> Result<HttpResponse, HttpError> {
            let body = req.body.clone().unwrap_or_default();
            let status = if body.contains(self.trigger) {
                500
            } else {
                200
            };
            Ok(HttpResponse {
                status,
                headers: Vec::new(),
                body: String::new(),
            })
        }
    }

    #[test]
    fn dry_run_generates_without_firing() {
        let opts = FuzzOptions {
            field: "amount".to_string(),
            method: "POST".to_string(),
            generators: vec!["negative_numbers".to_string(), "zero".to_string()],
            target: None,
        };
        // A client that would panic if called — proves nothing is fired.
        struct NoCall;
        impl HttpClient for NoCall {
            fn execute(&self, _: &HttpRequest) -> Result<HttpResponse, HttpError> {
                panic!("dry run must not send requests");
            }
        }
        let report = run(&NoCall, &opts);
        assert_eq!(report.total_inputs(), 3); // 2 negatives + 1 zero
        assert!(report.hits.is_empty());
        assert_eq!(report.anomalies().count(), 0);
    }

    #[test]
    fn fault_is_detected_and_flagged_as_anomaly() {
        let opts = FuzzOptions {
            field: "q".to_string(),
            method: "POST".to_string(),
            generators: vec!["sql_injection".to_string(), "zero".to_string()],
            target: Some("http://127.0.0.1:9/x".to_string()),
        };
        // The SQLi payload contains "OR 1=1"; make that the fault trigger.
        let report = run(&FaultyClient { trigger: "OR 1=1" }, &opts);
        assert_eq!(report.hits.len(), 2);
        let anomalies: Vec<_> = report.anomalies().collect();
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].generator, "sql_injection");
        assert!(matches!(anomalies[0].outcome, HitOutcome::Fault(500)));
    }

    #[test]
    fn unreachable_target_is_an_anomaly() {
        struct DeadClient;
        impl HttpClient for DeadClient {
            fn execute(&self, _: &HttpRequest) -> Result<HttpResponse, HttpError> {
                Err(HttpError {
                    message: "connection refused".to_string(),
                })
            }
        }
        let opts = FuzzOptions {
            field: "x".to_string(),
            method: "POST".to_string(),
            generators: vec!["zero".to_string()],
            target: Some("http://127.0.0.1:9/x".to_string()),
        };
        let report = run(&DeadClient, &opts);
        assert_eq!(report.anomalies().count(), 1);
        assert!(matches!(report.hits[0].outcome, HitOutcome::Unreachable(_)));
    }
}
