//! The `.klr` interpreter: executes [`Attack`]s against a target and evaluates
//! their expectations into [`AttackOutcome`]s.
//!
//! Semantics: a `.klr` attack describes how a *secure* system should behave.
//! When every expectation holds, the system defended itself and the verdict is
//! `Secure` (`PASSED`). When an expectation fails, a vulnerability is indicated
//! and the verdict is `Vulnerable` (`FAILED`) — matching the "attack report"
//! framing of the language.

use crate::attacks::http::{HttpClient, HttpRequest, Url};
use crate::attacks::{database, filesystem};
use crate::klr::ast::{Attack, Expectation, Value};
use crate::results::{AttackOutcome, CheckResult, Verdict};

/// Runtime configuration for the interpreter.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Base URL that relative targets resolve against.
    pub base_url: String,
    /// Hard cap on how many requests a `repeat` will actually send.
    pub max_requests: usize,
}

impl Default for RunConfig {
    fn default() -> Self {
        RunConfig {
            base_url: "http://127.0.0.1:8080".to_string(),
            max_requests: 100,
        }
    }
}

/// Status codes that count as "rate limited / blocked".
const BLOCKED_STATUSES: &[u16] = &[403, 429, 503];

pub struct Interpreter<'a> {
    client: &'a dyn HttpClient,
    config: RunConfig,
}

impl<'a> Interpreter<'a> {
    pub fn new(client: &'a dyn HttpClient, config: RunConfig) -> Self {
        Interpreter { client, config }
    }

    /// Execute every attack in order.
    pub fn run(&self, attacks: &[Attack]) -> Vec<AttackOutcome> {
        attacks.iter().map(|a| self.run_attack(a)).collect()
    }

    fn run_attack(&self, attack: &Attack) -> AttackOutcome {
        let issue_id = classify(attack);
        if is_session_flow(attack) {
            return self.run_session_flow(attack, issue_id);
        }
        self.run_request_attack(attack, issue_id)
    }

    // --- request-based attacks --------------------------------------------

    fn run_request_attack(&self, attack: &Attack, issue_id: Option<String>) -> AttackOutcome {
        let Some(target) = attack.target.clone() else {
            return errored(
                attack,
                "attack has no `target`/`endpoint` to request",
                issue_id,
            );
        };

        let url = match Url::resolve(&self.config.base_url, &target) {
            Ok(u) => u,
            Err(e) => return errored(attack, &format!("invalid target: {e}"), issue_id),
        };
        let method = attack
            .method
            .clone()
            .unwrap_or_else(|| default_method(attack));
        let (body, mut headers) = build_body(attack);
        for (k, v) in &attack.headers {
            headers.push((k.clone(), v.as_string()));
        }

        let req = HttpRequest {
            method: method.clone(),
            url: url.to_absolute(),
            headers,
            body,
        };

        let repeat = attack.repeat.unwrap_or(1).max(1);
        let effective = repeat.min(self.config.max_requests);

        let mut statuses: Vec<u16> = Vec::new();
        let mut first_blocked: Option<usize> = None;
        let mut last_body = String::new();

        for n in 1..=effective {
            match self.client.execute(&req) {
                Ok(resp) => {
                    if first_blocked.is_none() && BLOCKED_STATUSES.contains(&resp.status) {
                        first_blocked = Some(n);
                    }
                    statuses.push(resp.status);
                    last_body = resp.body;
                    // Once blocked, no need to keep hammering for rate-limit tests.
                    if first_blocked.is_some()
                        && attack
                            .expectations
                            .iter()
                            .any(|e| matches!(e, Expectation::BlockedAfter(_)))
                    {
                        break;
                    }
                }
                Err(e) => {
                    if n == 1 {
                        return errored(attack, &format!("request failed: {e}"), issue_id);
                    }
                    // Later failure: stop and evaluate what we have.
                    break;
                }
            }
        }

        let last_status = *statuses.last().unwrap_or(&0);
        let target_line = format!("{} {}", method, url.to_absolute());

        let mut checks = Vec::new();
        for exp in &attack.expectations {
            checks.push(self.eval_expectation(
                exp,
                last_status,
                &last_body,
                &statuses,
                first_blocked,
            ));
        }

        // Automatic bonus check: a leaked SQL error is always a failure when we
        // sent a body (i.e. this looks like an injection probe).
        if (!attack.send.is_empty() || attack.payload.is_some())
            && database::response_indicates_sqli(&last_body)
        {
            checks.push(CheckResult {
                description: "no SQL error leaked in response".to_string(),
                passed: false,
                evaluated: true,
                detail: "response body contains a database error signature".to_string(),
            });
        }

        let verdict = verdict_from_checks(&checks);
        AttackOutcome {
            name: attack.name.clone(),
            suite: attack.suite.clone(),
            severity: attack.severity.label().to_string(),
            target: target_line,
            verdict,
            message: attack.message.clone(),
            checks,
            error: None,
            issue_id,
        }
    }

    fn eval_expectation(
        &self,
        exp: &Expectation,
        last_status: u16,
        last_body: &str,
        statuses: &[u16],
        first_blocked: Option<usize>,
    ) -> CheckResult {
        match exp {
            Expectation::Status { op, value } => {
                let passed = op.apply(last_status as i64, *value);
                CheckResult {
                    description: format!("status {} {}", op.symbol(), value),
                    passed,
                    evaluated: true,
                    detail: format!("observed status {last_status}"),
                }
            }
            Expectation::ResponseContains(s) => {
                let passed = last_body.contains(s);
                CheckResult {
                    description: format!("response contains \"{s}\""),
                    passed,
                    evaluated: true,
                    detail: if passed {
                        "found in response".to_string()
                    } else {
                        "not found in response".to_string()
                    },
                }
            }
            Expectation::ResponseNotContains(s) => {
                let passed = !last_body.contains(s);
                CheckResult {
                    description: format!("response does_not_contain \"{s}\""),
                    passed,
                    evaluated: true,
                    detail: if passed {
                        "absent from response".to_string()
                    } else {
                        format!("\"{s}\" leaked in response")
                    },
                }
            }
            Expectation::BlockedAfter(n) => {
                let passed = first_blocked.is_some();
                let detail = match first_blocked {
                    Some(idx) => format!("blocked at request #{idx} (limit {n})"),
                    None => format!("no rate limiting after {} requests", statuses.len()),
                };
                CheckResult {
                    description: format!("blocked_after {n}"),
                    passed,
                    evaluated: true,
                    detail,
                }
            }
            Expectation::Named { name, expected } => {
                self.eval_named(name, *expected, last_status, last_body)
            }
        }
    }

    fn eval_named(
        &self,
        name: &str,
        expected: bool,
        last_status: u16,
        last_body: &str,
    ) -> CheckResult {
        match name {
            "file_not_exposed" => {
                let exposed = filesystem::response_exposes_file(last_body);
                let held = !exposed; // secure = not exposed
                CheckResult {
                    description: format!("{name} {expected}"),
                    passed: held == expected,
                    evaluated: true,
                    detail: if exposed {
                        "sensitive file contents found in response".to_string()
                    } else {
                        "no sensitive file contents in response".to_string()
                    },
                }
            }
            "session_invalidated" => {
                let invalidated = matches!(last_status, 401 | 403);
                CheckResult {
                    description: format!("{name} {expected}"),
                    passed: invalidated == expected,
                    evaluated: true,
                    detail: format!("reuse returned status {last_status}"),
                }
            }
            // `check authentication` — the endpoint should reject unauthenticated
            // access (401/403) rather than serve it (200).
            "requires_auth" => {
                let denied = matches!(last_status, 401 | 403 | 302);
                CheckResult {
                    description: "requires authentication".to_string(),
                    passed: denied == expected,
                    evaluated: true,
                    detail: format!("unauthenticated request returned status {last_status}"),
                }
            }
            // `check injection` — no database error should leak.
            "no_sql_error" => {
                let leaked = database::response_indicates_sqli(last_body);
                CheckResult {
                    description: "no SQL error leaked".to_string(),
                    passed: !leaked == expected,
                    evaluated: true,
                    detail: if leaked {
                        "database error signature found in response".to_string()
                    } else {
                        "no database error in response".to_string()
                    },
                }
            }
            _ => CheckResult {
                description: format!("{name} {expected}"),
                passed: true,
                evaluated: false,
                detail: "not evaluated by this engine".to_string(),
            },
        }
    }

    // --- session flow -----------------------------------------------------

    fn run_session_flow(&self, attack: &Attack, issue_id: Option<String>) -> AttackOutcome {
        let login_path = attack
            .target
            .clone()
            .unwrap_or_else(|| "/login".to_string());
        let url = match Url::resolve(&self.config.base_url, &login_path) {
            Ok(u) => u,
            Err(e) => return errored(attack, &format!("invalid login target: {e}"), issue_id),
        };

        // Build login body from the `login user "..."` action (plus any `send`).
        let mut fields: Vec<(String, Value)> = attack.send.clone();
        if let Some(login) = attack.actions.iter().find(|a| a.verb == "login") {
            if let Some(Value::Str(user)) = login.args.iter().find(|v| matches!(v, Value::Str(_))) {
                fields.push(("username".to_string(), Value::Str(user.clone())));
            }
        }
        let body = json_object(&fields);

        let login_req = HttpRequest {
            method: "POST".to_string(),
            url: url.to_absolute(),
            headers: vec![],
            body: Some(body),
        };

        let login_resp = match self.client.execute(&login_req) {
            Ok(r) => r,
            Err(e) => return errored(attack, &format!("login request failed: {e}"), issue_id),
        };
        let cookie = login_resp
            .header("set-cookie")
            .map(|c| c.split(';').next().unwrap_or(c).to_string());

        // Reuse the (possibly stolen) cookie against the same endpoint.
        let mut reuse_headers = Vec::new();
        if let Some(c) = &cookie {
            reuse_headers.push(("Cookie".to_string(), c.clone()));
        }
        let reuse_req = HttpRequest {
            method: "GET".to_string(),
            url: url.to_absolute(),
            headers: reuse_headers,
            body: None,
        };
        let reuse_resp = match self.client.execute(&reuse_req) {
            Ok(r) => r,
            Err(e) => return errored(attack, &format!("reuse request failed: {e}"), issue_id),
        };

        let mut checks = Vec::new();
        checks.push(CheckResult {
            description: "captured session cookie".to_string(),
            passed: true,
            evaluated: true,
            detail: match &cookie {
                Some(c) => format!("stole cookie `{c}`"),
                None => "no Set-Cookie returned by login".to_string(),
            },
        });
        for exp in &attack.expectations {
            checks.push(self.eval_expectation(exp, reuse_resp.status, &reuse_resp.body, &[], None));
        }

        let verdict = verdict_from_checks(&checks);
        AttackOutcome {
            name: attack.name.clone(),
            suite: attack.suite.clone(),
            severity: attack.severity.label().to_string(),
            target: format!("session flow via {}", url.to_absolute()),
            verdict,
            message: attack.message.clone(),
            checks,
            error: None,
            issue_id,
        }
    }
}

// --- helpers --------------------------------------------------------------

fn verdict_from_checks(checks: &[CheckResult]) -> Verdict {
    let any_failed = checks.iter().any(|c| c.evaluated && !c.passed);
    if any_failed {
        Verdict::Vulnerable
    } else {
        Verdict::Secure
    }
}

fn errored(attack: &Attack, message: &str, issue_id: Option<String>) -> AttackOutcome {
    AttackOutcome {
        name: attack.name.clone(),
        suite: attack.suite.clone(),
        severity: attack.severity.label().to_string(),
        target: attack.target.clone().unwrap_or_default(),
        verdict: Verdict::Errored,
        message: attack.message.clone(),
        checks: Vec::new(),
        error: Some(message.to_string()),
        issue_id,
    }
}

fn default_method(attack: &Attack) -> String {
    if !attack.send.is_empty() || attack.payload.is_some() {
        "POST".to_string()
    } else {
        "GET".to_string()
    }
}

/// Build the request body and any implied headers for an attack's `send` /
/// `payload` fields. Exposed to the crate so `killer fuzz` fires requests that
/// are byte-for-byte identical to a `.klr` `mutate`.
pub(crate) fn build_body(attack: &Attack) -> (Option<String>, Vec<(String, String)>) {
    if !attack.send.is_empty() {
        (Some(json_object(&attack.send)), Vec::new())
    } else if let Some(p) = &attack.payload {
        (
            Some(p.clone()),
            vec![("Content-Type".to_string(), "text/plain".to_string())],
        )
    } else {
        (None, Vec::new())
    }
}

/// Serialize key/value pairs into a compact JSON object string.
fn json_object(fields: &[(String, Value)]) -> String {
    let mut out = String::from("{");
    for (i, (k, v)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("\"{}\":", json_escape(k)));
        match v {
            Value::Num(n) => out.push_str(&n.to_string()),
            Value::Bool(b) => out.push_str(&b.to_string()),
            other => out.push_str(&format!("\"{}\"", json_escape(&other.as_string()))),
        }
    }
    out.push('}');
    out
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

fn is_session_flow(attack: &Attack) -> bool {
    attack.actions.iter().any(|a| a.verb == "login")
        || attack
            .expectations
            .iter()
            .any(|e| matches!(e, Expectation::Named { name, .. } if name == "session_invalidated"))
}

/// Assign a stable issue id (used by `killer explain`) based on the attack's shape.
fn classify(attack: &Attack) -> Option<String> {
    if attack
        .payload
        .as_ref()
        .is_some_and(|p| filesystem::is_path_traversal(p))
    {
        return Some("KLR-PATH-TRAVERSAL".to_string());
    }
    if attack
        .expectations
        .iter()
        .any(|e| matches!(e, Expectation::BlockedAfter(_)))
    {
        return Some("KLR-RATE-LIMIT".to_string());
    }
    if is_session_flow(attack) {
        return Some("KLR-SESSION".to_string());
    }
    if looks_like_sqli(attack) {
        return Some("KLR-SQLI".to_string());
    }
    Some("KLR-GENERIC".to_string())
}

fn looks_like_sqli(attack: &Attack) -> bool {
    let needles = ["'", " or ", "1=1", "--", "union select", "\" or"];
    let in_send = attack.send.iter().any(|(_, v)| {
        let s = v.as_string().to_ascii_lowercase();
        needles.iter().any(|n| s.contains(n))
    });
    let in_msg = attack
        .message
        .as_ref()
        .map(|m| {
            let m = m.to_ascii_lowercase();
            m.contains("sql") || m.contains("injection")
        })
        .unwrap_or(false);
    in_send || in_msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attacks::http::{HttpError, HttpResponse};
    use std::cell::RefCell;

    /// A scripted client that returns queued responses in order.
    struct MockClient {
        responses: RefCell<Vec<HttpResponse>>,
        default: HttpResponse,
    }

    impl MockClient {
        fn new(responses: Vec<HttpResponse>, default: HttpResponse) -> Self {
            MockClient {
                responses: RefCell::new(responses),
                default,
            }
        }
    }

    impl HttpClient for MockClient {
        fn execute(&self, _req: &HttpRequest) -> Result<HttpResponse, HttpError> {
            let mut q = self.responses.borrow_mut();
            if q.is_empty() {
                Ok(self.default.clone())
            } else {
                Ok(q.remove(0))
            }
        }
    }

    fn resp(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![],
            body: body.to_string(),
        }
    }

    fn run_one(src: &str, client: &dyn HttpClient) -> AttackOutcome {
        let program = crate::klr::parser::parse(src).unwrap();
        let interp = Interpreter::new(client, RunConfig::default());
        interp.run(&program.attacks).remove(0)
    }

    #[test]
    fn sqli_vulnerable_when_login_succeeds() {
        // Server wrongly returns 200 with a token -> both expectations fail.
        let client = MockClient::new(vec![], resp(200, "{\"token\":\"abc\"}"));
        let src = r#"
attack authentication {
    target "/api/login"
    send { username = "' OR 1=1" password = "x" }
    expect {
        status != 200
        response does_not_contain "token"
    }
    severity critical
    message: "SQL injection vulnerability detected"
}
"#;
        let out = run_one(src, &client);
        assert_eq!(out.verdict, Verdict::Vulnerable);
        assert_eq!(out.issue_id.as_deref(), Some("KLR-SQLI"));
    }

    #[test]
    fn sqli_secure_when_login_rejected() {
        let client = MockClient::new(vec![], resp(401, "invalid credentials"));
        let src = r#"
attack authentication {
    target "/api/login"
    send { username = "' OR 1=1" }
    expect {
        status != 200
        response does_not_contain "token"
    }
}
"#;
        let out = run_one(src, &client);
        assert_eq!(out.verdict, Verdict::Secure);
    }

    #[test]
    fn rate_limit_secure_when_blocked() {
        // First two 200s then a 429.
        let client = MockClient::new(
            vec![resp(200, "ok"), resp(200, "ok"), resp(429, "slow down")],
            resp(200, "ok"),
        );
        let src = r#"
attack rl {
    request: POST "/login"
    repeat: 100 times
    expect: blocked_after 10
}
"#;
        let out = run_one(src, &client);
        assert_eq!(out.verdict, Verdict::Secure);
        assert_eq!(out.issue_id.as_deref(), Some("KLR-RATE-LIMIT"));
    }

    #[test]
    fn rate_limit_vulnerable_when_never_blocked() {
        let client = MockClient::new(vec![], resp(200, "ok"));
        let src = r#"
attack rl {
    request: POST "/login"
    repeat: 20 times
    expect: blocked_after 10
}
"#;
        let out = run_one(src, &client);
        assert_eq!(out.verdict, Verdict::Vulnerable);
    }

    #[test]
    fn upload_vulnerable_when_file_exposed() {
        let client = MockClient::new(vec![], resp(200, "root:x:0:0:root:/root:/bin/bash"));
        let src = r#"
attack upload {
    endpoint "/upload"
    payload: "../../etc/passwd"
    expect { file_not_exposed true }
}
"#;
        let out = run_one(src, &client);
        assert_eq!(out.verdict, Verdict::Vulnerable);
        assert_eq!(out.issue_id.as_deref(), Some("KLR-PATH-TRAVERSAL"));
    }

    #[test]
    fn errored_when_connection_fails() {
        struct FailClient;
        impl HttpClient for FailClient {
            fn execute(&self, _: &HttpRequest) -> Result<HttpResponse, HttpError> {
                Err(HttpError {
                    message: "connection refused".to_string(),
                })
            }
        }
        let src = r#"
attack a {
    target "/x"
    expect { status != 200 }
}
"#;
        let out = run_one(src, &FailClient);
        assert_eq!(out.verdict, Verdict::Errored);
        assert!(out.error.is_some());
    }
}
