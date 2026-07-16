//! End-to-end tests for the `.klr` pipeline over a real TCP socket.
//!
//! A tiny throwaway HTTP server responds with canned responses so the real
//! [`StdHttpClient`] is exercised against actual sockets (not a mock).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use killer::attacks::http::StdHttpClient;
use killer::klr::interpreter::{Interpreter, RunConfig};
use killer::klr::parse;
use killer::results::Verdict;

/// Start a server that answers `max_conns` requests with `response`, then stops.
/// Returns the bound port.
fn spawn_server(response: &'static str, max_conns: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        let mut handled = 0;
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            handle(&mut stream, response);
            handled += 1;
            if handled >= max_conns {
                break;
            }
        }
    });

    port
}

fn handle(stream: &mut TcpStream, response: &str) {
    // Read the request headers (best effort) so the client's write completes.
    let mut buf = [0u8; 2048];
    let _ = stream.read(&mut buf);
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
    // Dropping the stream closes the connection (client uses Connection: close).
}

fn run_first(src: &str, port: u16) -> killer::results::AttackOutcome {
    let program = parse(src).expect("parse");
    let client = StdHttpClient::new();
    let config = RunConfig {
        base_url: format!("http://127.0.0.1:{port}"),
        ..RunConfig::default()
    };
    Interpreter::new(&client, config)
        .run(&program.attacks)
        .remove(0)
}

#[test]
fn detects_sql_injection_over_real_socket() {
    // A vulnerable server: the injection "logs in" (200 + token).
    let response =
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{\"token\":\"abc\"}\n";
    let port = spawn_server(response, 1);

    let src = r#"
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
    let out = run_first(src, port);
    assert_eq!(out.verdict, Verdict::Vulnerable);
    assert_eq!(out.issue_id.as_deref(), Some("KLR-SQLI"));
}

#[test]
fn secure_server_defends_over_real_socket() {
    // A secure server rejects the injection with 401 and no token.
    let response =
        "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\nContent-Length: 20\r\nConnection: close\r\n\r\ninvalid credentials\n";
    let port = spawn_server(response, 1);

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
    let out = run_first(src, port);
    assert_eq!(out.verdict, Verdict::Secure);
}

#[test]
fn errors_when_target_unreachable() {
    // Nothing is listening on this port.
    let src = r#"
attack a {
    target "/x"
    expect { status != 200 }
}
"#;
    // Use a port unlikely to be open; the client should surface a connect error.
    let out = run_first(src, 1);
    assert_eq!(out.verdict, Verdict::Errored);
}
