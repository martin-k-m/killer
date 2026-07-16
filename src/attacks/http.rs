//! A minimal, dependency-free HTTP/1.1 client used to execute attacks.
//!
//! The client speaks plain `http://` over [`std::net::TcpStream`]. It is
//! deliberately behind the [`HttpClient`] trait so a TLS-capable backend can be
//! dropped in later (a Phase 3 item) without changing the interpreter.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// An HTTP request to execute.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    /// Fully-resolved absolute URL (e.g. `http://host:port/path`).
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// An HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpResponse {
    /// Look up a header value case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Something that can execute an [`HttpRequest`].
pub trait HttpClient {
    fn execute(&self, req: &HttpRequest) -> Result<HttpResponse, HttpError>;
}

/// An error executing an HTTP request.
#[derive(Debug)]
pub struct HttpError {
    pub message: String,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for HttpError {}

impl HttpError {
    fn new(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
        }
    }
}

/// A parsed absolute URL (http only).
#[derive(Debug, Clone, PartialEq)]
pub struct Url {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub secure: bool,
}

impl Url {
    /// Parse an absolute `http://` or `https://` URL.
    pub fn parse(input: &str) -> Result<Url, HttpError> {
        let (secure, rest) = if let Some(r) = input.strip_prefix("http://") {
            (false, r)
        } else if let Some(r) = input.strip_prefix("https://") {
            (true, r)
        } else {
            return Err(HttpError::new(format!(
                "URL must start with http:// or https:// (got '{input}')"
            )));
        };

        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };

        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                let port = p
                    .parse::<u16>()
                    .map_err(|_| HttpError::new(format!("invalid port '{p}'")))?;
                (h.to_string(), port)
            }
            None => (authority.to_string(), if secure { 443 } else { 80 }),
        };

        if host.is_empty() {
            return Err(HttpError::new("URL host is empty"));
        }

        Ok(Url {
            host,
            port,
            path: if path.is_empty() {
                "/".to_string()
            } else {
                path.to_string()
            },
            secure,
        })
    }

    /// Reconstruct the absolute URL string.
    pub fn to_absolute(&self) -> String {
        let scheme = if self.secure { "https" } else { "http" };
        format!("{}://{}:{}{}", scheme, self.host, self.port, self.path)
    }

    /// Resolve a `target` against an optional base URL. A `target` that is
    /// already absolute wins; otherwise it is joined onto `base`.
    pub fn resolve(base: &str, target: &str) -> Result<Url, HttpError> {
        if target.starts_with("http://") || target.starts_with("https://") {
            return Url::parse(target);
        }
        let base = base.trim_end_matches('/');
        let path = if target.starts_with('/') {
            target.to_string()
        } else {
            format!("/{target}")
        };
        Url::parse(&format!("{base}{path}"))
    }
}

/// The default plain-HTTP client.
pub struct StdHttpClient {
    timeout: Duration,
}

impl StdHttpClient {
    pub fn new() -> Self {
        StdHttpClient {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        StdHttpClient { timeout }
    }
}

impl Default for StdHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient for StdHttpClient {
    fn execute(&self, req: &HttpRequest) -> Result<HttpResponse, HttpError> {
        let url = Url::parse(&req.url)?;
        if url.secure {
            return Err(HttpError::new(
                "https:// targets are not supported by the built-in client yet; use an http:// URL",
            ));
        }

        let addr = format!("{}:{}", url.host, url.port);
        let stream = TcpStream::connect(&addr)
            .map_err(|e| HttpError::new(format!("could not connect to {addr}: {e}")))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|_| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|e| HttpError::new(format!("could not configure socket: {e}")))?;

        let raw = write_and_read(stream, &url, req, self.timeout)?;
        parse_response(&raw)
    }
}

fn write_and_read(
    mut stream: TcpStream,
    url: &Url,
    req: &HttpRequest,
    _timeout: Duration,
) -> Result<Vec<u8>, HttpError> {
    let body = req.body.clone().unwrap_or_default();
    let mut request = format!("{} {} HTTP/1.1\r\n", req.method, url.path);
    request.push_str(&format!("Host: {}\r\n", url.host));
    request.push_str("User-Agent: killer/0.1\r\n");
    request.push_str("Accept: */*\r\n");
    request.push_str("Connection: close\r\n");

    let mut has_content_type = false;
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("content-type") {
            has_content_type = true;
        }
        if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("connection") {
            continue;
        }
        request.push_str(&format!("{k}: {v}\r\n"));
    }

    if !body.is_empty() {
        if !has_content_type {
            request.push_str("Content-Type: application/json\r\n");
        }
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    } else if req.method == "POST" || req.method == "PUT" {
        request.push_str("Content-Length: 0\r\n");
    }
    request.push_str("\r\n");
    request.push_str(&body);

    stream
        .write_all(request.as_bytes())
        .map_err(|e| HttpError::new(format!("write failed: {e}")))?;
    stream
        .flush()
        .map_err(|e| HttpError::new(format!("flush failed: {e}")))?;

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| HttpError::new(format!("read failed: {e}")))?;
    Ok(buf)
}

/// Parse a raw HTTP response into a [`HttpResponse`]. Handles the status line,
/// headers, and (optionally chunked) body well enough for testing purposes.
fn parse_response(raw: &[u8]) -> Result<HttpResponse, HttpError> {
    let split = find_header_end(raw)
        .ok_or_else(|| HttpError::new("malformed response: no header terminator"))?;
    let head = String::from_utf8_lossy(&raw[..split.0]);
    let body_bytes = &raw[split.1..];

    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| HttpError::new("empty response"))?;
    let status = parse_status_code(status_line)?;

    let mut headers = Vec::new();
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            if k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked") {
                chunked = true;
            }
            headers.push((k, v));
        }
    }

    let body = if chunked {
        decode_chunked(body_bytes)
    } else {
        String::from_utf8_lossy(body_bytes).into_owned()
    };

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn find_header_end(raw: &[u8]) -> Option<(usize, usize)> {
    // Returns (index of first \r, index just after \r\n\r\n).
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, i + 4))
}

fn parse_status_code(status_line: &str) -> Result<u16, HttpError> {
    // e.g. "HTTP/1.1 200 OK"
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let code = parts
        .next()
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| HttpError::new(format!("malformed status line: '{status_line}'")))?;
    Ok(code)
}

fn decode_chunked(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    let mut rest = text.as_ref();
    while let Some(nl) = rest.find("\r\n") {
        let size_str = &rest[..nl];
        let size = usize::from_str_radix(size_str.trim(), 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        let chunk_start = nl + 2;
        let chunk_end = (chunk_start + size).min(rest.len());
        out.push_str(&rest[chunk_start..chunk_end]);
        // Skip the chunk and its trailing CRLF.
        let next = (chunk_end + 2).min(rest.len());
        rest = &rest[next..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls() {
        let u = Url::parse("http://example.com/api/login").unwrap();
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 80);
        assert_eq!(u.path, "/api/login");
        assert!(!u.secure);

        let u = Url::parse("https://host:8443/x").unwrap();
        assert_eq!(u.port, 8443);
        assert!(u.secure);

        assert!(Url::parse("ftp://x").is_err());
    }

    #[test]
    fn resolves_targets() {
        let u = Url::resolve("http://127.0.0.1:8080", "/api/login").unwrap();
        assert_eq!(u.path, "/api/login");
        assert_eq!(u.port, 8080);

        // Absolute target overrides the base.
        let u = Url::resolve("http://127.0.0.1:8080", "http://other:9/z").unwrap();
        assert_eq!(u.host, "other");
        assert_eq!(u.path, "/z");
    }

    #[test]
    fn parses_a_raw_response() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nnope!";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 401);
        assert_eq!(resp.header("content-type"), Some("text/plain"));
        assert_eq!(resp.body, "nope!");
    }

    #[test]
    fn decodes_chunked_body() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.body, "hello");
    }
}
