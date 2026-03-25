use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use aegis_protocol::target_validation::validate_target_is_localhost;
use url::Url;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const TIMING_THRESHOLD: Duration = Duration::from_secs(5);
const SMUGGLING_SEVERITY: f64 = 8.5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SmugglingType {
    ClTe,
    TeCl,
    TeTe,
}

impl fmt::Display for SmugglingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClTe => write!(f, "CL.TE"),
            Self::TeCl => write!(f, "TE.CL"),
            Self::TeTe => write!(f, "TE.TE"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmugglingFinding {
    pub endpoint: String,
    pub smuggling_type: SmugglingType,
    pub severity: f64,
    pub evidence: String,
}

pub struct SmugglingDetector {
    timeout: Duration,
}

impl Default for SmugglingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SmugglingDetector {
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn test_smuggling(&self, endpoint: &str) -> Vec<SmugglingFinding> {
        if validate_target_is_localhost(endpoint).is_err() {
            return Vec::new();
        }

        let addr = match extract_socket_addr(endpoint) {
            Some(a) => a,
            None => return Vec::new(),
        };

        let path = extract_path(endpoint);
        let host = extract_host(endpoint).unwrap_or("localhost");

        let mut findings = Vec::new();

        if let Some(f) = self.test_clte_probe(&addr, host, &path, endpoint) {
            findings.push(f);
        }
        if let Some(f) = self.test_tecl_probe(&addr, host, &path, endpoint) {
            findings.push(f);
        }

        for (variant_header, label) in build_te_obfuscation_variants() {
            if let Some(f) =
                self.test_te_variant(&addr, host, &path, endpoint, &variant_header, label)
            {
                findings.push(f);
            }
        }

        findings
    }

    fn test_clte_probe(
        &self,
        addr: &str,
        host: &str,
        path: &str,
        endpoint: &str,
    ) -> Option<SmugglingFinding> {
        let (probe, _) = build_clte_probe(host, path);
        let (elapsed, _status) = send_raw_request(addr, &probe, self.timeout).ok()?;

        if elapsed >= TIMING_THRESHOLD {
            return Some(SmugglingFinding {
                endpoint: endpoint.to_string(),
                smuggling_type: SmugglingType::ClTe,
                severity: SMUGGLING_SEVERITY,
                evidence: format!(
                    "CL.TE desync detected: response took {:.1}s (threshold {:.1}s)",
                    elapsed.as_secs_f64(),
                    TIMING_THRESHOLD.as_secs_f64(),
                ),
            });
        }
        None
    }

    fn test_tecl_probe(
        &self,
        addr: &str,
        host: &str,
        path: &str,
        endpoint: &str,
    ) -> Option<SmugglingFinding> {
        let (probe, _) = build_tecl_probe(host, path);
        let (elapsed, _status) = send_raw_request(addr, &probe, self.timeout).ok()?;

        if elapsed >= TIMING_THRESHOLD {
            return Some(SmugglingFinding {
                endpoint: endpoint.to_string(),
                smuggling_type: SmugglingType::TeCl,
                severity: SMUGGLING_SEVERITY,
                evidence: format!(
                    "TE.CL desync detected: response took {:.1}s (threshold {:.1}s)",
                    elapsed.as_secs_f64(),
                    TIMING_THRESHOLD.as_secs_f64(),
                ),
            });
        }
        None
    }

    fn test_te_variant(
        &self,
        addr: &str,
        host: &str,
        path: &str,
        endpoint: &str,
        variant_header: &str,
        label: &str,
    ) -> Option<SmugglingFinding> {
        let probe = build_te_variant_probe(host, path, variant_header);
        let (elapsed, _status) = send_raw_request(addr, &probe, self.timeout).ok()?;

        if elapsed >= TIMING_THRESHOLD {
            return Some(SmugglingFinding {
                endpoint: endpoint.to_string(),
                smuggling_type: SmugglingType::TeTe,
                severity: SMUGGLING_SEVERITY,
                evidence: format!(
                    "TE obfuscation variant '{label}' triggered desync: \
                     response took {:.1}s (threshold {:.1}s)",
                    elapsed.as_secs_f64(),
                    TIMING_THRESHOLD.as_secs_f64(),
                ),
            });
        }
        None
    }
}

/// Build a CL.TE desync probe.
///
/// Sets Content-Length: 6 with Transfer-Encoding: chunked.
/// Body is "0\r\n\r\nX" — if the back-end uses TE, it sees chunk 0 (end)
/// and leaves "X" as the start of the next request. If the back-end
/// waits for more chunk data, the response will be delayed (>5s).
pub fn build_clte_probe(host: &str, path: &str) -> (Vec<u8>, &'static str) {
    let body = "0\r\n\r\nX";
    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: 6\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: close\r\n\
         \r\n\
         {body}"
    );
    (request.into_bytes(), "CL.TE")
}

/// Build a TE.CL desync probe.
///
/// Sets Content-Length: 3 with Transfer-Encoding: chunked.
/// Body is "8\r\nSMUGGLED\r\n0\r\n\r\n" — if the back-end uses CL,
/// it reads only 3 bytes ("8\r\n"), leaving the rest as the next request.
pub fn build_tecl_probe(host: &str, path: &str) -> (Vec<u8>, &'static str) {
    let body = "8\r\nSMUGGLED\r\n0\r\n\r\n";
    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: 3\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: close\r\n\
         \r\n\
         {body}"
    );
    (request.into_bytes(), "TE.CL")
}

/// Build TE header obfuscation variants that may cause front-end/back-end disagreement.
pub fn build_te_obfuscation_variants() -> Vec<(String, &'static str)> {
    vec![
        ("Transfer-Encoding: xchunked".to_string(), "xchunked"),
        (
            "Transfer-Encoding : chunked".to_string(),
            "space-before-colon",
        ),
        (
            "Transfer-Encoding: chunked\r\nTransfer-encoding: x".to_string(),
            "duplicate-different-case",
        ),
        (
            "Transfer-Encoding:\tchunked".to_string(),
            "tab-before-value",
        ),
    ]
}

fn build_te_variant_probe(host: &str, path: &str, te_header: &str) -> Vec<u8> {
    let body = "0\r\n\r\nX";
    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: 6\r\n\
         {te_header}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}"
    );
    request.into_bytes()
}

/// Send raw bytes over TCP and measure response timing.
///
/// Returns `(elapsed_duration, status_code)`. The status code is parsed
/// from the HTTP status line; 0 indicates a parse failure.
pub fn send_raw_request(
    addr: &str,
    raw_bytes: &[u8],
    timeout: Duration,
) -> Result<(Duration, u16), std::io::Error> {
    let start = Instant::now();

    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?,
        timeout,
    )?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    stream.write_all(raw_bytes)?;
    stream.flush()?;

    let mut buf = [0u8; 4096];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
            return Ok((start.elapsed(), 0));
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            return Ok((start.elapsed(), 0));
        }
        Err(e) => return Err(e),
    };

    let elapsed = start.elapsed();
    let status = parse_status_code(&buf[..n]);

    Ok((elapsed, status))
}

pub(crate) fn parse_status_code(response: &[u8]) -> u16 {
    let text = String::from_utf8_lossy(response);
    let first_line = text.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() >= 2 {
        parts[1].parse().unwrap_or(0)
    } else {
        0
    }
}

fn extract_socket_addr(endpoint: &str) -> Option<String> {
    let parsed = Url::parse(endpoint).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port().unwrap_or(match parsed.scheme() {
        "https" => 443,
        _ => 80,
    });
    Some(format!("{host}:{port}"))
}

fn extract_host(endpoint: &str) -> Option<&str> {
    let after_scheme = endpoint.find("://").map(|i| &endpoint[i + 3..])?;
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    Some(&after_scheme[..end])
}

fn extract_path(endpoint: &str) -> String {
    Url::parse(endpoint)
        .ok()
        .map(|u| u.path().to_string())
        .unwrap_or_else(|| "/".to_string())
}

/// Interpret a timing result into a finding, exposed for unit testing.
pub fn interpret_timing(
    endpoint: &str,
    smuggling_type: SmugglingType,
    elapsed: Duration,
    label: &str,
) -> Option<SmugglingFinding> {
    if elapsed < TIMING_THRESHOLD {
        return None;
    }

    let evidence = match smuggling_type {
        SmugglingType::ClTe | SmugglingType::TeCl => {
            format!(
                "{smuggling_type} desync detected: response took {:.1}s (threshold {:.1}s)",
                elapsed.as_secs_f64(),
                TIMING_THRESHOLD.as_secs_f64(),
            )
        }
        SmugglingType::TeTe => {
            format!(
                "TE obfuscation variant '{label}' triggered desync: \
                 response took {:.1}s (threshold {:.1}s)",
                elapsed.as_secs_f64(),
                TIMING_THRESHOLD.as_secs_f64(),
            )
        }
    };

    Some(SmugglingFinding {
        endpoint: endpoint.to_string(),
        smuggling_type,
        severity: SMUGGLING_SEVERITY,
        evidence,
    })
}

#[cfg(test)]
#[path = "smuggling_detector_test.rs"]
mod smuggling_detector_test;
