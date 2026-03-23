use std::time::Duration;

use aegis_protocol::finding::{Confidence, VulnerabilityClass};
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Extracts domain and rejects localhost targets.
/// Returns `None` for localhost/127.0.0.1/::1 (scanners should skip these).
pub fn validated_domain(target: &str) -> Option<String> {
    let domain = aegis_exploiter::extract_domain(target)?;
    if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
        return None;
    }
    Some(domain)
}

/// Builds a standard reqwest blocking client for recon scanners.
pub fn build_client(timeout: Duration) -> Option<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .build()
        .ok()
}

/// Builds a client with default 10s timeout.
pub fn default_client() -> Option<reqwest::blocking::Client> {
    build_client(DEFAULT_TIMEOUT)
}

/// Builds a client with default 10s timeout that doesn't follow redirects.
pub fn default_client_no_redirect() -> Option<reqwest::blocking::Client> {
    build_client_no_redirect(DEFAULT_TIMEOUT)
}

/// Builds a client that doesn't follow redirects.
pub fn build_client_no_redirect(timeout: Duration) -> Option<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()
}

/// Builds a client with limited redirect following.
pub fn build_client_limited_redirect(
    timeout: Duration,
    max_redirects: usize,
) -> Option<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(max_redirects))
        .build()
        .ok()
}

/// Truncates a string to `max` characters, appending "..." if truncated.
pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max.saturating_sub(3)])
    } else {
        s.to_string()
    }
}

/// Checks whether a URL points to an external domain (not a subdomain of `target_domain`).
pub(crate) fn is_external(url: &str, target_domain: &str) -> bool {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    let Some(rest) = rest else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    !host.is_empty() && !host.ends_with(target_domain) && host != target_domain
}

/// Extracts the hostname from a URL, stripping scheme, port, and path.
pub(crate) fn extract_host(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = without_scheme.split('/').next()?;
    let host = host.split(':').next()?;
    if host.is_empty() {
        return None;
    }
    Some(host.to_string())
}

/// Creates an `AddFinding` operation entry for passive recon.
pub fn finding_entry(
    seq: &mut u64,
    vuln_class: VulnerabilityClass,
    severity: f64,
    confidence: f64,
) -> OperationLogEntry {
    *seq += 1;
    OperationLogEntry {
        sequence_number: *seq,
        module: ModuleIdentifier::PassiveRecon,
        operation: GraphOperation::AddFinding {
            linked_node_ids: vec![],
            vulnerability_class: vuln_class,
            severity,
            confidence: Confidence::new(confidence).unwrap(),
            certificate: Vec::new(),
        },
        timestamp_unix_ms: timestamp_ms(),
    }
}
