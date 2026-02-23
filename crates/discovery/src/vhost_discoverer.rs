use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{HOST, HeaderValue};

use aegis_protocol::target_validation::validate_target_is_localhost;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const BODY_SIZE_TOLERANCE: usize = 64;

pub const VHOST_PREFIXES: &[&str] = &[
    "admin",
    "api",
    "app",
    "beta",
    "blog",
    "cdn",
    "ci",
    "dashboard",
    "db",
    "demo",
    "dev",
    "docs",
    "ftp",
    "git",
    "grafana",
    "internal",
    "jenkins",
    "jira",
    "kibana",
    "mail",
    "monitor",
    "portal",
    "private",
    "prometheus",
    "staging",
    "static",
    "status",
    "test",
    "vault",
    "vpn",
    "wiki",
];

#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredVhost {
    pub hostname: String,
    pub status_code: u16,
    pub content_length: usize,
    pub evidence: String,
}

#[derive(Debug)]
pub enum VhostError {
    InvalidUrl(String),
    NonLocalhostTarget(String),
    HttpError(String),
}

impl std::fmt::Display for VhostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(url) => write!(f, "invalid URL: {url}"),
            Self::NonLocalhostTarget(url) => write!(f, "non-localhost target: {url}"),
            Self::HttpError(msg) => write!(f, "HTTP error: {msg}"),
        }
    }
}

impl std::error::Error for VhostError {}

pub struct VhostDiscoverer {
    client: Client,
}

impl std::fmt::Debug for VhostDiscoverer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhostDiscoverer").finish()
    }
}

impl VhostDiscoverer {
    pub fn new() -> Result<Self, VhostError> {
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| VhostError::HttpError(e.to_string()))?;

        Ok(Self { client })
    }

    pub fn discover_vhosts(
        &self,
        target_url: &str,
        target_domain: &str,
    ) -> Result<Vec<DiscoveredVhost>, VhostError> {
        let base = validate_and_normalize(target_url)?;
        let baseline = self.fetch_baseline(&base);

        let mut results = Vec::new();
        for prefix in VHOST_PREFIXES {
            let hostname = build_vhost_hostname(prefix, target_domain);
            if let Some(vhost) = self.probe_vhost(&base, &hostname, &baseline) {
                results.push(vhost);
            }
        }
        results.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        Ok(results)
    }

    fn fetch_baseline(&self, base_url: &str) -> BaselineResponse {
        match self.client.get(base_url).send() {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.bytes().ok().map(|b| b.to_vec()).unwrap_or_default();
                BaselineResponse {
                    status_code: status,
                    body_size: body.len(),
                    body_hash: simple_hash(&body),
                }
            }
            Err(_) => BaselineResponse {
                status_code: 0,
                body_size: 0,
                body_hash: 0,
            },
        }
    }

    fn probe_vhost(
        &self,
        base_url: &str,
        hostname: &str,
        baseline: &BaselineResponse,
    ) -> Option<DiscoveredVhost> {
        let header_value = HeaderValue::from_str(hostname).ok()?;
        let resp = self
            .client
            .get(base_url)
            .header(HOST, header_value)
            .send()
            .ok()?;
        let status = resp.status().as_u16();
        let body = resp.bytes().ok()?;
        let body_size = body.len();
        let body_hash = simple_hash(&body);

        if is_different_from_baseline(status, body_size, body_hash, baseline) {
            let evidence = build_evidence(hostname, status, body_size, baseline);
            return Some(DiscoveredVhost {
                hostname: hostname.to_string(),
                status_code: status,
                content_length: body_size,
                evidence,
            });
        }
        None
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BaselineResponse {
    pub(crate) status_code: u16,
    pub(crate) body_size: usize,
    pub(crate) body_hash: u64,
}

pub(crate) fn build_vhost_hostname(prefix: &str, domain: &str) -> String {
    format!("{prefix}.{domain}")
}

pub(crate) fn is_different_from_baseline(
    status: u16,
    body_size: usize,
    body_hash: u64,
    baseline: &BaselineResponse,
) -> bool {
    if status != baseline.status_code {
        return true;
    }
    if body_size.abs_diff(baseline.body_size) > BODY_SIZE_TOLERANCE {
        return true;
    }
    body_hash != baseline.body_hash && body_size > 0
}

pub(crate) fn build_evidence(
    hostname: &str,
    status: u16,
    body_size: usize,
    baseline: &BaselineResponse,
) -> String {
    let mut parts = Vec::new();
    if status != baseline.status_code {
        parts.push(format!(
            "status {} (baseline {})",
            status, baseline.status_code
        ));
    }
    if body_size.abs_diff(baseline.body_size) > BODY_SIZE_TOLERANCE {
        parts.push(format!(
            "body size {} (baseline {})",
            body_size, baseline.body_size
        ));
    }
    if parts.is_empty() {
        parts.push("different body content".to_string());
    }
    format!("Host: {hostname} differs: {}", parts.join(", "))
}

pub(crate) fn simple_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 5381;
    for &byte in data {
        hash = hash.wrapping_mul(33).wrapping_add(u64::from(byte));
    }
    hash
}

fn validate_and_normalize(url: &str) -> Result<String, VhostError> {
    if url.is_empty() {
        return Err(VhostError::InvalidUrl(url.to_string()));
    }
    validate_target_is_localhost(url)
        .map_err(|_| VhostError::NonLocalhostTarget(url.to_string()))?;
    Ok(url.trim_end_matches('/').to_string())
}
