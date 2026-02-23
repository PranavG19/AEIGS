use std::fmt;

use aegis_protocol::target_validation::validate_target_is_localhost;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CorsIssue {
    ReflectedOrigin,
    NullOriginAccepted,
    WildcardWithCredentials,
    SubdomainTrust,
    WildcardOrigin,
}

impl CorsIssue {
    pub fn severity(self) -> f64 {
        match self {
            Self::ReflectedOrigin => 7.0,
            Self::WildcardWithCredentials => 7.0,
            Self::NullOriginAccepted => 5.0,
            Self::SubdomainTrust => 5.0,
            Self::WildcardOrigin => 3.0,
        }
    }
}

impl fmt::Display for CorsIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ReflectedOrigin => "reflected-origin",
            Self::NullOriginAccepted => "null-origin-accepted",
            Self::WildcardWithCredentials => "wildcard-with-credentials",
            Self::SubdomainTrust => "subdomain-trust",
            Self::WildcardOrigin => "wildcard-origin",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone)]
pub struct CorsFinding {
    pub endpoint: String,
    pub issue: CorsIssue,
    pub severity: f64,
    pub evidence: String,
}

pub struct CorsDetector {
    client: reqwest::blocking::Client,
}

impl Default for CorsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CorsDetector {
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    pub fn with_client(client: reqwest::blocking::Client) -> Self {
        Self { client }
    }

    pub fn test_cors(&self, endpoint: &str) -> Vec<CorsFinding> {
        if validate_target_is_localhost(endpoint).is_err() {
            return Vec::new();
        }

        let mut findings = Vec::new();

        if let Some(f) = self.test_reflected_origin(endpoint) {
            findings.push(f);
        }
        if let Some(f) = self.test_null_origin(endpoint) {
            findings.push(f);
        }
        if let Some(f) = self.test_wildcard_credentials(endpoint) {
            findings.push(f);
        }
        if let Some(f) = self.test_subdomain_trust(endpoint) {
            findings.push(f);
        }
        if let Some(f) = self.test_wildcard_origin(endpoint) {
            findings.push(f);
        }

        findings
    }

    fn test_reflected_origin(&self, endpoint: &str) -> Option<CorsFinding> {
        let resp = self
            .client
            .get(endpoint)
            .header("Origin", "https://evil.com")
            .send()
            .ok()?;

        let acao = resp
            .headers()
            .get("access-control-allow-origin")?
            .to_str()
            .ok()?;

        if acao == "https://evil.com" {
            return Some(CorsFinding {
                endpoint: endpoint.to_string(),
                issue: CorsIssue::ReflectedOrigin,
                severity: CorsIssue::ReflectedOrigin.severity(),
                evidence: acao.to_string(),
            });
        }

        None
    }

    fn test_null_origin(&self, endpoint: &str) -> Option<CorsFinding> {
        let resp = self
            .client
            .get(endpoint)
            .header("Origin", "null")
            .send()
            .ok()?;

        let acao = resp
            .headers()
            .get("access-control-allow-origin")?
            .to_str()
            .ok()?;

        if acao == "null" {
            return Some(CorsFinding {
                endpoint: endpoint.to_string(),
                issue: CorsIssue::NullOriginAccepted,
                severity: CorsIssue::NullOriginAccepted.severity(),
                evidence: acao.to_string(),
            });
        }

        None
    }

    fn test_wildcard_credentials(&self, endpoint: &str) -> Option<CorsFinding> {
        let resp = self
            .client
            .get(endpoint)
            .header("Origin", "https://test.com")
            .send()
            .ok()?;

        let acao = resp
            .headers()
            .get("access-control-allow-origin")?
            .to_str()
            .ok()?;

        if acao != "*" {
            return None;
        }

        let acac = resp
            .headers()
            .get("access-control-allow-credentials")
            .and_then(|v: &reqwest::header::HeaderValue| v.to_str().ok())
            .unwrap_or("");

        if acac.eq_ignore_ascii_case("true") {
            return Some(CorsFinding {
                endpoint: endpoint.to_string(),
                issue: CorsIssue::WildcardWithCredentials,
                severity: CorsIssue::WildcardWithCredentials.severity(),
                evidence: format!("ACAO: {acao}, ACAC: {acac}"),
            });
        }

        None
    }

    fn test_subdomain_trust(&self, endpoint: &str) -> Option<CorsFinding> {
        let target_domain = extract_domain(endpoint)?;
        let evil_origin = format!("https://evil.{target_domain}");

        let resp = self
            .client
            .get(endpoint)
            .header("Origin", &evil_origin)
            .send()
            .ok()?;

        let acao = resp
            .headers()
            .get("access-control-allow-origin")?
            .to_str()
            .ok()?;

        if acao == evil_origin {
            return Some(CorsFinding {
                endpoint: endpoint.to_string(),
                issue: CorsIssue::SubdomainTrust,
                severity: CorsIssue::SubdomainTrust.severity(),
                evidence: acao.to_string(),
            });
        }

        None
    }

    fn test_wildcard_origin(&self, endpoint: &str) -> Option<CorsFinding> {
        let resp = self
            .client
            .get(endpoint)
            .header("Origin", "https://anything.com")
            .send()
            .ok()?;

        let acao = resp
            .headers()
            .get("access-control-allow-origin")?
            .to_str()
            .ok()?;

        if acao != "*" {
            return None;
        }

        let acac = resp
            .headers()
            .get("access-control-allow-credentials")
            .and_then(|v: &reqwest::header::HeaderValue| v.to_str().ok())
            .unwrap_or("");

        if acac.eq_ignore_ascii_case("true") {
            return None;
        }

        Some(CorsFinding {
            endpoint: endpoint.to_string(),
            issue: CorsIssue::WildcardOrigin,
            severity: CorsIssue::WildcardOrigin.severity(),
            evidence: acao.to_string(),
        })
    }
}

fn extract_domain(endpoint: &str) -> Option<String> {
    let parsed = Url::parse(endpoint).ok()?;
    parsed.host_str().map(|h| h.to_string())
}

#[cfg(test)]
#[path = "cors_detector_test.rs"]
mod cors_detector_test;
