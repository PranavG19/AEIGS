use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum CachePoisonIssue {
    CachedWithoutVary,
    VaryMissingSensitiveHeader { missing: String },
    CacheControlPublicWithAuth,
    UnkeyedHeaderReflected { header: String },
}

impl std::fmt::Display for CachePoisonIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CachedWithoutVary => write!(f, "cached_without_vary"),
            Self::VaryMissingSensitiveHeader { missing } => {
                write!(f, "vary_missing:{missing}")
            }
            Self::CacheControlPublicWithAuth => write!(f, "cache_public_with_auth"),
            Self::UnkeyedHeaderReflected { header } => {
                write!(f, "unkeyed_header_reflected:{header}")
            }
        }
    }
}

const CACHE_INDICATORS: &[&str] = &["x-cache", "cf-cache-status", "x-varnish", "age"];
const SENSITIVE_VARY_HEADERS: &[&str] = &["origin", "cookie", "authorization"];
const CANARY: &str = "evil-cache-poison.example.com";

const UNKEYED_HEADERS: &[&str] = &[
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Original-URL",
    "X-Rewrite-URL",
];

pub fn audit_cache_poison(target: &str) -> Vec<CachePoisonIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let headers = resp.headers();
    let vary = headers
        .get("vary")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let cache_control = headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let has_auth_header = headers.get("www-authenticate").is_some();

    let is_cached = CACHE_INDICATORS.iter().any(|h| headers.get(*h).is_some());

    let mut issues = analyze_cache_headers(is_cached, vary, cache_control, has_auth_header);

    for unkeyed in UNKEYED_HEADERS {
        if let Ok(probe_resp) = client.get(target).header(*unkeyed, CANARY).send()
            && let Ok(body) = probe_resp.text()
            && body.contains(CANARY)
        {
            issues.push(CachePoisonIssue::UnkeyedHeaderReflected {
                header: unkeyed.to_string(),
            });
            break;
        }
    }

    issues
}

pub(crate) fn analyze_cache_headers(
    is_cached: bool,
    vary: &str,
    cache_control: &str,
    has_auth: bool,
) -> Vec<CachePoisonIssue> {
    let mut issues = Vec::new();

    if !is_cached {
        return issues;
    }

    if vary.is_empty() {
        issues.push(CachePoisonIssue::CachedWithoutVary);
    } else {
        let vary_lower = vary.to_ascii_lowercase();
        for sensitive in SENSITIVE_VARY_HEADERS {
            if !vary_lower.contains(sensitive) {
                issues.push(CachePoisonIssue::VaryMissingSensitiveHeader {
                    missing: sensitive.to_string(),
                });
            }
        }
    }

    let cc_lower = cache_control.to_ascii_lowercase();
    if cc_lower.contains("public") && has_auth {
        issues.push(CachePoisonIssue::CacheControlPublicWithAuth);
    }

    issues
}

pub(crate) fn cache_poison_severity(issue: &CachePoisonIssue) -> f64 {
    match issue {
        CachePoisonIssue::UnkeyedHeaderReflected { .. } => 8.5,
        CachePoisonIssue::CacheControlPublicWithAuth => 7.0,
        CachePoisonIssue::CachedWithoutVary => 5.0,
        CachePoisonIssue::VaryMissingSensitiveHeader { .. } => 4.5,
    }
}

pub fn cache_poison_to_operations(
    issues: &[CachePoisonIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CachePoisoning,
                cache_poison_severity(issue),
                0.8,
            )
        })
        .collect()
}
