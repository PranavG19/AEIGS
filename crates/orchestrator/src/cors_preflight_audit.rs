use std::time::Duration;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq)]
pub enum CorsPreflightIssue {
    DangerousMethodAllowed { method: String },
    WildcardMethods,
    WildcardHeaders,
    SensitiveHeaderAllowed { header: String },
    ExcessiveMaxAge { seconds: u64 },
}

impl std::fmt::Display for CorsPreflightIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DangerousMethodAllowed { method } => {
                write!(f, "dangerous_method_allowed:{method}")
            }
            Self::WildcardMethods => write!(f, "wildcard_methods"),
            Self::WildcardHeaders => write!(f, "wildcard_headers"),
            Self::SensitiveHeaderAllowed { header } => {
                write!(f, "sensitive_header_allowed:{header}")
            }
            Self::ExcessiveMaxAge { seconds } => write!(f, "excessive_max_age:{seconds}"),
        }
    }
}

const DANGEROUS_METHODS: &[&str] = &["PUT", "DELETE", "PATCH", "TRACE"];
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "x-csrf-token",
    "cookie",
    "x-forwarded-for",
];
const MAX_SAFE_AGE: u64 = 86400; // 24 hours

pub fn audit_cors_preflight(target: &str) -> Vec<CorsPreflightIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::build_client(PREFLIGHT_TIMEOUT) else {
        return Vec::new();
    };

    let resp = match client
        .request(reqwest::Method::OPTIONS, target)
        .header("Origin", "https://evil.example.com")
        .header("Access-Control-Request-Method", "PUT")
        .send()
    {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let acam = resp
        .headers()
        .get("access-control-allow-methods")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let acah = resp
        .headers()
        .get("access-control-allow-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let acma = resp
        .headers()
        .get("access-control-max-age")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    analyze_preflight_response(acam, acah, acma)
}

pub(crate) fn analyze_preflight_response(
    allow_methods: &str,
    allow_headers: &str,
    max_age: &str,
) -> Vec<CorsPreflightIssue> {
    let mut issues = Vec::new();

    if allow_methods.trim() == "*" {
        issues.push(CorsPreflightIssue::WildcardMethods);
    } else {
        let methods: Vec<&str> = allow_methods.split(',').map(|s| s.trim()).collect();
        for dangerous in DANGEROUS_METHODS {
            if methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(dangerous))
            {
                issues.push(CorsPreflightIssue::DangerousMethodAllowed {
                    method: dangerous.to_string(),
                });
            }
        }
    }

    if allow_headers.trim() == "*" {
        issues.push(CorsPreflightIssue::WildcardHeaders);
    } else {
        let headers: Vec<&str> = allow_headers.split(',').map(|s| s.trim()).collect();
        for sensitive in SENSITIVE_HEADERS {
            if headers
                .iter()
                .any(|h| h.eq_ignore_ascii_case(sensitive))
            {
                issues.push(CorsPreflightIssue::SensitiveHeaderAllowed {
                    header: sensitive.to_string(),
                });
            }
        }
    }

    if let Ok(seconds) = max_age.trim().parse::<u64>()
        && seconds > MAX_SAFE_AGE
    {
        issues.push(CorsPreflightIssue::ExcessiveMaxAge { seconds });
    }

    issues
}

pub(crate) fn preflight_severity(issue: &CorsPreflightIssue) -> f64 {
    match issue {
        CorsPreflightIssue::WildcardMethods => 6.0,
        CorsPreflightIssue::WildcardHeaders => 5.5,
        CorsPreflightIssue::DangerousMethodAllowed { method } => {
            if method == "TRACE" {
                6.5
            } else {
                5.0
            }
        }
        CorsPreflightIssue::SensitiveHeaderAllowed { header } => {
            if header == "authorization" || header == "cookie" {
                6.0
            } else {
                4.5
            }
        }
        CorsPreflightIssue::ExcessiveMaxAge { .. } => 3.0,
    }
}

pub fn preflight_to_operations(
    issues: &[CorsPreflightIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CrossOriginMisconfiguration,
                preflight_severity(issue),
                0.85,
            )
        })
        .collect()
}
