use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;
use std::time::Duration;

const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq)]
pub enum CorsPreflightIssue {
    WildcardOriginWithCredentials,
    NullOriginAllowed,
    OriginReflection,
    WildcardMethods,
    DangerousMethodAllowed { method: String },
    WildcardHeaders,
    SensitiveHeaderAllowed { header: String },
    SensitiveHeaderExposed { header: String },
    ExcessiveMaxAge { seconds: u64 },
    MissingMaxAge,
}

impl std::fmt::Display for CorsPreflightIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WildcardOriginWithCredentials => write!(f, "wildcard_origin_with_credentials"),
            Self::NullOriginAllowed => write!(f, "null_origin_allowed"),
            Self::OriginReflection => write!(f, "origin_reflection"),
            Self::WildcardMethods => write!(f, "wildcard_methods"),
            Self::DangerousMethodAllowed { method } => {
                write!(f, "dangerous_method_allowed:{method}")
            }
            Self::WildcardHeaders => write!(f, "wildcard_headers"),
            Self::SensitiveHeaderAllowed { header } => {
                write!(f, "sensitive_header_allowed:{header}")
            }
            Self::SensitiveHeaderExposed { header } => {
                write!(f, "sensitive_header_exposed:{header}")
            }
            Self::ExcessiveMaxAge { seconds } => write!(f, "excessive_max_age:{seconds}"),
            Self::MissingMaxAge => write!(f, "missing_max_age"),
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
const SENSITIVE_EXPOSED_HEADERS: &[&str] =
    &["authorization", "set-cookie", "x-csrf-token", "x-api-key"];
const MAX_SAFE_AGE: u64 = 86400;

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

    let acao = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let acac = resp
        .headers()
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
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
    let aceh = resp
        .headers()
        .get("access-control-expose-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let acma = resp
        .headers()
        .get("access-control-max-age")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    analyze_preflight_response(acao, acac, acam, acah, aceh, acma)
}

pub fn analyze_preflight_response(
    allow_origin: &str,
    allow_credentials: &str,
    allow_methods: &str,
    allow_headers: &str,
    expose_headers: &str,
    max_age: &str,
) -> Vec<CorsPreflightIssue> {
    let mut issues = Vec::new();

    let origin_trimmed = allow_origin.trim();
    let credentials_enabled = allow_credentials.trim().eq_ignore_ascii_case("true");

    if origin_trimmed == "*" && credentials_enabled {
        issues.push(CorsPreflightIssue::WildcardOriginWithCredentials);
    }

    if origin_trimmed == "null" {
        issues.push(CorsPreflightIssue::NullOriginAllowed);
    }

    if origin_trimmed == "https://evil.example.com" {
        issues.push(CorsPreflightIssue::OriginReflection);
    }

    if allow_methods.trim() == "*" {
        issues.push(CorsPreflightIssue::WildcardMethods);
    } else {
        let methods: Vec<&str> = allow_methods.split(',').map(|s| s.trim()).collect();
        for dangerous in DANGEROUS_METHODS {
            if methods.iter().any(|m| m.eq_ignore_ascii_case(dangerous)) {
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
            if headers.iter().any(|h| h.eq_ignore_ascii_case(sensitive)) {
                issues.push(CorsPreflightIssue::SensitiveHeaderAllowed {
                    header: sensitive.to_string(),
                });
            }
        }
    }

    let exposed: Vec<&str> = expose_headers.split(',').map(|s| s.trim()).collect();
    for sensitive in SENSITIVE_EXPOSED_HEADERS {
        if exposed.iter().any(|h| h.eq_ignore_ascii_case(sensitive)) {
            issues.push(CorsPreflightIssue::SensitiveHeaderExposed {
                header: sensitive.to_string(),
            });
        }
    }

    if max_age.trim().is_empty() && !allow_methods.trim().is_empty() && !origin_trimmed.is_empty() {
        issues.push(CorsPreflightIssue::MissingMaxAge);
    } else if let Ok(seconds) = max_age.trim().parse::<u64>()
        && seconds > MAX_SAFE_AGE
    {
        issues.push(CorsPreflightIssue::ExcessiveMaxAge { seconds });
    }

    issues
}

pub fn cors_preflight_severity(issue: &CorsPreflightIssue) -> f64 {
    match issue {
        CorsPreflightIssue::WildcardOriginWithCredentials => 9.0,
        CorsPreflightIssue::NullOriginAllowed => 7.5,
        CorsPreflightIssue::OriginReflection => 8.0,
        CorsPreflightIssue::WildcardMethods => 6.0,
        CorsPreflightIssue::DangerousMethodAllowed { method } => {
            if method == "TRACE" {
                6.5
            } else {
                5.0
            }
        }
        CorsPreflightIssue::WildcardHeaders => 5.5,
        CorsPreflightIssue::SensitiveHeaderAllowed { header } => {
            if header == "authorization" || header == "cookie" {
                6.0
            } else {
                4.5
            }
        }
        CorsPreflightIssue::SensitiveHeaderExposed { header } => {
            if header == "authorization" || header == "set-cookie" {
                7.0
            } else {
                5.0
            }
        }
        CorsPreflightIssue::ExcessiveMaxAge { .. } => 3.0,
        CorsPreflightIssue::MissingMaxAge => 2.5,
    }
}

pub fn cors_preflight_to_operations(
    issues: &[CorsPreflightIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CrossOriginMisconfiguration,
                cors_preflight_severity(issue),
                0.85,
            )
        })
        .collect()
}
