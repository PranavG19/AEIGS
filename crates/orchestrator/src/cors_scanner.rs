use std::time::Duration;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const CORS_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_AGE_THRESHOLD: u64 = 86400;

#[derive(Debug, Clone, PartialEq)]
pub enum CorsIssue {
    WildcardOrigin,
    NullOrigin,
    ReflectedOrigin { origin: String },
    ArbitrarySubdomain { origin: String },
    CredentialsWithWildcard,
    CredentialsWithReflection { origin: String },
    CredentialsWithNull,
    PreflightMissing,
    WildcardMethods,
    WildcardHeaders,
    ExcessiveMaxAge { seconds: u64 },
    VaryOriginMissing,
}

impl std::fmt::Display for CorsIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CorsIssue::WildcardOrigin => write!(f, "wildcard_origin"),
            CorsIssue::NullOrigin => write!(f, "null_origin"),
            CorsIssue::ReflectedOrigin { .. } => write!(f, "reflected_origin"),
            CorsIssue::ArbitrarySubdomain { .. } => write!(f, "arbitrary_subdomain"),
            CorsIssue::CredentialsWithWildcard => write!(f, "credentials_with_wildcard"),
            CorsIssue::CredentialsWithReflection { .. } => {
                write!(f, "credentials_with_reflection")
            }
            CorsIssue::CredentialsWithNull => write!(f, "credentials_with_null"),
            CorsIssue::PreflightMissing => write!(f, "preflight_missing"),
            CorsIssue::WildcardMethods => write!(f, "wildcard_methods"),
            CorsIssue::WildcardHeaders => write!(f, "wildcard_headers"),
            CorsIssue::ExcessiveMaxAge { .. } => write!(f, "excessive_max_age"),
            CorsIssue::VaryOriginMissing => write!(f, "vary_origin_missing"),
        }
    }
}

pub fn cors_severity(issue: &CorsIssue) -> f64 {
    match issue {
        CorsIssue::CredentialsWithReflection { .. } => 8.0,
        CorsIssue::CredentialsWithNull => 7.5,
        CorsIssue::CredentialsWithWildcard => 7.0,
        CorsIssue::ReflectedOrigin { .. } => 7.0,
        CorsIssue::NullOrigin => 6.0,
        CorsIssue::ArbitrarySubdomain { .. } => 5.5,
        CorsIssue::WildcardMethods => 4.5,
        CorsIssue::WildcardOrigin => 4.0,
        CorsIssue::WildcardHeaders => 4.0,
        CorsIssue::PreflightMissing => 3.0,
        CorsIssue::VaryOriginMissing => 2.5,
        CorsIssue::ExcessiveMaxAge { .. } => 2.0,
    }
}

pub fn analyze_cors_headers(
    headers: &[(&str, &str)],
    test_origin: &str,
    domain: &str,
) -> Vec<CorsIssue> {
    let mut issues = Vec::new();

    let find_header = |name: &str| -> Option<&str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    };

    let acao = find_header("access-control-allow-origin");
    let acac = find_header("access-control-allow-credentials");
    let acam = find_header("access-control-allow-methods");
    let acah = find_header("access-control-allow-headers");
    let max_age = find_header("access-control-max-age");
    let vary = find_header("vary");

    let creds_true = acac
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let Some(acao_val) = acao else {
        return issues;
    };

    if acao_val == "*" {
        issues.push(CorsIssue::WildcardOrigin);
        if creds_true {
            issues.push(CorsIssue::CredentialsWithWildcard);
        }
    }

    if acao_val == "null" {
        issues.push(CorsIssue::NullOrigin);
        if creds_true {
            issues.push(CorsIssue::CredentialsWithNull);
        }
    }

    if acao_val == test_origin && acao_val != "*" && acao_val != "null" {
        issues.push(CorsIssue::ReflectedOrigin {
            origin: test_origin.to_string(),
        });
        if creds_true {
            issues.push(CorsIssue::CredentialsWithReflection {
                origin: test_origin.to_string(),
            });
        }
    }

    let evil_subdomain = format!("evil.{domain}");
    if acao_val.contains(&evil_subdomain) && acao_val != test_origin {
        issues.push(CorsIssue::ArbitrarySubdomain {
            origin: acao_val.to_string(),
        });
    }

    if acam.is_none() {
        issues.push(CorsIssue::PreflightMissing);
    }

    if acam.map(|v| v.trim()) == Some("*") {
        issues.push(CorsIssue::WildcardMethods);
    }

    if acah.map(|v| v.trim()) == Some("*") {
        issues.push(CorsIssue::WildcardHeaders);
    }

    if let Some(age_str) = max_age
        && let Ok(seconds) = age_str.trim().parse::<u64>()
        && seconds > MAX_AGE_THRESHOLD
    {
        issues.push(CorsIssue::ExcessiveMaxAge { seconds });
    }

    if acao_val != "*" {
        let has_vary_origin = vary
            .map(|v| {
                v.split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("origin"))
            })
            .unwrap_or(false);
        if !has_vary_origin {
            issues.push(CorsIssue::VaryOriginMissing);
        }
    }

    issues
}

pub fn scan_cors(target: &str) -> Vec<CorsIssue> {
    let Some(domain) = recon_client::validated_domain(target) else {
        return Vec::new();
    };
    let Some(client) = recon_client::build_client_limited_redirect(CORS_TIMEOUT, 3) else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    if let Some(headers) = fetch_cors_headers(&client, target, None) {
        let refs: Vec<(&str, &str)> =
            headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        findings.extend(analyze_cors_headers(&refs, "", &domain));
    }

    let evil_origin = "https://evil.example.com";
    if let Some(headers) = fetch_cors_headers(&client, target, Some(evil_origin)) {
        let refs: Vec<(&str, &str)> =
            headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        findings.extend(analyze_cors_headers(&refs, evil_origin, &domain));
    }

    let subdomain_origin = format!("https://evil.{domain}");
    if let Some(headers) = fetch_cors_headers(&client, target, Some(&subdomain_origin)) {
        let refs: Vec<(&str, &str)> =
            headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        findings.extend(analyze_cors_headers(&refs, &subdomain_origin, &domain));
    }

    findings.sort_by(|a, b| {
        cors_severity(b)
            .partial_cmp(&cors_severity(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    findings.dedup();

    findings
}

fn fetch_cors_headers(
    client: &reqwest::blocking::Client,
    target: &str,
    origin: Option<&str>,
) -> Option<Vec<(String, String)>> {
    let mut req = client.get(target);
    if let Some(o) = origin {
        req = req.header("Origin", o);
    }
    let resp = req.send().ok()?;
    let mut headers = Vec::new();
    for (name, value) in resp.headers() {
        if let Ok(v) = value.to_str() {
            headers.push((name.as_str().to_string(), v.to_string()));
        }
    }
    Some(headers)
}

pub fn cors_findings_to_operations(
    findings: &[CorsIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    findings
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                cors_severity(issue),
                0.5,
            )
        })
        .collect()
}
