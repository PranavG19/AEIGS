use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum CspReportLeakIssue {
    InternalReportUri { uri: String },
    DeprecatedReportUri,
    HttpReportEndpoint { uri: String },
    ThirdPartyReportEndpoint { uri: String },
}

impl std::fmt::Display for CspReportLeakIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InternalReportUri { uri } => write!(f, "internal_report_uri:{uri}"),
            Self::DeprecatedReportUri => write!(f, "deprecated_report_uri"),
            Self::HttpReportEndpoint { uri } => write!(f, "http_report_endpoint:{uri}"),
            Self::ThirdPartyReportEndpoint { uri } => {
                write!(f, "third_party_report_endpoint:{uri}")
            }
        }
    }
}

const INTERNAL_PATTERNS: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "::1",
    ".internal",
    ".local",
    ".corp",
    ".intranet",
];

pub fn audit_csp_report_leak(target: &str) -> Vec<CspReportLeakIssue> {
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

    let csp = resp
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let report_to_json = resp
        .headers()
        .get("report-to")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let target_domain = recon_client::validated_domain(target).unwrap_or_default();

    analyze_csp_report_directives(csp, report_to_json, &target_domain)
}

pub(crate) fn analyze_csp_report_directives(
    csp: &str,
    report_to_header: &str,
    target_domain: &str,
) -> Vec<CspReportLeakIssue> {
    let mut issues = Vec::new();

    let report_uris = extract_report_uris(csp);
    let report_to_endpoints = extract_report_to_endpoints(csp, report_to_header);

    if !report_uris.is_empty() {
        issues.push(CspReportLeakIssue::DeprecatedReportUri);
    }

    let all_endpoints: Vec<&str> = report_uris
        .iter()
        .chain(report_to_endpoints.iter())
        .copied()
        .collect();

    for ep in &all_endpoints {
        let lower = ep.to_ascii_lowercase();

        if INTERNAL_PATTERNS.iter().any(|p| lower.contains(p)) {
            issues.push(CspReportLeakIssue::InternalReportUri {
                uri: ep.to_string(),
            });
        }

        if lower.starts_with("http://") {
            issues.push(CspReportLeakIssue::HttpReportEndpoint {
                uri: ep.to_string(),
            });
        }

        if !target_domain.is_empty() && !lower.contains(target_domain) && lower.starts_with("http")
        {
            issues.push(CspReportLeakIssue::ThirdPartyReportEndpoint {
                uri: ep.to_string(),
            });
        }
    }

    issues
}

fn extract_report_uris(csp: &str) -> Vec<&str> {
    let mut uris = Vec::new();
    for directive in csp.split(';') {
        let trimmed = directive.trim();
        if let Some(rest) = trimmed.strip_prefix("report-uri") {
            for token in rest.split_whitespace() {
                if !token.is_empty() {
                    uris.push(token);
                }
            }
        }
    }
    uris
}

fn extract_report_to_endpoints<'a>(csp: &str, report_to_header: &'a str) -> Vec<&'a str> {
    let mut endpoints = Vec::new();

    let has_report_to_directive = csp.split(';').any(|d| d.trim().starts_with("report-to"));

    if has_report_to_directive && !report_to_header.is_empty() {
        for token in report_to_header.split('"') {
            let trimmed = token.trim();
            if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                endpoints.push(trimmed);
            }
        }
    }

    endpoints
}

pub(crate) fn csp_report_severity(issue: &CspReportLeakIssue) -> f64 {
    match issue {
        CspReportLeakIssue::InternalReportUri { .. } => 6.0,
        CspReportLeakIssue::HttpReportEndpoint { .. } => 5.0,
        CspReportLeakIssue::ThirdPartyReportEndpoint { .. } => 4.0,
        CspReportLeakIssue::DeprecatedReportUri => 2.5,
    }
}

pub fn csp_report_leak_to_operations(
    issues: &[CspReportLeakIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .filter(|i| csp_report_severity(i) >= 3.0)
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                csp_report_severity(issue),
                0.9,
            )
        })
        .collect()
}
