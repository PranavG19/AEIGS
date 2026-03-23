use std::collections::HashSet;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ReportingEndpointIssue {
    Present,
    ExternalCollector { url: String },
    HttpEndpoint { url: String },
    TooManyEndpoints { count: usize },
    DuplicateEndpointNames { name: String },
    InvalidEndpointUrl { name: String, url: String },
    ThirdPartyCollector { service: String },
    DeprecatedReportTo,
}

impl std::fmt::Display for ReportingEndpointIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Present => write!(f, "present"),
            Self::ExternalCollector { url } => write!(f, "external_collector: {url}"),
            Self::HttpEndpoint { url } => write!(f, "http_endpoint: {url}"),
            Self::TooManyEndpoints { count } => write!(f, "too_many_endpoints: {count}"),
            Self::DuplicateEndpointNames { name } => {
                write!(f, "duplicate_endpoint_names: {name}")
            }
            Self::InvalidEndpointUrl { name, url } => {
                write!(f, "invalid_endpoint_url: {name}={url}")
            }
            Self::ThirdPartyCollector { service } => {
                write!(f, "third_party_collector: {service}")
            }
            Self::DeprecatedReportTo => write!(f, "deprecated_report_to"),
        }
    }
}

const THIRD_PARTY_SERVICES: &[(&str, &str)] = &[
    ("sentry.io", "Sentry"),
    ("report-uri.com", "Report URI"),
    ("uriports.com", "URIports"),
];

const MAX_ENDPOINTS: usize = 5;

pub fn reporting_endpoint_severity(issue: &ReportingEndpointIssue) -> f64 {
    match issue {
        ReportingEndpointIssue::Present => 2.0,
        ReportingEndpointIssue::ExternalCollector { .. } => 3.5,
        ReportingEndpointIssue::HttpEndpoint { .. } => 5.0,
        ReportingEndpointIssue::TooManyEndpoints { .. } => 2.0,
        ReportingEndpointIssue::DuplicateEndpointNames { .. } => 2.5,
        ReportingEndpointIssue::InvalidEndpointUrl { .. } => 3.0,
        ReportingEndpointIssue::ThirdPartyCollector { .. } => 2.5,
        ReportingEndpointIssue::DeprecatedReportTo => 1.5,
    }
}

pub fn audit_reporting_endpoints(target: &str) -> Vec<ReportingEndpointIssue> {
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

    let reporting_endpoints = resp
        .headers()
        .get("reporting-endpoints")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let report_to = resp
        .headers()
        .get("report-to")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let target_domain = recon_client::validated_domain(target);
    analyze_reporting_endpoints(
        reporting_endpoints.as_deref(),
        report_to.as_deref(),
        target_domain.as_deref(),
    )
}

pub fn analyze_reporting_endpoints(
    reporting_endpoints: Option<&str>,
    report_to: Option<&str>,
    target_domain: Option<&str>,
) -> Vec<ReportingEndpointIssue> {
    let mut issues = Vec::new();

    if report_to.is_some() {
        issues.push(ReportingEndpointIssue::DeprecatedReportTo);
    }

    let Some(val) = reporting_endpoints else {
        return issues;
    };

    issues.push(ReportingEndpointIssue::Present);

    let entries: Vec<&str> = val.split(',').map(|e| e.trim()).collect();

    if entries.len() > MAX_ENDPOINTS {
        issues.push(ReportingEndpointIssue::TooManyEndpoints {
            count: entries.len(),
        });
    }

    let mut seen_names: HashSet<String> = HashSet::new();

    for entry in &entries {
        let Some((name, url)) = extract_endpoint_parts(entry) else {
            continue;
        };

        let name_lower = name.to_ascii_lowercase();
        if !seen_names.insert(name_lower.clone()) {
            issues.push(ReportingEndpointIssue::DuplicateEndpointNames {
                name: name.to_string(),
            });
        }

        if !url.starts_with("http://") && !url.starts_with("https://") {
            issues.push(ReportingEndpointIssue::InvalidEndpointUrl {
                name: name.to_string(),
                url: recon_client::truncate(&url, 60),
            });
            continue;
        }

        if url.starts_with("http://") {
            issues.push(ReportingEndpointIssue::HttpEndpoint {
                url: recon_client::truncate(&url, 60),
            });
        }

        if let Some(domain) = target_domain
            && recon_client::is_external(&url, domain)
        {
            issues.push(ReportingEndpointIssue::ExternalCollector {
                url: recon_client::truncate(&url, 60),
            });
        }

        for &(pattern, service) in THIRD_PARTY_SERVICES {
            if url.contains(pattern) {
                issues.push(ReportingEndpointIssue::ThirdPartyCollector {
                    service: service.to_string(),
                });
                break;
            }
        }
    }

    issues
}

fn extract_endpoint_parts(entry: &str) -> Option<(String, String)> {
    let eq_pos = entry.find('=')?;
    let name = entry[..eq_pos].trim().to_string();
    let url_part = entry[eq_pos + 1..].trim();
    let url = url_part.trim_matches('"');
    if url.is_empty() {
        return None;
    }
    Some((name, url.to_string()))
}

pub fn extract_endpoint_url(entry: &str) -> Option<String> {
    let (_, url) = extract_endpoint_parts(entry)?;
    Some(url)
}

pub fn reporting_endpoints_to_operations(
    issues: &[ReportingEndpointIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                reporting_endpoint_severity(issue),
                0.5,
            )
        })
        .collect()
}
