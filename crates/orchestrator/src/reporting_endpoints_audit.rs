use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ReportingEndpointIssueKind {
    ExternalCollector,
    HttpEndpoint,
    Present,
}

#[derive(Debug, Clone)]
pub struct ReportingEndpointIssue {
    pub kind: ReportingEndpointIssueKind,
    pub detail: String,
    pub severity: f64,
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

    let value = resp
        .headers()
        .get("reporting-endpoints")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let target_domain = recon_client::validated_domain(target);
    analyze_reporting_endpoints(value.as_deref(), target_domain.as_deref())
}

pub(crate) fn analyze_reporting_endpoints(
    value: Option<&str>,
    target_domain: Option<&str>,
) -> Vec<ReportingEndpointIssue> {
    let Some(val) = value else {
        return Vec::new();
    };

    let mut issues = vec![ReportingEndpointIssue {
        kind: ReportingEndpointIssueKind::Present,
        detail: "Reporting-Endpoints header configured — browser sends error reports".into(),
        severity: 2.0,
    }];

    for entry in val.split(',') {
        let entry = entry.trim();
        let Some(url) = extract_endpoint_url(entry) else {
            continue;
        };

        if url.starts_with("http://") {
            issues.push(ReportingEndpointIssue {
                kind: ReportingEndpointIssueKind::HttpEndpoint,
                detail: format!("Report endpoint uses HTTP: {}", recon_client::truncate(&url, 60)),
                severity: 5.0,
            });
        }

        if let Some(domain) = target_domain
            && recon_client::is_external(&url, domain)
        {
            issues.push(ReportingEndpointIssue {
                kind: ReportingEndpointIssueKind::ExternalCollector,
                detail: format!("Reports sent to external collector: {}", recon_client::truncate(&url, 60)),
                severity: 3.5,
            });
        }
    }

    issues
}

fn extract_endpoint_url(entry: &str) -> Option<String> {
    let eq_pos = entry.find('=')?;
    let url_part = entry[eq_pos + 1..].trim();
    let url = url_part.trim_matches('"');
    if url.is_empty() {
        return None;
    }
    Some(url.to_string())
}

pub fn reporting_endpoints_to_operations(
    issues: &[ReportingEndpointIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues
        .iter()
        .map(|i| i.severity)
        .fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::InformationDisclosure,
        max_severity,
        0.85,
    )]
}
