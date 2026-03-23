use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ReportingApiIssue {
    ThirdPartyEndpoint,
    HttpEndpoint,
    ReportToDeprecated,
    ObserverDetected,
    ObserverBuffered,
    NoReportingEndpoints,
    ExcessiveReportTypes,
}

impl std::fmt::Display for ReportingApiIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ThirdPartyEndpoint => write!(f, "third_party_endpoint"),
            Self::HttpEndpoint => write!(f, "http_endpoint"),
            Self::ReportToDeprecated => write!(f, "report_to_deprecated"),
            Self::ObserverDetected => write!(f, "observer_detected"),
            Self::ObserverBuffered => write!(f, "observer_buffered"),
            Self::NoReportingEndpoints => write!(f, "no_reporting_endpoints"),
            Self::ExcessiveReportTypes => write!(f, "excessive_report_types"),
        }
    }
}

pub fn audit_reporting_api(target: &str) -> Vec<ReportingApiIssue> {
    let domain = match recon_client::validated_domain(target) {
        Some(d) => d,
        None => return Vec::new(),
    };
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let report_to = resp
        .headers()
        .get("report-to")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let reporting_endpoints = resp
        .headers()
        .get("reporting-endpoints")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp.text().unwrap_or_default();
    analyze_reporting_api(&domain, &report_to, &reporting_endpoints, &body)
}

pub fn analyze_reporting_api(
    domain: &str,
    report_to: &str,
    reporting_endpoints: &str,
    body: &str,
) -> Vec<ReportingApiIssue> {
    let mut issues = Vec::new();
    let has_report_to = !report_to.is_empty();
    let has_reporting_endpoints = !reporting_endpoints.is_empty();
    let has_observer = body.contains("ReportingObserver");

    if !has_report_to && !has_reporting_endpoints && !has_observer {
        return issues;
    }

    if has_report_to {
        issues.push(ReportingApiIssue::ReportToDeprecated);
        check_endpoints_in_value(report_to, domain, &mut issues);
    }

    if has_reporting_endpoints {
        check_endpoints_in_value(reporting_endpoints, domain, &mut issues);
        let type_count = reporting_endpoints.matches('=').count();
        if type_count > 5 {
            issues.push(ReportingApiIssue::ExcessiveReportTypes);
        }
    }

    if has_observer {
        issues.push(ReportingApiIssue::ObserverDetected);
        if body.contains("buffered") && body.contains("true") {
            issues.push(ReportingApiIssue::ObserverBuffered);
        }
    }

    if (has_report_to || has_observer) && !has_reporting_endpoints {
        issues.push(ReportingApiIssue::NoReportingEndpoints);
    }

    issues
}

fn check_endpoints_in_value(value: &str, domain: &str, issues: &mut Vec<ReportingApiIssue>) {
    if value.contains("http://") {
        issues.push(ReportingApiIssue::HttpEndpoint);
    }
    let has_third_party = value.contains("https://")
        && value
            .split("https://")
            .skip(1)
            .any(|part| !part.starts_with(domain));
    if has_third_party {
        issues.push(ReportingApiIssue::ThirdPartyEndpoint);
    }
}

pub fn reporting_api_severity(issue: &ReportingApiIssue) -> f64 {
    match issue {
        ReportingApiIssue::HttpEndpoint => 6.5,
        ReportingApiIssue::ThirdPartyEndpoint => 5.5,
        ReportingApiIssue::ObserverBuffered => 5.0,
        ReportingApiIssue::ReportToDeprecated => 4.5,
        ReportingApiIssue::ExcessiveReportTypes => 4.0,
        ReportingApiIssue::ObserverDetected => 3.5,
        ReportingApiIssue::NoReportingEndpoints => 3.0,
    }
}

pub fn reporting_api_to_operations(
    issues: &[ReportingApiIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                reporting_api_severity(issue),
                0.7,
            )
        })
        .collect()
}
