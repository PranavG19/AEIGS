use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum AttributionReportingIssue {
    ApiDetected,
    CrossSiteTracking,
    ExternalReportUrl,
    EventLevelFingerprint,
    DebugKeyLeak,
}

impl std::fmt::Display for AttributionReportingIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::CrossSiteTracking => write!(f, "cross_site_tracking"),
            Self::ExternalReportUrl => write!(f, "external_report_url"),
            Self::EventLevelFingerprint => write!(f, "event_level_fingerprint"),
            Self::DebugKeyLeak => write!(f, "debug_key_leak"),
        }
    }
}

pub fn audit_attribution_reporting(target: &str) -> Vec<AttributionReportingIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_attribution_reporting(&body)
}

pub fn analyze_attribution_reporting(body: &str) -> Vec<AttributionReportingIssue> {
    let has_attr = body.contains("attributionsrc") || body.contains("attributionReporting");
    let has_header = body.contains("Attribution-Reporting");

    if !has_attr && !has_header {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(AttributionReportingIssue::ApiDetected);

    if (has_attr || has_header)
        && (body.contains("source_event_id") || body.contains("destination"))
        && body.contains("trigger_data")
    {
        issues.push(AttributionReportingIssue::CrossSiteTracking);
    }

    if has_attr
        && body.contains("attributionsrc=")
        && (body.contains("http://") || body.contains("https://"))
    {
        let src_start = body.find("attributionsrc=");
        if let Some(idx) = src_start {
            let after = &body[idx..];
            if after.contains("http://") || (after.contains("https://") && after.contains(".com")) {
                issues.push(AttributionReportingIssue::ExternalReportUrl);
            }
        }
    }

    if (has_attr || has_header)
        && body.contains("event_trigger_data")
        && (body.contains("trigger_data") || body.contains("priority"))
    {
        issues.push(AttributionReportingIssue::EventLevelFingerprint);
    }

    if (has_attr || has_header) && (body.contains("debug_key") || body.contains("debug_reporting"))
    {
        issues.push(AttributionReportingIssue::DebugKeyLeak);
    }

    issues
}

pub fn attribution_reporting_severity(issue: &AttributionReportingIssue) -> f64 {
    match issue {
        AttributionReportingIssue::CrossSiteTracking => 7.0,
        AttributionReportingIssue::DebugKeyLeak => 6.5,
        AttributionReportingIssue::ExternalReportUrl => 6.0,
        AttributionReportingIssue::EventLevelFingerprint => 5.0,
        AttributionReportingIssue::ApiDetected => 2.0,
    }
}

pub fn attribution_reporting_to_operations(
    issues: &[AttributionReportingIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                attribution_reporting_severity(issue),
                0.5,
            )
        })
        .collect()
}
