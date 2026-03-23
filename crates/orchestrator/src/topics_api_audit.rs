use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum TopicsApiIssue {
    ApiDetected,
    InterestTracking,
    CrossSiteCorrelation,
    NoPermissionPolicy,
    ThirdPartyAccess,
    SilentObservation,
}

impl std::fmt::Display for TopicsApiIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::InterestTracking => write!(f, "interest_tracking"),
            Self::CrossSiteCorrelation => write!(f, "cross_site_correlation"),
            Self::NoPermissionPolicy => write!(f, "no_permission_policy"),
            Self::ThirdPartyAccess => write!(f, "third_party_access"),
            Self::SilentObservation => write!(f, "silent_observation"),
        }
    }
}

pub fn audit_topics_api(target: &str) -> Vec<TopicsApiIssue> {
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
    analyze_topics_api(&body)
}

pub fn analyze_topics_api(body: &str) -> Vec<TopicsApiIssue> {
    if !body.contains("browsingTopics") && !body.contains("BrowsingTopics") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(TopicsApiIssue::ApiDetected);

    if body.contains("document.browsingTopics(") || body.contains(".browsingTopics(") {
        issues.push(TopicsApiIssue::InterestTracking);
    }

    let has_topics_call = body.contains("browsingTopics(");
    if has_topics_call
        && (body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest"))
    {
        issues.push(TopicsApiIssue::CrossSiteCorrelation);
    }

    if !body.contains("Permissions-Policy") && !body.contains("permissions-policy") {
        issues.push(TopicsApiIssue::NoPermissionPolicy);
    }

    if body.contains("iframe") && has_topics_call {
        issues.push(TopicsApiIssue::ThirdPartyAccess);
    }

    if body.contains("browsingTopics") && body.contains("observe: true") {
        issues.push(TopicsApiIssue::SilentObservation);
    }

    issues
}

pub fn topics_api_severity(issue: &TopicsApiIssue) -> f64 {
    match issue {
        TopicsApiIssue::CrossSiteCorrelation => 7.0,
        TopicsApiIssue::SilentObservation => 6.5,
        TopicsApiIssue::ThirdPartyAccess => 6.0,
        TopicsApiIssue::InterestTracking => 5.5,
        TopicsApiIssue::NoPermissionPolicy => 4.5,
        TopicsApiIssue::ApiDetected => 2.5,
    }
}

pub fn topics_api_to_operations(
    issues: &[TopicsApiIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                topics_api_severity(issue),
                0.6,
            )
        })
        .collect()
}
