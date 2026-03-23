use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum BadgingIssue {
    ApiDetected,
    MisleadingBadge,
    ContinuousUpdate,
    NoUserActivation,
    SpoofedUrgency,
}

impl std::fmt::Display for BadgingIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::MisleadingBadge => write!(f, "misleading_badge"),
            Self::ContinuousUpdate => write!(f, "continuous_update"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::SpoofedUrgency => write!(f, "spoofed_urgency"),
        }
    }
}

pub fn audit_badging(target: &str) -> Vec<BadgingIssue> {
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
    analyze_badging(&body)
}

pub fn analyze_badging(body: &str) -> Vec<BadgingIssue> {
    if !body.contains("setAppBadge") && !body.contains("clearAppBadge") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(BadgingIssue::ApiDetected);

    if body.contains("setAppBadge(")
        && !body.contains("click")
        && !body.contains("pointerdown")
        && !body.contains("submit")
    {
        issues.push(BadgingIssue::NoUserActivation);
    }

    if body.contains("setInterval") || body.contains("setTimeout") && body.contains("setAppBadge") {
        issues.push(BadgingIssue::ContinuousUpdate);
    }

    if body.contains("setAppBadge(")
        && (body.contains("999") || body.contains("9999") || body.contains("Math.random"))
    {
        issues.push(BadgingIssue::MisleadingBadge);
    }

    if body.contains("setAppBadge(")
        && (body.contains("urgent") || body.contains("alert") || body.contains("warning")
            || body.contains("security"))
    {
        issues.push(BadgingIssue::SpoofedUrgency);
    }

    issues
}

pub fn badging_severity(issue: &BadgingIssue) -> f64 {
    match issue {
        BadgingIssue::SpoofedUrgency => 6.0,
        BadgingIssue::MisleadingBadge => 5.5,
        BadgingIssue::ContinuousUpdate => 4.5,
        BadgingIssue::NoUserActivation => 4.0,
        BadgingIssue::ApiDetected => 2.0,
    }
}

pub fn badging_to_operations(
    issues: &[BadgingIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                badging_severity(issue),
                0.5,
            )
        })
        .collect()
}
