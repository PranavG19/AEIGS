use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebShareIssue {
    ApiDetected,
    DataExfiltration,
    NoUserActivation,
    FileSharing,
    SensitiveContent,
    UnvalidatedUrl,
}

impl std::fmt::Display for WebShareIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::FileSharing => write!(f, "file_sharing"),
            Self::SensitiveContent => write!(f, "sensitive_content"),
            Self::UnvalidatedUrl => write!(f, "unvalidated_url"),
        }
    }
}

pub fn audit_web_share(target: &str) -> Vec<WebShareIssue> {
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
    analyze_web_share(&body)
}

pub fn analyze_web_share(body: &str) -> Vec<WebShareIssue> {
    if !body.contains("navigator.share") && !body.contains("navigator.canShare") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebShareIssue::ApiDetected);

    if !body.contains("click") && !body.contains("keydown") && !body.contains("pointerdown") {
        issues.push(WebShareIssue::NoUserActivation);
    }

    let has_share = body.contains("navigator.share(");
    if has_share
        && (body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest"))
    {
        issues.push(WebShareIssue::DataExfiltration);
    }

    if body.contains("files:") || body.contains("new File(") || body.contains("new Blob(") {
        issues.push(WebShareIssue::FileSharing);
    }

    if has_share
        && (body.contains("password") || body.contains("token") || body.contains("cookie")
            || body.contains("localStorage") || body.contains("sessionStorage"))
    {
        issues.push(WebShareIssue::SensitiveContent);
    }

    if has_share && (body.contains("url:") || body.contains("text:"))
        && !body.contains("encodeURI") && !body.contains("new URL(")
    {
        issues.push(WebShareIssue::UnvalidatedUrl);
    }

    issues
}

pub fn web_share_severity(issue: &WebShareIssue) -> f64 {
    match issue {
        WebShareIssue::DataExfiltration => 7.0,
        WebShareIssue::SensitiveContent => 6.5,
        WebShareIssue::UnvalidatedUrl => 5.5,
        WebShareIssue::FileSharing => 5.0,
        WebShareIssue::NoUserActivation => 4.5,
        WebShareIssue::ApiDetected => 2.5,
    }
}

pub fn web_share_to_operations(
    issues: &[WebShareIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                web_share_severity(issue),
                0.6,
            )
        })
        .collect()
}
