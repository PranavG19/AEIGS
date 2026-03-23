use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum LaunchHandlerIssue {
    ApiDetected,
    UrlInjection,
    FileHandling,
    DataExfiltration,
    NoInputValidation,
}

impl std::fmt::Display for LaunchHandlerIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::UrlInjection => write!(f, "url_injection"),
            Self::FileHandling => write!(f, "file_handling"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::NoInputValidation => write!(f, "no_input_validation"),
        }
    }
}

pub fn audit_launch_handler(target: &str) -> Vec<LaunchHandlerIssue> {
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
    analyze_launch_handler(&body)
}

pub fn analyze_launch_handler(body: &str) -> Vec<LaunchHandlerIssue> {
    if !body.contains("launchQueue") && !body.contains("LaunchParams") && !body.contains("launch_handler") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(LaunchHandlerIssue::ApiDetected);

    let has_consumer = body.contains("setConsumer") || body.contains("launchQueue");
    if has_consumer
        && body.contains("targetURL")
        && !body.contains("new URL(")
        && !body.contains("encodeURI")
        && !body.contains("sanitize")
    {
        issues.push(LaunchHandlerIssue::UrlInjection);
    }

    if body.contains("files") && has_consumer {
        issues.push(LaunchHandlerIssue::FileHandling);
    }

    if has_consumer
        && (body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest"))
    {
        issues.push(LaunchHandlerIssue::DataExfiltration);
    }

    if has_consumer
        && !body.contains("validate")
        && !body.contains("sanitize")
        && !body.contains("allowlist")
        && !body.contains("whitelist")
    {
        issues.push(LaunchHandlerIssue::NoInputValidation);
    }

    issues
}

pub fn launch_handler_severity(issue: &LaunchHandlerIssue) -> f64 {
    match issue {
        LaunchHandlerIssue::UrlInjection => 7.5,
        LaunchHandlerIssue::DataExfiltration => 7.0,
        LaunchHandlerIssue::FileHandling => 6.0,
        LaunchHandlerIssue::NoInputValidation => 5.0,
        LaunchHandlerIssue::ApiDetected => 2.5,
    }
}

pub fn launch_handler_to_operations(
    issues: &[LaunchHandlerIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                launch_handler_severity(issue),
                0.6,
            )
        })
        .collect()
}
