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
    if !body.contains("launchQueue")
        && !body.contains("LaunchParams")
        && !body.contains("launch_handler")
    {
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
        && (body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("XMLHttpRequest"))
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

#[derive(Debug, Clone, PartialEq)]
pub enum LaunchHandlerSecurityIssue {
    LaunchUrlExfiltration,
    LaunchWithoutValidation,
    LaunchRedirectAbuse,
    LaunchCrossOrigin,
    LaunchParamInjection,
    LaunchPersistence,
    LaunchInBackground,
    LaunchFileAccess,
    LaunchProtocolAbuse,
    LaunchChaining,
}

impl std::fmt::Display for LaunchHandlerSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LaunchUrlExfiltration => write!(f, "launch_url_exfiltration"),
            Self::LaunchWithoutValidation => write!(f, "launch_without_validation"),
            Self::LaunchRedirectAbuse => write!(f, "launch_redirect_abuse"),
            Self::LaunchCrossOrigin => write!(f, "launch_cross_origin"),
            Self::LaunchParamInjection => write!(f, "launch_param_injection"),
            Self::LaunchPersistence => write!(f, "launch_persistence"),
            Self::LaunchInBackground => write!(f, "launch_in_background"),
            Self::LaunchFileAccess => write!(f, "launch_file_access"),
            Self::LaunchProtocolAbuse => write!(f, "launch_protocol_abuse"),
            Self::LaunchChaining => write!(f, "launch_chaining"),
        }
    }
}

pub fn analyze_launch_handler_security(body: &str) -> Vec<LaunchHandlerSecurityIssue> {
    let has_launch_api = body.contains("launchQueue")
        || body.contains("LaunchParams")
        || body.contains("launch_handler");
    let has_protocol_handler = body.contains("registerProtocolHandler");

    if !has_launch_api && !has_protocol_handler {
        return Vec::new();
    }

    let mut issues = Vec::new();
    let has_consumer = body.contains("setConsumer") || body.contains("launchQueue");

    if has_consumer
        && body.contains("targetURL")
        && (body.contains("fetch(")
            || body.contains("XMLHttpRequest")
            || body.contains("sendBeacon"))
        && (body.contains("external") || body.contains("analytics") || body.contains("track"))
    {
        issues.push(LaunchHandlerSecurityIssue::LaunchUrlExfiltration);
    }

    if has_consumer
        && !body.contains("validate")
        && !body.contains("sanitize")
        && !body.contains("allowlist")
        && !body.contains("whitelist")
        && !body.contains("URL(")
    {
        issues.push(LaunchHandlerSecurityIssue::LaunchWithoutValidation);
    }

    if has_consumer
        && body.contains("targetURL")
        && (body.contains("window.location") || body.contains("location.href"))
        && !body.contains("origin")
        && !body.contains("allowlist")
    {
        issues.push(LaunchHandlerSecurityIssue::LaunchRedirectAbuse);
    }

    if has_consumer
        && (body.contains("postMessage") || body.contains("parent.postMessage"))
        && body.contains("targetURL")
    {
        issues.push(LaunchHandlerSecurityIssue::LaunchCrossOrigin);
    }

    if has_consumer
        && (body.contains("innerHTML")
            || body.contains("document.write")
            || body.contains("outerHTML"))
        && body.contains("targetURL")
    {
        issues.push(LaunchHandlerSecurityIssue::LaunchParamInjection);
    }

    if has_consumer
        && (body.contains("localStorage")
            || body.contains("sessionStorage")
            || body.contains("indexedDB"))
        && body.contains("targetURL")
    {
        issues.push(LaunchHandlerSecurityIssue::LaunchPersistence);
    }

    if has_consumer
        && (body.contains("visibilityState") || body.contains("document.hidden"))
        && body.contains("'hidden'")
    {
        issues.push(LaunchHandlerSecurityIssue::LaunchInBackground);
    }

    if has_consumer
        && body.contains("files")
        && (body.contains("FileReader")
            || body.contains("readAsText")
            || body.contains("readAsDataURL"))
    {
        issues.push(LaunchHandlerSecurityIssue::LaunchFileAccess);
    }

    if has_protocol_handler
        && (body.contains("web+") || body.contains("mailto") || body.contains("tel"))
    {
        issues.push(LaunchHandlerSecurityIssue::LaunchProtocolAbuse);
    }

    if has_consumer
        && body.contains("targetURL")
        && (body.contains("window.open") || body.contains("iframe"))
    {
        issues.push(LaunchHandlerSecurityIssue::LaunchChaining);
    }

    issues
}

pub fn launch_handler_security_severity(issue: &LaunchHandlerSecurityIssue) -> f64 {
    match issue {
        LaunchHandlerSecurityIssue::LaunchParamInjection => 9.0,
        LaunchHandlerSecurityIssue::LaunchUrlExfiltration => 8.5,
        LaunchHandlerSecurityIssue::LaunchRedirectAbuse => 8.0,
        LaunchHandlerSecurityIssue::LaunchProtocolAbuse => 7.5,
        LaunchHandlerSecurityIssue::LaunchCrossOrigin => 7.0,
        LaunchHandlerSecurityIssue::LaunchFileAccess => 6.5,
        LaunchHandlerSecurityIssue::LaunchChaining => 6.0,
        LaunchHandlerSecurityIssue::LaunchPersistence => 5.5,
        LaunchHandlerSecurityIssue::LaunchInBackground => 4.5,
        LaunchHandlerSecurityIssue::LaunchWithoutValidation => 3.0,
    }
}

pub fn launch_handler_security_to_operations(
    issues: &[LaunchHandlerSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                launch_handler_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
