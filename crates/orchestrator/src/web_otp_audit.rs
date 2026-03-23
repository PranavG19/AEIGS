use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebOtpIssue {
    ApiDetected,
    OtpInterception,
    NoRateLimiting,
    InsecureTransport,
    CrossOriginRisk,
}

impl std::fmt::Display for WebOtpIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::OtpInterception => write!(f, "otp_interception"),
            Self::NoRateLimiting => write!(f, "no_rate_limiting"),
            Self::InsecureTransport => write!(f, "insecure_transport"),
            Self::CrossOriginRisk => write!(f, "cross_origin_risk"),
        }
    }
}

pub fn audit_web_otp(target: &str) -> Vec<WebOtpIssue> {
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
    analyze_web_otp(&body)
}

pub fn analyze_web_otp(body: &str) -> Vec<WebOtpIssue> {
    let has_api = body.contains("OTPCredential")
        || body.contains("otp")
        || body.contains("autocomplete=\"one-time-code\"")
        || body.contains("navigator.credentials.get");

    if !has_api {
        return Vec::new();
    }

    let mut issues = vec![WebOtpIssue::ApiDetected];

    let has_external_send =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    let has_otp_param = body.contains("otp")
        || body.contains("code")
        || body.contains("token")
        || body.contains("pin");
    if has_external_send && has_otp_param {
        issues.push(WebOtpIssue::OtpInterception);
    }

    let has_verification =
        body.contains("verify") || body.contains("validate") || body.contains("check");
    let has_rate_limit = body.contains("rateLimit")
        || body.contains("throttle")
        || body.contains("cooldown")
        || body.contains("attempt");
    if has_verification && !has_rate_limit {
        issues.push(WebOtpIssue::NoRateLimiting);
    }

    if body.contains("http://") {
        issues.push(WebOtpIssue::InsecureTransport);
    }

    let has_cross_origin =
        body.contains("postMessage") || body.contains("iframe") || body.contains("cross-origin");
    if has_cross_origin {
        issues.push(WebOtpIssue::CrossOriginRisk);
    }

    issues
}

pub fn web_otp_severity(issue: &WebOtpIssue) -> f64 {
    match issue {
        WebOtpIssue::ApiDetected => 2.0,
        WebOtpIssue::OtpInterception => 8.0,
        WebOtpIssue::NoRateLimiting => 7.0,
        WebOtpIssue::InsecureTransport => 7.5,
        WebOtpIssue::CrossOriginRisk => 6.0,
    }
}

pub fn web_otp_to_operations(issues: &[WebOtpIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                web_otp_severity(issue),
                0.5,
            )
        })
        .collect()
}
