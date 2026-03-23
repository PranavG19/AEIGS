use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebNfcIssue {
    ApiDetected,
    DataExfiltration,
    NoUserActivation,
    WriteCapability,
    ContinuousScanning,
    UrlRecordInjection,
}

impl std::fmt::Display for WebNfcIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::WriteCapability => write!(f, "write_capability"),
            Self::ContinuousScanning => write!(f, "continuous_scanning"),
            Self::UrlRecordInjection => write!(f, "url_record_injection"),
        }
    }
}

pub fn audit_web_nfc(target: &str) -> Vec<WebNfcIssue> {
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
    analyze_web_nfc(&body)
}

pub fn analyze_web_nfc(body: &str) -> Vec<WebNfcIssue> {
    if !body.contains("NDEFReader") && !body.contains("NDEFWriter") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebNfcIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(WebNfcIssue::DataExfiltration);
    }

    if !body.contains("click") && !body.contains("keydown") && !body.contains("pointerdown") {
        issues.push(WebNfcIssue::NoUserActivation);
    }

    if body.contains(".write(") || body.contains("NDEFWriter") {
        issues.push(WebNfcIssue::WriteCapability);
    }

    if body.contains(".scan(") || body.contains("onreading") || body.contains("\"reading\"") {
        issues.push(WebNfcIssue::ContinuousScanning);
    }

    if body.contains("NDEFRecord") && body.contains("url") {
        issues.push(WebNfcIssue::UrlRecordInjection);
    }

    issues
}

pub fn web_nfc_severity(issue: &WebNfcIssue) -> f64 {
    match issue {
        WebNfcIssue::WriteCapability => 7.5,
        WebNfcIssue::DataExfiltration => 7.0,
        WebNfcIssue::UrlRecordInjection => 6.5,
        WebNfcIssue::ContinuousScanning => 5.5,
        WebNfcIssue::NoUserActivation => 5.0,
        WebNfcIssue::ApiDetected => 3.0,
    }
}

pub fn web_nfc_to_operations(
    issues: &[WebNfcIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                web_nfc_severity(issue),
                0.6,
            )
        })
        .collect()
}
