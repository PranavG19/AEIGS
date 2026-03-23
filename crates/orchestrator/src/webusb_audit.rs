use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebUsbIssue {
    ApiDetected,
    DataExfiltration,
    NoUserActivation,
    BulkTransfer,
    DeviceEnumeration,
    ClaimInterface,
}

impl std::fmt::Display for WebUsbIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::BulkTransfer => write!(f, "bulk_transfer"),
            Self::DeviceEnumeration => write!(f, "device_enumeration"),
            Self::ClaimInterface => write!(f, "claim_interface"),
        }
    }
}

pub fn audit_webusb(target: &str) -> Vec<WebUsbIssue> {
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
    analyze_webusb(&body)
}

pub fn analyze_webusb(body: &str) -> Vec<WebUsbIssue> {
    if !body.contains("navigator.usb") && !body.contains("USBDevice") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebUsbIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(WebUsbIssue::DataExfiltration);
    }

    if !body.contains("click") && !body.contains("keydown") && !body.contains("pointerdown") {
        issues.push(WebUsbIssue::NoUserActivation);
    }

    if body.contains("transferIn") || body.contains("transferOut") {
        issues.push(WebUsbIssue::BulkTransfer);
    }

    if body.contains("getDevices") || body.contains("requestDevice") {
        issues.push(WebUsbIssue::DeviceEnumeration);
    }

    if body.contains("claimInterface") {
        issues.push(WebUsbIssue::ClaimInterface);
    }

    issues
}

pub fn webusb_severity(issue: &WebUsbIssue) -> f64 {
    match issue {
        WebUsbIssue::DataExfiltration => 7.5,
        WebUsbIssue::BulkTransfer => 7.0,
        WebUsbIssue::ClaimInterface => 6.5,
        WebUsbIssue::DeviceEnumeration => 5.5,
        WebUsbIssue::NoUserActivation => 5.0,
        WebUsbIssue::ApiDetected => 3.0,
    }
}

pub fn webusb_to_operations(issues: &[WebUsbIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                webusb_severity(issue),
                0.6,
            )
        })
        .collect()
}
