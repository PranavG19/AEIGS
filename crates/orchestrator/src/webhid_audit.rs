use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebHidIssue {
    ApiDetected,
    DataExfiltration,
    NoUserActivation,
    RawDataAccess,
    DeviceEnumeration,
    PersistentConnection,
}

impl std::fmt::Display for WebHidIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::RawDataAccess => write!(f, "raw_data_access"),
            Self::DeviceEnumeration => write!(f, "device_enumeration"),
            Self::PersistentConnection => write!(f, "persistent_connection"),
        }
    }
}

pub fn audit_webhid(target: &str) -> Vec<WebHidIssue> {
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
    analyze_webhid(&body)
}

pub fn analyze_webhid(body: &str) -> Vec<WebHidIssue> {
    if !body.contains("navigator.hid") && !body.contains("HIDDevice") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebHidIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(WebHidIssue::DataExfiltration);
    }

    if !body.contains("click") && !body.contains("keydown") && !body.contains("pointerdown") {
        issues.push(WebHidIssue::NoUserActivation);
    }

    if body.contains("sendReport")
        || body.contains("sendFeatureReport")
        || body.contains("receiveFeatureReport")
    {
        issues.push(WebHidIssue::RawDataAccess);
    }

    if body.contains("getDevices") || body.contains("requestDevice") {
        issues.push(WebHidIssue::DeviceEnumeration);
    }

    if body.contains("oninputreport") || body.contains("inputreport") {
        issues.push(WebHidIssue::PersistentConnection);
    }

    issues
}

pub fn webhid_severity(issue: &WebHidIssue) -> f64 {
    match issue {
        WebHidIssue::DataExfiltration => 7.5,
        WebHidIssue::RawDataAccess => 7.0,
        WebHidIssue::PersistentConnection => 6.0,
        WebHidIssue::DeviceEnumeration => 5.5,
        WebHidIssue::NoUserActivation => 5.0,
        WebHidIssue::ApiDetected => 3.0,
    }
}

pub fn webhid_to_operations(issues: &[WebHidIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                webhid_severity(issue),
                0.6,
            )
        })
        .collect()
}
