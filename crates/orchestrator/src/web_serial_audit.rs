use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebSerialIssue {
    ApiDetected,
    DataExfiltration,
    NoUserActivation,
    RawReadWrite,
    DeviceEnumeration,
    PersistentStream,
}

impl std::fmt::Display for WebSerialIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::RawReadWrite => write!(f, "raw_read_write"),
            Self::DeviceEnumeration => write!(f, "device_enumeration"),
            Self::PersistentStream => write!(f, "persistent_stream"),
        }
    }
}

pub fn audit_web_serial(target: &str) -> Vec<WebSerialIssue> {
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
    analyze_web_serial(&body)
}

pub fn analyze_web_serial(body: &str) -> Vec<WebSerialIssue> {
    if !body.contains("navigator.serial") && !body.contains("SerialPort") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebSerialIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(WebSerialIssue::DataExfiltration);
    }

    if !body.contains("click") && !body.contains("keydown") && !body.contains("pointerdown") {
        issues.push(WebSerialIssue::NoUserActivation);
    }

    if body.contains(".readable") || body.contains(".writable") || body.contains("getReader") || body.contains("getWriter") {
        issues.push(WebSerialIssue::RawReadWrite);
    }

    if body.contains("getPorts") || body.contains("requestPort") {
        issues.push(WebSerialIssue::DeviceEnumeration);
    }

    if body.contains("pipeTo") || body.contains("pipeThrough") || body.contains("ReadableStream") {
        issues.push(WebSerialIssue::PersistentStream);
    }

    issues
}

pub fn web_serial_severity(issue: &WebSerialIssue) -> f64 {
    match issue {
        WebSerialIssue::DataExfiltration => 7.5,
        WebSerialIssue::RawReadWrite => 7.0,
        WebSerialIssue::PersistentStream => 6.0,
        WebSerialIssue::DeviceEnumeration => 5.5,
        WebSerialIssue::NoUserActivation => 5.0,
        WebSerialIssue::ApiDetected => 3.0,
    }
}

pub fn web_serial_to_operations(
    issues: &[WebSerialIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                web_serial_severity(issue),
                0.6,
            )
        })
        .collect()
}
