use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum DeviceMemoryIssue {
    ApiDetected,
    FingerprintingVector,
    DataExfiltration,
    CombinedFingerprint,
    ClientHintHeader,
}

impl std::fmt::Display for DeviceMemoryIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::FingerprintingVector => write!(f, "fingerprinting_vector"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::CombinedFingerprint => write!(f, "combined_fingerprint"),
            Self::ClientHintHeader => write!(f, "client_hint_header"),
        }
    }
}

pub fn audit_device_memory(target: &str) -> Vec<DeviceMemoryIssue> {
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
    analyze_device_memory(&body)
}

pub fn analyze_device_memory(body: &str) -> Vec<DeviceMemoryIssue> {
    let has_api = body.contains("navigator.deviceMemory") || body.contains("deviceMemory");
    let has_header = body.contains("Device-Memory") || body.contains("device-memory");

    if !has_api && !has_header {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(DeviceMemoryIssue::ApiDetected);

    if has_header {
        issues.push(DeviceMemoryIssue::ClientHintHeader);
    }

    if has_api {
        issues.push(DeviceMemoryIssue::FingerprintingVector);
    }

    if has_api
        && (body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("XMLHttpRequest"))
    {
        issues.push(DeviceMemoryIssue::DataExfiltration);
    }

    if has_api
        && (body.contains("hardwareConcurrency")
            || body.contains("platform")
            || body.contains("userAgent")
            || body.contains("maxTouchPoints"))
    {
        issues.push(DeviceMemoryIssue::CombinedFingerprint);
    }

    issues
}

pub fn device_memory_severity(issue: &DeviceMemoryIssue) -> f64 {
    match issue {
        DeviceMemoryIssue::CombinedFingerprint => 7.0,
        DeviceMemoryIssue::DataExfiltration => 6.5,
        DeviceMemoryIssue::FingerprintingVector => 5.5,
        DeviceMemoryIssue::ClientHintHeader => 4.5,
        DeviceMemoryIssue::ApiDetected => 2.5,
    }
}

pub fn device_memory_to_operations(
    issues: &[DeviceMemoryIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                device_memory_severity(issue),
                0.6,
            )
        })
        .collect()
}
