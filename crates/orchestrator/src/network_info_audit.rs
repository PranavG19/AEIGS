use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum NetworkInfoIssue {
    ApiDetected,
    FingerprintingVector,
    DataExfiltration,
    ConnectionMonitoring,
    CombinedFingerprint,
}

impl std::fmt::Display for NetworkInfoIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::FingerprintingVector => write!(f, "fingerprinting_vector"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::ConnectionMonitoring => write!(f, "connection_monitoring"),
            Self::CombinedFingerprint => write!(f, "combined_fingerprint"),
        }
    }
}

pub fn audit_network_info(target: &str) -> Vec<NetworkInfoIssue> {
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
    analyze_network_info(&body)
}

pub fn analyze_network_info(body: &str) -> Vec<NetworkInfoIssue> {
    if !body.contains("navigator.connection") && !body.contains("NetworkInformation") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(NetworkInfoIssue::ApiDetected);

    if body.contains("effectiveType")
        || body.contains("downlink")
        || body.contains("rtt")
        || body.contains("saveData")
    {
        issues.push(NetworkInfoIssue::FingerprintingVector);
    }

    if body.contains("navigator.connection")
        && (body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest"))
    {
        issues.push(NetworkInfoIssue::DataExfiltration);
    }

    if body.contains("onchange") || body.contains("addEventListener") && body.contains("change") {
        issues.push(NetworkInfoIssue::ConnectionMonitoring);
    }

    if body.contains("navigator.connection")
        && (body.contains("deviceMemory")
            || body.contains("hardwareConcurrency")
            || body.contains("userAgent")
            || body.contains("platform"))
    {
        issues.push(NetworkInfoIssue::CombinedFingerprint);
    }

    issues
}

pub fn network_info_severity(issue: &NetworkInfoIssue) -> f64 {
    match issue {
        NetworkInfoIssue::CombinedFingerprint => 7.0,
        NetworkInfoIssue::DataExfiltration => 6.5,
        NetworkInfoIssue::ConnectionMonitoring => 5.5,
        NetworkInfoIssue::FingerprintingVector => 5.0,
        NetworkInfoIssue::ApiDetected => 2.5,
    }
}

pub fn network_info_to_operations(
    issues: &[NetworkInfoIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                network_info_severity(issue),
                0.6,
            )
        })
        .collect()
}
