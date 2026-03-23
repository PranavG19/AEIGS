use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ComputePressureIssue {
    ApiDetected,
    StateExfiltration,
    CpuFingerprinting,
    CrossOriginLeak,
    ContinuousObserving,
}

impl std::fmt::Display for ComputePressureIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::StateExfiltration => write!(f, "state_exfiltration"),
            Self::CpuFingerprinting => write!(f, "cpu_fingerprinting"),
            Self::CrossOriginLeak => write!(f, "cross_origin_leak"),
            Self::ContinuousObserving => write!(f, "continuous_observing"),
        }
    }
}

pub fn audit_compute_pressure(target: &str) -> Vec<ComputePressureIssue> {
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
    analyze_compute_pressure(&body)
}

pub fn analyze_compute_pressure(body: &str) -> Vec<ComputePressureIssue> {
    if !body.contains("PressureObserver") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(ComputePressureIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(ComputePressureIssue::StateExfiltration);
    }

    if body.contains("hardwareConcurrency") || body.contains("deviceMemory") {
        issues.push(ComputePressureIssue::CpuFingerprinting);
    }

    if body.contains("iframe") || body.contains("postMessage") || body.contains("SharedWorker") {
        issues.push(ComputePressureIssue::CrossOriginLeak);
    }

    if body.contains(".observe(") && !body.contains(".unobserve(") && !body.contains("disconnect") {
        issues.push(ComputePressureIssue::ContinuousObserving);
    }

    issues
}

pub fn compute_pressure_severity(issue: &ComputePressureIssue) -> f64 {
    match issue {
        ComputePressureIssue::StateExfiltration => 6.5,
        ComputePressureIssue::CpuFingerprinting => 6.0,
        ComputePressureIssue::CrossOriginLeak => 5.5,
        ComputePressureIssue::ContinuousObserving => 5.0,
        ComputePressureIssue::ApiDetected => 3.0,
    }
}

pub fn compute_pressure_to_operations(
    issues: &[ComputePressureIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                compute_pressure_severity(issue),
                0.6,
            )
        })
        .collect()
}
