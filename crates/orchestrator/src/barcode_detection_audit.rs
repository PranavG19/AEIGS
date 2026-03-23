use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum BarcodeDetectionIssue {
    ApiDetected,
    CameraAccess,
    DataExfiltration,
    ContinuousScanning,
    NoUserActivation,
}

impl std::fmt::Display for BarcodeDetectionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::CameraAccess => write!(f, "camera_access"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::ContinuousScanning => write!(f, "continuous_scanning"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
        }
    }
}

pub fn audit_barcode_detection(target: &str) -> Vec<BarcodeDetectionIssue> {
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
    analyze_barcode_detection(&body)
}

pub fn analyze_barcode_detection(body: &str) -> Vec<BarcodeDetectionIssue> {
    if !body.contains("BarcodeDetector") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(BarcodeDetectionIssue::ApiDetected);

    if body.contains("getUserMedia") || body.contains("getDisplayMedia") {
        issues.push(BarcodeDetectionIssue::CameraAccess);
    }

    if body.contains(".detect(")
        && (body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest"))
    {
        issues.push(BarcodeDetectionIssue::DataExfiltration);
    }

    if body.contains("setInterval") || body.contains("requestAnimationFrame") || body.contains("while(") || body.contains("while ") {
        issues.push(BarcodeDetectionIssue::ContinuousScanning);
    }

    if !body.contains("click") && !body.contains("pointerdown") && !body.contains("submit") {
        issues.push(BarcodeDetectionIssue::NoUserActivation);
    }

    issues
}

pub fn barcode_detection_severity(issue: &BarcodeDetectionIssue) -> f64 {
    match issue {
        BarcodeDetectionIssue::DataExfiltration => 7.0,
        BarcodeDetectionIssue::CameraAccess => 6.5,
        BarcodeDetectionIssue::ContinuousScanning => 5.5,
        BarcodeDetectionIssue::NoUserActivation => 4.5,
        BarcodeDetectionIssue::ApiDetected => 2.5,
    }
}

pub fn barcode_detection_to_operations(
    issues: &[BarcodeDetectionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                barcode_detection_severity(issue),
                0.6,
            )
        })
        .collect()
}
