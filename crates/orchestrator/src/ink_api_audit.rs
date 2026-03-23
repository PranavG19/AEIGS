use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum InkApiIssue {
    ApiDetected,
    InputTracking,
    DataExfiltration,
    ContinuousCapture,
    CanvasFingerprinting,
}

impl std::fmt::Display for InkApiIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::InputTracking => write!(f, "input_tracking"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::ContinuousCapture => write!(f, "continuous_capture"),
            Self::CanvasFingerprinting => write!(f, "canvas_fingerprinting"),
        }
    }
}

pub fn audit_ink_api(target: &str) -> Vec<InkApiIssue> {
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
    analyze_ink_api(&body)
}

pub fn analyze_ink_api(body: &str) -> Vec<InkApiIssue> {
    if !body.contains("navigator.ink") && !body.contains("InkPresenter") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(InkApiIssue::ApiDetected);

    if body.contains("pointermove")
        || body.contains("pointerdown")
        || body.contains("pointerrawupdate")
    {
        issues.push(InkApiIssue::InputTracking);
    }

    if (body.contains("navigator.ink") || body.contains("InkPresenter"))
        && (body.contains("fetch(") || body.contains("sendBeacon") || body.contains("WebSocket"))
    {
        issues.push(InkApiIssue::DataExfiltration);
    }

    if body.contains("requestAnimationFrame") || body.contains("setInterval") {
        issues.push(InkApiIssue::ContinuousCapture);
    }

    if body.contains("canvas")
        && (body.contains("toDataURL") || body.contains("getImageData") || body.contains("toBlob"))
    {
        issues.push(InkApiIssue::CanvasFingerprinting);
    }

    issues
}

pub fn ink_api_severity(issue: &InkApiIssue) -> f64 {
    match issue {
        InkApiIssue::DataExfiltration => 6.5,
        InkApiIssue::CanvasFingerprinting => 6.0,
        InkApiIssue::InputTracking => 5.5,
        InkApiIssue::ContinuousCapture => 5.0,
        InkApiIssue::ApiDetected => 2.0,
    }
}

pub fn ink_api_to_operations(issues: &[InkApiIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                ink_api_severity(issue),
                0.5,
            )
        })
        .collect()
}
