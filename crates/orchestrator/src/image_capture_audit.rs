use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ImageCaptureIssue {
    ApiDetected,
    SilentCapture,
    DataExfiltration,
    ContinuousCapture,
    MetadataLeak,
}

impl std::fmt::Display for ImageCaptureIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::SilentCapture => write!(f, "silent_capture"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::ContinuousCapture => write!(f, "continuous_capture"),
            Self::MetadataLeak => write!(f, "metadata_leak"),
        }
    }
}

pub fn audit_image_capture(target: &str) -> Vec<ImageCaptureIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_image_capture(&body)
}

pub fn analyze_image_capture(body: &str) -> Vec<ImageCaptureIssue> {
    let has_api = body.contains("ImageCapture")
        || body.contains("imageCapture")
        || body.contains("takePhoto")
        || body.contains("grabFrame");

    if !has_api {
        return Vec::new();
    }

    let mut issues = Vec::new();

    issues.push(ImageCaptureIssue::ApiDetected);

    let has_capture = body.contains("takePhoto") || body.contains("grabFrame");

    if has_capture
        && !body.contains("notification")
        && !body.contains("indicator")
        && !body.contains("alert(")
    {
        issues.push(ImageCaptureIssue::SilentCapture);
    }

    if has_capture
        && (body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("WebSocket")
            || body.contains("XMLHttpRequest"))
    {
        issues.push(ImageCaptureIssue::DataExfiltration);
    }

    if (body.contains("setInterval") || body.contains("requestAnimationFrame")) && has_capture {
        issues.push(ImageCaptureIssue::ContinuousCapture);
    }

    if (body.contains("getPhotoCapabilities") || body.contains("getPhotoSettings"))
        && (body.contains("fetch(") || body.contains("sendBeacon"))
    {
        issues.push(ImageCaptureIssue::MetadataLeak);
    }

    issues
}

pub fn image_capture_severity(issue: &ImageCaptureIssue) -> f64 {
    match issue {
        ImageCaptureIssue::SilentCapture => 8.0,
        ImageCaptureIssue::DataExfiltration => 7.5,
        ImageCaptureIssue::ContinuousCapture => 6.5,
        ImageCaptureIssue::MetadataLeak => 5.5,
        ImageCaptureIssue::ApiDetected => 2.0,
    }
}

pub fn image_capture_to_operations(
    issues: &[ImageCaptureIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                image_capture_severity(issue),
                0.55,
            )
        })
        .collect()
}
