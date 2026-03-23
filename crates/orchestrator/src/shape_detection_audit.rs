use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ShapeDetectionIssue {
    ApiDetected,
    FaceDetection,
    TextOcr,
    CameraAccess,
    DataExfiltration,
    ContinuousDetection,
}

impl std::fmt::Display for ShapeDetectionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::FaceDetection => write!(f, "face_detection"),
            Self::TextOcr => write!(f, "text_ocr"),
            Self::CameraAccess => write!(f, "camera_access"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::ContinuousDetection => write!(f, "continuous_detection"),
        }
    }
}

pub fn audit_shape_detection(target: &str) -> Vec<ShapeDetectionIssue> {
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
    analyze_shape_detection(&body)
}

pub fn analyze_shape_detection(body: &str) -> Vec<ShapeDetectionIssue> {
    let has_face = body.contains("FaceDetector");
    let has_text = body.contains("TextDetector");
    let has_barcode = body.contains("BarcodeDetector");

    if !has_face && !has_text && !has_barcode {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(ShapeDetectionIssue::ApiDetected);

    if has_face {
        issues.push(ShapeDetectionIssue::FaceDetection);
    }

    if has_text {
        issues.push(ShapeDetectionIssue::TextOcr);
    }

    if body.contains("getUserMedia") || body.contains("getDisplayMedia") {
        issues.push(ShapeDetectionIssue::CameraAccess);
    }

    if body.contains(".detect(")
        && (body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("XMLHttpRequest"))
    {
        issues.push(ShapeDetectionIssue::DataExfiltration);
    }

    if body.contains("setInterval")
        || body.contains("requestAnimationFrame")
        || body.contains("while(")
        || body.contains("while ")
    {
        issues.push(ShapeDetectionIssue::ContinuousDetection);
    }

    issues
}

pub fn shape_detection_severity(issue: &ShapeDetectionIssue) -> f64 {
    match issue {
        ShapeDetectionIssue::FaceDetection => 7.5,
        ShapeDetectionIssue::DataExfiltration => 7.0,
        ShapeDetectionIssue::TextOcr => 6.5,
        ShapeDetectionIssue::CameraAccess => 6.0,
        ShapeDetectionIssue::ContinuousDetection => 5.0,
        ShapeDetectionIssue::ApiDetected => 2.5,
    }
}

pub fn shape_detection_to_operations(
    issues: &[ShapeDetectionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                shape_detection_severity(issue),
                0.6,
            )
        })
        .collect()
}
