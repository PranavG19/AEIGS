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

#[derive(Debug, Clone, PartialEq)]
pub enum ShapeDetectionSecurityIssue {
    FaceDetectionSurveillance,
    FaceDataExfiltration,
    FaceDetectionWithoutConsent,
    TextRecognitionPrivacy,
    FaceRecognitionFingerprinting,
    ShapeDetectionInIframe,
    FaceDataPersistence,
    ContinuousFaceDetection,
    FaceDetectionWithGeolocation,
    ShapeDetectionInWorker,
}

impl std::fmt::Display for ShapeDetectionSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FaceDetectionSurveillance => write!(f, "face_detection_surveillance"),
            Self::FaceDataExfiltration => write!(f, "face_data_exfiltration"),
            Self::FaceDetectionWithoutConsent => write!(f, "face_detection_without_consent"),
            Self::TextRecognitionPrivacy => write!(f, "text_recognition_privacy"),
            Self::FaceRecognitionFingerprinting => write!(f, "face_recognition_fingerprinting"),
            Self::ShapeDetectionInIframe => write!(f, "shape_detection_in_iframe"),
            Self::FaceDataPersistence => write!(f, "face_data_persistence"),
            Self::ContinuousFaceDetection => write!(f, "continuous_face_detection"),
            Self::FaceDetectionWithGeolocation => write!(f, "face_detection_with_geolocation"),
            Self::ShapeDetectionInWorker => write!(f, "shape_detection_in_worker"),
        }
    }
}

pub fn analyze_shape_detection_security(body: &str) -> Vec<ShapeDetectionSecurityIssue> {
    let mut issues = Vec::new();
    let body_lower = body.to_ascii_lowercase();

    let has_face_detector = body.contains("FaceDetector");
    let has_text_detector = body.contains("TextDetector");

    if !has_face_detector && !has_text_detector && !body.contains("BarcodeDetector") {
        return issues;
    }

    // FaceDetectionSurveillance - tracking with face detection
    if has_face_detector
        && (body_lower.contains("track")
            || body_lower.contains("monitor")
            || body_lower.contains("surveillance")
            || body_lower.contains("watchlist"))
    {
        issues.push(ShapeDetectionSecurityIssue::FaceDetectionSurveillance);
    }

    // FaceDataExfiltration - sending face data externally
    if has_face_detector
        && body.contains(".detect(")
        && (body.contains("fetch(")
            || body.contains("XMLHttpRequest")
            || body.contains("sendBeacon")
            || body.contains("WebSocket"))
    {
        issues.push(ShapeDetectionSecurityIssue::FaceDataExfiltration);
    }

    // FaceDetectionWithoutConsent - no permission/consent flow
    if has_face_detector
        && !(body_lower.contains("permission")
            || body_lower.contains("consent")
            || body_lower.contains("agree")
            || body_lower.contains("accept"))
    {
        issues.push(ShapeDetectionSecurityIssue::FaceDetectionWithoutConsent);
    }

    // TextRecognitionPrivacy - OCR on sensitive areas
    if has_text_detector
        && (body_lower.contains("password")
            || body_lower.contains("credit")
            || body_lower.contains("ssn")
            || body_lower.contains("sensitive")
            || body_lower.contains("private"))
    {
        issues.push(ShapeDetectionSecurityIssue::TextRecognitionPrivacy);
    }

    // FaceRecognitionFingerprinting - using face features for identity
    if has_face_detector
        && (body_lower.contains("fingerprint")
            || body_lower.contains("identity")
            || body_lower.contains("recognize")
            || body_lower.contains("match")
            || body_lower.contains("compare"))
    {
        issues.push(ShapeDetectionSecurityIssue::FaceRecognitionFingerprinting);
    }

    // ShapeDetectionInIframe - detection from cross-origin iframe
    if (has_face_detector || has_text_detector)
        && (body.contains("<iframe")
            || body.contains("contentWindow")
            || body.contains("postMessage")
            || body.contains("parent."))
    {
        issues.push(ShapeDetectionSecurityIssue::ShapeDetectionInIframe);
    }

    // FaceDataPersistence - storing face detection results
    if has_face_detector
        && (body.contains("localStorage")
            || body.contains("sessionStorage")
            || body.contains("indexedDB")
            || body.contains("openDatabase"))
    {
        issues.push(ShapeDetectionSecurityIssue::FaceDataPersistence);
    }

    // ContinuousFaceDetection - always-on face detection
    if has_face_detector
        && (body.contains("setInterval")
            || body.contains("requestAnimationFrame")
            || body.contains("while(")
            || body.contains("while "))
    {
        issues.push(ShapeDetectionSecurityIssue::ContinuousFaceDetection);
    }

    // FaceDetectionWithGeolocation - combining face data with location
    if has_face_detector
        && (body.contains("geolocation")
            || body.contains("getCurrentPosition")
            || body.contains("watchPosition")
            || body.contains("coords"))
    {
        issues.push(ShapeDetectionSecurityIssue::FaceDetectionWithGeolocation);
    }

    // ShapeDetectionInWorker - running detection in worker context
    if (has_face_detector || has_text_detector || body.contains("BarcodeDetector"))
        && (body.contains("new Worker")
            || body.contains("SharedWorker")
            || body.contains("ServiceWorker")
            || body.contains("worker.postMessage"))
    {
        issues.push(ShapeDetectionSecurityIssue::ShapeDetectionInWorker);
    }

    issues
}

pub fn shape_detection_security_severity(issue: &ShapeDetectionSecurityIssue) -> f64 {
    match issue {
        ShapeDetectionSecurityIssue::FaceDetectionSurveillance => 9.0,
        ShapeDetectionSecurityIssue::FaceDataExfiltration => 8.5,
        ShapeDetectionSecurityIssue::FaceRecognitionFingerprinting => 8.0,
        ShapeDetectionSecurityIssue::FaceDetectionWithoutConsent => 7.5,
        ShapeDetectionSecurityIssue::TextRecognitionPrivacy => 7.0,
        ShapeDetectionSecurityIssue::FaceDetectionWithGeolocation => 7.0,
        ShapeDetectionSecurityIssue::ContinuousFaceDetection => 6.5,
        ShapeDetectionSecurityIssue::FaceDataPersistence => 6.0,
        ShapeDetectionSecurityIssue::ShapeDetectionInIframe => 5.5,
        ShapeDetectionSecurityIssue::ShapeDetectionInWorker => 4.5,
    }
}

pub fn shape_detection_security_to_operations(
    issues: &[ShapeDetectionSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                shape_detection_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
