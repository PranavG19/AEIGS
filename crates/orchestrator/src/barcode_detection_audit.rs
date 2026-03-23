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
    BarcodeFingerprinting,
    BarcodeCrossOriginSharing,
    BarcodeInWorker,
    BarcodeWithStorage,
    BarcodeQrCodeInjection,
    BarcodePaymentDataCapture,
    BarcodeLocationTracking,
    BarcodeWithoutPermission,
    BarcodeSilentCapture,
    BarcodeMultiFormatScan,
}

impl std::fmt::Display for BarcodeDetectionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::CameraAccess => write!(f, "camera_access"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::ContinuousScanning => write!(f, "continuous_scanning"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::BarcodeFingerprinting => write!(f, "barcode_fingerprinting"),
            Self::BarcodeCrossOriginSharing => write!(f, "barcode_cross_origin_sharing"),
            Self::BarcodeInWorker => write!(f, "barcode_in_worker"),
            Self::BarcodeWithStorage => write!(f, "barcode_with_storage"),
            Self::BarcodeQrCodeInjection => write!(f, "barcode_qr_code_injection"),
            Self::BarcodePaymentDataCapture => write!(f, "barcode_payment_data_capture"),
            Self::BarcodeLocationTracking => write!(f, "barcode_location_tracking"),
            Self::BarcodeWithoutPermission => write!(f, "barcode_without_permission"),
            Self::BarcodeSilentCapture => write!(f, "barcode_silent_capture"),
            Self::BarcodeMultiFormatScan => write!(f, "barcode_multi_format_scan"),
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
        && (body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("XMLHttpRequest"))
    {
        issues.push(BarcodeDetectionIssue::DataExfiltration);
    }

    if body.contains("setInterval")
        || body.contains("requestAnimationFrame")
        || body.contains("while(")
        || body.contains("while ")
    {
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
        BarcodeDetectionIssue::BarcodePaymentDataCapture => 9.0,
        BarcodeDetectionIssue::BarcodeSilentCapture => 8.5,
        BarcodeDetectionIssue::BarcodeQrCodeInjection => 8.0,
        BarcodeDetectionIssue::BarcodeLocationTracking => 7.5,
        BarcodeDetectionIssue::BarcodeCrossOriginSharing => 7.0,
        BarcodeDetectionIssue::BarcodeInWorker => 6.0,
        BarcodeDetectionIssue::BarcodeFingerprinting => 5.5,
        BarcodeDetectionIssue::BarcodeWithStorage => 5.5,
        BarcodeDetectionIssue::BarcodeMultiFormatScan => 4.5,
        BarcodeDetectionIssue::BarcodeWithoutPermission => 4.0,
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

pub fn analyze_barcode_security(body: &str) -> Vec<BarcodeDetectionIssue> {
    if !body.contains("BarcodeDetector") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if (body.contains("getSupportedFormats") || body.contains("formats"))
        && body.contains("fingerprint")
    {
        issues.push(BarcodeDetectionIssue::BarcodeFingerprinting);
    }

    if body.contains("postMessage") || body.contains("cross-origin") || body.contains("iframe") {
        issues.push(BarcodeDetectionIssue::BarcodeCrossOriginSharing);
    }

    if body.contains("Worker") || body.contains("SharedWorker") {
        issues.push(BarcodeDetectionIssue::BarcodeInWorker);
    }

    if body.contains("localStorage")
        || body.contains("sessionStorage")
        || body.contains("indexedDB")
    {
        issues.push(BarcodeDetectionIssue::BarcodeWithStorage);
    }

    let has_qr = body.contains("qr_code") || body.contains("qr-code") || body.contains("QR");
    let has_url_risk = body.contains("url")
        || body.contains("javascript:")
        || body.contains("eval")
        || body.contains("location");
    if has_qr && has_url_risk {
        issues.push(BarcodeDetectionIssue::BarcodeQrCodeInjection);
    }

    if body.contains("payment")
        || body.contains("credit")
        || body.contains("card")
        || body.contains("CVV")
        || body.contains("account")
    {
        issues.push(BarcodeDetectionIssue::BarcodePaymentDataCapture);
    }

    if body.contains("geolocation")
        || body.contains("getCurrentPosition")
        || body.contains("location")
    {
        issues.push(BarcodeDetectionIssue::BarcodeLocationTracking);
    }

    if !body.contains("permissions") && !body.contains("navigator.permissions") {
        issues.push(BarcodeDetectionIssue::BarcodeWithoutPermission);
    }

    let has_display_none = body.contains("display:none")
        || body.contains("display: none")
        || body.contains("display:'none'")
        || body.contains("display: 'none'")
        || body.contains("display = 'none'");
    let has_visibility_hidden = body.contains("visibility:hidden")
        || body.contains("visibility: hidden")
        || body.contains("visibility:'hidden'")
        || body.contains("visibility: 'hidden'")
        || body.contains("visibility = 'hidden'");
    let has_opacity_zero = body.contains("opacity:0")
        || body.contains("opacity: 0")
        || body.contains("opacity:'0'")
        || body.contains("opacity: '0'")
        || body.contains("opacity = '0'");
    if has_display_none || has_visibility_hidden || has_opacity_zero {
        issues.push(BarcodeDetectionIssue::BarcodeSilentCapture);
    }

    let format_patterns = [
        "qr_code",
        "ean_13",
        "code_128",
        "data_matrix",
        "aztec",
        "pdf417",
        "upc_a",
    ];
    let format_count = format_patterns
        .iter()
        .filter(|pattern| body.contains(*pattern))
        .count();
    if format_count >= 3 {
        issues.push(BarcodeDetectionIssue::BarcodeMultiFormatScan);
    }

    issues
}

pub fn barcode_security_to_operations(
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
