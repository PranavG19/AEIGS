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

#[derive(Debug, Clone, PartialEq)]
pub enum InkApiSecurityIssue {
    InkFingerprinting,
    InkDataExfiltration,
    InkWithoutPermission,
    InkInIframe,
    InkSignatureCapture,
    InkPressureTracking,
    InkCrossOriginSharing,
    InkPersistentStorage,
    InkTimingAttack,
    InkWithCanvas,
}

impl std::fmt::Display for InkApiSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InkFingerprinting => write!(f, "ink_fingerprinting"),
            Self::InkDataExfiltration => write!(f, "ink_data_exfiltration"),
            Self::InkWithoutPermission => write!(f, "ink_without_permission"),
            Self::InkInIframe => write!(f, "ink_in_iframe"),
            Self::InkSignatureCapture => write!(f, "ink_signature_capture"),
            Self::InkPressureTracking => write!(f, "ink_pressure_tracking"),
            Self::InkCrossOriginSharing => write!(f, "ink_cross_origin_sharing"),
            Self::InkPersistentStorage => write!(f, "ink_persistent_storage"),
            Self::InkTimingAttack => write!(f, "ink_timing_attack"),
            Self::InkWithCanvas => write!(f, "ink_with_canvas"),
        }
    }
}

pub fn analyze_ink_api_security(body: &str) -> Vec<InkApiSecurityIssue> {
    if !body.contains("navigator.ink") && !body.contains("InkPresenter") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    // InkFingerprinting - using ink rendering for device fingerprinting
    if (body.contains("navigator.ink") || body.contains("InkPresenter"))
        && (body.contains("devicePixelRatio")
            || body.contains("screen.width")
            || body.contains("screen.height")
            || body.contains("hardwareConcurrency"))
    {
        issues.push(InkApiSecurityIssue::InkFingerprinting);
    }

    // InkDataExfiltration - capturing pen stroke data and sending externally
    if (body.contains("getCoalescedEvents") || body.contains("getPredictedEvents"))
        && (body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("XMLHttpRequest")
            || body.contains("WebSocket"))
    {
        issues.push(InkApiSecurityIssue::InkDataExfiltration);
    }

    // InkWithoutPermission - using ink API without proper permission checks
    if (body.contains("navigator.ink") || body.contains("InkPresenter"))
        && !body.contains("permissions.query")
        && !body.contains("navigator.permissions")
    {
        issues.push(InkApiSecurityIssue::InkWithoutPermission);
    }

    // InkInIframe - accessing ink API from cross-origin iframe
    if (body.contains("navigator.ink") || body.contains("InkPresenter"))
        && (body.contains("iframe") || body.contains("postMessage") || body.contains("parent."))
    {
        issues.push(InkApiSecurityIssue::InkInIframe);
    }

    // InkSignatureCapture - capturing handwriting/signature data
    if (body.contains("navigator.ink") || body.contains("InkPresenter"))
        && (body.contains("signature")
            || body.contains("sign here")
            || body.contains("handwriting")
            || body.contains("autograph"))
    {
        issues.push(InkApiSecurityIssue::InkSignatureCapture);
    }

    // InkPressureTracking - using pressure data for biometric profiling
    if body.contains("pressure") || body.contains("force") || body.contains("tangentialPressure") {
        issues.push(InkApiSecurityIssue::InkPressureTracking);
    }

    // InkCrossOriginSharing - sharing ink data across origins
    if (body.contains("navigator.ink") || body.contains("InkPresenter"))
        && (body.contains("postMessage")
            || body.contains("BroadcastChannel")
            || body.contains("SharedWorker"))
    {
        issues.push(InkApiSecurityIssue::InkCrossOriginSharing);
    }

    // InkPersistentStorage - storing ink strokes persistently
    if (body.contains("navigator.ink") || body.contains("InkPresenter"))
        && (body.contains("localStorage")
            || body.contains("sessionStorage")
            || body.contains("indexedDB")
            || body.contains("openDatabase"))
    {
        issues.push(InkApiSecurityIssue::InkPersistentStorage);
    }

    // InkTimingAttack - using ink timing data for side-channel attacks
    if (body.contains("navigator.ink") || body.contains("InkPresenter"))
        && (body.contains("performance.now")
            || body.contains("Date.now")
            || body.contains("timestamp")
            || body.contains("timeOrigin"))
    {
        issues.push(InkApiSecurityIssue::InkTimingAttack);
    }

    // InkWithCanvas - combining ink with canvas for data capture
    if (body.contains("navigator.ink") || body.contains("InkPresenter"))
        && body.contains("canvas")
        && (body.contains("getContext") || body.contains("OffscreenCanvas"))
    {
        issues.push(InkApiSecurityIssue::InkWithCanvas);
    }

    issues
}

pub fn ink_api_security_severity(issue: &InkApiSecurityIssue) -> f64 {
    match issue {
        InkApiSecurityIssue::InkDataExfiltration => 7.5,
        InkApiSecurityIssue::InkSignatureCapture => 7.0,
        InkApiSecurityIssue::InkFingerprinting => 6.5,
        InkApiSecurityIssue::InkPressureTracking => 6.0,
        InkApiSecurityIssue::InkCrossOriginSharing => 5.5,
        InkApiSecurityIssue::InkInIframe => 5.0,
        InkApiSecurityIssue::InkPersistentStorage => 4.5,
        InkApiSecurityIssue::InkTimingAttack => 4.0,
        InkApiSecurityIssue::InkWithCanvas => 3.5,
        InkApiSecurityIssue::InkWithoutPermission => 3.0,
    }
}

pub fn ink_api_security_to_operations(
    issues: &[InkApiSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                ink_api_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
