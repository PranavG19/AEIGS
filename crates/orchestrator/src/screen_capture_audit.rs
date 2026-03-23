use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ScreenCaptureIssue {
    GetDisplayMedia,
    ScreenCaptureRecording,
    CaptureDataExfiltration,
    CaptureWithoutUi,
    CaptureStreamToCanvas,
    PreferCurrentTab,
}

impl std::fmt::Display for ScreenCaptureIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GetDisplayMedia => write!(f, "get_display_media"),
            Self::ScreenCaptureRecording => write!(f, "screen_capture_recording"),
            Self::CaptureDataExfiltration => write!(f, "capture_data_exfiltration"),
            Self::CaptureWithoutUi => write!(f, "capture_without_ui"),
            Self::CaptureStreamToCanvas => write!(f, "capture_stream_to_canvas"),
            Self::PreferCurrentTab => write!(f, "prefer_current_tab"),
        }
    }
}

pub fn audit_screen_capture(target: &str) -> Vec<ScreenCaptureIssue> {
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
    analyze_screen_capture(&body)
}

pub fn analyze_screen_capture(body: &str) -> Vec<ScreenCaptureIssue> {
    if !body.contains("getDisplayMedia") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    issues.push(ScreenCaptureIssue::GetDisplayMedia);

    if body.contains("MediaRecorder") {
        issues.push(ScreenCaptureIssue::ScreenCaptureRecording);
    }

    if body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains(".send(")
        || body.contains("sendBeacon")
    {
        issues.push(ScreenCaptureIssue::CaptureDataExfiltration);
    }

    if body.contains("display: none")
        || body.contains("visibility: hidden")
        || body.contains("opacity: 0")
        || body.contains("offscreen")
    {
        issues.push(ScreenCaptureIssue::CaptureWithoutUi);
    }

    if body.contains("captureStream") || body.contains("drawImage") {
        issues.push(ScreenCaptureIssue::CaptureStreamToCanvas);
    }

    if body.contains("preferCurrentTab") {
        issues.push(ScreenCaptureIssue::PreferCurrentTab);
    }

    issues
}

pub fn screen_capture_severity(issue: &ScreenCaptureIssue) -> f64 {
    match issue {
        ScreenCaptureIssue::CaptureDataExfiltration => 8.0,
        ScreenCaptureIssue::ScreenCaptureRecording => 7.5,
        ScreenCaptureIssue::CaptureWithoutUi => 7.0,
        ScreenCaptureIssue::CaptureStreamToCanvas => 6.5,
        ScreenCaptureIssue::PreferCurrentTab => 5.5,
        ScreenCaptureIssue::GetDisplayMedia => 5.0,
    }
}

pub fn screen_capture_to_operations(
    issues: &[ScreenCaptureIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                screen_capture_severity(issue),
                0.7,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScreenCaptureSecurityIssue {
    CaptureWithoutPermissionPolicy,
    SilentRecording,
    ScreenshotExfiltration,
    MultiMonitorCapture,
    AudioCaptureCombined,
    ContinuousCapture,
    WorkerBasedCapture,
    CaptureToStorage,
    CrossOriginCaptureShare,
    CaptureWithoutUserGesture,
}

impl std::fmt::Display for ScreenCaptureSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CaptureWithoutPermissionPolicy => write!(f, "capture_without_permission_policy"),
            Self::SilentRecording => write!(f, "silent_recording"),
            Self::ScreenshotExfiltration => write!(f, "screenshot_exfiltration"),
            Self::MultiMonitorCapture => write!(f, "multi_monitor_capture"),
            Self::AudioCaptureCombined => write!(f, "audio_capture_combined"),
            Self::ContinuousCapture => write!(f, "continuous_capture"),
            Self::WorkerBasedCapture => write!(f, "worker_based_capture"),
            Self::CaptureToStorage => write!(f, "capture_to_storage"),
            Self::CrossOriginCaptureShare => write!(f, "cross_origin_capture_share"),
            Self::CaptureWithoutUserGesture => write!(f, "capture_without_user_gesture"),
        }
    }
}

pub fn analyze_screen_capture_security(body: &str) -> Vec<ScreenCaptureSecurityIssue> {
    if !body.contains("getDisplayMedia") && !body.contains("getScreenDetails") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    // CaptureWithoutPermissionPolicy: getDisplayMedia without Permissions-Policy header
    if body.contains("getDisplayMedia")
        && !body.contains("Permissions-Policy")
        && !body.contains("permissions-policy")
    {
        issues.push(ScreenCaptureSecurityIssue::CaptureWithoutPermissionPolicy);
    }

    // SilentRecording: MediaRecorder without visible indicator
    if body.contains("MediaRecorder")
        && !body.contains("recording-indicator")
        && !body.contains("rec-icon")
        && !body.contains("recording-badge")
    {
        issues.push(ScreenCaptureSecurityIssue::SilentRecording);
    }

    // ScreenshotExfiltration: canvas/toBlob/toDataURL with network send
    if (body.contains("toBlob") || body.contains("toDataURL") || body.contains("canvas"))
        && (body.contains("fetch(")
            || body.contains("XMLHttpRequest")
            || body.contains(".send(")
            || body.contains("sendBeacon"))
    {
        issues.push(ScreenCaptureSecurityIssue::ScreenshotExfiltration);
    }

    // MultiMonitorCapture: getScreenDetails for multi-monitor enumeration
    if body.contains("getScreenDetails") {
        issues.push(ScreenCaptureSecurityIssue::MultiMonitorCapture);
    }

    // AudioCaptureCombined: audio capture with screen share
    if body.contains("getDisplayMedia")
        && (body.contains("audio: true") || body.contains("audio:true"))
    {
        issues.push(ScreenCaptureSecurityIssue::AudioCaptureCombined);
    }

    // ContinuousCapture: capture kept active in loop/interval
    if body.contains("getDisplayMedia")
        && (body.contains("setInterval")
            || body.contains("while")
            || body.contains("for(")
            || body.contains("for ("))
    {
        issues.push(ScreenCaptureSecurityIssue::ContinuousCapture);
    }

    // WorkerBasedCapture: screen capture in Worker context
    if (body.contains("getDisplayMedia") || body.contains("getScreenDetails"))
        && (body.contains("Worker") || body.contains("postMessage"))
    {
        issues.push(ScreenCaptureSecurityIssue::WorkerBasedCapture);
    }

    // CaptureToStorage: captured data stored locally
    if (body.contains("getDisplayMedia") || body.contains("toBlob") || body.contains("toDataURL"))
        && (body.contains("localStorage")
            || body.contains("sessionStorage")
            || body.contains("indexedDB")
            || body.contains("IndexedDB"))
    {
        issues.push(ScreenCaptureSecurityIssue::CaptureToStorage);
    }

    // CrossOriginCaptureShare: capture data shared via postMessage
    if (body.contains("getDisplayMedia") || body.contains("toBlob") || body.contains("toDataURL"))
        && body.contains("postMessage")
    {
        issues.push(ScreenCaptureSecurityIssue::CrossOriginCaptureShare);
    }

    // CaptureWithoutUserGesture: getDisplayMedia not in click/touch handler
    if body.contains("getDisplayMedia")
        && !body.contains("addEventListener")
        && !body.contains("onclick")
        && !body.contains("ontouchstart")
        && !body.contains("onClick")
    {
        issues.push(ScreenCaptureSecurityIssue::CaptureWithoutUserGesture);
    }

    issues
}

pub fn screen_capture_security_severity(issue: &ScreenCaptureSecurityIssue) -> f64 {
    match issue {
        ScreenCaptureSecurityIssue::ScreenshotExfiltration => 9.0,
        ScreenCaptureSecurityIssue::SilentRecording => 8.5,
        ScreenCaptureSecurityIssue::MultiMonitorCapture => 8.0,
        ScreenCaptureSecurityIssue::CrossOriginCaptureShare => 7.5,
        ScreenCaptureSecurityIssue::CaptureToStorage => 7.0,
        ScreenCaptureSecurityIssue::AudioCaptureCombined => 6.5,
        ScreenCaptureSecurityIssue::WorkerBasedCapture => 6.0,
        ScreenCaptureSecurityIssue::ContinuousCapture => 5.5,
        ScreenCaptureSecurityIssue::CaptureWithoutUserGesture => 5.0,
        ScreenCaptureSecurityIssue::CaptureWithoutPermissionPolicy => 4.5,
    }
}

pub fn screen_capture_security_to_operations(
    issues: &[ScreenCaptureSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                screen_capture_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
