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
