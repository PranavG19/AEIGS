use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum MediaRecorderIssue {
    ApiDetected,
    SurveillanceRisk,
    SilentRecording,
    DataExfiltration,
    UnboundedRecording,
}

impl std::fmt::Display for MediaRecorderIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::SurveillanceRisk => write!(f, "surveillance_risk"),
            Self::SilentRecording => write!(f, "silent_recording"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::UnboundedRecording => write!(f, "unbounded_recording"),
        }
    }
}

pub fn audit_media_recorder(target: &str) -> Vec<MediaRecorderIssue> {
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
    analyze_media_recorder(&body)
}

pub fn analyze_media_recorder(body: &str) -> Vec<MediaRecorderIssue> {
    let has_recorder = body.contains("MediaRecorder") || body.contains("mediaRecorder");

    if !has_recorder {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(MediaRecorderIssue::ApiDetected);

    if (body.contains("getUserMedia") || body.contains("getDisplayMedia"))
        && (body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("WebSocket")
            || body.contains("XMLHttpRequest"))
    {
        issues.push(MediaRecorderIssue::SurveillanceRisk);
    }

    if body.contains("start(")
        && !body.contains("notification")
        && !body.contains("indicator")
        && !body.contains("alert(")
    {
        issues.push(MediaRecorderIssue::SilentRecording);
    }

    if body.contains("ondataavailable")
        && (body.contains("upload")
            || body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("WebSocket"))
    {
        issues.push(MediaRecorderIssue::DataExfiltration);
    }

    if body.contains("start(")
        && !body.contains("stop(")
        && !body.contains("timeslice")
        && !body.contains("setTimeout")
    {
        issues.push(MediaRecorderIssue::UnboundedRecording);
    }

    issues
}

pub fn media_recorder_severity(issue: &MediaRecorderIssue) -> f64 {
    match issue {
        MediaRecorderIssue::SurveillanceRisk => 8.0,
        MediaRecorderIssue::SilentRecording => 7.5,
        MediaRecorderIssue::DataExfiltration => 7.0,
        MediaRecorderIssue::UnboundedRecording => 5.5,
        MediaRecorderIssue::ApiDetected => 2.0,
    }
}

pub fn media_recorder_to_operations(
    issues: &[MediaRecorderIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                media_recorder_severity(issue),
                0.55,
            )
        })
        .collect()
}
