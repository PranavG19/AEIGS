use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebCodecsIssue {
    ApiDetected,
    VideoCapture,
    AudioCapture,
    RawFrameAccess,
    DataExfiltration,
    ContinuousEncoding,
}

impl std::fmt::Display for WebCodecsIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::VideoCapture => write!(f, "video_capture"),
            Self::AudioCapture => write!(f, "audio_capture"),
            Self::RawFrameAccess => write!(f, "raw_frame_access"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::ContinuousEncoding => write!(f, "continuous_encoding"),
        }
    }
}

pub fn audit_web_codecs(target: &str) -> Vec<WebCodecsIssue> {
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
    analyze_web_codecs(&body)
}

pub fn analyze_web_codecs(body: &str) -> Vec<WebCodecsIssue> {
    let has_video = body.contains("VideoEncoder") || body.contains("VideoDecoder");
    let has_audio = body.contains("AudioEncoder") || body.contains("AudioDecoder");
    let has_frame = body.contains("VideoFrame") || body.contains("AudioData");

    if !has_video && !has_audio && !has_frame {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebCodecsIssue::ApiDetected);

    if has_video && body.contains("getUserMedia") {
        issues.push(WebCodecsIssue::VideoCapture);
    }

    if has_audio && body.contains("getUserMedia") {
        issues.push(WebCodecsIssue::AudioCapture);
    }

    if has_frame
        && (body.contains("copyTo")
            || body.contains("createImageBitmap")
            || body.contains("clone()"))
    {
        issues.push(WebCodecsIssue::RawFrameAccess);
    }

    if (has_video || has_audio)
        && (body.contains("fetch(") || body.contains("sendBeacon") || body.contains("WebSocket"))
    {
        issues.push(WebCodecsIssue::DataExfiltration);
    }

    if body.contains("requestAnimationFrame")
        || body.contains("setInterval")
        || body.contains("while(")
        || body.contains("while ")
    {
        issues.push(WebCodecsIssue::ContinuousEncoding);
    }

    issues
}

pub fn web_codecs_severity(issue: &WebCodecsIssue) -> f64 {
    match issue {
        WebCodecsIssue::DataExfiltration => 7.5,
        WebCodecsIssue::VideoCapture => 7.0,
        WebCodecsIssue::AudioCapture => 7.0,
        WebCodecsIssue::RawFrameAccess => 6.0,
        WebCodecsIssue::ContinuousEncoding => 5.0,
        WebCodecsIssue::ApiDetected => 2.5,
    }
}

pub fn web_codecs_to_operations(
    issues: &[WebCodecsIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                web_codecs_severity(issue),
                0.6,
            )
        })
        .collect()
}
