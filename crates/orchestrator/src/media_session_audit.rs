use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum MediaSessionIssue {
    ApiDetected,
    MetadataSpoofing,
    ActionHijacking,
    ExternalArtwork,
    SilentPlayback,
    PositionTracking,
}

impl std::fmt::Display for MediaSessionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::MetadataSpoofing => write!(f, "metadata_spoofing"),
            Self::ActionHijacking => write!(f, "action_hijacking"),
            Self::ExternalArtwork => write!(f, "external_artwork"),
            Self::SilentPlayback => write!(f, "silent_playback"),
            Self::PositionTracking => write!(f, "position_tracking"),
        }
    }
}

pub fn audit_media_session(target: &str) -> Vec<MediaSessionIssue> {
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
    analyze_media_session(&body)
}

pub fn analyze_media_session(body: &str) -> Vec<MediaSessionIssue> {
    if !body.contains("navigator.mediaSession") && !body.contains("MediaSession") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(MediaSessionIssue::ApiDetected);

    if body.contains("MediaMetadata") || body.contains("metadata =") {
        issues.push(MediaSessionIssue::MetadataSpoofing);
    }

    if body.contains("setActionHandler") {
        issues.push(MediaSessionIssue::ActionHijacking);
    }

    if body.contains("artwork") && (body.contains("http://") || body.contains("https://")) {
        issues.push(MediaSessionIssue::ExternalArtwork);
    }

    if body.contains("Audio(") && body.contains("volume") && body.contains("0") {
        issues.push(MediaSessionIssue::SilentPlayback);
    }

    if body.contains("setPositionState") {
        issues.push(MediaSessionIssue::PositionTracking);
    }

    issues
}

pub fn media_session_severity(issue: &MediaSessionIssue) -> f64 {
    match issue {
        MediaSessionIssue::ActionHijacking => 6.5,
        MediaSessionIssue::MetadataSpoofing => 6.0,
        MediaSessionIssue::SilentPlayback => 5.5,
        MediaSessionIssue::ExternalArtwork => 4.5,
        MediaSessionIssue::PositionTracking => 4.0,
        MediaSessionIssue::ApiDetected => 2.0,
    }
}

pub fn media_session_to_operations(
    issues: &[MediaSessionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                media_session_severity(issue),
                0.5,
            )
        })
        .collect()
}
