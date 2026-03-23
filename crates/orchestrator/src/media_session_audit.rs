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

#[derive(Debug, Clone, PartialEq)]
pub enum MediaSessionSecurityIssue {
    MediaSessionHijack,
    MediaSessionExfiltration,
    MediaSessionFingerprinting,
    MediaSessionCrossOrigin,
    MediaSessionPersistence,
    MediaSessionInBackground,
    MediaSessionFakeMetadata,
    MediaSessionPositionTracking,
    MediaSessionWithoutUserAction,
    MediaSessionNotificationAbuse,
}

impl std::fmt::Display for MediaSessionSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MediaSessionHijack => write!(f, "media_session_hijack"),
            Self::MediaSessionExfiltration => write!(f, "media_session_exfiltration"),
            Self::MediaSessionFingerprinting => write!(f, "media_session_fingerprinting"),
            Self::MediaSessionCrossOrigin => write!(f, "media_session_cross_origin"),
            Self::MediaSessionPersistence => write!(f, "media_session_persistence"),
            Self::MediaSessionInBackground => write!(f, "media_session_in_background"),
            Self::MediaSessionFakeMetadata => write!(f, "media_session_fake_metadata"),
            Self::MediaSessionPositionTracking => write!(f, "media_session_position_tracking"),
            Self::MediaSessionWithoutUserAction => {
                write!(f, "media_session_without_user_action")
            }
            Self::MediaSessionNotificationAbuse => write!(f, "media_session_notification_abuse"),
        }
    }
}

pub fn analyze_media_session_security(body: &str) -> Vec<MediaSessionSecurityIssue> {
    if !body.contains("navigator.mediaSession") && !body.contains("MediaSession") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("setActionHandler") && body.contains("window.location") {
        issues.push(MediaSessionSecurityIssue::MediaSessionHijack);
    }

    if (body.contains("fetch(") || body.contains("XMLHttpRequest"))
        && (body.contains("mediaSession.metadata") || body.contains("playbackState"))
    {
        issues.push(MediaSessionSecurityIssue::MediaSessionExfiltration);
    }

    if (body.contains("mediaSession") || body.contains("playbackState"))
        && (body.contains("fingerprint") || body.contains("canvas") || body.contains("deviceId"))
    {
        issues.push(MediaSessionSecurityIssue::MediaSessionFingerprinting);
    }

    if body.contains("postMessage") && body.contains("mediaSession") {
        issues.push(MediaSessionSecurityIssue::MediaSessionCrossOrigin);
    }

    if (body.contains("localStorage")
        || body.contains("sessionStorage")
        || body.contains("indexedDB"))
        && body.contains("mediaSession")
    {
        issues.push(MediaSessionSecurityIssue::MediaSessionPersistence);
    }

    if body.contains("document.hidden") && body.contains("mediaSession") {
        issues.push(MediaSessionSecurityIssue::MediaSessionInBackground);
    }

    if body.contains("MediaMetadata")
        && (body.contains("Bank") || body.contains("Alert") || body.contains("Security"))
    {
        issues.push(MediaSessionSecurityIssue::MediaSessionFakeMetadata);
    }

    if body.contains("setPositionState") && body.contains("setInterval") {
        issues.push(MediaSessionSecurityIssue::MediaSessionPositionTracking);
    }

    if body.contains("mediaSession")
        && !body.contains("addEventListener")
        && !body.contains("onclick")
        && !body.contains("click")
    {
        issues.push(MediaSessionSecurityIssue::MediaSessionWithoutUserAction);
    }

    if body.contains("Notification") && body.contains("mediaSession") {
        issues.push(MediaSessionSecurityIssue::MediaSessionNotificationAbuse);
    }

    issues
}

pub fn media_session_security_severity(issue: &MediaSessionSecurityIssue) -> f64 {
    match issue {
        MediaSessionSecurityIssue::MediaSessionHijack => 9.0,
        MediaSessionSecurityIssue::MediaSessionExfiltration => 8.5,
        MediaSessionSecurityIssue::MediaSessionNotificationAbuse => 7.5,
        MediaSessionSecurityIssue::MediaSessionFakeMetadata => 7.0,
        MediaSessionSecurityIssue::MediaSessionCrossOrigin => 6.5,
        MediaSessionSecurityIssue::MediaSessionFingerprinting => 6.0,
        MediaSessionSecurityIssue::MediaSessionPersistence => 5.5,
        MediaSessionSecurityIssue::MediaSessionPositionTracking => 5.0,
        MediaSessionSecurityIssue::MediaSessionInBackground => 4.5,
        MediaSessionSecurityIssue::MediaSessionWithoutUserAction => 3.0,
    }
}

pub fn media_session_security_to_operations(
    issues: &[MediaSessionSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                media_session_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
