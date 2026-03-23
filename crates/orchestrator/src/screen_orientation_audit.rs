use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ScreenOrientationIssue {
    ApiDetected,
    OrientationLockAbuse,
    FingerprintingViaOrientation,
    PhishingFullscreen,
    ChangeEventTracking,
}

impl std::fmt::Display for ScreenOrientationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::OrientationLockAbuse => write!(f, "orientation_lock_abuse"),
            Self::FingerprintingViaOrientation => write!(f, "fingerprinting_via_orientation"),
            Self::PhishingFullscreen => write!(f, "phishing_fullscreen"),
            Self::ChangeEventTracking => write!(f, "change_event_tracking"),
        }
    }
}

pub fn audit_screen_orientation(target: &str) -> Vec<ScreenOrientationIssue> {
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
    analyze_screen_orientation(&body)
}

pub fn analyze_screen_orientation(body: &str) -> Vec<ScreenOrientationIssue> {
    let has_api = body.contains("screen.orientation")
        || body.contains("ScreenOrientation")
        || body.contains("orientation.lock");

    if !has_api {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(ScreenOrientationIssue::ApiDetected);

    let has_lock =
        body.contains("orientation.lock") || body.contains("screen.orientation.lock");
    if has_lock
        && (body.contains("fullscreen") || body.contains("requestFullscreen"))
    {
        issues.push(ScreenOrientationIssue::OrientationLockAbuse);
    }

    if (body.contains("screen.orientation") || body.contains("ScreenOrientation"))
        && (body.contains(".type") || body.contains(".angle"))
        && (body.contains("navigator.userAgent")
            || body.contains("screen.width")
            || body.contains("screen.height")
            || body.contains("devicePixelRatio"))
    {
        issues.push(ScreenOrientationIssue::FingerprintingViaOrientation);
    }

    if has_lock
        && (body.contains("requestFullscreen") || body.contains("webkitRequestFullscreen"))
        && (body.contains("innerHTML") || body.contains("document.write") || body.contains("location.href"))
    {
        issues.push(ScreenOrientationIssue::PhishingFullscreen);
    }

    if (body.contains("orientationchange") || body.contains("screen.orientation.addEventListener"))
        && (body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("XMLHttpRequest")
            || body.contains("navigator.sendBeacon"))
    {
        issues.push(ScreenOrientationIssue::ChangeEventTracking);
    }

    issues
}

pub fn screen_orientation_severity(issue: &ScreenOrientationIssue) -> f64 {
    match issue {
        ScreenOrientationIssue::PhishingFullscreen => 7.0,
        ScreenOrientationIssue::OrientationLockAbuse => 6.5,
        ScreenOrientationIssue::FingerprintingViaOrientation => 5.5,
        ScreenOrientationIssue::ChangeEventTracking => 4.5,
        ScreenOrientationIssue::ApiDetected => 2.0,
    }
}

pub fn screen_orientation_to_operations(
    issues: &[ScreenOrientationIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                screen_orientation_severity(issue),
                0.5,
            )
        })
        .collect()
}
