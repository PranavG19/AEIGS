use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum FullscreenIssue {
    ApiDetected,
    NoUserActivation,
    FakeUiOverlay,
    KeyboardLock,
    PointerLock,
    AutoFullscreen,
}

impl std::fmt::Display for FullscreenIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::FakeUiOverlay => write!(f, "fake_ui_overlay"),
            Self::KeyboardLock => write!(f, "keyboard_lock"),
            Self::PointerLock => write!(f, "pointer_lock"),
            Self::AutoFullscreen => write!(f, "auto_fullscreen"),
        }
    }
}

pub fn audit_fullscreen(target: &str) -> Vec<FullscreenIssue> {
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
    analyze_fullscreen(&body)
}

pub fn analyze_fullscreen(body: &str) -> Vec<FullscreenIssue> {
    let has_request = body.contains("requestFullscreen")
        || body.contains("webkitRequestFullscreen")
        || body.contains("mozRequestFullScreen");
    if !has_request {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(FullscreenIssue::ApiDetected);

    let has_user_gesture = body.contains("click") || body.contains("keydown") || body.contains("pointerdown");
    if !has_user_gesture {
        issues.push(FullscreenIssue::NoUserActivation);
    }

    if body.contains("createElement") || body.contains("innerHTML") || body.contains("insertAdjacentHTML") {
        issues.push(FullscreenIssue::FakeUiOverlay);
    }

    if body.contains("keyboard.lock") || body.contains("Keyboard.lock") {
        issues.push(FullscreenIssue::KeyboardLock);
    }

    if body.contains("requestPointerLock") {
        issues.push(FullscreenIssue::PointerLock);
    }

    if body.contains("DOMContentLoaded") || body.contains("window.onload") || body.contains("addEventListener(\"load\"") {
        issues.push(FullscreenIssue::AutoFullscreen);
    }

    issues
}

pub fn fullscreen_severity(issue: &FullscreenIssue) -> f64 {
    match issue {
        FullscreenIssue::KeyboardLock => 7.0,
        FullscreenIssue::FakeUiOverlay => 6.5,
        FullscreenIssue::PointerLock => 6.0,
        FullscreenIssue::AutoFullscreen => 5.5,
        FullscreenIssue::NoUserActivation => 5.0,
        FullscreenIssue::ApiDetected => 3.0,
    }
}

pub fn fullscreen_to_operations(
    issues: &[FullscreenIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                fullscreen_severity(issue),
                0.7,
            )
        })
        .collect()
}
