use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum FullscreenIssue {
    ApiDetected,
    UiSpoofing,
    PhishingOverlay,
    NoExitIndicator,
    IframeFullscreen,
    KeyboardTrap,
}

impl std::fmt::Display for FullscreenIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::UiSpoofing => write!(f, "ui_spoofing"),
            Self::PhishingOverlay => write!(f, "phishing_overlay"),
            Self::NoExitIndicator => write!(f, "no_exit_indicator"),
            Self::IframeFullscreen => write!(f, "iframe_fullscreen"),
            Self::KeyboardTrap => write!(f, "keyboard_trap"),
        }
    }
}

pub fn fullscreen_severity(issue: &FullscreenIssue) -> f64 {
    match issue {
        FullscreenIssue::PhishingOverlay => 8.5,
        FullscreenIssue::UiSpoofing => 8.0,
        FullscreenIssue::KeyboardTrap => 7.5,
        FullscreenIssue::IframeFullscreen => 6.5,
        FullscreenIssue::NoExitIndicator => 5.5,
        FullscreenIssue::ApiDetected => 3.0,
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
        || body.contains("mozRequestFullScreen")
        || body.contains("msRequestFullscreen");
    if !has_request {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(FullscreenIssue::ApiDetected);

    if detect_ui_spoofing(body) {
        issues.push(FullscreenIssue::UiSpoofing);
    }

    if detect_phishing_overlay(body) {
        issues.push(FullscreenIssue::PhishingOverlay);
    }

    if detect_no_exit_indicator(body) {
        issues.push(FullscreenIssue::NoExitIndicator);
    }

    if detect_iframe_fullscreen(body) {
        issues.push(FullscreenIssue::IframeFullscreen);
    }

    if detect_keyboard_trap(body) {
        issues.push(FullscreenIssue::KeyboardTrap);
    }

    issues
}

pub fn detect_ui_spoofing(body: &str) -> bool {
    let has_fullscreen_element = body.contains("fullscreenElement")
        || body.contains("webkitFullscreenElement")
        || body.contains("mozFullScreenElement");

    let browser_chrome_indicators = [
        "address",
        "url",
        "navigation",
        "toolbar",
        "chrome",
        "browser",
        "location-bar",
        "nav-bar",
    ];

    let has_chrome_creation = browser_chrome_indicators
        .iter()
        .any(|&indicator| body.contains(indicator));

    let has_dom_manipulation = body.contains("createElement")
        || body.contains("innerHTML")
        || body.contains("insertAdjacentHTML")
        || body.contains("appendChild");

    has_fullscreen_element && has_chrome_creation && has_dom_manipulation
}

pub fn detect_phishing_overlay(body: &str) -> bool {
    let has_fullscreen = body.contains("requestFullscreen")
        || body.contains("webkitRequestFullscreen")
        || body.contains("mozRequestFullScreen");

    let form_indicators = [
        "password",
        "login",
        "signin",
        "credentials",
        "username",
        "email",
        "credit-card",
        "card-number",
        "cvv",
    ];

    let has_sensitive_form = form_indicators
        .iter()
        .any(|&indicator| body.contains(indicator));

    let has_form_element = body.contains("<form")
        || body.contains("type=\"password\"")
        || body.contains("type='password'")
        || body.contains("<input");

    has_fullscreen && has_sensitive_form && has_form_element
}

pub fn detect_no_exit_indicator(body: &str) -> bool {
    let has_fullscreen = body.contains("requestFullscreen")
        || body.contains("webkitRequestFullscreen")
        || body.contains("mozRequestFullScreen");

    let exit_indicators = [
        "Press ESC",
        "Press Escape",
        "exit",
        "close",
        "exitFullscreen",
        "fullscreen-exit",
        "leave fullscreen",
    ];

    let has_exit_instruction = exit_indicators
        .iter()
        .any(|&indicator| body.contains(indicator));

    has_fullscreen && !has_exit_instruction
}

pub fn detect_iframe_fullscreen(body: &str) -> bool {
    let has_allowfullscreen = body.contains("allowfullscreen")
        || body.contains("webkitallowfullscreen")
        || body.contains("mozallowfullscreen");

    let has_iframe = body.contains("<iframe");

    let cross_origin_indicators = body.contains("http://") || body.contains("https://");

    has_iframe && has_allowfullscreen && cross_origin_indicators
}

pub fn detect_keyboard_trap(body: &str) -> bool {
    let has_fullscreen = body.contains("requestFullscreen")
        || body.contains("webkitRequestFullscreen")
        || body.contains("mozRequestFullScreen");

    let has_keyboard_lock = body.contains("keyboard.lock") || body.contains("Keyboard.lock");

    let has_escape_prevent = body.contains("preventDefault")
        && (body.contains("Escape") || body.contains("keyCode") || body.contains("key ==="));

    let has_pointer_lock = body.contains("requestPointerLock");

    has_fullscreen && (has_keyboard_lock || has_escape_prevent || has_pointer_lock)
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
                0.5,
            )
        })
        .collect()
}
