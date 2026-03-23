use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WindowManagementIssue {
    ApiDetected,
    ScreenEnumeration,
    CrossScreenPopup,
    ScreenDetailExfiltration,
    NoPermissionCheck,
    FullscreenOnExternal,
}

impl std::fmt::Display for WindowManagementIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::ScreenEnumeration => write!(f, "screen_enumeration"),
            Self::CrossScreenPopup => write!(f, "cross_screen_popup"),
            Self::ScreenDetailExfiltration => write!(f, "screen_detail_exfiltration"),
            Self::NoPermissionCheck => write!(f, "no_permission_check"),
            Self::FullscreenOnExternal => write!(f, "fullscreen_on_external"),
        }
    }
}

pub fn audit_window_management(target: &str) -> Vec<WindowManagementIssue> {
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
    analyze_window_management(&body)
}

pub fn analyze_window_management(body: &str) -> Vec<WindowManagementIssue> {
    if !body.contains("getScreenDetails") && !body.contains("window-management") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WindowManagementIssue::ApiDetected);

    if body.contains("screens") && (body.contains(".length") || body.contains("forEach")) {
        issues.push(WindowManagementIssue::ScreenEnumeration);
    }

    if body.contains("window.open") && (body.contains("screenX") || body.contains("screenY") || body.contains("left=") || body.contains("top=")) {
        issues.push(WindowManagementIssue::CrossScreenPopup);
    }

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil && (body.contains("availWidth") || body.contains("availHeight") || body.contains("devicePixelRatio")) {
        issues.push(WindowManagementIssue::ScreenDetailExfiltration);
    }

    if !body.contains("permissions") && !body.contains("query(") {
        issues.push(WindowManagementIssue::NoPermissionCheck);
    }

    if body.contains("requestFullscreen") && body.contains("screen") {
        issues.push(WindowManagementIssue::FullscreenOnExternal);
    }

    issues
}

pub fn window_management_severity(issue: &WindowManagementIssue) -> f64 {
    match issue {
        WindowManagementIssue::ScreenDetailExfiltration => 6.5,
        WindowManagementIssue::CrossScreenPopup => 6.0,
        WindowManagementIssue::FullscreenOnExternal => 5.5,
        WindowManagementIssue::ScreenEnumeration => 5.0,
        WindowManagementIssue::NoPermissionCheck => 4.5,
        WindowManagementIssue::ApiDetected => 3.0,
    }
}

pub fn window_management_to_operations(
    issues: &[WindowManagementIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                window_management_severity(issue),
                0.6,
            )
        })
        .collect()
}
