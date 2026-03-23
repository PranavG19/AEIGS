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

    if body.contains("window.open")
        && (body.contains("screenX")
            || body.contains("screenY")
            || body.contains("left=")
            || body.contains("top="))
    {
        issues.push(WindowManagementIssue::CrossScreenPopup);
    }

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil
        && (body.contains("availWidth")
            || body.contains("availHeight")
            || body.contains("devicePixelRatio"))
    {
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

#[derive(Debug, Clone, PartialEq)]
pub enum WindowManagementSecurityIssue {
    ScreenEnumeration,
    WindowPositionTracking,
    MultiScreenFingerprinting,
    WindowPlacementAbuse,
    FullscreenOnAllScreens,
    WindowCrossOriginPositioning,
    ScreenDetailsSurveillance,
    WindowInBackground,
    WindowResizeTracking,
    ScreenLabelExposure,
}

impl std::fmt::Display for WindowManagementSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScreenEnumeration => write!(f, "screen_enumeration"),
            Self::WindowPositionTracking => write!(f, "window_position_tracking"),
            Self::MultiScreenFingerprinting => write!(f, "multi_screen_fingerprinting"),
            Self::WindowPlacementAbuse => write!(f, "window_placement_abuse"),
            Self::FullscreenOnAllScreens => write!(f, "fullscreen_on_all_screens"),
            Self::WindowCrossOriginPositioning => write!(f, "window_cross_origin_positioning"),
            Self::ScreenDetailsSurveillance => write!(f, "screen_details_surveillance"),
            Self::WindowInBackground => write!(f, "window_in_background"),
            Self::WindowResizeTracking => write!(f, "window_resize_tracking"),
            Self::ScreenLabelExposure => write!(f, "screen_label_exposure"),
        }
    }
}

pub fn analyze_window_management_security(body: &str) -> Vec<WindowManagementSecurityIssue> {
    let mut issues = Vec::new();

    if body.contains("screens") && body.contains(".length") {
        issues.push(WindowManagementSecurityIssue::ScreenEnumeration);
    }

    if body.contains("screenX") || body.contains("screenY") {
        let has_tracking = body.contains("setInterval") || body.contains("requestAnimationFrame");
        if has_tracking {
            issues.push(WindowManagementSecurityIssue::WindowPositionTracking);
        }
    }

    if body.contains("screens") && body.contains("devicePixelRatio") {
        let has_fingerprint_storage = body.contains("localStorage")
            || body.contains("sessionStorage")
            || body.contains("indexedDB");
        if has_fingerprint_storage {
            issues.push(WindowManagementSecurityIssue::MultiScreenFingerprinting);
        }
    }

    if body.contains("window.open") && body.contains("screens") {
        let has_coords = body.contains("left=") || body.contains("top=");
        if has_coords {
            issues.push(WindowManagementSecurityIssue::WindowPlacementAbuse);
        }
    }

    if body.contains("requestFullscreen") {
        let has_loop = body.contains("forEach") || body.contains("for");
        if has_loop && body.contains("screens") {
            issues.push(WindowManagementSecurityIssue::FullscreenOnAllScreens);
        }
    }

    if body.contains("postMessage") && (body.contains("screenX") || body.contains("screenY")) {
        issues.push(WindowManagementSecurityIssue::WindowCrossOriginPositioning);
    }

    if body.contains("getScreenDetails") {
        let surveillance_indicators = [
            "availWidth",
            "availHeight",
            "colorDepth",
            "orientation",
            "isPrimary",
            "isInternal",
        ];
        let count = surveillance_indicators
            .iter()
            .filter(|&indicator| body.contains(indicator))
            .count();
        if count >= 3 {
            issues.push(WindowManagementSecurityIssue::ScreenDetailsSurveillance);
        }
    }

    if body.contains("document.hidden") || body.contains("visibilityState") {
        let has_positioning = body.contains("moveTo") || body.contains("moveBy");
        if has_positioning {
            issues.push(WindowManagementSecurityIssue::WindowInBackground);
        }
    }

    if body.contains("resize") && body.contains("addEventListener") {
        let has_exfil = body.contains("fetch") || body.contains("sendBeacon");
        if has_exfil {
            issues.push(WindowManagementSecurityIssue::WindowResizeTracking);
        }
    }

    if body.contains("label") && body.contains("screens") {
        let has_exfil = body.contains("fetch") || body.contains("XMLHttpRequest");
        if has_exfil {
            issues.push(WindowManagementSecurityIssue::ScreenLabelExposure);
        }
    }

    issues
}

pub fn window_management_security_severity(issue: &WindowManagementSecurityIssue) -> f64 {
    match issue {
        WindowManagementSecurityIssue::ScreenDetailsSurveillance => 7.5,
        WindowManagementSecurityIssue::MultiScreenFingerprinting => 7.0,
        WindowManagementSecurityIssue::ScreenLabelExposure => 6.8,
        WindowManagementSecurityIssue::WindowCrossOriginPositioning => 6.5,
        WindowManagementSecurityIssue::WindowPositionTracking => 6.0,
        WindowManagementSecurityIssue::WindowPlacementAbuse => 5.8,
        WindowManagementSecurityIssue::FullscreenOnAllScreens => 5.5,
        WindowManagementSecurityIssue::WindowResizeTracking => 5.2,
        WindowManagementSecurityIssue::WindowInBackground => 5.0,
        WindowManagementSecurityIssue::ScreenEnumeration => 4.5,
    }
}

pub fn window_management_security_to_operations(
    issues: &[WindowManagementSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                window_management_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
