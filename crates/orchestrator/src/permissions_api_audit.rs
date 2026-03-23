use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum PermissionsApiIssue {
    BulkPermissionQuery,
    PermissionStatusMonitoring,
    SensitivePermissionRequest,
    PermissionFingerprinting,
    PermissionOnchangeTracking,
    AutoplayPermissionProbe,
    MidiPermissionRequest,
}

impl std::fmt::Display for PermissionsApiIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BulkPermissionQuery => write!(f, "bulk_permission_query"),
            Self::PermissionStatusMonitoring => write!(f, "permission_status_monitoring"),
            Self::SensitivePermissionRequest => write!(f, "sensitive_permission_request"),
            Self::PermissionFingerprinting => write!(f, "permission_fingerprinting"),
            Self::PermissionOnchangeTracking => write!(f, "permission_onchange_tracking"),
            Self::AutoplayPermissionProbe => write!(f, "autoplay_permission_probe"),
            Self::MidiPermissionRequest => write!(f, "midi_permission_request"),
        }
    }
}

pub fn audit_permissions_api(target: &str) -> Vec<PermissionsApiIssue> {
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
    analyze_permissions_api(&body)
}

pub fn analyze_permissions_api(body: &str) -> Vec<PermissionsApiIssue> {
    if !has_permissions_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    let query_count = count_permission_queries(body);
    if query_count >= 3 {
        issues.push(PermissionsApiIssue::BulkPermissionQuery);
    }

    if body.contains("permissions.query") && body.contains(".state") {
        issues.push(PermissionsApiIssue::PermissionStatusMonitoring);
    }

    if has_sensitive_permission_request(body) {
        issues.push(PermissionsApiIssue::SensitivePermissionRequest);
    }

    if body.contains("permissions.query")
        && (body.contains("fetch(") || body.contains("XMLHttpRequest") || body.contains(".send("))
    {
        issues.push(PermissionsApiIssue::PermissionFingerprinting);
    }

    if body.contains("onchange") && body.contains("permissions.query") {
        issues.push(PermissionsApiIssue::PermissionOnchangeTracking);
    }

    if body.contains("permissions.query") && body.contains("autoplay") {
        issues.push(PermissionsApiIssue::AutoplayPermissionProbe);
    }

    if body.contains("requestMIDIAccess") || body.contains("\"midi\"") {
        issues.push(PermissionsApiIssue::MidiPermissionRequest);
    }

    issues
}

fn has_permissions_indicators(body: &str) -> bool {
    body.contains("permissions.query")
        || body.contains("requestMIDIAccess")
        || body.contains("\"midi\"")
}

fn count_permission_queries(body: &str) -> usize {
    let names = [
        "camera",
        "microphone",
        "geolocation",
        "notifications",
        "push",
        "clipboard-read",
        "clipboard-write",
        "accelerometer",
        "gyroscope",
        "magnetometer",
        "ambient-light-sensor",
        "background-sync",
        "persistent-storage",
        "screen-wake-lock",
    ];
    names.iter().filter(|n| body.contains(**n)).count()
}

fn has_sensitive_permission_request(body: &str) -> bool {
    let sensitive = ["camera", "microphone", "geolocation"];
    body.contains("permissions.query") && sensitive.iter().any(|s| body.contains(s))
}

pub fn permissions_api_severity(issue: &PermissionsApiIssue) -> f64 {
    match issue {
        PermissionsApiIssue::PermissionFingerprinting => 7.0,
        PermissionsApiIssue::BulkPermissionQuery => 6.5,
        PermissionsApiIssue::SensitivePermissionRequest => 6.0,
        PermissionsApiIssue::PermissionOnchangeTracking => 5.5,
        PermissionsApiIssue::MidiPermissionRequest => 5.0,
        PermissionsApiIssue::PermissionStatusMonitoring => 4.5,
        PermissionsApiIssue::AutoplayPermissionProbe => 4.0,
    }
}

pub fn permissions_api_to_operations(
    issues: &[PermissionsApiIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                permissions_api_severity(issue),
                0.7,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum PermissionsApiSecurityIssue {
    ExcessivePermissionRequests,
    PermissionWithoutUserGesture,
    PermissionPersistentQuery,
    SilentPermissionChange,
    CrossOriginPermissionCheck,
    PermissionFingerprinting,
    GeolocationWithoutPurpose,
    CameraAndMicTogether,
    NotificationSpam,
    PermissionGatedDataLeak,
}

impl std::fmt::Display for PermissionsApiSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExcessivePermissionRequests => write!(f, "excessive_permission_requests"),
            Self::PermissionWithoutUserGesture => write!(f, "permission_without_user_gesture"),
            Self::PermissionPersistentQuery => write!(f, "permission_persistent_query"),
            Self::SilentPermissionChange => write!(f, "silent_permission_change"),
            Self::CrossOriginPermissionCheck => write!(f, "cross_origin_permission_check"),
            Self::PermissionFingerprinting => write!(f, "permission_fingerprinting"),
            Self::GeolocationWithoutPurpose => write!(f, "geolocation_without_purpose"),
            Self::CameraAndMicTogether => write!(f, "camera_and_mic_together"),
            Self::NotificationSpam => write!(f, "notification_spam"),
            Self::PermissionGatedDataLeak => write!(f, "permission_gated_data_leak"),
        }
    }
}

pub fn analyze_permissions_api_security(body: &str) -> Vec<PermissionsApiSecurityIssue> {
    let mut issues = Vec::new();

    let request_count = count_permission_requests(body);
    if request_count >= 5 {
        issues.push(PermissionsApiSecurityIssue::ExcessivePermissionRequests);
    }

    if has_permission_without_gesture(body) {
        issues.push(PermissionsApiSecurityIssue::PermissionWithoutUserGesture);
    }

    if has_persistent_permission_query(body) {
        issues.push(PermissionsApiSecurityIssue::PermissionPersistentQuery);
    }

    if has_silent_permission_change(body) {
        issues.push(PermissionsApiSecurityIssue::SilentPermissionChange);
    }

    if has_cross_origin_permission_check(body) {
        issues.push(PermissionsApiSecurityIssue::CrossOriginPermissionCheck);
    }

    if has_permission_fingerprinting_pattern(body) {
        issues.push(PermissionsApiSecurityIssue::PermissionFingerprinting);
    }

    if has_geolocation_without_purpose(body) {
        issues.push(PermissionsApiSecurityIssue::GeolocationWithoutPurpose);
    }

    if has_camera_and_mic_together(body) {
        issues.push(PermissionsApiSecurityIssue::CameraAndMicTogether);
    }

    if has_notification_spam(body) {
        issues.push(PermissionsApiSecurityIssue::NotificationSpam);
    }

    if has_permission_gated_data_leak(body) {
        issues.push(PermissionsApiSecurityIssue::PermissionGatedDataLeak);
    }

    issues
}

fn count_permission_requests(body: &str) -> usize {
    let notification_count = body.matches("Notification.requestPermission").count();
    let generic_request = body
        .matches(".requestPermission")
        .count()
        .saturating_sub(notification_count);
    generic_request
        + notification_count
        + body.matches("permissions.request").count()
        + body.matches("getUserMedia").count()
        + body.matches("requestMIDIAccess").count()
}

fn has_permission_without_gesture(body: &str) -> bool {
    let has_request = body.contains(".requestPermission")
        || body.contains("permissions.request")
        || body.contains("getUserMedia");
    let has_gesture_handlers = body.contains("addEventListener")
        && (body.contains("'click'")
            || body.contains("\"click\"")
            || body.contains("'mousedown'")
            || body.contains("\"mousedown\""));
    has_request && !has_gesture_handlers
}

fn has_persistent_permission_query(body: &str) -> bool {
    let has_interval = body.contains("setInterval") || body.contains("setTimeout");
    let has_query = body.contains("permissions.query") || body.contains("permissions.request");
    has_interval && has_query
}

fn has_silent_permission_change(body: &str) -> bool {
    body.contains("permissions.revoke")
        && !body.contains("alert")
        && !body.contains("console.log")
        && !body.contains("notify")
}

fn has_cross_origin_permission_check(body: &str) -> bool {
    (body.contains("permissions.query") || body.contains("permissions.request"))
        && (body.contains("postMessage") || body.contains("iframe"))
}

fn has_permission_fingerprinting_pattern(body: &str) -> bool {
    let has_query = body.contains("permissions.query");
    let has_tracking = body.contains("fetch")
        || body.contains("XMLHttpRequest")
        || body.contains("beacon")
        || body.contains("analytics");
    let has_multiple_permissions = count_permission_queries(body) >= 3;
    has_query && has_tracking && has_multiple_permissions
}

fn has_geolocation_without_purpose(body: &str) -> bool {
    let has_geolocation = body.contains("geolocation") && body.contains("getCurrentPosition");
    let has_map = body.contains("map") || body.contains("Map");
    let has_location_context = body.contains("updateLocation")
        || body.contains("showLocation")
        || body.contains("setLocation");
    has_geolocation && !has_map && !has_location_context
}

fn has_camera_and_mic_together(body: &str) -> bool {
    let has_video = body.contains("video: true") || body.contains("video:true");
    let has_audio = body.contains("audio: true") || body.contains("audio:true");
    (has_video && has_audio) || (body.contains("camera") && body.contains("microphone"))
}

fn has_notification_spam(body: &str) -> bool {
    body.contains("Notification.requestPermission") && body.contains("setInterval")
}

fn has_permission_gated_data_leak(body: &str) -> bool {
    let has_permission_check = body.contains("permissions.query")
        || body.contains(".state")
        || body.contains("PermissionStatus");
    let has_data_leak = (body.contains("fetch") || body.contains("XMLHttpRequest"))
        && (body.contains("localStorage")
            || body.contains("sessionStorage")
            || body.contains("cookie"));
    has_permission_check && has_data_leak
}

pub fn permissions_api_security_severity(issue: &PermissionsApiSecurityIssue) -> f64 {
    match issue {
        PermissionsApiSecurityIssue::PermissionGatedDataLeak => 8.5,
        PermissionsApiSecurityIssue::PermissionFingerprinting => 8.0,
        PermissionsApiSecurityIssue::CrossOriginPermissionCheck => 7.5,
        PermissionsApiSecurityIssue::SilentPermissionChange => 7.0,
        PermissionsApiSecurityIssue::ExcessivePermissionRequests => 6.5,
        PermissionsApiSecurityIssue::CameraAndMicTogether => 6.0,
        PermissionsApiSecurityIssue::PermissionWithoutUserGesture => 5.5,
        PermissionsApiSecurityIssue::NotificationSpam => 5.0,
        PermissionsApiSecurityIssue::PermissionPersistentQuery => 4.5,
        PermissionsApiSecurityIssue::GeolocationWithoutPurpose => 4.0,
    }
}

pub fn permissions_api_security_to_operations(
    issues: &[PermissionsApiSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                permissions_api_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
