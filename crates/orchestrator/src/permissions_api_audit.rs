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
