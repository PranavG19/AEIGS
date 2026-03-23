use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum BeaconApiIssue {
    ApiDetected,
    SensitiveDataLeak,
    CrossOriginBeacon,
    UnboundedPayload,
    UnloadTracking,
}

impl std::fmt::Display for BeaconApiIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::SensitiveDataLeak => write!(f, "sensitive_data_leak"),
            Self::CrossOriginBeacon => write!(f, "cross_origin_beacon"),
            Self::UnboundedPayload => write!(f, "unbounded_payload"),
            Self::UnloadTracking => write!(f, "unload_tracking"),
        }
    }
}

pub fn audit_beacon_api(target: &str) -> Vec<BeaconApiIssue> {
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
    analyze_beacon_api(&body)
}

pub fn analyze_beacon_api(body: &str) -> Vec<BeaconApiIssue> {
    if !body.contains("sendBeacon") && !body.contains("navigator.sendBeacon") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(BeaconApiIssue::ApiDetected);

    let has_sensitive = body.contains("password")
        || body.contains("token")
        || body.contains("credential")
        || body.contains("secret")
        || body.contains("apiKey")
        || body.contains("sessionId");
    if has_sensitive {
        issues.push(BeaconApiIssue::SensitiveDataLeak);
    }

    let has_http = body.contains("http://") || body.contains("https://");
    let has_same_origin = body.contains("location.origin")
        || body.contains("window.origin")
        || body.contains("self.origin")
        || body.contains("same-origin");
    if has_http && !has_same_origin {
        issues.push(BeaconApiIssue::CrossOriginBeacon);
    }

    let has_serialization = body.contains("JSON.stringify")
        || body.contains("FormData")
        || body.contains("Blob");
    let has_limit = body.contains("slice")
        || body.contains("substring")
        || body.contains("maxLength")
        || body.contains("limit");
    if has_serialization && !has_limit {
        issues.push(BeaconApiIssue::UnboundedPayload);
    }

    let has_unload = body.contains("unload")
        || body.contains("beforeunload")
        || body.contains("visibilitychange")
        || body.contains("pagehide");
    let has_tracking = body.contains("track")
        || body.contains("analytics")
        || body.contains("log")
        || body.contains("metric");
    if has_unload && has_tracking {
        issues.push(BeaconApiIssue::UnloadTracking);
    }

    issues
}

pub fn beacon_api_severity(issue: &BeaconApiIssue) -> f64 {
    match issue {
        BeaconApiIssue::ApiDetected => 2.0,
        BeaconApiIssue::SensitiveDataLeak => 7.5,
        BeaconApiIssue::CrossOriginBeacon => 6.5,
        BeaconApiIssue::UnboundedPayload => 5.5,
        BeaconApiIssue::UnloadTracking => 6.0,
    }
}

pub fn beacon_api_to_operations(
    issues: &[BeaconApiIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                beacon_api_severity(issue),
                0.5,
            )
        })
        .collect()
}
