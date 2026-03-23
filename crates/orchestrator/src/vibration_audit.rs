use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum VibrationIssue {
    ApiDetected,
    NoUserActivation,
    ExcessiveDuration,
    ContinuousVibration,
    CovertChannel,
}

impl std::fmt::Display for VibrationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::ExcessiveDuration => write!(f, "excessive_duration"),
            Self::ContinuousVibration => write!(f, "continuous_vibration"),
            Self::CovertChannel => write!(f, "covert_channel"),
        }
    }
}

pub fn audit_vibration(target: &str) -> Vec<VibrationIssue> {
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
    analyze_vibration(&body)
}

pub fn analyze_vibration(body: &str) -> Vec<VibrationIssue> {
    if !body.contains("navigator.vibrate") && !body.contains(".vibrate(") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(VibrationIssue::ApiDetected);

    if !body.contains("click") && !body.contains("keydown") && !body.contains("pointerdown") {
        issues.push(VibrationIssue::NoUserActivation);
    }

    if body.contains("[") && body.contains("vibrate(") {
        issues.push(VibrationIssue::ExcessiveDuration);
    }

    if body.contains("setInterval") || body.contains("while(") || body.contains("while ") {
        issues.push(VibrationIssue::ContinuousVibration);
    }

    if body.contains("vibrate(")
        && (body.contains("WebSocket") || body.contains("BroadcastChannel") || body.contains("postMessage"))
    {
        issues.push(VibrationIssue::CovertChannel);
    }

    issues
}

pub fn vibration_severity(issue: &VibrationIssue) -> f64 {
    match issue {
        VibrationIssue::CovertChannel => 6.5,
        VibrationIssue::ContinuousVibration => 5.5,
        VibrationIssue::ExcessiveDuration => 5.0,
        VibrationIssue::NoUserActivation => 4.5,
        VibrationIssue::ApiDetected => 2.0,
    }
}

pub fn vibration_to_operations(
    issues: &[VibrationIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                vibration_severity(issue),
                0.5,
            )
        })
        .collect()
}
