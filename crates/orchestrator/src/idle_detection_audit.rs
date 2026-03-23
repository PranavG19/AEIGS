use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum IdleDetectionIssue {
    IdleDetectorUsage,
    IdleStateExfiltration,
    IdleChangeTracking,
    ScreenStateMonitoring,
    ContinuousIdlePolling,
}

impl std::fmt::Display for IdleDetectionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdleDetectorUsage => write!(f, "idle_detector_usage"),
            Self::IdleStateExfiltration => write!(f, "idle_state_exfiltration"),
            Self::IdleChangeTracking => write!(f, "idle_change_tracking"),
            Self::ScreenStateMonitoring => write!(f, "screen_state_monitoring"),
            Self::ContinuousIdlePolling => write!(f, "continuous_idle_polling"),
        }
    }
}

pub fn audit_idle_detection(target: &str) -> Vec<IdleDetectionIssue> {
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
    analyze_idle_detection(&body)
}

pub fn analyze_idle_detection(body: &str) -> Vec<IdleDetectionIssue> {
    if !body.contains("IdleDetector") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    issues.push(IdleDetectionIssue::IdleDetectorUsage);

    if body.contains("userState") || body.contains("screenState") {
        let sends = body.contains("fetch(")
            || body.contains("XMLHttpRequest")
            || body.contains(".send(")
            || body.contains("sendBeacon");
        if sends {
            issues.push(IdleDetectionIssue::IdleStateExfiltration);
        }
    }

    if body.contains("onchange") || body.contains("addEventListener") {
        issues.push(IdleDetectionIssue::IdleChangeTracking);
    }

    if body.contains("screenState") {
        issues.push(IdleDetectionIssue::ScreenStateMonitoring);
    }

    if body.contains("setInterval") || body.contains("requestAnimationFrame") {
        issues.push(IdleDetectionIssue::ContinuousIdlePolling);
    }

    issues
}

pub fn idle_detection_severity(issue: &IdleDetectionIssue) -> f64 {
    match issue {
        IdleDetectionIssue::IdleStateExfiltration => 7.5,
        IdleDetectionIssue::ScreenStateMonitoring => 7.0,
        IdleDetectionIssue::ContinuousIdlePolling => 6.5,
        IdleDetectionIssue::IdleChangeTracking => 6.0,
        IdleDetectionIssue::IdleDetectorUsage => 5.0,
    }
}

pub fn idle_detection_to_operations(
    issues: &[IdleDetectionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                idle_detection_severity(issue),
                0.7,
            )
        })
        .collect()
}
