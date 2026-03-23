use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ResizeObserverIssue {
    ObserverDetected,
    ContentRectAccess,
    BorderBoxSize,
    MultipleTargets,
    DataExfiltration,
    ContinuousTracking,
}

impl std::fmt::Display for ResizeObserverIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObserverDetected => write!(f, "observer_detected"),
            Self::ContentRectAccess => write!(f, "content_rect_access"),
            Self::BorderBoxSize => write!(f, "border_box_size"),
            Self::MultipleTargets => write!(f, "multiple_targets"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::ContinuousTracking => write!(f, "continuous_tracking"),
        }
    }
}

pub fn audit_resize_observer(target: &str) -> Vec<ResizeObserverIssue> {
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
    analyze_resize_observer(&body)
}

pub fn analyze_resize_observer(body: &str) -> Vec<ResizeObserverIssue> {
    if !body.contains("ResizeObserver") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(ResizeObserverIssue::ObserverDetected);

    if body.contains("contentRect") {
        issues.push(ResizeObserverIssue::ContentRectAccess);
    }

    if body.contains("borderBoxSize")
        || body.contains("contentBoxSize")
        || body.contains("devicePixelContentBoxSize")
    {
        issues.push(ResizeObserverIssue::BorderBoxSize);
    }

    let observe_count = body.matches(".observe(").count();
    if observe_count > 3 {
        issues.push(ResizeObserverIssue::MultipleTargets);
    }

    if body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest") {
        issues.push(ResizeObserverIssue::DataExfiltration);
    }

    if body.contains("requestAnimationFrame") || body.contains("setInterval") {
        issues.push(ResizeObserverIssue::ContinuousTracking);
    }

    issues
}

pub fn resize_observer_severity(issue: &ResizeObserverIssue) -> f64 {
    match issue {
        ResizeObserverIssue::DataExfiltration => 5.5,
        ResizeObserverIssue::ContinuousTracking => 5.0,
        ResizeObserverIssue::MultipleTargets => 4.5,
        ResizeObserverIssue::BorderBoxSize => 4.0,
        ResizeObserverIssue::ContentRectAccess => 3.5,
        ResizeObserverIssue::ObserverDetected => 3.0,
    }
}

pub fn resize_observer_to_operations(
    issues: &[ResizeObserverIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                resize_observer_severity(issue),
                0.6,
            )
        })
        .collect()
}
