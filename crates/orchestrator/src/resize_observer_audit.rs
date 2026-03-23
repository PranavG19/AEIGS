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
    CrossOriginResizeTracking,
    ResizeFingerprinting,
    ResizeBasedLayoutDetection,
    ResizeInWorker,
    ResizeWithIntersectionObserver,
    ResizeToLocalStorage,
    ResizeTimingAttack,
    ResizeCrossTabCommunication,
    ResizeBasedKeylogging,
    ResizeWithoutThrottling,
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
            Self::CrossOriginResizeTracking => write!(f, "cross_origin_resize_tracking"),
            Self::ResizeFingerprinting => write!(f, "resize_fingerprinting"),
            Self::ResizeBasedLayoutDetection => write!(f, "resize_based_layout_detection"),
            Self::ResizeInWorker => write!(f, "resize_in_worker"),
            Self::ResizeWithIntersectionObserver => write!(f, "resize_with_intersection_observer"),
            Self::ResizeToLocalStorage => write!(f, "resize_to_local_storage"),
            Self::ResizeTimingAttack => write!(f, "resize_timing_attack"),
            Self::ResizeCrossTabCommunication => write!(f, "resize_cross_tab_communication"),
            Self::ResizeBasedKeylogging => write!(f, "resize_based_keylogging"),
            Self::ResizeWithoutThrottling => write!(f, "resize_without_throttling"),
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
        ResizeObserverIssue::ResizeBasedKeylogging => 8.0,
        ResizeObserverIssue::CrossOriginResizeTracking => 7.5,
        ResizeObserverIssue::ResizeFingerprinting => 7.0,
        ResizeObserverIssue::ResizeTimingAttack => 7.0,
        ResizeObserverIssue::ResizeToLocalStorage => 6.5,
        ResizeObserverIssue::ResizeCrossTabCommunication => 6.5,
        ResizeObserverIssue::ResizeInWorker => 6.0,
        ResizeObserverIssue::DataExfiltration => 5.5,
        ResizeObserverIssue::ResizeWithIntersectionObserver => 5.0,
        ResizeObserverIssue::ContinuousTracking => 5.0,
        ResizeObserverIssue::MultipleTargets => 4.5,
        ResizeObserverIssue::BorderBoxSize => 4.0,
        ResizeObserverIssue::ResizeBasedLayoutDetection => 4.0,
        ResizeObserverIssue::ContentRectAccess => 3.5,
        ResizeObserverIssue::ResizeWithoutThrottling => 3.5,
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

pub fn analyze_resize_observer_security(body: &str) -> Vec<ResizeObserverIssue> {
    if !body.contains("ResizeObserver") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if (body.contains("iframe") || body.contains("cross-origin") || body.contains("postMessage"))
        && body.contains("ResizeObserver")
    {
        issues.push(ResizeObserverIssue::CrossOriginResizeTracking);
    }

    if (body.contains("fingerprint")
        || body.contains("canvas")
        || body.contains("screen.width")
        || body.contains("screen.height"))
        && body.contains("ResizeObserver")
    {
        issues.push(ResizeObserverIssue::ResizeFingerprinting);
    }

    if (body.contains("innerWidth")
        || body.contains("innerHeight")
        || body.contains("matchMedia")
        || body.contains("breakpoint"))
        && body.contains("ResizeObserver")
    {
        issues.push(ResizeObserverIssue::ResizeBasedLayoutDetection);
    }

    if (body.contains("Worker") || body.contains("SharedWorker") || body.contains("postMessage"))
        && body.contains("ResizeObserver")
    {
        issues.push(ResizeObserverIssue::ResizeInWorker);
    }

    if body.contains("IntersectionObserver") && body.contains("ResizeObserver") {
        issues.push(ResizeObserverIssue::ResizeWithIntersectionObserver);
    }

    if (body.contains("localStorage")
        || body.contains("sessionStorage")
        || body.contains("indexedDB"))
        && body.contains("ResizeObserver")
    {
        issues.push(ResizeObserverIssue::ResizeToLocalStorage);
    }

    if (body.contains("performance.now")
        || body.contains("Date.now")
        || body.contains("performance.mark"))
        && body.contains("ResizeObserver")
    {
        issues.push(ResizeObserverIssue::ResizeTimingAttack);
    }

    if (body.contains("BroadcastChannel")
        || body.contains("SharedWorker")
        || body.contains("localStorage"))
        && body.contains("ResizeObserver")
    {
        issues.push(ResizeObserverIssue::ResizeCrossTabCommunication);
    }

    if (body.contains("keydown")
        || body.contains("keypress")
        || body.contains("keyup")
        || body.contains("input"))
        && body.contains("ResizeObserver")
    {
        issues.push(ResizeObserverIssue::ResizeBasedKeylogging);
    }

    if body.contains("ResizeObserver")
        && !body.contains("debounce")
        && !body.contains("throttle")
        && !body.contains("requestAnimationFrame")
        && !body.contains("setTimeout")
    {
        issues.push(ResizeObserverIssue::ResizeWithoutThrottling);
    }

    issues
}

pub fn resize_observer_security_to_operations(
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
                0.7,
            )
        })
        .collect()
}
