use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum IntersectionObserverIssue {
    ObserverDetected,
    VisibilityTracking,
    MultipleThresholds,
    CrossOriginTarget,
    ScrollJacking,
    AdVisibilityCheck,
}

impl std::fmt::Display for IntersectionObserverIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObserverDetected => write!(f, "observer_detected"),
            Self::VisibilityTracking => write!(f, "visibility_tracking"),
            Self::MultipleThresholds => write!(f, "multiple_thresholds"),
            Self::CrossOriginTarget => write!(f, "cross_origin_target"),
            Self::ScrollJacking => write!(f, "scroll_jacking"),
            Self::AdVisibilityCheck => write!(f, "ad_visibility_check"),
        }
    }
}

pub fn audit_intersection_observer(target: &str) -> Vec<IntersectionObserverIssue> {
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
    analyze_intersection_observer(&body)
}

pub fn analyze_intersection_observer(body: &str) -> Vec<IntersectionObserverIssue> {
    if !body.contains("IntersectionObserver") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(IntersectionObserverIssue::ObserverDetected);

    if body.contains("isIntersecting") && (body.contains("fetch(") || body.contains("sendBeacon")) {
        issues.push(IntersectionObserverIssue::VisibilityTracking);
    }

    if body.contains("threshold") && body.contains('[') {
        let threshold_count = count_thresholds(body);
        if threshold_count > 5 {
            issues.push(IntersectionObserverIssue::MultipleThresholds);
        }
    }

    if body.contains("iframe") && body.contains("observe(") {
        issues.push(IntersectionObserverIssue::CrossOriginTarget);
    }

    if body.contains("scrollTo") || body.contains("scrollIntoView") {
        issues.push(IntersectionObserverIssue::ScrollJacking);
    }

    let ad_markers = ["ad-", "advert", "banner", "sponsor", "promo"];
    if ad_markers.iter().any(|m| body.contains(m)) && body.contains("isIntersecting") {
        issues.push(IntersectionObserverIssue::AdVisibilityCheck);
    }

    issues
}

fn count_thresholds(body: &str) -> usize {
    if let Some(pos) = body.find("threshold") {
        let rest = &body[pos..];
        if let Some(bracket) = rest.find('[') {
            let after_bracket = &rest[bracket + 1..];
            if let Some(end) = after_bracket.find(']') {
                let inside = &after_bracket[..end];
                return inside.split(',').count();
            }
        }
    }
    0
}

pub fn intersection_observer_severity(issue: &IntersectionObserverIssue) -> f64 {
    match issue {
        IntersectionObserverIssue::VisibilityTracking => 5.5,
        IntersectionObserverIssue::CrossOriginTarget => 5.0,
        IntersectionObserverIssue::ScrollJacking => 4.5,
        IntersectionObserverIssue::AdVisibilityCheck => 4.0,
        IntersectionObserverIssue::MultipleThresholds => 3.5,
        IntersectionObserverIssue::ObserverDetected => 3.0,
    }
}

pub fn intersection_observer_to_operations(
    issues: &[IntersectionObserverIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                intersection_observer_severity(issue),
                0.6,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum IntersectionObserverSecurityIssue {
    VisibilityTracking,
    AdBlockDetection,
    ScrollJacking,
    LazyLoadFingerprint,
    CrossOriginVisibility,
    ViewportSizeLeakage,
    ElementTimingAttack,
    IntersectionWithStorage,
    InfiniteScrollTracking,
    IntersectionInWorker,
}

impl std::fmt::Display for IntersectionObserverSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VisibilityTracking => write!(f, "visibility_tracking"),
            Self::AdBlockDetection => write!(f, "adblock_detection"),
            Self::ScrollJacking => write!(f, "scroll_jacking"),
            Self::LazyLoadFingerprint => write!(f, "lazyload_fingerprint"),
            Self::CrossOriginVisibility => write!(f, "cross_origin_visibility"),
            Self::ViewportSizeLeakage => write!(f, "viewport_size_leakage"),
            Self::ElementTimingAttack => write!(f, "element_timing_attack"),
            Self::IntersectionWithStorage => write!(f, "intersection_with_storage"),
            Self::InfiniteScrollTracking => write!(f, "infinite_scroll_tracking"),
            Self::IntersectionInWorker => write!(f, "intersection_in_worker"),
        }
    }
}

pub fn analyze_intersection_observer_security(
    body: &str,
) -> Vec<IntersectionObserverSecurityIssue> {
    if !body.contains("IntersectionObserver") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    // VisibilityTracking: tracking element visibility for surveillance
    if body.contains("isIntersecting")
        && (body.contains("analytics")
            || body.contains("track")
            || body.contains("sendBeacon")
            || body.contains("fetch("))
    {
        issues.push(IntersectionObserverSecurityIssue::VisibilityTracking);
    }

    // AdBlockDetection: detecting ad blockers via intersection observer
    let adblock_indicators = ["adblock", "ad-block", "adblocker", "blocked"];
    if adblock_indicators
        .iter()
        .any(|i| body.to_ascii_lowercase().contains(i))
        && body.contains("IntersectionObserver")
    {
        issues.push(IntersectionObserverSecurityIssue::AdBlockDetection);
    }

    // ScrollJacking: hijacking scroll behavior
    if (body.contains("scrollTo") || body.contains("scrollIntoView") || body.contains("scroll("))
        && body.contains("isIntersecting")
    {
        issues.push(IntersectionObserverSecurityIssue::ScrollJacking);
    }

    // LazyLoadFingerprint: using lazy load timing for fingerprinting
    if body.contains("lazy")
        && body.contains("performance")
        && body.contains("IntersectionObserver")
    {
        issues.push(IntersectionObserverSecurityIssue::LazyLoadFingerprint);
    }

    // CrossOriginVisibility: observing cross-origin iframe visibility
    if (body.contains("iframe") || body.contains("crossOrigin")) && body.contains("observe(") {
        issues.push(IntersectionObserverSecurityIssue::CrossOriginVisibility);
    }

    // ViewportSizeLeakage: inferring viewport dimensions
    if body.contains("rootMargin")
        && (body.contains("window.innerWidth")
            || body.contains("window.innerHeight")
            || body.contains("viewport"))
    {
        issues.push(IntersectionObserverSecurityIssue::ViewportSizeLeakage);
    }

    // ElementTimingAttack: timing when elements enter viewport
    if (body.contains("performance.now()") || body.contains("Date.now()"))
        && body.contains("isIntersecting")
    {
        issues.push(IntersectionObserverSecurityIssue::ElementTimingAttack);
    }

    // IntersectionWithStorage: persisting intersection data
    let storage_keywords = ["localStorage", "sessionStorage", "indexedDB", "cookie"];
    if storage_keywords.iter().any(|k| body.contains(k)) && body.contains("IntersectionObserver") {
        issues.push(IntersectionObserverSecurityIssue::IntersectionWithStorage);
    }

    // InfiniteScrollTracking: tracking scroll patterns for profiling
    let has_infinite = body.to_ascii_lowercase().contains("infinite");
    let has_append_pattern = body.contains("append") || body.contains("appendChild");
    if has_infinite || has_append_pattern {
        issues.push(IntersectionObserverSecurityIssue::InfiniteScrollTracking);
    }

    // IntersectionInWorker: using intersection observer from worker
    if (body.contains("Worker(") || body.contains("postMessage"))
        && body.contains("IntersectionObserver")
    {
        issues.push(IntersectionObserverSecurityIssue::IntersectionInWorker);
    }

    issues
}

pub fn intersection_observer_security_severity(issue: &IntersectionObserverSecurityIssue) -> f64 {
    match issue {
        IntersectionObserverSecurityIssue::CrossOriginVisibility => 7.0,
        IntersectionObserverSecurityIssue::ElementTimingAttack => 6.5,
        IntersectionObserverSecurityIssue::VisibilityTracking => 6.0,
        IntersectionObserverSecurityIssue::IntersectionWithStorage => 5.5,
        IntersectionObserverSecurityIssue::ViewportSizeLeakage => 5.0,
        IntersectionObserverSecurityIssue::LazyLoadFingerprint => 4.8,
        IntersectionObserverSecurityIssue::AdBlockDetection => 4.5,
        IntersectionObserverSecurityIssue::InfiniteScrollTracking => 4.2,
        IntersectionObserverSecurityIssue::ScrollJacking => 4.0,
        IntersectionObserverSecurityIssue::IntersectionInWorker => 3.8,
    }
}

pub fn intersection_observer_security_to_operations(
    issues: &[IntersectionObserverSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                intersection_observer_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
