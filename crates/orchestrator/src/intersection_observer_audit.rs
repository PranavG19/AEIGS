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
