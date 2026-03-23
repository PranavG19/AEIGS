use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;
use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum PriorityHintsIssue {
    ApiDetected,
    HighPriorityTracker,
    LowPriorityCSP,
    ResourcePrioritySpoofing,
    PreloadAbuse,
}

impl std::fmt::Display for PriorityHintsIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::ApiDetected => "api_detected",
            Self::HighPriorityTracker => "high_priority_tracker",
            Self::LowPriorityCSP => "low_priority_csp",
            Self::ResourcePrioritySpoofing => "resource_priority_spoofing",
            Self::PreloadAbuse => "preload_abuse",
        };
        write!(f, "{}", s)
    }
}

pub fn audit_priority_hints(target: &str) -> Vec<PriorityHintsIssue> {
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
    analyze_priority_hints(&body)
}

pub fn analyze_priority_hints(body: &str) -> Vec<PriorityHintsIssue> {
    let mut issues = Vec::new();

    let has_fetchpriority = body.contains("fetchpriority");
    let has_fetchpriority_camel = body.contains("fetchPriority");
    let has_importance = body.contains("importance");

    if has_fetchpriority || has_fetchpriority_camel || has_importance {
        issues.push(PriorityHintsIssue::ApiDetected);
    }

    // HighPriorityTracker: tracking scripts given high priority
    if (body.contains("fetchpriority=\"high\"") || body.contains("fetchPriority")) &&
       (body.contains("analytics") || body.contains("tracking") ||
        body.contains("beacon") || body.contains("pixel")) {
        issues.push(PriorityHintsIssue::HighPriorityTracker);
    }

    // LowPriorityCSP: security resources deprioritized
    if body.contains("fetchpriority=\"low\"") &&
       (body.contains("csp-report") || body.contains("security") ||
        body.contains("integrity") || body.contains("nonce")) {
        issues.push(PriorityHintsIssue::LowPriorityCSP);
    }

    // ResourcePrioritySpoofing: dynamic priority manipulation
    if body.contains("fetchPriority") &&
       (body.contains("setAttribute") || body.contains("createElement")) &&
       !body.contains("static") && !body.contains("readonly") {
        issues.push(PriorityHintsIssue::ResourcePrioritySpoofing);
    }

    // PreloadAbuse: preload combined with priority to force resource loading
    if body.contains("fetchpriority") &&
       (body.contains("preload") || body.contains("prefetch") || body.contains("prerender")) &&
       (body.contains("script") || body.contains("style")) {
        issues.push(PriorityHintsIssue::PreloadAbuse);
    }

    issues
}

pub fn priority_hints_severity(issue: &PriorityHintsIssue) -> f64 {
    match issue {
        PriorityHintsIssue::ApiDetected => 2.0,
        PriorityHintsIssue::HighPriorityTracker => 6.5,
        PriorityHintsIssue::LowPriorityCSP => 7.0,
        PriorityHintsIssue::ResourcePrioritySpoofing => 5.5,
        PriorityHintsIssue::PreloadAbuse => 6.0,
    }
}

pub fn priority_hints_to_operations(
    issues: &[PriorityHintsIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                priority_hints_severity(issue),
                0.5,
            )
        })
        .collect()
}
