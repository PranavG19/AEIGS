use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ResourceTimingIssue {
    TimingApiUsed,
    CrossOriginSizeLeak,
    PerformanceObserverUsed,
    HighResTimestamp,
    NavigationTimingLeak,
    MissingTimingAllowOrigin,
}

impl std::fmt::Display for ResourceTimingIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimingApiUsed => write!(f, "timing_api_used"),
            Self::CrossOriginSizeLeak => write!(f, "cross_origin_size_leak"),
            Self::PerformanceObserverUsed => write!(f, "performance_observer"),
            Self::HighResTimestamp => write!(f, "high_res_timestamp"),
            Self::NavigationTimingLeak => write!(f, "navigation_timing_leak"),
            Self::MissingTimingAllowOrigin => write!(f, "missing_timing_allow_origin"),
        }
    }
}

pub fn audit_resource_timing(target: &str) -> Vec<ResourceTimingIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let tao = resp
        .headers()
        .get("timing-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let body = resp.text().unwrap_or_default();
    analyze_resource_timing(&body, &tao)
}

pub fn analyze_resource_timing(body: &str, timing_allow_origin: &str) -> Vec<ResourceTimingIssue> {
    if !has_timing_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("getEntriesByType") || body.contains("getEntriesByName") {
        issues.push(ResourceTimingIssue::TimingApiUsed);
    }

    if has_size_leak_pattern(body) {
        issues.push(ResourceTimingIssue::CrossOriginSizeLeak);
    }

    if body.contains("PerformanceObserver") {
        issues.push(ResourceTimingIssue::PerformanceObserverUsed);
    }

    if body.contains("performance.now()") || body.contains("performance.timeOrigin") {
        issues.push(ResourceTimingIssue::HighResTimestamp);
    }

    if body.contains("performance.timing") || body.contains("performance.navigation") {
        issues.push(ResourceTimingIssue::NavigationTimingLeak);
    }

    if !issues.is_empty() && timing_allow_origin.is_empty() {
        issues.push(ResourceTimingIssue::MissingTimingAllowOrigin);
    }

    issues
}

fn has_timing_indicators(body: &str) -> bool {
    body.contains("performance.")
        || body.contains("PerformanceObserver")
        || body.contains("transferSize")
        || body.contains("encodedBodySize")
        || body.contains("decodedBodySize")
        || body.contains("responseStart")
}

fn has_size_leak_pattern(body: &str) -> bool {
    body.contains("transferSize")
        || body.contains("encodedBodySize")
        || body.contains("decodedBodySize")
        || body.contains("responseStart")
            && (body.contains("requestStart") || body.contains("fetchStart"))
}

pub fn resource_timing_severity(issue: &ResourceTimingIssue) -> f64 {
    match issue {
        ResourceTimingIssue::CrossOriginSizeLeak => 6.0,
        ResourceTimingIssue::NavigationTimingLeak => 5.5,
        ResourceTimingIssue::HighResTimestamp => 4.5,
        ResourceTimingIssue::PerformanceObserverUsed => 4.0,
        ResourceTimingIssue::TimingApiUsed => 3.5,
        ResourceTimingIssue::MissingTimingAllowOrigin => 3.0,
    }
}

pub fn resource_timing_to_operations(
    issues: &[ResourceTimingIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                resource_timing_severity(issue),
                0.7,
            )
        })
        .collect()
}
