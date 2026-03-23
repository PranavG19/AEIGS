use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum WebVitalsIssue {
    ApiDetected,
    MetricExfiltration,
    TimingFingerprinting,
    UserBehaviorTracking,
    ResourceTimingLeak,
}

impl std::fmt::Display for WebVitalsIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            WebVitalsIssue::ApiDetected => "api_detected",
            WebVitalsIssue::MetricExfiltration => "metric_exfiltration",
            WebVitalsIssue::TimingFingerprinting => "timing_fingerprinting",
            WebVitalsIssue::UserBehaviorTracking => "user_behavior_tracking",
            WebVitalsIssue::ResourceTimingLeak => "resource_timing_leak",
        };
        write!(f, "{}", s)
    }
}

pub fn audit_web_vitals(target: &str) -> Vec<WebVitalsIssue> {
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
    analyze_web_vitals(&body)
}

pub fn analyze_web_vitals(body: &str) -> Vec<WebVitalsIssue> {
    let mut issues = Vec::new();

    let has_web_vitals_api = body.contains("web-vitals")
        || body.contains("getCLS")
        || body.contains("getFID")
        || body.contains("getLCP")
        || body.contains("getINP")
        || body.contains("getTTFB");

    if has_web_vitals_api {
        issues.push(WebVitalsIssue::ApiDetected);

        let has_exfiltration = (body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("XMLHttpRequest"))
            && (body.contains("http://") || body.contains("https://"))
            && !body.contains("location.origin")
            && !body.contains("same-origin");

        if has_exfiltration {
            issues.push(WebVitalsIssue::MetricExfiltration);
        }

        let has_timing_fingerprinting = (body.contains("PerformanceObserver")
            || body.contains("performance.getEntries")
            || body.contains("performance.now"))
            && (body.contains("fingerprint")
                || body.contains("unique")
                || body.contains("hash")
                || body.contains("identity"));

        if has_timing_fingerprinting {
            issues.push(WebVitalsIssue::TimingFingerprinting);
        }

        let has_behavior_tracking = (body.contains("click")
            || body.contains("scroll")
            || body.contains("input")
            || body.contains("mousemove"))
            && (body.contains("track") || body.contains("analytics") || body.contains("monitor"));

        if has_behavior_tracking {
            issues.push(WebVitalsIssue::UserBehaviorTracking);
        }

        let has_resource_timing_leak = body.contains("PerformanceResourceTiming")
            || body.contains("transferSize")
            || body.contains("encodedBodySize")
            || body.contains("serverTiming");

        if has_resource_timing_leak {
            issues.push(WebVitalsIssue::ResourceTimingLeak);
        }
    }

    issues
}

pub fn web_vitals_severity(issue: &WebVitalsIssue) -> f64 {
    match issue {
        WebVitalsIssue::ApiDetected => 2.0,
        WebVitalsIssue::MetricExfiltration => 7.0,
        WebVitalsIssue::TimingFingerprinting => 6.5,
        WebVitalsIssue::UserBehaviorTracking => 6.0,
        WebVitalsIssue::ResourceTimingLeak => 5.5,
    }
}

pub fn web_vitals_to_operations(
    issues: &[WebVitalsIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                web_vitals_severity(issue),
                0.5,
            )
        })
        .collect()
}
