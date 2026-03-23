use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum ContentVisibilityIssue {
    ApiDetected,
    HiddenContentXss,
    RenderingTimingLeak,
    ContentExfiltration,
    SecurityControlBypass,
}

impl std::fmt::Display for ContentVisibilityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::ApiDetected => "api_detected",
            Self::HiddenContentXss => "hidden_content_xss",
            Self::RenderingTimingLeak => "rendering_timing_leak",
            Self::ContentExfiltration => "content_exfiltration",
            Self::SecurityControlBypass => "security_control_bypass",
        };
        write!(f, "{}", s)
    }
}

pub fn audit_content_visibility(target: &str) -> Vec<ContentVisibilityIssue> {
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
    analyze_content_visibility(&body)
}

pub fn analyze_content_visibility(body: &str) -> Vec<ContentVisibilityIssue> {
    let mut issues = Vec::new();

    let has_content_visibility = body.contains("content-visibility")
        || body.contains("contentVisibility")
        || body.contains("contain-intrinsic-size");

    if has_content_visibility {
        issues.push(ContentVisibilityIssue::ApiDetected);
    }

    let has_hidden =
        body.contains("content-visibility: hidden") || body.contains("content-visibility:hidden");
    let has_xss_vectors = body.contains("innerHTML")
        || body.contains("insertAdjacentHTML")
        || body.contains("document.write");
    if has_hidden && has_xss_vectors {
        issues.push(ContentVisibilityIssue::HiddenContentXss);
    }

    let has_observers =
        body.contains("IntersectionObserver") || body.contains("contentvisibilityautostatechange");
    let has_timing = body.contains("performance.now") || body.contains("Date.now");
    if has_content_visibility && has_observers && has_timing {
        issues.push(ContentVisibilityIssue::RenderingTimingLeak);
    }

    let has_mutation = body.contains("MutationObserver") || body.contains("querySelectorAll");
    let has_exfil = body.contains("fetch(") || body.contains("sendBeacon");
    if has_content_visibility && has_mutation && has_exfil {
        issues.push(ContentVisibilityIssue::ContentExfiltration);
    }

    let has_security_ui = body.contains("captcha")
        || body.contains("csrf")
        || body.contains("consent")
        || body.contains("security")
        || body.contains("warning");
    if has_content_visibility && has_security_ui {
        issues.push(ContentVisibilityIssue::SecurityControlBypass);
    }

    issues
}

pub fn content_visibility_severity(issue: &ContentVisibilityIssue) -> f64 {
    match issue {
        ContentVisibilityIssue::ApiDetected => 2.0,
        ContentVisibilityIssue::HiddenContentXss => 7.5,
        ContentVisibilityIssue::RenderingTimingLeak => 6.5,
        ContentVisibilityIssue::ContentExfiltration => 7.0,
        ContentVisibilityIssue::SecurityControlBypass => 6.0,
    }
}

pub fn content_visibility_to_operations(
    issues: &[ContentVisibilityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                content_visibility_severity(issue),
                0.5,
            )
        })
        .collect()
}
