use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum TextFragmentIssue {
    ApiDetected,
    ContentExfiltration,
    CrossOriginLeak,
    PrivacyViolation,
    PhishingAmplification,
}

impl std::fmt::Display for TextFragmentIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::ContentExfiltration => write!(f, "content_exfiltration"),
            Self::CrossOriginLeak => write!(f, "cross_origin_leak"),
            Self::PrivacyViolation => write!(f, "privacy_violation"),
            Self::PhishingAmplification => write!(f, "phishing_amplification"),
        }
    }
}

pub fn audit_text_fragment(target: &str) -> Vec<TextFragmentIssue> {
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
    analyze_text_fragment(&body)
}

pub fn analyze_text_fragment(body: &str) -> Vec<TextFragmentIssue> {
    let has_hash = body.contains("#:~:text=");
    let has_directive = body.contains("fragmentDirective");
    let has_text_fragment = body.contains("TextFragment");

    if !has_hash && !has_directive && !has_text_fragment {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(TextFragmentIssue::ApiDetected);

    let has_network =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if (has_hash || has_directive) && has_network {
        issues.push(TextFragmentIssue::ContentExfiltration);
    }

    if (has_directive || has_text_fragment)
        && (body.contains("referrer")
            || body.contains("Referer")
            || body.contains("document.referrer"))
    {
        issues.push(TextFragmentIssue::CrossOriginLeak);
    }

    if (has_hash || has_text_fragment)
        && (body.contains("scrollIntoView") || body.contains("IntersectionObserver"))
        && (body.contains("analytics") || body.contains("track") || body.contains("beacon"))
    {
        issues.push(TextFragmentIssue::PrivacyViolation);
    }

    if (has_hash || has_text_fragment)
        && (body.contains("href") || body.contains("window.open") || body.contains("location"))
        && (body.contains("password") || body.contains("login") || body.contains("credential"))
    {
        issues.push(TextFragmentIssue::PhishingAmplification);
    }

    issues
}

pub fn text_fragment_severity(issue: &TextFragmentIssue) -> f64 {
    match issue {
        TextFragmentIssue::ContentExfiltration => 7.0,
        TextFragmentIssue::CrossOriginLeak => 6.5,
        TextFragmentIssue::PrivacyViolation => 6.0,
        TextFragmentIssue::PhishingAmplification => 5.5,
        TextFragmentIssue::ApiDetected => 2.0,
    }
}

pub fn text_fragment_to_operations(
    issues: &[TextFragmentIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                text_fragment_severity(issue),
                0.5,
            )
        })
        .collect()
}
