use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ContentIndexIssue {
    ApiDetected,
    OfflineContentInjection,
    IndexEnumeration,
    PhishingContent,
    SilentRegistration,
    ExcessiveEntries,
}

impl std::fmt::Display for ContentIndexIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::OfflineContentInjection => write!(f, "offline_content_injection"),
            Self::IndexEnumeration => write!(f, "index_enumeration"),
            Self::PhishingContent => write!(f, "phishing_content"),
            Self::SilentRegistration => write!(f, "silent_registration"),
            Self::ExcessiveEntries => write!(f, "excessive_entries"),
        }
    }
}

pub fn audit_content_index(target: &str) -> Vec<ContentIndexIssue> {
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
    analyze_content_index(&body)
}

pub fn analyze_content_index(body: &str) -> Vec<ContentIndexIssue> {
    if !body.contains("ContentIndex") && !body.contains("contentIndex") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(ContentIndexIssue::ApiDetected);

    let has_add = body.contains(".add(");
    if has_add {
        if !body.contains("click") && !body.contains("submit") && !body.contains("pointerdown") {
            issues.push(ContentIndexIssue::SilentRegistration);
        }

        if body.contains("url:") && (body.contains("http://") || body.contains("data:")) {
            issues.push(ContentIndexIssue::OfflineContentInjection);
        }

        if body.contains("login")
            || body.contains("password")
            || body.contains("bank")
            || body.contains("verify")
        {
            issues.push(ContentIndexIssue::PhishingContent);
        }

        if body.contains("for(")
            || body.contains("for ")
            || body.contains("forEach")
            || body.contains("map(")
        {
            issues.push(ContentIndexIssue::ExcessiveEntries);
        }
    }

    if body.contains("getAll(") {
        issues.push(ContentIndexIssue::IndexEnumeration);
    }

    issues
}

pub fn content_index_severity(issue: &ContentIndexIssue) -> f64 {
    match issue {
        ContentIndexIssue::PhishingContent => 7.5,
        ContentIndexIssue::OfflineContentInjection => 7.0,
        ContentIndexIssue::ExcessiveEntries => 5.5,
        ContentIndexIssue::SilentRegistration => 5.0,
        ContentIndexIssue::IndexEnumeration => 4.5,
        ContentIndexIssue::ApiDetected => 2.5,
    }
}

pub fn content_index_to_operations(
    issues: &[ContentIndexIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                content_index_severity(issue),
                0.6,
            )
        })
        .collect()
}
