use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const SAFE_POLICIES: &[&str] = &[
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
];

const UNSAFE_POLICIES: &[(&str, f64)] = &[
    ("unsafe-url", 5.0),
    ("no-referrer-when-downgrade", 3.5),
    ("origin-when-cross-origin", 2.5),
    ("origin", 2.0),
];

#[derive(Debug, Clone)]
pub struct ReferrerPolicyIssue {
    pub policy: String,
    pub kind: ReferrerIssueKind,
    pub severity: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReferrerIssueKind {
    UnsafePolicy,
    MultiplePolicies,
    InvalidPolicy,
}

impl std::fmt::Display for ReferrerIssueKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafePolicy => write!(f, "unsafe referrer policy leaks URL information"),
            Self::MultiplePolicies => write!(f, "multiple referrer policies may cause confusion"),
            Self::InvalidPolicy => write!(f, "unrecognized referrer policy value"),
        }
    }
}

pub fn audit_referrer_policy(target: &str) -> Vec<ReferrerPolicyIssue> {
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

    let header_value = match resp.headers().get("referrer-policy") {
        Some(v) => match v.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return Vec::new(),
        },
        None => return Vec::new(),
    };

    analyze_referrer_policy(&header_value)
}

pub(crate) fn analyze_referrer_policy(value: &str) -> Vec<ReferrerPolicyIssue> {
    let mut issues = Vec::new();
    let policies: Vec<&str> = value.split(',').map(|s| s.trim()).collect();

    if policies.len() > 1 {
        issues.push(ReferrerPolicyIssue {
            policy: value.to_string(),
            kind: ReferrerIssueKind::MultiplePolicies,
            severity: 2.0,
        });
    }

    let effective = policies.last().unwrap_or(&"");
    let lower = effective.to_ascii_lowercase();

    if SAFE_POLICIES.contains(&lower.as_str()) {
        return issues;
    }

    for (policy, severity) in UNSAFE_POLICIES {
        if lower == *policy {
            issues.push(ReferrerPolicyIssue {
                policy: lower.clone(),
                kind: ReferrerIssueKind::UnsafePolicy,
                severity: *severity,
            });
            return issues;
        }
    }

    if !lower.is_empty() {
        issues.push(ReferrerPolicyIssue {
            policy: lower,
            kind: ReferrerIssueKind::InvalidPolicy,
            severity: 2.0,
        });
    }

    issues
}

pub fn referrer_to_operations(
    issues: &[ReferrerPolicyIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues.iter().map(|i| i.severity).fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        max_severity,
        0.9,
    )]
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReferrerSecurityIssue {
    UnsafeUrlPolicy,
    NoReferrerWhenDowngrade,
    OriginCrossOrigin,
    MissingReferrerPolicy,
    ConflictingPolicies,
    ReferrerInMetaTag,
    LinkWithNoReferrer,
    FormWithoutReferrer,
    CrossOriginLinkLeak,
    TokenInReferrer,
}

impl std::fmt::Display for ReferrerSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafeUrlPolicy => write!(
                f,
                "unsafe-url policy leaks full URL including path and query"
            ),
            Self::NoReferrerWhenDowngrade => write!(
                f,
                "no-referrer-when-downgrade leaks referrer on HTTPS to HTTP"
            ),
            Self::OriginCrossOrigin => {
                write!(f, "origin-when-cross-origin may leak path information")
            }
            Self::MissingReferrerPolicy => write!(
                f,
                "missing referrer policy relies on insecure browser default"
            ),
            Self::ConflictingPolicies => {
                write!(f, "meta tag and header referrer policies conflict")
            }
            Self::ReferrerInMetaTag => {
                write!(f, "referrer policy set via meta tag is weaker than header")
            }
            Self::LinkWithNoReferrer => write!(
                f,
                "selective rel=noreferrer on links may leak from other links"
            ),
            Self::FormWithoutReferrer => {
                write!(f, "forms missing referrer-policy attribute may leak data")
            }
            Self::CrossOriginLinkLeak => write!(
                f,
                "external links without noreferrer leak referrer information"
            ),
            Self::TokenInReferrer => {
                write!(f, "sensitive tokens detected in referrer-leaking URLs")
            }
        }
    }
}

pub fn analyze_referrer_security(
    referrer_policy: Option<&str>,
    html: &str,
) -> Vec<ReferrerSecurityIssue> {
    let mut issues = Vec::new();

    let has_header_policy = referrer_policy.is_some();
    let header_policy_str = referrer_policy.unwrap_or("");

    let meta_policy = extract_meta_referrer_policy(html);

    if let Some(ref meta_policy_val) = meta_policy {
        if has_header_policy && !meta_policy_val.eq_ignore_ascii_case(header_policy_str) {
            issues.push(ReferrerSecurityIssue::ConflictingPolicies);
        }
        if has_header_policy || !meta_policy_val.is_empty() {
            issues.push(ReferrerSecurityIssue::ReferrerInMetaTag);
        }
    }

    let effective_policy = if has_header_policy {
        header_policy_str
    } else {
        meta_policy.as_deref().unwrap_or("")
    };

    if effective_policy.is_empty() {
        issues.push(ReferrerSecurityIssue::MissingReferrerPolicy);
    } else if effective_policy.eq_ignore_ascii_case("unsafe-url") {
        issues.push(ReferrerSecurityIssue::UnsafeUrlPolicy);
    } else if effective_policy.eq_ignore_ascii_case("no-referrer-when-downgrade") {
        issues.push(ReferrerSecurityIssue::NoReferrerWhenDowngrade);
    } else if effective_policy.eq_ignore_ascii_case("origin-when-cross-origin") {
        issues.push(ReferrerSecurityIssue::OriginCrossOrigin);
    }

    let has_noreferrer_links =
        html.contains("rel=\"noreferrer\"") || html.contains("rel='noreferrer'");
    let has_external_links = count_external_links(html) > 0;

    if has_noreferrer_links && has_external_links {
        issues.push(ReferrerSecurityIssue::LinkWithNoReferrer);
    }

    if has_external_links && !is_safe_referrer_policy(effective_policy) && !has_noreferrer_links {
        issues.push(ReferrerSecurityIssue::CrossOriginLinkLeak);
    }

    if count_forms_without_referrer_policy(html) > 0 {
        issues.push(ReferrerSecurityIssue::FormWithoutReferrer);
    }

    if has_token_in_url(html) {
        issues.push(ReferrerSecurityIssue::TokenInReferrer);
    }

    issues
}

pub fn referrer_security_severity(issue: &ReferrerSecurityIssue) -> f64 {
    match issue {
        ReferrerSecurityIssue::UnsafeUrlPolicy => 5.0,
        ReferrerSecurityIssue::TokenInReferrer => 5.0,
        ReferrerSecurityIssue::NoReferrerWhenDowngrade => 4.0,
        ReferrerSecurityIssue::CrossOriginLinkLeak => 3.5,
        ReferrerSecurityIssue::OriginCrossOrigin => 3.0,
        ReferrerSecurityIssue::MissingReferrerPolicy => 2.5,
        ReferrerSecurityIssue::ConflictingPolicies => 2.5,
        ReferrerSecurityIssue::FormWithoutReferrer => 2.5,
        ReferrerSecurityIssue::ReferrerInMetaTag => 2.0,
        ReferrerSecurityIssue::LinkWithNoReferrer => 1.5,
    }
}

pub fn referrer_security_to_operations(
    issues: &[ReferrerSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues
        .iter()
        .map(referrer_security_severity)
        .fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        max_severity,
        0.5,
    )]
}

fn extract_meta_referrer_policy(html: &str) -> Option<String> {
    let html_lower = html.to_ascii_lowercase();
    if let Some(start) = html_lower.find("<meta name=\"referrer\"") {
        let after_tag = &html_lower[start..];
        if let Some(content_start) = after_tag.find("content=\"") {
            let content_offset = content_start + 9;
            let content_part = &after_tag[content_offset..];
            if let Some(end) = content_part.find('"') {
                return Some(content_part[..end].to_string());
            }
        }
    }
    None
}

fn count_external_links(html: &str) -> usize {
    let mut count = 0;
    let html_lower = html.to_ascii_lowercase();
    let patterns = ["http://", "https://"];

    for pattern in &patterns {
        let mut pos = 0;
        while let Some(idx) = html_lower[pos..].find(pattern) {
            let absolute_idx = pos + idx;
            if absolute_idx > 10 {
                let before = &html_lower[absolute_idx.saturating_sub(10)..absolute_idx];
                if before.contains("href=") {
                    count += 1;
                }
            }
            pos = absolute_idx + pattern.len();
        }
    }

    count
}

fn count_forms_without_referrer_policy(html: &str) -> usize {
    let html_lower = html.to_ascii_lowercase();
    let mut count = 0;
    let mut pos = 0;

    while let Some(form_idx) = html_lower[pos..].find("<form") {
        let absolute_idx = pos + form_idx;
        let after_form = &html_lower[absolute_idx..];
        if let Some(end_tag) = after_form.find('>') {
            let form_tag = &after_form[..end_tag];
            if !form_tag.contains("referrerpolicy=") {
                count += 1;
            }
            pos = absolute_idx + end_tag + 1;
        } else {
            break;
        }
    }

    count
}

fn is_safe_referrer_policy(policy: &str) -> bool {
    let lower = policy.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "no-referrer" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin"
    )
}

fn has_token_in_url(html: &str) -> bool {
    let html_lower = html.to_ascii_lowercase();
    let token_patterns = ["token=", "api_key=", "apikey=", "key=", "secret=", "auth="];

    for pattern in &token_patterns {
        if html_lower.contains(pattern) {
            return true;
        }
    }

    false
}
