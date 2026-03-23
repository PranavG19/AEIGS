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

    let max_severity = issues
        .iter()
        .map(|i| i.severity)
        .fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        max_severity,
        0.9,
    )]
}
