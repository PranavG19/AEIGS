use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ClickjackIssue {
    NoFrameProtection,
    XfoOnlyNoFrameAncestors,
    FrameAncestorsWildcard,
    FrameAncestorsNone,
    ConflictingPolicies { xfo: String, csp_fa: String },
}

impl std::fmt::Display for ClickjackIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoFrameProtection => write!(f, "no_frame_protection"),
            Self::XfoOnlyNoFrameAncestors => write!(f, "xfo_only_no_frame_ancestors"),
            Self::FrameAncestorsWildcard => write!(f, "frame_ancestors_wildcard"),
            Self::FrameAncestorsNone => write!(f, "frame_ancestors_none"),
            Self::ConflictingPolicies { xfo, csp_fa } => {
                write!(f, "conflicting_policies:{xfo}|{csp_fa}")
            }
        }
    }
}

pub fn audit_clickjacking(target: &str) -> Vec<ClickjackIssue> {
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

    let xfo = resp
        .headers()
        .get("x-frame-options")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let csp = resp
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    analyze_frame_protection(xfo.as_deref(), csp.as_deref())
}

pub(crate) fn analyze_frame_protection(
    xfo: Option<&str>,
    csp: Option<&str>,
) -> Vec<ClickjackIssue> {
    let mut issues = Vec::new();
    let frame_ancestors = csp.and_then(extract_frame_ancestors);

    match (xfo, &frame_ancestors) {
        (None, None) => {
            issues.push(ClickjackIssue::NoFrameProtection);
        }
        (Some(_), None) => {
            issues.push(ClickjackIssue::XfoOnlyNoFrameAncestors);
        }
        (_, Some(fa)) => {
            let fa_trimmed = fa.trim();
            if fa_trimmed == "*" {
                issues.push(ClickjackIssue::FrameAncestorsWildcard);
            }
            if fa_trimmed == "'none'" {
                issues.push(ClickjackIssue::FrameAncestorsNone);
            }
            if let Some(xfo_val) = xfo {
                let xfo_lower = xfo_val.trim().to_ascii_lowercase();
                let fa_lower = fa_trimmed.to_ascii_lowercase();
                let xfo_denies = xfo_lower == "deny";
                let fa_allows = fa_lower != "'none'" && fa_lower != "'self'";
                let xfo_allows_same = xfo_lower == "sameorigin";
                let fa_denies = fa_lower == "'none'";
                if (xfo_denies && fa_allows) || (xfo_allows_same && fa_denies) {
                    issues.push(ClickjackIssue::ConflictingPolicies {
                        xfo: xfo_val.to_string(),
                        csp_fa: fa_trimmed.to_string(),
                    });
                }
            }
        }
    }

    issues
}

fn extract_frame_ancestors(csp: &str) -> Option<String> {
    let lower = csp.to_ascii_lowercase();
    for directive in lower.split(';') {
        let trimmed = directive.trim();
        if let Some(value) = trimmed.strip_prefix("frame-ancestors") {
            return Some(value.trim().to_string());
        }
    }
    None
}

pub(crate) fn clickjack_severity(issue: &ClickjackIssue) -> f64 {
    match issue {
        ClickjackIssue::NoFrameProtection => 6.0,
        ClickjackIssue::FrameAncestorsWildcard => 5.5,
        ClickjackIssue::ConflictingPolicies { .. } => 5.0,
        ClickjackIssue::XfoOnlyNoFrameAncestors => 3.5,
        ClickjackIssue::FrameAncestorsNone => 1.0,
    }
}

pub fn clickjack_to_operations(
    issues: &[ClickjackIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .filter(|i| clickjack_severity(i) >= 3.0)
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::Clickjacking,
                clickjack_severity(issue),
                0.9,
            )
        })
        .collect()
}
