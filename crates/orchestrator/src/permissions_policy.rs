use std::fmt;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const SENSITIVE_FEATURES: &[&str] = &[
    "camera",
    "microphone",
    "geolocation",
    "payment",
    "usb",
    "bluetooth",
    "serial",
    "hid",
];

#[derive(Debug, Clone)]
pub struct PermissionsPolicyIssue {
    pub kind: PolicyIssueKind,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub enum PolicyIssueKind {
    MissingHeader,
    WildcardAllowlist,
    SensitiveFeatureUnrestricted,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyIssue {
    MissingPolicy,
    WildcardAllowlist { feature: String },
    SensitiveUnrestricted { feature: String },
    DeprecatedFeaturePolicy,
    SelfOriginOnly { feature: String },
    ThirdPartyAllowed { feature: String, origin: String },
    EmptyPolicy,
    InvalidDirective { directive: String },
    AllFeaturesUnrestricted,
    InterestCohortNotBlocked,
}

impl fmt::Display for PolicyIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPolicy => write!(f, "missing_policy"),
            Self::WildcardAllowlist { feature } => write!(f, "wildcard_allowlist:{feature}"),
            Self::SensitiveUnrestricted { feature } => {
                write!(f, "sensitive_unrestricted:{feature}")
            }
            Self::DeprecatedFeaturePolicy => write!(f, "deprecated_feature_policy"),
            Self::SelfOriginOnly { feature } => write!(f, "self_origin_only:{feature}"),
            Self::ThirdPartyAllowed { feature, origin } => {
                write!(f, "third_party_allowed:{feature}:{origin}")
            }
            Self::EmptyPolicy => write!(f, "empty_policy"),
            Self::InvalidDirective { directive } => write!(f, "invalid_directive:{directive}"),
            Self::AllFeaturesUnrestricted => write!(f, "all_features_unrestricted"),
            Self::InterestCohortNotBlocked => write!(f, "interest_cohort_not_blocked"),
        }
    }
}

pub fn policy_issue_severity(issue: &PolicyIssue) -> f64 {
    match issue {
        PolicyIssue::MissingPolicy => 3.0,
        PolicyIssue::WildcardAllowlist { .. } => 4.0,
        PolicyIssue::SensitiveUnrestricted { .. } => 3.5,
        PolicyIssue::DeprecatedFeaturePolicy => 2.0,
        PolicyIssue::SelfOriginOnly { .. } => 1.5,
        PolicyIssue::ThirdPartyAllowed { .. } => 3.0,
        PolicyIssue::EmptyPolicy => 2.5,
        PolicyIssue::InvalidDirective { .. } => 2.0,
        PolicyIssue::AllFeaturesUnrestricted => 4.5,
        PolicyIssue::InterestCohortNotBlocked => 2.5,
    }
}

pub fn check_permissions_policy(target: &str) -> Vec<PermissionsPolicyIssue> {
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

    let pp_header = resp
        .headers()
        .get("permissions-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let fp_header = resp
        .headers()
        .get("feature-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let header_value = pp_header.or(fp_header);

    match header_value {
        None => vec![PermissionsPolicyIssue {
            kind: PolicyIssueKind::MissingHeader,
            detail: "No Permissions-Policy or Feature-Policy header present".to_string(),
        }],
        Some(value) => analyze_policy(&value),
    }
}

pub fn analyze_policy(value: &str) -> Vec<PermissionsPolicyIssue> {
    let mut issues = Vec::new();

    if value.contains("=*") {
        issues.push(PermissionsPolicyIssue {
            kind: PolicyIssueKind::WildcardAllowlist,
            detail: "Policy contains wildcard (*) allowlist".to_string(),
        });
    }

    let restricted: Vec<&str> = value
        .split(',')
        .filter_map(|directive| {
            let directive = directive.trim();
            let name = directive.split('=').next()?.trim();
            if directive.contains("=()") {
                Some(name)
            } else {
                None
            }
        })
        .collect();

    for feature in SENSITIVE_FEATURES {
        if !restricted.contains(feature) && !value.contains(&format!("{feature}=()")) {
            issues.push(PermissionsPolicyIssue {
                kind: PolicyIssueKind::SensitiveFeatureUnrestricted,
                detail: format!("Sensitive feature '{feature}' not explicitly restricted"),
            });
        }
    }

    issues
}

pub fn issue_severity(issue: &PermissionsPolicyIssue) -> f64 {
    match issue.kind {
        PolicyIssueKind::MissingHeader => 3.0,
        PolicyIssueKind::WildcardAllowlist => 4.0,
        PolicyIssueKind::SensitiveFeatureUnrestricted => 2.5,
    }
}

pub fn policy_findings_to_operations(
    issues: &[PermissionsPolicyIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let is_missing = issues
        .iter()
        .any(|i| matches!(i.kind, PolicyIssueKind::MissingHeader));

    let vuln_class = if is_missing {
        VulnerabilityClass::MissingSecurityHeader
    } else {
        VulnerabilityClass::SecurityMisconfiguration
    };

    let max_severity = issues.iter().map(issue_severity).fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        vuln_class,
        max_severity,
        0.9,
    )]
}

pub fn analyze_permissions_policy(value: &str) -> Vec<PolicyIssue> {
    let mut issues = Vec::new();
    let trimmed = value.trim();

    if trimmed.is_empty() {
        issues.push(PolicyIssue::EmptyPolicy);
        return issues;
    }

    let directives: Vec<&str> = trimmed.split(',').map(|d| d.trim()).collect();
    let mut any_restricted = false;

    for directive in &directives {
        let directive = directive.trim();
        if directive.is_empty() {
            continue;
        }

        let Some((name, allowlist)) = directive.split_once('=') else {
            issues.push(PolicyIssue::InvalidDirective {
                directive: directive.to_string(),
            });
            continue;
        };

        let name = name.trim();
        let allowlist = allowlist.trim();

        if allowlist == "*" {
            issues.push(PolicyIssue::WildcardAllowlist {
                feature: name.to_string(),
            });
        } else if allowlist == "()" {
            any_restricted = true;
        } else if allowlist == "(self)" || allowlist == "self" {
            any_restricted = true;
            if SENSITIVE_FEATURES.contains(&name) {
                issues.push(PolicyIssue::SelfOriginOnly {
                    feature: name.to_string(),
                });
            }
        } else if allowlist.starts_with('(') && allowlist.ends_with(')') {
            any_restricted = true;
            let inner = &allowlist[1..allowlist.len() - 1];
            for token in inner.split_whitespace() {
                let token = token.trim_matches('"');
                if token == "self" || token == "*" {
                    continue;
                }
                issues.push(PolicyIssue::ThirdPartyAllowed {
                    feature: name.to_string(),
                    origin: token.to_string(),
                });
            }
        } else {
            issues.push(PolicyIssue::InvalidDirective {
                directive: directive.to_string(),
            });
        }
    }

    for feature in SENSITIVE_FEATURES {
        let is_mentioned = directives.iter().any(|d| {
            d.split_once('=')
                .map(|(n, _)| n.trim() == *feature)
                .unwrap_or(false)
        });
        if !is_mentioned {
            issues.push(PolicyIssue::SensitiveUnrestricted {
                feature: feature.to_string(),
            });
        }
    }

    if !any_restricted && !issues.iter().any(|i| matches!(i, PolicyIssue::EmptyPolicy)) {
        issues.push(PolicyIssue::AllFeaturesUnrestricted);
    }

    let has_interest_cohort = directives.iter().any(|d| {
        d.split_once('=')
            .map(|(n, a)| n.trim() == "interest-cohort" && a.trim() == "()")
            .unwrap_or(false)
    });
    if !has_interest_cohort {
        issues.push(PolicyIssue::InterestCohortNotBlocked);
    }

    issues
}

pub fn policy_issues_to_operations(
    issues: &[PolicyIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            let vuln_class = match issue {
                PolicyIssue::MissingPolicy => VulnerabilityClass::MissingSecurityHeader,
                _ => VulnerabilityClass::SecurityMisconfiguration,
            };
            recon_client::finding_entry(seq, vuln_class, policy_issue_severity(issue), 0.5)
        })
        .collect()
}
