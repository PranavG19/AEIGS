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

pub(crate) fn analyze_policy(value: &str) -> Vec<PermissionsPolicyIssue> {
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

fn issue_severity(issue: &PermissionsPolicyIssue) -> f64 {
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
