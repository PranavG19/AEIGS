use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone)]
pub struct XfoIssue {
    pub value: String,
    pub kind: XfoIssueKind,
    pub severity: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum XfoIssueKind {
    AllowAll,
    InvalidValue,
    AllowFromDeprecated,
    MultipleHeaders,
}

impl std::fmt::Display for XfoIssueKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AllowAll => write!(f, "X-Frame-Options ALLOWALL permits framing by any origin"),
            Self::InvalidValue => write!(f, "unrecognized X-Frame-Options value"),
            Self::AllowFromDeprecated => {
                write!(
                    f,
                    "X-Frame-Options ALLOW-FROM is deprecated and ignored by modern browsers"
                )
            }
            Self::MultipleHeaders => {
                write!(
                    f,
                    "multiple X-Frame-Options headers cause undefined behavior"
                )
            }
        }
    }
}

pub fn audit_xfo(target: &str) -> Vec<XfoIssue> {
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

    let values: Vec<String> = resp
        .headers()
        .get_all("x-frame-options")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();

    analyze_xfo(&values)
}

pub fn analyze_xfo(values: &[String]) -> Vec<XfoIssue> {
    if values.is_empty() {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if values.len() > 1 {
        issues.push(XfoIssue {
            value: values.join(", "),
            kind: XfoIssueKind::MultipleHeaders,
            severity: 4.0,
        });
    }

    for value in values {
        let lower = value.trim().to_ascii_lowercase();
        match lower.as_str() {
            "deny" | "sameorigin" => {}
            "allowall" => {
                issues.push(XfoIssue {
                    value: value.clone(),
                    kind: XfoIssueKind::AllowAll,
                    severity: 6.0,
                });
            }
            v if v.starts_with("allow-from") => {
                issues.push(XfoIssue {
                    value: value.clone(),
                    kind: XfoIssueKind::AllowFromDeprecated,
                    severity: 4.0,
                });
            }
            _ => {
                issues.push(XfoIssue {
                    value: value.clone(),
                    kind: XfoIssueKind::InvalidValue,
                    severity: 3.0,
                });
            }
        }
    }

    issues
}

pub fn xfo_to_operations(issues: &[XfoIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
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
pub enum XfoSecurityIssue {
    MissingXfo,
    XfoWithCspFrameAncestors,
    AllowFromWildcard,
    AllowFromMultipleOrigins,
    XfoBypassViaDoubleFraming,
    XfoWithPermissiveCSP,
    XfoOnApiEndpoint,
    XfoWeakerThanCSP,
    XfoInconsistentAcrossPages,
    XfoMissingSameOriginPolicy,
}

impl std::fmt::Display for XfoSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingXfo => write!(
                f,
                "X-Frame-Options header is missing, allowing unrestricted framing"
            ),
            Self::XfoWithCspFrameAncestors => write!(
                f,
                "X-Frame-Options is redundant when CSP frame-ancestors is present"
            ),
            Self::AllowFromWildcard => write!(
                f,
                "ALLOW-FROM wildcard or insecure protocol permits unrestricted framing"
            ),
            Self::AllowFromMultipleOrigins => write!(
                f,
                "ALLOW-FROM with multiple origins is invalid and ignored by browsers"
            ),
            Self::XfoBypassViaDoubleFraming => {
                write!(f, "SAMEORIGIN is vulnerable to double-framing attacks")
            }
            Self::XfoWithPermissiveCSP => write!(
                f,
                "X-Frame-Options DENY is overridden by permissive CSP frame-ancestors"
            ),
            Self::XfoOnApiEndpoint => {
                write!(f, "X-Frame-Options on API endpoint is unnecessary overhead")
            }
            Self::XfoWeakerThanCSP => write!(
                f,
                "X-Frame-Options SAMEORIGIN is weaker than CSP frame-ancestors 'none'"
            ),
            Self::XfoInconsistentAcrossPages => write!(
                f,
                "inconsistent X-Frame-Options values across pages reduce protection"
            ),
            Self::XfoMissingSameOriginPolicy => write!(
                f,
                "X-Frame-Options allows same-origin framing without explicit DENY"
            ),
        }
    }
}

pub fn analyze_xfo_security(
    xfo_values: &[String],
    csp_header: Option<&str>,
    is_api: bool,
) -> Vec<XfoSecurityIssue> {
    let mut issues = Vec::new();

    if xfo_values.is_empty() {
        issues.push(XfoSecurityIssue::MissingXfo);
        return issues;
    }

    let normalized_values: Vec<String> = xfo_values
        .iter()
        .map(|v| v.trim().to_ascii_lowercase())
        .collect();

    if let Some(csp) = csp_header {
        let csp_lower = csp.to_ascii_lowercase();
        if csp_lower.contains("frame-ancestors") {
            issues.push(XfoSecurityIssue::XfoWithCspFrameAncestors);
        }

        let has_deny = normalized_values.iter().any(|v| v == "deny");
        let has_permissive_csp = csp_lower.contains("frame-ancestors *")
            || (!csp_lower.contains("frame-ancestors 'none'")
                && csp_lower.contains("frame-ancestors"));
        if has_deny && has_permissive_csp {
            issues.push(XfoSecurityIssue::XfoWithPermissiveCSP);
        }

        let has_sameorigin = normalized_values.iter().any(|v| v == "sameorigin");
        let has_strict_csp = csp_lower.contains("frame-ancestors 'none'");
        if has_sameorigin && has_strict_csp {
            issues.push(XfoSecurityIssue::XfoWeakerThanCSP);
        }
    }

    for value in &normalized_values {
        if value.starts_with("allow-from") {
            if value.contains("allow-from *") || value.contains("allow-from http") {
                issues.push(XfoSecurityIssue::AllowFromWildcard);
            }

            let after_allow_from = value.strip_prefix("allow-from").unwrap_or("").trim();
            let has_multiple = after_allow_from.contains(',')
                || after_allow_from
                    .split_whitespace()
                    .filter(|s| !s.is_empty())
                    .count()
                    > 1;
            if has_multiple {
                issues.push(XfoSecurityIssue::AllowFromMultipleOrigins);
            }
        }

        if value == "sameorigin" {
            issues.push(XfoSecurityIssue::XfoBypassViaDoubleFraming);
        }
    }

    if is_api {
        issues.push(XfoSecurityIssue::XfoOnApiEndpoint);
    }

    let has_deny = normalized_values.iter().any(|v| v == "deny");
    let has_sameorigin = normalized_values.iter().any(|v| v == "sameorigin");
    if has_deny && has_sameorigin {
        issues.push(XfoSecurityIssue::XfoInconsistentAcrossPages);
    }

    let all_valid = normalized_values
        .iter()
        .all(|v| v == "deny" || v == "sameorigin" || v.starts_with("allow-from"));
    if all_valid && !has_deny {
        issues.push(XfoSecurityIssue::XfoMissingSameOriginPolicy);
    }

    issues
}

pub fn xfo_security_severity(issue: &XfoSecurityIssue) -> f64 {
    match issue {
        XfoSecurityIssue::MissingXfo => 5.0,
        XfoSecurityIssue::XfoWithCspFrameAncestors => 2.0,
        XfoSecurityIssue::AllowFromWildcard => 7.0,
        XfoSecurityIssue::AllowFromMultipleOrigins => 5.5,
        XfoSecurityIssue::XfoBypassViaDoubleFraming => 6.0,
        XfoSecurityIssue::XfoWithPermissiveCSP => 6.5,
        XfoSecurityIssue::XfoOnApiEndpoint => 2.5,
        XfoSecurityIssue::XfoWeakerThanCSP => 4.0,
        XfoSecurityIssue::XfoInconsistentAcrossPages => 4.5,
        XfoSecurityIssue::XfoMissingSameOriginPolicy => 3.5,
    }
}

pub fn xfo_security_to_operations(
    issues: &[XfoSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues
        .iter()
        .map(xfo_security_severity)
        .fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        max_severity,
        0.9,
    )]
}
