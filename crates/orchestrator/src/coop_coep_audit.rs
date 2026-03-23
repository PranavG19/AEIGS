use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone)]
pub struct CoopCoepIssue {
    pub header: String,
    pub kind: CoopCoepIssueKind,
    pub severity: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CoopCoepIssueKind {
    MissingCoop,
    MissingCoep,
    UnsafeCoop,
    UnsafeCoep,
}

impl std::fmt::Display for CoopCoepIssueKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCoop => write!(f, "missing Cross-Origin-Opener-Policy header"),
            Self::MissingCoep => write!(f, "missing Cross-Origin-Embedder-Policy header"),
            Self::UnsafeCoop => {
                write!(f, "Cross-Origin-Opener-Policy set to unsafe-none")
            }
            Self::UnsafeCoep => {
                write!(f, "Cross-Origin-Embedder-Policy set to unsafe-none")
            }
        }
    }
}

pub fn audit_coop_coep(target: &str) -> Vec<CoopCoepIssue> {
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

    let coop = resp
        .headers()
        .get("cross-origin-opener-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let coep = resp
        .headers()
        .get("cross-origin-embedder-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    analyze_coop_coep(coop.as_deref(), coep.as_deref())
}

pub fn analyze_coop_coep(coop: Option<&str>, coep: Option<&str>) -> Vec<CoopCoepIssue> {
    let mut issues = Vec::new();

    match coop {
        None => {
            issues.push(CoopCoepIssue {
                header: "cross-origin-opener-policy".to_string(),
                kind: CoopCoepIssueKind::MissingCoop,
                severity: 3.0,
            });
        }
        Some(v) if v.trim().eq_ignore_ascii_case("unsafe-none") => {
            issues.push(CoopCoepIssue {
                header: "cross-origin-opener-policy".to_string(),
                kind: CoopCoepIssueKind::UnsafeCoop,
                severity: 3.5,
            });
        }
        _ => {}
    }

    match coep {
        None => {
            issues.push(CoopCoepIssue {
                header: "cross-origin-embedder-policy".to_string(),
                kind: CoopCoepIssueKind::MissingCoep,
                severity: 2.5,
            });
        }
        Some(v) if v.trim().eq_ignore_ascii_case("unsafe-none") => {
            issues.push(CoopCoepIssue {
                header: "cross-origin-embedder-policy".to_string(),
                kind: CoopCoepIssueKind::UnsafeCoep,
                severity: 3.0,
            });
        }
        _ => {}
    }

    issues
}

pub fn coop_coep_to_operations(issues: &[CoopCoepIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues.iter().map(|i| i.severity).fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::MissingSecurityHeader,
        max_severity,
        0.9,
    )]
}

#[derive(Debug, Clone, PartialEq)]
pub enum CrossOriginIssue {
    MissingCoop,
    MissingCoep,
    MissingCorp,
    UnsafeNoneCoop,
    UnsafeNoneCoep,
    WeakCoop { value: String },
    WeakCoep { value: String },
    InconsistentPolicies { coop: String, coep: String },
    MissingReportingEndpoint { header: String },
    ReportOnlyCoop,
    ReportOnlyCoep,
    NoIsolation,
}

impl std::fmt::Display for CrossOriginIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCoop => write!(f, "missing_coop"),
            Self::MissingCoep => write!(f, "missing_coep"),
            Self::MissingCorp => write!(f, "missing_corp"),
            Self::UnsafeNoneCoop => write!(f, "unsafe_none_coop"),
            Self::UnsafeNoneCoep => write!(f, "unsafe_none_coep"),
            Self::WeakCoop { value } => write!(f, "weak_coop:{value}"),
            Self::WeakCoep { value } => write!(f, "weak_coep:{value}"),
            Self::InconsistentPolicies { coop, coep } => {
                write!(f, "inconsistent_policies:{coop}:{coep}")
            }
            Self::MissingReportingEndpoint { header } => {
                write!(f, "missing_reporting:{header}")
            }
            Self::ReportOnlyCoop => write!(f, "report_only_coop"),
            Self::ReportOnlyCoep => write!(f, "report_only_coep"),
            Self::NoIsolation => write!(f, "no_cross_origin_isolation"),
        }
    }
}

pub fn cross_origin_severity(issue: &CrossOriginIssue) -> f64 {
    match issue {
        CrossOriginIssue::UnsafeNoneCoop => 6.0,
        CrossOriginIssue::UnsafeNoneCoep => 5.5,
        CrossOriginIssue::NoIsolation => 5.0,
        CrossOriginIssue::InconsistentPolicies { .. } => 5.0,
        CrossOriginIssue::MissingCoop => 4.0,
        CrossOriginIssue::MissingCoep => 3.5,
        CrossOriginIssue::MissingCorp => 3.5,
        CrossOriginIssue::WeakCoop { .. } => 4.5,
        CrossOriginIssue::WeakCoep { .. } => 4.0,
        CrossOriginIssue::ReportOnlyCoop => 3.0,
        CrossOriginIssue::ReportOnlyCoep => 3.0,
        CrossOriginIssue::MissingReportingEndpoint { .. } => 2.0,
    }
}

pub fn analyze_cross_origin_headers(headers: &[(&str, &str)]) -> Vec<CrossOriginIssue> {
    let mut issues = Vec::new();

    let coop = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("cross-origin-opener-policy"))
        .map(|(_, v)| *v);
    let coep = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("cross-origin-embedder-policy"))
        .map(|(_, v)| *v);
    let corp = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("cross-origin-resource-policy"))
        .map(|(_, v)| *v);

    let has_coop_report_only = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("cross-origin-opener-policy-report-only"));
    let has_coep_report_only = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("cross-origin-embedder-policy-report-only"));

    match coop {
        None => {
            if has_coop_report_only {
                issues.push(CrossOriginIssue::ReportOnlyCoop);
            } else {
                issues.push(CrossOriginIssue::MissingCoop);
            }
        }
        Some(v) if v.trim().eq_ignore_ascii_case("unsafe-none") => {
            issues.push(CrossOriginIssue::UnsafeNoneCoop);
        }
        Some(v) if v.trim().eq_ignore_ascii_case("same-origin-allow-popups") => {
            issues.push(CrossOriginIssue::WeakCoop {
                value: v.trim().to_string(),
            });
        }
        _ => {}
    }

    match coep {
        None => {
            if has_coep_report_only {
                issues.push(CrossOriginIssue::ReportOnlyCoep);
            } else {
                issues.push(CrossOriginIssue::MissingCoep);
            }
        }
        Some(v) if v.trim().eq_ignore_ascii_case("unsafe-none") => {
            issues.push(CrossOriginIssue::UnsafeNoneCoep);
        }
        Some(v) if v.trim().eq_ignore_ascii_case("credentialless") => {
            issues.push(CrossOriginIssue::WeakCoep {
                value: v.trim().to_string(),
            });
        }
        _ => {}
    }

    if corp.is_none() {
        issues.push(CrossOriginIssue::MissingCorp);
    }

    // Check for inconsistent policies
    let coop_strong = matches!(coop, Some(v) if v.trim().eq_ignore_ascii_case("same-origin"));
    let coep_strong = matches!(coep, Some(v) if v.trim().eq_ignore_ascii_case("require-corp"));
    if (coop_strong && !coep_strong && coep.is_some())
        || (!coop_strong && coop.is_some() && coep_strong)
    {
        issues.push(CrossOriginIssue::InconsistentPolicies {
            coop: coop.unwrap_or("missing").to_string(),
            coep: coep.unwrap_or("missing").to_string(),
        });
    }

    // No cross-origin isolation if both aren't strong
    if !coop_strong || !coep_strong {
        issues.push(CrossOriginIssue::NoIsolation);
    }

    // Check for reporting endpoints
    let has_reporting = headers.iter().any(|(k, _)| {
        k.eq_ignore_ascii_case("reporting-endpoints") || k.eq_ignore_ascii_case("report-to")
    });
    if !has_reporting {
        if coop.is_some() {
            issues.push(CrossOriginIssue::MissingReportingEndpoint {
                header: "cross-origin-opener-policy".to_string(),
            });
        }
        if coep.is_some() {
            issues.push(CrossOriginIssue::MissingReportingEndpoint {
                header: "cross-origin-embedder-policy".to_string(),
            });
        }
    }

    issues
}

pub fn cross_origin_to_operations(
    issues: &[CrossOriginIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::MissingSecurityHeader,
                cross_origin_severity(issue),
                0.5,
            )
        })
        .collect()
}
