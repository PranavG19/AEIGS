use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum CorpIssue {
    Missing,
    CrossOrigin,
    InvalidValue { value: String },
    MissingCoep,
    MissingCoop,
    InconsistentPolicies { corp: String, coep: String },
    PermissiveCoep,
    UnsafeCoop { value: String },
}

impl std::fmt::Display for CorpIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "missing_corp"),
            Self::CrossOrigin => write!(f, "cross_origin"),
            Self::InvalidValue { value } => write!(f, "invalid_value:{value}"),
            Self::MissingCoep => write!(f, "missing_coep"),
            Self::MissingCoop => write!(f, "missing_coop"),
            Self::InconsistentPolicies { corp, coep } => {
                write!(f, "inconsistent_policies:{corp}+{coep}")
            }
            Self::PermissiveCoep => write!(f, "permissive_coep"),
            Self::UnsafeCoop { value } => write!(f, "unsafe_coop:{value}"),
        }
    }
}

pub fn corp_severity(issue: &CorpIssue) -> f64 {
    match issue {
        CorpIssue::Missing => 2.0,
        CorpIssue::CrossOrigin => 3.0,
        CorpIssue::InvalidValue { .. } => 2.5,
        CorpIssue::MissingCoep => 2.5,
        CorpIssue::MissingCoop => 2.5,
        CorpIssue::InconsistentPolicies { .. } => 4.0,
        CorpIssue::PermissiveCoep => 3.5,
        CorpIssue::UnsafeCoop { .. } => 3.5,
    }
}

pub fn audit_corp(target: &str) -> Vec<CorpIssue> {
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

    let mut raw_headers: Vec<(String, String)> = Vec::new();
    for (name, value) in resp.headers() {
        if let Ok(v) = value.to_str() {
            raw_headers.push((name.as_str().to_string(), v.to_string()));
        }
    }

    let header_refs: Vec<(&str, &str)> = raw_headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    analyze_corp(&header_refs)
}

pub fn analyze_corp(headers: &[(&str, &str)]) -> Vec<CorpIssue> {
    let mut issues = Vec::new();

    let corp_value = find_header(headers, "cross-origin-resource-policy");
    let coep_value = find_header(headers, "cross-origin-embedder-policy");
    let coop_value = find_header(headers, "cross-origin-opener-policy");

    let corp_normalized = corp_value.map(|v| v.trim().to_ascii_lowercase());
    let coep_normalized = coep_value.map(|v| v.trim().to_ascii_lowercase());
    let coop_normalized = coop_value.map(|v| v.trim().to_ascii_lowercase());

    match corp_normalized.as_deref() {
        None => issues.push(CorpIssue::Missing),
        Some("same-origin" | "same-site") => {}
        Some("cross-origin") => issues.push(CorpIssue::CrossOrigin),
        Some(other) => issues.push(CorpIssue::InvalidValue {
            value: other.to_string(),
        }),
    }

    match coep_normalized.as_deref() {
        None => issues.push(CorpIssue::MissingCoep),
        Some("require-corp" | "credentialless") => {}
        Some("unsafe-none") => issues.push(CorpIssue::PermissiveCoep),
        _ => {}
    }

    match coop_normalized.as_deref() {
        None => issues.push(CorpIssue::MissingCoop),
        Some("same-origin" | "same-origin-allow-popups") => {}
        Some("unsafe-none") => issues.push(CorpIssue::UnsafeCoop {
            value: "unsafe-none".to_string(),
        }),
        _ => {}
    }

    if let (Some(corp_str), Some(coep_str)) = (&corp_normalized, &coep_normalized)
        && corp_str == "same-origin"
        && coep_str == "unsafe-none"
    {
        issues.push(CorpIssue::InconsistentPolicies {
            corp: corp_str.clone(),
            coep: coep_str.clone(),
        });
    }

    issues
}

fn find_header<'a>(headers: &[(&str, &'a str)], target: &str) -> Option<&'a str> {
    let target_lower = target.to_ascii_lowercase();
    headers
        .iter()
        .find(|(name, _)| name.to_ascii_lowercase() == target_lower)
        .map(|(_, value)| *value)
}

pub fn corp_to_operations(issues: &[CorpIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                corp_severity(issue),
                0.5,
            )
        })
        .collect()
}
