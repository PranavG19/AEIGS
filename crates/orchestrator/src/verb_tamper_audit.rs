use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum VerbTamperIssue {
    AuthBypass {
        method: String,
        expected_status: u16,
        actual_status: u16,
    },
    UnexpectedSuccess {
        method: String,
        status: u16,
    },
}

impl std::fmt::Display for VerbTamperIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthBypass {
                method,
                expected_status,
                actual_status,
            } => write!(
                f,
                "verb_tamper_auth_bypass:{method}:{expected_status}->{actual_status}"
            ),
            Self::UnexpectedSuccess { method, status } => {
                write!(f, "verb_tamper_unexpected_success:{method}:{status}")
            }
        }
    }
}

const TAMPER_METHODS: &[&str] = &["HEAD", "PATCH", "PROPFIND", "XMETHOD"];
const AUTH_DENIED_CODES: &[u16] = &[401, 403, 405];

pub fn audit_verb_tampering(target: &str) -> Vec<VerbTamperIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let baseline_status = match client.get(target).send() {
        Ok(r) => r.status().as_u16(),
        Err(_) => return Vec::new(),
    };

    let mut method_results = Vec::new();
    for method_name in TAMPER_METHODS {
        let method = match reqwest::Method::from_bytes(method_name.as_bytes()) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if let Ok(resp) = client.request(method, target).send() {
            method_results.push((method_name.to_string(), resp.status().as_u16()));
        }
    }

    analyze_verb_tamper(baseline_status, &method_results)
}

const NONSTANDARD_METHODS: &[&str] = &["PROPFIND", "XMETHOD"];

pub(crate) fn analyze_verb_tamper(
    baseline_status: u16,
    method_results: &[(String, u16)],
) -> Vec<VerbTamperIssue> {
    let mut issues = Vec::new();
    let baseline_denied = AUTH_DENIED_CODES.contains(&baseline_status);

    for (method, status) in method_results {
        if baseline_denied && (200..300).contains(status) {
            issues.push(VerbTamperIssue::AuthBypass {
                method: method.clone(),
                expected_status: baseline_status,
                actual_status: *status,
            });
        } else if NONSTANDARD_METHODS.contains(&method.as_str()) && (200..300).contains(status) {
            issues.push(VerbTamperIssue::UnexpectedSuccess {
                method: method.clone(),
                status: *status,
            });
        }
    }

    issues
}

pub(crate) fn verb_tamper_severity(issue: &VerbTamperIssue) -> f64 {
    match issue {
        VerbTamperIssue::AuthBypass { .. } => 8.0,
        VerbTamperIssue::UnexpectedSuccess { .. } => 5.0,
    }
}

pub fn verb_tamper_to_operations(
    issues: &[VerbTamperIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::BrokenAuthorization,
                verb_tamper_severity(issue),
                0.75,
            )
        })
        .collect()
}
