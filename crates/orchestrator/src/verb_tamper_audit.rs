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

#[derive(Debug, Clone, PartialEq)]
pub enum VerbTamperSecurityIssue {
    TraceMethodEnabled,
    ConnectMethodEnabled,
    PatchWithoutAuth,
    DeleteWithoutAuth,
    OptionsExposingMethods { methods: Vec<String> },
    HeadMethodBypass,
    ArbitraryMethodAccepted { method: String },
    MethodOverrideViaHeader,
    PutMethodEnabled,
    PropfindEnabled,
}

impl std::fmt::Display for VerbTamperSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TraceMethodEnabled => write!(f, "verb_tamper_trace_enabled"),
            Self::ConnectMethodEnabled => write!(f, "verb_tamper_connect_enabled"),
            Self::PatchWithoutAuth => write!(f, "verb_tamper_patch_no_auth"),
            Self::DeleteWithoutAuth => write!(f, "verb_tamper_delete_no_auth"),
            Self::OptionsExposingMethods { methods } => {
                write!(f, "verb_tamper_options_exposing:{}", methods.join(","))
            }
            Self::HeadMethodBypass => write!(f, "verb_tamper_head_bypass"),
            Self::ArbitraryMethodAccepted { method } => {
                write!(f, "verb_tamper_arbitrary_method:{}", method)
            }
            Self::MethodOverrideViaHeader => write!(f, "verb_tamper_method_override_header"),
            Self::PutMethodEnabled => write!(f, "verb_tamper_put_enabled"),
            Self::PropfindEnabled => write!(f, "verb_tamper_propfind_enabled"),
        }
    }
}

const ARBITRARY_TEST_METHODS: &[&str] = &["XMETHOD", "CUSTOM", "FUZZ"];

pub fn analyze_verb_tamper_security(
    method: &str,
    allowed_methods: &[&str],
    response_status: u16,
) -> Vec<VerbTamperSecurityIssue> {
    let mut issues = Vec::new();
    let is_success = (200..300).contains(&response_status);

    if method.eq_ignore_ascii_case("TRACE") && is_success {
        issues.push(VerbTamperSecurityIssue::TraceMethodEnabled);
    }

    if method.eq_ignore_ascii_case("CONNECT") && is_success {
        issues.push(VerbTamperSecurityIssue::ConnectMethodEnabled);
    }

    if method.eq_ignore_ascii_case("PATCH") && is_success && !allowed_methods.contains(&"PATCH") {
        issues.push(VerbTamperSecurityIssue::PatchWithoutAuth);
    }

    if method.eq_ignore_ascii_case("DELETE") && is_success && !allowed_methods.contains(&"DELETE") {
        issues.push(VerbTamperSecurityIssue::DeleteWithoutAuth);
    }

    if method.eq_ignore_ascii_case("OPTIONS") && is_success && !allowed_methods.is_empty() {
        issues.push(VerbTamperSecurityIssue::OptionsExposingMethods {
            methods: allowed_methods.iter().map(|s| s.to_string()).collect(),
        });
    }

    if method.eq_ignore_ascii_case("HEAD") && is_success && !allowed_methods.contains(&"HEAD") {
        issues.push(VerbTamperSecurityIssue::HeadMethodBypass);
    }

    if ARBITRARY_TEST_METHODS
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method))
        && is_success
    {
        issues.push(VerbTamperSecurityIssue::ArbitraryMethodAccepted {
            method: method.to_string(),
        });
    }

    if method.eq_ignore_ascii_case("PUT") && is_success {
        issues.push(VerbTamperSecurityIssue::PutMethodEnabled);
    }

    if method.eq_ignore_ascii_case("PROPFIND") && is_success {
        issues.push(VerbTamperSecurityIssue::PropfindEnabled);
    }

    issues
}

pub fn verb_tamper_security_severity(issue: &VerbTamperSecurityIssue) -> f64 {
    match issue {
        VerbTamperSecurityIssue::TraceMethodEnabled => 6.5,
        VerbTamperSecurityIssue::ConnectMethodEnabled => 7.0,
        VerbTamperSecurityIssue::PatchWithoutAuth => 7.5,
        VerbTamperSecurityIssue::DeleteWithoutAuth => 8.5,
        VerbTamperSecurityIssue::OptionsExposingMethods { .. } => 4.0,
        VerbTamperSecurityIssue::HeadMethodBypass => 6.0,
        VerbTamperSecurityIssue::ArbitraryMethodAccepted { .. } => 5.5,
        VerbTamperSecurityIssue::MethodOverrideViaHeader => 7.0,
        VerbTamperSecurityIssue::PutMethodEnabled => 8.0,
        VerbTamperSecurityIssue::PropfindEnabled => 6.0,
    }
}

pub fn verb_tamper_security_to_operations(
    issues: &[VerbTamperSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                verb_tamper_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
