use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum TrustedTypesIssue {
    ApiDetected,
    MissingEnforcement,
    DefaultPolicyBypass,
    UnsafePolicyNoSanitization,
    XssSinkWithoutTrustedTypes,
}

impl std::fmt::Display for TrustedTypesIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::MissingEnforcement => write!(f, "missing_enforcement"),
            Self::DefaultPolicyBypass => write!(f, "default_policy_bypass"),
            Self::UnsafePolicyNoSanitization => write!(f, "unsafe_policy_no_sanitization"),
            Self::XssSinkWithoutTrustedTypes => write!(f, "xss_sink_without_trusted_types"),
        }
    }
}

pub fn trusted_types_severity(issue: &TrustedTypesIssue) -> f64 {
    match issue {
        TrustedTypesIssue::ApiDetected => 2.0,
        TrustedTypesIssue::MissingEnforcement => 6.5,
        TrustedTypesIssue::DefaultPolicyBypass => 8.0,
        TrustedTypesIssue::UnsafePolicyNoSanitization => 7.5,
        TrustedTypesIssue::XssSinkWithoutTrustedTypes => 7.0,
    }
}

pub fn audit_trusted_types(target: &str) -> Vec<TrustedTypesIssue> {
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
    let csp = resp
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();
    let body = resp.text().unwrap_or_default();
    analyze_trusted_types(&csp, &body)
}

pub fn analyze_trusted_types(csp: &str, body: &str) -> Vec<TrustedTypesIssue> {
    let mut issues = Vec::new();

    let has_api = body.contains("trustedTypes")
        || body.contains("TrustedHTML")
        || body.contains("TrustedScript")
        || body.contains("TrustedScriptURL")
        || body.contains("createPolicy")
        || body.contains("createHTML")
        || body.contains("createScript")
        || body.contains("createScriptURL");

    if has_api {
        issues.push(TrustedTypesIssue::ApiDetected);
    }

    let has_enforcement =
        csp.contains("require-trusted-types-for") || body.contains("require-trusted-types-for");

    if has_api && !has_enforcement {
        issues.push(TrustedTypesIssue::MissingEnforcement);
    }

    if body.contains("createPolicy('default'") || body.contains("createPolicy(\"default\"") {
        issues.push(TrustedTypesIssue::DefaultPolicyBypass);
    }

    if has_api && detect_unsafe_policy(body) {
        issues.push(TrustedTypesIssue::UnsafePolicyNoSanitization);
    }

    if !has_api && has_xss_sink(body) {
        issues.push(TrustedTypesIssue::XssSinkWithoutTrustedTypes);
    }

    issues
}

fn detect_unsafe_policy(body: &str) -> bool {
    if (body.contains("return input") || body.contains("return value"))
        && (body.contains("createHTML")
            || body.contains("createScript")
            || body.contains("createScriptURL"))
    {
        return true;
    }
    false
}

fn has_xss_sink(body: &str) -> bool {
    body.contains("innerHTML") || body.contains("eval(") || body.contains("document.write")
}

pub fn trusted_types_to_operations(
    issues: &[TrustedTypesIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CrossSiteScripting,
                trusted_types_severity(issue),
                0.5,
            )
        })
        .collect()
}
