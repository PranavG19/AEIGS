use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum TrustedTypesIssue {
    MissingTrustedTypes,
    AllowDuplicates,
    DefaultPolicyWildcard,
    UnsafeSinkWithoutPolicy { sink: String },
    TrustedTypesWithUnsafeEval,
}

impl std::fmt::Display for TrustedTypesIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingTrustedTypes => write!(f, "missing_trusted_types"),
            Self::AllowDuplicates => write!(f, "trusted_types_allow_duplicates"),
            Self::DefaultPolicyWildcard => write!(f, "trusted_types_wildcard"),
            Self::UnsafeSinkWithoutPolicy { sink } => {
                write!(f, "unsafe_sink_no_tt:{sink}")
            }
            Self::TrustedTypesWithUnsafeEval => write!(f, "trusted_types_unsafe_eval"),
        }
    }
}

const DANGEROUS_SINKS: &[&str] = &[
    ".innerHTML",
    ".outerHTML",
    ".insertAdjacentHTML",
    "document.write",
    "document.writeln",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "new Function(",
    "DOMParser",
    "Range.createContextualFragment",
    "Element.insertAdjacentHTML",
    "HTMLElement.setAttribute",
    "script.src",
    "script.text",
    "location.href",
    "location.assign",
    "location.replace",
];

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
        .unwrap_or("")
        .to_string();

    let body = resp.text().unwrap_or_default();
    analyze_trusted_types(&csp, &body)
}

pub fn analyze_trusted_types(csp: &str, body: &str) -> Vec<TrustedTypesIssue> {
    let mut issues = Vec::new();

    let tt_directive = extract_tt_directive(csp);
    let has_tt = tt_directive.is_some();

    if !has_tt && has_dangerous_sinks(body) {
        issues.push(TrustedTypesIssue::MissingTrustedTypes);
    }

    if let Some(directive) = &tt_directive {
        if directive.contains("'allow-duplicates'") {
            issues.push(TrustedTypesIssue::AllowDuplicates);
        }

        let parts: Vec<&str> = directive.split_whitespace().collect();
        if parts.contains(&"*") {
            issues.push(TrustedTypesIssue::DefaultPolicyWildcard);
        }
    }

    if has_tt {
        let csp_lower = csp.to_ascii_lowercase();
        if csp_lower.contains("'unsafe-eval'") {
            issues.push(TrustedTypesIssue::TrustedTypesWithUnsafeEval);
        }
    }

    if !has_tt {
        for &sink in DANGEROUS_SINKS {
            if body.contains(sink) {
                issues.push(TrustedTypesIssue::UnsafeSinkWithoutPolicy {
                    sink: sink.to_string(),
                });
                break;
            }
        }
    }

    issues
}

fn extract_tt_directive(csp: &str) -> Option<String> {
    for directive in csp.split(';') {
        let trimmed = directive.trim();
        if trimmed.starts_with("require-trusted-types-for")
            || trimmed.starts_with("trusted-types")
        {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn has_dangerous_sinks(body: &str) -> bool {
    DANGEROUS_SINKS.iter().any(|sink| body.contains(sink))
}

pub fn trusted_types_severity(issue: &TrustedTypesIssue) -> f64 {
    match issue {
        TrustedTypesIssue::DefaultPolicyWildcard => 7.0,
        TrustedTypesIssue::TrustedTypesWithUnsafeEval => 6.5,
        TrustedTypesIssue::AllowDuplicates => 5.5,
        TrustedTypesIssue::UnsafeSinkWithoutPolicy { .. } => 5.0,
        TrustedTypesIssue::MissingTrustedTypes => 3.0,
    }
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
                0.8,
            )
        })
        .collect()
}
