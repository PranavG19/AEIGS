use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum MutationObserverIssue {
    ObserverDetected,
    SubtreeWatch,
    CharacterDataWatch,
    AttributeFilterSensitive,
    FormInputMonitoring,
    DataExfiltration,
}

impl std::fmt::Display for MutationObserverIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObserverDetected => write!(f, "observer_detected"),
            Self::SubtreeWatch => write!(f, "subtree_watch"),
            Self::CharacterDataWatch => write!(f, "character_data_watch"),
            Self::AttributeFilterSensitive => write!(f, "attribute_filter_sensitive"),
            Self::FormInputMonitoring => write!(f, "form_input_monitoring"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
        }
    }
}

pub fn audit_mutation_observer(target: &str) -> Vec<MutationObserverIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_mutation_observer(&body)
}

pub fn analyze_mutation_observer(body: &str) -> Vec<MutationObserverIssue> {
    if !body.contains("MutationObserver") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(MutationObserverIssue::ObserverDetected);

    if body.contains("subtree") && body.contains("true") {
        issues.push(MutationObserverIssue::SubtreeWatch);
    }

    if body.contains("characterData") && body.contains("true") {
        issues.push(MutationObserverIssue::CharacterDataWatch);
    }

    let sensitive_attrs = ["value", "password", "token", "session", "auth", "href"];
    if body.contains("attributeFilter") && sensitive_attrs.iter().any(|a| body.contains(a)) {
        issues.push(MutationObserverIssue::AttributeFilterSensitive);
    }

    let form_markers = ["input", "form", "textarea", "select"];
    let has_form_target = form_markers.iter().any(|m| {
        let selector = format!("\"{m}\"");
        let selector2 = format!("'{m}'");
        body.contains(selector.as_str()) || body.contains(selector2.as_str())
    });
    if has_form_target && body.contains(".observe(") {
        issues.push(MutationObserverIssue::FormInputMonitoring);
    }

    if body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest") {
        issues.push(MutationObserverIssue::DataExfiltration);
    }

    issues
}

pub fn mutation_observer_severity(issue: &MutationObserverIssue) -> f64 {
    match issue {
        MutationObserverIssue::DataExfiltration => 6.0,
        MutationObserverIssue::FormInputMonitoring => 5.5,
        MutationObserverIssue::CharacterDataWatch => 5.0,
        MutationObserverIssue::AttributeFilterSensitive => 4.5,
        MutationObserverIssue::SubtreeWatch => 4.0,
        MutationObserverIssue::ObserverDetected => 3.0,
    }
}

pub fn mutation_observer_to_operations(
    issues: &[MutationObserverIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                mutation_observer_severity(issue),
                0.6,
            )
        })
        .collect()
}
