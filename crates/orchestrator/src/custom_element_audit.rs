use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum CustomElementIssue {
    ApiDetected,
    UnsanitizedContent,
    PrototypePollution,
    EventHijacking,
    NameCollision,
}

impl std::fmt::Display for CustomElementIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::UnsanitizedContent => write!(f, "unsanitized_content"),
            Self::PrototypePollution => write!(f, "prototype_pollution"),
            Self::EventHijacking => write!(f, "event_hijacking"),
            Self::NameCollision => write!(f, "name_collision"),
        }
    }
}

pub fn audit_custom_element(target: &str) -> Vec<CustomElementIssue> {
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
    analyze_custom_element(&body)
}

pub fn analyze_custom_element(body: &str) -> Vec<CustomElementIssue> {
    let has_api = body.contains("customElements.define")
        || body.contains("customElements")
        || (body.contains("HTMLElement") && body.contains("extends"));

    if !has_api {
        return Vec::new();
    }

    let mut issues = Vec::new();

    issues.push(CustomElementIssue::ApiDetected);

    let has_dangerous_sink = body.contains("innerHTML") || body.contains("insertAdjacentHTML");
    let has_sanitizer = body.contains("sanitize") || body.contains("DOMPurify");
    if has_dangerous_sink && !has_sanitizer {
        issues.push(CustomElementIssue::UnsanitizedContent);
    }

    let has_proto_vector = body.contains("__proto__")
        || body.contains("constructor.prototype")
        || body.contains("Object.assign");
    let has_lifecycle_callback =
        body.contains("connectedCallback") || body.contains("attributeChangedCallback");
    if has_proto_vector && has_lifecycle_callback {
        issues.push(CustomElementIssue::PrototypePollution);
    }

    let has_event_dispatch = body.contains("dispatchEvent") || body.contains("CustomEvent");
    let has_global_scope = body.contains("document.") || body.contains("window.");
    let has_stop_propagation = body.contains("stopPropagation");
    if has_event_dispatch && has_global_scope && !has_stop_propagation {
        issues.push(CustomElementIssue::EventHijacking);
    }

    let has_define = body.contains("customElements.define");
    let has_collision_signal =
        body.contains("override") || body.contains("redefine") || body.contains("whenDefined");
    if has_define && has_collision_signal {
        issues.push(CustomElementIssue::NameCollision);
    }

    issues
}

pub fn custom_element_severity(issue: &CustomElementIssue) -> f64 {
    match issue {
        CustomElementIssue::ApiDetected => 2.0,
        CustomElementIssue::UnsanitizedContent => 7.5,
        CustomElementIssue::PrototypePollution => 7.0,
        CustomElementIssue::EventHijacking => 6.0,
        CustomElementIssue::NameCollision => 5.0,
    }
}

pub fn custom_element_to_operations(
    issues: &[CustomElementIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CrossSiteScripting,
                custom_element_severity(issue),
                0.5,
            )
        })
        .collect()
}
