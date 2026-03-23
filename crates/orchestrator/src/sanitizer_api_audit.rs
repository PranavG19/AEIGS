use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum SanitizerApiIssue {
    ApiDetected,
    PermissiveConfig,
    ScriptAllowed,
    EventHandlerAllowed,
    CustomElementRisk,
    SanitizationBypassed,
}

impl std::fmt::Display for SanitizerApiIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::PermissiveConfig => write!(f, "permissive_config"),
            Self::ScriptAllowed => write!(f, "script_allowed"),
            Self::EventHandlerAllowed => write!(f, "event_handler_allowed"),
            Self::CustomElementRisk => write!(f, "custom_element_risk"),
            Self::SanitizationBypassed => write!(f, "sanitization_bypassed"),
        }
    }
}

pub fn audit_sanitizer_api(target: &str) -> Vec<SanitizerApiIssue> {
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
    analyze_sanitizer_api(&body)
}

pub fn analyze_sanitizer_api(body: &str) -> Vec<SanitizerApiIssue> {
    let has_sanitizer = body.contains("new Sanitizer") || body.contains("Sanitizer(");
    let has_set_html = body.contains("setHTML") || body.contains("sanitizeFor");

    if !has_sanitizer && !has_set_html {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(SanitizerApiIssue::ApiDetected);

    if has_sanitizer
        && (body.contains("allowElements") || body.contains("allowAttributes"))
        && (body.contains("\"*\"") || body.contains("'*'") || body.contains("..."))
    {
        issues.push(SanitizerApiIssue::PermissiveConfig);
    }

    if has_sanitizer && (body.contains("\"script\"") || body.contains("'script'")) {
        issues.push(SanitizerApiIssue::ScriptAllowed);
    }

    if has_sanitizer
        && (body.contains("\"onload\"")
            || body.contains("'onload'")
            || body.contains("\"onclick\"")
            || body.contains("'onclick'")
            || body.contains("\"onerror\"")
            || body.contains("'onerror'"))
    {
        issues.push(SanitizerApiIssue::EventHandlerAllowed);
    }

    if (has_sanitizer || has_set_html)
        && (body.contains("customElements.define") || body.contains("customElements.get"))
    {
        issues.push(SanitizerApiIssue::CustomElementRisk);
    }

    if body.contains("innerHTML") && !has_set_html && has_sanitizer {
        issues.push(SanitizerApiIssue::SanitizationBypassed);
    }

    issues
}

pub fn sanitizer_api_severity(issue: &SanitizerApiIssue) -> f64 {
    match issue {
        SanitizerApiIssue::ScriptAllowed => 9.0,
        SanitizerApiIssue::EventHandlerAllowed => 8.0,
        SanitizerApiIssue::SanitizationBypassed => 7.5,
        SanitizerApiIssue::PermissiveConfig => 6.5,
        SanitizerApiIssue::CustomElementRisk => 5.0,
        SanitizerApiIssue::ApiDetected => 2.0,
    }
}

pub fn sanitizer_api_to_operations(
    issues: &[SanitizerApiIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CrossSiteScripting,
                sanitizer_api_severity(issue),
                0.6,
            )
        })
        .collect()
}
