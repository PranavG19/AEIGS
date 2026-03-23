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

#[derive(Debug, Clone, PartialEq)]
pub enum MutationObserverSecurityIssue {
    PasswordFieldMonitoring,
    DocumentWideObserver,
    DomExfiltration,
    HiddenElementTracking,
    ScriptInjectionWatch,
    CrossOriginFrameWatch,
    TokenExtraction,
    KeystrokeReconstruction,
    ClipboardInterception,
    ShadowDomPenetration,
}

impl std::fmt::Display for MutationObserverSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PasswordFieldMonitoring => write!(f, "password_field_monitoring"),
            Self::DocumentWideObserver => write!(f, "document_wide_observer"),
            Self::DomExfiltration => write!(f, "dom_exfiltration"),
            Self::HiddenElementTracking => write!(f, "hidden_element_tracking"),
            Self::ScriptInjectionWatch => write!(f, "script_injection_watch"),
            Self::CrossOriginFrameWatch => write!(f, "cross_origin_frame_watch"),
            Self::TokenExtraction => write!(f, "token_extraction"),
            Self::KeystrokeReconstruction => write!(f, "keystroke_reconstruction"),
            Self::ClipboardInterception => write!(f, "clipboard_interception"),
            Self::ShadowDomPenetration => write!(f, "shadow_dom_penetration"),
        }
    }
}

pub fn analyze_mutation_observer_security(body: &str) -> Vec<MutationObserverSecurityIssue> {
    if !body.contains("MutationObserver") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    // PasswordFieldMonitoring - watching password inputs
    let password_markers = [
        "type=\"password\"",
        "type='password'",
        "[type=\"password\"]",
        "[type='password']",
        "input[type=password]",
    ];
    if password_markers.iter().any(|m| body.contains(m)) && body.contains(".observe(") {
        issues.push(MutationObserverSecurityIssue::PasswordFieldMonitoring);
    }

    // DocumentWideObserver - observing document.body or document.documentElement with subtree
    let doc_wide_patterns = [
        "document.body",
        "document.documentElement",
        "document.querySelector(\"body\")",
        "document.querySelector('body')",
    ];
    if doc_wide_patterns.iter().any(|p| body.contains(p))
        && body.contains("subtree")
        && body.contains("true")
    {
        issues.push(MutationObserverSecurityIssue::DocumentWideObserver);
    }

    // DomExfiltration - mutation data sent to remote server
    let exfil_patterns = [
        "fetch(\"http",
        "fetch('http",
        "XMLHttpRequest",
        "sendBeacon",
        ".send(",
        "navigator.sendBeacon",
    ];
    let mutation_data_patterns = ["mutations", "mutation.target", "mutation.addedNodes"];
    if exfil_patterns.iter().any(|p| body.contains(p))
        && mutation_data_patterns.iter().any(|m| body.contains(m))
    {
        issues.push(MutationObserverSecurityIssue::DomExfiltration);
    }

    // HiddenElementTracking - monitoring hidden/display:none elements
    let hidden_patterns = [
        "display:none",
        "display: none",
        "visibility:hidden",
        "visibility: hidden",
        "hidden",
        "[hidden]",
        "style.display",
    ];
    if hidden_patterns.iter().any(|h| body.contains(h)) && body.contains(".observe(") {
        issues.push(MutationObserverSecurityIssue::HiddenElementTracking);
    }

    // ScriptInjectionWatch - observing script element additions
    let script_watch_patterns = [
        "addedNodes",
        "nodeName",
        "tagName",
        "\"script\"",
        "'script'",
        "SCRIPT",
    ];
    if script_watch_patterns
        .iter()
        .filter(|p| body.contains(*p))
        .count()
        >= 2
    {
        issues.push(MutationObserverSecurityIssue::ScriptInjectionWatch);
    }

    // CrossOriginFrameWatch - observing iframe content mutations
    let iframe_patterns = ["iframe", "contentWindow", "contentDocument", "frame"];
    if iframe_patterns.iter().any(|i| body.contains(i)) && body.contains(".observe(") {
        issues.push(MutationObserverSecurityIssue::CrossOriginFrameWatch);
    }

    // TokenExtraction - extracting auth tokens/sessions from DOM mutations
    let token_patterns = [
        "token",
        "auth",
        "session",
        "bearer",
        "jwt",
        "csrf",
        "xsrf",
        "access_token",
    ];
    if token_patterns.iter().any(|t| body.contains(t))
        && (body.contains("localStorage")
            || body.contains("sessionStorage")
            || body.contains("cookie"))
        && body.contains(".observe(")
    {
        issues.push(MutationObserverSecurityIssue::TokenExtraction);
    }

    // KeystrokeReconstruction - reconstructing keystrokes from characterData mutations
    if body.contains("characterData")
        && body.contains("true")
        && (body.contains("input") || body.contains("textarea") || body.contains("keyCode"))
    {
        issues.push(MutationObserverSecurityIssue::KeystrokeReconstruction);
    }

    // ClipboardInterception - monitoring clipboard-related DOM changes
    let clipboard_patterns = [
        "clipboard",
        "copy",
        "paste",
        "cut",
        "oncopy",
        "onpaste",
        "oncut",
    ];
    if clipboard_patterns.iter().any(|c| body.contains(c)) && body.contains(".observe(") {
        issues.push(MutationObserverSecurityIssue::ClipboardInterception);
    }

    // ShadowDomPenetration - observing shadow DOM mutations
    let shadow_patterns = [
        "shadowRoot",
        "attachShadow",
        "shadow-root",
        ".shadowRoot",
        "attachShadow(",
    ];
    if shadow_patterns.iter().any(|s| body.contains(s)) && body.contains(".observe(") {
        issues.push(MutationObserverSecurityIssue::ShadowDomPenetration);
    }

    issues
}

pub fn mutation_observer_security_severity(issue: &MutationObserverSecurityIssue) -> f64 {
    match issue {
        MutationObserverSecurityIssue::DomExfiltration => 8.0,
        MutationObserverSecurityIssue::PasswordFieldMonitoring => 7.5,
        MutationObserverSecurityIssue::TokenExtraction => 7.0,
        MutationObserverSecurityIssue::KeystrokeReconstruction => 7.0,
        MutationObserverSecurityIssue::DocumentWideObserver => 6.5,
        MutationObserverSecurityIssue::CrossOriginFrameWatch => 6.0,
        MutationObserverSecurityIssue::ClipboardInterception => 5.5,
        MutationObserverSecurityIssue::ScriptInjectionWatch => 5.0,
        MutationObserverSecurityIssue::HiddenElementTracking => 4.5,
        MutationObserverSecurityIssue::ShadowDomPenetration => 4.0,
    }
}

pub fn mutation_observer_security_to_operations(
    issues: &[MutationObserverSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                mutation_observer_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
