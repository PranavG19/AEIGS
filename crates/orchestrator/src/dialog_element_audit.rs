use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum DialogElementIssue {
    ApiDetected,
    XssInDialog,
    ClickjackingViaModal,
    FormHijacking,
    FocusTrap,
}

impl std::fmt::Display for DialogElementIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::XssInDialog => write!(f, "xss_in_dialog"),
            Self::ClickjackingViaModal => write!(f, "clickjacking_via_modal"),
            Self::FormHijacking => write!(f, "form_hijacking"),
            Self::FocusTrap => write!(f, "focus_trap"),
        }
    }
}

pub fn audit_dialog_element(target: &str) -> Vec<DialogElementIssue> {
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
    analyze_dialog_element(&body)
}

pub fn analyze_dialog_element(body: &str) -> Vec<DialogElementIssue> {
    let mut issues = Vec::new();

    let has_api = body.contains("<dialog")
        || body.contains("showModal")
        || body.contains("showPopover")
        || body.contains("HTMLDialogElement");

    if !has_api {
        return issues;
    }

    issues.push(DialogElementIssue::ApiDetected);

    let has_unsafe_content = body.contains("innerHTML")
        || body.contains("insertAdjacentHTML")
        || body.contains("document.write");
    let has_sanitization =
        body.contains("sanitize") || body.contains("DOMPurify") || body.contains("escape");

    if has_unsafe_content && !has_sanitization {
        issues.push(DialogElementIssue::XssInDialog);
    }

    let has_show_modal = body.contains("showModal");
    let has_clickjack_style = body.contains("opacity")
        || body.contains("transparent")
        || body.contains("pointer-events")
        || body.contains("z-index");

    if has_show_modal && has_clickjack_style {
        issues.push(DialogElementIssue::ClickjackingViaModal);
    }

    let has_form = body.contains("<form") && body.contains("action=");
    let has_external_url = body.contains("http://") || body.contains("https://");
    let has_method_dialog = body.contains("method=\"dialog\"");

    if has_form && has_external_url && !has_method_dialog {
        issues.push(DialogElementIssue::FormHijacking);
    }

    let has_focus = body.contains("focus") || body.contains("autofocus");
    let has_close =
        body.contains("close") || body.contains("returnValue") || body.contains("Escape");

    if has_show_modal && has_focus && !has_close {
        issues.push(DialogElementIssue::FocusTrap);
    }

    issues
}

pub fn dialog_element_severity(issue: &DialogElementIssue) -> f64 {
    match issue {
        DialogElementIssue::ApiDetected => 2.0,
        DialogElementIssue::XssInDialog => 8.0,
        DialogElementIssue::ClickjackingViaModal => 7.0,
        DialogElementIssue::FormHijacking => 7.5,
        DialogElementIssue::FocusTrap => 5.5,
    }
}

pub fn dialog_element_to_operations(
    issues: &[DialogElementIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CrossSiteScripting,
                dialog_element_severity(issue),
                0.5,
            )
        })
        .collect()
}
