use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum DragDropIssue {
    DropEventDataAccess,
    DragStartDataSet,
    CrossOriginDragData,
    DragDataExfiltration,
    HiddenDropZone,
    DragOverPreventDefault,
    ClipboardViaDrag,
}

impl std::fmt::Display for DragDropIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DropEventDataAccess => write!(f, "drop_event_data_access"),
            Self::DragStartDataSet => write!(f, "drag_start_data_set"),
            Self::CrossOriginDragData => write!(f, "cross_origin_drag_data"),
            Self::DragDataExfiltration => write!(f, "drag_data_exfiltration"),
            Self::HiddenDropZone => write!(f, "hidden_drop_zone"),
            Self::DragOverPreventDefault => write!(f, "dragover_prevent_default"),
            Self::ClipboardViaDrag => write!(f, "clipboard_via_drag"),
        }
    }
}

pub fn audit_drag_drop(target: &str) -> Vec<DragDropIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_drag_drop(&body)
}

pub fn analyze_drag_drop(body: &str) -> Vec<DragDropIssue> {
    if !has_drag_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("dataTransfer.getData") || body.contains("dataTransfer.items") {
        issues.push(DragDropIssue::DropEventDataAccess);
    }

    if body.contains("dataTransfer.setData") {
        issues.push(DragDropIssue::DragStartDataSet);
    }

    if body.contains("dataTransfer")
        && (body.contains("text/uri-list") || body.contains("text/html"))
    {
        issues.push(DragDropIssue::CrossOriginDragData);
    }

    let has_drag_data =
        body.contains("dataTransfer.getData") || body.contains("dataTransfer.items");
    let sends = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains(".send(")
        || body.contains("sendBeacon");
    if has_drag_data && sends {
        issues.push(DragDropIssue::DragDataExfiltration);
    }

    let lower = body.to_ascii_lowercase();
    if (lower.contains("opacity:0") || lower.contains("opacity: 0") || lower.contains("hidden"))
        && (body.contains("ondrop") || body.contains("addEventListener"))
    {
        issues.push(DragDropIssue::HiddenDropZone);
    }

    if body.contains("dragover") && body.contains("preventDefault") {
        issues.push(DragDropIssue::DragOverPreventDefault);
    }

    if body.contains("dataTransfer") && body.contains("clipboardData") {
        issues.push(DragDropIssue::ClipboardViaDrag);
    }

    issues
}

fn has_drag_indicators(body: &str) -> bool {
    body.contains("dataTransfer")
        || body.contains("ondrop")
        || body.contains("ondragstart")
        || body.contains("ondragover")
}

pub fn drag_drop_severity(issue: &DragDropIssue) -> f64 {
    match issue {
        DragDropIssue::DragDataExfiltration => 7.5,
        DragDropIssue::HiddenDropZone => 7.0,
        DragDropIssue::ClipboardViaDrag => 6.5,
        DragDropIssue::CrossOriginDragData => 6.0,
        DragDropIssue::DropEventDataAccess => 5.0,
        DragDropIssue::DragStartDataSet => 4.5,
        DragDropIssue::DragOverPreventDefault => 3.5,
    }
}

pub fn drag_drop_to_operations(issues: &[DragDropIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                drag_drop_severity(issue),
                0.7,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum DragDropSecurityIssue {
    DragDataExfiltration,
    DragCrossOrigin,
    DragHiddenContent,
    DropZonePhishing,
    DragWithoutUserInteraction,
    DragFileAccess,
    DragClipboardOverwrite,
    DragInIframe,
    DragSensitiveData,
    DragEventSpying,
}

impl std::fmt::Display for DragDropSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DragDataExfiltration => write!(f, "drag_data_exfiltration"),
            Self::DragCrossOrigin => write!(f, "drag_cross_origin"),
            Self::DragHiddenContent => write!(f, "drag_hidden_content"),
            Self::DropZonePhishing => write!(f, "drop_zone_phishing"),
            Self::DragWithoutUserInteraction => write!(f, "drag_without_user_interaction"),
            Self::DragFileAccess => write!(f, "drag_file_access"),
            Self::DragClipboardOverwrite => write!(f, "drag_clipboard_overwrite"),
            Self::DragInIframe => write!(f, "drag_in_iframe"),
            Self::DragSensitiveData => write!(f, "drag_sensitive_data"),
            Self::DragEventSpying => write!(f, "drag_event_spying"),
        }
    }
}

pub fn analyze_drag_drop_security(body: &str) -> Vec<DragDropSecurityIssue> {
    if !has_drag_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    let has_get_data = body.contains("dataTransfer.getData") || body.contains("dataTransfer.items");
    let sends = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains(".send(")
        || body.contains("sendBeacon");
    if has_get_data && sends {
        issues.push(DragDropSecurityIssue::DragDataExfiltration);
    }

    if body.contains("dataTransfer") && body.contains("postMessage") {
        issues.push(DragDropSecurityIssue::DragCrossOrigin);
    }

    let has_set_data = body.contains("dataTransfer.setData");
    if has_set_data
        && (body.contains("btoa") || body.contains("encodeURI") || body.contains("base64"))
    {
        issues.push(DragDropSecurityIssue::DragHiddenContent);
    }

    let lower = body.to_ascii_lowercase();
    if (lower.contains("drop") || lower.contains("ondrop"))
        && (lower.contains("password") || lower.contains("credentials") || lower.contains("login"))
    {
        issues.push(DragDropSecurityIssue::DropZonePhishing);
    }

    if body.contains("dispatchEvent") && body.contains("DragEvent") {
        issues.push(DragDropSecurityIssue::DragWithoutUserInteraction);
    }

    if body.contains("dataTransfer.files")
        || (body.contains("FileReader") && body.contains("dataTransfer"))
    {
        issues.push(DragDropSecurityIssue::DragFileAccess);
    }

    if has_set_data && body.contains("text/plain") {
        issues.push(DragDropSecurityIssue::DragClipboardOverwrite);
    }

    if body.contains("iframe") && (body.contains("ondrop") || body.contains("ondragstart")) {
        issues.push(DragDropSecurityIssue::DragInIframe);
    }

    let sensitive_patterns = ["password", "credit", "token", "api_key", "apikey", "secret"];
    if has_get_data && sensitive_patterns.iter().any(|p| lower.contains(p)) {
        issues.push(DragDropSecurityIssue::DragSensitiveData);
    }

    let drag_events = ["dragstart", "dragend", "drop"];
    let has_multiple_listeners = drag_events
        .iter()
        .filter(|e| {
            body.contains(&format!("addEventListener('{}'", e))
                || body.contains(&format!("on{}", e))
        })
        .count()
        >= 2;
    if has_multiple_listeners {
        issues.push(DragDropSecurityIssue::DragEventSpying);
    }

    issues
}

pub fn drag_drop_security_severity(issue: &DragDropSecurityIssue) -> f64 {
    match issue {
        DragDropSecurityIssue::DragDataExfiltration => 9.0,
        DragDropSecurityIssue::DragSensitiveData => 8.5,
        DragDropSecurityIssue::DragFileAccess => 8.0,
        DragDropSecurityIssue::DropZonePhishing => 7.5,
        DragDropSecurityIssue::DragCrossOrigin => 7.0,
        DragDropSecurityIssue::DragHiddenContent => 6.5,
        DragDropSecurityIssue::DragEventSpying => 6.0,
        DragDropSecurityIssue::DragInIframe => 5.5,
        DragDropSecurityIssue::DragWithoutUserInteraction => 5.0,
        DragDropSecurityIssue::DragClipboardOverwrite => 3.0,
    }
}

pub fn drag_drop_security_to_operations(
    issues: &[DragDropSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                drag_drop_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
