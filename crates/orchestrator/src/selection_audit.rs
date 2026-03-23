use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum SelectionIssue {
    ApiDetected,
    SelectionExfiltration,
    ClipboardHijack,
    HiddenTextSelection,
    ContinuousMonitoring,
    RangeManipulation,
    SelectionToClipboard,
    SelectionInIframe,
    SelectionWithDragDrop,
    SelectionPayloadInjection,
    SelectionTimingAttack,
    SelectionCrossOrigin,
    SelectionOfPasswordFields,
    SelectionWithMutationObserver,
    SelectionToWorker,
    SelectionScreenshot,
}

impl std::fmt::Display for SelectionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::SelectionExfiltration => write!(f, "selection_exfiltration"),
            Self::ClipboardHijack => write!(f, "clipboard_hijack"),
            Self::HiddenTextSelection => write!(f, "hidden_text_selection"),
            Self::ContinuousMonitoring => write!(f, "continuous_monitoring"),
            Self::RangeManipulation => write!(f, "range_manipulation"),
            Self::SelectionToClipboard => write!(f, "selection_to_clipboard"),
            Self::SelectionInIframe => write!(f, "selection_in_iframe"),
            Self::SelectionWithDragDrop => write!(f, "selection_with_drag_drop"),
            Self::SelectionPayloadInjection => write!(f, "selection_payload_injection"),
            Self::SelectionTimingAttack => write!(f, "selection_timing_attack"),
            Self::SelectionCrossOrigin => write!(f, "selection_cross_origin"),
            Self::SelectionOfPasswordFields => write!(f, "selection_of_password_fields"),
            Self::SelectionWithMutationObserver => write!(f, "selection_with_mutation_observer"),
            Self::SelectionToWorker => write!(f, "selection_to_worker"),
            Self::SelectionScreenshot => write!(f, "selection_screenshot"),
        }
    }
}

pub fn audit_selection(target: &str) -> Vec<SelectionIssue> {
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
    analyze_selection(&body)
}

pub fn analyze_selection(body: &str) -> Vec<SelectionIssue> {
    let has_selection = body.contains("getSelection")
        || body.contains("window.selection")
        || body.contains("document.selection");
    if !has_selection {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(SelectionIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(SelectionIssue::SelectionExfiltration);
    }

    if body.contains("execCommand(\"copy\")")
        || body.contains("execCommand('copy')")
        || body.contains("clipboard.writeText")
    {
        issues.push(SelectionIssue::ClipboardHijack);
    }

    if body.contains("visibility:hidden")
        || body.contains("display:none")
        || body.contains("opacity:0")
        || body.contains("position:absolute")
    {
        issues.push(SelectionIssue::HiddenTextSelection);
    }

    if body.contains("selectionchange") || body.contains("selectstart") {
        issues.push(SelectionIssue::ContinuousMonitoring);
    }

    if body.contains("createRange")
        || body.contains("addRange")
        || body.contains("selectAllChildren")
    {
        issues.push(SelectionIssue::RangeManipulation);
    }

    issues
}

pub fn analyze_selection_security(body: &str) -> Vec<SelectionIssue> {
    let has_selection = body.contains("getSelection")
        || body.contains("window.selection")
        || body.contains("document.selection");
    if !has_selection {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("navigator.clipboard") || body.contains("clipboardData") {
        issues.push(SelectionIssue::SelectionToClipboard);
    }

    if body.contains("contentDocument")
        || (body.contains("contentWindow") && body.contains("getSelection"))
    {
        issues.push(SelectionIssue::SelectionInIframe);
    }

    if body.contains("dragstart")
        || body.contains("dragover")
        || body.contains("drop")
        || body.contains("dataTransfer")
    {
        issues.push(SelectionIssue::SelectionWithDragDrop);
    }

    if body.contains("innerHTML")
        || body.contains("insertAdjacentHTML")
        || body.contains("document.write")
    {
        issues.push(SelectionIssue::SelectionPayloadInjection);
    }

    if body.contains("performance.now")
        || body.contains("Date.now")
        || body.contains("performance.mark")
    {
        issues.push(SelectionIssue::SelectionTimingAttack);
    }

    if body.contains("postMessage") || body.contains("cross-origin") || body.contains("iframe") {
        issues.push(SelectionIssue::SelectionCrossOrigin);
    }

    if body.contains("type=\"password\"")
        || body.contains("type='password'")
        || body.contains("password")
    {
        issues.push(SelectionIssue::SelectionOfPasswordFields);
    }

    if body.contains("MutationObserver") {
        issues.push(SelectionIssue::SelectionWithMutationObserver);
    }

    if body.contains("Worker") || body.contains("SharedWorker") || body.contains("postMessage") {
        issues.push(SelectionIssue::SelectionToWorker);
    }

    if body.contains("html2canvas")
        || body.contains("toDataURL")
        || body.contains("toBlob")
        || body.contains("captureStream")
    {
        issues.push(SelectionIssue::SelectionScreenshot);
    }

    issues
}

pub fn selection_severity(issue: &SelectionIssue) -> f64 {
    match issue {
        SelectionIssue::SelectionExfiltration => 6.5,
        SelectionIssue::ClipboardHijack => 6.0,
        SelectionIssue::HiddenTextSelection => 5.5,
        SelectionIssue::ContinuousMonitoring => 5.0,
        SelectionIssue::RangeManipulation => 4.5,
        SelectionIssue::ApiDetected => 3.0,
        SelectionIssue::SelectionToClipboard => 6.0,
        SelectionIssue::SelectionInIframe => 7.5,
        SelectionIssue::SelectionWithDragDrop => 5.5,
        SelectionIssue::SelectionPayloadInjection => 8.0,
        SelectionIssue::SelectionTimingAttack => 6.0,
        SelectionIssue::SelectionCrossOrigin => 7.0,
        SelectionIssue::SelectionOfPasswordFields => 9.0,
        SelectionIssue::SelectionWithMutationObserver => 5.0,
        SelectionIssue::SelectionToWorker => 6.5,
        SelectionIssue::SelectionScreenshot => 7.5,
    }
}

pub fn selection_to_operations(issues: &[SelectionIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                selection_severity(issue),
                0.7,
            )
        })
        .collect()
}

pub fn selection_security_to_operations(
    issues: &[SelectionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                selection_severity(issue),
                0.7,
            )
        })
        .collect()
}
