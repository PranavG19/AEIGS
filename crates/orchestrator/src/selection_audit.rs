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

pub fn selection_severity(issue: &SelectionIssue) -> f64 {
    match issue {
        SelectionIssue::SelectionExfiltration => 6.5,
        SelectionIssue::ClipboardHijack => 6.0,
        SelectionIssue::HiddenTextSelection => 5.5,
        SelectionIssue::ContinuousMonitoring => 5.0,
        SelectionIssue::RangeManipulation => 4.5,
        SelectionIssue::ApiDetected => 3.0,
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
