use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ClipboardIssue {
    ClipboardReadAccess,
    ClipboardWriteAccess,
    PasteEventIntercepted,
    CopyEventIntercepted,
    ExecCommandCopy,
    ExecCommandPaste,
    ClipboardDataExfiltration,
}

impl std::fmt::Display for ClipboardIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClipboardReadAccess => write!(f, "clipboard_read"),
            Self::ClipboardWriteAccess => write!(f, "clipboard_write"),
            Self::PasteEventIntercepted => write!(f, "paste_intercepted"),
            Self::CopyEventIntercepted => write!(f, "copy_intercepted"),
            Self::ExecCommandCopy => write!(f, "exec_command_copy"),
            Self::ExecCommandPaste => write!(f, "exec_command_paste"),
            Self::ClipboardDataExfiltration => write!(f, "clipboard_exfiltration"),
        }
    }
}

pub fn audit_clipboard(target: &str) -> Vec<ClipboardIssue> {
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
    analyze_clipboard(&body)
}

pub fn analyze_clipboard(body: &str) -> Vec<ClipboardIssue> {
    if !has_clipboard_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("navigator.clipboard.readText")
        || body.contains("navigator.clipboard.read(")
    {
        issues.push(ClipboardIssue::ClipboardReadAccess);
    }

    if body.contains("navigator.clipboard.writeText")
        || body.contains("navigator.clipboard.write(")
    {
        issues.push(ClipboardIssue::ClipboardWriteAccess);
    }

    check_event_listeners(body, &mut issues);
    check_exec_command(body, &mut issues);
    check_exfiltration(body, &mut issues);

    issues
}

fn has_clipboard_indicators(body: &str) -> bool {
    body.contains("clipboard")
        || body.contains("execCommand")
        || body.contains("onpaste")
        || body.contains("oncopy")
        || (body.contains("addEventListener")
            && (body.contains("paste") || body.contains("copy")))
}

fn check_event_listeners(body: &str, issues: &mut Vec<ClipboardIssue>) {
    let paste_patterns = [
        "addEventListener(\"paste\"",
        "addEventListener('paste'",
        "onpaste",
        "addEventListener(\"paste",
    ];
    if paste_patterns.iter().any(|p| body.contains(p)) {
        issues.push(ClipboardIssue::PasteEventIntercepted);
    }

    let copy_patterns = [
        "addEventListener(\"copy\"",
        "addEventListener('copy'",
        "oncopy",
        "addEventListener(\"copy",
    ];
    if copy_patterns.iter().any(|p| body.contains(p)) {
        issues.push(ClipboardIssue::CopyEventIntercepted);
    }
}

fn check_exec_command(body: &str, issues: &mut Vec<ClipboardIssue>) {
    if !body.contains("execCommand") {
        return;
    }
    if body.contains("execCommand(\"copy\"")
        || body.contains("execCommand('copy'")
        || body.contains("execCommand(\"copy)")
        || body.contains("execCommand('copy)")
    {
        issues.push(ClipboardIssue::ExecCommandCopy);
    }
    if body.contains("execCommand(\"paste\"")
        || body.contains("execCommand('paste'")
        || body.contains("execCommand(\"paste)")
        || body.contains("execCommand('paste)")
    {
        issues.push(ClipboardIssue::ExecCommandPaste);
    }
}

fn check_exfiltration(body: &str, issues: &mut Vec<ClipboardIssue>) {
    let reads_clipboard = body.contains("navigator.clipboard.readText")
        || body.contains("navigator.clipboard.read(")
        || body.contains("clipboardData.getData")
        || body.contains("execCommand('paste")
        || body.contains("execCommand(\"paste");

    let sends_data = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains("sendBeacon")
        || body.contains(".send(")
        || body.contains("$.ajax")
        || body.contains("$.post");

    if reads_clipboard && sends_data {
        issues.push(ClipboardIssue::ClipboardDataExfiltration);
    }
}

pub fn clipboard_severity(issue: &ClipboardIssue) -> f64 {
    match issue {
        ClipboardIssue::ClipboardDataExfiltration => 8.0,
        ClipboardIssue::ClipboardReadAccess => 6.0,
        ClipboardIssue::ExecCommandPaste => 5.5,
        ClipboardIssue::PasteEventIntercepted => 5.0,
        ClipboardIssue::CopyEventIntercepted => 4.0,
        ClipboardIssue::ClipboardWriteAccess => 3.5,
        ClipboardIssue::ExecCommandCopy => 3.0,
    }
}

pub fn clipboard_to_operations(
    issues: &[ClipboardIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                clipboard_severity(issue),
                0.7,
            )
        })
        .collect()
}
