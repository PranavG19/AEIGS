use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum ClipboardIssue {
    ApiDetected,
    SilentClipboardRead,
    ClipboardHijacking,
    SensitiveDataClipboard,
    MissingPermissionCheck,
    CrossOriginClipboardAccess,
}

impl std::fmt::Display for ClipboardIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "clipboard_api_detected"),
            Self::SilentClipboardRead => write!(f, "silent_clipboard_read"),
            Self::ClipboardHijacking => write!(f, "clipboard_hijacking"),
            Self::SensitiveDataClipboard => write!(f, "sensitive_data_clipboard"),
            Self::MissingPermissionCheck => write!(f, "missing_permission_check"),
            Self::CrossOriginClipboardAccess => write!(f, "cross_origin_clipboard_access"),
        }
    }
}

pub fn clipboard_severity(issue: &ClipboardIssue) -> f64 {
    match issue {
        ClipboardIssue::SilentClipboardRead => 8.5,
        ClipboardIssue::ClipboardHijacking => 8.0,
        ClipboardIssue::SensitiveDataClipboard => 7.5,
        ClipboardIssue::CrossOriginClipboardAccess => 6.5,
        ClipboardIssue::MissingPermissionCheck => 5.5,
        ClipboardIssue::ApiDetected => 3.0,
    }
}

pub fn audit_clipboard(target: &str) -> Vec<ClipboardIssue> {
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
    analyze_clipboard(&body)
}

pub fn analyze_clipboard(body: &str) -> Vec<ClipboardIssue> {
    if !has_clipboard_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if has_clipboard_api(body) {
        issues.push(ClipboardIssue::ApiDetected);
    }

    if has_silent_clipboard_read(body) {
        issues.push(ClipboardIssue::SilentClipboardRead);
    }

    if has_clipboard_hijacking(body) {
        issues.push(ClipboardIssue::ClipboardHijacking);
    }

    if has_sensitive_data_clipboard(body) {
        issues.push(ClipboardIssue::SensitiveDataClipboard);
    }

    if has_missing_permission_check(body) {
        issues.push(ClipboardIssue::MissingPermissionCheck);
    }

    if has_cross_origin_clipboard_access(body) {
        issues.push(ClipboardIssue::CrossOriginClipboardAccess);
    }

    issues
}

fn has_clipboard_indicators(body: &str) -> bool {
    body.contains("clipboard")
        || body.contains("execCommand")
        || body.contains("onpaste")
        || body.contains("oncopy")
        || body.contains("clipboardData")
}

fn has_clipboard_api(body: &str) -> bool {
    body.contains("navigator.clipboard")
        || body.contains("clipboard.readText")
        || body.contains("clipboard.writeText")
        || body.contains("clipboard.read(")
        || body.contains("clipboard.write(")
        || body.contains("execCommand('copy'")
        || body.contains("execCommand(\"copy\"")
        || body.contains("execCommand('paste'")
        || body.contains("execCommand(\"paste\"")
}

fn has_silent_clipboard_read(body: &str) -> bool {
    let has_read = body.contains("clipboard.readText")
        || body.contains("clipboard.read(")
        || body.contains("execCommand('paste'")
        || body.contains("execCommand(\"paste\"");

    if !has_read {
        return false;
    }

    let has_user_gesture = body.contains("click")
        || body.contains("mousedown")
        || body.contains("keydown")
        || body.contains("touchstart")
        || body.contains("pointerdown");

    let has_permission_check = body.contains("navigator.permissions.query")
        || body.contains("clipboard-read")
        || body.contains("clipboard-write");

    has_read && !has_user_gesture && !has_permission_check
}

fn has_clipboard_hijacking(body: &str) -> bool {
    let has_write = body.contains("clipboard.writeText")
        || body.contains("clipboard.write(")
        || body.contains("execCommand('copy'")
        || body.contains("execCommand(\"copy\"")
        || body.contains("clipboardData.setData");

    if !has_write {
        return false;
    }

    let suspicious_patterns = [
        "bitcoin",
        "btc",
        "ethereum",
        "eth",
        "wallet",
        "0x",
        "bc1",
        "address",
        "crypto",
        "oncopy",
        "addEventListener('copy'",
        "addEventListener(\"copy\"",
        "clipboardData.setData",
        "e.preventDefault()",
        "event.preventDefault()",
    ];

    suspicious_patterns.iter().any(|p| body.contains(p))
}

fn has_sensitive_data_clipboard(body: &str) -> bool {
    let has_clipboard_op = body.contains("clipboard.readText")
        || body.contains("clipboard.writeText")
        || body.contains("clipboard.read(")
        || body.contains("clipboard.write(")
        || body.contains("clipboardData.getData")
        || body.contains("clipboardData.setData");

    if !has_clipboard_op {
        return false;
    }

    let sensitive_patterns = [
        "password",
        "passwd",
        "pwd",
        "token",
        "secret",
        "apiKey",
        "api_key",
        "accessToken",
        "access_token",
        "authToken",
        "auth_token",
        "sessionId",
        "session_id",
        "privateKey",
        "private_key",
        "credential",
    ];

    sensitive_patterns.iter().any(|p| body.contains(p))
}

fn has_missing_permission_check(body: &str) -> bool {
    let has_clipboard_op = body.contains("clipboard.readText")
        || body.contains("clipboard.read(")
        || body.contains("clipboard.writeText")
        || body.contains("clipboard.write(");

    if !has_clipboard_op {
        return false;
    }

    let has_permission_check = body.contains("navigator.permissions.query")
        || body.contains("permissions.query")
        || body.contains("clipboard-read")
        || body.contains("clipboard-write");

    has_clipboard_op && !has_permission_check
}

fn has_cross_origin_clipboard_access(body: &str) -> bool {
    let has_iframe = body.contains("<iframe") || body.contains("iframe");

    if !has_iframe {
        return false;
    }

    let has_clipboard = body.contains("clipboard.readText")
        || body.contains("clipboard.writeText")
        || body.contains("clipboard.read(")
        || body.contains("clipboard.write(");

    if !has_clipboard {
        return false;
    }

    let has_allow_clipboard_read = body.contains("allow=\"clipboard-read")
        || body.contains("allow='clipboard-read")
        || body.contains("allow=\"clipboard-write")
        || body.contains("allow='clipboard-write");

    has_iframe && has_clipboard && !has_allow_clipboard_read
}

pub fn clipboard_to_operations(issues: &[ClipboardIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                clipboard_severity(issue),
                0.5,
            )
        })
        .collect()
}
