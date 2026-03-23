use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum DocumentPipIssue {
    ApiDetected,
    UiSpoofing,
    OverlayAttack,
    ContentInjection,
    PersistentWindow,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DocumentPipSecurityIssue {
    PipPhishing,
    PipDataExfiltration,
    PipWithoutUserGesture,
    PipCrossOriginContent,
    PipOverlayAttack,
    PipPersistentWindow,
    PipSensitiveDataDisplay,
    PipScreenCapture,
    PipInBackground,
    PipFormInjection,
}

impl std::fmt::Display for DocumentPipIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::UiSpoofing => write!(f, "ui_spoofing"),
            Self::OverlayAttack => write!(f, "overlay_attack"),
            Self::ContentInjection => write!(f, "content_injection"),
            Self::PersistentWindow => write!(f, "persistent_window"),
        }
    }
}

impl std::fmt::Display for DocumentPipSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PipPhishing => write!(f, "pip_phishing"),
            Self::PipDataExfiltration => write!(f, "pip_data_exfiltration"),
            Self::PipWithoutUserGesture => write!(f, "pip_without_user_gesture"),
            Self::PipCrossOriginContent => write!(f, "pip_cross_origin_content"),
            Self::PipOverlayAttack => write!(f, "pip_overlay_attack"),
            Self::PipPersistentWindow => write!(f, "pip_persistent_window"),
            Self::PipSensitiveDataDisplay => write!(f, "pip_sensitive_data_display"),
            Self::PipScreenCapture => write!(f, "pip_screen_capture"),
            Self::PipInBackground => write!(f, "pip_in_background"),
            Self::PipFormInjection => write!(f, "pip_form_injection"),
        }
    }
}

pub fn audit_document_pip(target: &str) -> Vec<DocumentPipIssue> {
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
    analyze_document_pip(&body)
}

pub fn analyze_document_pip(body: &str) -> Vec<DocumentPipIssue> {
    let has_api =
        body.contains("documentPictureInPicture") || body.contains("DocumentPictureInPicture");

    if !has_api {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(DocumentPipIssue::ApiDetected);

    if body.contains("requestWindow")
        && (body.contains("width") || body.contains("height"))
        && (body.contains("position") || body.contains("moveTo") || body.contains("resizeTo"))
    {
        issues.push(DocumentPipIssue::UiSpoofing);
    }

    if body.contains("requestWindow")
        && (body.contains("z-index") || body.contains("zIndex") || body.contains("alwaysOnTop"))
        && (body.contains("opacity") || body.contains("transparent"))
    {
        issues.push(DocumentPipIssue::OverlayAttack);
    }

    if has_api
        && (body.contains("innerHTML")
            || body.contains("document.write")
            || body.contains("insertAdjacentHTML"))
        && !body.contains("sanitize")
    {
        issues.push(DocumentPipIssue::ContentInjection);
    }

    if body.contains("requestWindow")
        && (body.contains("setInterval")
            || body.contains("beforeunload")
            || body.contains("visibilitychange"))
        && !body.contains("close(")
    {
        issues.push(DocumentPipIssue::PersistentWindow);
    }

    issues
}

pub fn document_pip_severity(issue: &DocumentPipIssue) -> f64 {
    match issue {
        DocumentPipIssue::ContentInjection => 7.5,
        DocumentPipIssue::OverlayAttack => 7.0,
        DocumentPipIssue::UiSpoofing => 6.5,
        DocumentPipIssue::PersistentWindow => 5.0,
        DocumentPipIssue::ApiDetected => 2.0,
    }
}

pub fn document_pip_to_operations(
    issues: &[DocumentPipIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                document_pip_severity(issue),
                0.5,
            )
        })
        .collect()
}

pub fn analyze_document_pip_security(body: &str) -> Vec<DocumentPipSecurityIssue> {
    let has_api =
        body.contains("documentPictureInPicture") || body.contains("DocumentPictureInPicture");

    if !has_api {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("requestWindow")
        && (body.contains("<input")
            && (body.contains("type=\"password\"")
                || body.contains("type='password'")
                || body.contains("password")))
        && (body.contains("<form") || body.contains("action="))
    {
        issues.push(DocumentPipSecurityIssue::PipPhishing);
    }

    if body.contains("requestWindow")
        && body.contains("fetch")
        && (body.contains("method:")
            || body.contains("POST")
            || body.contains("body:")
            || body.contains("JSON.stringify"))
    {
        issues.push(DocumentPipSecurityIssue::PipDataExfiltration);
    }

    if body.contains("requestWindow")
        && !body.contains("click")
        && !body.contains("keydown")
        && !body.contains("pointerdown")
        && !body.contains("addEventListener")
    {
        issues.push(DocumentPipSecurityIssue::PipWithoutUserGesture);
    }

    if body.contains("requestWindow")
        && (body.contains("src=")
            && (body.contains("http://") || body.contains("https://"))
            && !body.contains("same-origin"))
    {
        issues.push(DocumentPipSecurityIssue::PipCrossOriginContent);
    }

    if body.contains("requestWindow")
        && (body.contains("z-index")
            || body.contains("zIndex")
            || body.contains("position: absolute")
            || body.contains("position: fixed"))
        && (body.contains("pointer-events") || body.contains("pointerEvents"))
    {
        issues.push(DocumentPipSecurityIssue::PipOverlayAttack);
    }

    if body.contains("requestWindow")
        && (body.contains("beforeunload")
            || body.contains("pagehide")
            || body.contains("localStorage")
            || body.contains("sessionStorage"))
        && body.contains("setInterval")
    {
        issues.push(DocumentPipSecurityIssue::PipPersistentWindow);
    }

    if body.contains("requestWindow")
        && (body.contains("password")
            || body.contains("credit")
            || body.contains("ssn")
            || body.contains("social security")
            || body.contains("cvv")
            || body.contains("card"))
        && (body.contains("value") || body.contains("textContent") || body.contains("innerText"))
    {
        issues.push(DocumentPipSecurityIssue::PipSensitiveDataDisplay);
    }

    if body.contains("requestWindow")
        && (body.contains("getDisplayMedia") || body.contains("captureStream"))
    {
        issues.push(DocumentPipSecurityIssue::PipScreenCapture);
    }

    if body.contains("requestWindow")
        && (body.contains("visibilitychange")
            || body.contains("document.hidden")
            || body.contains("document.visibilityState"))
        && !body.contains("close(")
    {
        issues.push(DocumentPipSecurityIssue::PipInBackground);
    }

    if body.contains("requestWindow")
        && (body.contains("<form")
            || body.contains("createElement('form')")
            || body.contains("createElement(\"form\")"))
        && (body.contains("createElement")
            || body.contains("insertAdjacentHTML")
            || body.contains("innerHTML"))
        && !body.contains("sanitize")
    {
        issues.push(DocumentPipSecurityIssue::PipFormInjection);
    }

    issues
}

pub fn document_pip_security_severity(issue: &DocumentPipSecurityIssue) -> f64 {
    match issue {
        DocumentPipSecurityIssue::PipPhishing => 9.0,
        DocumentPipSecurityIssue::PipDataExfiltration => 8.5,
        DocumentPipSecurityIssue::PipFormInjection => 8.0,
        DocumentPipSecurityIssue::PipCrossOriginContent => 7.5,
        DocumentPipSecurityIssue::PipSensitiveDataDisplay => 7.0,
        DocumentPipSecurityIssue::PipOverlayAttack => 6.5,
        DocumentPipSecurityIssue::PipScreenCapture => 6.0,
        DocumentPipSecurityIssue::PipWithoutUserGesture => 5.5,
        DocumentPipSecurityIssue::PipPersistentWindow => 5.0,
        DocumentPipSecurityIssue::PipInBackground => 4.0,
    }
}

pub fn document_pip_security_to_operations(
    issues: &[DocumentPipSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                document_pip_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
