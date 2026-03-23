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
    let has_api = body.contains("documentPictureInPicture")
        || body.contains("DocumentPictureInPicture");

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
        && (body.contains("innerHTML") || body.contains("document.write") || body.contains("insertAdjacentHTML"))
        && !body.contains("sanitize")
    {
        issues.push(DocumentPipIssue::ContentInjection);
    }

    if body.contains("requestWindow")
        && (body.contains("setInterval") || body.contains("beforeunload") || body.contains("visibilitychange"))
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
