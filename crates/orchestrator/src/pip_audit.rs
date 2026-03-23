use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum PipIssue {
    PipRequested,
    DocumentPip,
    AutoPipAttribute,
    PipWindowAccess,
    OverlayAttack,
    NoUserActivation,
}

impl std::fmt::Display for PipIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PipRequested => write!(f, "pip_requested"),
            Self::DocumentPip => write!(f, "document_pip"),
            Self::AutoPipAttribute => write!(f, "auto_pip_attribute"),
            Self::PipWindowAccess => write!(f, "pip_window_access"),
            Self::OverlayAttack => write!(f, "overlay_attack"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
        }
    }
}

pub fn audit_pip(target: &str) -> Vec<PipIssue> {
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
    analyze_pip(&body)
}

pub fn analyze_pip(body: &str) -> Vec<PipIssue> {
    let has_pip = body.contains("requestPictureInPicture")
        || body.contains("pictureInPictureElement")
        || body.contains("documentPictureInPicture")
        || body.contains("autopictureinpicture");
    if !has_pip {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("requestPictureInPicture") {
        issues.push(PipIssue::PipRequested);

        if !body.contains("click") && !body.contains("pointerdown")
            && !body.contains("touchstart")
        {
            issues.push(PipIssue::NoUserActivation);
        }
    }

    if body.contains("documentPictureInPicture") {
        issues.push(PipIssue::DocumentPip);

        if body.contains("window") && body.contains("document.createElement") {
            issues.push(PipIssue::OverlayAttack);
        }
    }

    if body.contains("autopictureinpicture") {
        issues.push(PipIssue::AutoPipAttribute);
    }

    if body.contains("pictureInPictureWindow") || body.contains("pipWindow") {
        issues.push(PipIssue::PipWindowAccess);
    }

    issues
}

pub fn pip_severity(issue: &PipIssue) -> f64 {
    match issue {
        PipIssue::OverlayAttack => 6.5,
        PipIssue::DocumentPip => 5.5,
        PipIssue::NoUserActivation => 5.0,
        PipIssue::PipWindowAccess => 4.5,
        PipIssue::AutoPipAttribute => 4.0,
        PipIssue::PipRequested => 3.0,
    }
}

pub fn pip_to_operations(
    issues: &[PipIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                pip_severity(issue),
                0.6,
            )
        })
        .collect()
}
