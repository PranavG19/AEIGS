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

        if !body.contains("click") && !body.contains("pointerdown") && !body.contains("touchstart")
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

pub fn pip_to_operations(issues: &[PipIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
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

#[derive(Debug, Clone, PartialEq)]
pub enum PipSecurityIssue {
    PipWithoutUserGesture,
    DocumentPipOverlay,
    PipFormSpoofing,
    PipClickjacking,
    AutoPipWithoutConsent,
    CrossOriginPipContent,
    PersistentPipWindow,
    PipDataExfiltration,
    PipResizeManipulation,
    MediaSessionHijacking,
}

impl std::fmt::Display for PipSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PipWithoutUserGesture => write!(f, "pip_without_user_gesture"),
            Self::DocumentPipOverlay => write!(f, "document_pip_overlay"),
            Self::PipFormSpoofing => write!(f, "pip_form_spoofing"),
            Self::PipClickjacking => write!(f, "pip_clickjacking"),
            Self::AutoPipWithoutConsent => write!(f, "auto_pip_without_consent"),
            Self::CrossOriginPipContent => write!(f, "cross_origin_pip_content"),
            Self::PersistentPipWindow => write!(f, "persistent_pip_window"),
            Self::PipDataExfiltration => write!(f, "pip_data_exfiltration"),
            Self::PipResizeManipulation => write!(f, "pip_resize_manipulation"),
            Self::MediaSessionHijacking => write!(f, "media_session_hijacking"),
        }
    }
}

pub fn analyze_pip_security(body: &str) -> Vec<PipSecurityIssue> {
    let has_pip = body.contains("requestPictureInPicture")
        || body.contains("pictureInPictureElement")
        || body.contains("pictureInPictureWindow")
        || body.contains("documentPictureInPicture")
        || body.contains("autopictureinpicture")
        || body.contains("pipWindow");
    if !has_pip {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("requestPictureInPicture")
        && !body.contains("click")
        && !body.contains("pointerdown")
        && !body.contains("touchstart")
        && !body.contains("mousedown")
    {
        issues.push(PipSecurityIssue::PipWithoutUserGesture);
    }

    if body.contains("documentPictureInPicture") && body.contains("createElement") {
        issues.push(PipSecurityIssue::DocumentPipOverlay);
    }

    let has_pip_window =
        body.contains("documentPictureInPicture") || body.contains("pictureInPictureWindow");
    let has_form_input = body.contains("<input")
        || body.contains("type=\"password\"")
        || body.contains("type='password'");

    if has_pip_window && has_form_input {
        issues.push(PipSecurityIssue::PipFormSpoofing);
    }

    let has_window_ref = body.contains("pipWindow") || body.contains("pictureInPictureWindow");

    let has_positioning =
        body.contains("position") || body.contains("moveTo") || body.contains("resizeTo");

    if has_window_ref && has_positioning {
        issues.push(PipSecurityIssue::PipClickjacking);
    }

    if body.contains("autopictureinpicture")
        && !body.contains("user")
        && !body.contains("consent")
        && !body.contains("permission")
    {
        issues.push(PipSecurityIssue::AutoPipWithoutConsent);
    }

    let has_cross_origin =
        (body.contains("http://") || body.contains("https://")) && body.contains("iframe");
    let has_doc_pip_or_window =
        body.contains("documentPictureInPicture") || body.contains("pipWindow");

    if has_doc_pip_or_window && has_cross_origin {
        issues.push(PipSecurityIssue::CrossOriginPipContent);
    }

    let has_loop =
        body.contains("setInterval") || body.contains("while(true)") || body.contains("for(;;)");

    if has_window_ref && has_loop {
        issues.push(PipSecurityIssue::PersistentPipWindow);
    }

    let has_network =
        body.contains("fetch(") || body.contains("XMLHttpRequest") || body.contains("sendBeacon");

    if has_window_ref && has_network {
        issues.push(PipSecurityIssue::PipDataExfiltration);
    }

    let has_size_manipulation = body.contains("resize")
        || (body.contains("width") && body.contains("="))
        || (body.contains("height") && body.contains("="));

    if has_window_ref && has_size_manipulation {
        issues.push(PipSecurityIssue::PipResizeManipulation);
    }

    let has_media_session_api = body.contains("setActionHandler") || body.contains("metadata");
    let has_media_and_pip = body.contains("mediaSession")
        && (body.contains("pictureInPicture") || body.contains("pipWindow"));

    if has_media_and_pip && has_media_session_api {
        issues.push(PipSecurityIssue::MediaSessionHijacking);
    }

    issues
}

pub fn pip_security_severity(issue: &PipSecurityIssue) -> f64 {
    match issue {
        PipSecurityIssue::PipFormSpoofing => 8.5,
        PipSecurityIssue::PipDataExfiltration => 7.5,
        PipSecurityIssue::DocumentPipOverlay => 7.0,
        PipSecurityIssue::PipClickjacking => 6.5,
        PipSecurityIssue::CrossOriginPipContent => 6.0,
        PipSecurityIssue::MediaSessionHijacking => 5.5,
        PipSecurityIssue::PipWithoutUserGesture => 5.0,
        PipSecurityIssue::AutoPipWithoutConsent => 4.5,
        PipSecurityIssue::PipResizeManipulation => 4.0,
        PipSecurityIssue::PersistentPipWindow => 3.5,
    }
}

pub fn pip_security_to_operations(
    issues: &[PipSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                pip_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
