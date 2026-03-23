use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum EyeDropperIssue {
    ApiDetected,
    ColorExfiltration,
    NoUserActivation,
    LoopedPicking,
    PixelDataAccess,
}

impl std::fmt::Display for EyeDropperIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::ColorExfiltration => write!(f, "color_exfiltration"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::LoopedPicking => write!(f, "looped_picking"),
            Self::PixelDataAccess => write!(f, "pixel_data_access"),
        }
    }
}

pub fn audit_eyedropper(target: &str) -> Vec<EyeDropperIssue> {
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
    analyze_eyedropper(&body)
}

pub fn analyze_eyedropper(body: &str) -> Vec<EyeDropperIssue> {
    if !body.contains("EyeDropper") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(EyeDropperIssue::ApiDetected);

    let has_srgb = body.contains("sRGBHex");

    if body.contains(".open(") {
        if !body.contains("click") && !body.contains("pointerdown") {
            issues.push(EyeDropperIssue::NoUserActivation);
        }

        if has_srgb && (body.contains("fetch(") || body.contains("sendBeacon")) {
            issues.push(EyeDropperIssue::ColorExfiltration);
        }

        if body.contains("while(") || body.contains("while ") || body.contains("setInterval") || body.contains("for(") || body.contains("for ") {
            issues.push(EyeDropperIssue::LoopedPicking);
        }
    }

    if has_srgb || body.contains("colorSelectionResult") {
        issues.push(EyeDropperIssue::PixelDataAccess);
    }

    issues
}

pub fn eyedropper_severity(issue: &EyeDropperIssue) -> f64 {
    match issue {
        EyeDropperIssue::ColorExfiltration => 6.0,
        EyeDropperIssue::LoopedPicking => 5.5,
        EyeDropperIssue::NoUserActivation => 5.0,
        EyeDropperIssue::PixelDataAccess => 4.0,
        EyeDropperIssue::ApiDetected => 3.0,
    }
}

pub fn eyedropper_to_operations(
    issues: &[EyeDropperIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                eyedropper_severity(issue),
                0.6,
            )
        })
        .collect()
}
