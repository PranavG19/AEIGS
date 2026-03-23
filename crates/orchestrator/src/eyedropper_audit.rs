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

        if body.contains("while(")
            || body.contains("while ")
            || body.contains("setInterval")
            || body.contains("for(")
            || body.contains("for ")
        {
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

#[derive(Debug, Clone, PartialEq)]
pub enum EyeDropperSecurityIssue {
    DropperWithoutFeaturePolicy,
    ColorDataPersistence,
    BulkColorCollection,
    CrossOriginColorLeak,
    CanvasCorrelation,
    AutomatedInvocation,
    ColorToCoordinateMapping,
    UnencryptedColorTransmission,
    WorkerBasedColorCollection,
    ThirdPartyColorSharing,
}

impl std::fmt::Display for EyeDropperSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DropperWithoutFeaturePolicy => write!(f, "dropper_without_feature_policy"),
            Self::ColorDataPersistence => write!(f, "color_data_persistence"),
            Self::BulkColorCollection => write!(f, "bulk_color_collection"),
            Self::CrossOriginColorLeak => write!(f, "cross_origin_color_leak"),
            Self::CanvasCorrelation => write!(f, "canvas_correlation"),
            Self::AutomatedInvocation => write!(f, "automated_invocation"),
            Self::ColorToCoordinateMapping => write!(f, "color_to_coordinate_mapping"),
            Self::UnencryptedColorTransmission => write!(f, "unencrypted_color_transmission"),
            Self::WorkerBasedColorCollection => write!(f, "worker_based_color_collection"),
            Self::ThirdPartyColorSharing => write!(f, "third_party_color_sharing"),
        }
    }
}

pub fn analyze_eyedropper_security(body: &str) -> Vec<EyeDropperSecurityIssue> {
    if !body.contains("EyeDropper") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if !body.contains("Permissions-Policy") && !body.contains("Feature-Policy") {
        issues.push(EyeDropperSecurityIssue::DropperWithoutFeaturePolicy);
    }

    if body.contains("localStorage")
        || body.contains("sessionStorage")
        || body.contains("IndexedDB")
        || body.contains("indexedDB")
    {
        issues.push(EyeDropperSecurityIssue::ColorDataPersistence);
    }

    let open_count = body.matches(".open(").count();
    if (open_count > 3
        || body.contains("while(")
        || body.contains("while ")
        || body.contains("for(")
        || body.contains("for "))
        && body.contains(".open(")
    {
        issues.push(EyeDropperSecurityIssue::BulkColorCollection);
    }

    if body.contains("postMessage")
        && (body.contains("sRGBHex") || body.contains("colorSelectionResult"))
    {
        issues.push(EyeDropperSecurityIssue::CrossOriginColorLeak);
    }

    if (body.contains("canvas") || body.contains("getContext") || body.contains("getImageData"))
        && body.contains("EyeDropper")
    {
        issues.push(EyeDropperSecurityIssue::CanvasCorrelation);
    }

    if (body.contains("setTimeout") || body.contains("setInterval")) && body.contains(".open(") {
        issues.push(EyeDropperSecurityIssue::AutomatedInvocation);
    }

    if (body.contains("screenX")
        || body.contains("screenY")
        || body.contains("clientX")
        || body.contains("clientY"))
        && (body.contains("sRGBHex") || body.contains("colorSelectionResult"))
    {
        issues.push(EyeDropperSecurityIssue::ColorToCoordinateMapping);
    }

    if body.contains("http://")
        && (body.contains("sRGBHex") || body.contains("colorSelectionResult"))
        && (body.contains("fetch(")
            || body.contains("XMLHttpRequest")
            || body.contains("sendBeacon"))
    {
        issues.push(EyeDropperSecurityIssue::UnencryptedColorTransmission);
    }

    if (body.contains("Worker(") || body.contains("new Worker") || body.contains("SharedWorker"))
        && body.contains("EyeDropper")
    {
        issues.push(EyeDropperSecurityIssue::WorkerBasedColorCollection);
    }

    if (body.contains("fetch(") || body.contains("XMLHttpRequest") || body.contains("sendBeacon"))
        && (body.contains("sRGBHex") || body.contains("colorSelectionResult"))
    {
        let has_external_domain = body.contains(".com")
            || body.contains(".net")
            || body.contains(".org")
            || body.contains("://");
        if has_external_domain && !body.contains("localhost") {
            issues.push(EyeDropperSecurityIssue::ThirdPartyColorSharing);
        }
    }

    issues
}

pub fn eyedropper_security_severity(issue: &EyeDropperSecurityIssue) -> f64 {
    match issue {
        EyeDropperSecurityIssue::UnencryptedColorTransmission => 7.5,
        EyeDropperSecurityIssue::ThirdPartyColorSharing => 7.0,
        EyeDropperSecurityIssue::CrossOriginColorLeak => 6.5,
        EyeDropperSecurityIssue::ColorToCoordinateMapping => 6.0,
        EyeDropperSecurityIssue::BulkColorCollection => 5.5,
        EyeDropperSecurityIssue::WorkerBasedColorCollection => 5.0,
        EyeDropperSecurityIssue::AutomatedInvocation => 4.5,
        EyeDropperSecurityIssue::CanvasCorrelation => 4.0,
        EyeDropperSecurityIssue::ColorDataPersistence => 3.5,
        EyeDropperSecurityIssue::DropperWithoutFeaturePolicy => 3.0,
    }
}

pub fn eyedropper_security_to_operations(
    issues: &[EyeDropperSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                eyedropper_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
