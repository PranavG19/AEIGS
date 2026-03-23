use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum LocalFontIssue {
    ApiDetected,
    FontExfiltration,
    FullEnumeration,
    FontDataAccess,
    NoPermissionCheck,
}

impl std::fmt::Display for LocalFontIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::FontExfiltration => write!(f, "font_exfiltration"),
            Self::FullEnumeration => write!(f, "full_enumeration"),
            Self::FontDataAccess => write!(f, "font_data_access"),
            Self::NoPermissionCheck => write!(f, "no_permission_check"),
        }
    }
}

pub fn audit_local_font(target: &str) -> Vec<LocalFontIssue> {
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
    analyze_local_font(&body)
}

pub fn analyze_local_font(body: &str) -> Vec<LocalFontIssue> {
    if !body.contains("queryLocalFonts") && !body.contains("local-fonts") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(LocalFontIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(LocalFontIssue::FontExfiltration);
    }

    if body.contains("queryLocalFonts()")
        || (body.contains("queryLocalFonts") && !body.contains("postScriptName"))
    {
        issues.push(LocalFontIssue::FullEnumeration);
    }

    if body.contains(".blob(") || body.contains("arrayBuffer") || body.contains("FontData") {
        issues.push(LocalFontIssue::FontDataAccess);
    }

    if !body.contains("permissions") && !body.contains("query(") {
        issues.push(LocalFontIssue::NoPermissionCheck);
    }

    issues
}

pub fn local_font_severity(issue: &LocalFontIssue) -> f64 {
    match issue {
        LocalFontIssue::FontExfiltration => 7.0,
        LocalFontIssue::FullEnumeration => 6.5,
        LocalFontIssue::FontDataAccess => 6.0,
        LocalFontIssue::NoPermissionCheck => 4.5,
        LocalFontIssue::ApiDetected => 3.0,
    }
}

pub fn local_font_to_operations(
    issues: &[LocalFontIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                local_font_severity(issue),
                0.6,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum LocalFontSecurityIssue {
    FontEnumeration,
    FontFingerprinting,
    FontDataExfiltration,
    FontWithoutPermission,
    FontCrossOrigin,
    FontPersistentStorage,
    FontWithCanvas,
    FontTimingAttack,
    FontInWorker,
    SystemFontDetection,
}

impl std::fmt::Display for LocalFontSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FontEnumeration => write!(f, "font_enumeration"),
            Self::FontFingerprinting => write!(f, "font_fingerprinting"),
            Self::FontDataExfiltration => write!(f, "font_data_exfiltration"),
            Self::FontWithoutPermission => write!(f, "font_without_permission"),
            Self::FontCrossOrigin => write!(f, "font_cross_origin"),
            Self::FontPersistentStorage => write!(f, "font_persistent_storage"),
            Self::FontWithCanvas => write!(f, "font_with_canvas"),
            Self::FontTimingAttack => write!(f, "font_timing_attack"),
            Self::FontInWorker => write!(f, "font_in_worker"),
            Self::SystemFontDetection => write!(f, "system_font_detection"),
        }
    }
}

pub fn analyze_local_font_security(body: &str) -> Vec<LocalFontSecurityIssue> {
    if !body.contains("queryLocalFonts") && !body.contains("local-fonts") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("queryLocalFonts()") || body.contains("queryLocalFonts({") {
        issues.push(LocalFontSecurityIssue::FontEnumeration);
    }

    let has_fingerprinting = (body.contains("queryLocalFonts") && body.contains(".family"))
        || (body.contains("queryLocalFonts") && body.contains(".postScriptName"))
        || (body.contains("queryLocalFonts") && body.contains(".fullName"));
    if has_fingerprinting {
        issues.push(LocalFontSecurityIssue::FontFingerprinting);
    }

    let has_exfil = (body.contains("queryLocalFonts") && body.contains("fetch("))
        || (body.contains("queryLocalFonts") && body.contains("sendBeacon"))
        || (body.contains("queryLocalFonts") && body.contains("XMLHttpRequest"))
        || (body.contains("queryLocalFonts") && body.contains("WebSocket"));
    if has_exfil {
        issues.push(LocalFontSecurityIssue::FontDataExfiltration);
    }

    if body.contains("queryLocalFonts") && !body.contains("permissions.query") {
        issues.push(LocalFontSecurityIssue::FontWithoutPermission);
    }

    let has_cross_origin = (body.contains("queryLocalFonts") && body.contains("postMessage"))
        || (body.contains("queryLocalFonts") && body.contains("cross-origin"))
        || (body.contains("queryLocalFonts") && body.contains("SharedArrayBuffer"));
    if has_cross_origin {
        issues.push(LocalFontSecurityIssue::FontCrossOrigin);
    }

    let has_storage = (body.contains("queryLocalFonts") && body.contains("localStorage"))
        || (body.contains("queryLocalFonts") && body.contains("sessionStorage"))
        || (body.contains("queryLocalFonts") && body.contains("indexedDB"))
        || (body.contains("queryLocalFonts") && body.contains("Cache"));
    if has_storage {
        issues.push(LocalFontSecurityIssue::FontPersistentStorage);
    }

    let has_canvas = (body.contains("queryLocalFonts") && body.contains("canvas"))
        || (body.contains("queryLocalFonts") && body.contains("measureText"))
        || (body.contains("queryLocalFonts") && body.contains("getContext"));
    if has_canvas {
        issues.push(LocalFontSecurityIssue::FontWithCanvas);
    }

    let has_timing = (body.contains("queryLocalFonts") && body.contains("performance.now"))
        || (body.contains("queryLocalFonts") && body.contains("Date.now"))
        || (body.contains("queryLocalFonts") && body.contains("performance.mark"));
    if has_timing {
        issues.push(LocalFontSecurityIssue::FontTimingAttack);
    }

    let has_worker = (body.contains("queryLocalFonts") && body.contains("Worker"))
        || (body.contains("queryLocalFonts") && body.contains("ServiceWorker"))
        || (body.contains("queryLocalFonts") && body.contains("SharedWorker"));
    if has_worker {
        issues.push(LocalFontSecurityIssue::FontInWorker);
    }

    let system_fonts = [
        "Arial",
        "Times New Roman",
        "Helvetica",
        "Courier",
        "Verdana",
        "Tahoma",
        "Trebuchet",
        "Georgia",
        "Palatino",
        "Garamond",
        "Comic Sans",
        "Impact",
        "Lucida",
        "MS Sans Serif",
        "Symbol",
    ];
    let has_system_font = system_fonts.iter().any(|font| body.contains(font));
    if body.contains("queryLocalFonts") && has_system_font {
        issues.push(LocalFontSecurityIssue::SystemFontDetection);
    }

    issues
}

pub fn local_font_security_severity(issue: &LocalFontSecurityIssue) -> f64 {
    match issue {
        LocalFontSecurityIssue::FontDataExfiltration => 8.5,
        LocalFontSecurityIssue::FontFingerprinting => 7.5,
        LocalFontSecurityIssue::FontCrossOrigin => 7.0,
        LocalFontSecurityIssue::FontTimingAttack => 6.5,
        LocalFontSecurityIssue::FontWithCanvas => 6.0,
        LocalFontSecurityIssue::FontPersistentStorage => 5.5,
        LocalFontSecurityIssue::SystemFontDetection => 5.0,
        LocalFontSecurityIssue::FontEnumeration => 4.5,
        LocalFontSecurityIssue::FontInWorker => 4.0,
        LocalFontSecurityIssue::FontWithoutPermission => 3.5,
    }
}

pub fn local_font_security_to_operations(
    issues: &[LocalFontSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                local_font_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
