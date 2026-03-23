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
