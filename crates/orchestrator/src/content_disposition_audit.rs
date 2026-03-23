use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ContentDispositionIssue {
    MissingOnDownload,
    InlineForBinary,
    FilenameInjection,
    MissingFilename,
    UnsanitizedFilename,
}

impl std::fmt::Display for ContentDispositionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingOnDownload => write!(f, "missing_on_download"),
            Self::InlineForBinary => write!(f, "inline_for_binary"),
            Self::FilenameInjection => write!(f, "filename_injection"),
            Self::MissingFilename => write!(f, "missing_filename"),
            Self::UnsanitizedFilename => write!(f, "unsanitized_filename"),
        }
    }
}

pub fn audit_content_disposition(target: &str) -> Vec<ContentDispositionIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let cd = resp
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    analyze_content_disposition(&ct, &cd)
}

pub fn analyze_content_disposition(content_type: &str, disposition: &str) -> Vec<ContentDispositionIssue> {
    let mut issues = Vec::new();
    let ct_lower = content_type.to_ascii_lowercase();
    let is_binary = ct_lower.contains("octet-stream")
        || ct_lower.contains("application/pdf")
        || ct_lower.contains("application/zip")
        || ct_lower.contains("application/x-tar")
        || ct_lower.contains("application/gzip");

    if is_binary && disposition.is_empty() {
        issues.push(ContentDispositionIssue::MissingOnDownload);
    }

    if is_binary && disposition.contains("inline") {
        issues.push(ContentDispositionIssue::InlineForBinary);
    }

    if !disposition.is_empty() {
        if disposition.contains("..") || disposition.contains('/') || disposition.contains('\\') {
            issues.push(ContentDispositionIssue::FilenameInjection);
        }

        if disposition.contains("attachment") && !disposition.contains("filename") {
            issues.push(ContentDispositionIssue::MissingFilename);
        }

        if disposition.contains("filename") {
            let has_dangerous = disposition.contains(".exe")
                || disposition.contains(".bat")
                || disposition.contains(".cmd")
                || disposition.contains(".ps1")
                || disposition.contains(".vbs")
                || disposition.contains(".scr")
                || disposition.contains(".msi");
            if has_dangerous {
                issues.push(ContentDispositionIssue::UnsanitizedFilename);
            }
        }
    }

    issues
}

pub fn content_disposition_severity(issue: &ContentDispositionIssue) -> f64 {
    match issue {
        ContentDispositionIssue::FilenameInjection => 7.5,
        ContentDispositionIssue::UnsanitizedFilename => 6.5,
        ContentDispositionIssue::InlineForBinary => 5.5,
        ContentDispositionIssue::MissingOnDownload => 5.0,
        ContentDispositionIssue::MissingFilename => 4.0,
    }
}

pub fn content_disposition_to_operations(
    issues: &[ContentDispositionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                content_disposition_severity(issue),
                0.7,
            )
        })
        .collect()
}
