use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum FileHandlingIssue {
    ApiDetected,
    BroadFileTypes,
    DataExfiltration,
    NoContentValidation,
    ExecutableHandling,
}

impl std::fmt::Display for FileHandlingIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::BroadFileTypes => write!(f, "broad_file_types"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::NoContentValidation => write!(f, "no_content_validation"),
            Self::ExecutableHandling => write!(f, "executable_handling"),
        }
    }
}

pub fn audit_file_handling(target: &str) -> Vec<FileHandlingIssue> {
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
    analyze_file_handling(&body)
}

pub fn analyze_file_handling(body: &str) -> Vec<FileHandlingIssue> {
    if !body.contains("file_handlers")
        && !body.contains("launchQueue")
        && !body.contains("LaunchParams")
    {
        return Vec::new();
    }

    let has_files =
        body.contains("files") && (body.contains("launchQueue") || body.contains("LaunchParams"));
    let has_handlers = body.contains("file_handlers");

    if !has_files && !has_handlers {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(FileHandlingIssue::ApiDetected);

    if has_handlers && (body.contains("*/*") || body.contains("application/octet-stream")) {
        issues.push(FileHandlingIssue::BroadFileTypes);
    }

    if has_files
        && (body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("XMLHttpRequest"))
    {
        issues.push(FileHandlingIssue::DataExfiltration);
    }

    if has_files
        && !body.contains("type")
        && !body.contains("validate")
        && !body.contains("mime")
        && !body.contains("extension")
    {
        issues.push(FileHandlingIssue::NoContentValidation);
    }

    if has_handlers
        && (body.contains(".exe")
            || body.contains(".bat")
            || body.contains(".sh")
            || body.contains(".cmd")
            || body.contains(".ps1"))
    {
        issues.push(FileHandlingIssue::ExecutableHandling);
    }

    issues
}

pub fn file_handling_severity(issue: &FileHandlingIssue) -> f64 {
    match issue {
        FileHandlingIssue::ExecutableHandling => 8.0,
        FileHandlingIssue::DataExfiltration => 7.0,
        FileHandlingIssue::BroadFileTypes => 6.0,
        FileHandlingIssue::NoContentValidation => 5.5,
        FileHandlingIssue::ApiDetected => 2.5,
    }
}

pub fn file_handling_to_operations(
    issues: &[FileHandlingIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                file_handling_severity(issue),
                0.6,
            )
        })
        .collect()
}
