use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum FileSystemAccessIssue {
    ApiDetected,
    FileExfiltration,
    SilentWrite,
    DirectoryAccess,
    NoUserActivation,
    PersistentHandle,
}

impl std::fmt::Display for FileSystemAccessIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::FileExfiltration => write!(f, "file_exfiltration"),
            Self::SilentWrite => write!(f, "silent_write"),
            Self::DirectoryAccess => write!(f, "directory_access"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::PersistentHandle => write!(f, "persistent_handle"),
        }
    }
}

pub fn audit_file_system_access(target: &str) -> Vec<FileSystemAccessIssue> {
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
    analyze_file_system_access(&body)
}

pub fn analyze_file_system_access(body: &str) -> Vec<FileSystemAccessIssue> {
    let has_api = body.contains("showOpenFilePicker")
        || body.contains("showSaveFilePicker")
        || body.contains("showDirectoryPicker");
    if !has_api {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(FileSystemAccessIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if body.contains("showOpenFilePicker") && has_exfil {
        issues.push(FileSystemAccessIssue::FileExfiltration);
    }

    if body.contains("showSaveFilePicker") || body.contains("createWritable") {
        issues.push(FileSystemAccessIssue::SilentWrite);
    }

    if body.contains("showDirectoryPicker") {
        issues.push(FileSystemAccessIssue::DirectoryAccess);
    }

    if !body.contains("click") && !body.contains("keydown") && !body.contains("pointerdown") {
        issues.push(FileSystemAccessIssue::NoUserActivation);
    }

    if body.contains("queryPermission") || body.contains("requestPermission") {
        issues.push(FileSystemAccessIssue::PersistentHandle);
    }

    issues
}

pub fn file_system_access_severity(issue: &FileSystemAccessIssue) -> f64 {
    match issue {
        FileSystemAccessIssue::FileExfiltration => 7.5,
        FileSystemAccessIssue::SilentWrite => 7.0,
        FileSystemAccessIssue::DirectoryAccess => 6.5,
        FileSystemAccessIssue::PersistentHandle => 6.0,
        FileSystemAccessIssue::NoUserActivation => 5.0,
        FileSystemAccessIssue::ApiDetected => 3.0,
    }
}

pub fn file_system_access_to_operations(
    issues: &[FileSystemAccessIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                file_system_access_severity(issue),
                0.7,
            )
        })
        .collect()
}
