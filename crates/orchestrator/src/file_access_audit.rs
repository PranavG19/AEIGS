use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum FileAccessIssue {
    ShowOpenFilePicker,
    ShowSaveFilePicker,
    ShowDirectoryPicker,
    FileHandleWrite,
    FileDataExfiltration,
    OpaqueFileSystem,
}

impl std::fmt::Display for FileAccessIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShowOpenFilePicker => write!(f, "show_open_file_picker"),
            Self::ShowSaveFilePicker => write!(f, "show_save_file_picker"),
            Self::ShowDirectoryPicker => write!(f, "show_directory_picker"),
            Self::FileHandleWrite => write!(f, "file_handle_write"),
            Self::FileDataExfiltration => write!(f, "file_data_exfiltration"),
            Self::OpaqueFileSystem => write!(f, "opaque_file_system"),
        }
    }
}

pub fn audit_file_access(target: &str) -> Vec<FileAccessIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_file_access(&body)
}

pub fn analyze_file_access(body: &str) -> Vec<FileAccessIssue> {
    if !has_file_access_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("showOpenFilePicker") {
        issues.push(FileAccessIssue::ShowOpenFilePicker);
    }

    if body.contains("showSaveFilePicker") {
        issues.push(FileAccessIssue::ShowSaveFilePicker);
    }

    if body.contains("showDirectoryPicker") {
        issues.push(FileAccessIssue::ShowDirectoryPicker);
    }

    if body.contains("createWritable") || body.contains("getWriter") {
        issues.push(FileAccessIssue::FileHandleWrite);
    }

    let has_file = body.contains("showOpenFilePicker") || body.contains("showDirectoryPicker");
    let sends = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains(".send(")
        || body.contains("sendBeacon");
    if has_file && sends {
        issues.push(FileAccessIssue::FileDataExfiltration);
    }

    if body.contains("navigator.storage.getDirectory") || body.contains("StorageManager") {
        issues.push(FileAccessIssue::OpaqueFileSystem);
    }

    issues
}

fn has_file_access_indicators(body: &str) -> bool {
    body.contains("showOpenFilePicker")
        || body.contains("showSaveFilePicker")
        || body.contains("showDirectoryPicker")
        || body.contains("navigator.storage.getDirectory")
}

pub fn file_access_severity(issue: &FileAccessIssue) -> f64 {
    match issue {
        FileAccessIssue::FileDataExfiltration => 8.0,
        FileAccessIssue::ShowDirectoryPicker => 7.5,
        FileAccessIssue::FileHandleWrite => 7.0,
        FileAccessIssue::ShowOpenFilePicker => 6.5,
        FileAccessIssue::ShowSaveFilePicker => 6.0,
        FileAccessIssue::OpaqueFileSystem => 5.0,
    }
}

pub fn file_access_to_operations(
    issues: &[FileAccessIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                file_access_severity(issue),
                0.7,
            )
        })
        .collect()
}
