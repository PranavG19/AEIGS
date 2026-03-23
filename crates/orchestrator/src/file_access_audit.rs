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

#[derive(Debug, Clone, PartialEq)]
pub enum FileSecurityIssue {
    FilePickerUsed { picker_type: String },
    FileWriteAccess,
    DirectoryAccess,
    DataExfiltration { method: String },
    LargeFileRead,
    RecursiveDirectoryWalk,
    SensitiveFileType { extension: String },
    NoFileTypeRestriction,
    OpaqueOriginAccess,
    FileHandlePermissionPersist,
    CrossOriginFileAccess,
    MultipleFileOperations { count: usize },
}

impl std::fmt::Display for FileSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FilePickerUsed { picker_type } => write!(f, "file_picker_used_{}", picker_type),
            Self::FileWriteAccess => write!(f, "file_write_access"),
            Self::DirectoryAccess => write!(f, "directory_access"),
            Self::DataExfiltration { method } => write!(f, "data_exfiltration_{}", method),
            Self::LargeFileRead => write!(f, "large_file_read"),
            Self::RecursiveDirectoryWalk => write!(f, "recursive_directory_walk"),
            Self::SensitiveFileType { extension } => write!(f, "sensitive_file_type{}", extension),
            Self::NoFileTypeRestriction => write!(f, "no_file_type_restriction"),
            Self::OpaqueOriginAccess => write!(f, "opaque_origin_access"),
            Self::FileHandlePermissionPersist => write!(f, "file_handle_permission_persist"),
            Self::CrossOriginFileAccess => write!(f, "cross_origin_file_access"),
            Self::MultipleFileOperations { count } => {
                write!(f, "multiple_file_operations_{}", count)
            }
        }
    }
}

pub fn file_security_severity(issue: &FileSecurityIssue) -> f64 {
    match issue {
        FileSecurityIssue::DataExfiltration { .. } => 8.5,
        FileSecurityIssue::RecursiveDirectoryWalk => 8.0,
        FileSecurityIssue::CrossOriginFileAccess => 7.5,
        FileSecurityIssue::DirectoryAccess => 7.0,
        FileSecurityIssue::FileWriteAccess => 7.0,
        FileSecurityIssue::FileHandlePermissionPersist => 6.5,
        FileSecurityIssue::SensitiveFileType { .. } => 6.0,
        FileSecurityIssue::LargeFileRead => 5.5,
        FileSecurityIssue::FilePickerUsed { .. } => 5.0,
        FileSecurityIssue::NoFileTypeRestriction => 4.5,
        FileSecurityIssue::OpaqueOriginAccess => 4.0,
        FileSecurityIssue::MultipleFileOperations { .. } => 3.5,
    }
}

const SENSITIVE_EXTENSIONS: &[&str] = &[
    ".pem", ".key", ".env", ".cfg", ".ini", ".conf", ".sqlite", ".db", ".sql", ".csv", ".json",
];

pub fn analyze_file_security(body: &str) -> Vec<FileSecurityIssue> {
    let mut issues = Vec::new();
    let mut file_op_count = 0;

    if body.contains("showOpenFilePicker") {
        issues.push(FileSecurityIssue::FilePickerUsed {
            picker_type: "open".to_string(),
        });
        file_op_count += 1;
    }
    if body.contains("showSaveFilePicker") {
        issues.push(FileSecurityIssue::FilePickerUsed {
            picker_type: "save".to_string(),
        });
        file_op_count += 1;
    }
    if body.contains("showDirectoryPicker") {
        issues.push(FileSecurityIssue::DirectoryAccess);
        file_op_count += 1;
    }

    if body.contains("createWritable")
        || body.contains("write(") && body.contains("FileSystemWritableFileStream")
    {
        issues.push(FileSecurityIssue::FileWriteAccess);
    }

    let has_file_api = body.contains("showOpenFilePicker") || body.contains("showDirectoryPicker");
    let sends =
        body.contains("fetch(") || body.contains("XMLHttpRequest") || body.contains("sendBeacon");
    if has_file_api && sends {
        let method = if body.contains("fetch(") {
            "fetch"
        } else if body.contains("XMLHttpRequest") {
            "XMLHttpRequest"
        } else {
            "sendBeacon"
        };
        issues.push(FileSecurityIssue::DataExfiltration {
            method: method.to_string(),
        });
    }

    if body.contains("entries()") && body.contains("showDirectoryPicker") {
        issues.push(FileSecurityIssue::RecursiveDirectoryWalk);
    }

    if body.contains("slice(") && body.contains("getFile") || body.contains("arrayBuffer") {
        issues.push(FileSecurityIssue::LargeFileRead);
    }

    for ext in SENSITIVE_EXTENSIONS {
        if body.contains(ext) {
            issues.push(FileSecurityIssue::SensitiveFileType {
                extension: ext.to_string(),
            });
            break;
        }
    }

    if has_file_api && !body.contains("types:") && !body.contains("accept:") {
        issues.push(FileSecurityIssue::NoFileTypeRestriction);
    }

    if body.contains("navigator.storage.getDirectory") {
        issues.push(FileSecurityIssue::OpaqueOriginAccess);
    }

    if body.contains("queryPermission") || body.contains("requestPermission") {
        issues.push(FileSecurityIssue::FileHandlePermissionPersist);
    }

    if body.contains("postMessage") && has_file_api {
        issues.push(FileSecurityIssue::CrossOriginFileAccess);
    }

    if file_op_count > 2 {
        issues.push(FileSecurityIssue::MultipleFileOperations {
            count: file_op_count,
        });
    }

    issues
}

pub fn file_security_to_operations(
    issues: &[FileSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                file_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
