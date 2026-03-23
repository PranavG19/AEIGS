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

#[derive(Debug, Clone, PartialEq)]
pub enum FileSystemAccessSecurityIssue {
    UnrestrictedFileAccess,
    DirectoryTraversal,
    SensitiveFileTypeAccess,
    FileExfiltrationPattern,
    LargeFileRead,
    SilentFileWrite,
    FileHandleLeakCrossOrigin,
    PersistentFileAccess,
    FileSystemInServiceWorker,
    WritableStreamAbuse,
}

impl std::fmt::Display for FileSystemAccessSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnrestrictedFileAccess => write!(f, "unrestricted_file_access"),
            Self::DirectoryTraversal => write!(f, "directory_traversal"),
            Self::SensitiveFileTypeAccess => write!(f, "sensitive_file_type_access"),
            Self::FileExfiltrationPattern => write!(f, "file_exfiltration_pattern"),
            Self::LargeFileRead => write!(f, "large_file_read"),
            Self::SilentFileWrite => write!(f, "silent_file_write"),
            Self::FileHandleLeakCrossOrigin => write!(f, "file_handle_leak_cross_origin"),
            Self::PersistentFileAccess => write!(f, "persistent_file_access"),
            Self::FileSystemInServiceWorker => write!(f, "file_system_in_service_worker"),
            Self::WritableStreamAbuse => write!(f, "writable_stream_abuse"),
        }
    }
}

pub fn analyze_file_system_access_security(body: &str) -> Vec<FileSystemAccessSecurityIssue> {
    let has_file_api = body.contains("showOpenFilePicker")
        || body.contains("showSaveFilePicker")
        || body.contains("showDirectoryPicker");
    if !has_file_api {
        return Vec::new();
    }

    let mut issues = Vec::new();

    // UnrestrictedFileAccess: showOpenFilePicker without accept/types restriction
    if body.contains("showOpenFilePicker") {
        let has_accept = body.contains("accept:")
            || body.contains("\"accept\"")
            || body.contains("'accept'")
            || body.contains("types:");
        if !has_accept {
            issues.push(FileSystemAccessSecurityIssue::UnrestrictedFileAccess);
        }
    }

    // DirectoryTraversal: showDirectoryPicker with parent directory access
    if body.contains("showDirectoryPicker")
        && (body.contains("..") || body.contains("getParent") || body.contains("resolve("))
    {
        issues.push(FileSystemAccessSecurityIssue::DirectoryTraversal);
    }

    // SensitiveFileTypeAccess: accessing sensitive file extensions
    let sensitive_patterns = [
        ".env", ".ssh", ".key", ".pem", ".p12", ".pfx", "id_rsa", "config", ".aws",
    ];
    if sensitive_patterns.iter().any(|pat| body.contains(pat)) {
        issues.push(FileSystemAccessSecurityIssue::SensitiveFileTypeAccess);
    }

    // FileExfiltrationPattern: reading file and sending externally
    let has_read =
        body.contains("getFile()") || body.contains(".text()") || body.contains(".arrayBuffer()");
    let has_network = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains("sendBeacon")
        || body.contains("WebSocket")
        || body.contains("postMessage");
    if has_read && has_network {
        issues.push(FileSystemAccessSecurityIssue::FileExfiltrationPattern);
    }

    // LargeFileRead: reading files with size > threshold without chunking
    if body.contains("getFile()") && body.contains(".size") {
        let has_chunking =
            body.contains("slice(") || body.contains("Readable") || body.contains("stream()");
        if !has_chunking
            && (body.contains("1024")
                || body.contains("1000000")
                || body.contains("MB")
                || body.contains("GB"))
        {
            issues.push(FileSystemAccessSecurityIssue::LargeFileRead);
        }
    }

    // SilentFileWrite: writing without showing UI confirmation
    if (body.contains("createWritable") || body.contains("showSaveFilePicker"))
        && !body.contains("confirm(")
        && !body.contains("alert(")
    {
        issues.push(FileSystemAccessSecurityIssue::SilentFileWrite);
    }

    // FileHandleLeakCrossOrigin: postMessage with file handle to different origin
    if body.contains("postMessage")
        && (body.contains("FileSystemHandle")
            || body.contains("showOpenFilePicker")
            || body.contains("showDirectoryPicker"))
    {
        let has_origin_check =
            body.contains("origin") && (body.contains("===") || body.contains("=="));
        if !has_origin_check {
            issues.push(FileSystemAccessSecurityIssue::FileHandleLeakCrossOrigin);
        }
    }

    // PersistentFileAccess: storing file handles in IndexedDB
    if (body.contains("indexedDB")
        || body.contains("localStorage")
        || body.contains("sessionStorage"))
        && (body.contains("FileSystemHandle")
            || body.contains("FileSystemDirectoryHandle")
            || body.contains("FileSystemFileHandle")
            || body.contains("fileHandle")
            || body.contains("dirHandle")
            || body.contains("handle"))
    {
        issues.push(FileSystemAccessSecurityIssue::PersistentFileAccess);
    }

    // FileSystemInServiceWorker: accessing File System API from service worker context
    if (body.contains("navigator.serviceWorker") || body.contains("self.registration"))
        && (body.contains("showOpenFilePicker") || body.contains("showDirectoryPicker"))
    {
        issues.push(FileSystemAccessSecurityIssue::FileSystemInServiceWorker);
    }

    // WritableStreamAbuse: using writable streams to exfiltrate data
    if body.contains("createWritable") && body.contains("getWriter") {
        let has_external =
            body.contains("fetch(") || body.contains("WebSocket") || body.contains("postMessage");
        if has_external {
            issues.push(FileSystemAccessSecurityIssue::WritableStreamAbuse);
        }
    }

    issues
}

pub fn file_system_access_security_severity(issue: &FileSystemAccessSecurityIssue) -> f64 {
    match issue {
        FileSystemAccessSecurityIssue::FileExfiltrationPattern => 9.0,
        FileSystemAccessSecurityIssue::SensitiveFileTypeAccess => 8.5,
        FileSystemAccessSecurityIssue::DirectoryTraversal => 8.0,
        FileSystemAccessSecurityIssue::FileHandleLeakCrossOrigin => 7.5,
        FileSystemAccessSecurityIssue::WritableStreamAbuse => 7.0,
        FileSystemAccessSecurityIssue::PersistentFileAccess => 6.5,
        FileSystemAccessSecurityIssue::SilentFileWrite => 6.0,
        FileSystemAccessSecurityIssue::UnrestrictedFileAccess => 5.5,
        FileSystemAccessSecurityIssue::LargeFileRead => 5.0,
        FileSystemAccessSecurityIssue::FileSystemInServiceWorker => 4.5,
    }
}

pub fn file_system_access_security_to_operations(
    issues: &[FileSystemAccessSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                file_system_access_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
