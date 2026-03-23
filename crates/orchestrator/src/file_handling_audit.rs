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

#[derive(Debug, Clone, PartialEq)]
pub enum FileHandlingSecurityIssue {
    FileDataExfiltration,
    FileTypeBypass,
    FileWithoutValidation,
    FileCrossOrigin,
    FileInBackground,
    FilePersistentAccess,
    LargeFileDoS,
    FileExecutionAttempt,
    SensitiveFileAccess,
    FileHandlerRegistration,
}

impl std::fmt::Display for FileHandlingSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileDataExfiltration => write!(f, "file_data_exfiltration"),
            Self::FileTypeBypass => write!(f, "file_type_bypass"),
            Self::FileWithoutValidation => write!(f, "file_without_validation"),
            Self::FileCrossOrigin => write!(f, "file_cross_origin"),
            Self::FileInBackground => write!(f, "file_in_background"),
            Self::FilePersistentAccess => write!(f, "file_persistent_access"),
            Self::LargeFileDoS => write!(f, "large_file_dos"),
            Self::FileExecutionAttempt => write!(f, "file_execution_attempt"),
            Self::SensitiveFileAccess => write!(f, "sensitive_file_access"),
            Self::FileHandlerRegistration => write!(f, "file_handler_registration"),
        }
    }
}

pub fn analyze_file_handling_security(body: &str) -> Vec<FileHandlingSecurityIssue> {
    if body.is_empty() {
        return Vec::new();
    }

    let mut issues = Vec::new();

    // FileDataExfiltration - Sending opened file data externally
    if (body.contains("FileReader")
        || body.contains("file.text()")
        || body.contains("file.arrayBuffer()"))
        && body.contains("fetch(")
    {
        issues.push(FileHandlingSecurityIssue::FileDataExfiltration);
    }

    // FileTypeBypass - Accepting dangerous file types
    if body.contains(".exe")
        || body.contains(".bat")
        || body.contains(".cmd")
        || body.contains(".ps1")
        || body.contains(".sh")
    {
        issues.push(FileHandlingSecurityIssue::FileTypeBypass);
    }

    // FileWithoutValidation - Processing files without size/type validation
    if (body.contains("files[") || body.contains("launchQueue") || body.contains("input.files"))
        && !body.contains("size")
        && !body.contains("type")
        && !body.contains("validate")
    {
        issues.push(FileHandlingSecurityIssue::FileWithoutValidation);
    }

    // FileCrossOrigin - Sharing file data cross-origin
    if (body.contains("postMessage") || body.contains("MessageChannel"))
        && (body.contains("FileReader")
            || body.contains("file.text()")
            || body.contains("file.arrayBuffer()"))
    {
        issues.push(FileHandlingSecurityIssue::FileCrossOrigin);
    }

    // FileInBackground - File operations when page is hidden
    if body.contains("visibilitychange")
        && (body.contains("FileReader")
            || body.contains("file.text()")
            || body.contains("launchQueue"))
    {
        issues.push(FileHandlingSecurityIssue::FileInBackground);
    }

    // FilePersistentAccess - Retaining file handles for persistent access
    if body.contains("keepExistingData")
        || (body.contains("indexedDB") && (body.contains("FileHandle") || body.contains("file")))
    {
        issues.push(FileHandlingSecurityIssue::FilePersistentAccess);
    }

    // LargeFileDoS - No size limits allowing denial of service
    if (body.contains("FileReader")
        || body.contains("file.arrayBuffer()")
        || body.contains("file.text()"))
        && !body.contains("size")
        && !body.contains("MAX_")
        && !body.contains("limit")
    {
        issues.push(FileHandlingSecurityIssue::LargeFileDoS);
    }

    // FileExecutionAttempt - Attempting to execute file content
    if (body.contains("eval(") || body.contains("new Function("))
        && (body.contains("FileReader") || body.contains("file.text()"))
    {
        issues.push(FileHandlingSecurityIssue::FileExecutionAttempt);
    }

    // SensitiveFileAccess - Accessing known sensitive file patterns
    if body.contains(".env")
        || body.contains(".key")
        || body.contains(".pem")
        || body.contains("config.")
        || body.contains("private")
        || body.contains("secret")
    {
        issues.push(FileHandlingSecurityIssue::SensitiveFileAccess);
    }

    // FileHandlerRegistration - Registering as handler for sensitive file types
    if body.contains("file_handlers")
        && (body.contains(".key")
            || body.contains(".pem")
            || body.contains(".env")
            || body.contains(".config")
            || body.contains(".json"))
    {
        issues.push(FileHandlingSecurityIssue::FileHandlerRegistration);
    }

    issues
}

pub fn file_handling_security_severity(issue: &FileHandlingSecurityIssue) -> f64 {
    match issue {
        FileHandlingSecurityIssue::FileExecutionAttempt => 9.0,
        FileHandlingSecurityIssue::FileDataExfiltration => 8.5,
        FileHandlingSecurityIssue::SensitiveFileAccess => 8.0,
        FileHandlingSecurityIssue::FileTypeBypass => 7.5,
        FileHandlingSecurityIssue::FileCrossOrigin => 7.0,
        FileHandlingSecurityIssue::FilePersistentAccess => 6.5,
        FileHandlingSecurityIssue::FileInBackground => 6.0,
        FileHandlingSecurityIssue::LargeFileDoS => 5.5,
        FileHandlingSecurityIssue::FileHandlerRegistration => 5.0,
        FileHandlingSecurityIssue::FileWithoutValidation => 4.5,
    }
}

pub fn file_handling_security_to_operations(
    issues: &[FileHandlingSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                file_handling_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
