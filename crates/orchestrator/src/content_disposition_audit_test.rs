use crate::content_disposition_audit::*;

#[test]
fn empty_headers_no_issues() {
    let issues = analyze_content_disposition("", "");
    assert!(issues.is_empty());
}

#[test]
fn html_no_disposition_ok() {
    let issues = analyze_content_disposition("text/html", "");
    assert!(issues.is_empty());
}

#[test]
fn binary_missing_disposition() {
    let issues = analyze_content_disposition("application/octet-stream", "");
    assert!(issues.contains(&ContentDispositionIssue::MissingOnDownload));
}

#[test]
fn pdf_missing_disposition() {
    let issues = analyze_content_disposition("application/pdf", "");
    assert!(issues.contains(&ContentDispositionIssue::MissingOnDownload));
}

#[test]
fn binary_inline_flagged() {
    let issues = analyze_content_disposition("application/octet-stream", "inline");
    assert!(issues.contains(&ContentDispositionIssue::InlineForBinary));
}

#[test]
fn binary_attachment_ok() {
    let issues = analyze_content_disposition(
        "application/octet-stream",
        "attachment; filename=\"report.pdf\"",
    );
    assert!(!issues.contains(&ContentDispositionIssue::MissingOnDownload));
    assert!(!issues.contains(&ContentDispositionIssue::InlineForBinary));
}

#[test]
fn filename_injection_dotdot() {
    let issues =
        analyze_content_disposition("text/plain", "attachment; filename=\"../../etc/passwd\"");
    assert!(issues.contains(&ContentDispositionIssue::FilenameInjection));
}

#[test]
fn filename_injection_slash() {
    let issues =
        analyze_content_disposition("text/plain", "attachment; filename=\"/tmp/evil.txt\"");
    assert!(issues.contains(&ContentDispositionIssue::FilenameInjection));
}

#[test]
fn filename_injection_backslash() {
    let issues = analyze_content_disposition("text/plain", "attachment; filename=\"C:\\evil.exe\"");
    assert!(issues.contains(&ContentDispositionIssue::FilenameInjection));
}

#[test]
fn missing_filename_in_attachment() {
    let issues = analyze_content_disposition("text/plain", "attachment");
    assert!(issues.contains(&ContentDispositionIssue::MissingFilename));
}

#[test]
fn unsanitized_exe_filename() {
    let issues = analyze_content_disposition("text/plain", "attachment; filename=\"update.exe\"");
    assert!(issues.contains(&ContentDispositionIssue::UnsanitizedFilename));
}

#[test]
fn unsanitized_bat_filename() {
    let issues = analyze_content_disposition("text/plain", "attachment; filename=\"script.bat\"");
    assert!(issues.contains(&ContentDispositionIssue::UnsanitizedFilename));
}

#[test]
fn safe_pdf_filename() {
    let issues = analyze_content_disposition("text/plain", "attachment; filename=\"report.pdf\"");
    assert!(!issues.contains(&ContentDispositionIssue::UnsanitizedFilename));
}

#[test]
fn severity_injection_highest() {
    assert_eq!(
        content_disposition_severity(&ContentDispositionIssue::FilenameInjection),
        7.5
    );
}

#[test]
fn severity_missing_filename_lowest() {
    assert_eq!(
        content_disposition_severity(&ContentDispositionIssue::MissingFilename),
        4.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        ContentDispositionIssue::FilenameInjection,
        ContentDispositionIssue::MissingFilename,
    ];
    let mut seq = 0;
    let ops = content_disposition_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        ContentDispositionIssue::MissingOnDownload.to_string(),
        "missing_on_download"
    );
    assert_eq!(
        ContentDispositionIssue::FilenameInjection.to_string(),
        "filename_injection"
    );
    assert_eq!(
        ContentDispositionIssue::UnsanitizedFilename.to_string(),
        "unsanitized_filename"
    );
    assert_eq!(
        ContentDispositionIssue::InlineForBinary.to_string(),
        "inline_for_binary"
    );
}
