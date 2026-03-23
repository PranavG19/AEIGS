use crate::file_access_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_file_access("");
    assert!(issues.is_empty());
}

#[test]
fn no_file_api_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_file_access(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_show_open_file_picker() {
    let body = "const handle = await showOpenFilePicker();";
    let issues = analyze_file_access(body);
    assert!(issues.contains(&FileAccessIssue::ShowOpenFilePicker));
}

#[test]
fn detects_show_save_file_picker() {
    let body = "const handle = await showSaveFilePicker();";
    let issues = analyze_file_access(body);
    assert!(issues.contains(&FileAccessIssue::ShowSaveFilePicker));
}

#[test]
fn detects_show_directory_picker() {
    let body = "const dir = await showDirectoryPicker();";
    let issues = analyze_file_access(body);
    assert!(issues.contains(&FileAccessIssue::ShowDirectoryPicker));
}

#[test]
fn detects_file_handle_write() {
    let body = r#"
        const handle = await showSaveFilePicker();
        const writable = await handle.createWritable();
    "#;
    let issues = analyze_file_access(body);
    assert!(issues.contains(&FileAccessIssue::FileHandleWrite));
}

#[test]
fn detects_file_data_exfiltration() {
    let body = r#"
        const [handle] = await showOpenFilePicker();
        const file = await handle.getFile();
        fetch('/upload', {method:'POST', body: await file.text()});
    "#;
    let issues = analyze_file_access(body);
    assert!(issues.contains(&FileAccessIssue::FileDataExfiltration));
}

#[test]
fn detects_directory_exfiltration() {
    let body = r#"
        const dir = await showDirectoryPicker();
        fetch('/collect', {method:'POST', body: data});
    "#;
    let issues = analyze_file_access(body);
    assert!(issues.contains(&FileAccessIssue::FileDataExfiltration));
}

#[test]
fn detects_opaque_file_system() {
    let body = "const root = await navigator.storage.getDirectory();";
    let issues = analyze_file_access(body);
    assert!(issues.contains(&FileAccessIssue::OpaqueFileSystem));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        file_access_severity(&FileAccessIssue::FileDataExfiltration),
        8.0
    );
}

#[test]
fn severity_opaque_lowest() {
    assert_eq!(
        file_access_severity(&FileAccessIssue::OpaqueFileSystem),
        5.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        FileAccessIssue::ShowOpenFilePicker,
        FileAccessIssue::ShowDirectoryPicker,
    ];
    let mut seq = 0;
    let ops = file_access_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        FileAccessIssue::ShowOpenFilePicker.to_string(),
        "show_open_file_picker"
    );
    assert_eq!(
        FileAccessIssue::ShowDirectoryPicker.to_string(),
        "show_directory_picker"
    );
    assert_eq!(
        FileAccessIssue::FileHandleWrite.to_string(),
        "file_handle_write"
    );
    assert_eq!(
        FileAccessIssue::OpaqueFileSystem.to_string(),
        "opaque_file_system"
    );
}
