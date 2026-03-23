use crate::file_system_access_audit::*;

#[test]
fn no_file_api_no_issues() {
    assert!(analyze_file_system_access("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_open_file_picker() {
    let body = r#"<script>const fh = await showOpenFilePicker();</script>"#;
    let issues = analyze_file_system_access(body);
    assert!(issues.contains(&FileSystemAccessIssue::ApiDetected));
}

#[test]
fn detects_save_file_picker() {
    let body = r#"<script>const fh = await showSaveFilePicker();</script>"#;
    let issues = analyze_file_system_access(body);
    assert!(issues.contains(&FileSystemAccessIssue::ApiDetected));
    assert!(issues.contains(&FileSystemAccessIssue::SilentWrite));
}

#[test]
fn detects_file_exfiltration() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        const file = await fh.getFile();
        fetch("/upload", {method: "POST", body: await file.text()});
    </script>"#;
    let issues = analyze_file_system_access(body);
    assert!(issues.contains(&FileSystemAccessIssue::FileExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        console.log(fh);
    </script>"#;
    let issues = analyze_file_system_access(body);
    assert!(!issues.contains(&FileSystemAccessIssue::FileExfiltration));
}

#[test]
fn detects_silent_write() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const fh = await showSaveFilePicker();
            const writable = await fh.createWritable();
        });
    </script>"#;
    let issues = analyze_file_system_access(body);
    assert!(issues.contains(&FileSystemAccessIssue::SilentWrite));
}

#[test]
fn detects_directory_access() {
    let body = r#"<script>
        const dh = await showDirectoryPicker();
    </script>"#;
    let issues = analyze_file_system_access(body);
    assert!(issues.contains(&FileSystemAccessIssue::DirectoryAccess));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>const fh = await showOpenFilePicker();</script>"#;
    let issues = analyze_file_system_access(body);
    assert!(issues.contains(&FileSystemAccessIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const fh = await showOpenFilePicker();
        });
    </script>"#;
    let issues = analyze_file_system_access(body);
    assert!(!issues.contains(&FileSystemAccessIssue::NoUserActivation));
}

#[test]
fn detects_persistent_handle() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const fh = await showOpenFilePicker();
            const perm = await fh.queryPermission({mode: "readwrite"});
        });
    </script>"#;
    let issues = analyze_file_system_access(body);
    assert!(issues.contains(&FileSystemAccessIssue::PersistentHandle));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        file_system_access_severity(&FileSystemAccessIssue::FileExfiltration),
        7.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        file_system_access_severity(&FileSystemAccessIssue::ApiDetected),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        FileSystemAccessIssue::ApiDetected,
        FileSystemAccessIssue::DirectoryAccess,
    ];
    let mut seq = 0;
    let ops = file_system_access_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        FileSystemAccessIssue::ApiDetected.to_string(),
        "api_detected"
    );
    assert_eq!(
        FileSystemAccessIssue::FileExfiltration.to_string(),
        "file_exfiltration"
    );
    assert_eq!(
        FileSystemAccessIssue::SilentWrite.to_string(),
        "silent_write"
    );
    assert_eq!(
        FileSystemAccessIssue::DirectoryAccess.to_string(),
        "directory_access"
    );
    assert_eq!(
        FileSystemAccessIssue::NoUserActivation.to_string(),
        "no_user_activation"
    );
    assert_eq!(
        FileSystemAccessIssue::PersistentHandle.to_string(),
        "persistent_handle"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_file_system_access("").is_empty());
}
