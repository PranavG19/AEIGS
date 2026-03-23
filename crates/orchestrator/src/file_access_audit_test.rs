use crate::file_access_audit::*;

// === Original FileAccessIssue tests (13 tests) ===

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

// === New FileSecurityIssue tests (47 tests) ===

#[test]
fn security_empty_body_no_issues() {
    let issues = analyze_file_security("");
    assert!(issues.is_empty());
}

#[test]
fn security_no_file_api_no_issues() {
    let body = "<html><body>Hello World</body></html>";
    let issues = analyze_file_security(body);
    assert!(issues.is_empty());
}

#[test]
fn security_detects_open_picker() {
    let body = "const handle = await showOpenFilePicker();";
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::FilePickerUsed {
        picker_type: "open".to_string()
    }));
}

#[test]
fn security_detects_save_picker() {
    let body = "const handle = await showSaveFilePicker();";
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::FilePickerUsed {
        picker_type: "save".to_string()
    }));
}

#[test]
fn security_detects_directory_access() {
    let body = "const dir = await showDirectoryPicker();";
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::DirectoryAccess));
}

#[test]
fn security_detects_file_write_with_create_writable() {
    let body = r#"
        const handle = await showSaveFilePicker();
        const writable = await handle.createWritable();
    "#;
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::FileWriteAccess));
}

#[test]
fn security_detects_file_write_with_stream() {
    let body = r#"
        const stream = new FileSystemWritableFileStream();
        stream.write(data);
    "#;
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::FileWriteAccess));
}

#[test]
fn security_detects_data_exfiltration_fetch() {
    let body = r#"
        const [handle] = await showOpenFilePicker();
        const file = await handle.getFile();
        fetch('/upload', {method: 'POST', body: await file.text()});
    "#;
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::DataExfiltration {
        method: "fetch".to_string()
    }));
}

#[test]
fn security_detects_data_exfiltration_xhr() {
    let body = r#"
        const dir = await showDirectoryPicker();
        const xhr = new XMLHttpRequest();
        xhr.send(data);
    "#;
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::DataExfiltration {
        method: "XMLHttpRequest".to_string()
    }));
}

#[test]
fn security_detects_data_exfiltration_beacon() {
    let body = r#"
        const [handle] = await showOpenFilePicker();
        navigator.sendBeacon('/track', fileData);
    "#;
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::DataExfiltration {
        method: "sendBeacon".to_string()
    }));
}

#[test]
fn security_detects_recursive_directory_walk() {
    let body = r#"
        const dir = await showDirectoryPicker();
        for await (const entry of dir.entries()) {
            console.log(entry);
        }
    "#;
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::RecursiveDirectoryWalk));
}

#[test]
fn security_detects_large_file_read_with_slice() {
    let body = r#"
        const file = await handle.getFile();
        const chunk = file.slice(0, 1000000);
    "#;
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::LargeFileRead));
}

#[test]
fn security_detects_large_file_read_with_arraybuffer() {
    let body = r#"
        const file = await handle.getFile();
        const buffer = await file.arrayBuffer();
    "#;
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::LargeFileRead));
}

#[test]
fn security_detects_sensitive_file_pem() {
    let body = r#"
        const options = {
            types: [{ accept: { 'application/x-pem-file': ['.pem'] } }]
        };
    "#;
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::SensitiveFileType {
        extension: ".pem".to_string()
    }));
}

#[test]
fn security_detects_sensitive_file_key() {
    let body = "const file = 'private.key';";
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::SensitiveFileType {
        extension: ".key".to_string()
    }));
}

#[test]
fn security_detects_sensitive_file_env() {
    let body = "const configFile = '.env';";
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::SensitiveFileType {
        extension: ".env".to_string()
    }));
}

#[test]
fn security_detects_sensitive_file_cfg() {
    let body = "const config = 'settings.cfg';";
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::SensitiveFileType {
        extension: ".cfg".to_string()
    }));
}

#[test]
fn security_detects_sensitive_file_ini() {
    let body = "const iniFile = 'config.ini';";
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::SensitiveFileType {
        extension: ".ini".to_string()
    }));
}

#[test]
fn security_detects_sensitive_file_conf() {
    let body = "const confFile = 'app.conf';";
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::SensitiveFileType {
        extension: ".conf".to_string()
    }));
}

#[test]
fn security_detects_sensitive_file_sqlite() {
    let body = "const dbFile = 'data.sqlite';";
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::SensitiveFileType {
        extension: ".sqlite".to_string()
    }));
}

#[test]
fn security_detects_sensitive_file_db() {
    let body = "const database = 'users.db';";
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::SensitiveFileType {
        extension: ".db".to_string()
    }));
}

#[test]
fn security_detects_sensitive_file_sql() {
    let body = "const schema = 'schema.sql';";
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::SensitiveFileType {
        extension: ".sql".to_string()
    }));
}

#[test]
fn security_detects_sensitive_file_csv() {
    let body = "const exportFile = 'users.csv';";
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::SensitiveFileType {
        extension: ".csv".to_string()
    }));
}

#[test]
fn security_detects_sensitive_file_json() {
    let body = "const config = 'secrets.json';";
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::SensitiveFileType {
        extension: ".json".to_string()
    }));
}

#[test]
fn security_detects_no_file_type_restriction() {
    let body = r#"
        const handle = await showOpenFilePicker();
    "#;
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::NoFileTypeRestriction));
}

#[test]
fn security_no_restriction_with_types() {
    let body = r#"
        const options = { types: [{ accept: { 'text/plain': ['.txt'] } }] };
        const handle = await showOpenFilePicker(options);
    "#;
    let issues = analyze_file_security(body);
    assert!(!issues.contains(&FileSecurityIssue::NoFileTypeRestriction));
}

#[test]
fn security_no_restriction_with_accept() {
    let body = r#"
        const options = { accept: { 'image/*': ['.png', '.jpg'] } };
        const handle = await showOpenFilePicker(options);
    "#;
    let issues = analyze_file_security(body);
    assert!(!issues.contains(&FileSecurityIssue::NoFileTypeRestriction));
}

#[test]
fn security_detects_opaque_origin_access() {
    let body = "const root = await navigator.storage.getDirectory();";
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::OpaqueOriginAccess));
}

#[test]
fn security_detects_permission_persist_query() {
    let body = r#"
        const permission = await handle.queryPermission({ mode: 'readwrite' });
    "#;
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::FileHandlePermissionPersist));
}

#[test]
fn security_detects_permission_persist_request() {
    let body = r#"
        const permission = await handle.requestPermission({ mode: 'read' });
    "#;
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::FileHandlePermissionPersist));
}

#[test]
fn security_detects_cross_origin_file_access() {
    let body = r#"
        const [handle] = await showOpenFilePicker();
        window.postMessage({ file: handle }, '*');
    "#;
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::CrossOriginFileAccess));
}

#[test]
fn security_detects_multiple_file_operations() {
    let body = r#"
        const [handle1] = await showOpenFilePicker();
        const handle2 = await showSaveFilePicker();
        const dir = await showDirectoryPicker();
    "#;
    let issues = analyze_file_security(body);
    assert!(issues.contains(&FileSecurityIssue::MultipleFileOperations { count: 3 }));
}

#[test]
fn security_no_multiple_operations_when_count_low() {
    let body = r#"
        const [handle] = await showOpenFilePicker();
        const dir = await showDirectoryPicker();
    "#;
    let issues = analyze_file_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FileSecurityIssue::MultipleFileOperations { .. }))
    );
}

#[test]
fn security_severity_data_exfiltration_highest() {
    assert_eq!(
        file_security_severity(&FileSecurityIssue::DataExfiltration {
            method: "fetch".to_string()
        }),
        8.5
    );
}

#[test]
fn security_severity_recursive_walk() {
    assert_eq!(
        file_security_severity(&FileSecurityIssue::RecursiveDirectoryWalk),
        8.0
    );
}

#[test]
fn security_severity_cross_origin() {
    assert_eq!(
        file_security_severity(&FileSecurityIssue::CrossOriginFileAccess),
        7.5
    );
}

#[test]
fn security_severity_directory_access() {
    assert_eq!(
        file_security_severity(&FileSecurityIssue::DirectoryAccess),
        7.0
    );
}

#[test]
fn security_severity_file_write() {
    assert_eq!(
        file_security_severity(&FileSecurityIssue::FileWriteAccess),
        7.0
    );
}

#[test]
fn security_severity_permission_persist() {
    assert_eq!(
        file_security_severity(&FileSecurityIssue::FileHandlePermissionPersist),
        6.5
    );
}

#[test]
fn security_severity_sensitive_file() {
    assert_eq!(
        file_security_severity(&FileSecurityIssue::SensitiveFileType {
            extension: ".pem".to_string()
        }),
        6.0
    );
}

#[test]
fn security_severity_large_file_read() {
    assert_eq!(
        file_security_severity(&FileSecurityIssue::LargeFileRead),
        5.5
    );
}

#[test]
fn security_severity_file_picker() {
    assert_eq!(
        file_security_severity(&FileSecurityIssue::FilePickerUsed {
            picker_type: "open".to_string()
        }),
        5.0
    );
}

#[test]
fn security_severity_no_restriction() {
    assert_eq!(
        file_security_severity(&FileSecurityIssue::NoFileTypeRestriction),
        4.5
    );
}

#[test]
fn security_severity_opaque_origin() {
    assert_eq!(
        file_security_severity(&FileSecurityIssue::OpaqueOriginAccess),
        4.0
    );
}

#[test]
fn security_severity_multiple_operations_lowest() {
    assert_eq!(
        file_security_severity(&FileSecurityIssue::MultipleFileOperations { count: 3 }),
        3.5
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        FileSecurityIssue::FilePickerUsed {
            picker_type: "open".to_string(),
        },
        FileSecurityIssue::DirectoryAccess,
        FileSecurityIssue::DataExfiltration {
            method: "fetch".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = file_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn security_display_file_picker_open() {
    assert_eq!(
        FileSecurityIssue::FilePickerUsed {
            picker_type: "open".to_string()
        }
        .to_string(),
        "file_picker_used_open"
    );
}

#[test]
fn security_display_file_picker_save() {
    assert_eq!(
        FileSecurityIssue::FilePickerUsed {
            picker_type: "save".to_string()
        }
        .to_string(),
        "file_picker_used_save"
    );
}

#[test]
fn security_display_file_write_access() {
    assert_eq!(
        FileSecurityIssue::FileWriteAccess.to_string(),
        "file_write_access"
    );
}

#[test]
fn security_display_directory_access() {
    assert_eq!(
        FileSecurityIssue::DirectoryAccess.to_string(),
        "directory_access"
    );
}

#[test]
fn security_display_data_exfiltration() {
    assert_eq!(
        FileSecurityIssue::DataExfiltration {
            method: "fetch".to_string()
        }
        .to_string(),
        "data_exfiltration_fetch"
    );
}

#[test]
fn security_display_large_file_read() {
    assert_eq!(
        FileSecurityIssue::LargeFileRead.to_string(),
        "large_file_read"
    );
}

#[test]
fn security_display_recursive_walk() {
    assert_eq!(
        FileSecurityIssue::RecursiveDirectoryWalk.to_string(),
        "recursive_directory_walk"
    );
}

#[test]
fn security_display_sensitive_file() {
    assert_eq!(
        FileSecurityIssue::SensitiveFileType {
            extension: ".pem".to_string()
        }
        .to_string(),
        "sensitive_file_type.pem"
    );
}

#[test]
fn security_display_no_restriction() {
    assert_eq!(
        FileSecurityIssue::NoFileTypeRestriction.to_string(),
        "no_file_type_restriction"
    );
}

#[test]
fn security_display_opaque_origin() {
    assert_eq!(
        FileSecurityIssue::OpaqueOriginAccess.to_string(),
        "opaque_origin_access"
    );
}

#[test]
fn security_display_permission_persist() {
    assert_eq!(
        FileSecurityIssue::FileHandlePermissionPersist.to_string(),
        "file_handle_permission_persist"
    );
}

#[test]
fn security_display_cross_origin() {
    assert_eq!(
        FileSecurityIssue::CrossOriginFileAccess.to_string(),
        "cross_origin_file_access"
    );
}

#[test]
fn security_display_multiple_operations() {
    assert_eq!(
        FileSecurityIssue::MultipleFileOperations { count: 5 }.to_string(),
        "multiple_file_operations_5"
    );
}
