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
    let body = r#"{"file_handlers": [{"action": "/run", "accept": {"application/x-exe": [".exe"]}}]}"#;
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
    assert_eq!(file_handling_severity(&FileHandlingIssue::ExecutableHandling), 8.0);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(file_handling_severity(&FileHandlingIssue::ApiDetected), 2.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![FileHandlingIssue::ApiDetected, FileHandlingIssue::BroadFileTypes];
    let mut seq = 0;
    let ops = file_handling_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(FileHandlingIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(FileHandlingIssue::BroadFileTypes.to_string(), "broad_file_types");
    assert_eq!(FileHandlingIssue::DataExfiltration.to_string(), "data_exfiltration");
    assert_eq!(FileHandlingIssue::NoContentValidation.to_string(), "no_content_validation");
    assert_eq!(FileHandlingIssue::ExecutableHandling.to_string(), "executable_handling");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_file_handling("").is_empty());
}
