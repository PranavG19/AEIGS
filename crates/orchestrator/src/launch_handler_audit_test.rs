use crate::launch_handler_audit::*;

#[test]
fn no_launch_handler_no_issues() {
    assert!(analyze_launch_handler("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_launch_queue() {
    let body = r#"<script>window.launchQueue.setConsumer(params => {});</script>"#;
    let issues = analyze_launch_handler(body);
    assert!(issues.contains(&LaunchHandlerIssue::ApiDetected));
}

#[test]
fn detects_api_launch_params() {
    let body = r#"<script>if (window.LaunchParams) {}</script>"#;
    let issues = analyze_launch_handler(body);
    assert!(issues.contains(&LaunchHandlerIssue::ApiDetected));
}

#[test]
fn detects_url_injection() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            window.location = params.targetURL;
        });
    </script>"#;
    let issues = analyze_launch_handler(body);
    assert!(issues.contains(&LaunchHandlerIssue::UrlInjection));
}

#[test]
fn no_injection_with_validation() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            const url = new URL(params.targetURL);
            window.location = url.href;
        });
    </script>"#;
    let issues = analyze_launch_handler(body);
    assert!(!issues.contains(&LaunchHandlerIssue::UrlInjection));
}

#[test]
fn detects_file_handling() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            for (const f of params.files) { readFile(f); }
        });
    </script>"#;
    let issues = analyze_launch_handler(body);
    assert!(issues.contains(&LaunchHandlerIssue::FileHandling));
}

#[test]
fn no_files_without_keyword() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            navigate(params.targetURL);
        });
    </script>"#;
    let issues = analyze_launch_handler(body);
    assert!(!issues.contains(&LaunchHandlerIssue::FileHandling));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            fetch("/log", {body: JSON.stringify(params)});
        });
    </script>"#;
    let issues = analyze_launch_handler(body);
    assert!(issues.contains(&LaunchHandlerIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            console.log(params);
        });
    </script>"#;
    let issues = analyze_launch_handler(body);
    assert!(!issues.contains(&LaunchHandlerIssue::DataExfiltration));
}

#[test]
fn detects_no_input_validation() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            processData(params);
        });
    </script>"#;
    let issues = analyze_launch_handler(body);
    assert!(issues.contains(&LaunchHandlerIssue::NoInputValidation));
}

#[test]
fn no_validation_issue_with_sanitize() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            const safe = sanitize(params);
            processData(safe);
        });
    </script>"#;
    let issues = analyze_launch_handler(body);
    assert!(!issues.contains(&LaunchHandlerIssue::NoInputValidation));
}

#[test]
fn severity_injection_highest() {
    assert_eq!(launch_handler_severity(&LaunchHandlerIssue::UrlInjection), 7.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(launch_handler_severity(&LaunchHandlerIssue::ApiDetected), 2.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![LaunchHandlerIssue::ApiDetected, LaunchHandlerIssue::FileHandling];
    let mut seq = 0;
    let ops = launch_handler_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(LaunchHandlerIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(LaunchHandlerIssue::UrlInjection.to_string(), "url_injection");
    assert_eq!(LaunchHandlerIssue::FileHandling.to_string(), "file_handling");
    assert_eq!(LaunchHandlerIssue::DataExfiltration.to_string(), "data_exfiltration");
    assert_eq!(LaunchHandlerIssue::NoInputValidation.to_string(), "no_input_validation");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_launch_handler("").is_empty());
}
