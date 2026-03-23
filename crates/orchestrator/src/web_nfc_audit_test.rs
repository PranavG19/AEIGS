use crate::web_nfc_audit::*;

#[test]
fn no_nfc_no_issues() {
    assert!(analyze_web_nfc("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_reader() {
    let body = r#"<script>const reader = new NDEFReader();</script>"#;
    let issues = analyze_web_nfc(body);
    assert!(issues.contains(&WebNfcIssue::ApiDetected));
}

#[test]
fn detects_api_writer() {
    let body = r#"<script>const writer = new NDEFWriter();</script>"#;
    let issues = analyze_web_nfc(body);
    assert!(issues.contains(&WebNfcIssue::ApiDetected));
    assert!(issues.contains(&WebNfcIssue::WriteCapability));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const reader = new NDEFReader();
        fetch("/api/nfc-data", {body: "data"});
    </script>"#;
    let issues = analyze_web_nfc(body);
    assert!(issues.contains(&WebNfcIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const reader = new NDEFReader();
        console.log(reader);
    </script>"#;
    let issues = analyze_web_nfc(body);
    assert!(!issues.contains(&WebNfcIssue::DataExfiltration));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>const reader = new NDEFReader();</script>"#;
    let issues = analyze_web_nfc(body);
    assert!(issues.contains(&WebNfcIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const reader = new NDEFReader();
        });
    </script>"#;
    let issues = analyze_web_nfc(body);
    assert!(!issues.contains(&WebNfcIssue::NoUserActivation));
}

#[test]
fn detects_write_capability() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const reader = new NDEFReader();
            await reader.write("malicious data");
        });
    </script>"#;
    let issues = analyze_web_nfc(body);
    assert!(issues.contains(&WebNfcIssue::WriteCapability));
}

#[test]
fn detects_continuous_scanning() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const reader = new NDEFReader();
            reader.scan();
            reader.onreading = (event) => console.log(event);
        });
    </script>"#;
    let issues = analyze_web_nfc(body);
    assert!(issues.contains(&WebNfcIssue::ContinuousScanning));
}

#[test]
fn detects_url_record_injection() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const reader = new NDEFReader();
            const record = new NDEFRecord({recordType: "url", data: "https://evil.com"});
        });
    </script>"#;
    let issues = analyze_web_nfc(body);
    assert!(issues.contains(&WebNfcIssue::UrlRecordInjection));
}

#[test]
fn severity_write_highest() {
    assert_eq!(web_nfc_severity(&WebNfcIssue::WriteCapability), 7.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(web_nfc_severity(&WebNfcIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![WebNfcIssue::ApiDetected, WebNfcIssue::WriteCapability];
    let mut seq = 0;
    let ops = web_nfc_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(WebNfcIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(WebNfcIssue::DataExfiltration.to_string(), "data_exfiltration");
    assert_eq!(WebNfcIssue::NoUserActivation.to_string(), "no_user_activation");
    assert_eq!(WebNfcIssue::WriteCapability.to_string(), "write_capability");
    assert_eq!(WebNfcIssue::ContinuousScanning.to_string(), "continuous_scanning");
    assert_eq!(WebNfcIssue::UrlRecordInjection.to_string(), "url_record_injection");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_web_nfc("").is_empty());
}
