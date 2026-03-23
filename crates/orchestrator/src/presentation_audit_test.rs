use crate::presentation_audit::*;

#[test]
fn no_presentation_no_issues() {
    assert!(analyze_presentation("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_request() {
    let body = r#"<script>const req = new PresentationRequest(["cast.html"]);</script>"#;
    let issues = analyze_presentation(body);
    assert!(issues.contains(&PresentationIssue::ApiDetected));
}

#[test]
fn detects_api_connection() {
    let body = r#"<script>const conn = new PresentationConnection();</script>"#;
    let issues = analyze_presentation(body);
    assert!(issues.contains(&PresentationIssue::ApiDetected));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        fetch("/track?data=leaked");
    </script>"#;
    let issues = analyze_presentation(body);
    assert!(issues.contains(&PresentationIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        console.log(req);
    </script>"#;
    let issues = analyze_presentation(body);
    assert!(!issues.contains(&PresentationIssue::DataExfiltration));
}

#[test]
fn detects_cross_origin_url() {
    let body = r#"<script>
        const req = new PresentationRequest("http://evil.com/cast.html");
    </script>"#;
    let issues = analyze_presentation(body);
    assert!(issues.contains(&PresentationIssue::CrossOriginUrl));
}

#[test]
fn no_cross_origin_with_https() {
    let body = r#"<script>
        const req = new PresentationRequest("https://example.com/cast.html");
    </script>"#;
    let issues = analyze_presentation(body);
    assert!(!issues.contains(&PresentationIssue::CrossOriginUrl));
}

#[test]
fn detects_no_availability_check() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        req.start();
    </script>"#;
    let issues = analyze_presentation(body);
    assert!(issues.contains(&PresentationIssue::NoAvailabilityCheck));
}

#[test]
fn no_availability_issue_with_check() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        const avail = await req.getAvailability();
    </script>"#;
    let issues = analyze_presentation(body);
    assert!(!issues.contains(&PresentationIssue::NoAvailabilityCheck));
}

#[test]
fn detects_message_channel() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        conn.send("secret data");
        conn.onmessage = (e) => console.log(e);
    </script>"#;
    let issues = analyze_presentation(body);
    assert!(issues.contains(&PresentationIssue::MessageChannel));
}

#[test]
fn detects_auto_reconnect() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        navigator.presentation.defaultRequest = req;
        navigator.presentation.receiver.connectionavailable = handler;
    </script>"#;
    let issues = analyze_presentation(body);
    assert!(issues.contains(&PresentationIssue::AutoReconnect));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(presentation_severity(&PresentationIssue::DataExfiltration), 6.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(presentation_severity(&PresentationIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![PresentationIssue::ApiDetected, PresentationIssue::MessageChannel];
    let mut seq = 0;
    let ops = presentation_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(PresentationIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(PresentationIssue::DataExfiltration.to_string(), "data_exfiltration");
    assert_eq!(PresentationIssue::CrossOriginUrl.to_string(), "cross_origin_url");
    assert_eq!(PresentationIssue::NoAvailabilityCheck.to_string(), "no_availability_check");
    assert_eq!(PresentationIssue::MessageChannel.to_string(), "message_channel");
    assert_eq!(PresentationIssue::AutoReconnect.to_string(), "auto_reconnect");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_presentation("").is_empty());
}
