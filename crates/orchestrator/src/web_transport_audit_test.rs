use crate::web_transport_audit::*;

#[test]
fn no_transport_no_issues() {
    assert!(analyze_web_transport("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api() {
    let body = r#"<script>const wt = new WebTransport("https://example.com");</script>"#;
    let issues = analyze_web_transport(body);
    assert!(issues.contains(&WebTransportIssue::ApiDetected));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        fetch("/track?data=leaked");
    </script>"#;
    let issues = analyze_web_transport(body);
    assert!(issues.contains(&WebTransportIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        console.log(wt);
    </script>"#;
    let issues = analyze_web_transport(body);
    assert!(!issues.contains(&WebTransportIssue::DataExfiltration));
}

#[test]
fn detects_unencrypted_endpoint() {
    let body = r#"<script>
        const wt = new WebTransport("http://example.com:4433/wt");
    </script>"#;
    let issues = analyze_web_transport(body);
    assert!(issues.contains(&WebTransportIssue::UnencryptedEndpoint));
}

#[test]
fn no_unencrypted_with_https() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com:4433/wt");
    </script>"#;
    let issues = analyze_web_transport(body);
    assert!(!issues.contains(&WebTransportIssue::UnencryptedEndpoint));
}

#[test]
fn detects_bidirectional_stream() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        const stream = await wt.createBidirectionalStream();
    </script>"#;
    let issues = analyze_web_transport(body);
    assert!(issues.contains(&WebTransportIssue::BidirectionalStream));
}

#[test]
fn detects_datagram_abuse() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        const writer = wt.datagrams.writable.getWriter();
    </script>"#;
    let issues = analyze_web_transport(body);
    assert!(issues.contains(&WebTransportIssue::DatagramAbuse));
}

#[test]
fn detects_no_close_handling() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        const stream = await wt.createBidirectionalStream();
    </script>"#;
    let issues = analyze_web_transport(body);
    assert!(issues.contains(&WebTransportIssue::NoCloseHandling));
}

#[test]
fn no_close_issue_with_close() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        wt.closed.then(() => console.log("done"));
    </script>"#;
    let issues = analyze_web_transport(body);
    assert!(!issues.contains(&WebTransportIssue::NoCloseHandling));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        web_transport_severity(&WebTransportIssue::DataExfiltration),
        7.0
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(web_transport_severity(&WebTransportIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        WebTransportIssue::ApiDetected,
        WebTransportIssue::DatagramAbuse,
    ];
    let mut seq = 0;
    let ops = web_transport_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(WebTransportIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        WebTransportIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        WebTransportIssue::UnencryptedEndpoint.to_string(),
        "unencrypted_endpoint"
    );
    assert_eq!(
        WebTransportIssue::BidirectionalStream.to_string(),
        "bidirectional_stream"
    );
    assert_eq!(
        WebTransportIssue::DatagramAbuse.to_string(),
        "datagram_abuse"
    );
    assert_eq!(
        WebTransportIssue::NoCloseHandling.to_string(),
        "no_close_handling"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_web_transport("").is_empty());
}
