use crate::host_header_audit::*;

#[test]
fn analyze_no_reflection() {
    let issues = analyze_host_header_response(
        Some("https://example.com/login"),
        "<html><body>Welcome</body></html>",
        None,
        "",
    );
    assert!(issues.is_empty());
}

#[test]
fn analyze_host_reflected_in_location() {
    let issues = analyze_host_header_response(
        Some("https://evil-canary.example.com/login"),
        "<html></html>",
        None,
        "",
    );
    assert_eq!(issues, vec![HostHeaderIssue::ReflectedInLocation]);
}

#[test]
fn analyze_host_reflected_in_body() {
    let issues = analyze_host_header_response(
        Some("https://safe.example.com/"),
        r#"<html><a href="https://evil-canary.example.com/reset">Reset</a></html>"#,
        None,
        "",
    );
    assert_eq!(issues, vec![HostHeaderIssue::ReflectedInBody]);
}

#[test]
fn analyze_x_forwarded_host_in_location() {
    let issues = analyze_host_header_response(
        None,
        "",
        Some("https://evil-canary.example.com/redirect"),
        "",
    );
    assert_eq!(issues, vec![HostHeaderIssue::XForwardedHostAccepted]);
}

#[test]
fn analyze_x_forwarded_host_in_body() {
    let issues = analyze_host_header_response(
        None,
        "",
        None,
        r#"<base href="https://evil-canary.example.com/">"#,
    );
    assert_eq!(issues, vec![HostHeaderIssue::XForwardedHostAccepted]);
}

#[test]
fn analyze_multiple_issues() {
    let issues = analyze_host_header_response(
        Some("https://evil-canary.example.com/"),
        "Reflected: evil-canary.example.com",
        Some("https://evil-canary.example.com/x"),
        "",
    );
    assert_eq!(issues.len(), 3);
}

#[test]
fn severity_location_highest() {
    assert!(
        host_header_severity(&HostHeaderIssue::ReflectedInLocation)
            > host_header_severity(&HostHeaderIssue::ReflectedInBody)
    );
}

#[test]
fn severity_x_forwarded_medium() {
    let s = host_header_severity(&HostHeaderIssue::XForwardedHostAccepted);
    assert!(s > 6.0);
    assert!(s < 7.0);
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = host_header_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_created_for_issues() {
    let issues = vec![
        HostHeaderIssue::ReflectedInLocation,
        HostHeaderIssue::XForwardedHostAccepted,
    ];
    let mut seq = 0;
    let ops = host_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        HostHeaderIssue::ReflectedInBody.to_string(),
        "host_reflected_in_body"
    );
    assert_eq!(
        HostHeaderIssue::ReflectedInLocation.to_string(),
        "host_reflected_in_location"
    );
    assert_eq!(
        HostHeaderIssue::XForwardedHostAccepted.to_string(),
        "x_forwarded_host_accepted"
    );
}

#[test]
fn audit_host_header_skips_localhost() {
    let issues = audit_host_header("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_host_header_skips_loopback() {
    let issues = audit_host_header("http://127.0.0.1");
    assert!(issues.is_empty());
}
