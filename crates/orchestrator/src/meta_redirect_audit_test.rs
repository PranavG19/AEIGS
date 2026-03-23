use crate::meta_redirect_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_meta_redirect("");
    assert!(issues.is_empty());
}

#[test]
fn no_redirect_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_meta_redirect(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_meta_refresh_redirect() {
    let body =
        r#"<meta http-equiv="refresh" content="0;url=https://example.com">"#;
    let issues = analyze_meta_redirect(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        MetaRedirectIssue::MetaRefreshRedirect { .. }
    )));
}

#[test]
fn detects_meta_refresh_short_delay() {
    let body =
        r#"<meta http-equiv="refresh" content="0;url=https://example.com">"#;
    let issues = analyze_meta_redirect(body);
    assert!(issues.contains(&MetaRedirectIssue::MetaRefreshShortDelay));
}

#[test]
fn long_delay_no_short_delay_issue() {
    let body =
        r#"<meta http-equiv="refresh" content="30;url=https://example.com">"#;
    let issues = analyze_meta_redirect(body);
    assert!(!issues.contains(&MetaRedirectIssue::MetaRefreshShortDelay));
}

#[test]
fn detects_javascript_redirect_href() {
    let body = "window.location.href = 'https://evil.com';";
    let issues = analyze_meta_redirect(body);
    assert!(issues.contains(&MetaRedirectIssue::JavascriptRedirect));
}

#[test]
fn detects_javascript_redirect_replace() {
    let body = "location.replace('https://evil.com');";
    let issues = analyze_meta_redirect(body);
    assert!(issues.contains(&MetaRedirectIssue::JavascriptRedirect));
}

#[test]
fn detects_location_assign() {
    let body = "location.assign('https://evil.com');";
    let issues = analyze_meta_redirect(body);
    assert!(issues.contains(&MetaRedirectIssue::WindowLocationAssign));
}

#[test]
fn detects_document_write_redirect() {
    let body = r#"document.write('<script>location="url"</script>');"#;
    let issues = analyze_meta_redirect(body);
    assert!(issues.contains(&MetaRedirectIssue::DocumentWriteRedirect));
}

#[test]
fn detects_history_replace_state() {
    let body = r#"
        history.replaceState(null, '', '/new');
        location.reload();
    "#;
    let issues = analyze_meta_redirect(body);
    assert!(issues.contains(&MetaRedirectIssue::HistoryReplaceState));
}

#[test]
fn severity_document_write_highest() {
    assert_eq!(
        meta_redirect_severity(&MetaRedirectIssue::DocumentWriteRedirect),
        6.5
    );
}

#[test]
fn severity_short_delay_lowest() {
    assert_eq!(
        meta_redirect_severity(&MetaRedirectIssue::MetaRefreshShortDelay),
        3.5
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        MetaRedirectIssue::JavascriptRedirect,
        MetaRedirectIssue::MetaRefreshShortDelay,
    ];
    let mut seq = 0;
    let ops = meta_redirect_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        MetaRedirectIssue::MetaRefreshShortDelay.to_string(),
        "meta_refresh_short_delay"
    );
    assert_eq!(
        MetaRedirectIssue::JavascriptRedirect.to_string(),
        "javascript_redirect"
    );
    assert_eq!(
        MetaRedirectIssue::WindowLocationAssign.to_string(),
        "window_location_assign"
    );
    assert_eq!(
        MetaRedirectIssue::DocumentWriteRedirect.to_string(),
        "document_write_redirect"
    );
    assert_eq!(
        MetaRedirectIssue::HistoryReplaceState.to_string(),
        "history_replace_state"
    );
}

#[test]
fn display_meta_refresh() {
    let issue = MetaRedirectIssue::MetaRefreshRedirect {
        url: "https://example.com".to_string(),
    };
    assert_eq!(issue.to_string(), "meta_refresh:https://example.com");
}
