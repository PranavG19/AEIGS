use crate::form_audit::{analyze_forms, form_findings_to_operations, FormFinding, FormIssue};

#[test]
fn detects_insecure_form_action() {
    let html = r#"<form action="http://example.com/submit" method="post">
        <input type="text" name="user">
        <input type="hidden" name="csrf_token" value="abc">
    </form>"#;
    let findings = analyze_forms(html);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].issue, FormIssue::InsecureAction);
}

#[test]
fn detects_missing_csrf_token() {
    let html = r#"<form action="/submit" method="post">
        <input type="text" name="user">
    </form>"#;
    let findings = analyze_forms(html);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].issue, FormIssue::MissingCsrfToken);
}

#[test]
fn skips_csrf_check_for_get_forms() {
    let html = r#"<form action="/search" method="get">
        <input type="text" name="q">
    </form>"#;
    let findings = analyze_forms(html);
    assert!(findings.is_empty());
}

#[test]
fn skips_csrf_check_for_default_method() {
    let html = r#"<form action="/search">
        <input type="text" name="q">
    </form>"#;
    let findings = analyze_forms(html);
    assert!(findings.is_empty());
}

#[test]
fn accepts_form_with_csrf_token() {
    let html = r#"<form action="/submit" method="post">
        <input type="hidden" name="csrf_token" value="abc123">
        <input type="text" name="user">
    </form>"#;
    let findings = analyze_forms(html);
    assert!(findings.is_empty());
}

#[test]
fn accepts_form_with_authenticity_token() {
    let html = r#"<form action="/submit" method="post">
        <input type="hidden" name="authenticity_token" value="abc123">
    </form>"#;
    let findings = analyze_forms(html);
    assert!(findings.is_empty());
}

#[test]
fn detects_autocomplete_on_password() {
    let html = r#"<form action="/login" method="post">
        <input type="hidden" name="csrf_token" value="abc">
        <input type="password" name="pass">
    </form>"#;
    let findings = analyze_forms(html);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].issue, FormIssue::AutocompleteOnSensitive);
}

#[test]
fn autocomplete_off_suppresses_finding() {
    let html = r#"<form action="/login" method="post">
        <input type="hidden" name="csrf_token" value="abc">
        <input type="password" name="pass" autocomplete="off">
    </form>"#;
    let findings = analyze_forms(html);
    assert!(findings.is_empty());
}

#[test]
fn detects_multiple_issues() {
    let html = r#"
        <form action="http://example.com/login" method="post">
            <input type="password" name="pass">
        </form>
    "#;
    let findings = analyze_forms(html);
    assert!(findings.len() >= 2);
    let issues: Vec<_> = findings.iter().map(|f| &f.issue).collect();
    assert!(issues.contains(&&FormIssue::InsecureAction));
    assert!(issues.contains(&&FormIssue::MissingCsrfToken));
}

#[test]
fn no_findings_on_clean_page() {
    let html = r#"<html><body><p>No forms here</p></body></html>"#;
    let findings = analyze_forms(html);
    assert!(findings.is_empty());
}

#[test]
fn operations_empty_when_no_findings() {
    let mut seq = 0;
    let ops = form_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_csrf() {
    let findings = vec![FormFinding {
        issue: FormIssue::MissingCsrfToken,
        action: "/submit".to_string(),
    }];
    let mut seq = 0;
    let ops = form_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn display_issue_variants() {
    assert_eq!(FormIssue::InsecureAction.to_string(), "insecure_action");
    assert_eq!(FormIssue::MissingCsrfToken.to_string(), "missing_csrf_token");
    assert_eq!(
        FormIssue::AutocompleteOnSensitive.to_string(),
        "autocomplete_on_sensitive"
    );
}
