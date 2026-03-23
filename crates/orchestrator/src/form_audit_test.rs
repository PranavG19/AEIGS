use crate::form_audit::*;

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
    assert_eq!(
        FormIssue::MissingCsrfToken.to_string(),
        "missing_csrf_token"
    );
    assert_eq!(
        FormIssue::AutocompleteOnSensitive.to_string(),
        "autocomplete_on_sensitive"
    );
}

#[test]
fn display_security_issue_insecure_action() {
    let issue = FormSecurityIssue::InsecureAction {
        action: "http://example.com".to_string(),
    };
    assert_eq!(issue.to_string(), "insecure_action");
}

#[test]
fn display_security_issue_missing_csrf() {
    let issue = FormSecurityIssue::MissingCsrf {
        action: "/submit".to_string(),
    };
    assert_eq!(issue.to_string(), "missing_csrf");
}

#[test]
fn display_security_issue_autocomplete_password() {
    let issue = FormSecurityIssue::AutocompleteOnPassword;
    assert_eq!(issue.to_string(), "autocomplete_on_password");
}

#[test]
fn display_security_issue_autocomplete_credit_card() {
    let issue = FormSecurityIssue::AutocompleteOnCreditCard;
    assert_eq!(issue.to_string(), "autocomplete_on_credit_card");
}

#[test]
fn display_security_issue_missing_form_action() {
    let issue = FormSecurityIssue::MissingFormAction;
    assert_eq!(issue.to_string(), "missing_form_action");
}

#[test]
fn display_security_issue_target_blank() {
    let issue = FormSecurityIssue::TargetBlankWithoutNoopener;
    assert_eq!(issue.to_string(), "target_blank_without_noopener");
}

#[test]
fn display_security_issue_hidden_field() {
    let issue = FormSecurityIssue::HiddenFieldWithValue {
        name: "test".to_string(),
    };
    assert_eq!(issue.to_string(), "hidden_field_with_value");
}

#[test]
fn display_security_issue_file_upload() {
    let issue = FormSecurityIssue::FileUploadWithoutRestriction;
    assert_eq!(issue.to_string(), "file_upload_without_restriction");
}

#[test]
fn display_security_issue_password_minlength() {
    let issue = FormSecurityIssue::PasswordWithoutMinLength;
    assert_eq!(issue.to_string(), "password_without_minlength");
}

#[test]
fn display_security_issue_mixed_content() {
    let issue = FormSecurityIssue::MixedContentForm {
        action: "http://example.com".to_string(),
    };
    assert_eq!(issue.to_string(), "mixed_content_form");
}

#[test]
fn display_security_issue_method_override() {
    let issue = FormSecurityIssue::FormMethodOverride;
    assert_eq!(issue.to_string(), "form_method_override");
}

#[test]
fn display_security_issue_missing_enctype() {
    let issue = FormSecurityIssue::MissingEnctype {
        action: "/upload".to_string(),
    };
    assert_eq!(issue.to_string(), "missing_enctype");
}

#[test]
fn severity_missing_csrf() {
    let issue = FormSecurityIssue::MissingCsrf {
        action: "/submit".to_string(),
    };
    assert_eq!(form_security_severity(&issue), 7.0);
}

#[test]
fn severity_insecure_action() {
    let issue = FormSecurityIssue::InsecureAction {
        action: "http://example.com".to_string(),
    };
    assert_eq!(form_security_severity(&issue), 6.0);
}

#[test]
fn severity_mixed_content() {
    let issue = FormSecurityIssue::MixedContentForm {
        action: "http://example.com".to_string(),
    };
    assert_eq!(form_security_severity(&issue), 6.0);
}

#[test]
fn severity_file_upload() {
    let issue = FormSecurityIssue::FileUploadWithoutRestriction;
    assert_eq!(form_security_severity(&issue), 5.5);
}

#[test]
fn severity_method_override() {
    let issue = FormSecurityIssue::FormMethodOverride;
    assert_eq!(form_security_severity(&issue), 5.0);
}

#[test]
fn severity_password_minlength() {
    let issue = FormSecurityIssue::PasswordWithoutMinLength;
    assert_eq!(form_security_severity(&issue), 4.5);
}

#[test]
fn severity_hidden_field() {
    let issue = FormSecurityIssue::HiddenFieldWithValue {
        name: "test".to_string(),
    };
    assert_eq!(form_security_severity(&issue), 4.0);
}

#[test]
fn severity_autocomplete_password() {
    let issue = FormSecurityIssue::AutocompleteOnPassword;
    assert_eq!(form_security_severity(&issue), 3.5);
}

#[test]
fn severity_autocomplete_credit_card() {
    let issue = FormSecurityIssue::AutocompleteOnCreditCard;
    assert_eq!(form_security_severity(&issue), 3.5);
}

#[test]
fn severity_missing_form_action() {
    let issue = FormSecurityIssue::MissingFormAction;
    assert_eq!(form_security_severity(&issue), 3.0);
}

#[test]
fn severity_target_blank() {
    let issue = FormSecurityIssue::TargetBlankWithoutNoopener;
    assert_eq!(form_security_severity(&issue), 3.0);
}

#[test]
fn severity_missing_enctype() {
    let issue = FormSecurityIssue::MissingEnctype {
        action: "/upload".to_string(),
    };
    assert_eq!(form_security_severity(&issue), 2.5);
}

#[test]
fn analyze_insecure_action_http() {
    let html = r#"<form action="http://example.com/submit" method="post">
        <input type="hidden" name="csrf_token" value="abc">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::InsecureAction { .. }))
    );
}

#[test]
fn analyze_https_action_no_insecure() {
    let html = r#"<form action="https://example.com/submit" method="post">
        <input type="hidden" name="csrf_token" value="abc">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::InsecureAction { .. }))
    );
}

#[test]
fn analyze_missing_csrf_post_form() {
    let html = r#"<form action="/submit" method="post">
        <input type="text" name="user">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::MissingCsrf { .. }))
    );
}

#[test]
fn analyze_get_form_no_csrf_check() {
    let html = r#"<form action="/search" method="get">
        <input type="text" name="q">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::MissingCsrf { .. }))
    );
}

#[test]
fn analyze_csrf_token_present_no_issue() {
    let html = r#"<form action="/submit" method="post">
        <input type="hidden" name="csrf_token" value="abc123">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::MissingCsrf { .. }))
    );
}

#[test]
fn analyze_missing_form_action_post() {
    let html = r#"<form method="post">
        <input type="hidden" name="csrf_token" value="abc">
        <input type="text" name="user">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::MissingFormAction))
    );
}

#[test]
fn analyze_missing_form_action_get_ok() {
    let html = r#"<form method="get">
        <input type="text" name="q">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::MissingFormAction))
    );
}

#[test]
fn analyze_autocomplete_on_password() {
    let html = r#"<form action="/login" method="post">
        <input type="hidden" name="csrf_token" value="abc">
        <input type="password" name="pass">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::AutocompleteOnPassword))
    );
}

#[test]
fn analyze_autocomplete_new_password_ok() {
    let html = r#"<form action="/signup" method="post">
        <input type="hidden" name="csrf_token" value="abc">
        <input type="password" name="pass" autocomplete="new-password">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::AutocompleteOnPassword))
    );
}

#[test]
fn analyze_autocomplete_off_ok() {
    let html = r#"<form action="/login" method="post">
        <input type="hidden" name="csrf_token" value="abc">
        <input type="password" name="pass" autocomplete="off">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::AutocompleteOnPassword))
    );
}

#[test]
fn analyze_password_without_minlength() {
    let html = r#"<form action="/signup" method="post">
        <input type="hidden" name="csrf_token" value="abc">
        <input type="password" name="pass" autocomplete="off">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::PasswordWithoutMinLength))
    );
}

#[test]
fn analyze_password_with_minlength_ok() {
    let html = r#"<form action="/signup" method="post">
        <input type="hidden" name="csrf_token" value="abc">
        <input type="password" name="pass" autocomplete="off" minlength="8">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::PasswordWithoutMinLength))
    );
}

#[test]
fn analyze_autocomplete_on_credit_card() {
    let html = r#"<form action="/payment" method="post">
        <input type="hidden" name="csrf_token" value="abc">
        <input type="text" name="credit_card_number">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::AutocompleteOnCreditCard))
    );
}

#[test]
fn analyze_credit_card_autocomplete_off_ok() {
    let html = r#"<form action="/payment" method="post">
        <input type="hidden" name="csrf_token" value="abc">
        <input type="text" name="credit_card_number" autocomplete="off">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::AutocompleteOnCreditCard))
    );
}

#[test]
fn analyze_file_upload_no_accept() {
    let html = r#"<form action="/upload" method="post">
        <input type="hidden" name="csrf_token" value="abc">
        <input type="file" name="document">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::FileUploadWithoutRestriction))
    );
}

#[test]
fn analyze_file_upload_with_accept_ok() {
    let html = r#"<form action="/upload" method="post" enctype="multipart/form-data">
        <input type="hidden" name="csrf_token" value="abc">
        <input type="file" name="document" accept=".pdf,.doc">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::FileUploadWithoutRestriction))
    );
}

#[test]
fn analyze_missing_enctype_file_upload() {
    let html = r#"<form action="/upload" method="post">
        <input type="hidden" name="csrf_token" value="abc">
        <input type="file" name="document" accept=".pdf">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::MissingEnctype { .. }))
    );
}

#[test]
fn analyze_hidden_field_with_value() {
    let html = r#"<form action="/submit" method="post">
        <input type="hidden" name="csrf_token" value="abc">
        <input type="hidden" name="redirect" value="/dashboard">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::HiddenFieldWithValue { .. }))
    );
}

#[test]
fn analyze_method_override_detected() {
    let html = r#"<form action="/users/1" method="post">
        <input type="hidden" name="csrf_token" value="abc">
        <input type="hidden" name="_method" value="DELETE">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::FormMethodOverride))
    );
}

#[test]
fn analyze_target_blank_without_noopener() {
    let html = r#"<a href="https://example.com" target="_blank">Link</a>"#;
    let issues = analyze_form_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::TargetBlankWithoutNoopener))
    );
}

#[test]
fn analyze_target_blank_with_noopener_ok() {
    let html =
        r#"<a href="https://example.com" target="_blank" rel="noopener noreferrer">Link</a>"#;
    let issues = analyze_form_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::TargetBlankWithoutNoopener))
    );
}

#[test]
fn analyze_clean_form_no_issues() {
    let html = r#"<form action="https://example.com/submit" method="post" enctype="multipart/form-data">
        <input type="hidden" name="csrf_token" value="abc123">
        <input type="password" name="pass" autocomplete="off" minlength="8">
        <input type="file" name="doc" accept=".pdf">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::InsecureAction { .. }))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::MissingCsrf { .. }))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::AutocompleteOnPassword))
    );
}

#[test]
fn analyze_mixed_content_detected() {
    let html = r#"<form action="http://example.com/submit" method="post">
        <input type="hidden" name="csrf_token" value="abc">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::MixedContentForm { .. }))
    );
}

#[test]
fn analyze_combined_multiple_issues() {
    let html = r#"<form action="http://example.com/login" method="post">
        <input type="password" name="pass">
        <input type="file" name="avatar">
    </form>"#;
    let issues = analyze_form_security(html);
    assert!(issues.len() >= 5);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::InsecureAction { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::MissingCsrf { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::AutocompleteOnPassword))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::FileUploadWithoutRestriction))
    );
}

#[test]
fn security_operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = form_security_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn security_operations_single_issue() {
    let issues = vec![FormSecurityIssue::MissingCsrf {
        action: "/submit".to_string(),
    }];
    let mut seq = 0;
    let ops = form_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn security_operations_multiple_issues() {
    let issues = vec![
        FormSecurityIssue::MissingCsrf {
            action: "/submit".to_string(),
        },
        FormSecurityIssue::InsecureAction {
            action: "http://example.com".to_string(),
        },
        FormSecurityIssue::AutocompleteOnPassword,
    ];
    let mut seq = 10;
    let ops = form_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
}
