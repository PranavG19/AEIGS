use crate::hidden_input_audit::{
    HiddenInputIssueKind, find_hidden_input_issues, hidden_input_to_operations,
};

#[test]
fn no_inputs_no_issues() {
    let issues = find_hidden_input_issues("<html><body></body></html>");
    assert!(issues.is_empty());
}

#[test]
fn debug_param_detected() {
    let html = r#"<input type="hidden" name="debug" value="true">"#;
    let issues = find_hidden_input_issues(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, HiddenInputIssueKind::DebugParam);
}

#[test]
fn api_key_detected() {
    let html = r#"<input type="hidden" name="api_key" value="sk-12345">"#;
    let issues = find_hidden_input_issues(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, HiddenInputIssueKind::TokenLeak);
}

#[test]
fn version_detected() {
    let html = r#"<input type="hidden" name="version" value="2.3.1">"#;
    let issues = find_hidden_input_issues(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, HiddenInputIssueKind::VersionLeak);
}

#[test]
fn user_id_detected() {
    let html = r#"<input type="hidden" name="user_id" value="12345">"#;
    let issues = find_hidden_input_issues(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, HiddenInputIssueKind::InternalId);
}

#[test]
fn non_hidden_input_ignored() {
    let html = r#"<input type="text" name="debug" value="true">"#;
    let issues = find_hidden_input_issues(html);
    assert!(issues.is_empty());
}

#[test]
fn normal_hidden_input_ok() {
    let html = r#"<input type="hidden" name="csrf_token" value="abc123">"#;
    let issues = find_hidden_input_issues(html);
    assert!(issues.is_empty());
}

#[test]
fn multiple_issues() {
    let html = concat!(
        r#"<input type="hidden" name="debug" value="1">"#,
        r#"<input type="hidden" name="api_key" value="key123">"#,
    );
    let issues = find_hidden_input_issues(html);
    assert_eq!(issues.len(), 2);
}

#[test]
fn case_insensitive_type() {
    let html = r#"<INPUT TYPE="HIDDEN" NAME="debug" VALUE="true">"#;
    let issues = find_hidden_input_issues(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn no_name_attribute_skipped() {
    let html = r#"<input type="hidden" value="something">"#;
    let issues = find_hidden_input_issues(html);
    assert!(issues.is_empty());
}

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = hidden_input_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_on_issues() {
    let html = r#"<input type="hidden" name="debug" value="1">"#;
    let issues = find_hidden_input_issues(html);
    let mut seq = 5;
    let ops = hidden_input_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
}
