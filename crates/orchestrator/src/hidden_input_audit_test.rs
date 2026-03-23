use crate::hidden_input_audit::*;

// --- DebugParam ---

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
    assert_eq!(
        issues[0],
        HiddenInputIssue::DebugParam {
            name: "debug".into()
        }
    );
}

#[test]
fn debug_param_verbose() {
    let html = r#"<input type="hidden" name="verbose" value="1">"#;
    let issues = find_hidden_input_issues(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        HiddenInputIssue::DebugParam {
            name: "verbose".into()
        }
    );
}

// --- TokenLeak ---

#[test]
fn api_key_detected() {
    let html = r#"<input type="hidden" name="api_key" value="sk-12345">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::TokenLeak { name } if name == "api_key"))
    );
}

#[test]
fn jwt_token_detected() {
    let html = r#"<input type="hidden" name="jwt" value="eyJhbGci">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::TokenLeak { name } if name == "jwt"))
    );
}

#[test]
fn csrf_token_not_flagged() {
    let html = r#"<input type="hidden" name="csrf_token" value="abc123">"#;
    let issues = find_hidden_input_issues(html);
    assert!(issues.is_empty());
}

#[test]
fn xsrf_token_not_flagged() {
    let html = r#"<input type="hidden" name="xsrf_token" value="abc123">"#;
    let issues = find_hidden_input_issues(html);
    assert!(issues.is_empty());
}

// --- VersionLeak ---

#[test]
fn version_detected() {
    let html = r#"<input type="hidden" name="version" value="2.3.1">"#;
    let issues = find_hidden_input_issues(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        HiddenInputIssue::VersionLeak {
            name: "version".into()
        }
    );
}

#[test]
fn build_number_detected() {
    let html = r#"<input type="hidden" name="build_number" value="4521">"#;
    let issues = find_hidden_input_issues(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        HiddenInputIssue::VersionLeak {
            name: "build_number".into()
        }
    );
}

// --- InternalId ---

#[test]
fn user_id_detected() {
    let html = r#"<input type="hidden" name="user_id" value="12345">"#;
    let issues = find_hidden_input_issues(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        HiddenInputIssue::InternalId {
            name: "user_id".into()
        }
    );
}

#[test]
fn account_id_detected() {
    let html = r#"<input type="hidden" name="account_id" value="99">"#;
    let issues = find_hidden_input_issues(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        HiddenInputIssue::InternalId {
            name: "account_id".into()
        }
    );
}

#[test]
fn org_id_detected() {
    let html = r#"<input type="hidden" name="org_id" value="42">"#;
    let issues = find_hidden_input_issues(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        HiddenInputIssue::InternalId {
            name: "org_id".into()
        }
    );
}

// --- PasswordField ---

#[test]
fn password_field_detected() {
    let html = r#"<input type="hidden" name="password" value="hunter2">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::PasswordField { name } if name == "password"))
    );
}

#[test]
fn passwd_field_detected() {
    let html = r#"<input type="hidden" name="old_passwd" value="abc">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::PasswordField { name } if name == "old_passwd"))
    );
}

// --- EmailLeak ---

#[test]
fn email_leak_detected() {
    let html = r#"<input type="hidden" name="user_email" value="admin@example.com">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::EmailLeak { name } if name == "user_email"))
    );
}

#[test]
fn email_name_without_at_not_flagged() {
    let html = r#"<input type="hidden" name="email_pref" value="daily">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::EmailLeak { .. }))
    );
}

// --- PathLeak ---

#[test]
fn path_leak_detected() {
    let html = r#"<input type="hidden" name="upload_dir" value="/var/www/uploads">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::PathLeak { name } if name == "upload_dir"))
    );
}

#[test]
fn single_slash_not_path_leak() {
    let html = r#"<input type="hidden" name="sep" value="/single">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::PathLeak { .. }))
    );
}

// --- SqlFragment ---

#[test]
fn sql_select_detected() {
    let html = r#"<input type="hidden" name="query" value="SELECT * FROM users">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::SqlFragment { name } if name == "query"))
    );
}

#[test]
fn sql_where_detected() {
    let html = r#"<input type="hidden" name="filter" value="id=1 WHERE active=true">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::SqlFragment { name } if name == "filter"))
    );
}

#[test]
fn sql_case_insensitive() {
    let html = r#"<input type="hidden" name="q" value="select name from tbl">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::SqlFragment { name } if name == "q"))
    );
}

// --- Base64EncodedValue ---

#[test]
fn base64_value_detected() {
    let html = r#"<input type="hidden" name="data" value="SGVsbG8gV29ybGQhISE=">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::Base64EncodedValue { name } if name == "data"))
    );
}

#[test]
fn short_value_not_base64() {
    let html = r#"<input type="hidden" name="data" value="abc=">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::Base64EncodedValue { .. }))
    );
}

#[test]
fn no_padding_not_base64() {
    let html = r#"<input type="hidden" name="data" value="SGVsbG8gV29ybGQhISE">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::Base64EncodedValue { .. }))
    );
}

// --- AutocompleteEnabled ---

#[test]
fn autocomplete_on_token_field() {
    let html = r#"<input type="hidden" name="api_key" value="key123">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        issues.iter().any(
            |i| matches!(i, HiddenInputIssue::AutocompleteEnabled { name } if name == "api_key")
        )
    );
}

#[test]
fn autocomplete_off_suppresses() {
    let html = r#"<input type="hidden" name="api_key" value="key123" autocomplete="off">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::AutocompleteEnabled { .. }))
    );
}

#[test]
fn autocomplete_not_on_safe_token() {
    let html = r#"<input type="hidden" name="csrf_token" value="abc">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::AutocompleteEnabled { .. }))
    );
}

// --- ExcessiveHiddenFields ---

#[test]
fn excessive_hidden_fields_triggered() {
    let mut html = String::new();
    for i in 0..21 {
        html.push_str(&format!(r#"<input type="hidden" name="f{i}" value="{i}">"#));
    }
    let issues = find_hidden_input_issues(&html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::ExcessiveHiddenFields { count: 21 }))
    );
}

#[test]
fn exactly_twenty_not_excessive() {
    let mut html = String::new();
    for i in 0..20 {
        html.push_str(&format!(r#"<input type="hidden" name="f{i}" value="{i}">"#));
    }
    let issues = find_hidden_input_issues(&html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::ExcessiveHiddenFields { .. }))
    );
}

// --- Display ---

#[test]
fn display_debug_param() {
    let issue = HiddenInputIssue::DebugParam {
        name: "debug".into(),
    };
    assert_eq!(issue.to_string(), "debug_param:debug");
}

#[test]
fn display_token_leak() {
    let issue = HiddenInputIssue::TokenLeak { name: "jwt".into() };
    assert_eq!(issue.to_string(), "token_leak:jwt");
}

#[test]
fn display_excessive_fields() {
    let issue = HiddenInputIssue::ExcessiveHiddenFields { count: 25 };
    assert_eq!(issue.to_string(), "excessive_hidden_fields:25");
}

#[test]
fn display_all_variants() {
    let cases = vec![
        (
            HiddenInputIssue::DebugParam { name: "d".into() },
            "debug_param:d",
        ),
        (
            HiddenInputIssue::InternalId { name: "i".into() },
            "internal_id:i",
        ),
        (
            HiddenInputIssue::TokenLeak { name: "t".into() },
            "token_leak:t",
        ),
        (
            HiddenInputIssue::VersionLeak { name: "v".into() },
            "version_leak:v",
        ),
        (
            HiddenInputIssue::PasswordField { name: "p".into() },
            "password_field:p",
        ),
        (
            HiddenInputIssue::EmailLeak { name: "e".into() },
            "email_leak:e",
        ),
        (
            HiddenInputIssue::PathLeak { name: "l".into() },
            "path_leak:l",
        ),
        (
            HiddenInputIssue::SqlFragment { name: "s".into() },
            "sql_fragment:s",
        ),
        (
            HiddenInputIssue::Base64EncodedValue { name: "b".into() },
            "base64_encoded_value:b",
        ),
        (
            HiddenInputIssue::AutocompleteEnabled { name: "a".into() },
            "autocomplete_enabled:a",
        ),
        (
            HiddenInputIssue::ExcessiveHiddenFields { count: 30 },
            "excessive_hidden_fields:30",
        ),
    ];
    for (issue, expected) in cases {
        assert_eq!(issue.to_string(), expected);
    }
}

// --- Severity ---

#[test]
fn severity_token_leak_highest() {
    let issue = HiddenInputIssue::TokenLeak { name: "jwt".into() };
    assert_eq!(hidden_input_severity(&issue), 5.0);
}

#[test]
fn severity_password_field_highest() {
    let issue = HiddenInputIssue::PasswordField { name: "pw".into() };
    assert_eq!(hidden_input_severity(&issue), 5.0);
}

#[test]
fn severity_version_leak_lowest() {
    let issue = HiddenInputIssue::VersionLeak { name: "v".into() };
    assert_eq!(hidden_input_severity(&issue), 2.0);
}

#[test]
fn severity_ordering() {
    let high = hidden_input_severity(&HiddenInputIssue::TokenLeak { name: "t".into() });
    let mid = hidden_input_severity(&HiddenInputIssue::DebugParam { name: "d".into() });
    let low = hidden_input_severity(&HiddenInputIssue::VersionLeak { name: "v".into() });
    assert!(high > mid);
    assert!(mid > low);
}

// --- Operations ---

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = hidden_input_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_one_per_issue() {
    let html = concat!(
        r#"<input type="hidden" name="debug" value="1">"#,
        r#"<input type="hidden" name="version" value="1.0">"#,
    );
    let issues = find_hidden_input_issues(html);
    let mut seq = 0;
    let ops = hidden_input_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), issues.len());
    assert_eq!(seq, issues.len() as u64);
}

#[test]
fn operations_seq_increments() {
    let html = r#"<input type="hidden" name="debug" value="1">"#;
    let issues = find_hidden_input_issues(html);
    let mut seq = 5;
    let ops = hidden_input_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
}

// --- Edge cases ---

#[test]
fn non_hidden_input_ignored() {
    let html = r#"<input type="text" name="debug" value="true">"#;
    let issues = find_hidden_input_issues(html);
    assert!(issues.is_empty());
}

#[test]
fn no_name_attribute_skipped() {
    let html = r#"<input type="hidden" value="something">"#;
    let issues = find_hidden_input_issues(html);
    assert!(issues.is_empty());
}

#[test]
fn case_insensitive_type() {
    let html = r#"<INPUT TYPE="HIDDEN" NAME="debug" VALUE="true">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::DebugParam { .. }))
    );
}

#[test]
fn multiple_issues_from_one_field() {
    let html = r#"<input type="hidden" name="api_key" value="SELECT * FROM keys">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::TokenLeak { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::SqlFragment { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::AutocompleteEnabled { .. }))
    );
}

#[test]
fn password_takes_priority_over_debug() {
    let html = r#"<input type="hidden" name="admin_password" value="x">"#;
    let issues = find_hidden_input_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::PasswordField { .. }))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HiddenInputIssue::DebugParam { .. }))
    );
}

#[test]
fn empty_html_no_issues() {
    let issues = find_hidden_input_issues("");
    assert!(issues.is_empty());
}
