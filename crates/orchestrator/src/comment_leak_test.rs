use crate::comment_leak::{
    CommentLeak, CommentLeakSecurityIssue, LeakCategory, analyze_comment_security,
    comment_leak_to_operations, comment_security_severity, comment_security_to_operations,
    find_comment_leaks,
};

#[test]
fn detects_password_in_comment() {
    let html = r#"<html><!-- password: hunter2 --><body></body></html>"#;
    let leaks = find_comment_leaks(html);
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].category, LeakCategory::Credential);
}

#[test]
fn detects_api_key_in_comment() {
    let html = r#"<html><!-- api_key=abc123def456 --></html>"#;
    let leaks = find_comment_leaks(html);
    assert!(leaks.iter().any(|l| l.category == LeakCategory::Credential));
}

#[test]
fn detects_todo_comment() {
    let html = r#"<html><!-- TODO: fix this vulnerability --></html>"#;
    let leaks = find_comment_leaks(html);
    assert!(
        leaks
            .iter()
            .any(|l| l.category == LeakCategory::DeveloperNote)
    );
}

#[test]
fn detects_fixme_comment() {
    let html = r#"<html><!-- FIXME: remove before production --></html>"#;
    let leaks = find_comment_leaks(html);
    assert!(
        leaks
            .iter()
            .any(|l| l.category == LeakCategory::DeveloperNote)
    );
}

#[test]
fn detects_debug_info() {
    let html = r#"<html><!-- debug mode enabled --></html>"#;
    let leaks = find_comment_leaks(html);
    assert!(leaks.iter().any(|l| l.category == LeakCategory::DebugInfo));
}

#[test]
fn detects_internal_ip() {
    let html = r#"<html><!-- Backend: 192.168.1.100:8080 --></html>"#;
    let leaks = find_comment_leaks(html);
    assert!(
        leaks
            .iter()
            .any(|l| l.category == LeakCategory::InternalPath)
    );
}

#[test]
fn detects_filesystem_path() {
    let html = r#"<html><!-- Config: /etc/nginx/nginx.conf --></html>"#;
    let leaks = find_comment_leaks(html);
    assert!(
        leaks
            .iter()
            .any(|l| l.category == LeakCategory::InternalPath)
    );
}

#[test]
fn ignores_benign_comments() {
    let html = r#"<html><!-- This is the main page --></html>"#;
    let leaks = find_comment_leaks(html);
    assert!(leaks.is_empty());
}

#[test]
fn no_leaks_in_commentless_html() {
    let html = r#"<html><body><p>Hello world</p></body></html>"#;
    let leaks = find_comment_leaks(html);
    assert!(leaks.is_empty());
}

#[test]
fn truncates_long_snippets() {
    let leaks = find_comment_leaks(&format!("<!-- TODO: {} -->", "a".repeat(200)));
    assert!(!leaks.is_empty());
    assert!(leaks[0].snippet.len() <= 83); // 80 + "..."
}

#[test]
fn multiple_comments_multiple_leaks() {
    let html = r#"
        <!-- password: secret -->
        <p>content</p>
        <!-- TODO: fix auth -->
    "#;
    let leaks = find_comment_leaks(html);
    assert!(leaks.len() >= 2);
}

#[test]
fn deduplicates_categories_within_comment() {
    let html = r#"<!-- secret api_key token -->"#;
    let leaks = find_comment_leaks(html);
    let cred_count = leaks
        .iter()
        .filter(|l| l.category == LeakCategory::Credential)
        .count();
    assert_eq!(cred_count, 1);
}

#[test]
fn operations_empty_when_no_leaks() {
    let mut seq = 0;
    let ops = comment_leak_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_high_severity_for_credentials() {
    let leaks = vec![CommentLeak {
        category: LeakCategory::Credential,
        snippet: "password: test".to_string(),
    }];
    let mut seq = 0;
    let ops = comment_leak_to_operations(&leaks, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn display_categories() {
    assert_eq!(LeakCategory::Credential.to_string(), "credential");
    assert_eq!(LeakCategory::DeveloperNote.to_string(), "developer_note");
    assert_eq!(LeakCategory::DebugInfo.to_string(), "debug_info");
    assert_eq!(LeakCategory::InternalPath.to_string(), "internal_path");
    assert_eq!(LeakCategory::VersionInfo.to_string(), "version_info");
}

#[test]
fn detects_todo_with_credentials() {
    let html = r#"<!-- TODO: remove hardcoded password before deploy -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::TodoWithCredentials { .. }))
    );
}

#[test]
fn detects_fixme_with_secret() {
    let html = r#"<!-- FIXME: secret key needs rotation -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::TodoWithCredentials { .. }))
    );
}

#[test]
fn ignores_todo_without_credentials() {
    let html = r#"<!-- TODO: update documentation -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::TodoWithCredentials { .. }))
    );
}

#[test]
fn detects_select_query() {
    let html = r#"<!-- select * from users where id=1 -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::SqlQueryInComment { .. }))
    );
}

#[test]
fn detects_insert_query() {
    let html = r#"<!-- insert into logs values ('test') -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::SqlQueryInComment { .. }))
    );
}

#[test]
fn detects_update_query() {
    let html = r#"<!-- update users set active=1 -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::SqlQueryInComment { .. }))
    );
}

#[test]
fn detects_delete_query() {
    let html = r#"<!-- delete from sessions where expired -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::SqlQueryInComment { .. }))
    );
}

#[test]
fn detects_localhost_url() {
    let html = r#"<!-- API endpoint: localhost:8080/api -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::InternalUrlInComment { .. }))
    );
}

#[test]
fn detects_127_0_0_1_url() {
    let html = r#"<!-- Backend: 127.0.0.1:3000 -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::InternalUrlInComment { .. }))
    );
}

#[test]
fn detects_192_168_ip() {
    let html = r#"<!-- Server: 192.168.1.50 -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::InternalUrlInComment { .. }))
    );
}

#[test]
fn detects_10_0_network() {
    let html = r#"<!-- Internal: 10.0.2.15:9000 -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::InternalUrlInComment { .. }))
    );
}

#[test]
fn detects_debug_true() {
    let html = r#"<!-- debug=true for testing -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::DebugFlagInComment { .. }))
    );
}

#[test]
fn detects_debug_mode_true() {
    let html = r#"<!-- debug_mode=true -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::DebugFlagInComment { .. }))
    );
}

#[test]
fn detects_verbose_true() {
    let html = r#"<!-- verbose=true for diagnostics -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::DebugFlagInComment { .. }))
    );
}

#[test]
fn detects_api_key_equals() {
    let html = r#"<!-- api_key=sk_live_123abc456def -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::ApiKeyInComment { .. }))
    );
}

#[test]
fn detects_api_key_colon() {
    let html = r#"<!-- api-key: abc123xyz789 -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::ApiKeyInComment { .. }))
    );
}

#[test]
fn detects_access_key() {
    let html = r#"<!-- access_key=AKIAIOSFODNN7EXAMPLE -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::ApiKeyInComment { .. }))
    );
}

#[test]
fn detects_secret_key() {
    let html = r#"<!-- secret_key: wJalrXUtnFEMI/K7MDENG -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::ApiKeyInComment { .. }))
    );
}

#[test]
fn detects_version_with_label() {
    let html = r#"<!-- version: 2.3.4 -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::VersionInfoInComment { .. }))
    );
}

#[test]
fn detects_version_pattern() {
    let html = r#"<!-- Build v1.2.3 deployed -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::VersionInfoInComment { .. }))
    );
}

#[test]
fn detects_numeric_version() {
    let html = r#"<!-- App 3.14.159 -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::VersionInfoInComment { .. }))
    );
}

#[test]
fn detects_java_stack_trace() {
    let html = r#"<!-- Exception at com.example.Controller.java:42 -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::StackTraceInComment { .. }))
    );
}

#[test]
fn detects_python_traceback() {
    let html = r#"<!-- Traceback (most recent call last): -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::StackTraceInComment { .. }))
    );
}

#[test]
fn detects_at_keyword() {
    let html = r#"<!--     at Object.<anonymous> (app.js:15) -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::StackTraceInComment { .. }))
    );
}

#[test]
fn detects_python_file_line() {
    let html = r#"<!-- File "views.py", line 123, in handle_request -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::StackTraceInComment { .. }))
    );
}

#[test]
fn detects_ie_if_conditional() {
    let html = r#"<!--[if lt IE 9]><script src="shim.js"></script><![endif]-->"#;
    let issues = analyze_comment_security(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        CommentLeakSecurityIssue::ConditionalCommentIeBypass { .. }
    )));
}

#[test]
fn detects_ie_endif() {
    let html = r#"<!--[endif]-->"#;
    let issues = analyze_comment_security(html);
    assert!(issues.iter().any(|i| matches!(
        i,
        CommentLeakSecurityIssue::ConditionalCommentIeBypass { .. }
    )));
}

#[test]
fn detects_var_path() {
    let html = r#"<!-- Config: /var/www/config.ini -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::ServerPathInComment { .. }))
    );
}

#[test]
fn detects_etc_path() {
    let html = r#"<!-- Load from /etc/nginx/sites-enabled/ -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::ServerPathInComment { .. }))
    );
}

#[test]
fn detects_usr_path() {
    let html = r#"<!-- Binary: /usr/local/bin/app -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::ServerPathInComment { .. }))
    );
}

#[test]
fn detects_windows_c_drive() {
    let html = r#"<!-- Path: C:\Program Files\App\config.xml -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::ServerPathInComment { .. }))
    );
}

#[test]
fn detects_author_tag() {
    let html = r#"<!-- @author John Doe -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::DeveloperNoteInComment { .. }))
    );
}

#[test]
fn detects_by_author() {
    let html = r#"<!-- written by Jane Smith -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::DeveloperNoteInComment { .. }))
    );
}

#[test]
fn detects_author_with_email() {
    let html = r#"<!-- @author bob.builder@example.com -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::DeveloperNoteInComment { .. }))
    );
}

#[test]
fn ignores_short_author_name() {
    let html = r#"<!-- @author AB -->"#;
    let issues = analyze_comment_security(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CommentLeakSecurityIssue::DeveloperNoteInComment { .. }))
    );
}

#[test]
fn security_issues_empty_for_benign_comment() {
    let html = r#"<!-- This is a regular comment -->"#;
    let issues = analyze_comment_security(html);
    assert!(issues.is_empty());
}

#[test]
fn security_issues_empty_for_no_comments() {
    let html = r#"<html><body>No comments here</body></html>"#;
    let issues = analyze_comment_security(html);
    assert!(issues.is_empty());
}

#[test]
fn severity_api_key_highest() {
    let issue = CommentLeakSecurityIssue::ApiKeyInComment {
        snippet: "test".to_string(),
    };
    assert_eq!(comment_security_severity(&issue), 8.0);
}

#[test]
fn severity_todo_credentials_high() {
    let issue = CommentLeakSecurityIssue::TodoWithCredentials {
        snippet: "test".to_string(),
    };
    assert_eq!(comment_security_severity(&issue), 7.5);
}

#[test]
fn severity_sql_query_medium_high() {
    let issue = CommentLeakSecurityIssue::SqlQueryInComment {
        snippet: "test".to_string(),
    };
    assert_eq!(comment_security_severity(&issue), 6.5);
}

#[test]
fn severity_developer_note_low() {
    let issue = CommentLeakSecurityIssue::DeveloperNoteInComment {
        name: "Test".to_string(),
        snippet: "test".to_string(),
    };
    assert_eq!(comment_security_severity(&issue), 3.0);
}

#[test]
fn operations_empty_for_no_issues() {
    let mut seq = 0;
    let ops = comment_security_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_creates_entries_for_issues() {
    let issues = vec![
        CommentLeakSecurityIssue::ApiKeyInComment {
            snippet: "key123".to_string(),
        },
        CommentLeakSecurityIssue::SqlQueryInComment {
            snippet: "select *".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = comment_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_todo_credentials() {
    let issue = CommentLeakSecurityIssue::TodoWithCredentials {
        snippet: "fix pass".to_string(),
    };
    assert!(issue.to_string().contains("todo_with_credentials"));
}

#[test]
fn display_sql_query() {
    let issue = CommentLeakSecurityIssue::SqlQueryInComment {
        snippet: "select".to_string(),
    };
    assert!(issue.to_string().contains("sql_query"));
}

#[test]
fn display_internal_url() {
    let issue = CommentLeakSecurityIssue::InternalUrlInComment {
        url: "localhost".to_string(),
    };
    assert!(issue.to_string().contains("internal_url"));
}

#[test]
fn multiple_issues_in_single_comment() {
    let html = r#"<!-- TODO: password in /var/config api_key=abc123 select * from users -->"#;
    let issues = analyze_comment_security(html);
    assert!(issues.len() >= 3);
}

#[test]
fn multiple_comments_with_issues() {
    let html = r#"
        <!-- api_key=test123 -->
        <p>content</p>
        <!-- select * from logs -->
        <p>more</p>
        <!-- localhost:8080 -->
    "#;
    let issues = analyze_comment_security(html);
    assert!(issues.len() >= 3);
}
