use crate::comment_leak::{
    comment_leak_to_operations, find_comment_leaks, CommentLeak, LeakCategory,
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
    assert!(leaks.iter().any(|l| l.category == LeakCategory::DeveloperNote));
}

#[test]
fn detects_fixme_comment() {
    let html = r#"<html><!-- FIXME: remove before production --></html>"#;
    let leaks = find_comment_leaks(html);
    assert!(leaks.iter().any(|l| l.category == LeakCategory::DeveloperNote));
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
    assert!(leaks.iter().any(|l| l.category == LeakCategory::InternalPath));
}

#[test]
fn detects_filesystem_path() {
    let html = r#"<html><!-- Config: /etc/nginx/nginx.conf --></html>"#;
    let leaks = find_comment_leaks(html);
    assert!(leaks.iter().any(|l| l.category == LeakCategory::InternalPath));
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
    let long_comment = format!("<!-- {} -->", "a".repeat(200));
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
