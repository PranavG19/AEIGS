use crate::sensitive_file_audit::*;

#[test]
fn validate_git_head_ref() {
    assert!(analyze_sensitive_file("ref: refs/heads/main\n", 0));
}

#[test]
fn validate_git_head_sha() {
    assert!(analyze_sensitive_file(
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n",
        0
    ));
}

#[test]
fn validate_git_head_rejects_html() {
    assert!(!analyze_sensitive_file("<html>404 Not Found</html>", 0));
}

#[test]
fn validate_git_head_rejects_oversized() {
    let large = "ref: refs/".to_string() + &"a".repeat(300);
    assert!(!analyze_sensitive_file(&large, 0));
}

#[test]
fn validate_env_file_with_secrets() {
    let env = "DB_HOST=localhost\nDB_PASSWORD=secret123\nAPP_PORT=3000\n";
    assert!(analyze_sensitive_file(env, 1));
}

#[test]
fn validate_env_file_rejects_html() {
    assert!(!analyze_sensitive_file("<html>Not found</html>", 1));
}

#[test]
fn validate_env_file_requires_marker() {
    let env = "FOO=bar\nBAZ=qux\n";
    assert!(!analyze_sensitive_file(env, 1));
}

#[test]
fn validate_ds_store_with_magic() {
    assert!(analyze_sensitive_file("\x00\x00\x00\x01Bud1\x00\x00", 2));
}

#[test]
fn validate_ds_store_rejects_plain_text() {
    assert!(!analyze_sensitive_file("just some text", 2));
}

#[test]
fn validate_htaccess_rewrite_rule() {
    assert!(analyze_sensitive_file(
        "RewriteEngine On\nRewriteRule ^(.*)$ /index.php",
        3
    ));
}

#[test]
fn validate_htaccess_auth() {
    assert!(analyze_sensitive_file(
        "AuthType Basic\nRequire valid-user",
        3
    ));
}

#[test]
fn validate_htaccess_rejects_html() {
    assert!(!analyze_sensitive_file("<html>404</html>", 3));
}

#[test]
fn validate_server_status_apache() {
    assert!(analyze_sensitive_file(
        "<h1>Apache Server Status for example.com</h1>",
        4
    ));
}

#[test]
fn validate_phpinfo_version() {
    assert!(analyze_sensitive_file("<h1>PHP Version 8.2.0</h1>", 5));
}

#[test]
fn validate_phpinfo_rejects_html() {
    assert!(!analyze_sensitive_file("<html>Not Found</html>", 5));
}

#[test]
fn probe_count_matches() {
    assert_eq!(probe_count(), 6);
}

#[test]
fn severity_env_highest() {
    assert!(
        sensitive_file_severity(&SensitiveFileIssue::EnvFileExposed)
            > sensitive_file_severity(&SensitiveFileIssue::GitExposed)
    );
}

#[test]
fn severity_git_higher_than_ds_store() {
    assert!(
        sensitive_file_severity(&SensitiveFileIssue::GitExposed)
            > sensitive_file_severity(&SensitiveFileIssue::DsStoreExposed)
    );
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = sensitive_file_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_created_for_issues() {
    let issues = vec![
        SensitiveFileIssue::GitExposed,
        SensitiveFileIssue::EnvFileExposed,
    ];
    let mut seq = 0;
    let ops = sensitive_file_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        SensitiveFileIssue::GitExposed.to_string(),
        "git_repo_exposed"
    );
    assert_eq!(
        SensitiveFileIssue::EnvFileExposed.to_string(),
        "env_file_exposed"
    );
    assert_eq!(
        SensitiveFileIssue::DsStoreExposed.to_string(),
        "ds_store_exposed"
    );
    assert_eq!(
        SensitiveFileIssue::HtaccessExposed.to_string(),
        "htaccess_exposed"
    );
    assert_eq!(
        SensitiveFileIssue::ServerStatusExposed.to_string(),
        "server_status_exposed"
    );
    assert_eq!(
        SensitiveFileIssue::PhpInfoExposed.to_string(),
        "phpinfo_exposed"
    );
}

#[test]
fn audit_skips_localhost() {
    let issues = audit_sensitive_files("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback() {
    let issues = audit_sensitive_files("http://127.0.0.1");
    assert!(issues.is_empty());
}

#[test]
fn invalid_probe_index_returns_false() {
    assert!(!analyze_sensitive_file("anything", 99));
}
