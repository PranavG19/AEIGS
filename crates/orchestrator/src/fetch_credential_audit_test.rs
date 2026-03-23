use crate::fetch_credential_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_fetch_credentials("");
    assert!(issues.is_empty());
}

#[test]
fn normal_fetch_no_credentials() {
    let body = r#"<script>fetch("/api/data").then(r => r.json());</script>"#;
    let issues = analyze_fetch_credentials(body);
    assert!(issues.is_empty());
}

#[test]
fn credentials_include_double_quotes() {
    let body = r#"<script>fetch("/api", {credentials: "include"});</script>"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::CredentialsInclude)
    );
}

#[test]
fn credentials_include_single_quotes() {
    let body = "<script>fetch('/api', {credentials: 'include'});</script>";
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::CredentialsInclude)
    );
}

#[test]
fn credentials_same_origin_not_flagged() {
    let body = r#"<script>fetch("/api", {credentials: "same-origin"});</script>"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        !issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::CredentialsInclude)
    );
}

#[test]
fn xhr_with_credentials_detected() {
    let body = r#"<script>
        var xhr = new XMLHttpRequest();
        xhr.withCredentials = true;
        xhr.open("GET", "/api");
    </script>"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::XhrWithCredentials)
    );
}

#[test]
fn xhr_without_credentials_not_flagged() {
    let body = r#"<script>
        var xhr = new XMLHttpRequest();
        xhr.open("GET", "/api");
    </script>"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        !issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::XhrWithCredentials)
    );
}

#[test]
fn hardcoded_api_key_detected() {
    let body = r#"<script>var config = {apiKey":"sk-1234567890abcdef"};</script>"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::HardcodedApiKey { .. }))
    );
}

#[test]
fn no_hardcoded_key_in_normal_code() {
    let body = r#"<script>var x = {name: "test", value: 42};</script>"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::HardcodedApiKey { .. }))
    );
}

#[test]
fn severity_ordering() {
    assert!(
        fetch_credential_severity(&FetchCredentialIssue::HardcodedApiKey {
            pattern: "apiKey".into()
        }) > fetch_credential_severity(&FetchCredentialIssue::CrossOriginCredentials {
            url: "https://x.com".into()
        })
    );
    assert!(
        fetch_credential_severity(&FetchCredentialIssue::CrossOriginCredentials {
            url: "https://x.com".into()
        }) > fetch_credential_severity(&FetchCredentialIssue::CredentialsInclude)
    );
}

#[test]
fn to_operations_produces_entries() {
    let issues = vec![
        FetchCredentialIssue::CredentialsInclude,
        FetchCredentialIssue::HardcodedApiKey {
            pattern: "apiKey".into(),
        },
    ];
    let mut seq = 80;
    let ops = fetch_credential_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 82);
}

#[test]
fn display_variants() {
    assert_eq!(
        FetchCredentialIssue::CredentialsInclude.to_string(),
        "fetch_credentials_include"
    );
    assert_eq!(
        FetchCredentialIssue::XhrWithCredentials.to_string(),
        "xhr_with_credentials"
    );
    assert_eq!(
        FetchCredentialIssue::HardcodedApiKey {
            pattern: "apiKey".into()
        }
        .to_string(),
        "hardcoded_api_key:apiKey"
    );
}
