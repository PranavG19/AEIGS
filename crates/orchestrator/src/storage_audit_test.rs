use crate::storage_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_storage_usage("");
    assert!(issues.is_empty());
}

#[test]
fn no_storage_usage() {
    let body = "<script>var x = 'hello';</script>";
    let issues = analyze_storage_usage(body);
    assert!(issues.is_empty());
}

#[test]
fn sensitive_key_in_localstorage() {
    let body = r#"<script>localStorage.setItem("password", userPass);</script>"#;
    let issues = analyze_storage_usage(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        StorageIssue::SensitiveInLocalStorage { key } if key == "password"
    )));
}

#[test]
fn sensitive_key_in_sessionstorage() {
    let body = r#"<script>sessionStorage.setItem("api_key", key);</script>"#;
    let issues = analyze_storage_usage(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        StorageIssue::SensitiveInSessionStorage { key } if key == "api_key"
    )));
}

#[test]
fn token_in_localstorage() {
    let body = r#"<script>localStorage.setItem("access_token", tok);</script>"#;
    let issues = analyze_storage_usage(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        StorageIssue::TokenInStorage { storage_type, key }
            if storage_type == "localStorage" && key == "access_token"
    )));
}

#[test]
fn token_in_sessionstorage() {
    let body = r#"<script>sessionStorage.setItem("jwt", data.token);</script>"#;
    let issues = analyze_storage_usage(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        StorageIssue::TokenInStorage { storage_type, key }
            if storage_type == "sessionStorage" && key == "jwt"
    )));
}

#[test]
fn get_item_also_detected() {
    let body = r#"<script>var pw = localStorage.getItem("password");</script>"#;
    let issues = analyze_storage_usage(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        StorageIssue::SensitiveInLocalStorage { .. }
    )));
}

#[test]
fn bracket_access_detected() {
    let body = r#"<script>var t = localStorage["auth_token"];</script>"#;
    let issues = analyze_storage_usage(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        StorageIssue::TokenInStorage { key, .. } if key == "auth_token"
    )));
}

#[test]
fn safe_key_not_flagged() {
    let body = r#"<script>localStorage.setItem("theme", "dark");</script>"#;
    let issues = analyze_storage_usage(body);
    assert!(issues.is_empty());
}

#[test]
fn multiple_issues_detected() {
    let body = r#"<script>
        localStorage.setItem("password", pw);
        localStorage.setItem("access_token", tok);
    </script>"#;
    let issues = analyze_storage_usage(body);
    assert!(issues.len() >= 2);
}

#[test]
fn credential_pattern_detected() {
    let body = r#"<script>localStorage.setItem("password", raw);</script>"#;
    let issues = analyze_storage_usage(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        StorageIssue::RawCredentialInStorage { storage_type, .. }
            if storage_type == "localStorage"
    )));
}

#[test]
fn single_quotes_work() {
    let body = "<script>localStorage.setItem('secret', val);</script>";
    let issues = analyze_storage_usage(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        StorageIssue::SensitiveInLocalStorage { key } if key == "secret"
    )));
}

#[test]
fn severity_ordering() {
    assert!(
        storage_severity(&StorageIssue::RawCredentialInStorage {
            storage_type: "localStorage".into(),
            pattern: "password".into()
        }) > storage_severity(&StorageIssue::SensitiveInLocalStorage {
            key: "password".into()
        })
    );
    assert!(
        storage_severity(&StorageIssue::SensitiveInLocalStorage {
            key: "secret".into()
        }) > storage_severity(&StorageIssue::TokenInStorage {
            storage_type: "localStorage".into(),
            key: "token".into()
        })
    );
}

#[test]
fn to_operations_produces_entries() {
    let issues = vec![
        StorageIssue::SensitiveInLocalStorage {
            key: "password".into(),
        },
        StorageIssue::TokenInStorage {
            storage_type: "localStorage".into(),
            key: "jwt".into(),
        },
    ];
    let mut seq = 40;
    let ops = storage_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 42);
}

#[test]
fn display_variants() {
    let issue = StorageIssue::SensitiveInLocalStorage {
        key: "password".into(),
    };
    assert_eq!(issue.to_string(), "sensitive_localstorage:password");

    let issue = StorageIssue::TokenInStorage {
        storage_type: "sessionStorage".into(),
        key: "jwt".into(),
    };
    assert_eq!(issue.to_string(), "token_in_sessionStorage:jwt");
}
