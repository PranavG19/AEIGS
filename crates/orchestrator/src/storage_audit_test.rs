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
fn api_detected_localstorage() {
    let body = "<script>localStorage.setItem('key', 'value');</script>";
    let issues = analyze_storage_usage(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, StorageIssue::ApiDetected))
    );
}

#[test]
fn api_detected_sessionstorage() {
    let body = "<script>sessionStorage.setItem('key', 'value');</script>";
    let issues = analyze_storage_usage(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, StorageIssue::ApiDetected))
    );
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
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, StorageIssue::SensitiveInLocalStorage { .. }))
    );
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
    assert_eq!(issues.len(), 1);
    assert!(matches!(issues[0], StorageIssue::ApiDetected));
}

#[test]
fn multiple_issues_detected() {
    let body = r#"<script>
        localStorage.setItem("password", pw);
        localStorage.setItem("access_token", tok);
    </script>"#;
    let issues = analyze_storage_usage(body);
    assert!(issues.len() >= 3);
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
fn indexeddb_without_versioning() {
    let body = r#"<script>
        const request = indexedDB.open("mydb", 1);
        request.onsuccess = function(e) { console.log("opened"); };
    </script>"#;
    let issues = analyze_storage_usage(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, StorageIssue::IndexedDbWithoutVersioning))
    );
}

#[test]
fn indexeddb_with_versioning() {
    let body = r#"<script>
        const request = indexedDB.open("mydb", 1);
        request.onupgradeneeded = function(e) { e.target.result.createObjectStore("store"); };
    </script>"#;
    let issues = analyze_storage_usage(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, StorageIssue::IndexedDbWithoutVersioning))
    );
}

#[test]
fn cache_without_expiry() {
    let body = r#"<script>
        caches.open("v1").then(cache => cache.put(request, response));
    </script>"#;
    let issues = analyze_storage_usage(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, StorageIssue::CacheWithoutExpiry))
    );
}

#[test]
fn cache_with_expiry() {
    let body = r#"<script>
        caches.open("v1").then(cache => {
            const expires = Date.now() + 3600000;
            cache.put(request, response);
        });
    </script>"#;
    let issues = analyze_storage_usage(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, StorageIssue::CacheWithoutExpiry))
    );
}

#[test]
fn cross_tab_leakage_no_origin_check() {
    let body = r#"<script>
        window.addEventListener("storage", function(e) {
            console.log(e.key, e.newValue);
        });
    </script>"#;
    let issues = analyze_storage_usage(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, StorageIssue::CrossTabLeakage))
    );
}

#[test]
fn cross_tab_with_origin_check() {
    let body = r#"<script>
        window.addEventListener("storage", function(event) {
            if (event.origin !== window.location.origin) return;
            console.log(event.key);
        });
    </script>"#;
    let issues = analyze_storage_usage(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, StorageIssue::CrossTabLeakage))
    );
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
    assert!(
        storage_severity(&StorageIssue::CrossTabLeakage)
            > storage_severity(&StorageIssue::IndexedDbWithoutVersioning)
    );
    assert!(
        storage_severity(&StorageIssue::IndexedDbWithoutVersioning)
            > storage_severity(&StorageIssue::CacheWithoutExpiry)
    );
    assert!(
        storage_severity(&StorageIssue::CacheWithoutExpiry)
            > storage_severity(&StorageIssue::ApiDetected)
    );
}

#[test]
fn to_operations_produces_entries() {
    let issues = vec![
        StorageIssue::ApiDetected,
        StorageIssue::SensitiveInLocalStorage {
            key: "password".into(),
        },
        StorageIssue::TokenInStorage {
            storage_type: "localStorage".into(),
            key: "jwt".into(),
        },
    ];
    let mut seq = 0u64;
    let ops = storage_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn to_operations_increments_seq() {
    let issues = vec![
        StorageIssue::IndexedDbWithoutVersioning,
        StorageIssue::CacheWithoutExpiry,
    ];
    let mut seq = 10u64;
    let ops = storage_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 12);
}

#[test]
fn display_api_detected() {
    let issue = StorageIssue::ApiDetected;
    assert_eq!(issue.to_string(), "api_detected");
}

#[test]
fn display_sensitive_localstorage() {
    let issue = StorageIssue::SensitiveInLocalStorage {
        key: "password".into(),
    };
    assert_eq!(issue.to_string(), "sensitive_localstorage:password");
}

#[test]
fn display_token_in_storage() {
    let issue = StorageIssue::TokenInStorage {
        storage_type: "sessionStorage".into(),
        key: "jwt".into(),
    };
    assert_eq!(issue.to_string(), "token_in_sessionStorage:jwt");
}

#[test]
fn display_indexeddb_versioning() {
    let issue = StorageIssue::IndexedDbWithoutVersioning;
    assert_eq!(issue.to_string(), "indexeddb_no_versioning");
}

#[test]
fn display_cache_expiry() {
    let issue = StorageIssue::CacheWithoutExpiry;
    assert_eq!(issue.to_string(), "cache_no_expiry");
}

#[test]
fn display_cross_tab() {
    let issue = StorageIssue::CrossTabLeakage;
    assert_eq!(issue.to_string(), "cross_tab_leakage");
}

#[test]
fn multiple_storage_types_detected() {
    let body = r#"<script>
        localStorage.setItem("user_token", tok1);
        sessionStorage.setItem("session_token", tok2);
    </script>"#;
    let issues = analyze_storage_usage(body);
    assert!(issues.len() >= 3);
    assert!(issues.iter().any(|i| matches!(
        i,
        StorageIssue::TokenInStorage { storage_type, .. }
            if storage_type == "localStorage"
    )));
    assert!(issues.iter().any(|i| matches!(
        i,
        StorageIssue::TokenInStorage { storage_type, .. }
            if storage_type == "sessionStorage"
    )));
}

#[test]
fn extract_storage_contexts_empty() {
    let contexts = extract_storage_contexts("", "localStorage");
    assert!(contexts.is_empty());
}

#[test]
fn extract_quoted_string_double_quotes() {
    let result = extract_quoted_string(r#""mykey", value"#);
    assert_eq!(result, Some("mykey".to_string()));
}

#[test]
fn extract_quoted_string_single_quotes() {
    let result = extract_quoted_string("'mykey', value");
    assert_eq!(result, Some("mykey".to_string()));
}

#[test]
fn extract_quoted_string_no_quotes() {
    let result = extract_quoted_string("mykey, value");
    assert_eq!(result, None);
}
