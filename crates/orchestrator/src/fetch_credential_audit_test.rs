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

// --- New variant tests ---

#[test]
fn hardcoded_bearer_token_authorization_header() {
    let body = r#"<script>
        fetch("/api", {headers: {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9"}});
    </script>"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::HardcodedBearerToken)
    );
}

#[test]
fn hardcoded_bearer_token_lowercase() {
    let body = r#"headers["authorization"] = "bearer eyJhbGciOiJ";"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::HardcodedBearerToken)
    );
}

#[test]
fn hardcoded_bearer_token_json_style() {
    let body = r#"{"authorization":"Bearer eyABCDEF"}"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::HardcodedBearerToken)
    );
}

#[test]
fn no_bearer_token_in_safe_code() {
    let body = r#"<script>var msg = "Please authorize your account";</script>"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        !issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::HardcodedBearerToken)
    );
}

#[test]
fn hardcoded_password_double_quotes() {
    let body = r#"var creds = {"password":"s3cret123"};"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::HardcodedPassword { .. }))
    );
}

#[test]
fn hardcoded_password_single_quotes() {
    let body = "var creds = {'passwd':'hunter2'};";
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::HardcodedPassword { .. }))
    );
}

#[test]
fn hardcoded_password_with_space() {
    let body = r#"var creds = {"password": "s3cret123"};"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::HardcodedPassword { .. }))
    );
}

#[test]
fn no_hardcoded_password_in_label() {
    let body = r#"<label>Password</label><input type="password" />"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::HardcodedPassword { .. }))
    );
}

#[test]
fn credentials_in_url_http() {
    let body = r#"fetch("http://admin:pass123@internal.corp/api");"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::CredentialsInUrl { .. }))
    );
}

#[test]
fn credentials_in_url_https() {
    let body = r#"var url = "https://user:secret@example.com/data";"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::CredentialsInUrl { .. }))
    );
}

#[test]
fn no_credentials_in_url_without_password() {
    let body = r#"fetch("https://example.com/api");"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::CredentialsInUrl { .. }))
    );
}

#[test]
fn insecure_fetch_http_detected() {
    let body = r#"fetch("http://api.example.com/data");"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::InsecureFetchHttp { .. }))
    );
}

#[test]
fn insecure_fetch_http_single_quotes() {
    let body = "fetch('http://api.example.com/data');";
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::InsecureFetchHttp { .. }))
    );
}

#[test]
fn insecure_fetch_http_template_literal() {
    let body = "fetch(`http://api.example.com/data`);";
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::InsecureFetchHttp { .. }))
    );
}

#[test]
fn secure_fetch_https_not_flagged() {
    let body = r#"fetch("https://api.example.com/data");"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::InsecureFetchHttp { .. }))
    );
}

#[test]
fn storage_credential_access_localstorage_token() {
    let body = r#"var t = localStorage.getItem("token");"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::StorageCredentialAccess { .. }))
    );
}

#[test]
fn storage_credential_access_sessionstorage_auth() {
    let body = "var a = sessionStorage.getItem('auth');";
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::StorageCredentialAccess { .. }))
    );
}

#[test]
fn storage_access_non_credential_key_not_flagged() {
    let body = r#"var x = localStorage.getItem("theme");"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::StorageCredentialAccess { .. }))
    );
}

#[test]
fn postmessage_credentials_detected() {
    let body = r#"window.parent.postMessage({token: authToken}, "*");"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::PostMessageCredentials)
    );
}

#[test]
fn postmessage_safe_data_not_flagged() {
    let body = r#"window.parent.postMessage({type: "resize", height: 500}, "*");"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        !issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::PostMessageCredentials)
    );
}

#[test]
fn eval_with_credentials_detected() {
    let body = r#"var token = getToken(); eval(token + ".payload");"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::EvalWithCredentials)
    );
}

#[test]
fn eval_without_credentials_not_flagged() {
    let body = r#"var x = 42; eval("console.log(x)");"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        !issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::EvalWithCredentials)
    );
}

// --- Display tests for new variants ---

#[test]
fn display_hardcoded_bearer_token() {
    assert_eq!(
        FetchCredentialIssue::HardcodedBearerToken.to_string(),
        "hardcoded_bearer_token"
    );
}

#[test]
fn display_hardcoded_password() {
    assert_eq!(
        FetchCredentialIssue::HardcodedPassword {
            context: "password".into()
        }
        .to_string(),
        "hardcoded_password:password"
    );
}

#[test]
fn display_credentials_in_url() {
    assert_eq!(
        FetchCredentialIssue::CredentialsInUrl {
            url: "http://u:p@host".into()
        }
        .to_string(),
        "credentials_in_url:http://u:p@host"
    );
}

#[test]
fn display_insecure_fetch_http() {
    assert_eq!(
        FetchCredentialIssue::InsecureFetchHttp {
            url: "http://api.local".into()
        }
        .to_string(),
        "insecure_fetch_http:http://api.local"
    );
}

#[test]
fn display_storage_credential_access() {
    assert_eq!(
        FetchCredentialIssue::StorageCredentialAccess {
            storage_type: "localStorage".into()
        }
        .to_string(),
        "storage_credential_access:localStorage"
    );
}

#[test]
fn display_postmessage_credentials() {
    assert_eq!(
        FetchCredentialIssue::PostMessageCredentials.to_string(),
        "postmessage_credentials"
    );
}

#[test]
fn display_eval_with_credentials() {
    assert_eq!(
        FetchCredentialIssue::EvalWithCredentials.to_string(),
        "eval_with_credentials"
    );
}

// --- Severity tests for new variants ---

#[test]
fn severity_hardcoded_password_highest() {
    assert!(
        fetch_credential_severity(&FetchCredentialIssue::HardcodedPassword {
            context: "password".into()
        }) > fetch_credential_severity(&FetchCredentialIssue::HardcodedBearerToken)
    );
}

#[test]
fn severity_bearer_above_api_key() {
    assert!(
        fetch_credential_severity(&FetchCredentialIssue::HardcodedBearerToken)
            > fetch_credential_severity(&FetchCredentialIssue::HardcodedApiKey {
                pattern: "apiKey".into()
            })
    );
}

#[test]
fn severity_credentials_in_url_above_cross_origin() {
    assert!(
        fetch_credential_severity(&FetchCredentialIssue::CredentialsInUrl {
            url: "http://u:p@h".into()
        }) > fetch_credential_severity(&FetchCredentialIssue::CrossOriginCredentials {
            url: "https://x.com".into()
        })
    );
}

#[test]
fn severity_eval_above_insecure_fetch() {
    assert!(
        fetch_credential_severity(&FetchCredentialIssue::EvalWithCredentials)
            > fetch_credential_severity(&FetchCredentialIssue::InsecureFetchHttp {
                url: "http://x".into()
            })
    );
}

// --- to_operations tests for new variants ---

#[test]
fn to_operations_all_new_variants() {
    let issues = vec![
        FetchCredentialIssue::HardcodedBearerToken,
        FetchCredentialIssue::HardcodedPassword {
            context: "password".into(),
        },
        FetchCredentialIssue::CredentialsInUrl {
            url: "http://u:p@h".into(),
        },
        FetchCredentialIssue::InsecureFetchHttp {
            url: "http://api.local".into(),
        },
        FetchCredentialIssue::StorageCredentialAccess {
            storage_type: "localStorage".into(),
        },
        FetchCredentialIssue::PostMessageCredentials,
        FetchCredentialIssue::EvalWithCredentials,
    ];
    let mut seq = 0;
    let ops = fetch_credential_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 7);
    assert_eq!(seq, 7);
}

#[test]
fn to_operations_empty_issues() {
    let mut seq = 10;
    let ops = fetch_credential_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 10);
}

#[test]
fn to_operations_seq_increments_correctly() {
    let issues = vec![
        FetchCredentialIssue::CredentialsInclude,
        FetchCredentialIssue::HardcodedBearerToken,
        FetchCredentialIssue::PostMessageCredentials,
    ];
    let mut seq = 50;
    let ops = fetch_credential_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 53);
}

// --- Edge cases ---

#[test]
fn minified_js_credentials_include() {
    let body = r#"fetch("/a",{credentials:"include",mode:"cors"})"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::CredentialsInclude)
    );
}

#[test]
fn minified_js_xhr_credentials() {
    let body = "x.withCredentials=true;x.open('GET','/a')";
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::XhrWithCredentials)
    );
}

#[test]
fn multiple_issues_in_single_body() {
    let body = r#"<script>
        fetch("/api", {credentials: "include"});
        xhr.withCredentials = true;
        var config = {apiKey":"sk-12345"};
        fetch("http://api.local/data");
        localStorage.getItem("token");
    </script>"#;
    let issues = analyze_fetch_credentials(body);
    assert!(issues.len() >= 4);
    assert!(
        issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::CredentialsInclude)
    );
    assert!(
        issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::XhrWithCredentials)
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::HardcodedApiKey { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::StorageCredentialAccess { .. }))
    );
}

#[test]
fn safe_code_produces_no_issues() {
    let body = r#"<script>
        fetch("/api/users").then(r => r.json()).then(data => {
            document.getElementById("users").innerHTML = data.length;
        });
        var config = {theme: "dark", lang: "en"};
        localStorage.setItem("theme", "dark");
    </script>"#;
    let issues = analyze_fetch_credentials(body);
    assert!(issues.is_empty());
}

#[test]
fn bearer_token_in_single_quotes_json() {
    let body = "{'authorization': 'Bearer eyJhbGciOi'}";
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::HardcodedBearerToken)
    );
}

#[test]
fn postmessage_with_password_keyword() {
    let body = r#"iframe.contentWindow.postMessage({password: userPwd}, origin);"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::PostMessageCredentials)
    );
}

#[test]
fn eval_near_api_key_reference() {
    let body = r#"var apiKey = getKey(); eval(buildQuery(apiKey));"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| *i == FetchCredentialIssue::EvalWithCredentials)
    );
}

#[test]
fn storage_credential_jwt_key() {
    let body = r#"var jwt = sessionStorage.getItem("jwt");"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::StorageCredentialAccess { .. }))
    );
}

#[test]
fn credentials_in_url_no_at_sign_safe() {
    let body = r#"fetch("http://example.com:8080/api");"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::CredentialsInUrl { .. }))
    );
}

#[test]
fn cross_origin_credentials_url() {
    let body = r#"fetch("https://other.com/api", {credentials: "include"})"#;
    let issues = analyze_fetch_credentials(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, FetchCredentialIssue::CrossOriginCredentials { .. }))
    );
}
