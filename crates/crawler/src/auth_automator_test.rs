use std::collections::HashMap;

use crate::auth_automator::*;

#[test]
fn detect_simple_login_form() {
    let html = r#"
        <form action="/login" method="POST" id="login-form">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <button type="submit" id="login-btn">Login</button>
        </form>
    "#;

    let forms = detect_login_forms(html);
    assert_eq!(forms.len(), 1);
    assert_eq!(forms[0].action_url, "/login");
    assert_eq!(forms[0].method, "POST");
    assert_eq!(forms[0].username_field, "username");
    assert_eq!(forms[0].password_field, "password");
}

#[test]
fn detect_login_form_with_email() {
    let html = r#"
        <form action="/auth/login" method="POST">
            <input type="email" name="email" />
            <input type="password" name="passwd" />
            <button type="submit">Sign In</button>
        </form>
    "#;

    let forms = detect_login_forms(html);
    assert_eq!(forms.len(), 1);
    assert_eq!(forms[0].username_field, "email");
    assert_eq!(forms[0].password_field, "passwd");
}

#[test]
fn detect_login_form_with_csrf() {
    let html = r#"
        <form action="/login" method="POST">
            <input type="hidden" name="csrf_token" value="abc123" />
            <input type="text" name="user" />
            <input type="password" name="pass" />
        </form>
    "#;

    let forms = detect_login_forms(html);
    assert_eq!(forms.len(), 1);
    assert_eq!(forms[0].csrf_token_field.as_deref(), Some("csrf_token"));
    assert_eq!(forms[0].extra_fields.get("csrf_token").unwrap(), "abc123");
}

#[test]
fn no_login_form_without_password() {
    let html = r#"
        <form action="/search" method="GET">
            <input type="text" name="q" />
            <button type="submit">Search</button>
        </form>
    "#;

    let forms = detect_login_forms(html);
    assert!(forms.is_empty());
}

#[test]
fn detect_http_basic_from_headers() {
    let mut headers = HashMap::new();
    headers.insert(
        "www-authenticate".to_string(),
        "Basic realm=\"admin\"".to_string(),
    );
    assert_eq!(detect_auth_type_from_headers(&headers), AuthType::HttpBasic);
}

#[test]
fn detect_http_digest_from_headers() {
    let mut headers = HashMap::new();
    headers.insert(
        "www-authenticate".to_string(),
        "Digest realm=\"test\", nonce=\"abc\"".to_string(),
    );
    assert_eq!(
        detect_auth_type_from_headers(&headers),
        AuthType::HttpDigest
    );
}

#[test]
fn detect_bearer_from_headers() {
    let mut headers = HashMap::new();
    headers.insert(
        "www-authenticate".to_string(),
        "Bearer realm=\"api\"".to_string(),
    );
    assert_eq!(detect_auth_type_from_headers(&headers), AuthType::Bearer);
}

#[test]
fn detect_oauth_redirect_from_location() {
    let mut headers = HashMap::new();
    headers.insert(
        "location".to_string(),
        "https://auth.example.com/oauth/authorize?client_id=abc".to_string(),
    );
    assert_eq!(
        detect_auth_type_from_headers(&headers),
        AuthType::OAuthRedirect
    );
}

#[test]
fn detect_saml_from_location() {
    let mut headers = HashMap::new();
    headers.insert(
        "location".to_string(),
        "https://idp.example.com/saml/login".to_string(),
    );
    assert_eq!(detect_auth_type_from_headers(&headers), AuthType::Saml);
}

#[test]
fn detect_form_based_from_html() {
    let html = r#"
        <form action="/login" method="POST">
            <input type="text" name="user" />
            <input type="password" name="pass" />
        </form>
    "#;
    assert_eq!(detect_auth_type_from_html(html), AuthType::FormBased);
}

#[test]
fn detect_oauth_from_html() {
    let html =
        r#"<a href="https://provider.com/oauth/authorize?client_id=xyz">Login with OAuth</a>"#;
    assert_eq!(detect_auth_type_from_html(html), AuthType::OAuthRedirect);
}

#[test]
fn detect_jwt_from_html() {
    let html = r#"<script>const jwt = require('jsonwebtoken');</script>"#;
    assert_eq!(detect_auth_type_from_html(html), AuthType::Jwt);
}

#[test]
fn session_expired_on_401() {
    let config = AuthConfig::default();
    assert!(is_session_expired("Unauthorized", 401, &config));
}

#[test]
fn session_expired_on_403() {
    let config = AuthConfig::default();
    assert!(is_session_expired("Forbidden", 403, &config));
}

#[test]
fn session_expired_on_logout_indicator() {
    let config = AuthConfig::default();
    assert!(is_session_expired(
        "Your session expired. Please login again.",
        200,
        &config
    ));
}

#[test]
fn session_not_expired_on_normal_response() {
    let config = AuthConfig::default();
    assert!(!is_session_expired(
        "Welcome to the dashboard",
        200,
        &config
    ));
}

#[test]
fn build_bearer_auth_headers() {
    let session = AuthSession {
        role: "admin".to_string(),
        auth_type: AuthType::Bearer,
        cookies: HashMap::new(),
        headers: HashMap::new(),
        token: Some("abc123token".to_string()),
        refresh_token: None,
        expires_at_ms: None,
        is_valid: true,
    };

    let headers = build_auth_headers(&session);
    assert_eq!(headers.get("Authorization").unwrap(), "Bearer abc123token");
}

#[test]
fn build_api_key_auth_headers() {
    let session = AuthSession {
        role: "service".to_string(),
        auth_type: AuthType::ApiKey,
        cookies: HashMap::new(),
        headers: HashMap::new(),
        token: Some("sk-myapikey123".to_string()),
        refresh_token: None,
        expires_at_ms: None,
        is_valid: true,
    };

    let headers = build_auth_headers(&session);
    assert_eq!(headers.get("X-API-Key").unwrap(), "sk-myapikey123");
}

#[test]
fn build_cookie_auth_headers() {
    let mut cookies = HashMap::new();
    cookies.insert("session_id".to_string(), "xyz789".to_string());
    cookies.insert("csrf".to_string(), "token123".to_string());

    let session = AuthSession {
        role: "user".to_string(),
        auth_type: AuthType::Cookie,
        cookies,
        headers: HashMap::new(),
        token: None,
        refresh_token: None,
        expires_at_ms: None,
        is_valid: true,
    };

    let headers = build_auth_headers(&session);
    let cookie_header = headers.get("Cookie").unwrap();
    assert!(cookie_header.contains("session_id=xyz789"));
    assert!(cookie_header.contains("csrf=token123"));
}

#[test]
fn build_cookie_header_from_session() {
    let mut cookies = HashMap::new();
    cookies.insert("sid".to_string(), "abc".to_string());

    let session = AuthSession {
        role: "user".to_string(),
        auth_type: AuthType::Cookie,
        cookies,
        headers: HashMap::new(),
        token: None,
        refresh_token: None,
        expires_at_ms: None,
        is_valid: true,
    };

    let header = build_cookie_header(&session);
    assert!(header.is_some());
    assert!(header.unwrap().contains("sid=abc"));
}

#[test]
fn build_cookie_header_empty_when_no_cookies() {
    let session = AuthSession {
        role: "user".to_string(),
        auth_type: AuthType::Cookie,
        cookies: HashMap::new(),
        headers: HashMap::new(),
        token: None,
        refresh_token: None,
        expires_at_ms: None,
        is_valid: true,
    };

    assert!(build_cookie_header(&session).is_none());
}

#[test]
fn parse_set_cookie_headers() {
    let headers = vec![
        "session_id=abc123; Path=/; HttpOnly".to_string(),
        "csrf_token=xyz789; Path=/; Secure".to_string(),
    ];

    let cookies = parse_set_cookies(&headers);
    assert_eq!(cookies.get("session_id").unwrap(), "abc123");
    assert_eq!(cookies.get("csrf_token").unwrap(), "xyz789");
}

#[test]
fn session_expiry_check() {
    let session = AuthSession {
        role: "user".to_string(),
        auth_type: AuthType::Jwt,
        cookies: HashMap::new(),
        headers: HashMap::new(),
        token: None,
        refresh_token: None,
        expires_at_ms: Some(1700000000000),
        is_valid: true,
    };

    assert!(!session.is_expired(1699999999000));
    assert!(session.is_expired(1700000000000));
    assert!(session.is_expired(1700000001000));
}

#[test]
fn session_needs_refresh_within_five_minutes() {
    let session = AuthSession {
        role: "user".to_string(),
        auth_type: AuthType::Jwt,
        cookies: HashMap::new(),
        headers: HashMap::new(),
        token: None,
        refresh_token: Some("refresh_tok".to_string()),
        expires_at_ms: Some(1700000300000),
        is_valid: true,
    };

    assert!(!session.needs_refresh(1699999000000));
    assert!(session.needs_refresh(1700000000001));
}

#[test]
fn extract_jwt_expiry_from_token() {
    // Header: {"alg":"HS256","typ":"JWT"}
    // Payload: {"sub":"1234567890","exp":1700000000}
    // This is a valid JWT structure (signature doesn't matter for parsing)
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNzAwMDAwMDAwfQ.signature";
    let expiry = extract_jwt_expiry(token);
    assert_eq!(expiry, Some(1700000000000));
}

#[test]
fn extract_jwt_expiry_returns_none_for_invalid() {
    assert_eq!(extract_jwt_expiry("not-a-jwt"), None);
    assert_eq!(extract_jwt_expiry("a.b"), None);
}

#[test]
fn auth_config_builder() {
    let config = AuthConfig::default()
        .with_role("admin", "admin_user", "admin_pass")
        .with_role("user", "regular_user", "user_pass")
        .with_session_check_url("/api/me")
        .with_max_login_attempts(5);

    assert_eq!(config.credentials.len(), 2);
    assert_eq!(config.credentials[0].role, "admin");
    assert_eq!(config.credentials[1].username, "regular_user");
    assert_eq!(config.session_check_url.as_deref(), Some("/api/me"));
    assert_eq!(config.max_login_attempts, 5);
}

#[test]
fn auth_type_as_str() {
    assert_eq!(AuthType::FormBased.as_str(), "Form-Based");
    assert_eq!(AuthType::HttpBasic.as_str(), "HTTP Basic");
    assert_eq!(AuthType::OAuthRedirect.as_str(), "OAuth Redirect");
    assert_eq!(AuthType::Jwt.as_str(), "JWT");
    assert_eq!(AuthType::ApiKey.as_str(), "API Key");
    assert_eq!(AuthType::Bearer.as_str(), "Bearer Token");
    assert_eq!(AuthType::Saml.as_str(), "SAML");
    assert_eq!(AuthType::OpenIdConnect.as_str(), "OpenID Connect");
}

#[test]
fn detect_django_csrf_in_login_form() {
    let html = r#"
        <form action="/accounts/login/" method="POST">
            <input type="hidden" name="csrfmiddlewaretoken" value="django-csrf-xyz" />
            <input type="text" name="username" />
            <input type="password" name="password" />
        </form>
    "#;

    let forms = detect_login_forms(html);
    assert_eq!(forms.len(), 1);
    assert_eq!(
        forms[0].csrf_token_field.as_deref(),
        Some("csrfmiddlewaretoken")
    );
}

#[test]
fn detect_multiple_login_forms() {
    let html = r#"
        <form action="/admin/login" method="POST">
            <input type="text" name="admin_user" />
            <input type="password" name="admin_pass" />
        </form>
        <form action="/user/login" method="POST">
            <input type="email" name="email" />
            <input type="password" name="password" />
        </form>
    "#;

    let forms = detect_login_forms(html);
    assert_eq!(forms.len(), 2);
    assert_eq!(forms[0].action_url, "/admin/login");
    assert_eq!(forms[1].action_url, "/user/login");
}

#[test]
fn unknown_auth_type_from_empty_headers() {
    let headers = HashMap::new();
    assert_eq!(detect_auth_type_from_headers(&headers), AuthType::Unknown);
}
