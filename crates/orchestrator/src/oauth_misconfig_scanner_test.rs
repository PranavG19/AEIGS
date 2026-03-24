use crate::oauth_misconfig_scanner::*;

// --- OAuthMisconfigIssue detection tests ---

#[test]
fn empty_body_no_misconfig_issues() {
    let issues = analyze_oauth_misconfig("");
    assert!(issues.is_empty());
}

#[test]
fn clean_oauth_flow_no_issues() {
    let body = r#"
        <a href="https://auth.example.com/oauth/authorize?response_type=code&client_id=abc&state=xyz123&redirect_uri=https://app.example.com/callback&code_challenge=abc123">Login</a>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_implicit_flow_response_type_token() {
    let body = r#"
        <a href="https://auth.example.com/oauth/authorize?response_type=token&client_id=abc">Login</a>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(issues.contains(&OAuthMisconfigIssue::ImplicitFlowUsed));
}

#[test]
fn detects_implicit_flow_response_type_id_token() {
    let body = r#"
        <script>
        window.location = "https://auth.example.com/authorize?response_type=id_token&client_id=abc";
        </script>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(issues.contains(&OAuthMisconfigIssue::ImplicitFlowUsed));
}

#[test]
fn detects_missing_state_parameter() {
    let body = r#"
        <a href="https://auth.example.com/oauth/authorize?response_type=code&client_id=abc&redirect_uri=https://app.example.com/callback&code_challenge=xyz">Login</a>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(issues.contains(&OAuthMisconfigIssue::MissingStateParameter));
}

#[test]
fn state_parameter_present_no_issue() {
    let body = r#"
        <a href="https://auth.example.com/oauth/authorize?response_type=code&client_id=abc&state=random123&redirect_uri=https://app.example.com/callback&code_challenge=xyz">Login</a>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(!issues.contains(&OAuthMisconfigIssue::MissingStateParameter));
}

#[test]
fn detects_insecure_redirect_uri() {
    let body = r#"
        <a href="https://auth.example.com/authorize?response_type=code&state=abc&redirect_uri=http://app.example.com/callback&code_challenge=xyz">Login</a>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(issues.contains(&OAuthMisconfigIssue::InsecureRedirectUri));
}

#[test]
fn detects_insecure_redirect_uri_url_encoded() {
    let body = r#"
        <a href="https://auth.example.com/authorize?response_type=code&state=abc&redirect_uri=http%3a%2f%2fapp.example.com/callback&code_challenge=xyz">Login</a>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(issues.contains(&OAuthMisconfigIssue::InsecureRedirectUri));
}

#[test]
fn https_redirect_uri_no_issue() {
    let body = r#"
        <a href="https://auth.example.com/oauth/authorize?response_type=code&state=abc&redirect_uri=https://app.example.com/callback&code_challenge=xyz">Login</a>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(!issues.contains(&OAuthMisconfigIssue::InsecureRedirectUri));
}

#[test]
fn detects_wildcard_redirect_uri() {
    let body = r#"
        <script>
        const config = { redirect_uri: "https://app.example.com/*" };
        </script>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(issues.contains(&OAuthMisconfigIssue::WildcardRedirectUri));
}

#[test]
fn detects_wildcard_redirect_uri_url_encoded() {
    let body = r#"redirect_uri=https%3a%2f%2fapp.example.com%2f%2a"#;
    let issues = analyze_oauth_misconfig(body);
    assert!(issues.contains(&OAuthMisconfigIssue::WildcardRedirectUri));
}

#[test]
fn detects_open_redirect_in_auth() {
    let body = r#"
        <a href="https://auth.example.com/oauth/authorize?redirect=true&url=javascript:alert(1)">Login</a>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(issues.contains(&OAuthMisconfigIssue::OpenRedirectInAuth));
}

#[test]
fn detects_token_in_query_string() {
    let body = r#"
        <script>
        const url = "/api/data?access_token=eyJhbGciOiJSUzI1NiJ9.abc123";
        fetch(url);
        </script>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(issues.contains(&OAuthMisconfigIssue::TokenInQueryString));
}

#[test]
fn detects_missing_pkce() {
    let body = r#"
        <a href="https://auth.example.com/authorize?response_type=code&client_id=abc&state=xyz">Login</a>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(issues.contains(&OAuthMisconfigIssue::MissingPkce));
}

#[test]
fn pkce_present_no_issue() {
    let body = r#"
        <a href="https://auth.example.com/authorize?response_type=code&client_id=abc&state=xyz&code_challenge=abc123&code_challenge_method=S256">Login</a>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(!issues.contains(&OAuthMisconfigIssue::MissingPkce));
}

#[test]
fn detects_insecure_token_storage_localstorage() {
    let body = r#"
        <script>
        const token = response.access_token;
        localStorage.setItem('auth_token', token);
        </script>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(issues.contains(&OAuthMisconfigIssue::InsecureTokenStorage));
}

#[test]
fn detects_insecure_token_storage_sessionstorage() {
    let body = r#"
        <script>
        sessionStorage.setItem('id_token', jwt);
        </script>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(issues.contains(&OAuthMisconfigIssue::InsecureTokenStorage));
}

#[test]
fn storage_without_token_keyword_no_issue() {
    let body = r#"
        <script>
        localStorage.setItem('theme', 'dark');
        </script>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(!issues.contains(&OAuthMisconfigIssue::InsecureTokenStorage));
}

#[test]
fn mixed_case_implicit_flow() {
    let body = r#"<a href="https://auth.example.com/authorize?Response_Type=Token&client_id=abc">Login</a>"#;
    let issues = analyze_oauth_misconfig(body);
    assert!(issues.contains(&OAuthMisconfigIssue::ImplicitFlowUsed));
}

// --- Severity tests ---

#[test]
fn severity_open_redirect_highest() {
    assert_eq!(
        oauth_misconfig_severity(&OAuthMisconfigIssue::OpenRedirectInAuth),
        8.0
    );
}

#[test]
fn severity_implicit_flow() {
    assert_eq!(
        oauth_misconfig_severity(&OAuthMisconfigIssue::ImplicitFlowUsed),
        7.5
    );
}

#[test]
fn severity_token_in_query_string() {
    assert_eq!(
        oauth_misconfig_severity(&OAuthMisconfigIssue::TokenInQueryString),
        7.5
    );
}

#[test]
fn severity_missing_state() {
    assert_eq!(
        oauth_misconfig_severity(&OAuthMisconfigIssue::MissingStateParameter),
        7.0
    );
}

#[test]
fn severity_wildcard_redirect() {
    assert_eq!(
        oauth_misconfig_severity(&OAuthMisconfigIssue::WildcardRedirectUri),
        7.0
    );
}

#[test]
fn severity_insecure_redirect() {
    assert_eq!(
        oauth_misconfig_severity(&OAuthMisconfigIssue::InsecureRedirectUri),
        6.5
    );
}

#[test]
fn severity_insecure_token_storage() {
    assert_eq!(
        oauth_misconfig_severity(&OAuthMisconfigIssue::InsecureTokenStorage),
        6.5
    );
}

#[test]
fn severity_missing_pkce_lowest() {
    assert_eq!(
        oauth_misconfig_severity(&OAuthMisconfigIssue::MissingPkce),
        6.0
    );
}

// --- Operations tests ---

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        OAuthMisconfigIssue::ImplicitFlowUsed,
        OAuthMisconfigIssue::MissingStateParameter,
    ];
    let mut seq = 0;
    let ops = oauth_misconfig_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn to_operations_empty_vec() {
    let issues: Vec<OAuthMisconfigIssue> = vec![];
    let mut seq = 0;
    let ops = oauth_misconfig_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

// --- Display tests ---

#[test]
fn display_misconfig_variants() {
    assert_eq!(
        OAuthMisconfigIssue::ImplicitFlowUsed.to_string(),
        "implicit_flow_used"
    );
    assert_eq!(
        OAuthMisconfigIssue::MissingStateParameter.to_string(),
        "missing_state_parameter"
    );
    assert_eq!(
        OAuthMisconfigIssue::InsecureRedirectUri.to_string(),
        "insecure_redirect_uri"
    );
    assert_eq!(
        OAuthMisconfigIssue::WildcardRedirectUri.to_string(),
        "wildcard_redirect_uri"
    );
    assert_eq!(
        OAuthMisconfigIssue::OpenRedirectInAuth.to_string(),
        "open_redirect_in_auth"
    );
    assert_eq!(
        OAuthMisconfigIssue::TokenInQueryString.to_string(),
        "token_in_query_string"
    );
    assert_eq!(OAuthMisconfigIssue::MissingPkce.to_string(), "missing_pkce");
    assert_eq!(
        OAuthMisconfigIssue::InsecureTokenStorage.to_string(),
        "insecure_token_storage"
    );
}

// --- OAuthSecurityIssue detection tests ---

#[test]
fn security_empty_body() {
    let issues = analyze_oauth_security("");
    assert!(issues.is_empty());
}

#[test]
fn security_clean_html_no_issues() {
    let body = "<html><head><title>Home</title></head><body>Welcome</body></html>";
    let issues = analyze_oauth_security(body);
    assert!(issues.is_empty());
}

#[test]
fn security_detects_oauth_endpoint_exposed_client_id() {
    let body = r#"
        <script>
        const authUrl = "https://auth.example.com/oauth/authorize?client_id=abc123";
        </script>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(issues.contains(&OAuthSecurityIssue::OAuthEndpointExposed));
}

#[test]
fn security_detects_oauth_endpoint_exposed_authorize() {
    let body = r#"
        <a href="/oauth/authorize">Login with OAuth</a>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(issues.contains(&OAuthSecurityIssue::OAuthEndpointExposed));
}

#[test]
fn security_detects_client_secret_exposed() {
    let body = r#"
        <script>
        const config = {
            client_id: "abc123",
            client_secret: "super_secret_value_here"
        };
        </script>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(issues.contains(&OAuthSecurityIssue::ClientSecretExposed));
}

#[test]
fn security_detects_jwks_endpoint_exposed() {
    let body = r#"
        <script>
        fetch("https://auth.example.com/.well-known/jwks")
            .then(r => r.json())
            .then(keys => validate(keys));
        </script>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(issues.contains(&OAuthSecurityIssue::JwksEndpointExposed));
}

#[test]
fn security_detects_jwks_uri_exposed() {
    let body = r#"
        <script>
        const jwks_uri = "https://auth.example.com/keys";
        </script>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(issues.contains(&OAuthSecurityIssue::JwksEndpointExposed));
}

#[test]
fn security_detects_token_endpoint_cors() {
    let body = r#"
        <script>
        // POST to /oauth/token
        // Response includes Access-Control-Allow-Origin: *
        </script>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(issues.contains(&OAuthSecurityIssue::TokenEndpointCors));
}

#[test]
fn security_detects_refresh_token_in_client() {
    let body = r#"
        <script>
        function refreshAuth() {
            const refresh_token = localStorage.getItem('refresh_token');
            fetch('/oauth/token', {
                method: 'POST',
                body: JSON.stringify({ grant_type: 'refresh_token', refresh_token })
            });
        }
        </script>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(issues.contains(&OAuthSecurityIssue::RefreshTokenInClient));
}

#[test]
fn security_detects_refresh_token_arrow_function() {
    let body = r#"
        <script>
        const renew = () => {
            const refresh_token = getToken();
        };
        </script>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(issues.contains(&OAuthSecurityIssue::RefreshTokenInClient));
}

#[test]
fn security_detects_id_token_unvalidated() {
    let body = r#"
        <script>
        const payload = parseJwt(id_token);
        document.getElementById('user').textContent = payload.name;
        </script>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(issues.contains(&OAuthSecurityIssue::IdTokenUnvalidated));
}

#[test]
fn security_id_token_with_verify_no_issue() {
    let body = r#"
        <script>
        const verified = verify(id_token, publicKey);
        </script>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(!issues.contains(&OAuthSecurityIssue::IdTokenUnvalidated));
}

#[test]
fn security_id_token_with_validate_no_issue() {
    let body = r#"
        <script>
        const result = validate(id_token, jwks);
        </script>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(!issues.contains(&OAuthSecurityIssue::IdTokenUnvalidated));
}

#[test]
fn security_detects_nonce_reuse() {
    let body = r#"
        <a href="https://auth.example.com/authorize?nonce=static_value_123&client_id=abc">Login</a>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(issues.contains(&OAuthSecurityIssue::NonceReuse));
}

#[test]
fn security_detects_scope_overprivileged() {
    let body = r#"
        <a href="https://auth.example.com/authorize?scope=openid profile email admin users.read&client_id=abc">Login</a>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(issues.contains(&OAuthSecurityIssue::ScopeOverprivileged));
}

#[test]
fn security_small_scope_no_issue() {
    let body = r#"
        <a href="https://auth.example.com/authorize?scope=openid profile&client_id=abc">Login</a>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(!issues.contains(&OAuthSecurityIssue::ScopeOverprivileged));
}

#[test]
fn security_detects_implicit_consent_prompt_none() {
    let body = r#"
        <script>
        window.location = "https://auth.example.com/authorize?prompt=none&client_id=abc";
        </script>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(issues.contains(&OAuthSecurityIssue::ImplicitConsentScreen));
}

#[test]
fn security_detects_implicit_consent_auto() {
    let body = r#"
        <a href="https://auth.example.com/authorize?consent=auto&client_id=abc">Login</a>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(issues.contains(&OAuthSecurityIssue::ImplicitConsentScreen));
}

#[test]
fn security_detects_discovery_endpoint_exposed() {
    let body = r#"
        <script>
        fetch("https://auth.example.com/.well-known/openid-configuration")
            .then(r => r.json())
            .then(config => setup(config));
        </script>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(issues.contains(&OAuthSecurityIssue::DiscoveryEndpointExposed));
}

// --- Security severity tests ---

#[test]
fn security_severity_client_secret_highest() {
    assert_eq!(
        oauth_security_severity(&OAuthSecurityIssue::ClientSecretExposed),
        9.0
    );
}

#[test]
fn security_severity_refresh_token() {
    assert_eq!(
        oauth_security_severity(&OAuthSecurityIssue::RefreshTokenInClient),
        7.5
    );
}

#[test]
fn security_severity_id_token_unvalidated() {
    assert_eq!(
        oauth_security_severity(&OAuthSecurityIssue::IdTokenUnvalidated),
        7.0
    );
}

#[test]
fn security_severity_token_endpoint_cors() {
    assert_eq!(
        oauth_security_severity(&OAuthSecurityIssue::TokenEndpointCors),
        6.5
    );
}

#[test]
fn security_severity_nonce_reuse() {
    assert_eq!(
        oauth_security_severity(&OAuthSecurityIssue::NonceReuse),
        6.5
    );
}

#[test]
fn security_severity_implicit_consent() {
    assert_eq!(
        oauth_security_severity(&OAuthSecurityIssue::ImplicitConsentScreen),
        6.5
    );
}

#[test]
fn security_severity_scope_overprivileged() {
    assert_eq!(
        oauth_security_severity(&OAuthSecurityIssue::ScopeOverprivileged),
        6.0
    );
}

#[test]
fn security_severity_jwks_endpoint() {
    assert_eq!(
        oauth_security_severity(&OAuthSecurityIssue::JwksEndpointExposed),
        5.5
    );
}

#[test]
fn security_severity_oauth_endpoint() {
    assert_eq!(
        oauth_security_severity(&OAuthSecurityIssue::OAuthEndpointExposed),
        5.0
    );
}

#[test]
fn security_severity_discovery_endpoint_lowest() {
    assert_eq!(
        oauth_security_severity(&OAuthSecurityIssue::DiscoveryEndpointExposed),
        4.5
    );
}

// --- Security operations tests ---

#[test]
fn security_operations_creates_entries() {
    let issues = vec![
        OAuthSecurityIssue::ClientSecretExposed,
        OAuthSecurityIssue::OAuthEndpointExposed,
    ];
    let mut seq = 0;
    let ops = oauth_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_operations_empty_vec() {
    let issues: Vec<OAuthSecurityIssue> = vec![];
    let mut seq = 0;
    let ops = oauth_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

// --- Security display tests ---

#[test]
fn security_display_variants() {
    assert_eq!(
        OAuthSecurityIssue::OAuthEndpointExposed.to_string(),
        "oauth_endpoint_exposed"
    );
    assert_eq!(
        OAuthSecurityIssue::ClientSecretExposed.to_string(),
        "client_secret_exposed"
    );
    assert_eq!(
        OAuthSecurityIssue::JwksEndpointExposed.to_string(),
        "jwks_endpoint_exposed"
    );
    assert_eq!(
        OAuthSecurityIssue::TokenEndpointCors.to_string(),
        "token_endpoint_cors"
    );
    assert_eq!(
        OAuthSecurityIssue::RefreshTokenInClient.to_string(),
        "refresh_token_in_client"
    );
    assert_eq!(
        OAuthSecurityIssue::IdTokenUnvalidated.to_string(),
        "id_token_unvalidated"
    );
    assert_eq!(OAuthSecurityIssue::NonceReuse.to_string(), "nonce_reuse");
    assert_eq!(
        OAuthSecurityIssue::ScopeOverprivileged.to_string(),
        "scope_overprivileged"
    );
    assert_eq!(
        OAuthSecurityIssue::ImplicitConsentScreen.to_string(),
        "implicit_consent_screen"
    );
    assert_eq!(
        OAuthSecurityIssue::DiscoveryEndpointExposed.to_string(),
        "discovery_endpoint_exposed"
    );
}

// --- Combined/edge case tests ---

#[test]
fn multiple_misconfig_issues_detected() {
    let body = r#"
        <script>
        const authUrl = "https://auth.example.com/authorize?response_type=token&client_id=abc&redirect_uri=http://app.example.com/callback";
        const data = "/api?access_token=xyz";
        localStorage.setItem('token', response.access_token);
        </script>
    "#;
    let issues = analyze_oauth_misconfig(body);
    assert!(issues.contains(&OAuthMisconfigIssue::ImplicitFlowUsed));
    assert!(issues.contains(&OAuthMisconfigIssue::InsecureRedirectUri));
    assert!(issues.contains(&OAuthMisconfigIssue::TokenInQueryString));
    assert!(issues.contains(&OAuthMisconfigIssue::InsecureTokenStorage));
}

#[test]
fn multiple_security_issues_detected() {
    let body = r#"
        <script>
        const config = {
            client_id: "abc",
            client_secret: "super_secret"
        };
        fetch("https://auth.example.com/.well-known/openid-configuration");
        const payload = parseJwt(id_token);
        window.location = "https://auth.example.com/oauth/authorize?prompt=none";
        </script>
    "#;
    let issues = analyze_oauth_security(body);
    assert!(issues.contains(&OAuthSecurityIssue::ClientSecretExposed));
    assert!(issues.contains(&OAuthSecurityIssue::DiscoveryEndpointExposed));
    assert!(issues.contains(&OAuthSecurityIssue::IdTokenUnvalidated));
    assert!(issues.contains(&OAuthSecurityIssue::ImplicitConsentScreen));
    assert!(issues.contains(&OAuthSecurityIssue::OAuthEndpointExposed));
}

#[test]
fn minimal_html_no_false_positives() {
    let body = r#"
        <html>
        <head><title>Simple Page</title></head>
        <body><p>Hello world</p></body>
        </html>
    "#;
    let misconfig = analyze_oauth_misconfig(body);
    let security = analyze_oauth_security(body);
    assert!(misconfig.is_empty());
    assert!(security.is_empty());
}

#[test]
fn operations_sequence_numbers_increment() {
    let misconfig_issues = vec![
        OAuthMisconfigIssue::ImplicitFlowUsed,
        OAuthMisconfigIssue::MissingPkce,
    ];
    let security_issues = vec![OAuthSecurityIssue::ClientSecretExposed];
    let mut seq = 10;
    let ops1 = oauth_misconfig_to_operations(&misconfig_issues, &mut seq);
    assert_eq!(ops1.len(), 2);
    assert_eq!(seq, 12);
    let ops2 = oauth_security_to_operations(&security_issues, &mut seq);
    assert_eq!(ops2.len(), 1);
    assert_eq!(seq, 13);
}
