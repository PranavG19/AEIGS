#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenTestType {
    Expired,
    Malformed,
    Empty,
    Null,
    MissingSignature,
    WrongAlgorithm,
    TamperedPayload,
    InvalidAudience,
    InvalidIssuer,
    FutureNotBefore,
}

impl std::fmt::Display for TokenTestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Expired => "expired",
            Self::Malformed => "malformed",
            Self::Empty => "empty",
            Self::Null => "null",
            Self::MissingSignature => "missing_signature",
            Self::WrongAlgorithm => "wrong_algorithm",
            Self::TamperedPayload => "tampered_payload",
            Self::InvalidAudience => "invalid_audience",
            Self::InvalidIssuer => "invalid_issuer",
            Self::FutureNotBefore => "future_not_before",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenTestCase {
    pub test_type: TokenTestType,
    pub description: String,
    pub token_value: String,
    pub header_name: String,
    pub header_prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiKeyLocation {
    Header,
    Query,
    Cookie,
}

impl std::fmt::Display for ApiKeyLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Header => "header",
            Self::Query => "query",
            Self::Cookie => "cookie",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyTestCase {
    pub location: ApiKeyLocation,
    pub key_name: String,
    pub key_value: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthScopeTestType {
    EscalateToAdmin,
    AddExtraScopes,
    RemoveAllScopes,
    WildcardScope,
    DuplicateScopes,
}

impl std::fmt::Display for OAuthScopeTestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::EscalateToAdmin => "escalate_to_admin",
            Self::AddExtraScopes => "add_extra_scopes",
            Self::RemoveAllScopes => "remove_all_scopes",
            Self::WildcardScope => "wildcard_scope",
            Self::DuplicateScopes => "duplicate_scopes",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthScopeTestCase {
    pub test_type: OAuthScopeTestType,
    pub scopes_requested: Vec<String>,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionTestType {
    CookieOnly,
    TokenOnly,
    BothCookieAndToken,
    NeitherCookieNorToken,
    MismatchedCookieAndToken,
}

impl std::fmt::Display for SessionTestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::CookieOnly => "cookie_only",
            Self::TokenOnly => "token_only",
            Self::BothCookieAndToken => "both",
            Self::NeitherCookieNorToken => "neither",
            Self::MismatchedCookieAndToken => "mismatched",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTestCase {
    pub test_type: SessionTestType,
    pub description: String,
    pub cookie_value: Option<String>,
    pub token_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiTenantTestCase {
    pub description: String,
    pub tenant_header: String,
    pub own_tenant_id: String,
    pub target_tenant_id: String,
    pub method: String,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct AuthTestSuite {
    pub token_tests: Vec<TokenTestCase>,
    pub api_key_tests: Vec<ApiKeyTestCase>,
    pub oauth_scope_tests: Vec<OAuthScopeTestCase>,
    pub session_tests: Vec<SessionTestCase>,
    pub multi_tenant_tests: Vec<MultiTenantTestCase>,
}

pub struct ApiAuthTester {
    api_key_names: Vec<(String, ApiKeyLocation)>,
    tenant_header: String,
    own_tenant_id: String,
    target_endpoints: Vec<(String, String)>,
}

impl ApiAuthTester {
    pub fn new() -> Self {
        Self {
            api_key_names: vec![
                ("X-API-Key".to_string(), ApiKeyLocation::Header),
                ("Authorization".to_string(), ApiKeyLocation::Header),
                ("api_key".to_string(), ApiKeyLocation::Query),
                ("token".to_string(), ApiKeyLocation::Query),
                ("session".to_string(), ApiKeyLocation::Cookie),
                ("auth_token".to_string(), ApiKeyLocation::Cookie),
            ],
            tenant_header: "X-Tenant-ID".to_string(),
            own_tenant_id: "tenant-001".to_string(),
            target_endpoints: Vec::new(),
        }
    }

    pub fn with_api_key_names(mut self, names: Vec<(String, ApiKeyLocation)>) -> Self {
        self.api_key_names = names;
        self
    }

    pub fn with_tenant_header(mut self, header: &str) -> Self {
        self.tenant_header = header.to_string();
        self
    }

    pub fn with_own_tenant_id(mut self, id: &str) -> Self {
        self.own_tenant_id = id.to_string();
        self
    }

    pub fn add_target_endpoint(&mut self, method: &str, path: &str) {
        self.target_endpoints
            .push((method.to_string(), path.to_string()));
    }

    pub fn generate_test_suite(&self) -> AuthTestSuite {
        AuthTestSuite {
            token_tests: self.generate_token_tests(),
            api_key_tests: self.generate_api_key_tests(),
            oauth_scope_tests: self.generate_oauth_scope_tests(),
            session_tests: self.generate_session_tests(),
            multi_tenant_tests: self.generate_multi_tenant_tests(),
        }
    }

    pub fn generate_token_tests(&self) -> Vec<TokenTestCase> {
        let fake_expired_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
            eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxMDAwMDAwMDAwfQ.\
            SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        let malformed_jwt = "not.a.valid.jwt.token";

        let no_sig_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.\
            eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9.";

        let alg_none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.\
            eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.";

        let tampered_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
            eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiZXhwIjo5OTk5OTk5OTk5fQ.\
            tampered_signature_here";

        let wrong_aud_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
            eyJzdWIiOiIxIiwiYXVkIjoid3JvbmctYXVkaWVuY2UifQ.\
            invalid";

        let wrong_iss_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
            eyJzdWIiOiIxIiwiaXNzIjoiZXZpbC1pc3N1ZXIifQ.\
            invalid";

        let future_nbf_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
            eyJzdWIiOiIxIiwibmJmIjo5OTk5OTk5OTk5fQ.\
            invalid";

        vec![
            TokenTestCase {
                test_type: TokenTestType::Expired,
                description: "JWT with exp claim in the past".to_string(),
                token_value: fake_expired_jwt.to_string(),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
            TokenTestCase {
                test_type: TokenTestType::Malformed,
                description: "Malformed token string — not valid JWT structure".to_string(),
                token_value: malformed_jwt.to_string(),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
            TokenTestCase {
                test_type: TokenTestType::Empty,
                description: "Empty Authorization header value".to_string(),
                token_value: String::new(),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
            TokenTestCase {
                test_type: TokenTestType::Null,
                description: "Literal 'null' as token value".to_string(),
                token_value: "null".to_string(),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
            TokenTestCase {
                test_type: TokenTestType::MissingSignature,
                description: "JWT with alg:none and no signature".to_string(),
                token_value: no_sig_jwt.to_string(),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
            TokenTestCase {
                test_type: TokenTestType::WrongAlgorithm,
                description: "JWT with alg:none attempting algorithm confusion".to_string(),
                token_value: alg_none_jwt.to_string(),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
            TokenTestCase {
                test_type: TokenTestType::TamperedPayload,
                description: "JWT with modified payload but original signature".to_string(),
                token_value: tampered_jwt.to_string(),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
            TokenTestCase {
                test_type: TokenTestType::InvalidAudience,
                description: "JWT with wrong audience claim".to_string(),
                token_value: wrong_aud_jwt.to_string(),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
            TokenTestCase {
                test_type: TokenTestType::InvalidIssuer,
                description: "JWT with untrusted issuer claim".to_string(),
                token_value: wrong_iss_jwt.to_string(),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
            TokenTestCase {
                test_type: TokenTestType::FutureNotBefore,
                description: "JWT with nbf claim in the far future".to_string(),
                token_value: future_nbf_jwt.to_string(),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
        ]
    }

    pub fn generate_api_key_tests(&self) -> Vec<ApiKeyTestCase> {
        let mut tests = Vec::new();

        for (name, location) in &self.api_key_names {
            tests.push(ApiKeyTestCase {
                location: location.clone(),
                key_name: name.clone(),
                key_value: String::new(),
                description: format!("Empty API key in {location} ({name})"),
            });

            tests.push(ApiKeyTestCase {
                location: location.clone(),
                key_name: name.clone(),
                key_value: "null".to_string(),
                description: format!("Literal 'null' API key in {location} ({name})"),
            });

            tests.push(ApiKeyTestCase {
                location: location.clone(),
                key_name: name.clone(),
                key_value: "a".repeat(10000),
                description: format!("Oversized API key (10K chars) in {location} ({name})"),
            });

            tests.push(ApiKeyTestCase {
                location: location.clone(),
                key_name: name.clone(),
                key_value: "AAAA-BBBB-CCCC-DDDD".to_string(),
                description: format!("Known-format invalid key in {location} ({name})"),
            });
        }

        tests
    }

    pub fn generate_oauth_scope_tests(&self) -> Vec<OAuthScopeTestCase> {
        vec![
            OAuthScopeTestCase {
                test_type: OAuthScopeTestType::EscalateToAdmin,
                scopes_requested: vec![
                    "admin".to_string(),
                    "admin:write".to_string(),
                    "superuser".to_string(),
                ],
                description: "Request admin-level scopes to test scope enforcement".to_string(),
            },
            OAuthScopeTestCase {
                test_type: OAuthScopeTestType::AddExtraScopes,
                scopes_requested: vec![
                    "read".to_string(),
                    "write".to_string(),
                    "delete".to_string(),
                    "users:manage".to_string(),
                    "billing:read".to_string(),
                ],
                description: "Request more scopes than originally granted".to_string(),
            },
            OAuthScopeTestCase {
                test_type: OAuthScopeTestType::RemoveAllScopes,
                scopes_requested: Vec::new(),
                description: "Request token with no scopes — test default permissions".to_string(),
            },
            OAuthScopeTestCase {
                test_type: OAuthScopeTestType::WildcardScope,
                scopes_requested: vec!["*".to_string(), "**".to_string(), "all".to_string()],
                description: "Request wildcard scopes to bypass granular controls".to_string(),
            },
            OAuthScopeTestCase {
                test_type: OAuthScopeTestType::DuplicateScopes,
                scopes_requested: vec![
                    "read".to_string(),
                    "read".to_string(),
                    "read".to_string(),
                    "write".to_string(),
                ],
                description: "Duplicate scopes to test parser handling".to_string(),
            },
        ]
    }

    pub fn generate_session_tests(&self) -> Vec<SessionTestCase> {
        vec![
            SessionTestCase {
                test_type: SessionTestType::CookieOnly,
                description: "Send session cookie without Authorization header".to_string(),
                cookie_value: Some("session=valid_session_id".to_string()),
                token_value: None,
            },
            SessionTestCase {
                test_type: SessionTestType::TokenOnly,
                description: "Send Authorization header without session cookie".to_string(),
                cookie_value: None,
                token_value: Some("Bearer valid_token".to_string()),
            },
            SessionTestCase {
                test_type: SessionTestType::BothCookieAndToken,
                description: "Send both cookie and token — which takes precedence?".to_string(),
                cookie_value: Some("session=user_session".to_string()),
                token_value: Some("Bearer admin_token".to_string()),
            },
            SessionTestCase {
                test_type: SessionTestType::NeitherCookieNorToken,
                description: "Send request with neither cookie nor token".to_string(),
                cookie_value: None,
                token_value: None,
            },
            SessionTestCase {
                test_type: SessionTestType::MismatchedCookieAndToken,
                description: "Cookie and token belong to different users".to_string(),
                cookie_value: Some("session=user_a_session".to_string()),
                token_value: Some("Bearer user_b_token".to_string()),
            },
        ]
    }

    pub fn generate_multi_tenant_tests(&self) -> Vec<MultiTenantTestCase> {
        let target_tenants = vec![
            "tenant-002",
            "tenant-admin",
            "00000000-0000-0000-0000-000000000000",
            "",
            "../tenant-001",
        ];

        let mut tests = Vec::new();

        let endpoints = if self.target_endpoints.is_empty() {
            vec![
                ("GET".to_string(), "/api/resources".to_string()),
                ("POST".to_string(), "/api/resources".to_string()),
                ("DELETE".to_string(), "/api/resources/1".to_string()),
            ]
        } else {
            self.target_endpoints.clone()
        };

        for target in &target_tenants {
            for (method, path) in &endpoints {
                tests.push(MultiTenantTestCase {
                    description: format!(
                        "Access {method} {path} as tenant '{target}' while authenticated as '{}'",
                        self.own_tenant_id
                    ),
                    tenant_header: self.tenant_header.clone(),
                    own_tenant_id: self.own_tenant_id.clone(),
                    target_tenant_id: target.to_string(),
                    method: method.clone(),
                    path: path.clone(),
                });
            }
        }

        tests
    }
}

impl Default for ApiAuthTester {
    fn default() -> Self {
        Self::new()
    }
}
