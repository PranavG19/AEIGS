use std::collections::HashMap;

/// Header rotation techniques for bypassing IP-based rate limiting.
/// Each entry is (header_name, description).
pub const RATE_LIMIT_BYPASS_HEADERS: &[(&str, &str)] = &[
    ("X-Forwarded-For", "standard proxy header, rotate IPs"),
    ("X-Real-IP", "nginx real-ip header"),
    ("X-Originating-IP", "legacy proxy header"),
    ("X-Client-IP", "client IP override"),
    ("CF-Connecting-IP", "Cloudflare connecting IP"),
    ("True-Client-IP", "Akamai true client header"),
    ("X-Forwarded-Host", "host-based rate limit bypass"),
    ("X-Remote-IP", "generic remote IP header"),
    ("X-Remote-Addr", "generic remote address header"),
    ("Forwarded", "RFC 7239 standard forwarded header"),
];

/// Common fields injected during mass assignment probes.
pub const MASS_ASSIGNMENT_FIELDS: &[(&str, &str)] = &[
    ("role", "admin"),
    ("is_admin", "true"),
    ("admin", "1"),
    ("verified", "true"),
    ("email_verified", "true"),
    ("active", "true"),
    ("approved", "true"),
    ("privilege", "superuser"),
    ("permissions", "all"),
    ("group_id", "1"),
    ("account_type", "premium"),
    ("balance", "999999"),
    ("discount", "100"),
    ("price", "0"),
    ("credit", "999999"),
];

/// IP addresses used for header rotation during rate limit bypass probes.
const ROTATION_IPS: &[&str] = &[
    "127.0.0.1",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "10.10.10.1",
    "172.31.255.1",
    "192.168.0.1",
    "10.255.255.1",
];

/// Patterns indicating sequential/predictable resource identifiers.
const SEQUENTIAL_ID_PATTERNS: &[&str] = &[
    "/users/1",
    "/users/2",
    "/users/3",
    "/api/v1/items/100",
    "/api/v1/items/101",
    "/api/v1/items/102",
    "/orders/1000",
    "/orders/1001",
    "/orders/1002",
    "/accounts/1",
    "/accounts/2",
    "/invoices/1",
    "/invoices/2",
];

/// Admin-only endpoint patterns for broken function-level auth testing.
const ADMIN_ENDPOINT_PATTERNS: &[&str] = &[
    "/admin",
    "/admin/users",
    "/admin/settings",
    "/admin/config",
    "/api/admin",
    "/api/v1/admin",
    "/internal/",
    "/management/",
    "/dashboard/admin",
    "/system/",
    "/_debug",
    "/_internal",
];

/// Batch/bulk endpoint patterns.
const BATCH_ENDPOINT_PATTERNS: &[&str] = &[
    "/batch",
    "/bulk",
    "/api/batch",
    "/api/bulk",
    "/graphql",
    "/api/v1/batch",
    "/api/v2/batch",
    "/multi",
    "/api/multi",
];

#[derive(Debug, Clone, PartialEq)]
pub enum AbusePattern {
    PaginationAbuse,
    RateLimitBypass,
    MassAssignment,
    ExcessiveDataExposure,
    BrokenFunctionLevelAuth,
    ResourceEnumeration,
    BatchEndpointAbuse,
    GraphQlQueryCostBypass,
}

impl std::fmt::Display for AbusePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PaginationAbuse => write!(f, "Pagination Abuse"),
            Self::RateLimitBypass => write!(f, "Rate Limit Bypass"),
            Self::MassAssignment => write!(f, "Mass Assignment"),
            Self::ExcessiveDataExposure => write!(f, "Excessive Data Exposure"),
            Self::BrokenFunctionLevelAuth => write!(f, "Broken Function-Level Authorization"),
            Self::ResourceEnumeration => write!(f, "Resource Enumeration"),
            Self::BatchEndpointAbuse => write!(f, "Batch Endpoint Abuse"),
            Self::GraphQlQueryCostBypass => write!(f, "GraphQL Query Cost Bypass"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AbuseProbe {
    pub pattern: AbusePattern,
    pub endpoint: String,
    pub method: String,
    pub description: String,
    pub payloads: Vec<ProbePayload>,
    pub severity: Severity,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProbePayload {
    pub description: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AbuseDetectorConfig {
    pub base_url: String,
    pub endpoints: Vec<EndpointInfo>,
    pub auth_token: Option<String>,
    pub admin_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EndpointInfo {
    pub path: String,
    pub method: String,
    pub params: Vec<String>,
    pub accepts_body: bool,
    pub requires_auth: bool,
}

#[derive(Debug)]
pub enum AbuseDetectorError {
    InvalidConfig(String),
    NoEndpoints,
}

impl std::fmt::Display for AbuseDetectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
            Self::NoEndpoints => write!(f, "no endpoints provided"),
        }
    }
}

impl std::error::Error for AbuseDetectorError {}

pub struct ApiAbuseDetector {
    config: AbuseDetectorConfig,
}

impl std::fmt::Debug for ApiAbuseDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiAbuseDetector")
            .field("base_url", &self.config.base_url)
            .field("endpoint_count", &self.config.endpoints.len())
            .finish()
    }
}

impl ApiAbuseDetector {
    pub fn new(config: AbuseDetectorConfig) -> Result<Self, AbuseDetectorError> {
        if config.base_url.is_empty() {
            return Err(AbuseDetectorError::InvalidConfig(
                "base_url must not be empty".to_string(),
            ));
        }
        if config.endpoints.is_empty() {
            return Err(AbuseDetectorError::NoEndpoints);
        }
        Ok(Self { config })
    }

    /// Generate all abuse probes for configured endpoints.
    pub fn generate_probes(&self) -> Vec<AbuseProbe> {
        let mut probes = Vec::new();
        probes.extend(self.generate_pagination_probes());
        probes.extend(self.generate_rate_limit_bypass_probes());
        probes.extend(self.generate_mass_assignment_probes());
        probes.extend(self.generate_data_exposure_probes());
        probes.extend(self.generate_bfla_probes());
        probes.extend(self.generate_enumeration_probes());
        probes.extend(self.generate_batch_abuse_probes());
        probes.extend(self.generate_graphql_cost_probes());
        probes
    }

    /// Pattern 1: Pagination abuse — IDOR via page/offset manipulation.
    pub fn generate_pagination_probes(&self) -> Vec<AbuseProbe> {
        let mut probes = Vec::new();
        for ep in &self.config.endpoints {
            let has_pagination_param = ep
                .params
                .iter()
                .any(|p| matches!(p.as_str(), "page" | "offset" | "limit" | "skip" | "cursor"));
            if !has_pagination_param && ep.method != "GET" {
                continue;
            }
            let url = format!("{}{}", self.config.base_url, ep.path);
            let pagination_payloads = vec![
                ProbePayload {
                    description: "negative offset to access prior records".to_string(),
                    headers: HashMap::new(),
                    query_params: HashMap::from([
                        ("offset".to_string(), "-1".to_string()),
                        ("limit".to_string(), "10".to_string()),
                    ]),
                    body: None,
                },
                ProbePayload {
                    description: "zero offset with maximum page size".to_string(),
                    headers: HashMap::new(),
                    query_params: HashMap::from([
                        ("offset".to_string(), "0".to_string()),
                        ("limit".to_string(), "999999".to_string()),
                    ]),
                    body: None,
                },
                ProbePayload {
                    description: "large page number to enumerate total count".to_string(),
                    headers: HashMap::new(),
                    query_params: HashMap::from([
                        ("page".to_string(), "99999".to_string()),
                        ("limit".to_string(), "100".to_string()),
                    ]),
                    body: None,
                },
                ProbePayload {
                    description: "page zero boundary test".to_string(),
                    headers: HashMap::new(),
                    query_params: HashMap::from([("page".to_string(), "0".to_string())]),
                    body: None,
                },
                ProbePayload {
                    description: "negative page to trigger error leak".to_string(),
                    headers: HashMap::new(),
                    query_params: HashMap::from([("page".to_string(), "-100".to_string())]),
                    body: None,
                },
                ProbePayload {
                    description: "float offset for type coercion".to_string(),
                    headers: HashMap::new(),
                    query_params: HashMap::from([("offset".to_string(), "1.5".to_string())]),
                    body: None,
                },
            ];
            probes.push(AbuseProbe {
                pattern: AbusePattern::PaginationAbuse,
                endpoint: url,
                method: ep.method.clone(),
                description: "pagination parameter manipulation for IDOR/data leak".to_string(),
                payloads: pagination_payloads,
                severity: Severity::High,
            });
        }
        probes
    }

    /// Pattern 2: Rate limit bypass via header rotation.
    pub fn generate_rate_limit_bypass_probes(&self) -> Vec<AbuseProbe> {
        let mut probes = Vec::new();
        for ep in &self.config.endpoints {
            let url = format!("{}{}", self.config.base_url, ep.path);
            let mut payloads = Vec::new();
            for (i, (header, desc)) in RATE_LIMIT_BYPASS_HEADERS.iter().enumerate() {
                let ip = ROTATION_IPS[i % ROTATION_IPS.len()];
                payloads.push(ProbePayload {
                    description: format!("{desc} — {header}: {ip}"),
                    headers: HashMap::from([(header.to_string(), ip.to_string())]),
                    query_params: HashMap::new(),
                    body: None,
                });
            }
            payloads.push(ProbePayload {
                description: "double X-Forwarded-For chain".to_string(),
                headers: HashMap::from([(
                    "X-Forwarded-For".to_string(),
                    "127.0.0.1, 10.0.0.1".to_string(),
                )]),
                query_params: HashMap::new(),
                body: None,
            });
            payloads.push(ProbePayload {
                description: "case variation header bypass".to_string(),
                headers: HashMap::from([(
                    "x-forwarded-for".to_string(),
                    "192.168.1.100".to_string(),
                )]),
                query_params: HashMap::new(),
                body: None,
            });
            payloads.push(ProbePayload {
                description: "endpoint alias via trailing slash".to_string(),
                headers: HashMap::new(),
                query_params: HashMap::from([("_bypass".to_string(), "1".to_string())]),
                body: None,
            });
            probes.push(AbuseProbe {
                pattern: AbusePattern::RateLimitBypass,
                endpoint: url,
                method: ep.method.clone(),
                description: "rate limit bypass via header rotation and endpoint aliasing"
                    .to_string(),
                payloads,
                severity: Severity::Medium,
            });
        }
        probes
    }

    /// Pattern 3: Mass assignment — inject unexpected fields into POST/PUT bodies.
    pub fn generate_mass_assignment_probes(&self) -> Vec<AbuseProbe> {
        let mut probes = Vec::new();
        for ep in &self.config.endpoints {
            if !ep.accepts_body {
                continue;
            }
            let url = format!("{}{}", self.config.base_url, ep.path);
            let mut payloads = Vec::new();
            for (field, value) in MASS_ASSIGNMENT_FIELDS {
                let body_map: HashMap<&str, &str> = HashMap::from([(*field, *value)]);
                let body_json =
                    serde_json::to_string(&body_map).unwrap_or_else(|_| "{}".to_string());
                payloads.push(ProbePayload {
                    description: format!("inject {field}={value} into request body"),
                    headers: HashMap::from([(
                        "Content-Type".to_string(),
                        "application/json".to_string(),
                    )]),
                    query_params: HashMap::new(),
                    body: Some(body_json),
                });
            }
            let combo_body: HashMap<&str, &str> = HashMap::from([
                ("role", "admin"),
                ("is_admin", "true"),
                ("verified", "true"),
            ]);
            let combo_json =
                serde_json::to_string(&combo_body).unwrap_or_else(|_| "{}".to_string());
            payloads.push(ProbePayload {
                description: "combined privilege escalation fields".to_string(),
                headers: HashMap::from([(
                    "Content-Type".to_string(),
                    "application/json".to_string(),
                )]),
                query_params: HashMap::new(),
                body: Some(combo_json),
            });
            probes.push(AbuseProbe {
                pattern: AbusePattern::MassAssignment,
                endpoint: url,
                method: ep.method.clone(),
                description: "mass assignment probe with privilege escalation fields".to_string(),
                payloads,
                severity: Severity::Critical,
            });
        }
        probes
    }

    /// Pattern 4: Excessive data exposure — compare auth vs unauth responses.
    pub fn generate_data_exposure_probes(&self) -> Vec<AbuseProbe> {
        let mut probes = Vec::new();
        for ep in &self.config.endpoints {
            if ep.method != "GET" {
                continue;
            }
            let url = format!("{}{}", self.config.base_url, ep.path);
            let mut payloads = Vec::new();
            payloads.push(ProbePayload {
                description: "unauthenticated request to compare response fields".to_string(),
                headers: HashMap::new(),
                query_params: HashMap::new(),
                body: None,
            });
            if self.config.auth_token.is_some() {
                payloads.push(ProbePayload {
                    description: "authenticated request for field comparison".to_string(),
                    headers: HashMap::from([(
                        "Authorization".to_string(),
                        format!("Bearer {}", self.config.auth_token.as_deref().unwrap_or("")),
                    )]),
                    query_params: HashMap::new(),
                    body: None,
                });
            }
            payloads.push(ProbePayload {
                description: "request with verbose/debug flag".to_string(),
                headers: HashMap::new(),
                query_params: HashMap::from([("verbose".to_string(), "true".to_string())]),
                body: None,
            });
            payloads.push(ProbePayload {
                description: "request with fields=* wildcard".to_string(),
                headers: HashMap::new(),
                query_params: HashMap::from([("fields".to_string(), "*".to_string())]),
                body: None,
            });
            probes.push(AbuseProbe {
                pattern: AbusePattern::ExcessiveDataExposure,
                endpoint: url,
                method: "GET".to_string(),
                description: "excessive data exposure via auth comparison and field expansion"
                    .to_string(),
                payloads,
                severity: Severity::High,
            });
        }
        probes
    }

    /// Pattern 5: Broken function-level authorization — test admin endpoints with user tokens.
    pub fn generate_bfla_probes(&self) -> Vec<AbuseProbe> {
        let mut probes = Vec::new();
        for ep in &self.config.endpoints {
            let is_admin = ADMIN_ENDPOINT_PATTERNS
                .iter()
                .any(|pattern| ep.path.contains(pattern));
            if !is_admin {
                continue;
            }
            let url = format!("{}{}", self.config.base_url, ep.path);
            let mut payloads = Vec::new();
            payloads.push(ProbePayload {
                description: "access admin endpoint without authentication".to_string(),
                headers: HashMap::new(),
                query_params: HashMap::new(),
                body: None,
            });
            if let Some(ref token) = self.config.auth_token {
                payloads.push(ProbePayload {
                    description: "access admin endpoint with regular user token".to_string(),
                    headers: HashMap::from([(
                        "Authorization".to_string(),
                        format!("Bearer {token}"),
                    )]),
                    query_params: HashMap::new(),
                    body: None,
                });
            }
            payloads.push(ProbePayload {
                description: "access admin endpoint with empty bearer token".to_string(),
                headers: HashMap::from([("Authorization".to_string(), "Bearer ".to_string())]),
                query_params: HashMap::new(),
                body: None,
            });
            payloads.push(ProbePayload {
                description: "access admin endpoint with manipulated JWT none alg".to_string(),
                headers: HashMap::from([(
                    "Authorization".to_string(),
                    "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ."
                        .to_string(),
                )]),
                query_params: HashMap::new(),
                body: None,
            });
            probes.push(AbuseProbe {
                pattern: AbusePattern::BrokenFunctionLevelAuth,
                endpoint: url,
                method: ep.method.clone(),
                description:
                    "broken function-level authorization — admin endpoint with user credentials"
                        .to_string(),
                payloads,
                severity: Severity::Critical,
            });
        }
        probes
    }

    /// Pattern 6: Resource enumeration — sequential ID guessing and UUID prediction.
    pub fn generate_enumeration_probes(&self) -> Vec<AbuseProbe> {
        let mut probes = Vec::new();
        for ep in &self.config.endpoints {
            let has_id_param = ep.params.iter().any(|p| {
                matches!(
                    p.as_str(),
                    "id" | "user_id" | "account_id" | "order_id" | "item_id" | "invoice_id"
                )
            });
            let path_has_id = SEQUENTIAL_ID_PATTERNS.iter().any(|pattern| {
                ep.path
                    .starts_with(pattern.rsplit('/').nth(1).unwrap_or(""))
            });
            if !has_id_param && !path_has_id {
                continue;
            }
            let url = format!("{}{}", self.config.base_url, ep.path);
            let mut payloads = Vec::new();
            for id_val in &["1", "2", "3", "100", "101", "1000", "0", "-1"] {
                payloads.push(ProbePayload {
                    description: format!("sequential ID probe: id={id_val}"),
                    headers: HashMap::new(),
                    query_params: HashMap::from([("id".to_string(), id_val.to_string())]),
                    body: None,
                });
            }
            payloads.push(ProbePayload {
                description: "UUID v1 timestamp-based prediction".to_string(),
                headers: HashMap::new(),
                query_params: HashMap::from([(
                    "id".to_string(),
                    "00000000-0000-1000-8000-000000000000".to_string(),
                )]),
                body: None,
            });
            payloads.push(ProbePayload {
                description: "null UUID probe".to_string(),
                headers: HashMap::new(),
                query_params: HashMap::from([(
                    "id".to_string(),
                    "00000000-0000-0000-0000-000000000000".to_string(),
                )]),
                body: None,
            });
            probes.push(AbuseProbe {
                pattern: AbusePattern::ResourceEnumeration,
                endpoint: url,
                method: ep.method.clone(),
                description: "resource enumeration via sequential/predictable IDs".to_string(),
                payloads,
                severity: Severity::High,
            });
        }
        probes
    }

    /// Pattern 7: Batch endpoint abuse — find bulk endpoints that bypass per-request limits.
    pub fn generate_batch_abuse_probes(&self) -> Vec<AbuseProbe> {
        let mut probes = Vec::new();
        for ep in &self.config.endpoints {
            let is_batch = BATCH_ENDPOINT_PATTERNS.iter().any(|p| ep.path.contains(p));
            if !is_batch {
                continue;
            }
            let url = format!("{}{}", self.config.base_url, ep.path);
            let single_request = serde_json::json!([{"method": "GET", "url": "/api/users/1"}]);
            let large_batch: Vec<serde_json::Value> = (1..=100)
                .map(|i| serde_json::json!({"method": "GET", "url": format!("/api/users/{i}")}))
                .collect();
            let payloads = vec![
                ProbePayload {
                    description: "single request in batch array".to_string(),
                    headers: HashMap::from([(
                        "Content-Type".to_string(),
                        "application/json".to_string(),
                    )]),
                    query_params: HashMap::new(),
                    body: Some(serde_json::to_string(&single_request).unwrap_or_default()),
                },
                ProbePayload {
                    description: "100-request batch to bypass per-request rate limit".to_string(),
                    headers: HashMap::from([(
                        "Content-Type".to_string(),
                        "application/json".to_string(),
                    )]),
                    query_params: HashMap::new(),
                    body: Some(serde_json::to_string(&large_batch).unwrap_or_default()),
                },
                ProbePayload {
                    description: "nested batch request to multiply throughput".to_string(),
                    headers: HashMap::from([(
                        "Content-Type".to_string(),
                        "application/json".to_string(),
                    )]),
                    query_params: HashMap::new(),
                    body: Some(
                        serde_json::json!({
                            "batch": [
                                {"method": "GET", "url": "/api/users/1"},
                                {"method": "GET", "url": "/api/users/2"},
                                {"batch": [
                                    {"method": "GET", "url": "/api/users/3"},
                                    {"method": "GET", "url": "/api/users/4"}
                                ]}
                            ]
                        })
                        .to_string(),
                    ),
                },
            ];
            probes.push(AbuseProbe {
                pattern: AbusePattern::BatchEndpointAbuse,
                endpoint: url,
                method: "POST".to_string(),
                description: "batch endpoint abuse to bypass per-request rate limits".to_string(),
                payloads,
                severity: Severity::High,
            });
        }
        probes
    }

    /// Pattern 8: GraphQL query cost bypass via alias multiplication.
    pub fn generate_graphql_cost_probes(&self) -> Vec<AbuseProbe> {
        let mut probes = Vec::new();
        for ep in &self.config.endpoints {
            let is_graphql = ep.path.contains("graphql") || ep.path.contains("gql");
            if !is_graphql {
                continue;
            }
            let url = format!("{}{}", self.config.base_url, ep.path);
            let alias_multiplied = build_graphql_alias_query("users", 50);
            let deep_nested = build_graphql_deep_query(10);
            let fragment_bomb = build_graphql_fragment_bomb();
            let introspection_abuse = build_graphql_introspection_query();
            let payloads = vec![
                ProbePayload {
                    description: "alias multiplication — 50 aliased queries in single request"
                        .to_string(),
                    headers: HashMap::from([(
                        "Content-Type".to_string(),
                        "application/json".to_string(),
                    )]),
                    query_params: HashMap::new(),
                    body: Some(serde_json::json!({"query": alias_multiplied}).to_string()),
                },
                ProbePayload {
                    description: "deep nesting — 10-level nested query".to_string(),
                    headers: HashMap::from([(
                        "Content-Type".to_string(),
                        "application/json".to_string(),
                    )]),
                    query_params: HashMap::new(),
                    body: Some(serde_json::json!({"query": deep_nested}).to_string()),
                },
                ProbePayload {
                    description: "fragment spread bomb for exponential resolution".to_string(),
                    headers: HashMap::from([(
                        "Content-Type".to_string(),
                        "application/json".to_string(),
                    )]),
                    query_params: HashMap::new(),
                    body: Some(serde_json::json!({"query": fragment_bomb}).to_string()),
                },
                ProbePayload {
                    description: "introspection query for schema enumeration".to_string(),
                    headers: HashMap::from([(
                        "Content-Type".to_string(),
                        "application/json".to_string(),
                    )]),
                    query_params: HashMap::new(),
                    body: Some(serde_json::json!({"query": introspection_abuse}).to_string()),
                },
            ];
            probes.push(AbuseProbe {
                pattern: AbusePattern::GraphQlQueryCostBypass,
                endpoint: url,
                method: "POST".to_string(),
                description: "GraphQL query cost bypass via alias multiplication and deep nesting"
                    .to_string(),
                payloads,
                severity: Severity::High,
            });
        }
        probes
    }

    /// Analyze an endpoint path for potential IDOR indicators.
    pub fn detect_idor_indicators(path: &str) -> Vec<IdorIndicator> {
        let mut indicators = Vec::new();
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        for (i, segment) in segments.iter().enumerate() {
            if segment.parse::<u64>().is_ok() {
                indicators.push(IdorIndicator {
                    position: i,
                    value: segment.to_string(),
                    pattern: IdorPattern::SequentialInteger,
                });
            }
            if is_uuid_v1(segment) {
                indicators.push(IdorIndicator {
                    position: i,
                    value: segment.to_string(),
                    pattern: IdorPattern::PredictableUuidV1,
                });
            }
            if is_uuid_v4(segment) {
                indicators.push(IdorIndicator {
                    position: i,
                    value: segment.to_string(),
                    pattern: IdorPattern::RandomUuidV4,
                });
            }
            if is_short_hash(segment) {
                indicators.push(IdorIndicator {
                    position: i,
                    value: segment.to_string(),
                    pattern: IdorPattern::ShortHash,
                });
            }
        }
        indicators
    }

    /// Generate rate limit bypass headers for a specific IP rotation index.
    pub fn generate_bypass_headers(rotation_index: usize) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        let ip = ROTATION_IPS[rotation_index % ROTATION_IPS.len()];
        for (header, _) in RATE_LIMIT_BYPASS_HEADERS.iter().take(5) {
            headers.insert(header.to_string(), ip.to_string());
        }
        headers
    }

    /// Generate mass assignment payload for a given endpoint.
    pub fn generate_mass_assignment_payload(
        existing_fields: &HashMap<String, String>,
    ) -> HashMap<String, String> {
        let mut payload = existing_fields.clone();
        for (field, value) in MASS_ASSIGNMENT_FIELDS {
            if !existing_fields.contains_key(*field) {
                payload.insert(field.to_string(), value.to_string());
            }
        }
        payload
    }

    /// Count all distinct abuse patterns implemented.
    pub fn pattern_count() -> usize {
        8
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IdorIndicator {
    pub position: usize,
    pub value: String,
    pub pattern: IdorPattern,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IdorPattern {
    SequentialInteger,
    PredictableUuidV1,
    RandomUuidV4,
    ShortHash,
}

impl std::fmt::Display for IdorPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SequentialInteger => write!(f, "Sequential Integer"),
            Self::PredictableUuidV1 => write!(f, "Predictable UUID v1"),
            Self::RandomUuidV4 => write!(f, "Random UUID v4"),
            Self::ShortHash => write!(f, "Short Hash"),
        }
    }
}

fn is_uuid_v1(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let all_hex = parts
        .iter()
        .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()));
    if !all_hex {
        return false;
    }
    parts[2].starts_with('1')
}

fn is_uuid_v4(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let all_hex = parts
        .iter()
        .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()));
    if !all_hex {
        return false;
    }
    parts[2].starts_with('4')
}

fn is_short_hash(s: &str) -> bool {
    let len = s.len();
    (6..=12).contains(&len) && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn build_graphql_alias_query(field: &str, count: usize) -> String {
    let mut query = String::from("{ ");
    for i in 0..count {
        if i > 0 {
            query.push(' ');
        }
        query.push_str(&format!("a{i}: {field} {{ id name email }}"));
    }
    query.push_str(" }");
    query
}

fn build_graphql_deep_query(depth: usize) -> String {
    let mut query = String::from("{ ");
    for _ in 0..depth {
        query.push_str("users { friends { ");
    }
    query.push_str("id name");
    for _ in 0..depth {
        query.push_str(" } }");
    }
    query.push_str(" }");
    query
}

fn build_graphql_fragment_bomb() -> String {
    String::from(
        "fragment A on User { id name ...B } \
         fragment B on User { email ...C } \
         fragment C on User { address phone ...D } \
         fragment D on User { orders { id total items { name price } } } \
         { users { ...A } }",
    )
}

fn build_graphql_introspection_query() -> String {
    String::from(
        "{ __schema { types { name kind fields { name type { name kind ofType { name } } } } } }",
    )
}
