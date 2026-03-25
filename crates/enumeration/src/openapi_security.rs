use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthSchemeType {
    ApiKey,
    Http,
    OAuth2,
    OpenIdConnect,
    None,
}

impl std::fmt::Display for AuthSchemeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::ApiKey => "apiKey",
            Self::Http => "http",
            Self::OAuth2 => "oauth2",
            Self::OpenIdConnect => "openIdConnect",
            Self::None => "none",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthStrength {
    None,
    Weak,
    Moderate,
    Strong,
}

impl std::fmt::Display for AuthStrength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::None => "none",
            Self::Weak => "weak",
            Self::Moderate => "moderate",
            Self::Strong => "strong",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSchemeAssessment {
    pub name: String,
    pub scheme_type: AuthSchemeType,
    pub strength: AuthStrength,
    pub location: Option<String>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointAuthCoverage {
    pub path: String,
    pub method: String,
    pub has_auth: bool,
    pub auth_schemes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterValidationIssue {
    pub path: String,
    pub method: String,
    pub parameter_name: String,
    pub parameter_in: String,
    pub missing_constraints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveDataExposure {
    pub path: String,
    pub method: String,
    pub status_code: String,
    pub sensitive_fields: Vec<String>,
    pub field_category: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaBypassRisk {
    pub path: String,
    pub method: String,
    pub allows_additional_properties: bool,
    pub schema_location: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitGap {
    pub path: String,
    pub method: String,
    pub has_rate_limit_header: bool,
}

#[derive(Debug, Clone)]
pub struct OpenApiSecurityReport {
    pub auth_assessments: Vec<AuthSchemeAssessment>,
    pub unauthenticated_endpoints: Vec<EndpointAuthCoverage>,
    pub parameter_issues: Vec<ParameterValidationIssue>,
    pub sensitive_exposures: Vec<SensitiveDataExposure>,
    pub schema_bypass_risks: Vec<SchemaBypassRisk>,
    pub rate_limit_gaps: Vec<RateLimitGap>,
    pub total_endpoints: usize,
    pub endpoints_without_auth: usize,
}

const SENSITIVE_PII_FIELDS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "ssn",
    "social_security",
    "credit_card",
    "card_number",
    "cvv",
    "pin",
    "dob",
    "date_of_birth",
    "email",
    "phone",
    "address",
    "salary",
    "bank_account",
];

const CREDENTIAL_FIELDS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "private_key",
    "client_secret",
];

pub struct OpenApiSecurityAnalyzer {
    spec: serde_json::Value,
}

impl OpenApiSecurityAnalyzer {
    pub fn new(spec: serde_json::Value) -> Self {
        Self { spec }
    }

    pub fn analyze(&self) -> OpenApiSecurityReport {
        let auth_assessments = self.analyze_auth_schemes();
        let endpoint_coverage = self.analyze_endpoint_auth_coverage();
        let unauthenticated_endpoints: Vec<EndpointAuthCoverage> = endpoint_coverage
            .iter()
            .filter(|e| !e.has_auth)
            .cloned()
            .collect();
        let total_endpoints = endpoint_coverage.len();
        let endpoints_without_auth = unauthenticated_endpoints.len();
        let parameter_issues = self.analyze_parameter_validation();
        let sensitive_exposures = self.analyze_sensitive_data_exposure();
        let schema_bypass_risks = self.analyze_schema_bypass();
        let rate_limit_gaps = self.analyze_rate_limit_gaps();

        OpenApiSecurityReport {
            auth_assessments,
            unauthenticated_endpoints,
            parameter_issues,
            sensitive_exposures,
            schema_bypass_risks,
            rate_limit_gaps,
            total_endpoints,
            endpoints_without_auth,
        }
    }

    pub fn analyze_auth_schemes(&self) -> Vec<AuthSchemeAssessment> {
        let mut assessments = Vec::new();
        let components = match self.spec.get("components") {
            Some(c) => c,
            None => return assessments,
        };
        let security_schemes = match components.get("securitySchemes") {
            Some(s) => s,
            None => return assessments,
        };
        let schemes = match security_schemes.as_object() {
            Some(o) => o,
            None => return assessments,
        };

        for (name, scheme) in schemes {
            let scheme_type_str = scheme
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");

            let (scheme_type, strength, location, issues) = match scheme_type_str {
                "apiKey" => {
                    let loc = scheme
                        .get("in")
                        .and_then(|v| v.as_str())
                        .unwrap_or("header");
                    let mut issues = Vec::new();
                    if loc == "query" {
                        issues.push(
                            "API key in query string — visible in logs and browser history"
                                .to_string(),
                        );
                    }
                    issues.push("API keys lack expiration and scope controls".to_string());
                    (
                        AuthSchemeType::ApiKey,
                        AuthStrength::Weak,
                        Some(loc.to_string()),
                        issues,
                    )
                }
                "http" => {
                    let http_scheme = scheme
                        .get("scheme")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let mut issues = Vec::new();
                    let strength = match http_scheme {
                        "bearer" => {
                            let bearer_format = scheme
                                .get("bearerFormat")
                                .and_then(|v| v.as_str())
                                .unwrap_or("opaque");
                            if bearer_format.to_lowercase() == "jwt" {
                                AuthStrength::Strong
                            } else {
                                issues.push("Bearer token without JWT — verify token validation server-side".to_string());
                                AuthStrength::Moderate
                            }
                        }
                        "basic" => {
                            issues.push(
                                "Basic auth sends credentials base64-encoded (not encrypted)"
                                    .to_string(),
                            );
                            issues.push("Requires HTTPS to be secure".to_string());
                            AuthStrength::Weak
                        }
                        _ => {
                            issues.push(format!("Unknown HTTP auth scheme: {http_scheme}"));
                            AuthStrength::Weak
                        }
                    };
                    (
                        AuthSchemeType::Http,
                        strength,
                        Some(http_scheme.to_string()),
                        issues,
                    )
                }
                "oauth2" => {
                    let mut issues = Vec::new();
                    if let Some(flows) = scheme.get("flows") {
                        if flows.get("implicit").is_some() {
                            issues.push(
                                "Implicit flow is deprecated — use authorization code with PKCE"
                                    .to_string(),
                            );
                        }
                    }
                    (AuthSchemeType::OAuth2, AuthStrength::Strong, None, issues)
                }
                "openIdConnect" => (
                    AuthSchemeType::OpenIdConnect,
                    AuthStrength::Strong,
                    None,
                    Vec::new(),
                ),
                _ => (
                    AuthSchemeType::None,
                    AuthStrength::None,
                    None,
                    vec![format!("Unknown security scheme type: {scheme_type_str}")],
                ),
            };

            assessments.push(AuthSchemeAssessment {
                name: name.clone(),
                scheme_type,
                strength,
                location,
                issues,
            });
        }

        assessments
    }

    pub fn analyze_endpoint_auth_coverage(&self) -> Vec<EndpointAuthCoverage> {
        let mut coverage = Vec::new();
        let global_security = self.spec.get("security");
        let has_global_security = global_security
            .and_then(|s| s.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);

        let paths = match self.spec.get("paths").and_then(|p| p.as_object()) {
            Some(p) => p,
            None => return coverage,
        };

        let http_methods = ["get", "post", "put", "delete", "patch", "options", "head"];

        for (path, path_item) in paths {
            let path_obj = match path_item.as_object() {
                Some(o) => o,
                None => continue,
            };

            for method in &http_methods {
                let operation = match path_obj.get(*method) {
                    Some(op) => op,
                    None => continue,
                };

                let op_security = operation.get("security");
                let (has_auth, auth_schemes) = if let Some(sec) = op_security {
                    let sec_arr = sec.as_array().map(|a| a.to_vec()).unwrap_or_default();
                    if sec_arr.is_empty()
                        || (sec_arr.len() == 1
                            && sec_arr[0]
                                .as_object()
                                .map(|o| o.is_empty())
                                .unwrap_or(false))
                    {
                        (false, Vec::new())
                    } else {
                        let schemes: Vec<String> = sec_arr
                            .iter()
                            .filter_map(|s| s.as_object())
                            .flat_map(|o| o.keys().cloned())
                            .collect();
                        (true, schemes)
                    }
                } else if has_global_security {
                    let schemes: Vec<String> = global_security
                        .unwrap()
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter_map(|s| s.as_object())
                        .flat_map(|o| o.keys().cloned())
                        .collect();
                    (true, schemes)
                } else {
                    (false, Vec::new())
                };

                coverage.push(EndpointAuthCoverage {
                    path: path.clone(),
                    method: method.to_uppercase(),
                    has_auth,
                    auth_schemes,
                });
            }
        }

        coverage
    }

    pub fn analyze_parameter_validation(&self) -> Vec<ParameterValidationIssue> {
        let mut issues = Vec::new();
        let paths = match self.spec.get("paths").and_then(|p| p.as_object()) {
            Some(p) => p,
            None => return issues,
        };

        let http_methods = ["get", "post", "put", "delete", "patch"];

        for (path, path_item) in paths {
            let path_obj = match path_item.as_object() {
                Some(o) => o,
                None => continue,
            };

            for method in &http_methods {
                let operation = match path_obj.get(*method) {
                    Some(op) => op,
                    None => continue,
                };

                if let Some(params) = operation.get("parameters").and_then(|p| p.as_array()) {
                    for param in params {
                        let param_name = param
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");
                        let param_in = param
                            .get("in")
                            .and_then(|i| i.as_str())
                            .unwrap_or("unknown");
                        let schema = param.get("schema");
                        let missing = Self::find_missing_constraints(schema);

                        if !missing.is_empty() {
                            issues.push(ParameterValidationIssue {
                                path: path.clone(),
                                method: method.to_uppercase(),
                                parameter_name: param_name.to_string(),
                                parameter_in: param_in.to_string(),
                                missing_constraints: missing,
                            });
                        }
                    }
                }

                if let Some(body) = operation.get("requestBody") {
                    if let Some(content) = body.get("content").and_then(|c| c.as_object()) {
                        for (_media_type, media_obj) in content {
                            if let Some(schema) = media_obj.get("schema") {
                                Self::check_body_schema_params(schema, path, method, &mut issues);
                            }
                        }
                    }
                }
            }
        }

        issues
    }

    fn find_missing_constraints(schema: Option<&serde_json::Value>) -> Vec<String> {
        let mut missing = Vec::new();
        let schema = match schema {
            Some(s) => s,
            None => {
                missing.push("no schema defined".to_string());
                return missing;
            }
        };

        let type_str = schema.get("type").and_then(|t| t.as_str()).unwrap_or("");

        match type_str {
            "string" => {
                if schema.get("maxLength").is_none() {
                    missing.push("missing maxLength".to_string());
                }
                if schema.get("pattern").is_none()
                    && schema.get("format").is_none()
                    && schema.get("enum").is_none()
                {
                    missing.push("missing pattern/format/enum constraint".to_string());
                }
            }
            "integer" | "number" => {
                if schema.get("minimum").is_none() && schema.get("exclusiveMinimum").is_none() {
                    missing.push("missing minimum bound".to_string());
                }
                if schema.get("maximum").is_none() && schema.get("exclusiveMaximum").is_none() {
                    missing.push("missing maximum bound".to_string());
                }
            }
            "array" => {
                if schema.get("maxItems").is_none() {
                    missing.push("missing maxItems — unbounded array".to_string());
                }
            }
            "" => {
                missing.push("missing type definition".to_string());
            }
            _ => {}
        }

        missing
    }

    fn check_body_schema_params(
        schema: &serde_json::Value,
        path: &str,
        method: &str,
        issues: &mut Vec<ParameterValidationIssue>,
    ) {
        let properties = match schema.get("properties").and_then(|p| p.as_object()) {
            Some(p) => p,
            None => return,
        };

        for (prop_name, prop_schema) in properties {
            let missing = Self::find_missing_constraints(Some(prop_schema));
            if !missing.is_empty() {
                issues.push(ParameterValidationIssue {
                    path: path.to_string(),
                    method: method.to_uppercase(),
                    parameter_name: prop_name.clone(),
                    parameter_in: "body".to_string(),
                    missing_constraints: missing,
                });
            }
        }
    }

    pub fn analyze_sensitive_data_exposure(&self) -> Vec<SensitiveDataExposure> {
        let mut exposures = Vec::new();
        let paths = match self.spec.get("paths").and_then(|p| p.as_object()) {
            Some(p) => p,
            None => return exposures,
        };

        let http_methods = ["get", "post", "put", "delete", "patch"];

        for (path, path_item) in paths {
            let path_obj = match path_item.as_object() {
                Some(o) => o,
                None => continue,
            };

            for method in &http_methods {
                let operation = match path_obj.get(*method) {
                    Some(op) => op,
                    None => continue,
                };

                let responses = match operation.get("responses").and_then(|r| r.as_object()) {
                    Some(r) => r,
                    None => continue,
                };

                for (status_code, response) in responses {
                    let content = match response.get("content").and_then(|c| c.as_object()) {
                        Some(c) => c,
                        None => continue,
                    };

                    for (_media, media_obj) in content {
                        if let Some(schema) = media_obj.get("schema") {
                            let sensitive = Self::find_sensitive_fields(schema);
                            if !sensitive.is_empty() {
                                let has_credential = sensitive.iter().any(|f| {
                                    CREDENTIAL_FIELDS
                                        .iter()
                                        .any(|c| f.to_lowercase().contains(c))
                                });
                                let category = if has_credential { "credentials" } else { "pii" };
                                exposures.push(SensitiveDataExposure {
                                    path: path.clone(),
                                    method: method.to_uppercase(),
                                    status_code: status_code.clone(),
                                    sensitive_fields: sensitive,
                                    field_category: category.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        exposures
    }

    fn find_sensitive_fields(schema: &serde_json::Value) -> Vec<String> {
        let mut sensitive = Vec::new();
        Self::collect_sensitive_fields(schema, "", &mut sensitive);
        sensitive
    }

    fn collect_sensitive_fields(
        schema: &serde_json::Value,
        prefix: &str,
        sensitive: &mut Vec<String>,
    ) {
        if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
            for (name, prop_schema) in properties {
                let full_name = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };

                let lower_name = name.to_lowercase();
                if SENSITIVE_PII_FIELDS.iter().any(|s| lower_name.contains(s)) {
                    sensitive.push(full_name.clone());
                }

                Self::collect_sensitive_fields(prop_schema, &full_name, sensitive);
            }
        }

        if let Some(items) = schema.get("items") {
            Self::collect_sensitive_fields(items, prefix, sensitive);
        }
    }

    pub fn analyze_schema_bypass(&self) -> Vec<SchemaBypassRisk> {
        let mut risks = Vec::new();
        let paths = match self.spec.get("paths").and_then(|p| p.as_object()) {
            Some(p) => p,
            None => return risks,
        };

        let http_methods = ["post", "put", "patch"];

        for (path, path_item) in paths {
            let path_obj = match path_item.as_object() {
                Some(o) => o,
                None => continue,
            };

            for method in &http_methods {
                let operation = match path_obj.get(*method) {
                    Some(op) => op,
                    None => continue,
                };

                if let Some(body) = operation.get("requestBody") {
                    if let Some(content) = body.get("content").and_then(|c| c.as_object()) {
                        for (_media, media_obj) in content {
                            if let Some(schema) = media_obj.get("schema") {
                                let allows = Self::allows_additional_properties(schema);
                                if allows {
                                    risks.push(SchemaBypassRisk {
                                        path: path.clone(),
                                        method: method.to_uppercase(),
                                        allows_additional_properties: true,
                                        schema_location: "requestBody".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        risks
    }

    fn allows_additional_properties(schema: &serde_json::Value) -> bool {
        if schema.get("properties").is_some() {
            match schema.get("additionalProperties") {
                None => true,
                Some(v) => {
                    if let Some(b) = v.as_bool() {
                        b
                    } else {
                        true
                    }
                }
            }
        } else {
            false
        }
    }

    pub fn analyze_rate_limit_gaps(&self) -> Vec<RateLimitGap> {
        let mut gaps = Vec::new();
        let paths = match self.spec.get("paths").and_then(|p| p.as_object()) {
            Some(p) => p,
            None => return gaps,
        };

        let http_methods = ["get", "post", "put", "delete", "patch"];

        for (path, path_item) in paths {
            let path_obj = match path_item.as_object() {
                Some(o) => o,
                None => continue,
            };

            for method in &http_methods {
                let operation = match path_obj.get(*method) {
                    Some(op) => op,
                    None => continue,
                };

                let has_rate_limit = Self::has_rate_limit_definition(operation);
                if !has_rate_limit {
                    gaps.push(RateLimitGap {
                        path: path.clone(),
                        method: method.to_uppercase(),
                        has_rate_limit_header: false,
                    });
                }
            }
        }

        gaps
    }

    fn has_rate_limit_definition(operation: &serde_json::Value) -> bool {
        let rate_limit_headers = [
            "X-RateLimit-Limit",
            "X-Rate-Limit-Limit",
            "RateLimit-Limit",
            "Retry-After",
            "x-ratelimit-limit",
        ];

        if let Some(responses) = operation.get("responses").and_then(|r| r.as_object()) {
            for (_code, response) in responses {
                if let Some(headers) = response.get("headers").and_then(|h| h.as_object()) {
                    for header_name in headers.keys() {
                        let lower = header_name.to_lowercase();
                        if rate_limit_headers
                            .iter()
                            .any(|rl| rl.to_lowercase() == lower)
                        {
                            return true;
                        }
                        if lower.contains("ratelimit") || lower.contains("rate-limit") {
                            return true;
                        }
                    }
                }
            }
        }

        if let Some(extensions) = operation.as_object() {
            for key in extensions.keys() {
                if key.starts_with("x-rate") || key.starts_with("x-throttl") {
                    return true;
                }
            }
        }

        false
    }
}
