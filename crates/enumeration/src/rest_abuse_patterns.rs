use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbusePatternCategory {
    MassAssignment,
    BrokenObjectLevelAuth,
    ExcessiveDataExposure,
    RateLimitAbuse,
    BatchEndpointAbuse,
    HttpMethodOverride,
    ContentTypeConfusion,
}

impl std::fmt::Display for AbusePatternCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::MassAssignment => "mass_assignment",
            Self::BrokenObjectLevelAuth => "broken_object_level_auth",
            Self::ExcessiveDataExposure => "excessive_data_exposure",
            Self::RateLimitAbuse => "rate_limit_abuse",
            Self::BatchEndpointAbuse => "batch_endpoint_abuse",
            Self::HttpMethodOverride => "http_method_override",
            Self::ContentTypeConfusion => "content_type_confusion",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbusePattern {
    pub category: AbusePatternCategory,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub test_cases: Vec<AbuseTestCase>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbuseTestCase {
    pub name: String,
    pub method: String,
    pub path_template: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub expected_vulnerable_status: Vec<u16>,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct AbusePatternLibrary {
    patterns: Vec<AbusePattern>,
}

impl AbusePatternLibrary {
    pub fn new() -> Self {
        let mut lib = Self {
            patterns: Vec::new(),
        };
        lib.register_mass_assignment();
        lib.register_broken_object_level_auth();
        lib.register_excessive_data_exposure();
        lib.register_rate_limit_abuse();
        lib.register_batch_endpoint_abuse();
        lib.register_http_method_override();
        lib.register_content_type_confusion();
        lib
    }

    pub fn patterns(&self) -> &[AbusePattern] {
        &self.patterns
    }

    pub fn patterns_by_category(&self, category: &AbusePatternCategory) -> Vec<&AbusePattern> {
        self.patterns
            .iter()
            .filter(|p| &p.category == category)
            .collect()
    }

    pub fn all_test_cases(&self) -> Vec<&AbuseTestCase> {
        self.patterns
            .iter()
            .flat_map(|p| p.test_cases.iter())
            .collect()
    }

    pub fn generate_for_endpoint(&self, method: &str, path: &str) -> Vec<AbuseTestCase> {
        let mut applicable = Vec::new();

        for pattern in &self.patterns {
            for test_case in &pattern.test_cases {
                if Self::method_matches(&test_case.method, method)
                    && Self::path_matches(&test_case.path_template, path)
                {
                    let mut concrete = test_case.clone();
                    concrete.path_template = path.to_string();
                    applicable.push(concrete);
                }
            }
        }

        applicable
    }

    fn method_matches(template_method: &str, actual_method: &str) -> bool {
        let tm = template_method.to_uppercase();
        let am = actual_method.to_uppercase();
        tm == am || tm == "ANY"
    }

    fn path_matches(template_path: &str, actual_path: &str) -> bool {
        if template_path == "{any}" {
            return true;
        }

        let template_segments: Vec<&str> =
            template_path.split('/').filter(|s| !s.is_empty()).collect();
        let actual_segments: Vec<&str> = actual_path.split('/').filter(|s| !s.is_empty()).collect();

        if template_segments.is_empty() {
            return true;
        }

        if template_segments.len() > actual_segments.len() {
            return false;
        }

        template_segments
            .iter()
            .zip(actual_segments.iter())
            .all(|(t, a)| t.starts_with('{') && t.ends_with('}') || *t == *a)
    }

    fn register_mass_assignment(&mut self) {
        let test_cases = vec![
            AbuseTestCase {
                name: "inject_admin_flag".to_string(),
                method: "POST".to_string(),
                path_template: "{any}".to_string(),
                headers: Self::json_headers(),
                body: Some(r#"{"isAdmin":true,"role":"admin"}"#.to_string()),
                expected_vulnerable_status: vec![200, 201],
                description: "Add isAdmin/role fields to check for mass assignment".to_string(),
            },
            AbuseTestCase {
                name: "inject_balance_field".to_string(),
                method: "POST".to_string(),
                path_template: "{any}".to_string(),
                headers: Self::json_headers(),
                body: Some(r#"{"balance":999999,"credits":999999}"#.to_string()),
                expected_vulnerable_status: vec![200, 201],
                description: "Add balance/credits fields to check for financial mass assignment"
                    .to_string(),
            },
            AbuseTestCase {
                name: "inject_id_override".to_string(),
                method: "PUT".to_string(),
                path_template: "{any}".to_string(),
                headers: Self::json_headers(),
                body: Some(r#"{"id":1,"user_id":1,"owner_id":1}"#.to_string()),
                expected_vulnerable_status: vec![200],
                description: "Override ID fields to take ownership of resources".to_string(),
            },
            AbuseTestCase {
                name: "inject_verified_flag".to_string(),
                method: "POST".to_string(),
                path_template: "{any}".to_string(),
                headers: Self::json_headers(),
                body: Some(
                    r#"{"email_verified":true,"is_active":true,"approved":true}"#.to_string(),
                ),
                expected_vulnerable_status: vec![200, 201],
                description: "Set verification/approval flags via mass assignment".to_string(),
            },
        ];

        self.patterns.push(AbusePattern {
            category: AbusePatternCategory::MassAssignment,
            name: "Mass Assignment".to_string(),
            description: "POST/PUT extra fields not intended by the API to escalate privileges or modify protected attributes".to_string(),
            severity: Severity::High,
            test_cases,
        });
    }

    fn register_broken_object_level_auth(&mut self) {
        let test_cases = vec![
            AbuseTestCase {
                name: "idor_sequential_id".to_string(),
                method: "GET".to_string(),
                path_template: "{any}".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_vulnerable_status: vec![200],
                description: "Replace resource ID with sequential IDs (id-1, id+1) to access other users' data".to_string(),
            },
            AbuseTestCase {
                name: "idor_zero_id".to_string(),
                method: "GET".to_string(),
                path_template: "{any}".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_vulnerable_status: vec![200],
                description: "Use ID=0 which sometimes maps to admin or first resource".to_string(),
            },
            AbuseTestCase {
                name: "idor_negative_id".to_string(),
                method: "GET".to_string(),
                path_template: "{any}".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_vulnerable_status: vec![200],
                description: "Use negative ID to test signed/unsigned confusion".to_string(),
            },
            AbuseTestCase {
                name: "idor_delete_other_resource".to_string(),
                method: "DELETE".to_string(),
                path_template: "{any}".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_vulnerable_status: vec![200, 204],
                description: "Delete another user's resource by changing the ID".to_string(),
            },
        ];

        self.patterns.push(AbusePattern {
            category: AbusePatternCategory::BrokenObjectLevelAuth,
            name: "Broken Object-Level Authorization".to_string(),
            description: "Enumerate other users' resources by manipulating object IDs in requests"
                .to_string(),
            severity: Severity::Critical,
            test_cases,
        });
    }

    fn register_excessive_data_exposure(&mut self) {
        let test_cases = vec![
            AbuseTestCase {
                name: "check_list_endpoint_fields".to_string(),
                method: "GET".to_string(),
                path_template: "{any}".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_vulnerable_status: vec![200],
                description: "Check if list endpoints return more fields than detail endpoints"
                    .to_string(),
            },
            AbuseTestCase {
                name: "verbose_error_response".to_string(),
                method: "GET".to_string(),
                path_template: "{any}".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_vulnerable_status: vec![400, 500],
                description: "Trigger errors to check if stack traces or internal details leak"
                    .to_string(),
            },
            AbuseTestCase {
                name: "request_debug_mode".to_string(),
                method: "GET".to_string(),
                path_template: "{any}".to_string(),
                headers: {
                    let mut h = HashMap::new();
                    h.insert("X-Debug".to_string(), "true".to_string());
                    h.insert("X-Debug-Mode".to_string(), "1".to_string());
                    h
                },
                body: None,
                expected_vulnerable_status: vec![200],
                description: "Send debug headers to check for verbose response data".to_string(),
            },
        ];

        self.patterns.push(AbusePattern {
            category: AbusePatternCategory::ExcessiveDataExposure,
            name: "Excessive Data Exposure".to_string(),
            description:
                "API responses contain more data than the client needs, exposing sensitive fields"
                    .to_string(),
            severity: Severity::Medium,
            test_cases,
        });
    }

    fn register_rate_limit_abuse(&mut self) {
        let test_cases = vec![
            AbuseTestCase {
                name: "login_brute_force".to_string(),
                method: "POST".to_string(),
                path_template: "{any}".to_string(),
                headers: Self::json_headers(),
                body: Some(r#"{"username":"test","password":"test"}"#.to_string()),
                expected_vulnerable_status: vec![200, 401],
                description: "Rapid login attempts to check for rate limiting on auth endpoints"
                    .to_string(),
            },
            AbuseTestCase {
                name: "ip_rotation_bypass".to_string(),
                method: "ANY".to_string(),
                path_template: "{any}".to_string(),
                headers: {
                    let mut h = HashMap::new();
                    h.insert("X-Forwarded-For".to_string(), "1.2.3.4".to_string());
                    h.insert("X-Real-IP".to_string(), "5.6.7.8".to_string());
                    h
                },
                body: None,
                expected_vulnerable_status: vec![200],
                description: "Bypass rate limits by spoofing IP via X-Forwarded-For".to_string(),
            },
            AbuseTestCase {
                name: "api_key_rotation".to_string(),
                method: "ANY".to_string(),
                path_template: "{any}".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_vulnerable_status: vec![200],
                description: "Check if rate limits are per-key (rotate keys to bypass)".to_string(),
            },
        ];

        self.patterns.push(AbusePattern {
            category: AbusePatternCategory::RateLimitAbuse,
            name: "Rate Limit Abuse".to_string(),
            description: "Find endpoints without rate limits or with bypassable rate limiting"
                .to_string(),
            severity: Severity::Medium,
            test_cases,
        });
    }

    fn register_batch_endpoint_abuse(&mut self) {
        let test_cases = vec![
            AbuseTestCase {
                name: "batch_operation_flood".to_string(),
                method: "POST".to_string(),
                path_template: "{any}".to_string(),
                headers: Self::json_headers(),
                body: Some(r#"[{"method":"GET","path":"/api/users/1"},{"method":"GET","path":"/api/users/2"},{"method":"DELETE","path":"/api/users/3"}]"#.to_string()),
                expected_vulnerable_status: vec![200],
                description: "Send batch requests mixing read and destructive operations".to_string(),
            },
            AbuseTestCase {
                name: "batch_size_abuse".to_string(),
                method: "POST".to_string(),
                path_template: "{any}".to_string(),
                headers: Self::json_headers(),
                body: Some(Self::generate_large_batch(1000)),
                expected_vulnerable_status: vec![200],
                description: "Send oversized batch (1000 operations) to test limits".to_string(),
            },
            AbuseTestCase {
                name: "batch_privilege_mixing".to_string(),
                method: "POST".to_string(),
                path_template: "{any}".to_string(),
                headers: Self::json_headers(),
                body: Some(r#"[{"method":"GET","path":"/api/public"},{"method":"GET","path":"/api/admin/users"},{"method":"POST","path":"/api/admin/config"}]"#.to_string()),
                expected_vulnerable_status: vec![200],
                description: "Mix public and admin operations in single batch to bypass auth".to_string(),
            },
        ];

        self.patterns.push(AbusePattern {
            category: AbusePatternCategory::BatchEndpointAbuse,
            name: "Batch Endpoint Abuse".to_string(),
            description: "Exploit /api/batch or similar endpoints that accept multiple operations"
                .to_string(),
            severity: Severity::High,
            test_cases,
        });
    }

    fn register_http_method_override(&mut self) {
        let override_headers = vec![
            ("X-HTTP-Method-Override", "DELETE"),
            ("X-HTTP-Method", "DELETE"),
            ("X-Method-Override", "DELETE"),
        ];

        let mut test_cases = Vec::new();
        for (header, value) in &override_headers {
            let mut headers = Self::json_headers();
            headers.insert(header.to_string(), value.to_string());

            test_cases.push(AbuseTestCase {
                name: format!("override_via_{}", header.to_lowercase().replace('-', "_")),
                method: "POST".to_string(),
                path_template: "{any}".to_string(),
                headers,
                body: None,
                expected_vulnerable_status: vec![200, 204],
                description: format!("Use {header}: {value} to bypass method restrictions"),
            });
        }

        test_cases.push(AbuseTestCase {
            name: "override_via_query_param".to_string(),
            method: "POST".to_string(),
            path_template: "{any}".to_string(),
            headers: Self::json_headers(),
            body: None,
            expected_vulnerable_status: vec![200, 204],
            description: "Append ?_method=DELETE to override HTTP method via query parameter"
                .to_string(),
        });

        self.patterns.push(AbusePattern {
            category: AbusePatternCategory::HttpMethodOverride,
            name: "HTTP Method Override".to_string(),
            description:
                "Use X-HTTP-Method-Override headers or query params to invoke forbidden methods"
                    .to_string(),
            severity: Severity::High,
            test_cases,
        });
    }

    fn register_content_type_confusion(&mut self) {
        let test_cases = vec![
            AbuseTestCase {
                name: "json_to_xml".to_string(),
                method: "POST".to_string(),
                path_template: "{any}".to_string(),
                headers: {
                    let mut h = HashMap::new();
                    h.insert("Content-Type".to_string(), "application/xml".to_string());
                    h
                },
                body: Some("<?xml version=\"1.0\"?><root><username>admin</username><password>test</password></root>".to_string()),
                expected_vulnerable_status: vec![200],
                description: "Send XML to a JSON endpoint to test for XXE or parser confusion".to_string(),
            },
            AbuseTestCase {
                name: "json_to_form_urlencoded".to_string(),
                method: "POST".to_string(),
                path_template: "{any}".to_string(),
                headers: {
                    let mut h = HashMap::new();
                    h.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());
                    h
                },
                body: Some("username=admin&password=test&isAdmin=true".to_string()),
                expected_vulnerable_status: vec![200],
                description: "Send URL-encoded form data where JSON is expected".to_string(),
            },
            AbuseTestCase {
                name: "double_content_type".to_string(),
                method: "POST".to_string(),
                path_template: "{any}".to_string(),
                headers: {
                    let mut h = HashMap::new();
                    h.insert("Content-Type".to_string(), "application/json, application/xml".to_string());
                    h
                },
                body: Some(r#"{"username":"admin"}"#.to_string()),
                expected_vulnerable_status: vec![200],
                description: "Send ambiguous dual content-type to confuse parsers".to_string(),
            },
            AbuseTestCase {
                name: "charset_override".to_string(),
                method: "POST".to_string(),
                path_template: "{any}".to_string(),
                headers: {
                    let mut h = HashMap::new();
                    h.insert("Content-Type".to_string(), "application/json; charset=utf-7".to_string());
                    h
                },
                body: Some(r#"{"test":"value"}"#.to_string()),
                expected_vulnerable_status: vec![200],
                description: "Use UTF-7 charset to bypass WAF or input validation".to_string(),
            },
        ];

        self.patterns.push(AbusePattern {
            category: AbusePatternCategory::ContentTypeConfusion,
            name: "Content-Type Confusion".to_string(),
            description:
                "Send unexpected content types to test parser confusion and bypass input validation"
                    .to_string(),
            severity: Severity::Medium,
            test_cases,
        });
    }

    fn json_headers() -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert("Content-Type".to_string(), "application/json".to_string());
        h
    }

    fn generate_large_batch(count: usize) -> String {
        let mut ops = Vec::with_capacity(count);
        for i in 0..count {
            ops.push(format!(r#"{{"method":"GET","path":"/api/resource/{i}"}}"#));
        }
        format!("[{}]", ops.join(","))
    }
}

impl Default for AbusePatternLibrary {
    fn default() -> Self {
        Self::new()
    }
}
