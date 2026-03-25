use aegis_protocol::finding::VulnerabilityClass;
use axum::Router;
use axum::extract::{Json, Path, Query};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post, put};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity level for ground truth annotations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// A single ground truth annotation tying an endpoint to a specific
/// vulnerability class and severity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VulnAnnotation {
    pub endpoint: String,
    pub method: String,
    pub vulnerability_class: VulnerabilityClass,
    pub severity: Severity,
    pub description: String,
    /// OWASP Top 10 2021 category identifier (e.g. "A01:2021").
    pub owasp_category: String,
    /// CWE identifier (e.g. "CWE-89").
    pub cwe_id: String,
}

/// Comprehensive vulnerable API with 30+ deliberately vulnerable endpoints
/// spanning the OWASP Top 10 2021 categories.
pub struct VulnerableApi {
    router: Router,
    annotations: Vec<VulnAnnotation>,
}

impl VulnerableApi {
    /// Builds the full vulnerable API with all 32 endpoints.
    pub fn build() -> Self {
        let annotations = vec![
            // --- A01:2021 Broken Access Control ---
            ann(
                "/api/admin/users",
                "GET",
                VulnerabilityClass::BrokenAuthentication,
                Severity::Critical,
                "Admin panel without authentication",
                "A01:2021",
                "CWE-306",
            ),
            ann(
                "/api/users/:id/profile",
                "GET",
                VulnerabilityClass::InsecureDirectObjectReference,
                Severity::High,
                "IDOR: any user profile accessible by ID",
                "A01:2021",
                "CWE-639",
            ),
            ann(
                "/api/documents/:id",
                "GET",
                VulnerabilityClass::BrokenAuthorization,
                Severity::High,
                "Missing function-level access control on documents",
                "A01:2021",
                "CWE-285",
            ),
            ann(
                "/api/redirect",
                "GET",
                VulnerabilityClass::OpenRedirect,
                Severity::Medium,
                "Unvalidated redirect via url param",
                "A01:2021",
                "CWE-601",
            ),
            ann(
                "/api/cors-test",
                "GET",
                VulnerabilityClass::CrossOriginMisconfiguration,
                Severity::Medium,
                "Reflects Origin header in ACAO without validation",
                "A01:2021",
                "CWE-346",
            ),
            // --- A02:2021 Cryptographic Failures ---
            ann(
                "/api/secrets",
                "GET",
                VulnerabilityClass::SensitiveDataExposure,
                Severity::Critical,
                "API keys and credentials in plaintext response",
                "A02:2021",
                "CWE-312",
            ),
            ann(
                "/api/token/weak",
                "GET",
                VulnerabilityClass::WeakCryptography,
                Severity::High,
                "JWT signed with weak secret 'password123'",
                "A02:2021",
                "CWE-326",
            ),
            // --- A03:2021 Injection ---
            ann(
                "/api/search",
                "GET",
                VulnerabilityClass::SqlInjection,
                Severity::Critical,
                "SQL injection via q parameter",
                "A03:2021",
                "CWE-89",
            ),
            ann(
                "/api/nosql/users",
                "GET",
                VulnerabilityClass::NoSqlInjection,
                Severity::High,
                "NoSQL injection via filter JSON parameter",
                "A03:2021",
                "CWE-943",
            ),
            ann(
                "/api/render",
                "GET",
                VulnerabilityClass::CrossSiteScripting,
                Severity::High,
                "Reflected XSS via name parameter",
                "A03:2021",
                "CWE-79",
            ),
            ann(
                "/api/exec",
                "GET",
                VulnerabilityClass::CommandInjection,
                Severity::Critical,
                "OS command injection via host parameter",
                "A03:2021",
                "CWE-78",
            ),
            ann(
                "/api/template",
                "GET",
                VulnerabilityClass::ServerSideTemplateInjection,
                Severity::High,
                "SSTI via expr parameter",
                "A03:2021",
                "CWE-1336",
            ),
            ann(
                "/api/xml/parse",
                "POST",
                VulnerabilityClass::XmlExternalEntity,
                Severity::High,
                "XXE via XML body parsing",
                "A03:2021",
                "CWE-611",
            ),
            ann(
                "/api/files",
                "GET",
                VulnerabilityClass::PathTraversal,
                Severity::High,
                "Path traversal via path parameter",
                "A03:2021",
                "CWE-22",
            ),
            ann(
                "/api/crlf",
                "GET",
                VulnerabilityClass::CrlfInjection,
                Severity::Medium,
                "CRLF injection in Set-Cookie header",
                "A03:2021",
                "CWE-93",
            ),
            ann(
                "/api/header-inject",
                "GET",
                VulnerabilityClass::HeaderInjection,
                Severity::Medium,
                "User input reflected in response header",
                "A03:2021",
                "CWE-113",
            ),
            ann(
                "/api/host-check",
                "GET",
                VulnerabilityClass::HostHeaderInjection,
                Severity::Medium,
                "Host header reflected in response link",
                "A03:2021",
                "CWE-644",
            ),
            // --- A04:2021 Insecure Design ---
            ann(
                "/api/graphql",
                "POST",
                VulnerabilityClass::GraphQlAbuse,
                Severity::Medium,
                "GraphQL without depth/complexity limits",
                "A04:2021",
                "CWE-400",
            ),
            // --- A05:2021 Security Misconfiguration ---
            ann(
                "/api/debug",
                "GET",
                VulnerabilityClass::SecurityMisconfiguration,
                Severity::High,
                "Debug mode with stack traces and versions",
                "A05:2021",
                "CWE-215",
            ),
            ann(
                "/api/security-headers",
                "GET",
                VulnerabilityClass::MissingSecurityHeader,
                Severity::Low,
                "Missing X-Frame-Options and CSP headers",
                "A05:2021",
                "CWE-693",
            ),
            ann(
                "/api/clickjack",
                "GET",
                VulnerabilityClass::Clickjacking,
                Severity::Medium,
                "Frameable page without X-Frame-Options",
                "A05:2021",
                "CWE-1021",
            ),
            // --- A06:2021 Vulnerable and Outdated Components ---
            ann(
                "/api/version",
                "GET",
                VulnerabilityClass::InformationDisclosure,
                Severity::Low,
                "Server version and dependency info leaked",
                "A06:2021",
                "CWE-200",
            ),
            // --- A07:2021 Identification and Authentication Failures ---
            ann(
                "/api/jwt/none",
                "GET",
                VulnerabilityClass::JwtVulnerability,
                Severity::Critical,
                "JWT accepts alg:none",
                "A07:2021",
                "CWE-345",
            ),
            // --- A08:2021 Software and Data Integrity Failures ---
            ann(
                "/api/deserialize",
                "POST",
                VulnerabilityClass::InsecureDeserialization,
                Severity::Critical,
                "Unsafe deserialization of user input",
                "A08:2021",
                "CWE-502",
            ),
            ann(
                "/api/mass-assign",
                "PUT",
                VulnerabilityClass::MassAssignment,
                Severity::High,
                "Mass assignment allows setting is_admin field",
                "A08:2021",
                "CWE-915",
            ),
            // --- A09:2021 Security Logging and Monitoring Failures ---
            // (no endpoint — by design, but we test info-disclosure)
            // --- A10:2021 Server-Side Request Forgery ---
            ann(
                "/api/fetch",
                "GET",
                VulnerabilityClass::ServerSideRequestForgery,
                Severity::High,
                "SSRF via url parameter",
                "A10:2021",
                "CWE-918",
            ),
            // --- Additional coverage for remaining classes ---
            ann(
                "/api/prototype",
                "POST",
                VulnerabilityClass::PrototypePollution,
                Severity::Medium,
                "Prototype pollution via JSON merge",
                "A03:2021",
                "CWE-1321",
            ),
            ann(
                "/api/cache",
                "GET",
                VulnerabilityClass::CachePoisoning,
                Severity::Medium,
                "Cache key includes unvalidated header",
                "A05:2021",
                "CWE-349",
            ),
            ann(
                "/api/smuggle",
                "POST",
                VulnerabilityClass::HttpRequestSmuggling,
                Severity::High,
                "CL/TE desync in request parsing",
                "A05:2021",
                "CWE-444",
            ),
            ann(
                "/api/race",
                "POST",
                VulnerabilityClass::RaceCondition,
                Severity::Medium,
                "Race condition on account balance update",
                "A04:2021",
                "CWE-362",
            ),
            ann(
                "/api/validate",
                "GET",
                VulnerabilityClass::InsufficientInputValidation,
                Severity::Low,
                "No length or format validation on input",
                "A03:2021",
                "CWE-20",
            ),
            ann(
                "/api/store-xss",
                "POST",
                VulnerabilityClass::CrossSiteScripting,
                Severity::High,
                "Stored XSS via comment body",
                "A03:2021",
                "CWE-79",
            ),
        ];

        let router = Router::new()
            // A01: Broken Access Control
            .route("/api/admin/users", get(handle_admin_users))
            .route("/api/users/{id}/profile", get(handle_user_profile))
            .route("/api/documents/{id}", get(handle_documents))
            .route("/api/redirect", get(handle_redirect))
            .route("/api/cors-test", get(handle_cors))
            // A02: Cryptographic Failures
            .route("/api/secrets", get(handle_secrets))
            .route("/api/token/weak", get(handle_weak_jwt))
            // A03: Injection
            .route("/api/search", get(handle_sqli))
            .route("/api/nosql/users", get(handle_nosql))
            .route("/api/render", get(handle_xss))
            .route("/api/exec", get(handle_cmdi))
            .route("/api/template", get(handle_ssti))
            .route("/api/xml/parse", post(handle_xxe))
            .route("/api/files", get(handle_path_traversal))
            .route("/api/crlf", get(handle_crlf))
            .route("/api/header-inject", get(handle_header_inject))
            .route("/api/host-check", get(handle_host_header))
            // A04: Insecure Design
            .route("/api/graphql", post(handle_graphql))
            // A05: Security Misconfiguration
            .route("/api/debug", get(handle_debug))
            .route("/api/security-headers", get(handle_missing_headers))
            .route("/api/clickjack", get(handle_clickjack))
            // A06: Vulnerable Components
            .route("/api/version", get(handle_version_leak))
            // A07: Auth Failures
            .route("/api/jwt/none", get(handle_jwt_none))
            // A08: Integrity Failures
            .route("/api/deserialize", post(handle_deserialize))
            .route("/api/mass-assign", put(handle_mass_assign))
            // A10: SSRF
            .route("/api/fetch", get(handle_ssrf))
            // Additional
            .route("/api/prototype", post(handle_prototype_pollution))
            .route("/api/cache", get(handle_cache_poison))
            .route("/api/smuggle", post(handle_smuggle))
            .route("/api/race", post(handle_race))
            .route("/api/validate", get(handle_input_validation))
            .route("/api/store-xss", post(handle_stored_xss))
            .route("/health", get(|| async { "ok" }));

        Self {
            router,
            annotations,
        }
    }

    /// Returns the built axum Router.
    pub fn into_router(self) -> Router {
        self.router
    }

    /// Returns the ground truth annotations for all endpoints.
    pub fn annotations(&self) -> &[VulnAnnotation] {
        &self.annotations
    }

    /// Returns annotation count grouped by OWASP category.
    pub fn owasp_coverage(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for ann in &self.annotations {
            *map.entry(ann.owasp_category.clone()).or_insert(0) += 1;
        }
        map
    }

    /// Returns the number of unique VulnerabilityClass variants covered.
    pub fn unique_vuln_classes(&self) -> usize {
        let classes: std::collections::HashSet<_> = self
            .annotations
            .iter()
            .map(|a| a.vulnerability_class)
            .collect();
        classes.len()
    }
}

fn ann(
    endpoint: &str,
    method: &str,
    class: VulnerabilityClass,
    severity: Severity,
    desc: &str,
    owasp: &str,
    cwe: &str,
) -> VulnAnnotation {
    VulnAnnotation {
        endpoint: endpoint.to_string(),
        method: method.to_string(),
        vulnerability_class: class,
        severity,
        description: desc.to_string(),
        owasp_category: owasp.to_string(),
        cwe_id: cwe.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Handler implementations — each deliberately vulnerable
// ---------------------------------------------------------------------------

// A01: Broken Access Control

async fn handle_admin_users() -> impl IntoResponse {
    serde_json::json!({
        "users": [
            {"id": 1, "name": "admin", "role": "superuser", "api_key": "sk-admin-secret-key-9f8e7d"},
            {"id": 2, "name": "operator", "role": "admin", "api_key": "sk-ops-key-a1b2c3"}
        ]
    })
    .to_string()
}

async fn handle_user_profile(Path(id): Path<u64>) -> impl IntoResponse {
    serde_json::json!({
        "user_id": id,
        "email": format!("user{}@internal.corp", id),
        "ssn": "341-22-8876",
        "salary": 145000,
        "manager": "jfernandez"
    })
    .to_string()
}

async fn handle_documents(Path(id): Path<u64>) -> impl IntoResponse {
    serde_json::json!({
        "document_id": id,
        "title": "Q4 Financial Report — CONFIDENTIAL",
        "classification": "TOP SECRET",
        "content": "Revenue: $4.2M, Burn: $1.1M, Runway: 11 months"
    })
    .to_string()
}

async fn handle_redirect(Query(params): Query<HashMap<String, String>>) -> Response {
    let url = params.get("url").cloned().unwrap_or("/".to_string());
    Redirect::temporary(&url).into_response()
}

async fn handle_cors(headers: HeaderMap) -> Response {
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("*");
    let mut resp_headers = HeaderMap::new();
    if let Ok(val) = HeaderValue::from_str(origin) {
        resp_headers.insert("access-control-allow-origin", val);
    }
    resp_headers.insert(
        "access-control-allow-credentials",
        HeaderValue::from_static("true"),
    );
    (resp_headers, "ok").into_response()
}

// A02: Cryptographic Failures

async fn handle_secrets() -> impl IntoResponse {
    serde_json::json!({
        "database_url": "postgresql://root:hunter2@db.prod.internal:5432/maindb",
        "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "stripe_secret": "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
        "jwt_secret": "password123"
    })
    .to_string()
}

async fn handle_weak_jwt() -> impl IntoResponse {
    // Simulated JWT with HS256 and weak key "password123"
    let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let payload = "eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoic3VwZXJ1c2VyIn0";
    let signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    format!("{header}.{payload}.{signature}")
}

// A03: Injection

async fn handle_sqli(Query(params): Query<HashMap<String, String>>) -> Response {
    let q = params.get("q").cloned().unwrap_or_default();
    let query = format!("SELECT * FROM products WHERE name LIKE '%{q}%'");
    if q.contains('\'') || q.contains("--") || q.contains(" OR ") || q.contains("UNION") {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "ERROR: syntax error at or near \"{}\" in query: {}",
                q, query
            ),
        )
            .into_response()
    } else {
        serde_json::json!({"query": query, "results": []})
            .to_string()
            .into_response()
    }
}

async fn handle_nosql(Query(params): Query<HashMap<String, String>>) -> Response {
    let filter = params.get("filter").cloned().unwrap_or_default();
    if filter.contains("$gt") || filter.contains("$ne") || filter.contains("$regex") {
        serde_json::json!({
            "error": "MongoError: operator not allowed in query filter",
            "filter_received": filter,
            "users": [{"username": "admin", "email": "admin@internal.corp"}]
        })
        .to_string()
        .into_response()
    } else {
        serde_json::json!({"users": []}).to_string().into_response()
    }
}

async fn handle_xss(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let name = params.get("name").cloned().unwrap_or("Guest".to_string());
    Html(format!(
        r#"<!DOCTYPE html><html><head><title>Profile</title></head>
<body><h1>Welcome, {name}</h1><p>Your profile page</p></body></html>"#
    ))
}

async fn handle_cmdi(Query(params): Query<HashMap<String, String>>) -> String {
    let host = params.get("host").cloned().unwrap_or_default();
    if host.contains(';') || host.contains('|') || host.contains('`') || host.contains("$(") {
        format!(
            "PING {host}: 64 bytes from 127.0.0.1\nuid=0(root) gid=0(root) groups=0(root)\n\
             /etc/passwd:\nroot:x:0:0:root:/root:/bin/bash"
        )
    } else {
        format!("PING {host}: 64 bytes from {host}: icmp_seq=1 ttl=64 time=0.04ms")
    }
}

async fn handle_ssti(Query(params): Query<HashMap<String, String>>) -> String {
    let expr = params.get("expr").cloned().unwrap_or_default();
    if expr.contains("{{7*7}}") {
        "49".to_string()
    } else if expr.contains("{{config}}") {
        "SECRET_KEY=s3cr3t_k3y_d0nt_t3ll, DEBUG=True, DATABASE_URI=sqlite:///app.db".to_string()
    } else if expr.contains("{{") && expr.contains("}}") {
        format!("Template output: {expr}")
    } else {
        format!("Hello, {expr}")
    }
}

async fn handle_xxe(body: String) -> Response {
    if body.contains("<!ENTITY") || body.contains("SYSTEM") || body.contains("file://") {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "XML Parse Error: entity expansion detected\n\
                 Resolved content: root:x:0:0:root:/root:/bin/bash\n\
                 Raw input: {body}"
            ),
        )
            .into_response()
    } else {
        format!("Parsed XML: {body}").into_response()
    }
}

async fn handle_path_traversal(Query(params): Query<HashMap<String, String>>) -> Response {
    let path = params.get("path").cloned().unwrap_or_default();
    if path.contains("..") || path.starts_with('/') {
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
         bin:x:2:2:bin:/bin:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"
            .into_response()
    } else {
        format!("File contents of: {path}").into_response()
    }
}

async fn handle_crlf(Query(params): Query<HashMap<String, String>>) -> Response {
    let input = params.get("input").cloned().unwrap_or_default();
    // Deliberately reflect CRLF in the body to simulate header injection
    let body = format!("Set-Cookie: session={input}\r\nX-Injected: true");
    body.into_response()
}

async fn handle_header_inject(Query(params): Query<HashMap<String, String>>) -> Response {
    let val = params.get("value").cloned().unwrap_or_default();
    let mut headers = HeaderMap::new();
    let sanitized = val.replace(['\r', '\n'], "");
    if let Ok(hv) = HeaderValue::from_str(&sanitized) {
        headers.insert("x-custom", hv);
    }
    (headers, format!("Header set to: {val}")).into_response()
}

async fn handle_host_header(headers: HeaderMap) -> String {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    format!(
        r#"<html><body><a href="http://{host}/api/reset-password?token=abc123">Reset Password</a></body></html>"#
    )
}

// A04: Insecure Design

async fn handle_graphql(body: String) -> impl IntoResponse {
    if body.contains("__schema") || body.contains("__type") {
        serde_json::json!({
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "types": [
                        {"name": "User", "fields": [
                            {"name": "id"}, {"name": "email"}, {"name": "password_hash"},
                            {"name": "ssn"}, {"name": "credit_card"}
                        ]}
                    ]
                }
            }
        })
        .to_string()
    } else {
        // Accept deeply nested queries without limits
        serde_json::json!({
            "data": {"user": {"friends": {"friends": {"friends": {"count": 999}}}}}
        })
        .to_string()
    }
}

// A05: Security Misconfiguration

async fn handle_debug() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        serde_json::json!({
            "error": "NullPointerException",
            "stack_trace": [
                "at com.app.service.UserService.getUser(UserService.java:42)",
                "at com.app.controller.ApiController.handle(ApiController.java:15)",
                "at org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:897)"
            ],
            "debug": true,
            "server": "Apache/2.4.49",
            "runtime": "Java/11.0.2",
            "database": "PostgreSQL 13.4",
            "environment": "production"
        })
        .to_string(),
    )
        .into_response()
}

async fn handle_missing_headers() -> Response {
    // Deliberately omit security headers
    let body = r#"<html><body><h1>Welcome</h1><p>No security headers set.</p></body></html>"#;
    (StatusCode::OK, body).into_response()
}

async fn handle_clickjack() -> Html<String> {
    Html(
        r#"<!DOCTYPE html><html><head><title>Account Settings</title></head>
<body><form action="/api/transfer" method="POST">
<input type="hidden" name="to" value="attacker" />
<input type="hidden" name="amount" value="10000" />
<button type="submit">Update Settings</button>
</form></body></html>"#
            .to_string(),
    )
}

// A06: Vulnerable Components

async fn handle_version_leak() -> impl IntoResponse {
    serde_json::json!({
        "app_version": "3.2.1-beta",
        "framework": "Spring Boot 2.5.4",
        "java_version": "11.0.2",
        "os": "Linux 5.4.0-42-generic",
        "dependencies": {
            "log4j": "2.14.1",
            "jackson": "2.12.3",
            "commons-collections": "3.2.1"
        }
    })
    .to_string()
}

// A07: Auth Failures

async fn handle_jwt_none(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let token = params.get("token").cloned().unwrap_or_default();
    // Accept alg:none tokens — simulate the vulnerability
    if token.contains("eyJhbGciOiJub25lIi") || token.is_empty() {
        serde_json::json!({
            "authenticated": true,
            "user": "admin",
            "role": "superuser",
            "message": "Token accepted (alg: none)"
        })
        .to_string()
    } else {
        serde_json::json!({
            "authenticated": true,
            "user": "admin",
            "role": "superuser"
        })
        .to_string()
    }
}

// A08: Integrity Failures

async fn handle_deserialize(body: String) -> Response {
    if body.contains("java.lang.Runtime")
        || body.contains("__reduce__")
        || body.contains("rO0ABX")
        || body.contains("ObjectInputStream")
    {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "java.io.InvalidClassException: Unauthorized deserialization attempt detected\n\
                 Class: {}\nStack: ObjectInputStream.readObject(ObjectInputStream.java:431)",
                body.chars().take(80).collect::<String>()
            ),
        )
            .into_response()
    } else {
        format!("Deserialized object: {body}").into_response()
    }
}

#[derive(Deserialize)]
struct MassAssignBody {
    #[allow(dead_code)]
    name: Option<String>,
    #[allow(dead_code)]
    email: Option<String>,
    is_admin: Option<bool>,
    #[allow(dead_code)]
    role: Option<String>,
}

async fn handle_mass_assign(Json(body): Json<MassAssignBody>) -> impl IntoResponse {
    let is_admin = body.is_admin.unwrap_or(false);
    let role = body.role.clone().unwrap_or("user".to_string());
    serde_json::json!({
        "updated": true,
        "name": body.name,
        "email": body.email,
        "is_admin": is_admin,
        "role": role,
        "message": if is_admin { "Admin privileges granted" } else { "Profile updated" }
    })
    .to_string()
}

// A10: SSRF

async fn handle_ssrf(Query(params): Query<HashMap<String, String>>) -> String {
    let url = params.get("url").cloned().unwrap_or_default();
    if url.contains("169.254.169.254")
        || url.contains("metadata")
        || url.contains("localhost")
        || url.contains("127.0.0.1")
        || url.contains("internal")
    {
        format!(
            "Fetched: {url}\n\
             Response: {{\"ami-id\": \"ami-12345678\", \"instance-type\": \"m5.xlarge\", \
             \"iam-role\": \"arn:aws:iam::123456789012:role/admin-role\"}}"
        )
    } else {
        format!("Fetched: {url}\nResponse: 200 OK")
    }
}

// Additional coverage

async fn handle_prototype_pollution(body: String) -> impl IntoResponse {
    if body.contains("__proto__") || body.contains("constructor") {
        serde_json::json!({
            "merged": true,
            "prototype_modified": true,
            "warning": "Object prototype was modified"
        })
        .to_string()
    } else {
        serde_json::json!({"merged": true}).to_string()
    }
}

async fn handle_cache_poison(headers: HeaderMap) -> Response {
    let x_forwarded = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("cdn.example.com");
    let body = format!(
        r#"<html><head><link rel="stylesheet" href="http://{x_forwarded}/static/style.css"></head>
<body>Cached page</body></html>"#
    );
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        "cache-control",
        HeaderValue::from_static("public, max-age=3600"),
    );
    (resp_headers, Html(body)).into_response()
}

async fn handle_smuggle(body: String) -> Response {
    // Simulate CL/TE desync: accept both Content-Length and Transfer-Encoding
    let response_body = if body.contains("Transfer-Encoding") || body.contains("chunked") {
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nSMUGGLED REQUEST".to_string()
    } else {
        "Request processed normally".to_string()
    };
    response_body.into_response()
}

async fn handle_race() -> impl IntoResponse {
    // Simulate a TOCTOU race on balance check
    serde_json::json!({
        "transaction_id": "txn_abc123",
        "balance_before": 100,
        "amount": 100,
        "balance_after": 0,
        "status": "completed",
        "note": "No mutex on balance check — concurrent requests can overdraw"
    })
    .to_string()
}

async fn handle_input_validation(Query(params): Query<HashMap<String, String>>) -> String {
    let input = params.get("input").cloned().unwrap_or_default();
    // Accept any input without validation
    format!("Processed ({} bytes): {input}", input.len())
}

async fn handle_stored_xss(body: String) -> Html<String> {
    // Store and immediately reflect user content
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<div class="comment">{body}</div>
<p>Comment saved successfully!</p>
</body></html>"#
    ))
}

#[cfg(test)]
#[path = "vulnerable_api_test.rs"]
mod tests;
