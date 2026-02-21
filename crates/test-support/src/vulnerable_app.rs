use aegis_protocol::finding::VulnerabilityClass;
use axum::Router;
use axum::extract::Query;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use std::collections::HashMap;

/// A single expected vulnerability at a specific endpoint.
///
/// Mirrors `aegis_orchestrator::benchmark::GroundTruthEntry` — defined locally
/// to avoid pulling the full orchestrator dependency tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroundTruthEntry {
    pub endpoint: String,
    pub vulnerability_class: VulnerabilityClass,
}

/// The complete set of expected vulnerabilities for a test fixture.
///
/// Mirrors `aegis_orchestrator::benchmark::GroundTruth`.
#[derive(Debug, Clone)]
pub struct GroundTruth {
    pub entries: Vec<GroundTruthEntry>,
}

/// A fully configured vulnerable application ready to build into a `Router`.
pub struct VulnerableApp;

impl VulnerableApp {
    pub fn builder() -> VulnerableAppBuilder {
        VulnerableAppBuilder::default()
    }
}

/// Declarative builder for a vulnerable test application.
///
/// Each `with_*` method registers a deliberately vulnerable endpoint and
/// records the corresponding ground truth entry.
#[derive(Default)]
pub struct VulnerableAppBuilder {
    router: Router,
    ground_truth: Vec<GroundTruthEntry>,
}

impl VulnerableAppBuilder {
    /// Builds the final router and ground truth manifest.
    pub fn build(self) -> (Router, GroundTruth) {
        (
            self.router,
            GroundTruth {
                entries: self.ground_truth,
            },
        )
    }

    /// SQL injection endpoint. Concatenates the `input` query param into a
    /// fake SQL string and returns an error message when injection metacharacters
    /// are detected.
    pub fn with_sqli(mut self, path: &str) -> Self {
        self.ground_truth.push(GroundTruthEntry {
            endpoint: path.to_string(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
        });
        self.router = self.router.route(path, get(handle_sqli));
        self
    }

    /// XSS endpoint. Reflects the `input` query param directly in an HTML
    /// body without escaping.
    pub fn with_xss(mut self, path: &str) -> Self {
        self.ground_truth.push(GroundTruthEntry {
            endpoint: path.to_string(),
            vulnerability_class: VulnerabilityClass::CrossSiteScripting,
        });
        self.router = self.router.route(path, get(handle_xss));
        self
    }

    /// Command injection endpoint. Echoes command output patterns when shell
    /// metacharacters appear in the `cmd` query param.
    pub fn with_command_injection(mut self, path: &str) -> Self {
        self.ground_truth.push(GroundTruthEntry {
            endpoint: path.to_string(),
            vulnerability_class: VulnerabilityClass::CommandInjection,
        });
        self.router = self.router.route(path, get(handle_command_injection));
        self
    }

    /// Path traversal endpoint. Returns file contents based on the `file`
    /// query param, including sensitive paths like `/etc/passwd`.
    pub fn with_path_traversal(mut self, path: &str) -> Self {
        self.ground_truth.push(GroundTruthEntry {
            endpoint: path.to_string(),
            vulnerability_class: VulnerabilityClass::PathTraversal,
        });
        self.router = self.router.route(path, get(handle_path_traversal));
        self
    }

    /// SSRF endpoint. Accepts a `url` query param and pretends to fetch it,
    /// returning the target URL in the response body.
    pub fn with_ssrf(mut self, path: &str) -> Self {
        self.ground_truth.push(GroundTruthEntry {
            endpoint: path.to_string(),
            vulnerability_class: VulnerabilityClass::ServerSideRequestForgery,
        });
        self.router = self.router.route(path, get(handle_ssrf));
        self
    }

    /// SSTI endpoint. Evaluates simple template expressions like `{{7*7}}`
    /// and returns the computed result.
    pub fn with_ssti(mut self, path: &str) -> Self {
        self.ground_truth.push(GroundTruthEntry {
            endpoint: path.to_string(),
            vulnerability_class: VulnerabilityClass::ServerSideTemplateInjection,
        });
        self.router = self.router.route(path, get(handle_ssti));
        self
    }

    /// Broken authentication endpoint. Returns sensitive data without
    /// requiring any authentication token.
    pub fn with_broken_auth(mut self, path: &str) -> Self {
        self.ground_truth.push(GroundTruthEntry {
            endpoint: path.to_string(),
            vulnerability_class: VulnerabilityClass::BrokenAuthentication,
        });
        self.router = self.router.route(path, get(handle_broken_auth));
        self
    }

    /// Broken authorization endpoint. Returns data for any user ID without
    /// checking ownership.
    pub fn with_broken_authz(mut self, path: &str) -> Self {
        self.ground_truth.push(GroundTruthEntry {
            endpoint: path.to_string(),
            vulnerability_class: VulnerabilityClass::BrokenAuthorization,
        });
        self.router = self.router.route(path, get(handle_broken_authz));
        self
    }

    /// IDOR endpoint. Returns sensitive data for any numeric `id` query param.
    pub fn with_idor(mut self, path: &str) -> Self {
        self.ground_truth.push(GroundTruthEntry {
            endpoint: path.to_string(),
            vulnerability_class: VulnerabilityClass::BrokenAuthorization,
        });
        self.router = self.router.route(path, get(handle_idor));
        self
    }

    /// Open redirect endpoint. Redirects to the URL specified in the `url`
    /// query param without validation.
    pub fn with_open_redirect(mut self, path: &str) -> Self {
        self.ground_truth.push(GroundTruthEntry {
            endpoint: path.to_string(),
            vulnerability_class: VulnerabilityClass::OpenRedirect,
        });
        self.router = self.router.route(path, get(handle_open_redirect));
        self
    }

    /// Header injection endpoint. Sets a response header from user-supplied
    /// `header_value` query param.
    pub fn with_header_injection(mut self, path: &str) -> Self {
        self.ground_truth.push(GroundTruthEntry {
            endpoint: path.to_string(),
            vulnerability_class: VulnerabilityClass::HeaderInjection,
        });
        self.router = self.router.route(path, get(handle_header_injection));
        self
    }

    /// CRLF injection endpoint. Injects the `input` query param value into
    /// a response header, allowing CRLF sequences.
    pub fn with_crlf_injection(mut self, path: &str) -> Self {
        self.ground_truth.push(GroundTruthEntry {
            endpoint: path.to_string(),
            vulnerability_class: VulnerabilityClass::CrlfInjection,
        });
        self.router = self.router.route(path, get(handle_crlf_injection));
        self
    }

    /// Sensitive data exposure endpoint. Returns PII and credentials in the
    /// response body.
    pub fn with_sensitive_data(mut self, path: &str) -> Self {
        self.ground_truth.push(GroundTruthEntry {
            endpoint: path.to_string(),
            vulnerability_class: VulnerabilityClass::SensitiveDataExposure,
        });
        self.router = self.router.route(path, get(handle_sensitive_data));
        self
    }

    /// Security misconfiguration endpoint. Exposes debug info and stack
    /// traces in the response.
    pub fn with_security_misconfig(mut self, path: &str) -> Self {
        self.ground_truth.push(GroundTruthEntry {
            endpoint: path.to_string(),
            vulnerability_class: VulnerabilityClass::SecurityMisconfiguration,
        });
        self.router = self.router.route(path, get(handle_security_misconfig));
        self
    }

    /// Insecure deserialization endpoint. Accepts serialized objects in the
    /// `data` query param and echoes deserialization results.
    pub fn with_deserialization(mut self, path: &str) -> Self {
        self.ground_truth.push(GroundTruthEntry {
            endpoint: path.to_string(),
            vulnerability_class: VulnerabilityClass::InsecureDeserialization,
        });
        self.router = self.router.route(path, get(handle_deserialization));
        self
    }

    /// Insufficient input validation endpoint. Accepts any input without
    /// length or format checks.
    pub fn with_input_validation(mut self, path: &str) -> Self {
        self.ground_truth.push(GroundTruthEntry {
            endpoint: path.to_string(),
            vulnerability_class: VulnerabilityClass::InsufficientInputValidation,
        });
        self.router = self.router.route(path, get(handle_input_validation));
        self
    }

    /// Health check endpoint at `/health` returning 200 "ok".
    pub fn with_health(mut self) -> Self {
        self.router = self.router.route("/health", get(|| async { "ok" }));
        self
    }

    /// Serves an OpenAPI spec at `/openapi.json`.
    pub fn with_openapi_spec(mut self, spec_json: &str) -> Self {
        let spec = spec_json.to_string();
        self.router = self.router.route(
            "/openapi.json",
            get(move || {
                let body = spec.clone();
                async move {
                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "application/json".to_string(),
                        )],
                        body,
                    )
                }
            }),
        );
        self
    }

    /// Serves a GraphQL endpoint with introspection enabled.
    pub fn with_graphql_introspection(mut self, schema: &str) -> Self {
        let schema_json = schema.to_string();
        self.router = self.router.route(
            "/graphql",
            get(move || {
                let body = schema_json.clone();
                async move {
                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "application/json".to_string(),
                        )],
                        body,
                    )
                }
            }),
        );
        self
    }

    /// Serves a GraphQL endpoint that rejects introspection with field hints.
    pub fn with_graphql_no_introspection(mut self) -> Self {
        self.router = self.router.route(
            "/graphql",
            get(|| async {
                (
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({
                        "errors": [{
                            "message": "Introspection is disabled. Available fields: user, product, order"
                        }]
                    })
                    .to_string(),
                )
            }),
        );
        self
    }
}

async fn handle_sqli(Query(params): Query<HashMap<String, String>>) -> Response {
    let input = params.get("input").cloned().unwrap_or_default();
    let query = format!("SELECT * FROM users WHERE name = '{input}'");
    if input.contains('\'') || input.contains("--") || input.contains("OR ") {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error: syntax error in SQL query: {query}"),
        )
            .into_response()
    } else {
        format!("Query OK: {query}").into_response()
    }
}

async fn handle_xss(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let input = params.get("input").cloned().unwrap_or_default();
    Html(format!("<html><body><p>Hello, {input}</p></body></html>"))
}

async fn handle_command_injection(Query(params): Query<HashMap<String, String>>) -> String {
    let cmd = params.get("cmd").cloned().unwrap_or_default();
    if cmd.contains(';') || cmd.contains('|') || cmd.contains('`') {
        format!("uid=0(root) gid=0(root)\n/bin/sh: executed: {cmd}")
    } else {
        format!("Processed: {cmd}")
    }
}

async fn handle_path_traversal(Query(params): Query<HashMap<String, String>>) -> Response {
    let file = params.get("file").cloned().unwrap_or_default();
    if file.contains("..") || file.starts_with('/') {
        "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"
            .to_string()
            .into_response()
    } else {
        format!("Contents of {file}").into_response()
    }
}

async fn handle_ssrf(Query(params): Query<HashMap<String, String>>) -> String {
    let url = params.get("url").cloned().unwrap_or_default();
    format!("Fetched content from: {url}\nResponse: 200 OK")
}

async fn handle_ssti(Query(params): Query<HashMap<String, String>>) -> String {
    let template = params.get("template").cloned().unwrap_or_default();
    if template.contains("{{7*7}}") {
        "49".to_string()
    } else if template.contains("{{") && template.contains("}}") {
        format!("Template rendered: {template}")
    } else {
        format!("Output: {template}")
    }
}

async fn handle_broken_auth() -> impl IntoResponse {
    serde_json::json!({
        "user": "admin",
        "role": "superuser",
        "api_key": "sk-secret-admin-key-12345"
    })
    .to_string()
}

async fn handle_broken_authz(Query(params): Query<HashMap<String, String>>) -> String {
    let user_id = params.get("user_id").cloned().unwrap_or("1".to_string());
    serde_json::json!({
        "user_id": user_id,
        "email": format!("user{user_id}@example.com"),
        "ssn": "123-45-6789",
        "balance": 50000
    })
    .to_string()
}

async fn handle_idor(Query(params): Query<HashMap<String, String>>) -> String {
    let id = params.get("id").cloned().unwrap_or("1".to_string());
    serde_json::json!({
        "id": id,
        "name": "Confidential Document",
        "content": "Sensitive internal data for record {id}",
        "classification": "TOP SECRET"
    })
    .to_string()
}

async fn handle_open_redirect(Query(params): Query<HashMap<String, String>>) -> Response {
    let url = params.get("url").cloned().unwrap_or("/".to_string());
    Redirect::temporary(&url).into_response()
}

async fn handle_header_injection(Query(params): Query<HashMap<String, String>>) -> Response {
    let value = params.get("header_value").cloned().unwrap_or_default();
    let mut headers = HeaderMap::new();
    if let Ok(hv) = HeaderValue::from_str(&value) {
        headers.insert("X-Custom-Header", hv);
    }
    (headers, "ok").into_response()
}

async fn handle_crlf_injection(Query(params): Query<HashMap<String, String>>) -> Response {
    let input = params.get("input").cloned().unwrap_or_default();
    let sanitized = input.replace(['\r', '\n'], "");
    let mut headers = HeaderMap::new();
    if let Ok(hv) = HeaderValue::from_str(&sanitized) {
        headers.insert("X-Injected", hv);
    }
    let body = format!("Set-Cookie: session={input}");
    (headers, body).into_response()
}

async fn handle_sensitive_data() -> impl IntoResponse {
    serde_json::json!({
        "database_url": "postgresql://admin:password123@db.internal:5432/prod",
        "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "users": [
            {"email": "alice@example.com", "ssn": "123-45-6789"},
            {"email": "bob@example.com", "ssn": "987-65-4321"}
        ]
    })
    .to_string()
}

async fn handle_security_misconfig() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        serde_json::json!({
            "error": "NullPointerException",
            "stack_trace": "at com.app.UserService.getUser(UserService.java:42)\nat com.app.Controller.handle(Controller.java:15)",
            "debug_mode": true,
            "server_version": "Apache/2.4.49",
            "php_version": "7.4.3"
        })
        .to_string(),
    )
        .into_response()
}

async fn handle_deserialization(Query(params): Query<HashMap<String, String>>) -> Response {
    let data = params.get("data").cloned().unwrap_or_default();
    if data.contains("java.lang.Runtime") || data.contains("__reduce__") || data.contains("rO0ABX")
    {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Deserialization error: unexpected class in stream: {data}"),
        )
            .into_response()
    } else {
        format!("Deserialized: {data}").into_response()
    }
}

async fn handle_input_validation(Query(params): Query<HashMap<String, String>>) -> String {
    let input = params.get("input").cloned().unwrap_or_default();
    format!("Accepted input ({} bytes): {input}", input.len())
}
