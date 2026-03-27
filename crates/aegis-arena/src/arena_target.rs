use axum::Router;
use axum::body::Body;
use axum::extract::{Json, Path, Query, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

/// A rule that Blue can apply to block malicious requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchRule {
    /// Endpoint path this rule applies to, e.g. "/search"
    pub endpoint: String,
    /// String or regex pattern to match against the full query/body
    pub block_pattern: String,
    /// Whether block_pattern is a regex
    pub is_regex: bool,
}

impl PatchRule {
    pub fn new(endpoint: &str, pattern: &str, is_regex: bool) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            block_pattern: pattern.to_string(),
            is_regex,
        }
    }

    /// Check if a request URI + body matches this patch rule.
    pub fn matches(&self, uri_path: &str, raw_request: &str) -> bool {
        if !uri_path.starts_with(&self.endpoint) {
            return false;
        }
        if self.is_regex {
            if let Ok(re) = Regex::new(&self.block_pattern) {
                return re.is_match(raw_request);
            }
            false
        } else {
            raw_request.contains(&self.block_pattern)
        }
    }
}

/// Shared arena state accessible by all handlers.
#[derive(Clone)]
pub struct ArenaState {
    pub flag: String,
    pub patches: Vec<PatchRule>,
    pub request_log: Arc<Mutex<Vec<RequestLogEntry>>>,
    pub stored_comments: Arc<Mutex<Vec<String>>>,
}

/// A logged HTTP request/response pair for Blue to analyze.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLogEntry {
    pub method: String,
    pub path: String,
    pub query_string: String,
    pub body: String,
    pub status: u16,
    pub response_body: String,
}

/// Middleware that checks all patches before routing to handlers.
async fn patch_middleware(
    State(state): State<ArenaState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let uri = request.uri().clone();
    let path = uri.path().to_string();
    let query_raw = uri.query().unwrap_or("");

    // URL-decode the query string so patches match decoded content
    let query_decoded = percent_decode(query_raw);
    let full_request_str = format!("{path}?{query_decoded}");

    // /health always passes through
    if path == "/health" {
        return next.run(request).await;
    }

    for patch in &state.patches {
        if patch.matches(&path, &full_request_str) {
            return (
                StatusCode::FORBIDDEN,
                format!("Blocked by Blue's patch: {}", patch.block_pattern),
            )
                .into_response();
        }
    }

    next.run(request).await
}

/// Simple percent-decoding for query strings.
fn percent_decode(input: &str) -> String {
    let mut result = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(
                &String::from_utf8_lossy(&bytes[i + 1..i + 3]),
                16,
            ) {
                result.push(byte);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).to_string()
}

/// Build the arena router with all vulnerable endpoints.
pub fn build_arena_router(flag: String, patches: Vec<PatchRule>) -> (Router, Arc<Mutex<Vec<RequestLogEntry>>>) {
    let request_log = Arc::new(Mutex::new(Vec::new()));
    let stored_comments = Arc::new(Mutex::new(Vec::new()));

    let state = ArenaState {
        flag,
        patches,
        request_log: Arc::clone(&request_log),
        stored_comments,
    };

    let router = Router::new()
        .route("/search", get(handle_search))
        .route("/login", post(handle_login))
        .route("/profile/{id}", get(handle_profile))
        .route("/comment", post(handle_comment))
        .route("/comments", get(handle_comments))
        .route("/template", post(handle_template))
        .route("/admin", get(handle_admin))
        .route("/flag", get(handle_flag))
        .route("/file", get(handle_file))
        .route("/health", get(handle_health))
        .layer(middleware::from_fn_with_state(state.clone(), patch_middleware))
        .with_state(state);

    (router, request_log)
}

/// Start the arena target on a given port. Returns a JoinHandle for the server
/// and a reference to the request log.
pub async fn start_arena_target(
    port: u16,
    flag: &str,
    patches: &[PatchRule],
) -> Result<(tokio::task::JoinHandle<()>, Arc<Mutex<Vec<RequestLogEntry>>>), std::io::Error> {
    let (router, request_log) = build_arena_router(flag.to_string(), patches.to_vec());
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    // Give server a moment to bind
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    Ok((handle, request_log))
}

// ─── Handlers ───────────────────────────────────────────────────────────────

/// GET /search?q=<input> — SQL injection via query concatenation
async fn handle_search(
    State(state): State<ArenaState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let q = params.get("q").cloned().unwrap_or_default();
    let query = format!("SELECT * FROM items WHERE name = '{q}'");

    let (status, body) = if q.contains('\'') || q.to_uppercase().contains("OR ")
        || q.contains("--") || q.to_uppercase().contains("UNION ")
    {
        // SQLi detected — leak flag in "error" like a real vulnerable app would leak data
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "SQL Error in query: {query}\nDatabase returned: secret_flag={}\n",
                state.flag
            ),
        )
    } else {
        (StatusCode::OK, format!("Results for: {q}"))
    };

    log_request(&state, "GET", "/search", &format!("q={q}"), "", status.as_u16(), &body);
    (status, body).into_response()
}

/// POST /login — SQL injection in authentication
async fn handle_login(
    State(state): State<ArenaState>,
    Json(payload): Json<HashMap<String, String>>,
) -> Response {
    let username = payload.get("username").cloned().unwrap_or_default();
    let password = payload.get("password").cloned().unwrap_or_default();
    let query = format!(
        "SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    );

    let (status, body) = if username.contains('\'') || password.contains('\'')
        || username.to_uppercase().contains("OR ")
        || password.to_uppercase().contains("OR ")
    {
        (
            StatusCode::OK,
            serde_json::json!({
                "authenticated": true,
                "user": "admin",
                "token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.",
                "debug_query": query,
                "flag": state.flag
            }).to_string(),
        )
    } else if username == "admin" && password == "admin" {
        (
            StatusCode::OK,
            serde_json::json!({"authenticated": true, "user": "admin"}).to_string(),
        )
    } else {
        (
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"authenticated": false, "error": "Invalid credentials"}).to_string(),
        )
    };

    let req_body = serde_json::to_string(&payload).unwrap_or_default();
    log_request(&state, "POST", "/login", "", &req_body, status.as_u16(), &body);
    (status, body).into_response()
}

/// GET /profile/{id} — IDOR, any ID returns data
async fn handle_profile(
    State(state): State<ArenaState>,
    Path(id): Path<String>,
) -> Response {
    let body = serde_json::json!({
        "id": id,
        "name": "Admin User",
        "email": "admin@aegis.local",
        "role": "superuser",
        "secret_note": format!("Flag backup: {}", state.flag),
    })
    .to_string();

    log_request(&state, "GET", &format!("/profile/{id}"), "", "", 200, &body);
    body.into_response()
}

/// POST /comment — stored XSS
async fn handle_comment(
    State(state): State<ArenaState>,
    Json(payload): Json<HashMap<String, String>>,
) -> Response {
    let comment = payload.get("comment").cloned().unwrap_or_default();

    if let Ok(mut comments) = state.stored_comments.lock() {
        comments.push(comment.clone());
    }

    let body = serde_json::json!({"stored": true, "comment": comment}).to_string();
    let req_body = serde_json::to_string(&payload).unwrap_or_default();
    log_request(&state, "POST", "/comment", "", &req_body, 200, &body);
    body.into_response()
}

/// GET /comments — displays stored comments (XSS reflected)
async fn handle_comments(State(state): State<ArenaState>) -> Html<String> {
    let comments = state
        .stored_comments
        .lock()
        .map(|c| c.clone())
        .unwrap_or_default();

    let html = comments
        .iter()
        .map(|c| format!("<div class=\"comment\">{c}</div>"))
        .collect::<Vec<_>>()
        .join("\n");

    Html(format!(
        "<html><body><h1>Comments</h1>{html}</body></html>"
    ))
}

/// POST /template — SSTI
async fn handle_template(
    State(state): State<ArenaState>,
    Json(payload): Json<HashMap<String, String>>,
) -> Response {
    let template = payload.get("template").cloned().unwrap_or_default();

    let body = if template.contains("{{") && template.contains("}}") {
        // Extract expression between {{ and }}
        if let (Some(start), Some(end)) = (template.find("{{"), template.find("}}")) {
            let expr = &template[start + 2..end];
            if expr.contains("flag") || expr.contains("config") || expr.contains("env") {
                format!("Rendered: {}", state.flag)
            } else if expr.trim() == "7*7" {
                "Rendered: 49".to_string()
            } else {
                format!("Rendered: {expr}")
            }
        } else {
            format!("Output: {template}")
        }
    } else if template.contains("{%") {
        format!("Template executed: {}", state.flag)
    } else {
        format!("Output: {template}")
    };

    let req_body = serde_json::to_string(&payload).unwrap_or_default();
    log_request(&state, "POST", "/template", "", &req_body, 200, &body);
    body.into_response()
}

/// GET /admin — JWT alg:none bypass
async fn handle_admin(
    State(state): State<ArenaState>,
    headers: HeaderMap,
) -> Response {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let (status, body) = if auth.is_empty() {
        (
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": "Authorization header required. Use Bearer <JWT>"}).to_string(),
        )
    } else if is_jwt_alg_none_bypass(auth) || auth.contains("admin") {
        // Vulnerable: accepts alg:none JWTs or any token containing "admin"
        (
            StatusCode::OK,
            serde_json::json!({
                "admin": true,
                "panel": "Admin Control Panel",
                "users_count": 1337,
                "flag_hint": "Try /flag with this same token",
            })
            .to_string(),
        )
    } else {
        (
            StatusCode::FORBIDDEN,
            serde_json::json!({"error": "Not authorized as admin"}).to_string(),
        )
    };

    log_request(&state, "GET", "/admin", "", "", status.as_u16(), &body);
    (status, body).into_response()
}

/// GET /flag — returns flag if authenticated as admin
async fn handle_flag(
    State(state): State<ArenaState>,
    headers: HeaderMap,
) -> Response {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let (status, body) = if auth.is_empty() {
        (
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": "Authentication required"}).to_string(),
        )
    } else if is_jwt_alg_none_bypass(auth) || auth.contains("admin") {
        (StatusCode::OK, serde_json::json!({"flag": state.flag}).to_string())
    } else {
        (
            StatusCode::FORBIDDEN,
            serde_json::json!({"error": "Admin access required"}).to_string(),
        )
    };

    log_request(&state, "GET", "/flag", "", "", status.as_u16(), &body);
    (status, body).into_response()
}

/// GET /file?path=<input> — path traversal / LFI
async fn handle_file(
    State(state): State<ArenaState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let path = params.get("path").cloned().unwrap_or_default();

    let (status, body) = if path.contains("..") || path.starts_with('/') {
        // LFI successful — leak flag in "file contents"
        (
            StatusCode::OK,
            format!(
                "root:x:0:0:root:/root:/bin/bash\n# FLAG={}\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
                state.flag
            ),
        )
    } else if path.is_empty() {
        (StatusCode::BAD_REQUEST, "Missing 'path' parameter".to_string())
    } else {
        (StatusCode::OK, format!("Contents of {path}: [file data]"))
    };

    log_request(&state, "GET", "/file", &format!("path={path}"), "", status.as_u16(), &body);
    (status, body).into_response()
}

/// GET /health — always 200
async fn handle_health() -> &'static str {
    "ok"
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Check if an Authorization header contains a JWT with alg:none bypass.
fn is_jwt_alg_none_bypass(auth: &str) -> bool {
    let token = auth.strip_prefix("Bearer ").unwrap_or(auth);
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return false;
    }

    // Try to decode the header
    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    if let Ok(decoded) = engine.decode(parts[0]) {
        if let Ok(header_str) = String::from_utf8(decoded) {
            let lower = header_str.to_lowercase();
            return lower.contains("\"alg\"") && lower.contains("\"none\"");
        }
    }
    false
}

/// Append a request/response pair to the shared log.
fn log_request(
    state: &ArenaState,
    method: &str,
    path: &str,
    query: &str,
    body: &str,
    status: u16,
    response_body: &str,
) {
    if let Ok(mut log) = state.request_log.lock() {
        log.push(RequestLogEntry {
            method: method.to_string(),
            path: path.to_string(),
            query_string: query.to_string(),
            body: body.to_string(),
            status,
            response_body: response_body.to_string(),
        });
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "arena_target_test.rs"]
mod arena_target_test;
