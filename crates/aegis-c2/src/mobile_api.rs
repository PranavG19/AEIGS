use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// REST API endpoints exposed by the mobile C2 management interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiEndpoint {
    ListImplants,
    GetImplant,
    SendCommand,
    StreamEvents,
    Authenticate,
}

/// HTTP methods supported by the mobile API router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
}

/// A registered route binding an HTTP method and path pattern to an endpoint handler.
#[derive(Debug, Clone)]
pub struct ApiRoute {
    pub method: HttpMethod,
    pub path: String,
    pub endpoint: ApiEndpoint,
}

/// An incoming API request with method, path, headers, optional body, and query parameters.
#[derive(Debug, Clone)]
pub struct ApiRequest {
    pub method: HttpMethod,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub query_params: HashMap<String, String>,
}

/// An outgoing API response with status code, headers, and JSON body.
#[derive(Debug, Clone)]
pub struct ApiResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// JWT claims embedded in operator authentication tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,
    pub exp: u64,
    pub iat: u64,
    pub role: String,
}

/// Simplified JWT validator that creates and verifies base64-encoded JSON tokens
/// using HMAC-style secret comparison. Suitable for demo/testing without
/// pulling in a full JWT library.
#[derive(Debug, Clone)]
pub struct JwtValidator {
    secret: Vec<u8>,
}

impl JwtValidator {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
        }
    }

    /// Create a base64-encoded JSON token embedding the claims and a keyed signature stub.
    /// The token format is: `base64(json_claims).base64(secret_hash)` where the signature
    /// portion is a simple XOR-fold of the secret bytes (demo only — not cryptographically secure).
    pub fn create_token(&self, operator_id: &str, role: &str) -> String {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let claims = JwtClaims {
            sub: operator_id.to_string(),
            exp: now_ms + 3600,
            iat: now_ms,
            role: role.to_string(),
        };

        let claims_json = serde_json::to_string(&claims).expect("claims serialize");
        let claims_b64 = base64_encode(claims_json.as_bytes());
        let sig = self.compute_signature(claims_json.as_bytes());
        let sig_b64 = base64_encode(&sig);

        format!("{claims_b64}.{sig_b64}")
    }

    /// Validate a token string, returning the decoded claims or an error.
    pub fn validate_token(&self, token: &str) -> Result<JwtClaims, ApiError> {
        let parts: Vec<&str> = token.splitn(2, '.').collect();
        if parts.len() != 2 {
            return Err(ApiError::Unauthorized);
        }

        let claims_bytes = base64_decode(parts[0]).map_err(|_| ApiError::Unauthorized)?;
        let expected_sig = self.compute_signature(&claims_bytes);
        let provided_sig = base64_decode(parts[1]).map_err(|_| ApiError::Unauthorized)?;

        if expected_sig != provided_sig {
            return Err(ApiError::Unauthorized);
        }

        let claims: JwtClaims =
            serde_json::from_slice(&claims_bytes).map_err(|_| ApiError::Unauthorized)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if claims.exp < now {
            return Err(ApiError::Unauthorized);
        }

        Ok(claims)
    }

    fn compute_signature(&self, data: &[u8]) -> Vec<u8> {
        let mut hash = vec![0u8; 32];
        for (i, &byte) in data.iter().enumerate() {
            hash[i % 32] ^= byte;
        }
        for (i, &byte) in self.secret.iter().enumerate() {
            hash[i % 32] ^= byte;
        }
        hash
    }
}

/// Serializable implant data suitable for API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplantData {
    pub id: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub ip: String,
    pub last_seen_ms: u64,
    pub sleep_secs: u64,
    pub status: String,
}

/// Request payload for sending a command to an implant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRequest {
    pub command_type: String,
    pub args: Vec<String>,
}

/// Response payload after queuing a command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    pub command_id: String,
    pub status: String,
    pub queued_at: String,
}

/// A server-sent event for the real-time stream endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEvent {
    pub event_type: String,
    pub timestamp_ms: u64,
    pub data: serde_json::Value,
}

/// Errors returned by mobile API handlers.
#[derive(Debug, Clone)]
pub enum ApiError {
    Unauthorized,
    NotFound,
    BadRequest(String),
    InternalError(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "Unauthorized"),
            Self::NotFound => write!(f, "Not Found"),
            Self::BadRequest(msg) => write!(f, "Bad Request: {msg}"),
            Self::InternalError(msg) => write!(f, "Internal Error: {msg}"),
        }
    }
}

/// Queued command entry stored in the router's command queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct QueuedCommand {
    implant_id: String,
    command: CommandRequest,
    command_id: String,
    queued_at: String,
}

/// Mobile API router that holds route definitions, implant state, and a command queue.
/// All request handling is synchronous — no server runtime required.
#[derive(Debug, Clone)]
pub struct MobileApiRouter {
    routes: Vec<ApiRoute>,
    jwt_validator: JwtValidator,
    implants: Vec<ImplantData>,
    command_queue: Vec<QueuedCommand>,
    next_command_seq: u64,
}

impl MobileApiRouter {
    pub fn new(jwt_secret: &[u8]) -> Self {
        Self {
            routes: Vec::new(),
            jwt_validator: JwtValidator::new(jwt_secret),
            implants: Vec::new(),
            command_queue: Vec::new(),
            next_command_seq: 1,
        }
    }

    /// Register the default C2 mobile API routes.
    pub fn register_default_routes(&mut self) {
        self.routes.push(ApiRoute {
            method: HttpMethod::GET,
            path: "/api/v1/implants".to_string(),
            endpoint: ApiEndpoint::ListImplants,
        });
        self.routes.push(ApiRoute {
            method: HttpMethod::GET,
            path: "/api/v1/implants/{id}".to_string(),
            endpoint: ApiEndpoint::GetImplant,
        });
        self.routes.push(ApiRoute {
            method: HttpMethod::POST,
            path: "/api/v1/implants/{id}/command".to_string(),
            endpoint: ApiEndpoint::SendCommand,
        });
        self.routes.push(ApiRoute {
            method: HttpMethod::GET,
            path: "/api/v1/stream".to_string(),
            endpoint: ApiEndpoint::StreamEvents,
        });
        self.routes.push(ApiRoute {
            method: HttpMethod::POST,
            path: "/api/v1/auth".to_string(),
            endpoint: ApiEndpoint::Authenticate,
        });
    }

    /// Add an implant to the router's tracked state.
    pub fn add_implant(&mut self, data: ImplantData) {
        self.implants.push(data);
    }

    /// Route an incoming request to the appropriate handler and return a response.
    pub fn handle_request(&mut self, request: &ApiRequest) -> ApiResponse {
        let matched = self.match_route(&request.method, &request.path);

        let Some((endpoint, params)) = matched else {
            return ApiResponse {
                status_code: 404,
                headers: json_headers(),
                body: r#"{"error":"Not Found"}"#.to_string(),
            };
        };

        match endpoint {
            ApiEndpoint::ListImplants => self.handle_list_implants(),
            ApiEndpoint::GetImplant => {
                let id = params.get("id").cloned().unwrap_or_default();
                self.handle_get_implant(&id)
            }
            ApiEndpoint::SendCommand => {
                let id = params.get("id").cloned().unwrap_or_default();
                let body = request.body.as_deref().unwrap_or("");
                self.handle_send_command(&id, body)
            }
            ApiEndpoint::StreamEvents => ApiResponse {
                status_code: 200,
                headers: json_headers(),
                body: serde_json::to_string(&Vec::<StreamEvent>::new())
                    .unwrap_or_else(|_| "[]".to_string()),
            },
            ApiEndpoint::Authenticate => {
                let body = request.body.as_deref().unwrap_or("");
                self.handle_authenticate(body)
            }
        }
    }

    /// Return a JSON array of all tracked implants.
    pub fn handle_list_implants(&self) -> ApiResponse {
        let body = serde_json::to_string(&self.implants).unwrap_or_else(|_| "[]".to_string());
        ApiResponse {
            status_code: 200,
            headers: json_headers(),
            body,
        }
    }

    /// Return a single implant by ID, or 404.
    pub fn handle_get_implant(&self, id: &str) -> ApiResponse {
        match self.implants.iter().find(|imp| imp.id == id) {
            Some(implant) => {
                let body = serde_json::to_string(implant).unwrap_or_else(|_| "{}".to_string());
                ApiResponse {
                    status_code: 200,
                    headers: json_headers(),
                    body,
                }
            }
            None => ApiResponse {
                status_code: 404,
                headers: json_headers(),
                body: r#"{"error":"Implant not found"}"#.to_string(),
            },
        }
    }

    /// Parse a command request body, queue the command, and return an acknowledgement.
    pub fn handle_send_command(&mut self, implant_id: &str, body: &str) -> ApiResponse {
        if !self.implants.iter().any(|imp| imp.id == implant_id) {
            return ApiResponse {
                status_code: 404,
                headers: json_headers(),
                body: r#"{"error":"Implant not found"}"#.to_string(),
            };
        }

        let cmd_req: CommandRequest = match serde_json::from_str(body) {
            Ok(c) => c,
            Err(e) => {
                return ApiResponse {
                    status_code: 400,
                    headers: json_headers(),
                    body: serde_json::json!({"error": format!("Bad request: {e}")}).to_string(),
                };
            }
        };

        let command_id = format!("cmd-{:06}", self.next_command_seq);
        self.next_command_seq += 1;

        let queued_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let queued = QueuedCommand {
            implant_id: implant_id.to_string(),
            command: cmd_req,
            command_id: command_id.clone(),
            queued_at: queued_at.clone(),
        };
        self.command_queue.push(queued);

        let resp = CommandResponse {
            command_id,
            status: "queued".to_string(),
            queued_at,
        };

        ApiResponse {
            status_code: 201,
            headers: json_headers(),
            body: serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()),
        }
    }

    /// Validate credentials in the request body and return a JWT token on success.
    /// Expected body: `{"operator_id": "...", "password": "...", "role": "..."}`.
    pub fn handle_authenticate(&self, body: &str) -> ApiResponse {
        #[derive(Deserialize)]
        struct AuthPayload {
            operator_id: String,
            password: String,
            #[serde(default = "default_role")]
            role: String,
        }

        fn default_role() -> String {
            "operator".to_string()
        }

        let payload: AuthPayload = match serde_json::from_str(body) {
            Ok(p) => p,
            Err(e) => {
                return ApiResponse {
                    status_code: 400,
                    headers: json_headers(),
                    body: serde_json::json!({"error": format!("Bad request: {e}")}).to_string(),
                };
            }
        };

        if payload.password.len() < 8 {
            return ApiResponse {
                status_code: 401,
                headers: json_headers(),
                body: r#"{"error":"Invalid credentials"}"#.to_string(),
            };
        }

        let token = self
            .jwt_validator
            .create_token(&payload.operator_id, &payload.role);

        ApiResponse {
            status_code: 200,
            headers: json_headers(),
            body: serde_json::json!({"token": token}).to_string(),
        }
    }

    /// Match an incoming method + path against registered routes. Supports `{id}`
    /// placeholders — extracted path parameters are returned in the HashMap.
    pub fn match_route(
        &self,
        method: &HttpMethod,
        path: &str,
    ) -> Option<(ApiEndpoint, HashMap<String, String>)> {
        let req_segments: Vec<&str> = path.trim_matches('/').split('/').collect();

        for route in &self.routes {
            if &route.method != method {
                continue;
            }

            let route_segments: Vec<&str> = route.path.trim_matches('/').split('/').collect();
            if route_segments.len() != req_segments.len() {
                continue;
            }

            let mut params = HashMap::new();
            let mut matched = true;

            for (pat, actual) in route_segments.iter().zip(req_segments.iter()) {
                if pat.starts_with('{') && pat.ends_with('}') {
                    let key = &pat[1..pat.len() - 1];
                    params.insert(key.to_string(), actual.to_string());
                } else if pat != actual {
                    matched = false;
                    break;
                }
            }

            if matched {
                return Some((route.endpoint.clone(), params));
            }
        }

        None
    }
}

fn json_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("Content-Type".to_string(), "application/json".to_string());
    h
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u32, String> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err(format!("invalid base64 char: {c}")),
        }
    }

    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("base64 length not multiple of 4".to_string());
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for quad in bytes.chunks(4) {
        let v0 = val(quad[0])?;
        let v1 = val(quad[1])?;
        let v2 = val(quad[2])?;
        let v3 = val(quad[3])?;
        let triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;

        out.push(((triple >> 16) & 0xFF) as u8);
        if quad[2] != b'=' {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if quad[3] != b'=' {
            out.push((triple & 0xFF) as u8);
        }
    }

    Ok(out)
}
