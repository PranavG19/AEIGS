<!-- metadata:
  crate: aegis-enumeration
  purpose: Endpoint discovery and API surface mapping via source parsing, OpenAPI/GraphQL introspection,
           authorization matrix testing, and multi-step auth flow modeling
  public_api: DiscoveredRoute, HttpMethod, Framework, RouteParseError,
              parse_routes_from_file(), parse_routes_from_source(),
              IntrospectedEndpoint, EndpointParameter, ParameterLocation, IntrospectionError,
              parse_openapi_json(), parse_graphql_introspection(), parse_graphql_sdl(),
              Credential, PrivilegeLevel, EndpointAccess, AuthorizationAnomaly, AnomalyType,
              AuthorizationMatrix,
              COMMON_QUERY_FIELDS, COMMON_MUTATION_FIELDS, COMMON_ARGUMENTS,
              DiscoveryMethod, GraphQlDiscoveryResult, DiscoveryError,
              extract_fields_from_error(), build_probe_queries(),
              discover_from_error_responses(), discover_common_fields(), merge_discovery_results(),
              AuthFlow, AuthFlowStep, AuthFlowState, AuthFlowVulnerability, AuthFlowFinding,
              ResponseExtraction, ExtractionSource, AuthFlowError,
              render_template(), extract_value(), validate_auth_flow(),
              detect_session_fixation(), detect_weak_session_id(), detect_insecure_cookie(),
              common_auth_flows()
  modules: route_parser, introspection, auth_matrix, graphql_discovery, auth_flow
  dependencies: aegis-protocol, aegis-knowledge-graph, serde, serde_json, tracing,
                reqwest, tokio, openapiv3, graphql-parser
-->

# aegis-enumeration

## Purpose

`aegis-enumeration` maps the attack surface of the target application by discovering its API
endpoints and authentication mechanisms. It works at three layers: static source analysis
(parsing route definitions from framework-specific syntax), schema-based introspection (OpenAPI
3.x and GraphQL SDL/introspection JSON), and dynamic authorization matrix construction (sending
requests with different credential privilege levels to identify authorization anomalies). A fourth
module handles GraphQL fallback discovery when introspection is disabled. A fifth module models
multi-step authentication flows for detecting session management vulnerabilities. The outputs of
this phase feed directly into the fuzzing scheduler as `FuzzTarget` entries.

## Crate Type

Library

## Dependencies on Workspace Crates

- `aegis-protocol` — `VulnerabilityClass`, `ModuleIdentifier`, `OperationLogEntry`
- `aegis-knowledge-graph` — `GraphStore` trait for writing discovered endpoints

## External Dependencies

| Dependency | Version | Role |
|---|---|---|
| serde | 1 | Derives on auth flow types |
| serde_json | 1 | OpenAPI/introspection JSON parsing; GraphQL error JSON parsing |
| tracing | 0.1 | Diagnostic spans |
| reqwest | 0.12 | HTTP requests for live introspection (async) |
| tokio | 1 | Async runtime for HTTP requests |
| openapiv3 | 2 | Spec-compliant OpenAPI 3.x parsing |
| graphql-parser | 0.4 | GraphQL SDL parsing; introspection response processing |

## Module Structure

| Module | Responsibility |
|---|---|
| `route_parser` | Static source analysis for Express, Flask, FastAPI, Django, Spring; `DiscoveredRoute`, `HttpMethod`, `Framework` |
| `introspection` | OpenAPI JSON and GraphQL SDL/introspection parsing; `IntrospectedEndpoint`, `EndpointParameter`, `ParameterLocation` |
| `auth_matrix` | Multi-credential authorization matrix; `AuthorizationMatrix`, anomaly detection |
| `graphql_discovery` | Fallback GraphQL field discovery when introspection disabled |
| `auth_flow` | Multi-step auth flow definitions, template rendering, vulnerability detection |

## Public API Summary

### route_parser

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredRoute {
    pub path_pattern: String,
    pub http_method: HttpMethod,
    pub handler_name: Option<String>,
    pub framework: Framework,
    pub source_file: String,
    pub line_number: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod { Get, Post, Put, Delete, Patch, Options, Head, Any }
impl Display for HttpMethod { ... }  // "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "ANY"

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Framework { Express, Flask, Django, FastApi, Spring, Rails, GoNet, Actix, Axum }
impl Display for Framework { ... }  // "express", "flask", "django", "fastapi", "spring", etc.

pub enum RouteParseError {
    IoError(std::io::Error),
    UnsupportedFramework(String),
}

pub fn parse_routes_from_file(path: &Path, framework: Framework) -> Result<Vec<DiscoveredRoute>, RouteParseError>;
pub fn parse_routes_from_source(source: &str, source_file: &str, framework: Framework) -> Result<Vec<DiscoveredRoute>, RouteParseError>;
// Supported: Express, Flask, FastAPI, Django, Spring
// Unsupported (RouteParseError::UnsupportedFramework): Rails, GoNet, Actix, Axum
```

**Framework-specific patterns:**

- **Express**: Detects `app.get(`, `app.post(`, `app.put(`, `app.delete(`, `app.patch(`,
  `app.use(`, `router.*` variants. Extracts the first quoted string as path, the second comma-
  separated argument as handler name.
- **Flask**: Detects `@app.route(path, methods=[...])` decorator — extracts methods from the
  `methods=` keyword argument; defaults to GET if absent. Also detects shorthand decorators
  `@app.get(`, `@app.post(`, etc. Looks at the next line for `def handler_name(`.
- **FastAPI**: Same decorator pattern as Flask. Supports `@app.*` and `@router.*`. Looks at next
  line for `async def` or `def` handler.
- **Django**: Detects `path("pattern", view_func)` calls. All routes get `HttpMethod::Any`.
  Prepends `/` to the extracted path pattern.
- **Spring**: Detects `@GetMapping(`, `@PostMapping(`, `@PutMapping(`, `@DeleteMapping(`,
  `@PatchMapping(`, `@RequestMapping(`. No handler name extraction.

### introspection

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrospectedEndpoint {
    pub path: String,
    pub method: String,
    pub parameters: Vec<EndpointParameter>,
    pub response_type: Option<String>,
    pub description: Option<String>,
    pub security_schemes: Vec<String>,
    pub request_content_types: Vec<String>,
    pub response_status_codes: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointParameter {
    pub name: String,
    pub location: ParameterLocation,
    pub param_type: String,   // "string", "number", "integer", "object", "array", "boolean"
    pub required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterLocation { Path, Query, Header, Cookie, Body }
impl Display for ParameterLocation { ... }

pub enum IntrospectionError {
    JsonParseError(serde_json::Error),
    InvalidSchema(String),
    NetworkError(String),
}

// Parse OpenAPI 3.x JSON spec
pub fn parse_openapi_json(json_content: &str) -> Result<Vec<IntrospectedEndpoint>, IntrospectionError>;
// Sorted by (path, method). Extracts:
// - Path/query/header/cookie parameters from operation.parameters
// - Body parameters from application/json, x-www-form-urlencoded, multipart/form-data requestBody
//   (top-level object properties only; all inherit body-level required flag)
// - Security schemes (operation-level overrides global if present)
// - Request content types from requestBody.content keys
// - Response status codes (numeric codes only, not ranges), sorted

// Parse GraphQL introspection JSON (__schema response)
pub fn parse_graphql_introspection(json_content: &str) -> Result<Vec<IntrospectedEndpoint>, IntrospectionError>;
// Converts introspection JSON to SDL, then calls parse_graphql_sdl

// Parse GraphQL SDL string
pub fn parse_graphql_sdl(sdl: &str) -> Result<Vec<IntrospectedEndpoint>, IntrospectionError>;
// Returns one IntrospectedEndpoint per Query/Mutation/Subscription field
// path="/graphql", method="POST", parameters from field arguments
// description="Query: fieldName" or "Mutation: fieldName"
```

### auth_matrix

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Credential {
    pub label: String,
    pub privilege_level: PrivilegeLevel,
    pub auth_header: Option<String>,  // e.g., "Bearer <token>"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PrivilegeLevel {
    Unauthenticated, User, Moderator, Admin, ServiceAccount,
}
impl Display for PrivilegeLevel { ... }  // "unauthenticated", "user", "moderator", "admin", "service-account"

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointAccess {
    pub endpoint: String,
    pub method: String,
    pub credential_label: String,
    pub status_code: u16,
}

#[derive(Debug, Clone)]
pub struct AuthorizationAnomaly {
    pub endpoint: String,
    pub method: String,
    pub low_privilege_credential: String,
    pub low_privilege_level: PrivilegeLevel,
    pub low_privilege_status: u16,
    pub high_privilege_credential: String,
    pub high_privilege_level: PrivilegeLevel,
    pub high_privilege_status: u16,
    pub anomaly_type: AnomalyType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyType { PotentialIdor, PrivilegeEscalation, MissingAuthentication }
impl Display for AnomalyType { ... }  // "potential-idor", "privilege-escalation", "missing-authentication"

pub struct AuthorizationMatrix {
    credentials: Vec<Credential>,
    access_results: Vec<EndpointAccess>,
}
impl AuthorizationMatrix {
    pub fn new(credentials: Vec<Credential>) -> Self;
    pub fn record_access(&mut self, access: EndpointAccess);
    pub fn record_access_batch(&mut self, accesses: Vec<EndpointAccess>);
    pub fn credentials(&self) -> &[Credential];
    pub fn access_results(&self) -> &[EndpointAccess];
    pub fn status_for(&self, endpoint: &str, method: &str, credential_label: &str) -> Option<u16>;
    pub fn build_matrix_table(&self) -> HashMap<(String, String), HashMap<String, u16>>;

    // Detect anomalies: two credentials with different privilege levels both get 2xx on same endpoint
    pub fn detect_anomalies(&self) -> Vec<AuthorizationAnomaly>;
    // Anomaly classification:
    //   - low == Unauthenticated -> MissingAuthentication
    //   - endpoint contains "admin"/"manage"/"config"/"setting"/"dashboard" -> PrivilegeEscalation
    //   - otherwise -> PotentialIdor

    pub fn endpoint_count(&self) -> usize;
}
```

### graphql_discovery

```rust
// Hardcoded wordlists for blind discovery
pub const COMMON_QUERY_FIELDS: &[&str];   // 21 entries: "users", "me", "viewer", "node", etc.
pub const COMMON_MUTATION_FIELDS: &[&str]; // 13 entries: "createUser", "login", "register", etc.
pub const COMMON_ARGUMENTS: &[(&str, &str)]; // 10 common (name, type) pairs

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMethod { ErrorBased, CommonFieldBrute, Combined }

#[derive(Debug, Clone)]
pub struct GraphQlDiscoveryResult {
    pub method: DiscoveryMethod,
    pub endpoints: Vec<IntrospectedEndpoint>,
    pub confidence: f64,  // ErrorBased=0.6, CommonFieldBrute=0.3, Combined=max of inputs
}

pub enum DiscoveryError {
    Parse(String),
    NoFieldsDiscovered,
}

// Extract field names from a GraphQL error response JSON.
// Recognizes patterns: "Cannot query field \"name\"", "Did you mean \"alt\"?", "Unknown field \"name\""
pub fn extract_fields_from_error(error_json: &str) -> Vec<String>;

// Build probe queries for a list of field names.
// Returns one query per field ({ fieldName }) plus one batch alias query.
pub fn build_probe_queries(fields: &[&str]) -> Vec<String>;

// Build a GraphQlDiscoveryResult from error response JSONs (confidence=0.6)
pub fn discover_from_error_responses(error_responses: &[&str]) -> GraphQlDiscoveryResult;

// Build a GraphQlDiscoveryResult from COMMON_QUERY_FIELDS + COMMON_MUTATION_FIELDS (confidence=0.3)
// Query fields get COMMON_ARGUMENTS; mutation fields get a single "input: JSON" parameter
pub fn discover_common_fields() -> GraphQlDiscoveryResult;

// Merge multiple results; deduplicates by endpoint description; overall confidence = max of inputs
pub fn merge_discovery_results(results: &[GraphQlDiscoveryResult]) -> GraphQlDiscoveryResult;
```

### auth_flow

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFlowStep {
    pub step_id: String,
    pub endpoint: String,
    pub method: String,
    pub body_template: Option<String>,    // {{variable}} placeholders
    pub extract_from_response: Vec<ResponseExtraction>,
    pub expected_status: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseExtraction {
    pub variable_name: String,
    pub source: ExtractionSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtractionSource {
    Header(String),       // header name (case-insensitive)
    JsonPath(String),     // dot-separated path (e.g. "token" or "data.access_token")
    Cookie(String),       // cookie name from Set-Cookie header
    StatusCode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFlow {
    pub name: String,
    pub steps: Vec<AuthFlowStep>,
    pub required_inputs: Vec<String>,  // variable names that must be provided before flow starts
}

#[derive(Debug, Clone)]
pub struct AuthFlowState {
    pub variables: HashMap<String, String>,
    pub completed_steps: Vec<String>,
    pub is_authenticated: bool,
}

pub enum AuthFlowError {
    MissingVariable(String),
    StepFailed { step_id: String, expected_status: u16, actual_status: u16 },
    ExtractionFailed { step_id: String, variable_name: String },
    InvalidJsonPath(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthFlowVulnerability {
    SessionFixation, TokenReuseAfterLogout, MissingTokenRotation,
    WeakSessionId, InsecureCookieAttributes,
}
impl Display for AuthFlowVulnerability { ... }

#[derive(Debug, Clone)]
pub struct AuthFlowFinding {
    pub vulnerability: AuthFlowVulnerability,
    pub flow_name: String,
    pub affected_step: String,
    pub description: String,
    pub evidence: String,
}

// Render {{variable}} placeholders from a HashMap. Returns MissingVariable if a variable is absent.
pub fn render_template(template: &str, variables: &HashMap<String, String>) -> Result<String, AuthFlowError>;

// Extract a value from simulated response data
pub fn extract_value(source: &ExtractionSource, status_code: u16, headers: &[(String, String)], body: &str) -> Option<String>;

// Validate auth flow structural correctness (no duplicate step IDs, template vars available)
pub fn validate_auth_flow(flow: &AuthFlow) -> Result<(), AuthFlowError>;

// Detect session fixation: pre and post-login session IDs are equal
pub fn detect_session_fixation(pre: Option<&str>, post: Option<&str>) -> Option<AuthFlowFinding>;

// Detect weak session ID: length < 16 or all-digit
pub fn detect_weak_session_id(session_id: &str) -> Option<AuthFlowFinding>;

// Detect insecure cookie attributes: missing Secure, HttpOnly, or SameSite
pub fn detect_insecure_cookie(set_cookie_header: &str) -> Vec<AuthFlowVulnerability>;

// Return three predefined auth flow templates: Basic Login, Bearer Token, Cookie Session
pub fn common_auth_flows() -> Vec<AuthFlow>;
```

## Error Types

- `RouteParseError` — IoError (with `From<io::Error>`), UnsupportedFramework
- `IntrospectionError` — JsonParseError (with `From<serde_json::Error>`), InvalidSchema, NetworkError
- `DiscoveryError` — Parse(String), NoFieldsDiscovered
- `AuthFlowError` — MissingVariable, StepFailed, ExtractionFailed, InvalidJsonPath

All implement `std::error::Error` and `Display`.

## Key Implementation Notes

**OpenAPI `requestBody` parameter extraction uses body-level `required` only.** The
`extract_body_parameters` function traverses object property names from `application/json` and
form-encoded content types, but inherits only the body-level `required` flag for all properties.
Per-property required arrays inside the schema are not traversed. This is a known simplification
documented in the CLAUDE.md "Known Pitfalls" section.

**OpenAPI parameters are extracted but not persisted to the knowledge graph and not used by the
fuzzer.** The fuzzer's `FuzzTarget.parameter` field is always an empty string; `enqueue_targets_for_
endpoints()` reads only `path` and `method` from graph node properties. The `IntrospectedEndpoint`
parameter data is available at the enumeration layer but the pipeline does not yet wire it through
to the scheduler.

**Auth matrix anomaly detection checks symmetric 200 responses.** An anomaly is flagged when both
a lower-privilege credential AND a higher-privilege credential receive 2xx responses on the same
endpoint. This correctly flags situations where a lower-privilege user can access a resource that
should be restricted. The symmetry of both receiving 200 is the signal — the high-privilege 200
alone is not an anomaly.

**GraphQL error-based extraction uses a multi-pattern parser.** `extract_fields_from_error` handles
three error message formats from different GraphQL runtime implementations:
`"Cannot query field \"name\""`, `"Did you mean \"alt\""`, and `"Unknown field \"name\""`. The
function traverses the full JSON structure recursively to find these patterns in nested error arrays.

**Auth flow template uses `{{variable}}` double-brace syntax** (not `{variable}` single-brace).
`render_template` processes the template in a single left-to-right pass, replacing each found
`{{...}}` placeholder. Unresolved variables cause `MissingVariable` errors. The double-brace
syntax was chosen to avoid conflicts with JSON payload templates.

**`detect_insecure_cookie` can return multiple issues for one header.** It checks Secure, HttpOnly,
and SameSite independently and may return up to three `InsecureCookieAttributes` variants in one
call.

## Usage Context

The enumeration phase runs after the recon phase. The orchestrator calls `parse_routes_from_file`
on source files discovered by the filesystem walker to populate the knowledge graph with `Endpoint`
nodes. If the target exposes an OpenAPI spec (at `/openapi.json` or similar), `parse_openapi_json`
is called to discover additional endpoints with parameter metadata. For GraphQL targets,
`parse_graphql_introspection` is attempted first; if introspection is disabled (error response or
DISABLE_INTROSPECTION), the orchestrator falls back to `discover_from_error_responses` combined
with `discover_common_fields`. The `AuthorizationMatrix` is used in a separate sub-phase where
the orchestrator fires requests with each credential set and calls `detect_anomalies()` to identify
broken authorization findings before the fuzz phase begins.
