<!-- metadata: crate=aegis-test-support, purpose=shared test infrastructure including fixture servers, mock graph/transport, vulnerable app builder, fixture data, and assertion helpers, type=library (dev-only), internal_deps=[aegis-protocol, aegis-audit-log], external_deps=[axum, tokio, tempfile, serde_json] -->

# aegis-test-support

## Purpose

Provides shared test infrastructure for all other AEGIS crates: an in-process HTTP test server, a mock knowledge graph store, a mock fuzz transport with WAF/rate-limit simulation, a declarative vulnerable application builder with ground truth tracking, pre-canned fixture data (lockfiles, source code, specs), and assertion helpers for findings and SARIF output.

## Crate Type

Library (intended for use in `[dev-dependencies]` only)

## Dependencies on Workspace Crates

- `aegis-protocol` — `VulnerabilityClass`, `FuzzRequest`, `FuzzResponse`, `ParameterLocation`, `GraphOperation`, `OperationLogEntry`
- `aegis-audit-log` — `log_verifier::verify_log` (used in `verify_audit_chain_at_path`)

## External Dependencies

- `axum` — `Router` for test server and vulnerable app endpoints
- `tokio` — async task spawning for `TestServer`, `TcpListener`
- `tempfile` — `TempDir` for `create_source_tree` and `create_recon_workspace`
- `serde_json` — SARIF validation, JSON body construction in vulnerable app handlers

## Module Structure

| Module | Description |
|---|---|
| `fixture_server` | `TestServer` — binds to OS-assigned port on 127.0.0.1, serves an axum Router in a background task, aborts on drop |
| `mock_graph` | `MockGraphStore` — records `OperationLogEntry` instances without full graph semantics; counts by operation type |
| `mock_transport` | `MockFuzzTransport` — records `FuzzRequest` instances, returns canned responses; simulates WAF blocking and rate limiting |
| `vulnerable_app` | `VulnerableAppBuilder` — declarative builder for a realistic vulnerable test application with 16+ vulnerability types and ground truth tracking |
| `fixture_data` | Static fixture strings: Cargo.lock, npm package-lock.json v2, poetry.lock, Gemfile.lock, Go sum, Express/Flask/FastAPI/Django/Spring source, OpenAPI spec, GraphQL introspection response + SDL, BusinessContext JSON |
| `assertions` | `assert_has_finding`, `assert_no_finding`, `validate_sarif_json`, `verify_audit_chain_at_path` |
| `temp_workspace` | `create_source_tree`, `create_recon_workspace`, `create_route_discovery_workspace`, `write_fixture_file` |

## Public API Summary

### `fixture_server`

```rust
pub struct TestServer { /* private */ }

impl TestServer {
    /// Binds to 127.0.0.1:0, serves router in background task.
    pub async fn new(router: Router) -> Self
    pub fn url(&self) -> String     // "http://127.0.0.1:{port}"
    pub fn port(&self) -> u16
}
// Drop impl aborts the background task.
```

### `mock_graph`

```rust
/// Vec-backed recording store. Does NOT implement the full GraphStore trait.
pub struct MockGraphStore { /* private */ }

impl MockGraphStore {
    pub fn new() -> Self
    pub fn apply(&mut self, entry: OperationLogEntry)
    pub fn apply_batch(&mut self, entries: &[OperationLogEntry])
    pub fn operations(&self) -> &[OperationLogEntry]
    pub fn node_count(&self) -> usize    // count of AddNode operations
    pub fn edge_count(&self) -> usize    // count of AddEdge operations
    pub fn finding_count(&self) -> usize // count of AddFinding operations
    pub fn total_count(&self) -> usize
}
```

### `mock_transport`

```rust
pub struct MockFuzzTransport { /* private */ }

impl MockFuzzTransport {
    pub fn new() -> Self
    /// Configure canned response for requests where endpoint contains pattern (substring).
    pub fn with_response(self, endpoint_pattern: &str, status: u16, body: &str,
        headers: Vec<(String, String)>) -> Self
    /// Simulate WAF: returns 403 when payload contains SQL/XSS/CmdInj metacharacters.
    pub fn with_waf_block(self, vendor: &str, blocked_classes: Vec<VulnerabilityClass>) -> Self
    /// Simulate rate limit: after rps requests, return status_code (e.g., 429).
    pub fn with_rate_limit(self, rps: u32, status_code: u16) -> Self
    pub fn requests(&self) -> Vec<FuzzRequest>
    pub fn request_count(&self) -> usize
    /// Synchronous send — records the request and returns a configured or default response.
    pub fn send(&self, request: FuzzRequest) -> FuzzResponse
}
```

### `vulnerable_app`

```rust
pub struct GroundTruthEntry { pub endpoint: String, pub vulnerability_class: VulnerabilityClass }
pub struct GroundTruth { pub entries: Vec<GroundTruthEntry> }

pub struct VulnerableApp;
impl VulnerableApp { pub fn builder() -> VulnerableAppBuilder }

pub struct VulnerableAppBuilder { /* private */ }

impl VulnerableAppBuilder {
    pub fn build(self) -> (Router, GroundTruth)

    // Each method registers a handler + ground truth entry:
    pub fn with_sqli(self, path: &str) -> Self
    pub fn with_xss(self, path: &str) -> Self
    pub fn with_command_injection(self, path: &str) -> Self
    pub fn with_path_traversal(self, path: &str) -> Self
    pub fn with_ssrf(self, path: &str) -> Self
    pub fn with_ssti(self, path: &str) -> Self
    pub fn with_broken_auth(self, path: &str) -> Self
    pub fn with_broken_authz(self, path: &str) -> Self
    pub fn with_idor(self, path: &str) -> Self
    pub fn with_open_redirect(self, path: &str) -> Self
    pub fn with_header_injection(self, path: &str) -> Self
    pub fn with_crlf_injection(self, path: &str) -> Self
    pub fn with_sensitive_data(self, path: &str) -> Self
    pub fn with_security_misconfig(self, path: &str) -> Self
    pub fn with_deserialization(self, path: &str) -> Self
    pub fn with_input_validation(self, path: &str) -> Self
    pub fn with_health(self) -> Self                         // /health -> "ok"
    pub fn with_openapi_spec(self, spec_json: &str) -> Self  // /openapi.json
    pub fn with_graphql_introspection(self, schema: &str) -> Self  // /graphql (introspection enabled)
    pub fn with_graphql_no_introspection(self) -> Self        // /graphql (returns error + field hints)
}
```

### `fixture_data`

```rust
pub fn cargo_lock_with_vuln() -> &'static str      // hyper 0.14.0 (CVE-affected)
pub fn package_lock_v2() -> &'static str           // lodash 4.17.20
pub fn poetry_lock() -> &'static str               // pyyaml 5.3.1 (CVE-2020-14343)
pub fn gemfile_lock() -> &'static str              // actionpack 6.1.4 with nested deps
pub fn go_sum() -> &'static str                    // gin v1.7.0
pub fn express_source() -> &'static str            // 8 routes (CRUD + login + health)
pub fn flask_source() -> &'static str              // 6 routes
pub fn fastapi_source() -> &'static str            // 6 routes
pub fn django_source() -> &'static str             // 7 urlconf path() entries
pub fn spring_source() -> &'static str             // 7 REST controller mappings
pub fn openapi_spec() -> &'static str              // 9-endpoint OpenAPI 3.0 JSON
pub fn graphql_introspection_response() -> &'static str  // full __schema response
pub fn graphql_sdl() -> &'static str               // SDL with Query, Mutation, User, Product
pub fn business_context_json() -> &'static str     // excluded/critical/PII endpoint lists
```

### `assertions`

```rust
/// Panics if no finding matches the given vulnerability_class.
/// (endpoint_substring parameter accepted for API symmetry but matching is on class alone)
pub fn assert_has_finding(findings: &[FindingData], class: VulnerabilityClass,
    _endpoint_substring: &str)

/// Panics if any finding matches the given vulnerability_class.
pub fn assert_no_finding(findings: &[FindingData], class: VulnerabilityClass,
    _endpoint_substring: &str)

/// Returns true if JSON string is a valid SARIF 2.1.0 document ($schema, version, runs fields).
pub fn validate_sarif_json(json_str: &str) -> bool

/// Returns true if the audit log at path has valid hash chain and HMAC signatures.
pub fn verify_audit_chain_at_path(path: &Path, hmac_key: &[u8]) -> bool
```

### `temp_workspace`

```rust
pub fn create_source_tree(files: &[(&str, &str)]) -> TempDir
pub fn create_recon_workspace() -> TempDir          // Cargo.lock + package-lock.json
pub fn create_route_discovery_workspace() -> TempDir // app.js + app.py + urls.py + etc.
pub fn write_fixture_file(base: &Path, rel_path: &str, content: &str)
```

## Key Implementation Notes

- **`TestServer` uses OS-assigned port 0**: `TcpListener::bind("127.0.0.1:0")` lets the OS assign a free port, preventing port conflicts between parallel test runs. The assigned port is read back via `local_addr().port()` (fixture_server.rs:17-19).

- **`TestServer::drop` aborts the task**: The `Drop` implementation calls `handle.abort()`, which sends a cancellation signal to the background task. This ensures clean teardown when a test ends (fixture_server.rs:43-48).

- **`MockFuzzTransport` rate limit is request-count based, not time based**: Rate limiting is simulated by counting total requests — once `reqs.len() > rl.max_rps`, all subsequent requests return the rate limit status code. This is not wall-clock rate limiting; it simulates endpoint response behavior for testing fuzzer rate-limit detection (mock_transport.rs:106-117).

- **WAF simulation checks payload keywords for specific classes**: The WAF simulation uses literal string matching (`select`, `union`, `'` for SQLi; `<script`, `onerror` for XSS; `;`, `|` for CmdInj) rather than testing arbitrary payloads (mock_transport.rs:121-140). This is sufficient for testing that the fuzzer correctly detects and responds to 403 responses.

- **`VulnerableApp` handlers simulate realistic vulnerability signals**: `handle_sqli` returns a 500 with SQL error text when injection characters are present; `handle_ssti` evaluates `{{7*7}}` to `"49"`. These signals are what the fuzzer's anomaly oracle is trained to detect (vulnerable_app.rs:301-354).

- **`assert_has_finding` endpoint_substring is accepted but not used**: The `_endpoint_substring` parameter is accepted for API symmetry with future implementations but matching is currently performed on `vulnerability_class` alone, since `FindingData` does not store endpoint strings directly (assertions.rs:10-25).

- **`verify_audit_chain_at_path` requires both chain validity and no tampering**: It checks `!report.tamper_detected && report.hash_chain_valid && report.hmac_valid` — all three conditions must hold (assertions.rs:67-71).

## Usage Context

Used exclusively in `[dev-dependencies]` across the workspace. `TestServer` + `VulnerableAppBuilder` are the primary tools for integration tests that require a live HTTP endpoint. `MockGraphStore` and `MockFuzzTransport` are used for unit tests of phases that would otherwise require a full `KnowledgeGraph` or real HTTP transport. `fixture_data` provides static strings used by passive-recon parser tests and enumeration crate tests. `create_recon_workspace` and `create_route_discovery_workspace` are used by orchestrator integration tests.
