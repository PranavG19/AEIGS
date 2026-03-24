<!-- metadata: crate=aegis-proxy, purpose=HTTP recording proxy with request repeater and 4-mode intruder attack engine + knowledge graph sync, type=library, internal_deps=[aegis-protocol], external_deps=[hyper, http-body-util, hyper-util, reqwest (async), tokio, serde, serde_json, url] -->

# aegis-proxy

## Purpose

Provides an HTTP recording proxy that captures all traffic between a client and target application, a request repeater for manual replay with modifications, a 4-mode intruder for automated payload injection attacks, and a knowledge graph sync layer that converts recorded exchanges into endpoint operations.

## Crate Type

Library

## Dependencies on Workspace Crates

- `aegis-protocol` — `NodeType`, `GraphOperation`, `OperationLogEntry`, `ModuleIdentifier`

## External Dependencies

- `hyper` — HTTP/1.1 server for the proxy listener
- `http-body-util`, `hyper-util` — body collection and tokio I/O adapter for hyper
- `reqwest` (async) — upstream forwarding and intruder request sending
- `tokio` — async runtime (RwLock for log, oneshot for shutdown, semaphore for concurrency)
- `serde`, `serde_json` — `RecordedExchange` serialization, JSON body parameter extraction
- `url` — URL path extraction, query parameter parsing

## Module Structure

| Module | Description |
|---|---|
| `types` | `RecordedExchange` (full request/response pair), `ProxyConfig` (listen address + max log size) |
| `proxy` | `start_proxy` / `ProxyHandle` — async HTTP/1.1 recording proxy with shutdown control |
| `repeater` | `Repeater` — replays a `RecordedExchange` with optional modifications; `ModifiedRequest` for field overrides |
| `intruder` | `run_intruder` — 4-mode (Sniper, BatteringRam, Pitchfork, ClusterBomb) payload injection; `generate_attack_requests` |
| `graph_sync` | `sync_exchanges_to_graph` — converts proxy exchanges into graph operations; extracts URL/body parameters |

## Public API Summary

### `types`

```rust
pub struct RecordedExchange {
    pub id: u64,
    pub request_method: String,
    pub request_url: String,
    pub request_headers: Vec<(String, String)>,
    pub request_body: Vec<u8>,
    pub response_status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Vec<u8>,
    pub timestamp_ms: u64,
    pub duration_ms: u64,
}

pub struct ProxyConfig {
    pub listen_addr: SocketAddr,   // default: 127.0.0.1:8080
    pub max_log_size: usize,       // default: 10_000 (FIFO eviction)
}
impl ProxyConfig {
    pub fn with_listen_addr(self, addr: SocketAddr) -> Self
    pub fn with_max_log_size(self, max: usize) -> Self
}
```

### `proxy`

```rust
pub struct ProxyHandle { /* private */ }

impl ProxyHandle {
    pub async fn exchanges(&self) -> Vec<RecordedExchange>
    pub async fn exchange_count(&self) -> usize
    pub async fn exchange_by_id(&self, id: u64) -> Option<RecordedExchange>
    pub async fn clear_log(&self)
    pub fn listen_addr(&self) -> SocketAddr
    pub async fn shutdown(self)  // sends oneshot signal to accept loop
}

/// Binds TCP listener, starts accept loop in background task, returns handle.
pub async fn start_proxy(config: ProxyConfig) -> Result<ProxyHandle, std::io::Error>
```

### `repeater`

```rust
pub struct ModifiedRequest {
    pub method: String, pub url: String,
    pub headers: Vec<(String, String)>, pub body: Vec<u8>,
}
impl ModifiedRequest {
    /// Clones all fields from an existing RecordedExchange.
    pub fn from_exchange(exchange: &RecordedExchange) -> Self
}

pub struct RepeaterResult {
    pub original: RecordedExchange, pub modified_request: ModifiedRequest,
    pub response_status: u16, pub response_headers: Vec<(String, String)>,
    pub response_body: Vec<u8>, pub duration_ms: u64,
}

pub struct Repeater { /* private */ }
impl Repeater {
    pub fn new() -> Self
    pub fn with_client(client: reqwest::Client) -> Self
    /// Sends the exchange (or modifications if provided) and captures the response.
    pub async fn repeat(&self, exchange: &RecordedExchange,
        modifications: Option<ModifiedRequest>) -> Result<RepeaterResult, reqwest::Error>
}
```

### `intruder`

```rust
pub enum AttackMode {
    Sniper,       // one position at a time, others keep marker text
    BatteringRam, // same payload in all positions simultaneously
    Pitchfork,    // parallel (zip) iteration across payload lists
    ClusterBomb,  // cartesian product of all payload lists
}

pub struct IntruderConfig {
    pub template: ModifiedRequest,
    pub positions: Vec<String>,         // marker strings to substitute
    pub payload_lists: Vec<Vec<String>>,
    pub mode: AttackMode,
    pub concurrency: usize,
}

pub struct IntruderResult {
    pub payload: Vec<String>, pub status_code: u16,
    pub body_length: usize, pub duration_ms: u64,
}

/// Returns (payload_combo, modified_request) pairs for the attack config.
pub fn generate_attack_requests(config: &IntruderConfig) -> Vec<(Vec<String>, ModifiedRequest)>

/// Executes the full intruder run concurrently (via semaphore), returns sorted results.
/// Sorted by: anomalous status codes first, then descending body length.
pub async fn run_intruder(config: IntruderConfig) -> Vec<IntruderResult>
```

### `graph_sync`

```rust
pub struct ProxyGraphSync;

pub struct SyncResult {
    pub endpoints_added: usize, pub parameters_discovered: usize,
    pub operations: Vec<OperationLogEntry>,
}

/// Converts recorded exchanges to graph operations.
/// Deduplicates by (path, method). Extracts parameters from URL query strings,
/// JSON bodies (top-level keys), and form-encoded bodies.
pub fn sync_exchanges_to_graph(exchanges: &[RecordedExchange]) -> SyncResult

/// Extracts parameters from a single exchange without deduplication.
pub fn extract_parameters_from_exchange(exchange: &RecordedExchange) -> Vec<(String, String)>
```

## Key Implementation Notes

- **Proxy uses hyper HTTP/1.1 server with `preserve_header_case`**: The proxy runs `http1::Builder::new().preserve_header_case(true)` to avoid normalizing header names, which matters for security testing where mixed-case headers can affect WAF evasion (proxy.rs:111-114).

- **Hop-by-hop headers are stripped on forwarding**: `is_hop_by_hop_header` removes `connection`, `keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`, `trailers`, `transfer-encoding`, and `upgrade` before forwarding upstream (proxy.rs:218-230). This prevents protocol errors on the forwarded request.

- **FIFO eviction when log is full**: `append_exchange` removes the first entry when `entries.len() >= max_log_size` (proxy.rs:232-242). This means the oldest exchange is dropped, not the new one. With the default `max_log_size = 10_000`, memory usage is bounded.

- **Exchange IDs are atomic and monotonically increasing**: `AtomicU64` starting at 1 is shared across all connections via `Arc`. This guarantees unique IDs even under concurrent requests (proxy.rs:58, fetched with `Ordering::Relaxed`).

- **Intruder result sort order**: `run_intruder` sorts by `b_anomalous.cmp(&a_anomalous)` (non-200 first) then by `b.body_length.cmp(&a.body_length)` (larger bodies first). This surfaces likely successful injections to the top (intruder.rs:172-178).

- **ClusterBomb cartesian product implementation**: Built iteratively by accumulating combinations. Memory grows as the product of all payload list lengths — callers should limit list sizes for large payloads (intruder.rs:106-123).

- **`sync_exchanges_to_graph` uses `ModuleIdentifier::Proxy`**: Operations emitted from the graph sync module are tagged with `Proxy` as the module identifier, which the knowledge graph uses for attribution and replay (graph_sync.rs:58-61).

- **Body parameter extraction by Content-Type**: JSON bodies extract only top-level object keys; form-encoded bodies split on `&` and `=`. Non-JSON, non-form bodies produce no parameters (graph_sync.rs:106-125).

- **Technology hints from response headers**: `append_response_metadata` captures `Server` and `X-Powered-By` headers as node properties on the discovered endpoint (graph_sync.rs:163-175).

## Usage Context

The proxy runs as an optional intercepting layer during manual testing or when the orchestrator is in interactive mode. `ProxyGraphSync::sync_exchanges_to_graph` is called to populate the knowledge graph from manually-triggered traffic. The `Repeater` supports the interactive scan session's ability to replay specific requests. The `Intruder` is used for targeted payload injection against specific endpoints identified during crawling.
