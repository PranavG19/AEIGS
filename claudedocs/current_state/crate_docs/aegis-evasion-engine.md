# aegis-evasion-engine

<!-- metadata: crate purpose, public API, modules, HTTP transport, personas, TLS fingerprinting, header transforms, timing jitter, session rotation -->

## Purpose

Provides persona-based HTTP transport for all AEGIS HTTP requests. Implements request evasion through persona simulation (10 browser personas), header/encoding transforms, timing jitter, session rotation, and TLS fingerprint abstraction (JA3 mapping). Enforces localhost target validation at the transport layer. Designed for future swap to `rquest` (TLS fingerprint control) from current `reqwest` backend.

## Crate Type
Library

## Dependencies on Workspace Crates
- `aegis-protocol` — `FuzzRequest`, `FuzzResponse`, `ParameterLocation`, `SignedScopeAttestation`, `target_validation`

## External Dependencies
- `reqwest` 0.12 — HTTP client (JSON feature)
- `rand` 0.9 — timing jitter, header randomization
- `serde`, `serde_json` — persona catalog serialization
- `tokio` 1 — async `send()` implementation

## Module Structure

| Module | Description |
|--------|-------------|
| `transport` (pub) | `EvasionTransport` — main HTTP client with all evasion features |
| `persona` (pub) | `Persona`, `PersonaId`, `PersonaCatalog` — browser persona definitions |
| `header_transformer` (pub) | `HeaderTransformer` — randomizes and transforms HTTP headers |
| `encoding_transformer` (pub) | `EncodingTransformer` — URL encoding, double-encoding, unicode transforms |
| `timing_controller` (pub) | `TimingController` — request delay computation with jitter |
| `session_manager` (pub) | `SessionManager` — cookie jar rotation, session expiry |
| `tls_config` (pub) | `TlsConfig`, `TlsFingerprint`, `HttpClientBackend` — TLS fingerprint abstraction |

## Public API Summary

### EvasionTransport

```rust
pub struct EvasionTransport { /* private */ }

impl EvasionTransport {
    pub fn builder() -> EvasionTransportBuilder
    pub async fn send(&mut self, request: &FuzzRequest) -> Result<FuzzResponse, TransportError>
    // Builder methods:
    pub fn with_persona(persona: &Persona) -> Self (via builder)
    pub fn with_persona_catalog(path: &Path) -> Self (via builder)
    pub fn with_accept_self_signed(bool) -> Self (via builder)
    pub fn with_scope_attestation(attestation) -> Self (via builder)
    pub fn with_operator_authorized(bool) -> Self (via builder)
}
```

**send() flow:**
1. `validate_target_with_override()` — enforce localhost (fails with `TransportError::TargetNotAllowed` if not localhost and not authorized)
2. `TimingController::compute_delay_ms()` → `tokio::time::sleep()`
3. `SessionManager::session_headers()` → merge with request headers
4. `HeaderTransformer::transform()` → randomize headers per persona
5. Build reqwest request with persona User-Agent
6. Execute, measure response time, return `FuzzResponse`

### PersonaId — 10 variants

```rust
pub enum PersonaId {
    ChromeDesktop | FirefoxDesktop | SafariDesktop | ChromeMobile |
    Googlebot | EdgeDesktop | OperaDesktop | SafariMobile |
    CurlClient | PythonRequests
}
```

### TlsFingerprint — 6 variants

```rust
pub enum TlsFingerprint {
    Chrome120 | Firefox121 | Safari17 | Edge120 | Curl | Default
}
// Chrome120 and Edge120 share same JA3 hash (both Chromium)
impl TlsFingerprint {
    pub fn ja3_hash(&self) -> &'static str
}
```

### TransportError

```rust
pub enum TransportError {
    NetworkError(String),
    Timeout(String),
    BuildError(String),
    TargetNotAllowed(String),
}
```

### Persona Catalog

```rust
pub fn load_persona_catalog(path: Option<&Path>) -> Result<Vec<Persona>, ...>
// path=None: uses embedded default catalog
// path=Some(p): loads custom JSON persona catalog
```

## Key Implementation Notes

- **Target validation in `send()`**: Calls `validate_target_with_override()` before every HTTP request — third layer of localhost enforcement.
- **No `rquest` yet**: The `HttpClientBackend` enum (Reqwest vs Rquest) exists in `tls_config.rs` but only Reqwest is wired. Rquest (TLS fingerprint control) is planned.
- **Chrome120 and Edge120 share JA3**: Both are Chromium-based; their `ja3_hash()` values are identical by design.
- **Persona rotation**: `EvasionTransport` tracks `sessions_since_rotation` and rotates to next persona in catalog after `persona_rotation_interval` requests (if configured).
- **Blocking in separate thread**: Defense fingerprinting in `pipeline.rs` calls `probe_defenses()` on a separate OS thread via `std::thread::spawn` because `reqwest::blocking` cannot run inside a tokio runtime.

## Usage Context

Used in the `fuzz` phase — `build_fuzz_transport()` in `pipeline.rs` creates the transport from `ScanConfig` stealth settings. Also used internally by `phase_fingerprint` for HTTP discovery probes.
