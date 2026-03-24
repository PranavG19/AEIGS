# AEGIS External Dependencies

<!-- metadata: external dependencies, categories, version constraints, feature flags -->

## Workspace-Level Dependencies (shared across crates)

Declared in root `Cargo.toml` under `[workspace.dependencies]` and inherited via `dep.workspace = true`:

| Dependency | Version | Features | Purpose |
|-----------|---------|---------|---------|
| tokio | 1 | full | Async runtime |
| serde | 1 | derive | Serialization framework |
| serde_json | 1 | — | JSON encoding/decoding |
| thiserror | 2 | — | Error derive macro |
| uuid | 1 | v4 | UUID generation |
| tracing | 0.1 | — | Structured logging |
| tracing-subscriber | 0.3 | env-filter | Log subscriber with env filter |
| ciborium | 0.2 | — | CBOR serialization |
| sha3 | 0.10 | — | SHA3-256 hashing |
| hmac | 0.12 | — | HMAC authentication |
| sha2 | 0.10 | — | SHA2-256 hashing |
| base64 | 0.22 | — | Base64 encoding |
| petgraph | 0.7 | — | Graph algorithms |
| reqwest | 0.12 | json | HTTP client |
| rusqlite | 0.32 | bundled | SQLite (C bundled, no system dep) |
| semver | 1 | — | Semantic versioning |
| rand | 0.9 | — | Random number generation |
| cargo-lock | 10 | — | Cargo.lock parsing |
| sarif_rust | 0.3 | — | SARIF 2.1.0 report format |
| openapiv3 | 2 | — | OpenAPI 3 spec parsing |
| graphql-parser | 0.4 | — | GraphQL SDL/introspection parsing |
| regex | 1 | — | Regular expressions |
| clap | 4 | derive | CLI argument parsing |
| ed25519-dalek | 2 | rand_core | Ed25519 signatures |
| url | 2 | — | URL parsing and validation |
| axum | 0.8 | — | HTTP server framework |
| tower | 0.5 | — | HTTP middleware |
| hyper | 1 | — | HTTP/1.1 and HTTP/2 |
| tempfile | 3 | — | Temporary file/dir management |

---

## Dependencies by Category

### Async Runtime & Utilities

| Dependency | Version | Used By | Notes |
|-----------|---------|---------|-------|
| tokio | 1.49.0 | supervisor, enumeration, fuzzing, evasion-engine, orchestrator, crawler, proxy, test-support | Full feature set (runtime, macros, fs, net, sync) |
| futures | (transitive via chromiumoxide) | crawler | Async combinators for stream processing |
| http-body-util | 0.1.3 | proxy | HTTP body utilities for hyper |

**Runtime setup:** Single `#[tokio::main]` entry point in `crates/orchestrator/src/main.rs`. Multi-threaded runtime (default tokio behavior). `tokio::join!` used for concurrent recon + fingerprint phases.

---

### Serialization

| Dependency | Version | Used By | Notes |
|-----------|---------|---------|-------|
| serde | 1.0.228 | all crates | `derive` feature for `#[derive(Serialize, Deserialize)]` |
| serde_json | 1.0.149 | all crates | JSON for IPC, graph persistence, report output |
| ciborium | 0.2.2 | audit-log, reporting | CBOR binary format for audit log and certificates (~40% smaller than JSON) |
| base64 | 0.22.1 | fuzzing, exploiter | Payload encoding, JWT manipulation |
| urlencoding | 2.1.3 | fuzzing (dev) | URL-encoded payload generation in tests |

**Design choice:** CBOR chosen for audit log and certificates — compact, binary-safe, self-describing. JSON for human-readable outputs and IPC with Python subprocess.

---

### HTTP & Networking

| Dependency | Version | Used By | Notes |
|-----------|---------|---------|-------|
| reqwest | 0.12.28 | enumeration, fuzzing, evasion-engine, discovery, orchestrator, proxy | `json` feature; `blocking` feature in orchestrator for `update-db` |
| hyper | 1.8.1 | proxy | Low-level HTTP for recording proxy |
| hyper-util | 0.1.20 | proxy | Hyper helper utilities |
| axum | 0.8.8 | test-support (prod), dev-deps | HTTP server for test fixtures and integration test servers |
| tower | 0.5 | (via axum) | Service/layer abstraction |
| wiremock | 0.6.5 | evasion-engine (dev) | HTTP mock server for transport tests |
| chromiumoxide | (latest) | crawler | Headless Chrome via Chrome DevTools Protocol |
| url | 2.5.8 | protocol, fuzzing, discovery, orchestrator, proxy, crawler | URL parsing; target validation enforces localhost constraint |

**Note:** `reqwest` is used with `blocking` feature specifically in `update-db` subcommand (runs before tokio runtime). All other HTTP usage is async.

---

### Database & Storage

| Dependency | Version | Used By | Notes |
|-----------|---------|---------|-------|
| rusqlite | 0.32.1 | passive-recon, orchestrator | `bundled` feature — compiles SQLite from source, no system library required |

**Two SQLite databases:**
1. `~/.aegis/vuln.db` — vulnerability database populated by `update-db` subcommand from OSV API
2. Per-scan SQLite file (path from `--graph-db`) — scan history and checkpoint storage

---

### CLI

| Dependency | Version | Used By | Notes |
|-----------|---------|---------|-------|
| clap | 4.5.59 | orchestrator only | `derive` feature for struct-based arg parsing |

---

### Logging & Tracing

| Dependency | Version | Used By | Notes |
|-----------|---------|---------|-------|
| tracing | 0.1.44 | audit-log, passive-recon, enumeration, fuzzing, chain-synthesis, evasion-engine, orchestrator, proxy, crawler | Structured event logging with spans |
| tracing-subscriber | 0.3.22 | supervisor, orchestrator | `env-filter` feature for `RUST_LOG` env var control |

---

### Cryptography & Security

| Dependency | Version | Used By | Notes |
|-----------|---------|---------|-------|
| sha3 | 0.10.8 | protocol, audit-log, reporting | SHA3-256 for hash chain and certificate hashing (Keccak sponge, structurally diverse from SHA2) |
| sha2 | 0.10.9 | exploiter | SHA2-256 for JWT HMAC verification |
| hmac | 0.12.1 | audit-log, exploiter | HMAC-SHA3 for audit log signing; HMAC-SHA256 for JWT testing |
| ed25519-dalek | 2.2.0 | protocol, orchestrator (prod); evasion-engine (dev) | Ed25519 asymmetric signatures for scope attestation and config signing |
| subtle | (latest) | supervisor | Timing-safe comparison for capability tokens (`ct_eq`) |

**Design choice:** SHA3-256 (not SHA2) for hash chains — Keccak sponge construction provides defense-in-depth against SHA2-specific class attacks.

---

### Graph & Algorithms

| Dependency | Version | Used By | Notes |
|-----------|---------|---------|-------|
| petgraph | 0.7.1 | chain-synthesis | DiGraph for attack graph; uses astar, all_simple_paths, Bfs |
| parking_lot | (latest) | knowledge-graph | `RwLock` with upgradable read locks (no lock poisoning), better performance than std |

---

### Domain-Specific Parsers

| Dependency | Version | Used By | Notes |
|-----------|---------|---------|-------|
| openapiv3 | 2.2.0 | enumeration | OpenAPI 3.x spec parsing for route/parameter discovery |
| graphql-parser | 0.4.1 | enumeration | GraphQL SDL and introspection response parsing |
| cargo-lock | 10 | passive-recon | Cargo.lock format parsing (all versions); filters to default registry |
| semver | 1 | passive-recon | Version range comparison for CVE matching |
| sarif_rust | 0.3 | reporting | SARIF 2.1.0 type-safe report generation; ensures schema compliance for IDE/CI integration |

---

### Utilities

| Dependency | Version | Used By | Notes |
|-----------|---------|---------|-------|
| rand | 0.9.2 | evasion-engine, fuzzing, orchestrator | Randomness for jitter, payload selection, persona rotation |
| uuid | 1.21.0 | audit-log, fuzzing, exploiter, protocol | v4 random UUIDs for event IDs and request correlation |
| regex | 1.12.3 | crawler, discovery, fuzzing | Pattern matching for endpoint extraction and payload generation |

---

### Testing (dev-dependencies only)

| Dependency | Version | Used By | Notes |
|-----------|---------|---------|-------|
| tempfile | 3.25.0 | many crates (dev) | Temporary files for test isolation |
| proptest | (latest) | knowledge-graph (dev) | Property-based testing for graph invariants |
| wiremock | 0.6.5 | evasion-engine (dev) | HTTP mock server |
| axum | 0.8.8 | enumeration, evasion-engine, fuzzing, proxy (dev) | In-test HTTP server; also used in test-support (prod) |
| tokio | 1 | many (dev) | Test runtime (`rt`, `macros` features) |

---

## Notable Dependency Choices

| Decision | Rationale |
|---------|-----------|
| `rusqlite` with `bundled` feature | Zero external system dependencies for SQLite — portable across environments without requiring libsqlite3-dev |
| `reqwest` (not `hyper` directly) | Higher-level API sufficient for localhost testing; evasion-engine designed for future `rquest` swap (TLS fingerprint control) |
| `parking_lot` over `std::sync` | Upgradable read locks (`RwLockUpgradableReadGuard`) for atomic validate-then-apply in knowledge graph; no lock poisoning |
| `petgraph` for attack graph | Mature, proven graph algorithms (astar, BFS, simple paths); avoids reimplementing complex graph algorithms |
| `sarif_rust` for reports | Schema compliance guaranteed; interoperability with GitHub, Azure DevOps, VS Code SARIF viewers |
| `chromiumoxide` for crawling | Full JS execution for SPA support; Chrome DevTools Protocol for programmatic control |
| `ed25519-dalek` for signing | Asymmetric signatures allow offline verification without shared secrets; modern, audited implementation |

---

## No Feature Flags

No crate in this workspace defines custom feature flags. All features are unconditionally compiled. External dependency features are fixed (e.g., tokio `full`, rusqlite `bundled`, serde `derive`).
