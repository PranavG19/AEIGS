# Safety and Correctness Improvements

Generated: 2026-02-23 | Source depth: 2 (source-confirmed for all high/critical)

---

### SAFETY-001: Blocking std::fs I/O on Tokio Async Runtime Thread
**Severity:** high
**Effort:** medium
**Affected:** aegis-orchestrator
**Source confirmed:** yes (0 uses of `tokio::fs` or `spawn_blocking` in entire codebase)

Multiple production code paths call blocking `std::fs::write` / `std::fs::read_to_string` directly inside async functions running on the Tokio runtime:
- `checkpoint.rs:56-58` — `std::fs::write`, `std::fs::rename` (called from async pipeline)
- `phase_report.rs:163, 417, 422` — `std::fs::write` for SARIF output (async context)
- `telemetry.rs:210` — `std::fs::write` (can be called from async context)
- `audit-log/src/log_writer.rs` — `file.write_all` + `file.flush()` on every audit event

Blocking the Tokio thread pool with I/O operations can cause: degraded scan performance (other async tasks starved), potential deadlocks on single-threaded runtimes, and is explicitly warned against in Tokio documentation.

**Recommendation:** Replace `std::fs::write` / `std::fs::read_to_string` with `tokio::fs::write` / `tokio::fs::read_to_string` in async contexts. For the audit log (which is sync), wrap writes in `tokio::task::spawn_blocking`:
```rust
// In async phase_report.rs:
tokio::fs::write(&ctx.config.output, json).await?;

// For sync AuditLogWriter in async context:
tokio::task::spawn_blocking(|| audit_writer.append_event(event)).await??;
```

**Code location:** `crates/orchestrator/src/checkpoint.rs:56-58`, `crates/orchestrator/src/phase_report.rs:163`

---

### SAFETY-002: std::sync::Mutex for Interactive Session (Poisoning Risk)
**Severity:** medium
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** yes (`pipeline.rs:3` uses `use std::sync::{Arc, Mutex}`)

The interactive session uses `std::sync::Mutex<InteractiveSession>` (not `parking_lot::Mutex`). Unlike `parking_lot`, `std::sync::Mutex` can be poisoned if the thread holding the lock panics. All subsequent `lock().unwrap()` calls (lines 177, 179, 231, 246, 312, 329, 336, 1248) will panic with "mutex poisoned" — crashing the scan unexpectedly.

**Recommendation:** Replace `std::sync::Mutex` with `parking_lot::Mutex` for consistency with the rest of the codebase (which already uses parking_lot for KnowledgeGraph). Parking_lot mutexes never poison.
```rust
use parking_lot::Mutex;  // Replace use std::sync::{Arc, Mutex}
// Then: session.lock().handle_command()  (no .unwrap() needed)
```

**Code location:** `crates/orchestrator/src/pipeline.rs:3, 177, 231, 246, 312`

---

### SAFETY-003: 66 unwrap() + 34 expect() Calls in Production Code
**Severity:** medium
**Effort:** large
**Affected:** multiple crates
**Source confirmed:** yes (grep confirmed 66 + 34 = 100 instances)

The codebase has 100 instances of `.unwrap()` and `.expect()` in non-test production code. Not all are unsafe (e.g., regex statics in `LazyLock`, guaranteed-by-invariant unwraps in graph traversal), but many are undocumented assumptions.

Key instances of concern:
- `knowledge-graph/src/query/path_queries.rs` — `edge_store.get(edge_id).unwrap()` (multiple) — relies on internal consistency invariant that IDs are always valid, but no `SAFETY:` comment
- `oracle.rs:394-405` — regex `LazyLock` unwraps (safe, but undocumented)
- `update_db.rs:297, 299` — `current_introduced.take().unwrap()` — panics if OSV data malformed

**Recommendation:**
1. For invariant-based unwraps in graph traversal, add `// INVARIANT: ...` comments explaining why panic is impossible
2. For potentially-failing unwraps like `update_db.rs:297`, convert to `?` with `ok_or_else(|| UpdateDbError::MalformedOsvData(...))`
3. Audit all `.expect()` messages to ensure they describe the invariant being violated (e.g., `expect("INVARIANT: edge IDs are always valid within a validated graph")`)

**Code location:** `crates/knowledge-graph/src/query/path_queries.rs:37`, `crates/orchestrator/src/update_db.rs:297`

---

### SAFETY-004: Socket File Not Cleaned Up on Panic
**Severity:** medium
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** partial (Drop impl noted in architecture docs, but panic path unclear)

The Unix domain socket `/tmp/aegis-hypothesis-{pid}-{timestamp}.sock` is cleaned up on `HypothesisBridge` `Drop`. However, if a panic occurs while `HypothesisBridge` is borrowed but not owned (e.g., a panic in a phase function that borrows from `ctx`), the Drop may not run because the thread stack unwinds and drops are unreliable in panic contexts with `panic = "abort"`.

**Recommendation:** Add cleanup logic that handles socket files even on abnormal exits:
1. Use a `std::panic::catch_unwind()` wrapper around the main scan if possible
2. Alternatively, use a named socket path based on PID and add cleanup via a process-exit hook
3. At minimum, the socket file naming with timestamp ensures leftover files don't conflict between runs, but a `cleanup_stale_sockets()` function at startup would be good hygiene

**Code location:** `crates/orchestrator/src/hypothesis_bridge.rs` (Drop impl)

---

### SAFETY-005: Target Validation — Obfuscation Bypass Prevention Needs Verification
**Severity:** medium
**Effort:** small
**Affected:** aegis-protocol
**Source confirmed:** partial

`validate_target_with_override()` claims to reject "hex/octal IP encodings" for SSRF bypass prevention. The implementation should be verified to cover:
- `0x7f000001` (hex encoding of 127.0.0.1)
- `0177.0.0.1` (octal encoding)
- `127.1` (incomplete dotted notation)
- `[::ffff:127.0.0.1]` (IPv4-mapped IPv6)
- URL redirects that resolve to localhost

**Recommendation:** Read `crates/protocol/src/target_validation.rs` and verify all obfuscation vectors are covered. Add an exhaustive test suite for the validation function covering all bypass patterns listed in OWASP SSRF documentation.

**Code location:** `crates/protocol/src/target_validation.rs`

---

### SAFETY-006: Checkpoint Race Condition with Concurrent Scans
**Severity:** low
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** yes (`checkpoint.rs:56-58` atomic rename confirmed)

Checkpoint writes use atomic `.tmp` → rename (`checkpoint.rs:57`), which prevents partial writes. However, if two scan instances with the same `--graph-db` path run concurrently, they will overwrite each other's checkpoints. The current code has no file locking.

**Recommendation:** Document that `--graph-db` paths must be unique per concurrent scan instance. Add a validation check that creates a lock file (using `OpenOptions::new().create_new(true)`) when opening a graph database, failing with a clear error if already locked.

---

### SAFETY-007: Auth Flow Template Injection Risk
**Severity:** low
**Effort:** small
**Affected:** aegis-enumeration
**Source confirmed:** partial

The auth flow engine uses `{{variable}}` template rendering where variables come from `--auth-input KEY=VALUE` CLI arguments. If the variable values contain `{{` or `}}` themselves, the rendering might produce unexpected output. Additionally, rendered templates are sent as HTTP request bodies — if the rendering produces malformed JSON, this could cause confusing errors.

**Recommendation:** Validate that `--auth-input` values don't contain `{{` or `}}` to prevent accidental template injection. Add a test with nested braces.

---

### SAFETY-008: HMAC Key Potentially Not Zeroed After Use
**Severity:** low
**Effort:** small
**Affected:** aegis-audit-log, aegis-orchestrator
**Source confirmed:** partial

The 32-byte random HMAC key is generated via `rand::random::<[u8; 32]>()` in `pipeline.rs:1838` and passed to `AuditLogWriter::create()`. If the key bytes remain in memory (stack or heap) after the audit writer is created, an attacker with memory access could extract the key and forge audit entries.

**Recommendation:** Use `zeroize::Zeroize` or `secrecy::Secret<[u8; 32]>` to ensure the key material is zeroed when the array goes out of scope. The `ed25519-dalek` signing keys should also use `zeroize` (which the dalek library supports via the `zeroize` feature).

---

### SAFETY-010: Persona Catalog Loading Uses .expect() in Production Path
**Severity:** high
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** yes (`pipeline.rs:720`)

`load_persona_catalog(catalog_path).expect("persona catalog must be valid")` will panic if the persona catalog file is malformed or missing. This is in the main scan pipeline's `build_fuzz_transport()` function — a malformed custom `--persona-catalog` file crashes the entire scan.

**Recommendation:** Return `Result` instead of panicking:
```rust
let catalog = load_persona_catalog(catalog_path)
    .map_err(|e| PipelineError::Config(ConfigError::InvalidTarget(format!("persona catalog: {e}"))))?;
```

**Code location:** `crates/orchestrator/src/pipeline.rs:720`

---

### SAFETY-011: Interactive Thread Spawn Uses .expect()
**Severity:** medium
**Effort:** small
**Affected:** aegis-orchestrator

`std::thread::Builder::new().spawn(...).expect("failed to spawn interactive stdin reader thread")` in `spawn_interactive_reader()`. Under extreme resource exhaustion, thread spawning can fail, which crashes the entire scan.

**Recommendation:** Return `Option<Arc<Mutex<InteractiveSession>>>` or log the error and continue without interactive mode:
```rust
match thread::Builder::new().name("interactive-stdin").spawn(move || { ... }) {
    Ok(_) => Some(session),
    Err(e) => { tracing::warn!("failed to start interactive mode: {e}"); None }
}
```

**Code location:** `crates/orchestrator/src/pipeline.rs:190`

---

### SAFETY-012: extract_raw_host() IPv6 Bracket Logic Potential Panic
**Severity:** medium
**Effort:** small
**Affected:** aegis-protocol
**Source confirmed:** yes

In `extract_raw_host()`, the IPv6 bracket logic uses `.unwrap_or(len)` for the closing `]` position then indexes `&s[..=bracket_end]`. If bracket_end equals string length, this panics.

**Recommendation:** Add bounds check before slice access:
```rust
let bracket_end = s.find(']').unwrap_or(s.len().saturating_sub(1));
if bracket_end >= s.len() { return None; }
```

**Code location:** `crates/protocol/src/target_validation.rs:116-117`

---

### SAFETY-009: update_db Uses Plaintext HTTP (OSV API)
**Severity:** low
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** yes (update_db queries `https://api.osv.dev/v1/querybatch`)

The `update-db` subcommand queries the OSV API over HTTPS. The `reqwest::blocking::Client` default should use TLS. However, the code does not explicitly set `danger_accept_invalid_certs(false)` (which is the default, so this is fine) or verify certificate pinning. This is low severity because OSV is a well-maintained Google service.

**Recommendation:** No immediate action needed. Document that the OSV API connection uses standard TLS verification and does not need certificate pinning for public endpoints.
