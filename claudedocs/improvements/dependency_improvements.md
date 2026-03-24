# Dependency Improvements

Generated: 2026-02-23 | Source depth: 2
Note: `cargo-audit` and `cargo-outdated` are not installed. Analysis based on known versions and documentation.

---

### DEP-001: tokio "full" Feature Enables Unused Sub-features
**Severity:** medium
**Effort:** small
**Affected:** all crates that use tokio
**Source confirmed:** yes (workspace Cargo.toml declares `tokio = { version = "1", features = ["full"] }`)

`tokio`'s `"full"` feature enables all Tokio components: runtime, I/O, net, fs, time, sync, macros, signal, process, and test utilities. AEGIS uses: runtime, time (sleeps), sync (no Tokio channels), macros (`#[tokio::main]`). It does NOT use: `tokio::net`, `tokio::fs`, `tokio::process`, `tokio::signal`.

Unnecessary features add compile time, binary size, and increase the attack surface.

**Recommendation:** Replace `features = ["full"]` with explicit features:
```toml
tokio = { version = "1", features = ["rt-multi-thread", "macros", "time", "sync"] }
```
Add `tokio::fs` only when PERF-001 (blocking I/O fix) is implemented.

---

### DEP-002: reqwest Has Both blocking and async Features Enabled
**Severity:** medium
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** yes (Cargo.toml: `reqwest = { version = "0.12", features = ["blocking", "json"] }`)

Orchestrator enables both `blocking` and `json` features for reqwest. The `blocking` feature pulls in an additional internal runtime and adds compile overhead. It's only needed for the `update-db` subcommand (which runs before the tokio runtime).

**Recommendation:** Consider separating `update-db` into a separate binary target (`[[bin]]`) that links against a minimal reqwest with just `blocking` feature, keeping the main `aegis` binary with only async reqwest. Alternatively, replace the blocking reqwest in `update-db` with `tokio::runtime::Runtime::new().unwrap().block_on(...)` using the async client.

---

### DEP-003: chromiumoxide Is Always Compiled Despite browser Feature Gate
**Severity:** medium
**Effort:** small
**Affected:** aegis-crawler
**Source confirmed:** yes (chromiumoxide in Cargo.toml without feature condition)

The `aegis-crawler` crate includes `chromiumoxide` in its Cargo.toml unconditionally, but only uses it behind `#[cfg(feature = "browser")]` guards. This means `chromiumoxide` (a large dependency that pulls in Chrome DevTools Protocol bindings) is ALWAYS compiled even when the browser feature is not enabled.

**Recommendation:** Move `chromiumoxide` to an optional dependency:
```toml
[dependencies]
chromiumoxide = { version = "...", optional = true }

[features]
browser = ["chromiumoxide", "futures"]
```
This will dramatically reduce compile time when `browser` feature is not needed (which is the default case).

---

### DEP-004: parking_lot vs std::sync Inconsistency
**Severity:** low
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** yes (pipeline.rs uses both `std::sync::Mutex` and parking_lot is used elsewhere)

The codebase uses `parking_lot` for `KnowledgeGraph`'s `RwLock` (for upgradable read locks and no poisoning) but `std::sync::Mutex` for the interactive session (`pipeline.rs:3`). This is inconsistent and introduces the poisoning risk documented in SAFETY-002.

**Recommendation:** Standardize on `parking_lot` for all synchronization primitives. Add a clippy lint or workspace-level comment documenting this convention.

---

### DEP-005: rand 0.9 — Verify this is Current Stable
**Severity:** low
**Effort:** small
**Affected:** all crates using rand
**Source confirmed:** partial (workspace declares `rand = "0.9"`)

At the time of documentation generation (2026-02-23), `rand = "0.9"` should be verified against crates.io. The `rand` crate has historically had breaking changes between major versions. Verify there are no known security issues in 0.9.x.

**Recommendation:** Run `cargo update -p rand` to get the latest patch version. If rand 1.0 has been released, plan migration.

---

### DEP-006: Multiple Crates Depend on reqwest for Simple HTTP
**Severity:** low
**Effort:** small
**Affected:** aegis-enumeration, aegis-fuzzing, aegis-evasion-engine, aegis-discovery, aegis-orchestrator
**Source confirmed:** yes (cargo tree shows reqwest in 5+ crates)

`reqwest` is used in 5+ crates. For some crates (like `aegis-enumeration` which just parses OpenAPI), reqwest is a heavyweight dependency for simple HTTP fetches.

**Recommendation:** For `aegis-discovery` (which does blocking HTTP for brute-forcing), consider whether `reqwest::blocking` is appropriate or whether a lighter client like `ureq` would reduce binary size and compile time. However, consolidating on `reqwest` is likely better for consistency.

---

### DEP-007: cargo-lock Crate for Cargo.lock Parsing
**Severity:** low
**Effort:** medium
**Affected:** aegis-passive-recon
**Source confirmed:** yes (workspace declares `cargo-lock = "10"`)

The `cargo-lock` crate (version 10) parses Cargo.lock files. This is a reasonably sized dependency for a single crate's feature. However, `cargo-lock` at version 10 supports only Cargo.lock v3 format (current format). If newer Cargo.lock versions are released, this dependency may need updating.

**Recommendation:** No immediate action. Monitor `cargo-lock` for compatibility issues with future Cargo.lock format versions. Consider whether `toml` crate + custom parsing would be lighter.

---

### DEP-008: ed25519-dalek Without zeroize Feature
**Severity:** low
**Effort:** small
**Affected:** aegis-protocol, aegis-orchestrator
**Source confirmed:** yes (workspace declares `ed25519-dalek = { version = "2", features = ["rand_core"] }`)

`ed25519-dalek` supports a `zeroize` feature that zeroes key material from memory on Drop. Without it, signing keys may remain in memory after use, potentially readable via memory dumps.

**Recommendation:** Add the `zeroize` feature:
```toml
ed25519-dalek = { version = "2", features = ["rand_core", "zeroize"] }
```
This is a minor security improvement for key handling.

---

### DEP-009: No cargo-deny Configuration for License/Security Policy
**Severity:** low
**Effort:** small
**Affected:** workspace
**Source confirmed:** partial (no deny.toml found)

The workspace lacks `cargo-deny` configuration for:
- License policy enforcement (some third-party licenses may conflict with commercial use)
- Dependency duplication detection (two versions of the same crate)
- Security advisory checks (alternative to `cargo audit`)

**Recommendation:** Add a `deny.toml` to the workspace root and configure `cargo-deny` in CI:
```toml
[licenses]
allow = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]

[advisories]
ignore = []
```

---

### DEP-010: petgraph 0.7 — Verify Latest
**Severity:** low
**Effort:** small
**Affected:** aegis-chain-synthesis
**Source confirmed:** yes (workspace declares `petgraph = "0.7"`)

Verify that `petgraph 0.7.1` (currently used) is the latest stable version. petgraph is the core dependency for attack graph analysis.

**Recommendation:** Run `cargo update -p petgraph` to get the latest patch. Consider adding to `cargo-deny` watch list.
