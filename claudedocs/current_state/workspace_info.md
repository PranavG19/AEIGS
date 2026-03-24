# AEGIS Workspace Information

<!-- metadata: workspace overview, crate listing, dependency graph, binary entry points -->

## Project Overview

| Field | Value |
|-------|-------|
| **Name** | AEGIS — Adversarial Vulnerability Discovery Framework |
| **Version** | 0.1.0 (all crates) |
| **Rust Edition** | 2024 |
| **License** | MIT |
| **Resolver** | Cargo v2 |
| **Toolchain** | Stable (no rust-toolchain.toml — uses system stable) |
| **Cargo.lock** | Present (dependencies pinned) |
| **Build scripts** | None (no build.rs in any crate) |
| **Custom Cargo config** | None (.cargo/config.toml absent) |

**Description:** A security testing framework for web applications providing automated vulnerability discovery through passive recon, active enumeration, AI-driven fuzzing, attack chain synthesis, and compliance reporting. Designed for authorized penetration testing of localhost targets (remote scanning requires explicit authorization flags).

---

## Binary Entry Points

| Binary | Crate | Path |
|--------|-------|------|
| `aegis` | aegis-orchestrator | `crates/orchestrator/src/main.rs` |

The `aegis` binary is the sole user-facing CLI. All other crates are libraries consumed by the orchestrator.

---

## Workspace Members (17 crates)

### Core Foundation

| Crate | Package Name | Description |
|-------|-------------|-------------|
| `crates/protocol` | `aegis-protocol` | Shared types and contracts across all crates. NodeType, EdgeLabel, VulnerabilityClass, FuzzRequest/Response, EvidenceLevel, GraphOperation, audit events, IPC types, security attestation types. No internal deps — the dependency root. |
| `crates/knowledge-graph` | `aegis-knowledge-graph` | In-memory graph engine with arena-style Vec storage and parking_lot::RwLock. Stores nodes, edges, and findings about scanned targets. Provides semantic edge validation, JSON persistence, and batch operation log. |
| `crates/audit-log` | `aegis-audit-log` | Hash-chained, HMAC-signed append-only audit log. SHA3-256 chain + CBOR serialization. Provides AuditWriter trait, event sourcing (replay/snapshot/diff), tamper detection. |
| `crates/supervisor` | `aegis-supervisor` | Process lifecycle management and capability token validation. Uses subtle crate for timing-safe token comparison. Depends on audit-log for operator event recording. |

### Scanning Pipeline Crates

| Crate | Package Name | Description |
|-------|-------------|-------------|
| `crates/passive-recon` | `aegis-passive-recon` | Lock file parsing (cargo-lock), OSV vulnerability DB (SQLite), filesystem walking. Populates knowledge graph with dependency vulnerabilities. |
| `crates/enumeration` | `aegis-enumeration` | Route discovery from OpenAPI specs, GraphQL introspection/fallback, auth matrix analysis, auth flow modeling. Produces FuzzTarget candidates. |
| `crates/fuzzing` | `aegis-fuzzing` | Priority scheduler (BinaryHeap, novelty-based), payload mutation/generation, rate-limited HTTP execution, counterfactual anomaly oracle, WAF/rate-limit/bot detection, WebSocket/SSE streaming fuzzer, UCB1 payload selector. Also contains merged defense-fingerprinting types (WAF, rate limit, bot detection). |
| `crates/evasion-engine` | `aegis-evasion-engine` | Persona-based HTTP transport (10 personas), header/encoding transforms, timing jitter, session rotation, TLS fingerprint abstraction (JA3, dual-backend Reqwest/Rquest). Enforces localhost target validation. |
| `crates/chain-synthesis` | `aegis-chain-synthesis` | Attack graph construction (petgraph DiGraph), shortest path analysis, centrality, defense gap analysis, DOT export, causal mitigation impact estimation. |
| `crates/reporting` | `aegis-reporting` | Risk scoring (defense-aware, confidence-weighted), SARIF 2.1.0 output (CWE + ATT&CK), CBOR certificates, multi-format reports (Developer/Security/Executive). |
| `crates/crawler` | `aegis-crawler` | Headless browser crawling via chromiumoxide. JS endpoint extraction with 7 regex patterns, sitemap/robots.txt parsing. |

### Auxiliary Capabilities

| Crate | Package Name | Description |
|-------|-------------|-------------|
| `crates/compliance` | `aegis-compliance` | CVSS v3.1 scoring (FIRST spec), OWASP Top 10 2021 + API Security 2023 + PCI-DSS compliance mapping, pentest report generation. Used only in orchestrator dev-dependencies (tests). |
| `crates/discovery` | `aegis-discovery` | Directory brute-forcing (2,013 paths), JS endpoint extraction (7 regex patterns), backup file scanning (40 paths), technology fingerprinting, parameter discovery (67 params), virtual host discovery (31 prefixes). Used only in orchestrator dev-dependencies (tests). |
| `crates/exploiter` | `aegis-exploiter` | Tool wrapper framework (ToolWrapper trait), SQLMap/Nuclei/Nmap/Subfinder/Interactsh wrappers, native JWT vulnerability tester. Used only in orchestrator dev-dependencies (tests). |
| `crates/proxy` | `aegis-proxy` | HTTP recording proxy (hyper-based), request repeater, 4-mode intruder (Sniper/BatteringRam/Pitchfork/ClusterBomb), proxy-to-knowledge-graph sync. |

### Infrastructure

| Crate | Package Name | Description |
|-------|-------------|-------------|
| `crates/orchestrator` | `aegis-orchestrator` | CLI binary (clap), full scan pipeline orchestration, LLM hypothesis bridge, scan checkpoints/resume, benchmark evaluation, confidence calibration, distributed coordination, telemetry, vulnerability DB updater. **The integration point for all other crates.** |
| `crates/test-support` | `aegis-test-support` | Test utilities: in-process axum HTTP server builder, audit log helpers. Used as dev-dependency by passive-recon and enumeration. |

---

## Internal Dependency Graph

```
aegis-protocol  (no internal deps — foundation)
    │
    ├──► aegis-knowledge-graph
    │         │
    │         ├──► aegis-passive-recon ──► (uses test-support in dev)
    │         ├──► aegis-enumeration   ──► (uses test-support in dev)
    │         ├──► aegis-fuzzing
    │         ├──► aegis-chain-synthesis
    │         └──► aegis-reporting ──► (also uses aegis-fuzzing)
    │
    ├──► aegis-audit-log
    │         │
    │         └──► aegis-supervisor
    │
    ├──► aegis-evasion-engine
    ├──► aegis-crawler
    ├──► aegis-compliance
    ├──► aegis-discovery
    ├──► aegis-exploiter
    ├──► aegis-proxy
    └──► aegis-test-support ──► (also uses aegis-audit-log)

aegis-orchestrator  (depends on all of the above except compliance/discovery/exploiter which are dev-only)
    ├── [runtime] protocol, knowledge-graph, audit-log, supervisor
    ├── [runtime] passive-recon, enumeration, fuzzing, chain-synthesis
    ├── [runtime] reporting, evasion-engine, crawler
    └── [dev-only] compliance, discovery, exploiter
```

**Key structural observations:**
- `aegis-protocol` is the single dependency root — all crates depend on it, none depend back on it
- `aegis-orchestrator` is the single integration point — the only binary, depends on 11 runtime crates
- `aegis-compliance`, `aegis-discovery`, `aegis-exploiter` are dev-dependencies only — not linked into the production binary
- `aegis-proxy` has no consumer in this workspace (standalone library)
- `aegis-test-support` exists solely for test utilities (no production usage path)

---

## Crate Dependency Layers

```
Layer 0 (foundation):   protocol
Layer 1 (storage):      knowledge-graph, audit-log
Layer 2 (capabilities): supervisor, passive-recon, enumeration, fuzzing,
                         chain-synthesis, reporting, evasion-engine, crawler
                         compliance, discovery, exploiter, proxy, test-support
Layer 3 (integration):  orchestrator
```

---

## Test Structure Overview

| Category | Count |
|----------|-------|
| Rust workspace tests | 4,073 |
| Python hypothesis-engine tests | 511 |
| Docker Tier 2 integration tests | 34 (gated: `AEGIS_INTEGRATION_TESTS=1`) |

Each crate follows `{module}_test.rs` adjacent-file convention with `#[path]` attributes in source files.

---

## Python Component

`hypothesis-engine/` (separate Python package, not a Cargo crate):
- Managed by `uv` / Poetry with Python >= 3.12
- Provides LLM-based vulnerability hypothesis generation
- Communicates with Rust orchestrator via JSON IPC (stdin/stdout subprocess)
- Backends: AWS Bedrock (default), OpenAI-compatible, ollama
