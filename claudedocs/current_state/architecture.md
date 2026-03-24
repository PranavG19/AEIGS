# AEGIS System Architecture

<!-- metadata: system architecture, design patterns, concurrency model, async boundaries, pipeline phases, security design -->

## High-Level Architecture

AEGIS is a pipeline-based security scanner organized around a **central knowledge graph** that all pipeline phases read from and write to. The architecture separates:

1. **Foundation** (`protocol`) — shared type contracts, all other crates depend on this
2. **Storage** (`knowledge-graph`, `audit-log`) — persistence and integrity
3. **Pipeline phases** — each crate owns one responsibility in the scan pipeline
4. **Integration** (`orchestrator`) — wires all phases, provides CLI

```
                    ┌─────────────────────────────────────────┐
                    │         aegis-orchestrator (CLI)         │
                    │                                          │
                    │  recon → crawl → fingerprint →          │
                    │  (fuzz → analyze)* → dom_verify →        │
                    │  report                                  │
                    └──────────────┬──────────────────────────┘
                                   │ all phases read/write
                                   ▼
                    ┌─────────────────────────────────────────┐
                    │         KnowledgeGraph (in-memory)       │
                    │   RwLock<Inner{NodeStore, EdgeStore,     │
                    │   FindingStore, OperationLog}>           │
                    └─────────────────────────────────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │     aegis-protocol           │
                    │  (shared types: NodeType,    │
                    │   VulnerabilityClass, etc.)  │
                    └─────────────────────────────┘
```

---

## Core Architectural Decisions

### 1. Knowledge Graph as Shared State

All pipeline phases communicate via the knowledge graph rather than passing data directly. This enables:
- Clean phase boundaries (each phase is independently testable)
- Incremental scan resumption (graph persisted to JSON)
- Cross-phase analysis (chain-synthesis reasons about the full graph)
- Event sourcing (operation log enables replay)

**Pattern:** Each phase returns `Vec<OperationLogEntry>` and applies them via `graph.apply_operations()`. No phase directly modifies graph internals.

### 2. Trait-Based Abstractions at Boundaries

Two key interfaces enable testing and flexibility:

```
GraphStore trait — abstracts knowledge graph access
  KnowledgeGraph (concrete, full implementation with parking_lot RwLock)
  TestFakeGraph (lightweight in tests — no locks, no validation)

AuditWriter trait — abstracts audit logging
  AuditLogWriter (persists SHA3-256 chain + HMAC to CBOR file)
  NoOpAuditLogWriter (discards all events for --no-audit mode)
```

### 3. Protocol Crate as Contract Layer

All shared types live in `aegis-protocol`. This crate has zero internal dependencies — it is the dependency root. The `ModuleIdentifier` enum specifically prevents circular dependencies: modules are identified by enum variant, not by importing each other's types.

### 4. Atomic Validate-Then-Apply via RwLockUpgradableReadGuard

The knowledge graph uses `parking_lot::RwLockUpgradableReadGuard` for mutation:
1. Acquire upgradable read lock (allows concurrent readers during validation)
2. Validate entire batch (semantic edge checks, weight bounds, duplicate detection)
3. Atomically upgrade to write lock (no other writer can intervene)
4. Apply batch
5. Release write lock

This eliminates the TOCTOU gap — no partial application is possible. A batch either fully succeeds or the graph is unchanged.

### 5. Localhost Enforcement at Three Layers

Target URL validation is enforced at:
1. `aegis-protocol::target_validation` — shared validator used by all HTTP clients
2. `aegis-evasion-engine::transport` — before every HTTP request
3. `aegis-fuzzing::executor` — before executing fuzz requests

Override paths: `--scope-attestation` (Ed25519-signed) or `--i-am-authorized` flag (recorded in audit).

---

## Pipeline Architecture

### Phase Sequence and Data Flow

```
Phase           Input                           Output                  Module
───────         ─────                           ──────                  ──────
recon           source_dir + vuln_db            OperationLogEntry[]     passive-recon
                                                (Dependency nodes)
crawl           target URL                      OperationLogEntry[]     crawler
                                                (Endpoint nodes)
fingerprint     target URL + source_dir         OperationLogEntry[]     enumeration
                                                (Defense + Endpoint     evasion-engine
                                                nodes)
fuzz:N          graph endpoints +               OperationLogEntry[]     fuzzing
                evasion transport +             (Finding nodes)         evasion-engine
                LLM payloads
analyze:N       graph state                     OperationLogEntry[]     chain-synthesis
                                                (chain findings)
dom_verify      graph findings                  OperationLogEntry[]     crawl/reporting
                                                (verified findings)
report          graph (all data)                SARIF file              reporting
```

### Iterative Fuzz-Analyze Loop

The scan runs `max_iterations` fuzz→analyze rounds (default 1). Convergence stops the loop when `N` consecutive rounds produce zero new findings:

```
for iteration in 0..max_iterations:
  fuzz(graph) → new findings?
  → LLM hypothesis step → inject payloads into next iteration
  analyze(graph) → chain findings?
  if both zero N times → break (converged)
```

### Capability System (Least Privilege)

Each pipeline phase operates under capability tokens:

```
Module           Permissions
──────           ───────────
PassiveRecon     ReadFilesystem, WriteGraph
Enumeration      ReadGraph, WriteGraph, ExecuteRequests
Fuzzing          ReadGraph, WriteGraph, ExecuteRequests
ChainSynthesis   ReadGraph, WriteGraph
HypothesisEngine ReadGraph (read-only)
```

Tokens are HMAC-signed with a per-scan random master key. Validation is advisory (non-blocking) — failures generate warnings in the audit trail.

---

## Concurrency Model

**Runtime:** Tokio multi-threaded (via `#[tokio::main]`). Single tokio runtime for the full scan.

**Thread types in a scan:**
1. **Tokio runtime threads** (N workers) — async pipeline execution
2. **OS threads for blocking work** (via `std::thread::spawn`):
   - Defense fingerprinting probe (reqwest::blocking cannot run in tokio runtime)
   - OpenAPI/GraphQL discovery (blocking HTTP)
   - Interactive stdin reader
3. **Python subprocess** — hypothesis-engine, blocking stdin/stdout I/O

**Shared state in ScanContext:**
```rust
ScanContext {
  graph: Box<dyn GraphStore>   // KnowledgeGraph behind RwLock — thread-safe
  // All other fields owned by the single pipeline execution path
}
```

The main pipeline is single-threaded async — there's no concurrent execution of phases. Concurrency only occurs within the fingerprint phase sub-tasks.

**No channels:** The pipeline does not use `mpsc`/`broadcast`/`watch` channels. Data flows directly via function returns and graph mutations.

---

## Design Patterns in Use

### Builder Pattern

All configuration structs use fluent `with_*` builder methods:

```rust
// NodeData
NodeData::new(id, NodeType::Endpoint)
    .with_property("path", "/api/login")
    .with_property("method", "POST")

// EvasionTransport
EvasionTransport::builder()
    .with_persona(&persona)
    .with_accept_self_signed(true)
    .with_scope_attestation(attestation)
    .build()

// DefenseProfile
DefenseProfile::new()
    .with_waf(waf_fingerprint)
    .with_rate_limit(rate_limit_profile)
    .with_bot_detection(bot_detection_result)
```

### Repository Pattern (via GraphStore trait)

Pipeline phase functions accept `&dyn GraphStore` or `&mut dyn GraphStore`. Test implementations:
```rust
// Real production implementation
let graph: Box<dyn GraphStore> = Box::new(KnowledgeGraph::new());

// Test fake (no locking, no validation overhead)
let graph: Box<dyn GraphStore> = Box::new(TestFakeGraphStore::new());
```

### Command Pattern (GraphOperation enum)

Operations are first-class values: created by one module, validated by another, applied to the store. The operation log enables:
- Batch atomic validation
- Event sourcing / replay
- Provenance tracking (which module created which node)

### Strategy Pattern (Pluggable Backends)

- **Audit writer**: `Box<dyn AuditWriter>` — swap between file-based and no-op at runtime
- **LLM backend** (Python): `LlmBackend` ABC — swap between Bedrock/OpenAI/ollama via factory
- **HTTP transport**: `HttpClientBackend` enum — Reqwest (current) or Rquest (planned, TLS fingerprint control)

### Facade Pattern (KnowledgeGraph)

`KnowledgeGraph` wraps `RwLock<KnowledgeGraphInner>`. Callers never see the lock or the inner struct. All mutations go through the facade's public API which handles locking, validation, and atomicity.

### Event Sourcing

`OperationLogEntry` records form an ordered sequence of graph mutations. The full operation history allows:
- Replay to reconstruct graph state
- Diff between scan snapshots
- Audit trail of which module made which change

---

## Security Architecture

### Defense-in-Depth for Authorization

```
Layer 1: Target validation at protocol level (localhost enforcement)
Layer 2: Scope attestation (Ed25519-signed authorization document)
Layer 3: Capability tokens (HMAC-signed, per-module least-privilege)
Layer 4: Audit logging (SHA3-256 hash chain + HMAC tamper detection)
Layer 5: Signed config (Ed25519 signature on scan parameters)
```

Override escalation: `--scope-attestation` > `--i-am-authorized` flag (recorded in audit)

### Audit Log Integrity

```
Entry N: [sequence][hash(payload_N)][payload_N_cbor][hmac(payload_N)]
  where hash(payload_N) = SHA3-256(prev_hash || payload_N_cbor)

Verification: replay chain, check each hash extends previous, re-verify HMACs
```

The hash chain is SHA3-256 (not SHA2) — Keccak sponge provides structural diversity against SHA2-specific attacks.

---

## Python-Rust Integration Architecture

```
┌─────────────────────────────────┐
│  aegis-orchestrator (Rust)      │
│                                 │
│  HypothesisBridge::start()     │──spawn──► python3 -m hypothesis_engine.bridge
│     ↕ JSON lines                │           ↕ BridgeRequest/BridgeResponse
│  build_hypothesis_context()    │           ↕ stdin/stdout
│  generate_hypotheses()         │
│  compile_payloads()            │
└─────────────────────────────────┘
         ↓ payloads
┌─────────────────────────────────┐
│  FuzzScheduler                  │  Injects LLM payloads alongside
│  UCB1 payload selector          │  static/mutation-based payloads
└─────────────────────────────────┘
```

IPC protocol: JSON-newline, internally-tagged with `"type"` discriminant. Framing: one JSON object per line.

---

## Attack Graph Architecture

Source: `crates/chain-synthesis`

```
KnowledgeGraph (property graph)
         ↓ convert
AttackGraph (petgraph DiGraph)
         ↓ algorithms
  - shortest path (A*)
  - all simple paths (bounded DFS, MAX_TOTAL_PATHS=100,000)
  - betweenness centrality
  - cut vertices (bridges in attack graph)
  - defense gap analysis
         ↓ export
  DOT format (Graphviz)
  D3 JSON format
```

**Edge weights** encode traversal difficulty. Lower weight = easier for attacker. Priority-bounded DFS explores lowest-weight edges first (most-exploitable paths found before cap hit).

**Mitigation estimation:** `estimated_mitigation_impact(node)` removes a node from the attack graph and computes which findings become unreachable — structural graph estimate, not causal claim.

---

## Evasion Engine Architecture

Source: `crates/evasion-engine`

```
EvasionTransport
  ├── PersonaId → PersonaCatalog → HTTP headers, User-Agent, timing parameters
  ├── HeaderTransformer → randomize non-essential headers
  ├── EncodingTransformer → URL encoding variations
  ├── TimingController → request jitter (min/max intervals from persona)
  ├── SessionManager → cookie jar rotation
  └── TlsConfig → JA3 fingerprint mapping
                    ChromeDesktop|Firefox|Safari|Edge|Curl

Transport auto-adjusts from DefenseProfile:
  WAF detected → cap rps to 5
  Rate limit detected → rps = detected_rps * 0.8
  Bot detection detected → log recommendation for paranoid mode
```

**TLS fingerprint backends:**
- `Reqwest` — always available, standard TLS
- `Rquest` — planned, JA3/JA4 control for WAF evasion

---

## Fuzzing Architecture

Source: `crates/fuzzing`

```
FuzzTarget (endpoint + method + parameter + vulnerability_class + priority)
         ↓ enqueue
FuzzScheduler (BinaryHeap, UCB1 scoring)
         ↓ dequeue (highest priority first)
PayloadSelector (UCB1 multi-armed bandit)
         ↓ select payload origin
PayloadMutator → tagged payloads (Template|Generative|BitFlip|Boundary|BypassCorpus)
         ↓
FuzzExecutor
  ├── EvasionTransport → HTTP requests
  ├── AnomalyOracle (counterfactual: paired control/treatment requests)
  └── WafFingerprinter + RateLimitDetector + BotDetectionProbe (defense detection)
         ↓
FuzzPhaseResult → OperationLogEntry[] (findings)
```

**UCB1 for payload selection:** `score = mean_success + C * sqrt(ln(total_trials) / trials_for_arm)`. Novel payloads (trials=0) get infinite score — always tried first.

**Counterfactual testing:** For each fuzz request, send a paired "control" request with a benign payload. Anomaly is detected when treatment differs from control, eliminating false positives from broken endpoints.

---

## Module-Level Summary

| Crate | Phase | Inputs | Outputs | Key Types |
|-------|-------|--------|---------|-----------|
| passive-recon | recon | source_dir, vuln_db | Dependency + finding nodes | VulnerabilityRecord, ParsedDependency |
| enumeration | fingerprint | target URL, OpenAPI/GraphQL | Endpoint + Function nodes | IntrospectedEndpoint, AuthFlow |
| crawler | crawl | target URL | Endpoint nodes | CrawlResult |
| fuzzing | fuzz | graph endpoints + transport | Finding nodes | FuzzTarget, FuzzScheduler, AnomalyOracle |
| evasion-engine | transport | PersonaId, StealthConfig | HTTP requests | EvasionTransport, PersonaCatalog |
| chain-synthesis | analyze | graph | chain findings | AttackGraph, PathResult |
| reporting | report | graph + metrics | SARIF/JSON file | SarifFinding, RiskScorer |
| compliance | (dev tests) | findings | CVSS/compliance scores | CvssScore, OwaspMapping |
| discovery | (dev tests) | target URL | discovered paths | DirectoryBruteForcer |
| exploiter | (dev tests) | target URL | tool outputs | ToolWrapper, JwtTester |
| proxy | standalone | HTTP traffic | recorded requests | RecordingProxy, Intruder |
| supervisor | pipeline init | module policies | capability tokens | CapabilityManager |
| audit-log | throughout | events | CBOR audit trail | AuditWriter, HashChain |

---

## Data Flow Architecture (Detailed)

```
RECON (Source)
  - Filesystem walk → dependency parsing → vuln DB lookup
  - Emits: EndpointDiscovered events + AddNode(Endpoint, Dependency) ops
       ↓
FINGERPRINT (Source)
  - HTTP probing → WAF/rate-limit/bot detection → tech stack inference
  - Emits: AddNode(Defense) ops + DefenseProfile in ScanContext
       ↓
FUZZ (Transform)  ─────────────────────── LOOP ───────────────────────────┐
  - Priority scheduler dequeues FuzzTargets                                │
  - Mutator generates TaggedPayload[] (5 strategies + LLM payloads)       │
  - Executor sends request pairs (counterfactual: benign + malicious)      │
  - Oracle compares responses → detects anomaly by AnomalyType             │
  - Emits: PayloadTested, AnomalyDetected events + AddFinding ops          │
       ↓                                                                    │
HYPOTHESIS BRIDGE (if !--no-llm)                                           │
  - Builds ScanContextJson from graph (tech stack, findings, history rates) │
  - Unix socket → Python LLM → hypotheses + compiled payloads              │
  - Filtered payloads stored in ScanContext.llm_payloads                   │
       ↓                                                                    │
ANALYZE (Transform)                                                         │
  - KnowledgeGraph findings → AttackGraph (petgraph DiGraph)               │
  - A* shortest paths, betweenness centrality, defense gap analysis        │
  - graph_influence_ranking() → mitigation priority                        │
  - Emits: FindingConfirmed events + AddFinding(chain) ops                 │
       ↓                                                                    │
CONVERGENCE CHECK                                                           │
  - fuzz_findings + analyze_findings == 0? → consecutive_zero++           │
  - If consecutive_zero >= threshold: break loop                           │
  - Else: ──────────────────────────────────────────────────────────────────┘
       ↓
DOM_VERIFY (Transform)  [if browser feature enabled]
  - XSS findings verified via chromiumoxide DOM execution
  - inject_xss_instrumentation() → navigate → check_xss_markers()
  - Emits: FindingConfirmed events with confidence_boost
       ↓
REPORT (Sink)
  - RiskScorer: CVSS × confidence × defense adjustment
  - SarifEmitter: SARIF 2.1.0 with CWE + ATT&CK enrichment (or Executive JSON)
  - Attack graph export if --export-graph
  - Write to --output path
       ↓
AUDIT VERIFICATION
  - verify_log(): SHA3-256 hash chain + HMAC check
  - Returns audit_verified: Option<bool> in ScanSummary

Knowledge Graph accumulates OperationLogEntry[] from ALL phases:
  RECON ops → FINGERPRINT ops → FUZZ finding ops → ANALYZE chain ops
  All applied via atomic validate-then-apply (upgradable RwLock)
  Persisted to --graph-db JSON if configured
```
