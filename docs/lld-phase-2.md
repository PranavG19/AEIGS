# AEGIS Phase 1.5 + Phase 2: Low-Level Design Document

**Document Version:** 1.0
**Date:** 2026-02-18
**Status:** Draft

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Current State Assessment](#2-current-state-assessment)
3. [Phase 1.5 — Refactoring Existing Crates](#3-phase-15--refactoring-existing-crates)
   - 3.1 Migrate chain-synthesis to petgraph
   - 3.2 Replace SARIF emitter with sarif_rust
   - 3.3 Replace OpenAPI parsing with openapiv3
   - 3.4 Replace GraphQL parsing with graphql-parser
   - 3.5 Replace Cargo.lock parser with cargo-lock crate
   - 3.6 Unify VulnerabilityClassTarget into protocol VulnerabilityClass
   - 3.7 Remove dead dependencies
   - 3.8 Add certificate versioning envelope
   - 3.9 Add default headers to FuzzRequest
   - 3.10 Validate full operation batch before applying
4. [Phase 2 — Adversarial Simulation Layer](#4-phase-2--adversarial-simulation-layer)
   - 4.1 Defense Stack Composer (Docker infrastructure)
   - 4.2 Evasion Engine (new Rust crate)
   - 4.3 Defense Fingerprinting Module (new Rust crate)
   - 4.4 Stealth Fuzzing Mode (augment fuzzing crate)
   - 4.5 Evasion Feedback Loop (augment hypothesis-engine)
   - 4.6 WAF Bypass Payload Integration (augment fuzzing + hypothesis-engine)
   - 4.7 Reporting Enhancements (augment reporting crate)
   - 4.8 Orchestrator CLI (new Rust crate)
5. [New Dependency Registry](#5-new-dependency-registry)
6. [Testing Strategy](#6-testing-strategy)
7. [Migration and Rollout Order](#7-migration-and-rollout-order)

---

## 1. Introduction

### 1.1 Purpose

This document specifies the low-level design for two sequential workstreams on the AEGIS codebase:

**Phase 1.5 (Refactoring):** Ten targeted refactors to the existing nine crates. These replace hand-rolled implementations with battle-tested libraries, eliminate type duplication, remove dead dependencies, and fix design gaps that would complicate Phase 2 integration. Phase 1.5 produces no new user-facing features — it reduces maintenance surface and increases correctness before building on top.

**Phase 2 (Adversarial Simulation Layer):** Eight new components that teach AEGIS to test against realistic defenses (WAFs, rate limiters, bot detection) deployed in the localhost environment. Phase 2 adds two new Rust crates, Docker infrastructure, and augments four existing components. The core principle is unchanged: bring defenses to localhost, not AEGIS to the internet.

### 1.2 Design Constraints

All design decisions in this document are bound by:

- **Localhost-only operation.** No changes introduce remote target scanning. Defense stacks run locally.
- **Existing conventions.** No comments in code. One public type per file. Functions under 40 lines. Enums over strings. Builder pattern for config. Adjacent test files via `#[path]` attribute. `lib.rs` contains only re-exports.
- **Existing tech stack.** Rust 2024 edition. Python >= 3.12 via uv. SHA3-256 for hashing. CBOR via ciborium. AWS Bedrock for LLM inference.
- **Test coverage parity.** Every new module has an adjacent test file. Every refactored module retains or increases test count. Zero-warnings clippy policy. `cargo fmt` gate.
- **No Anthropic model fine-tuning.** Claude models on Bedrock do not support fine-tuning. All LLM-driven improvements use prompt engineering with curated in-context examples.

### 1.3 Out of Scope

The following items from the original Phase 2 proposal are excluded with rationale:

| Excluded Item | Reason |
|---|---|
| Cloudflare Tunnel defense stack | Traffic leaves localhost, violates confinement principle |
| Claude fine-tuning on WAF bypass corpus | Anthropic models are not fine-tunable on Bedrock |
| Mouse movement / browser event simulation | Requires headless browser runtime, fundamentally different execution model from HTTP-based fuzzing; deferred to Phase 3 if needed |
| Taint analysis expansion (2000 to 5000 patterns) | No taint analysis module exists in the codebase; `TaintAnalysis` is an unused `ModuleIdentifier` variant |
| Distributed scanning / master-slave architecture | Violates localhost-only constraint |
| Cross-language taint tracking | No taint analysis module exists |

### 1.4 Document Conventions

- **File paths** are relative to the workspace root (`/`) unless prefixed with `crates/` or `hypothesis-engine/`.
- **"Adjacent test file"** means `{module}_test.rs` co-located with `{module}.rs`, included via `#[path]` attribute.
- **Library names** in monospace refer to crates.io packages (Rust) or PyPI packages (Python).
- **No code appears in this document.** Implementation details are described structurally and algorithmically.

---

## 2. Current State Assessment

This section documents the actual state of each crate as investigated, correcting assumptions from the original Phase 2 proposal where necessary.

### 2.1 Crate Inventory

| Crate | Lines (src) | Tests | Key Responsibility |
|---|---|---|---|
| `protocol` | ~350 | 42 | Shared types: NodeType (8), EdgeLabel (7), VulnerabilityClass (16), GraphOperation (4), ModuleIdentifier (6), IPC messages |
| `knowledge-graph` | ~800 | 89 | Arena-style graph storage, RwLock concurrency, BFS/DFS/Dijkstra/Tarjan/betweenness algorithms |
| `audit-log` | ~300 | 38 | SHA3-256 hash chain, HMAC-SHA3-256 signing, CBOR-serialized append-only log |
| `supervisor` | ~250 | 32 | Process lifecycle (ComponentId, backoff restart), SHA3-256 capability token issuance |
| `passive-recon` | ~450 | 47 | Lock file parsing (5 ecosystems), SQLite vuln DB, filesystem walker |
| `enumeration` | ~500 | 53 | Route parsing (5 frameworks), OpenAPI/GraphQL introspection, auth matrix anomaly detection |
| `fuzzing` | ~550 | 42 | Priority scheduler, payload mutator (10 classes, 46 templates), rate limiter, anomaly oracle |
| `chain-synthesis` | ~400 | 35 | Attack graph construction, Dijkstra/BFS/DFS path analysis, betweenness centrality |
| `reporting` | ~400 | 46 | Risk scorer (custom composite), SARIF 2.1.0 emitter (~40% spec), CBOR certificate serializer (5 types) |
| `hypothesis-engine` | ~600 | 52 | Bedrock LLM integration, hypothesis generation, test compilation, feedback loop |

**Total: ~4,600 lines of source, 476 tests.**

### 2.2 Corrections to Original Proposal

The original Phase 2 proposal made several claims about the current state that do not match the codebase:

| Original Claim | Actual State |
|---|---|
| "TPM + eBPF + watchdog makes localhost-only enforcement cryptographically strong" | No TPM integration, no eBPF filter, no watchdog process exists. The supervisor crate manages process lifecycles and capability tokens. Localhost-only is a convention enforced by configuration, not by kernel-level network filtering. |
| "Confinement stack prevents misuse" | No confinement stack exists. The capability token system in supervisor restricts inter-module permissions (ReadGraph, WriteGraph, ExecuteRequests, ReadFilesystem, WriteAuditLog) but does not enforce network boundaries. |
| "Currently ~2000 source/sink taint patterns" | No taint analysis module exists. `TaintAnalysis` is declared as a `ModuleIdentifier` variant but has no implementing crate. |
| "Currently ~30 frameworks supported" | The enumeration crate supports 5 frameworks: Express, Flask, FastAPI, Django, Spring. |
| "Parallelize fuzzing across multiple endpoints (currently serial)" | The fuzzing crate does not execute HTTP requests. `RequestExecutor` builds `FuzzRequest` structs; the caller is responsible for transport. Parallelism is a caller concern, not a crate limitation. |

### 2.3 Identified Technical Debt

**Dead dependencies:**
- `knowledge-graph` declares `petgraph` but never imports it
- `reporting` declares `tracing` but never imports it

**Type duplication:**
- `fuzzing::VulnerabilityClassTarget` (10 variants) duplicates a subset of `protocol::VulnerabilityClass` (16 variants) with a naming mismatch (`Deserialization` vs `InsecureDeserialization`)

**Unused enum variants:**
- `fuzzing::MutationStrategy::Generative` is declared but never constructed
- `protocol::ModuleIdentifier::TaintAnalysis` has no implementing crate

**Library underuse:**
- `chain-synthesis` depends on `petgraph` but reimplements all its algorithms by hand (~260 lines of redundant graph code)
- `enumeration` hand-parses OpenAPI and GraphQL instead of using `openapiv3` / `graphql-parser`
- `reporting` hand-builds SARIF JSON covering ~40% of the spec instead of using `sarif_rust`
- `passive-recon` hand-parses Cargo.lock via string matching instead of using the `cargo-lock` crate

**Design gaps:**
- Certificate serializer has no version envelope; adding new certificate types breaks deserialization of existing blobs
- `FuzzRequest.headers` is always initialized empty; requests lack basic browser-like headers
- `OperationLog.apply_batch` can partially apply a batch, leaving the graph in an inconsistent state if a later operation in the batch fails
- No orchestrator binary exists to wire the crates into an end-to-end scan pipeline

### 2.4 Architectural Strengths (Do Not Change)

The following design decisions are sound and should be preserved:

- **Arena-style Vec storage in knowledge-graph.** O(1) lookup by stable u64 index. The public API contract across all crates depends on u64 node/edge IDs. Do not replace with petgraph (whose NodeIndex is opaque and unstable across deletions).
- **RwLock\<Inner\> facade in KnowledgeGraph.** Coarse-grained locking is simpler and sufficient for the current single-orchestrator model.
- **CBOR + SHA3-256 for certificates.** Compact, deterministic, RFC-standardized. No reason to change serialization format.
- **Append-only hash-chained audit log.** Tamper-evident by design. The HMAC layer adds authentication.
- **Hypothesis engine three-stage pipeline (generate → compile → feedback).** Clean separation. Extensible via new context fields and prompt modes.
- **Multiplicative risk scoring formula.** Contextual (incorporates reachability and blast radius), which is more useful for a security testing tool than pure CVSS.

---

## 3. Phase 1.5 — Refactoring Existing Crates

All ten refactors in this section are prerequisite to Phase 2. They are ordered by dependency — later items may depend on earlier ones completing first.

### 3.1 Migrate chain-synthesis to petgraph

**Crate:** `crates/chain-synthesis`
**Files affected:** `attack_graph.rs`, `path_analysis.rs`, `Cargo.toml`, `lib.rs`, and their adjacent test files
**Library:** `petgraph` 0.7 (already a workspace dependency)

#### Rationale

chain-synthesis declares petgraph as a dependency but never imports it. Instead, it hand-rolls a complete graph engine: HashMap-based node storage, Vec-based edge storage, manual adjacency list maintenance, plus four graph algorithms (BFS reachability, Dijkstra shortest path, DFS all-simple-paths, betweenness centrality). All four algorithms have direct equivalents in `petgraph::algo`. This is ~260 lines of redundant, less-tested graph logic.

#### Structural Changes

**attack_graph.rs — Replace custom graph storage with petgraph::DiGraph:**

The current `AttackGraph` struct contains three fields: a HashMap of nodes, a Vec of edges, and a HashMap adjacency list. Replace all three with a single `petgraph::DiGraph<AttackNode, AttackEdge>` field plus a reverse-lookup `HashMap<u64, petgraph::graph::NodeIndex>` to preserve the u64-based public API.

`AttackNode` and `AttackEdge` structs remain unchanged — they become the generic parameters of the DiGraph. `AttackNodeType` enum remains unchanged.

The `AttackPath` struct remains unchanged — it is a result type, not a storage type.

Public API changes:
- `add_node(label, node_type) -> u64` — internally calls `DiGraph::add_node()`, stores mapping from u64 to NodeIndex, returns u64
- `add_edge(source, target, difficulty, vulnerability_id)` — looks up NodeIndex for source/target, calls `DiGraph::add_edge()`
- `outgoing_edges(node_id) -> Vec<&AttackEdge>` — looks up NodeIndex, iterates `DiGraph::edges()` for that node
- `entry_points() -> Vec<u64>` and `assets() -> Vec<u64>` — filter `DiGraph::node_weights()` by type, map back to u64
- `node_count()`, `edge_count()` — delegate to DiGraph methods

No public API signature changes. Only internal storage changes.

**path_analysis.rs — Replace hand-rolled algorithms with petgraph::algo:**

| Current Function | Replacement |
|---|---|
| `bfs_reachable(graph, start) -> HashSet<u64>` | `petgraph::visit::Bfs` iterator, collecting reachable NodeIndex values and mapping back to u64 |
| `shortest_attack_path(graph, source, target) -> Option<AttackPath>` | `petgraph::algo::dijkstra()` with edge weight = `exploitation_difficulty`, followed by path reconstruction via `petgraph::algo::astar()` for the actual path |
| `all_simple_paths(graph, source, target, max_depth) -> Vec<AttackPath>` | `petgraph::algo::simple_paths::all_simple_paths()` with max intermediate nodes = max_depth - 2 |
| `betweenness_centrality(graph) -> HashMap<u64, f64>` | Retain custom implementation but operate on DiGraph references instead of raw adjacency lists. petgraph does not provide a direct betweenness centrality function, so this stays as a thin algorithm over petgraph's traversal iterators. |

The `reachable_assets` and `critical_fix_targets` functions are thin wrappers around the above — they adapt return types. Their logic stays the same; only the underlying calls change.

#### Test Migration

Every existing test in `attack_graph_test.rs` and `path_analysis_test.rs` must continue to pass with identical assertions. The tests verify public API behavior (add nodes, add edges, find paths, compute centrality), not internal storage layout. No test assertions should need changing — only the implementation behind the API changes.

Add one new test per algorithm to verify edge cases that petgraph handles differently from the hand-rolled version (empty graph, self-loops, disconnected components).

#### Net Effect

- Remove: ~260 lines of graph storage and algorithm code
- Add: ~80 lines of petgraph wrapper + NodeIndex mapping
- Net: ~180 line reduction, proven algorithm correctness

---

### 3.2 Replace SARIF Emitter with sarif_rust

**Crate:** `crates/reporting`
**Files affected:** `sarif_emitter.rs`, its adjacent test file, `Cargo.toml`
**Library:** `sarif_rust` (latest stable, targets SARIF 2.1.0 full spec)

#### Rationale

The current SARIF emitter defines 10 custom structs (SarifReport, SarifRun, SarifTool, SarifDriver, SarifRule, SarifResult, SarifLocation, SarifPhysicalLocation, SarifLogicalLocation, SarifResultProperties) to produce JSON that covers approximately 40% of the SARIF 2.1.0 specification. Missing features include `fixes` (remediation guidance), `codeFlows` (taint/data flow visualization), `relatedLocations`, `taxa` (CWE/PCI-DSS categorization), `stacks`, and `notifications`. These gaps mean downstream SARIF consumers (GitHub Code Scanning, Snyk, SonarQube) receive incomplete data.

#### Structural Changes

**sarif_emitter.rs — Replace custom structs with sarif_rust types:**

Delete all 10 custom SARIF structs. The module's public type becomes a builder/facade that constructs `sarif_rust` types.

The public-facing struct (currently `SarifEmitter` or equivalent) retains its public API but internally populates `sarif_rust::Sarif`, `sarif_rust::Run`, `sarif_rust::Result`, etc.

New capabilities enabled by `sarif_rust` that should be wired in:
- **`fixes`:** For each finding, generate a `Fix` object containing a `description` and `artifactChanges` pointing to the affected file + region. The fix description should come from the vulnerability class (a static mapping of VulnerabilityClass → remediation text).
- **`taxa`:** Map each `VulnerabilityClass` to its CWE identifier. This is a static lookup table (e.g., SqlInjection → CWE-89, CrossSiteScripting → CWE-79). Populate the `taxa` array on the tool driver, and reference taxa from each result.
- **`relatedLocations`:** For findings with multiple `linked_node_ids`, the primary location is the first node; remaining nodes become related locations.

Features to defer (not needed yet): `codeFlows` (requires taint analysis module), `stacks` (not captured by current finding model), `notifications` (no tool execution message model).

**Cargo.toml:** Add `sarif_rust` to dependencies. Remove manual serde_json struct definitions.

#### CWE Mapping Table

This static mapping lives in `sarif_emitter.rs` as a function from `VulnerabilityClass` to CWE ID string:

| VulnerabilityClass | CWE |
|---|---|
| SqlInjection | CWE-89 |
| CrossSiteScripting | CWE-79 |
| CommandInjection | CWE-78 |
| PathTraversal | CWE-22 |
| ServerSideRequestForgery | CWE-918 |
| InsecureDeserialization | CWE-502 |
| BrokenAuthentication | CWE-287 |
| BrokenAuthorization | CWE-862 |
| SecurityMisconfiguration | CWE-16 |
| SensitiveDataExposure | CWE-200 |
| ServerSideTemplateInjection | CWE-1336 |
| HeaderInjection | CWE-113 |
| OpenRedirect | CWE-601 |
| CrlfInjection | CWE-93 |
| KnownVulnerableDependency | CWE-1395 |
| InsufficientInputValidation | CWE-20 |

#### Test Migration

Existing tests verify JSON structure, deduplication, and location handling. After migration, tests should verify:
- Output JSON validates against the SARIF 2.1.0 JSON schema
- Each result has a `taxa` reference
- Findings with multiple linked nodes produce `relatedLocations`
- The `fixes` array is populated with remediation text

---

### 3.3 Replace OpenAPI Parsing with openapiv3

**Crate:** `crates/enumeration`
**Files affected:** `introspection.rs` (OpenAPI portion), its adjacent test file, `Cargo.toml`
**Library:** `openapiv3` (latest stable)

#### Rationale

The current OpenAPI parser defines four custom structs (OpenApiSpec, OpenApiOperation, OpenApiParameter, OpenApiSchema) and deserializes JSON via serde. This covers basic path/method/parameter extraction but misses: `$ref` resolution (references to shared schemas/parameters), security scheme definitions, server variables, request body schemas (separate from parameters in OpenAPI 3.x), and response schemas. The `openapiv3` crate handles the full OpenAPI 3.0.x specification including all of these.

#### Structural Changes

**introspection.rs — Replace custom OpenAPI structs:**

Delete the four custom OpenAPI structs. Replace with `openapiv3::OpenAPI` as the deserialization target.

The `parse_openapi` function (or equivalent) currently returns a `Vec<IntrospectedEndpoint>`. This return type remains unchanged — `IntrospectedEndpoint` is the crate's own domain type, not an OpenAPI type. The function body changes from manual JSON traversal to:

1. Deserialize input JSON into `openapiv3::OpenAPI`
2. Iterate over `openapi.paths` — each path item contains operations keyed by HTTP method
3. For each operation, resolve `$ref` references via `openapiv3`'s built-in dereferencing
4. Extract parameters (path, query, header, cookie) from both the path item level and operation level
5. Extract request body media type schemas (for POST/PUT/PATCH)
6. Map security requirements to a list of required auth schemes per endpoint
7. Construct `IntrospectedEndpoint` with the extracted fields

New fields to add to `IntrospectedEndpoint`:
- `security_schemes: Vec<String>` — names of security schemes required by this endpoint
- `request_body_content_type: Option<String>` — media type of request body if present
- `response_status_codes: Vec<u16>` — documented response codes

These new fields feed into the auth matrix analysis (section 3.3 of the codebase) and into Phase 2 defense fingerprinting.

#### Test Migration

Existing tests use inline JSON strings to test parsing. These continue to work since the output type (`IntrospectedEndpoint`) is unchanged. Add tests for:
- OpenAPI specs with `$ref` references
- Specs with security scheme requirements
- Specs with request body schemas
- Malformed/partial specs (error handling)

---

### 3.4 Replace GraphQL Parsing with graphql-parser

**Crate:** `crates/enumeration`
**Files affected:** `introspection.rs` (GraphQL portion), its adjacent test file, `Cargo.toml`
**Library:** `graphql-parser` (latest stable)

#### Rationale

The current GraphQL introspection parser defines four custom structs (GraphQlIntrospectionResponse, GraphQlSchema, GraphQlType, GraphQlField, GraphQlArg) and extracts only query/mutation field names with argument names. Type information is discarded (hardcoded to "string"). Subscriptions are ignored. The `graphql-parser` crate provides full schema parsing including type definitions, interfaces, unions, enums, input types, and directives.

#### Structural Changes

**introspection.rs — Replace custom GraphQL structs:**

Delete the four custom GraphQL structs. The module should accept two input formats:

1. **Introspection JSON response** (the `__schema` query result) — parse via serde into `graphql-parser`'s introspection types, or convert the JSON introspection result to SDL and then parse
2. **SDL string** (Schema Definition Language) — parse directly via `graphql-parser::parse_schema()`

For both paths, the output is `Vec<IntrospectedEndpoint>` where each GraphQL query/mutation/subscription field becomes one endpoint entry.

New information extractable via `graphql-parser` that the current implementation misses:
- Argument types (not just names) — enables smarter payload generation in fuzzing
- Return types — identifies which queries return sensitive data types
- Subscription fields — a new attack surface category
- Custom directives (e.g., `@auth`, `@deprecated`) — feed into auth matrix
- Input object types — complex nested inputs are common fuzzing targets

Construct `IntrospectedEndpoint` entries with:
- `endpoint`: `/graphql` (fixed path, since GraphQL uses a single endpoint)
- `method`: `POST` for mutations, `POST` or `GET` for queries
- `parameter_name`: field argument name
- `parameter_type`: resolved type name from the schema (instead of hardcoded "string")

#### Test Migration

Existing tests use inline JSON introspection responses. After migration:
- Existing introspection JSON tests should produce the same `IntrospectedEndpoint` values (modulo new fields like resolved types)
- Add tests for SDL parsing
- Add tests for subscription field extraction
- Add tests for nested input type resolution

---

### 3.5 Replace Cargo.lock Parser with cargo-lock Crate

**Crate:** `crates/passive-recon`
**Files affected:** `dependency_parser.rs` (Cargo.lock section only), its adjacent test file, `Cargo.toml`
**Library:** `cargo-lock` (latest stable)

#### Rationale

The current Cargo.lock parser uses line-by-line string prefix matching (`line.starts_with("name = ")`, `line.starts_with("version = ")`) to extract package names and versions. This is fragile: it doesn't handle quoted values correctly in all cases, ignores the `checksum` field, doesn't distinguish between direct and transitive dependencies, and would break if the Cargo.lock format adds new fields or changes whitespace conventions. The `cargo-lock` crate is maintained by the Rust project and handles all format versions.

#### Structural Changes

**dependency_parser.rs — Replace the Cargo.lock parsing branch:**

The current `parse_dependencies` function (or equivalent) takes a file path and ecosystem identifier, dispatches to ecosystem-specific parsers, and returns `Vec<ParsedDependency>` where `ParsedDependency` has fields like `name`, `version`, `ecosystem`.

Only the Cargo.lock branch changes. Replace the line-by-line scanner with:

1. Read the file contents as a string
2. Call `cargo_lock::Lockfile::from_str()` to parse
3. Iterate over `lockfile.packages` — each `Package` has `name`, `version`, `source`, `checksum`, `dependencies`
4. Map each `Package` to `ParsedDependency { name, version, ecosystem: "cargo" }`

New information available from `cargo-lock` that the current parser misses:
- `source` field — distinguishes crates.io packages from git/path dependencies (only crates.io packages should be checked against vuln DB)
- `checksum` — can be used for integrity verification
- `dependencies` — the dependency tree, enabling transitive vulnerability tracking

For now, only populate `name`, `version`, `ecosystem`. Store `source` to filter out non-crates.io dependencies from vuln DB lookups (path and git dependencies are local and not in public CVE databases).

The other four parsers (npm, pip, Go, RubyGems) remain unchanged.

#### Test Migration

Existing Cargo.lock tests use inline lock file content strings. After migration:
- Same test inputs should produce the same `ParsedDependency` outputs
- Add a test with a real-world Cargo.lock containing git and path dependencies to verify source filtering
- Add a test with the latest Cargo.lock format version

---

### 3.6 Unify VulnerabilityClassTarget into Protocol VulnerabilityClass

**Crate:** `crates/fuzzing`
**Files affected:** `scheduler.rs`, `mutator.rs`, `oracle.rs`, their adjacent test files
**Library:** None (uses existing `protocol` crate)

#### Rationale

The fuzzing crate defines `VulnerabilityClassTarget` with 10 variants as a subset of `protocol::VulnerabilityClass` which has 16 variants. There is a naming mismatch: fuzzing uses `Deserialization` while protocol uses `InsecureDeserialization`. This duplication means:
- Adding a new fuzzable vulnerability class to protocol requires a corresponding manual update in fuzzing
- There is no compile-time guarantee that the two enums stay in sync
- Converting between the two types requires a manual match arm that can silently become stale

#### Structural Changes

**scheduler.rs — Delete `VulnerabilityClassTarget` enum entirely.**

Replace all occurrences of `VulnerabilityClassTarget` with `protocol::VulnerabilityClass` throughout the fuzzing crate.

Add a function `is_fuzzable(class: VulnerabilityClass) -> bool` to the scheduler module that returns true for the 10 classes amenable to payload mutation:
- SqlInjection, CrossSiteScripting, CommandInjection, PathTraversal, ServerSideRequestForgery, InsecureDeserialization, ServerSideTemplateInjection, HeaderInjection, OpenRedirect, CrlfInjection

The remaining 6 classes return false:
- BrokenAuthentication, BrokenAuthorization, SecurityMisconfiguration, SensitiveDataExposure, KnownVulnerableDependency, InsufficientInputValidation

`FuzzTarget.vulnerability_class` field type changes from `VulnerabilityClassTarget` to `VulnerabilityClass`. The scheduler's `enqueue` method should reject non-fuzzable classes (return an error or silently skip — decide based on caller contract).

**mutator.rs — Update template keys.**

The template storage `Vec<(VulnerabilityClassTarget, Vec<String>)>` becomes `Vec<(VulnerabilityClass, Vec<String>)>`. The `Deserialization` key becomes `InsecureDeserialization`. All template lookup logic uses `VulnerabilityClass` directly.

The `MutatedPayload.vulnerability_class` field type changes from `VulnerabilityClassTarget` to `VulnerabilityClass`.

**oracle.rs — No changes needed.** The oracle does not reference `VulnerabilityClassTarget`.

**Also address `MutationStrategy::Generative`:** This variant is declared but never constructed. Either remove it (if there are no near-term plans to use it) or document it as the integration point for Phase 2 LLM-generated payloads. Recommendation: keep it and add a doc-comment-equivalent field name that signals its purpose, since Phase 2 section 4.6 will use it.

#### Test Migration

All tests in `scheduler_test.rs` and `mutator_test.rs` that reference `VulnerabilityClassTarget::*` change to `VulnerabilityClass::*`. The `Deserialization` variant becomes `InsecureDeserialization`. No behavioral changes — only type names.

Add a test that verifies `is_fuzzable` returns false for the 6 non-fuzzable classes.

---

### 3.7 Remove Dead Dependencies

**Crates:** `crates/knowledge-graph`, `crates/reporting`
**Files affected:** `Cargo.toml` in each crate
**Library:** None

#### Changes

**knowledge-graph/Cargo.toml:** Remove `petgraph = { workspace = true }`. This crate uses hand-rolled arena storage and algorithms by design (see section 2.4). The petgraph dependency was never imported.

**reporting/Cargo.toml:** Remove `tracing = { workspace = true }`. The reporting crate does not emit any tracing spans or events. If tracing is needed in the future, it should be added with explicit usage.

After removal, run `cargo build --workspace` and `cargo test --workspace` to verify no compilation errors. Run `cargo clippy --workspace -- -D warnings` to verify no new warnings.

#### Verification

Confirm that `petgraph` is still present in the workspace `Cargo.toml` (it is used by `chain-synthesis` after the 3.1 migration). Only the per-crate dependency declaration in `knowledge-graph` is removed.

---

### 3.8 Add Certificate Versioning Envelope

**Crate:** `crates/reporting`
**Files affected:** `certificate_serializer.rs`, its adjacent test file
**Library:** None (uses existing `ciborium` + `serde`)

#### Rationale

The `Certificate` enum currently has 5 variants (Fuzzing, Taint, Chain, Config, Dependency). When a new variant is added (Phase 2 will add an `Evasion` variant), any CBOR blob serialized with the old enum definition will fail to deserialize with the new definition because serde's enum encoding uses variant index or name, and unknown variants produce deserialization errors.

#### Structural Changes

**certificate_serializer.rs — Add a versioned envelope struct:**

Introduce a `CertificateEnvelope` struct with two fields:
- `version: u16` — schema version number, starting at 1
- `payload: Vec<u8>` — the CBOR-serialized `Certificate` enum

The public API changes:
- `serialize_certificate(cert: &Certificate) -> Vec<u8>` now serializes a `CertificateEnvelope` (version=1, payload=CBOR of cert)
- `deserialize_certificate(bytes: &[u8]) -> Result<Certificate, Error>` now:
  1. Deserializes the outer `CertificateEnvelope`
  2. Checks `version` — if version > supported, return a typed error (`UnsupportedVersion`)
  3. Deserializes `payload` into `Certificate`
- `hash_certificate(cert: &Certificate) -> [u8; 32]` remains unchanged — it hashes the serialized bytes regardless of envelope

When Phase 2 adds a new variant to `Certificate`, increment the version to 2. Old blobs (version=1) can still be deserialized because the old variants are a subset of the new enum. Only truly breaking changes (removing or renaming a variant) require version-specific deserialization logic.

#### Test Migration

Existing roundtrip tests must be updated to go through the envelope. Add:
- A test that serializes with version 1 and deserializes successfully
- A test that a version 99 envelope returns `UnsupportedVersion` error
- A test that old-format (non-enveloped) bytes produce a clear error message

---

### 3.9 Add Default Headers to FuzzRequest

**Crate:** `crates/fuzzing`
**Files affected:** `executor.rs`, its adjacent test file
**Library:** None

#### Rationale

`RequestExecutor::build_request` creates `FuzzRequest` with `headers: vec![]`. Every request sent by the fuzzing engine arrives at the target with no `User-Agent`, no `Accept`, no `Accept-Language`, and no other standard headers. Against any defense stack (WAF, bot detection, rate limiter), this is an immediate red flag — no real browser or HTTP client sends zero headers.

#### Structural Changes

**executor.rs — Add a default header set to RequestExecutor:**

Add a field `default_headers: Vec<(String, String)>` to `RequestExecutor`. The constructor (`new`) populates this with a baseline set of browser-like headers:

| Header | Default Value |
|---|---|
| User-Agent | A realistic Chrome user-agent string |
| Accept | `text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` |
| Accept-Language | `en-US,en;q=0.9` |
| Accept-Encoding | `gzip, deflate` |
| Connection | `keep-alive` |

Add a builder method `with_default_headers(headers: Vec<(String, String)>) -> Self` to allow callers (including the Phase 2 evasion engine) to override the defaults.

`build_request` changes: instead of `headers: vec![]`, it initializes `headers` from `self.default_headers.clone()`. Per-request headers can still be appended by the caller after construction.

This is a behavioral change — existing callers that rely on empty headers will now get populated headers. This is intentional and correct. No valid use case requires zero headers.

#### Test Migration

Update the test that asserts `headers` is empty to instead assert `headers` contains the 5 default entries. Add a test for the `with_default_headers` builder that verifies custom headers replace defaults.

---

### 3.10 Validate Full Operation Batch Before Applying

**Crate:** `crates/knowledge-graph`
**Files affected:** `operation_log.rs`, `graph.rs`, their adjacent test files
**Library:** None

#### Rationale

`OperationLog::apply_batch` currently processes operations sequentially. If the third operation in a batch of five fails (e.g., `AddEdge` references a non-existent node), the first two operations have already been applied and cannot be rolled back. The graph is left in a partially-updated state. Phase 2 introduces speculative operations from the evasion feedback loop where batch failures are more likely.

#### Structural Changes

**operation_log.rs — Add a validation pass:**

Split `apply_batch` into two phases:

**Phase 1 (Validate):** Iterate over all operations in the batch without mutating any state. For each operation:
- `AddNode`: always valid (no preconditions)
- `AddEdge`: verify `source_node_id` and `target_node_id` exist in the current node store, OR are being added by a preceding `AddNode` in the same batch (lookahead within the batch)
- `UpdateWeight`: verify `edge_id` exists in the current edge store, OR is being added by a preceding `AddEdge` in the same batch
- `AddFinding`: verify all `linked_node_ids` exist in the current node store, OR are being added by a preceding `AddNode` in the same batch

Sequence number validation also happens in this phase: every entry's `sequence_number` must be >= the current sequence for its module.

If any operation fails validation, return an error containing the operation index and reason. No mutations occur.

**Phase 2 (Apply):** If all operations pass validation, apply them sequentially as before. This phase cannot fail (all preconditions verified).

**graph.rs — Propagate validation errors:**

The `KnowledgeGraph::apply_operations` method acquires the write lock, calls the two-phase `apply_batch`, and releases the lock. If validation fails, the lock is released with no mutations. The error type should include the failing operation index and a descriptive reason.

#### Test Migration

Existing tests that test successful batches should continue to pass unchanged. Add:
- A test with a batch where a middle operation references a non-existent node — verify the entire batch is rejected and the graph state is unchanged
- A test with a batch where `AddEdge` references a node added earlier in the same batch — verify this succeeds (intra-batch dependency resolution)
- A test with an out-of-sequence batch — verify rejection with no mutations

---

## 4. Phase 2 — Adversarial Simulation Layer

Phase 2 builds on the refactored codebase to add realistic defense testing. Eight components are grouped into three categories: infrastructure (4.1), new crates (4.2–4.3), and augmentations to existing components (4.4–4.8).

---

### 4.1 Defense Stack Composer (Docker Infrastructure)

**Location:** `defense-stacks/` (new top-level directory, not a Rust crate)
**Files:** Docker Compose files, configuration files, a README
**Libraries/Images:** `owasp/modsecurity-crs:nginx`, `nginx` (official), `python:3.12-slim` (for custom bot detection)

#### Purpose

Provide pre-built, one-command localhost defense stacks that AEGIS can test against. Each stack simulates a different class of production defense. The target application runs on one localhost port; the defense stack proxies on another. AEGIS points at the defense proxy.

#### Directory Structure

```
defense-stacks/
├── modsecurity/
│   ├── compose.yml
│   └── modsecurity-override.conf
├── rate-limiting/
│   ├── compose.yml
│   └── nginx.conf
├── bot-detection/
│   ├── compose.yml
│   ├── detector/
│   │   ├── pyproject.toml
│   │   └── src/
│   │       └── detector/
│   │           ├── app.py
│   │           └── scoring.py
│   └── nginx.conf
└── combined/
    ├── compose.yml
    └── nginx.conf
```

#### Stack 1: ModSecurity + OWASP Core Rule Set

**compose.yml:** Single service using `owasp/modsecurity-crs:nginx` image. Exposes port 8080. Backend configured to proxy to `host.docker.internal:{target_port}` (the target application running on the host).

**modsecurity-override.conf:** Sets `SecRuleEngine On`, paranoia level 2 (default for testing — level 1 is too permissive, level 3+ generates excessive false positives). Enables request body inspection. Sets `SecResponseBodyAccess On` to allow response-body-based rules.

Configuration is parameterized: paranoia level is set via environment variable in compose.yml so tests can sweep paranoia 1–4.

#### Stack 2: nginx Rate Limiting

**compose.yml:** Single nginx service. Exposes port 8081. Proxies to host target application.

**nginx.conf:** Configures three `limit_req_zone` directives:
- Per-IP burst limiting: 10 requests/second with burst of 20
- Per-URI rate limiting: 5 requests/second per unique URI
- Global connection limiting: `limit_conn` at 50 concurrent connections

Returns 429 (Too Many Requests) when limits are exceeded instead of nginx's default 503. This allows AEGIS to distinguish rate limiting from application errors.

Limits are parameterized via environment variables for sweep testing.

#### Stack 3: Custom Bot Detection Service

**compose.yml:** Two services — the bot detector (Python Flask app on port 5000) and nginx as a reverse proxy (port 8082). Nginx calls the detector as an auth subrequest on every incoming request. If the detector returns 403, nginx rejects the request.

**detector/app.py:** A Flask application that scores each request on four dimensions:

| Dimension | What It Checks | Score Range |
|---|---|---|
| Header analysis | Presence and ordering of standard browser headers (User-Agent, Accept, Accept-Language, Accept-Encoding, Sec-Fetch-*) | 0.0–0.3 |
| TLS metadata | Connection protocol version, cipher suite name (passed by nginx via proxy headers) | 0.0–0.2 |
| Timing analysis | Inter-request interval distribution for the session — human-like exponential vs bot-like constant | 0.0–0.3 |
| Session consistency | Cookie persistence, referrer chain plausibility, consistent viewport hints across requests | 0.0–0.2 |

Total score 0.0–1.0. Threshold at 0.5 (configurable via environment variable). Below threshold → 403 Forbidden. Above → pass through to target.

**detector/scoring.py:** Scoring logic, separated from Flask routing for testability.

The bot detector is intentionally simplistic — it tests whether AEGIS's evasion engine can fool a basic behavioral model, not a production-grade system like DataDome or PerimeterX.

#### Stack 4: Combined

**compose.yml:** Chains all three: nginx rate limiter → bot detection subrequest → ModSecurity WAF → target application. Port 8083. This is the "hard mode" stack for integration testing.

#### Usage Pattern

Each stack is started independently of AEGIS:
1. User starts their target application on a localhost port (e.g., 3000)
2. User runs `docker compose -f defense-stacks/modsecurity/compose.yml up -d` with `TARGET_PORT=3000`
3. User points AEGIS at the defense proxy port (e.g., 8080)
4. AEGIS scans through the defense stack, encountering blocks/rate-limits
5. Defense fingerprinting module (4.3) identifies what's in the way
6. Evasion engine (4.2) adapts requests to get through

#### Testing

Each stack has a smoke test script (`test.sh`) that:
- Starts the stack against a minimal echo server
- Sends a known-malicious request and verifies it's blocked
- Sends a benign request and verifies it passes through
- Tears down the stack

---

### 4.2 Evasion Engine (New Rust Crate)

**Location:** `crates/evasion-engine/`
**Workspace member:** Add `"crates/evasion-engine"` to workspace `Cargo.toml` members list
**Dependencies:** `rquest` (TLS/HTTP2 fingerprint impersonation), `rand` (jitter), `serde` (config serialization), `protocol` (shared types), `tokio` (async timing)

#### Purpose

Transform outgoing HTTP requests to evade defense detection. Sits between the fuzzing executor (which builds requests) and the actual HTTP transport. The evasion engine applies a "persona" — a coherent set of browser-like characteristics — to each request before sending.

#### Crate Structure

```
crates/evasion-engine/src/
├── lib.rs                  (re-exports only)
├── persona.rs              (Persona struct, PersonaId enum, persona catalog)
├── header_transformer.rs   (header injection/reordering)
├── timing_controller.rs    (inter-request jitter)
├── session_manager.rs      (cookie/referer state)
├── encoding_transformer.rs (payload encoding variations)
└── transport.rs            (rquest-based HTTP client with persona application)
```

Each file has an adjacent test file per convention.

#### Key Types

**persona.rs — Browser persona definitions:**

`PersonaId` enum with variants: ChromeDesktop, FirefoxDesktop, SafariDesktop, ChromeMobile, Googlebot. Each variant maps to a `Persona` struct.

`Persona` struct fields:
- `id: PersonaId`
- `user_agent: String`
- `accept_header: String`
- `accept_language: String`
- `accept_encoding: String`
- `sec_fetch_headers: Vec<(String, String)>` — Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest
- `tls_profile: TlsProfile` — maps to `rquest`'s impersonation target
- `header_order: Vec<String>` — the order in which headers appear (browsers have characteristic orderings)
- `min_request_interval_ms: u64` — minimum time between requests for this persona
- `max_request_interval_ms: u64` — maximum time between requests
- `jitter_distribution: JitterDistribution` — enum: Uniform, Exponential, Normal

The persona catalog is a function that returns a `Vec<Persona>` with the five pre-built personas. A builder method `Persona::custom()` allows user-defined personas.

**header_transformer.rs — Request header manipulation:**

`HeaderTransformer` struct. Takes a `FuzzRequest` (from the fuzzing crate) and a `Persona`, returns a modified `FuzzRequest` with:
- Headers populated from the persona (User-Agent, Accept, etc.)
- Headers ordered according to the persona's `header_order`
- Any existing headers on the FuzzRequest preserved (appended after persona headers)
- `Sec-Fetch-*` headers added if the persona includes them
- A synthetic `Referer` header if the session manager provides one

**timing_controller.rs — Inter-request delay:**

`TimingController` struct with fields:
- `persona: PersonaId` (determines timing parameters)
- `last_request_time: Option<Instant>`
- `rng: rand::rngs::StdRng` (seeded for reproducibility in tests)

Public method: `async fn wait_before_next_request(&mut self)` — calculates the delay based on the persona's min/max interval and jitter distribution, then sleeps for that duration. First request has no delay.

The jitter distribution options:
- Uniform: random value between min and max
- Exponential: `min + exponential_sample(lambda)` clamped to max, where lambda = 1.0 / (max - min). This produces mostly short intervals with occasional long pauses — mimics human browsing patterns.
- Normal: `mean = (min+max)/2`, `stddev = (max-min)/4`, clamped to [min, max]

**session_manager.rs — Stateful session tracking:**

`SessionManager` struct with fields:
- `cookies: HashMap<String, String>` — cookies received from Set-Cookie headers
- `request_history: Vec<String>` — URLs of previous requests (for Referer generation)
- `session_id: u64` — monotonically increasing, for session rotation
- `requests_in_session: u32` — counter, for rotation threshold
- `max_requests_per_session: u32` — configurable, default 50

Public methods:
- `apply_session_state(request: &mut FuzzRequest)` — adds Cookie header from stored cookies, sets Referer to last URL in history, records the request URL
- `process_response(response: &FuzzResponse)` — extracts Set-Cookie headers, updates cookie store
- `rotate_session()` — clears cookies and history, increments session_id. Called automatically when `requests_in_session >= max_requests_per_session`.

**encoding_transformer.rs — Payload encoding variations:**

`EncodingTransformer` struct. Takes a payload string and a `VulnerabilityClass`, returns a set of encoded variations.

Encoding strategies per vulnerability class:

| Strategy | Applicable Classes | Transformation |
|---|---|---|
| Double URL encoding | All injection classes | `<` → `%253C` |
| Unicode normalization | XSS, SSTI | `<` → `\u003c` |
| Mixed case | SQLi, XSS | `SELECT` → `SeLeCt` |
| Comment insertion | SQLi | `UNION SELECT` → `UNION/**/SELECT` |
| Whitespace variation | SQLi, command injection | tabs, newlines, multiple spaces replacing single space |
| Null byte insertion | Path traversal | `../etc/passwd` → `../etc/passwd%00.jpg` |
| HTML entity encoding | XSS | `<` → `&lt;` or `&#60;` or `&#x3c;` |
| Concatenation splitting | SQLi | `'admin'` → `'adm'+'in'` (MSSQL) or `'adm' || 'in'` (PostgreSQL) |

The transformer returns a `Vec<EncodedPayload>` struct with fields `encoded: String`, `strategy: EncodingStrategy` enum, and `original: String`.

**transport.rs — rquest-based HTTP client:**

`EvasionTransport` struct. This is the actual HTTP client that sends requests over the network. Fields:
- `client: rquest::Client` — configured with the persona's TLS profile via `rquest`'s impersonation API
- `persona: Persona`
- `timing: TimingController`
- `session: SessionManager`
- `header_transformer: HeaderTransformer`

Public method: `async fn send(request: FuzzRequest) -> Result<FuzzResponse, TransportError>`

The send flow:
1. `timing.wait_before_next_request()` — inter-request delay
2. `header_transformer.transform(request, persona)` — apply persona headers
3. `session.apply_session_state(request)` — add cookies and referer
4. Build `rquest::Request` from the transformed `FuzzRequest`
5. Send via `client.execute(request)`
6. Map response to `FuzzResponse`
7. `session.process_response(response)` — extract cookies
8. Return response

`rquest` integration: The `rquest` crate provides `rquest::Client::builder().impersonate(Impersonate::Chrome131)` (or Firefox, Safari, etc.). Each `PersonaId` maps to a `rquest::Impersonate` variant. This handles TLS ClientHello fingerprinting (JA3/JA4), HTTP/2 SETTINGS frame ordering, and HPACK compression behavior — all automatically matching the target browser.

#### Integration with Existing Crates

The evasion engine does not modify the fuzzing crate. Instead, the orchestrator (section 4.8) wires them together:
- Fuzzing executor builds `FuzzRequest` (with default headers from refactor 3.9)
- Evasion engine's `EvasionTransport` receives the `FuzzRequest`, transforms it, sends it, returns `FuzzResponse`
- Fuzzing oracle analyzes the `FuzzResponse` as before

This preserves the fuzzing crate's testability (it remains transport-agnostic) while adding evasion capability at the integration layer.

---

### 4.3 Defense Fingerprinting Module (New Rust Crate)

**Location:** `crates/defense-fingerprinting/`
**Workspace member:** Add to workspace `Cargo.toml`
**Dependencies:** `protocol` (shared types), `reqwest` (plain HTTP for probing — no evasion needed for fingerprinting), `serde`, `serde_json`, `regex`

#### Purpose

Identify what defenses are present between AEGIS and the target application. Outputs a `DefenseProfile` that other components use to select evasion strategies. Runs once at the start of a scan, before fuzzing begins.

#### Crate Structure

```
crates/defense-fingerprinting/src/
├── lib.rs                  (re-exports only)
├── defense_profile.rs      (DefenseProfile struct, DefenseType enum)
├── waf_fingerprinter.rs    (WAF identification via probe responses)
├── rate_limit_detector.rs  (rate limit measurement)
└── bot_detection_probe.rs  (bot detection identification)
```

#### Key Types

**defense_profile.rs:**

`DefenseType` enum: Waf, RateLimiter, BotDetection, TlsTermination, None.

`WafVendor` enum: ModSecurity, Cloudflare, AwsWaf, Imperva, Akamai, Unknown.

`RateLimitProfile` struct:
- `requests_per_second: Option<f64>` — measured limit
- `burst_allowance: Option<u32>` — measured burst before limiting kicks in
- `limit_response_code: u16` — the HTTP status code returned when limited (429, 503, etc.)
- `limit_window_seconds: Option<u32>` — estimated window size

`WafProfile` struct:
- `vendor: WafVendor`
- `paranoia_level: Option<u8>` — estimated for ModSecurity (1–4)
- `blocked_response_code: u16` — typically 403
- `blocked_categories: Vec<VulnerabilityClass>` — which attack categories are blocked based on probing

`BotDetectionProfile` struct:
- `detected: bool`
- `detection_method: String` — "javascript_challenge", "captcha", "header_analysis", "behavioral"
- `challenge_response_code: Option<u16>`

`DefenseProfile` struct (the top-level output):
- `waf: Option<WafProfile>`
- `rate_limit: Option<RateLimitProfile>`
- `bot_detection: Option<BotDetectionProfile>`
- `fingerprint_timestamp_ms: u64`

#### Protocol Integration

Add to `crates/protocol/src/node.rs`: a new `NodeType::Defense` variant. Defense profiles are stored as nodes in the knowledge graph with properties encoding the profile fields as key-value strings. This allows the knowledge graph to represent "target is behind ModSecurity with paranoia level 2" as a queryable node connected to endpoint nodes via a new `EdgeLabel::ProtectedBy` variant in `crates/protocol/src/edge.rs`.

These are the only protocol changes for Phase 2.

**waf_fingerprinter.rs — WAF identification:**

Fingerprinting algorithm:
1. Send a benign request to the target to establish baseline response (status, headers, body pattern)
2. Send a set of known-malicious probe payloads — one per vulnerability class — to the target's root or a known-valid endpoint. Payloads should be from the mutator's existing template list.
3. For each probe:
   - If response status matches baseline → WAF did not block → this category is not filtered
   - If response status is 403/406/419/451 → WAF blocked → this category is filtered
   - Inspect response headers for WAF signatures:
     - `Server: cloudflare` or `cf-ray` header → Cloudflare
     - `X-Powered-By: ModSecurity` or response body contains `Mod_Security` → ModSecurity
     - `X-Amzn-Waf-*` headers → AWS WAF
     - Response body contains "Powered by Imperva" or "incapsula` → Imperva
   - Inspect response body for block page patterns (vendor-specific HTML snippets)
4. Aggregate results into `WafProfile`

ModSecurity paranoia level estimation: send payloads of increasing subtlety. Level 1 blocks only obvious attacks. Level 2 blocks encoded variants. Level 3 blocks anomaly-scored requests. Level 4 blocks nearly everything unusual. The highest subtlety level that gets blocked indicates the paranoia level.

**rate_limit_detector.rs — Rate limit measurement:**

Detection algorithm:
1. Send requests at increasing rates: 1/sec, 5/sec, 10/sec, 20/sec, 50/sec, 100/sec
2. At each rate, send 10 requests and count how many return the baseline status vs. a rate-limit status (429, 503, or Retry-After header)
3. The rate at which >50% of requests are limited is the estimated limit
4. Measure burst: send N requests as fast as possible (no delay). The count before the first rate-limit response is the burst allowance.
5. Estimate window: after hitting the limit, wait increasing intervals (1s, 2s, 5s, 10s) and retry. The shortest wait after which requests succeed again indicates the window.

**bot_detection_probe.rs — Bot detection identification:**

Detection algorithm:
1. Send a request with no headers at all → if 403 with JavaScript challenge or CAPTCHA HTML in body → bot detection present
2. Send a request with realistic browser headers → if now succeeds → detection is header-based
3. If still challenged → inspect response body for known patterns:
   - `<script>` tags with challenge logic → JavaScript challenge
   - reCAPTCHA/hCaptcha/Turnstile HTML → CAPTCHA-based
4. Send rapid requests with perfect headers → if suddenly challenged after N requests → behavioral analysis (timing-based)

#### Knowledge Graph Integration

After fingerprinting completes, the module emits `GraphOperation::AddNode` with `NodeType::Defense` and properties encoding the `DefenseProfile` fields. It also emits `GraphOperation::AddEdge` with `EdgeLabel::ProtectedBy` from each endpoint node to the defense node. This allows chain-synthesis to incorporate defense layers into attack path analysis — a path that goes through a WAF node has higher exploitation difficulty.

---

### 4.4 Stealth Fuzzing Mode (Augment Fuzzing Crate)

**Crate:** `crates/fuzzing`
**Files affected:** `scheduler.rs`, `executor.rs`, new file `stealth_config.rs`, adjacent test files
**Library:** None (uses existing `rand` workspace dependency)

#### Purpose

Add an alternative fuzzing mode that prioritizes avoiding detection over scan speed. When a defense fingerprint indicates rate limiting or behavioral bot detection, the orchestrator switches to stealth mode. Stealth mode changes request timing, payload selection priority, and session rotation frequency.

#### New File: stealth_config.rs

`StealthConfig` struct (builder pattern):
- `max_requests_per_second: f64` — default 1.5 (vs normal mode's configurable 100+)
- `jitter_distribution: JitterDistribution` — reuse the enum from the evasion engine; default Exponential
- `min_delay_ms: u64` — default 400
- `max_delay_ms: u64` — default 3000
- `session_rotation_interval: u32` — rotate session every N requests; default 25
- `prefer_blind_payloads: bool` — default true; prioritizes time-based blind injection over error-based
- `avoid_signature_payloads: bool` — default true; deprioritizes well-known signature-triggering payloads

Builder methods: `with_max_rps`, `with_jitter`, `with_session_rotation`, etc.

`StealthConfig::default()` returns conservative values suitable for evading most behavioral detection.
`StealthConfig::aggressive()` returns values that are faster but more detectable (3 rps, shorter delays).
`StealthConfig::paranoid()` returns the slowest, most cautious settings (0.5 rps, long delays, rotate every 10 requests).

#### Changes to scheduler.rs

Add a method `reprioritize_for_stealth(config: &StealthConfig)` on `FuzzScheduler`.

When `prefer_blind_payloads` is true, this method iterates over the queue and multiplies the priority score of targets whose vulnerability class favors blind/time-based payloads (SqlInjection, CommandInjection) by 1.5, while reducing the priority of classes that require obvious payload reflection (CrossSiteScripting, OpenRedirect) by 0.7.

When `avoid_signature_payloads` is true, this is a signal to the mutator (not the scheduler) — the scheduler stores the flag and exposes it via `scheduler.should_avoid_signatures() -> bool`.

#### Changes to executor.rs

Add `with_stealth_config(config: StealthConfig) -> Self` builder method on `RequestExecutor`.

When a stealth config is set:
- The `RateLimiter` max_requests_per_second is overridden to `config.max_requests_per_second`
- A new method `stealth_delay_ms(&self) -> u64` returns a jittered delay value based on the config's distribution and min/max range. The caller (orchestrator) is responsible for sleeping this duration between requests.

The executor itself remains synchronous and non-blocking — it returns the delay value; the async orchestrator performs the actual sleep. This preserves testability.

#### Changes to mutator.rs (Payload Prioritization)

Add a method `generate_stealth_payloads(class: VulnerabilityClass, count: usize) -> Vec<MutatedPayload>` on `PayloadMutator`.

This method differs from `generate_payloads` in template selection order. For each vulnerability class, templates are internally tagged with a stealth rating:
- **High stealth**: time-based blind SQLi (`SLEEP(5)`), blind command injection (`ping -c 5 127.0.0.1`), blind SSRF (DNS-based out-of-band)
- **Medium stealth**: encoded payloads, case-varied payloads
- **Low stealth**: obvious signature payloads (`' OR '1'='1`, `<script>alert(1)</script>`)

`generate_stealth_payloads` returns high-stealth templates first, then medium, then low. If `count` exceeds available templates, overflow is filled with encoding-varied mutations of high-stealth templates rather than bitflip mutations.

The stealth rating is an internal property of each template, stored as an additional field in the template tuple. The rating is assigned at compile time in `build_default_templates`.

---

### 4.5 Evasion Feedback Loop (Augment Hypothesis Engine)

**Package:** `hypothesis-engine/`
**Files affected:** `generator.py`, `compiler.py`, `feedback.py`, new file `evasion_mode.py`, test files
**Library:** None new (uses existing `boto3`, `pydantic`)

#### Purpose

When fuzzing requests are blocked by defenses (403, 429, CAPTCHA), feed the blocked request details and defense profile into the LLM to generate alternative payloads that might evade the defense. This creates a closed loop: fuzz → block → hypothesize evasion → retry → learn.

#### New File: evasion_mode.py

**EvasionContext** Pydantic model (extends the existing context pattern):
- `blocked_request_method: str`
- `blocked_request_endpoint: str`
- `blocked_request_payload: str`
- `blocked_request_headers: list[dict[str, str]]`
- `block_response_status: int`
- `block_response_headers: list[dict[str, str]]`
- `block_response_body_snippet: str` — first 500 characters of the block response body
- `defense_profile: dict[str, Any]` — serialized DefenseProfile from the fingerprinting module
- `vulnerability_class: str`
- `previously_attempted_evasions: list[str]` — payloads already tried and blocked, to avoid repetition

**Evasion system prompt** (module-level constant):

The system prompt instructs the LLM to act as a WAF bypass researcher. It specifies:
- The target vulnerability class
- The defense type and vendor (if known)
- The blocked payload
- What evasion strategies have already been tried

It asks for 5–10 alternative payloads that test the same vulnerability but use different encoding, syntax, or structure to evade signature-based detection. Each alternative must be a valid payload for the vulnerability class (not random garbage).

Output format: JSON array of objects with fields `payload`, `strategy` (human-readable description of the evasion technique), and `confidence` (0.0–1.0 estimate of bypass likelihood).

**EvasionHypothesisGenerator** class:
- Constructor: same parameters as `HypothesisGenerator` (model_id, aws_profile, max_retries, timeout_seconds)
- Shares the `_get_client()` and `_invoke_with_retry()` methods — extract these to a base class or mixin `BedrockClient` to avoid duplication
- Public method: `generate_evasions(context: EvasionContext, max_evasions: int = 10) -> EvasionResult`
- `EvasionResult` model: `evasions: list[EvasionPayload]`, `model_id: str`, `generation_time_ms: float`
- `EvasionPayload` model: `payload: str`, `strategy: str`, `confidence: float`

**Curated in-context examples:**

Since Claude cannot be fine-tuned on Bedrock, the evasion system prompt includes curated examples of successful WAF bypasses organized by defense vendor and vulnerability class. These examples are stored as a JSON file (`hypothesis-engine/src/hypothesis_engine/bypass_examples.json`) loaded at import time.

The JSON structure groups examples by `(waf_vendor, vulnerability_class)`:

```
{
  "ModSecurity": {
    "SqlInjection": [
      {"blocked": "' OR 1=1 --", "bypass": "' /*!OR*/ 1=1 --", "technique": "MySQL inline comment"},
      ...
    ],
    "CrossSiteScripting": [...]
  },
  "AwsWaf": {...}
}
```

The system prompt selects the relevant examples based on the `EvasionContext.defense_profile.waf.vendor` and `vulnerability_class` fields. Only examples matching the current scenario are included in the prompt — not the entire corpus.

Initial corpus size target: 10–20 examples per (vendor, class) pair for the most common combinations (ModSecurity + top 5 injection classes = ~75 examples total). This is a starting point; the corpus grows as AEGIS discovers new bypasses.

#### Changes to feedback.py

Add a new `HypothesisOutcome` value: consider extending the labeling to track evasion-specific outcomes. Actually, the existing `CONFIRMED` / `REFUTED` / `INCONCLUSIVE` labels are sufficient:
- Evasion payload gets through and triggers anomaly → `CONFIRMED`
- Evasion payload gets through but no anomaly → `REFUTED` (the payload works as evasion but the underlying vulnerability isn't there)
- Evasion payload is still blocked → `INCONCLUSIVE` (evasion failed, not a statement about the vulnerability)

Add a field to `LabeledHypothesis`: `evasion_attempt: bool` — flag to distinguish evasion-loop hypotheses from standard hypotheses in training data export.

#### Changes to generator.py

Extract the Bedrock client setup (`_get_client`, `_invoke_with_retry`) into a shared base class `BedrockClient` in a new file `bedrock_client.py`. Both `HypothesisGenerator` and `EvasionHypothesisGenerator` inherit from it. `HypothesisCompiler` also inherits from it (it currently duplicates the same client code).

This refactor eliminates the three copies of identical Bedrock integration code currently spread across generator.py, compiler.py, and the new evasion_mode.py.

#### Integration Flow

The orchestrator (section 4.8) implements the feedback loop:

1. Fuzzing sends a request via the evasion engine
2. If the response indicates a block (403, 429, response body matches defense block patterns):
   a. Construct `EvasionContext` from the blocked request, response, and defense profile
   b. Call `EvasionHypothesisGenerator.generate_evasions(context)`
   c. For each returned evasion payload, construct a new `FuzzRequest` with the evasion payload
   d. Send each evasion request via the evasion engine
   e. Label the results via `FeedbackManager`
   f. If any evasion succeeds (gets through the defense AND triggers an anomaly):
      - Record the successful evasion technique in the knowledge graph as a finding property
      - Add the successful payload to the mutator's template list for this vulnerability class (via the `with_custom_templates` builder from refactor 3.8's mutator extensibility)
      - Use this evasion technique on similar endpoints without needing another LLM call
3. If all evasions are blocked, record the endpoint as "defended against [vulnerability_class]" in the knowledge graph and move on

Maximum evasion retries per endpoint per vulnerability class: 3 rounds of LLM generation. This prevents infinite loops on well-defended endpoints.

---

### 4.6 WAF Bypass Payload Integration (Augment Fuzzing + Hypothesis Engine)

**Crates:** `crates/fuzzing`, `hypothesis-engine/`
**Files affected:** `mutator.rs`, `evasion_mode.py`, new file `bypass_corpus.json`
**Libraries:** None new

#### Purpose

Expand the fuzzing mutator's payload database with community-sourced WAF bypass payloads from SecLists and similar sources, organized by WAF vendor and vulnerability class. This complements the LLM-generated evasions (section 4.5) with known, proven bypasses.

#### Bypass Corpus File

**Location:** `crates/fuzzing/data/bypass_corpus.json`

Structure: a JSON object keyed by vulnerability class name (matching `VulnerabilityClass` enum variant names), where each value is an array of payload objects:

Each payload object:
- `raw: string` — the payload text
- `waf_targets: [string]` — WAF vendors this bypass is known to work against (`["ModSecurity", "AwsWaf"]`), or `["generic"]` for vendor-agnostic
- `technique: string` — short description of the bypass technique
- `stealth_rating: string` — "high", "medium", or "low"

Source material for populating this corpus:
- SecLists `Fuzzing/` directory — SQLi, XSS, command injection payloads
- PayloadsAllTheThings repository — organized by vulnerability class with WAF bypass sections
- OWASP WAF bypass cheat sheets
- PortSwigger Web Security Academy examples

Target: 50–100 payloads per vulnerability class for the top 5 fuzzable classes (SqlInjection, CrossSiteScripting, CommandInjection, PathTraversal, ServerSideRequestForgery). 20–30 for the remaining 5 classes. Total: ~400 curated payloads.

Attribution: the corpus file should include a top-level `"sources"` array documenting where payloads were sourced from, for license compliance.

#### Changes to mutator.rs

Add a `load_bypass_corpus(path: &Path) -> Result<Vec<(VulnerabilityClass, Vec<BypassPayload>)>, Error>` function.

`BypassPayload` struct:
- `raw: String`
- `waf_targets: Vec<String>`
- `technique: String`
- `stealth_rating: StealthRating` (enum: High, Medium, Low)

Add `with_bypass_corpus(corpus: Vec<(VulnerabilityClass, Vec<BypassPayload>)>) -> Self` builder method on `PayloadMutator`.

When a bypass corpus is loaded, `generate_payloads` merges corpus payloads with built-in templates. Order: built-in templates first, then corpus payloads, then bitflip mutations.

When stealth mode is active (`generate_stealth_payloads`), corpus payloads are sorted by stealth_rating (high first) and interleaved with built-in templates by rating.

When a `DefenseProfile` is known (passed via a new optional parameter on generate methods), filter corpus payloads to those where `waf_targets` contains the detected vendor or `"generic"`. This avoids wasting requests on bypasses known to not work against the detected WAF.

#### Relationship to Evasion Feedback Loop

The bypass corpus provides a static, curated baseline. The evasion feedback loop (section 4.5) provides dynamic, LLM-generated alternatives when the corpus payloads are blocked. The two complement each other:

1. First attempt: use corpus payloads matching the detected WAF + vulnerability class
2. If blocked: invoke LLM evasion generator with the blocked payload as context
3. If LLM evasion succeeds: optionally append the successful payload to the corpus file for future scans (manual review recommended before persisting)

---

### 4.7 Reporting Enhancements (Augment Reporting Crate)

**Crate:** `crates/reporting`
**Files affected:** `risk_scorer.rs`, `sarif_emitter.rs`, `certificate_serializer.rs`, adjacent test files
**Library:** None new (uses `sarif_rust` from refactor 3.2)

#### Purpose

Extend the reporting pipeline to include defense context in vulnerability findings. A finding should communicate not just "this endpoint has SQLi" but "this endpoint has SQLi that is exploitable despite ModSecurity CRS at paranoia level 2 using comment-insertion evasion."

#### Changes to risk_scorer.rs

**Add defense-aware scoring adjustments:**

The current composite formula is `(exploitability × reachability × blast_radius × confidence) / 1000 × 100`.

Exploitability already has adjustment factors for authentication (×0.7), rate limiting (×0.8), and WAF (×0.6). These were static assumptions. With defense fingerprinting data available, make them dynamic:

- If `DefenseProfile.waf` is `Some` AND the vulnerability was confirmed despite the WAF: do not apply the WAF discount (×1.0 instead of ×0.6). The finding is proven exploitable through the WAF.
- If `DefenseProfile.waf` is `Some` AND the vulnerability was NOT confirmed through the WAF (found via direct scanning without defenses): apply WAF discount based on the WAF's `blocked_categories`. If the vulnerability class is in `blocked_categories`, apply ×0.3 (likely blocked in production). If not, apply ×0.8 (WAF might not catch it).
- If `DefenseProfile.rate_limit` is `Some`: apply rate-limit discount proportional to how restrictive the limit is. Limits below 10 rps → ×0.6 (hard to exploit at scale). Limits above 100 rps → ×0.95 (minimal impediment).
- If `DefenseProfile.bot_detection` is `Some` AND detection was evaded: ×1.0. If not evaded: ×0.5.

Add a new method: `score_with_defense(finding: &FindingData, defense: &DefenseProfile, evasion_succeeded: bool) -> ScoredFinding`.

The existing `score` method (without defense context) remains unchanged for backward compatibility.

**New output type: `ScoredFinding` struct:**
- `finding_id: u64`
- `composite_score: f64` (0–100)
- `exploitability: f64`
- `reachability: f64`
- `blast_radius: f64`
- `confidence: f64`
- `defense_context: Option<DefenseScoreContext>`

`DefenseScoreContext` struct:
- `waf_present: bool`
- `waf_bypassed: bool`
- `bypass_technique: Option<String>`
- `rate_limit_present: bool`
- `bot_detection_present: bool`
- `bot_detection_evaded: bool`

#### Changes to sarif_emitter.rs

With `sarif_rust` (from refactor 3.2), add defense context to SARIF output:

**Per-result properties:** Each SARIF result's `properties` bag should include:
- `defenseProfile` — serialized defense profile summary
- `evasionTechnique` — if the finding was confirmed via evasion, the technique used
- `exploitableDespiteWaf` — boolean flag
- `wafVendor` — if known

**Per-run properties:** The SARIF run-level `properties` bag should include:
- `defensesDetected` — summary of all defenses found
- `evasionSuccessRate` — percentage of blocked requests that were successfully evaded
- `stealthModeUsed` — boolean

These properties are non-standard (they go in the `properties` bag, which SARIF allows for extensions) and do not break SARIF consumers.

#### Changes to certificate_serializer.rs

Add a new `Certificate` variant: `EvasionCertificate`.

`EvasionCertificate` fields:
- `original_payload: String` — the payload that was blocked
- `evasion_payload: String` — the payload that bypassed the defense
- `defense_vendor: String` — WAF/rate-limiter/bot-detection vendor
- `evasion_technique: String` — human-readable description
- `block_response_status: u16` — HTTP status of the block
- `bypass_response_status: u16` — HTTP status of the successful bypass
- `anomaly_detected: bool` — whether the bypass also triggered a vulnerability

This certificate type provides cryptographic proof that a specific evasion technique worked against a specific defense.

The certificate envelope version (from refactor 3.8) increments to 2 when this variant is added.

---

### 4.8 Orchestrator CLI (New Rust Crate)

**Location:** `crates/orchestrator/`
**Workspace member:** Add to workspace `Cargo.toml`
**Dependencies:** `protocol`, `knowledge-graph`, `audit-log`, `supervisor`, `passive-recon`, `enumeration`, `fuzzing`, `chain-synthesis`, `reporting`, `evasion-engine`, `defense-fingerprinting`, `tokio`, `clap` (CLI argument parsing), `tracing`, `tracing-subscriber`

#### Purpose

Wire all crates into an end-to-end scan pipeline. This is the `main.rs` binary — the entry point that users invoke. Currently no orchestrator exists; each crate is independently testable but there is no integration harness.

#### Crate Structure

```
crates/orchestrator/src/
├── main.rs                 (CLI entry point, argument parsing)
├── lib.rs                  (re-exports only)
├── scan_config.rs          (ScanConfig struct, loaded from CLI args or config file)
├── pipeline.rs             (scan pipeline: phases and phase transitions)
├── phase_recon.rs          (orchestrates passive-recon + enumeration)
├── phase_fingerprint.rs    (orchestrates defense fingerprinting)
├── phase_fuzz.rs           (orchestrates fuzzing + evasion + feedback loop)
├── phase_analyze.rs        (orchestrates chain-synthesis)
└── phase_report.rs         (orchestrates reporting + SARIF output)
```

#### CLI Interface

The orchestrator accepts arguments via `clap`:

| Argument | Type | Required | Description |
|---|---|---|---|
| `--target` | URL | Yes | Base URL of the target application (must be localhost) |
| `--output` | Path | No | SARIF output file path (default: `aegis-report.sarif`) |
| `--persona` | String | No | Evasion persona (chrome, firefox, safari, mobile, googlebot; default: chrome) |
| `--stealth` | Flag | No | Enable stealth fuzzing mode |
| `--stealth-level` | String | No | Stealth preset: default, aggressive, paranoid |
| `--bypass-corpus` | Path | No | Path to WAF bypass corpus JSON |
| `--max-rps` | u32 | No | Maximum requests per second (overrides persona/stealth defaults) |
| `--paranoia-sweep` | Flag | No | Test against ModSecurity paranoia levels 1–4 |
| `--skip-fingerprint` | Flag | No | Skip defense fingerprinting phase |
| `--skip-evasion` | Flag | No | Disable evasion engine (send raw requests) |
| `--verbose` | Flag | No | Enable tracing output |

**Localhost validation:** Before starting any scan, the orchestrator resolves the `--target` URL and verifies the host is `127.0.0.1`, `::1`, or `localhost`. Any other host is rejected with an error. This is the soft confinement check (not kernel-level, but prevents accidental remote scanning).

#### Scan Pipeline

The pipeline executes five phases in order:

**Phase 1: Reconnaissance**
1. Initialize `KnowledgeGraph` (in-memory)
2. Initialize `AuditLogWriter` (file-backed, path derived from target URL hash)
3. Run `passive-recon` filesystem walker on the target's source directory (if `--source-dir` provided)
4. Run `passive-recon` dependency parser on discovered lock files
5. Run `passive-recon` vuln database lookups on parsed dependencies
6. Run `enumeration` route parser on discovered source files
7. Run `enumeration` introspection (OpenAPI/GraphQL) against the target URL
8. Run `enumeration` auth matrix builder from discovered routes + credentials (if provided)
9. Feed all results into the knowledge graph via `OperationLogEntry` batches
10. Log phase completion to audit log

**Phase 2: Defense Fingerprinting** (skippable via `--skip-fingerprint`)
1. Initialize `defense-fingerprinting` module
2. Run WAF fingerprinting against target
3. Run rate limit detection
4. Run bot detection probing
5. Construct `DefenseProfile`
6. Add defense node + ProtectedBy edges to knowledge graph
7. If defenses detected, select evasion strategy:
   - If WAF detected → load bypass corpus, configure encoding transformer
   - If rate limiting detected → enable stealth mode (or lower rps)
   - If bot detection detected → enable full persona (headers + timing + session)
8. Log fingerprint results to audit log

**Phase 3: Fuzzing** (the core scanning loop)
1. Build `FuzzScheduler` from knowledge graph endpoints
2. Initialize `PayloadMutator` (with bypass corpus if loaded)
3. Initialize `RequestExecutor` (with stealth config if enabled)
4. Initialize `EvasionTransport` (if evasion not skipped) or plain `reqwest::Client`
5. Establish baseline profiles via `FuzzOracle` (send benign requests, record normal behavior)
6. Main loop:
   a. `scheduler.next_target()` → get next `FuzzTarget`
   b. Generate payloads via mutator (standard or stealth mode)
   c. For each payload:
      - Build `FuzzRequest` via executor
      - Send via evasion transport (or plain client)
      - Analyze response via oracle
      - If anomaly detected → create `FindingData`, add to knowledge graph
      - If blocked (403/429) AND evasion enabled → enter evasion feedback loop (section 4.5)
   d. `scheduler.mark_completed(target)`
7. Log fuzzing completion stats to audit log

**Phase 4: Analysis**
1. Build `AttackGraph` from knowledge graph (now using petgraph, per refactor 3.1)
2. Run `reachable_assets` analysis
3. Run `shortest_attack_path` for each entry-point → asset pair
4. Run `betweenness_centrality`
5. Run `critical_fix_targets`
6. Record chain findings in knowledge graph

**Phase 5: Reporting**
1. Score all findings via `risk_scorer` (with defense context if available)
2. Rank findings by composite score
3. Emit SARIF via `sarif_emitter` (with CWE taxa, defense properties)
4. Serialize certificates for each finding
5. Write SARIF to output file
6. Log scan completion to audit log
7. Print summary to stdout: total findings, top 5 by severity, evasion stats

#### Hypothesis Engine Integration

The orchestrator calls the Python hypothesis engine via subprocess. The integration mechanism:

1. Before Phase 3 (fuzzing), construct a `ScanContext` JSON from knowledge graph state
2. Write `ScanContext` to a temporary JSON file
3. Invoke the hypothesis engine Python script via `tokio::process::Command`:
   - `uv run python -m hypothesis_engine.generate --context /tmp/scan_context.json --output /tmp/hypotheses.json`
4. Read the output hypotheses JSON
5. For each hypothesis, compile to `TestSpecification` via a second subprocess call:
   - `uv run python -m hypothesis_engine.compile --hypotheses /tmp/hypotheses.json --output /tmp/test_specs.json`
6. Merge test specifications into the fuzzing scheduler as additional `FuzzTarget` entries
7. After fuzzing, write feedback data:
   - `uv run python -m hypothesis_engine.feedback --results /tmp/fuzz_results.json --output /tmp/training.json`

The subprocess approach avoids embedding a Python runtime in the Rust binary. Temporary files are used for IPC because the data volumes are small (kilobytes). If latency becomes an issue in the evasion feedback loop (which makes LLM calls per-blocked-request), consider switching to a long-lived Python subprocess with JSON-over-stdin/stdout communication.

For the evasion feedback loop specifically, the orchestrator maintains a persistent subprocess:
1. Start `uv run python -m hypothesis_engine.evasion_server` as a long-lived process at scan start
2. Communicate via JSON lines over stdin/stdout
3. Send `EvasionContext` as a JSON line, receive `EvasionResult` as a JSON line
4. Shut down the subprocess at scan end

This avoids the overhead of starting a new Python process for each blocked request (which could happen hundreds of times in a scan).

---

## 5. New Dependency Registry

### Workspace-Level Additions (Cargo.toml)

| Dependency | Version | Features | Used By | Purpose |
|---|---|---|---|---|
| `rquest` | latest stable | `["json"]` | evasion-engine | TLS/HTTP2 fingerprint impersonation |
| `sarif_rust` | latest stable | — | reporting | SARIF 2.1.0 spec-compliant output |
| `openapiv3` | latest stable | — | enumeration | OpenAPI 3.x schema parsing |
| `graphql-parser` | latest stable | — | enumeration | GraphQL SDL + introspection parsing |
| `cargo-lock` | latest stable | — | passive-recon | Cargo.lock parsing |
| `clap` | 4.x | `["derive"]` | orchestrator | CLI argument parsing |
| `regex` | 1.x | — | defense-fingerprinting | Response body pattern matching |

### Per-Crate Dependency Changes

| Crate | Added | Removed |
|---|---|---|
| `knowledge-graph` | — | `petgraph` |
| `reporting` | `sarif_rust` | `tracing` |
| `enumeration` | `openapiv3`, `graphql-parser` | — |
| `passive-recon` | `cargo-lock` | — |
| `evasion-engine` (new) | `rquest`, `rand`, `serde`, `protocol`, `fuzzing`, `tokio` | — |
| `defense-fingerprinting` (new) | `protocol`, `reqwest`, `serde`, `serde_json`, `regex` | — |
| `orchestrator` (new) | all workspace crates + `clap`, `tracing`, `tracing-subscriber`, `tokio` | — |

### Python Package Changes (hypothesis-engine/pyproject.toml)

No new Python dependencies. The existing `boto3` and `pydantic` are sufficient. The new `evasion_mode.py` and `bedrock_client.py` modules use only stdlib + existing deps.

Add a new CLI entry point in `pyproject.toml` for the evasion server subprocess:
- `hypothesis-engine-evasion = "hypothesis_engine.evasion_mode:serve"` (a function that reads JSON lines from stdin and writes responses to stdout)

---

## 6. Testing Strategy

### Unit Test Requirements

Every new or modified source file requires an adjacent test file. Test counts per component:

| Component | Estimated New/Modified Tests | Test Approach |
|---|---|---|
| chain-synthesis (refactor 3.1) | ~5 new (petgraph edge cases), 35 existing unchanged | Existing behavioral tests validate the migration; add petgraph-specific edge cases |
| reporting/sarif (refactor 3.2) | ~8 new (CWE taxa, fixes, relatedLocations), 46 existing updated | Validate SARIF JSON against official schema; test new fields |
| enumeration/openapi (refactor 3.3) | ~6 new ($ref, security schemes, request body), existing updated | Test specs with complex features that old parser missed |
| enumeration/graphql (refactor 3.4) | ~5 new (SDL, subscriptions, types), existing updated | Test full schema parsing vs previous shallow extraction |
| passive-recon/cargo (refactor 3.5) | ~3 new (git/path deps, format versions), existing unchanged | Real-world Cargo.lock samples |
| fuzzing/unify enum (refactor 3.6) | ~3 new (is_fuzzable filter), existing updated (type names) | Verify filter correctness, existing behavior preserved |
| certificate envelope (refactor 3.8) | ~3 new (versioning, error cases) | Roundtrip with version, unsupported version error |
| default headers (refactor 3.9) | ~2 updated, ~1 new | Verify headers populated, verify override works |
| batch validation (refactor 3.10) | ~3 new (partial batch rejection, intra-batch deps) | Verify all-or-nothing semantics |
| evasion-engine (new 4.2) | ~40 new | Per-module: persona construction, header transform, timing jitter distribution, session rotation, encoding variations, transport integration |
| defense-fingerprinting (new 4.3) | ~25 new | WAF signature matching, rate limit measurement, bot detection probe, profile construction |
| stealth fuzzing (4.4) | ~8 new | Config presets, priority reprioritization, stealth payload ordering |
| evasion feedback loop (4.5) | ~15 new | EvasionContext construction, prompt building, evasion parsing, bedrock client base class, feedback labeling |
| bypass corpus (4.6) | ~6 new | Corpus loading, WAF-targeted filtering, merge with templates |
| reporting enhancements (4.7) | ~8 new | Defense-aware scoring, SARIF properties, EvasionCertificate roundtrip |
| orchestrator (4.8) | ~15 new | Config parsing, localhost validation, pipeline phase transitions, hypothesis engine subprocess integration |

**Estimated total: ~155 new tests, bringing the workspace from ~476 to ~630.**

### Integration Test Requirements

Integration tests live in the orchestrator crate's `tests/` directory (not adjacent test files — these are `#[cfg(test)]` integration tests or a separate `tests/` folder).

| Test | What It Validates |
|---|---|
| `scan_without_defenses` | Full pipeline against a mock HTTP server (no WAF/rate-limit). Verifies findings are produced and SARIF is written. |
| `scan_with_modsecurity` | Full pipeline against ModSecurity Docker stack. Verifies defense fingerprinting detects WAF, evasion engine adapts, some findings still produced. Requires Docker. |
| `scan_with_rate_limiting` | Full pipeline against nginx rate limit stack. Verifies stealth mode activates and requests stay under limit. Requires Docker. |
| `scan_with_bot_detection` | Full pipeline against bot detection stack. Verifies persona headers fool the detector. Requires Docker. |
| `evasion_feedback_loop` | Mock a WAF that blocks standard payloads. Verify the feedback loop calls the hypothesis engine and retries with evasion payloads. Mock LLM responses. |
| `hypothesis_engine_subprocess` | Verify the orchestrator can start, communicate with, and shut down the Python hypothesis engine subprocess. |

Docker-dependent integration tests should be gated behind a feature flag or environment variable (`AEGIS_INTEGRATION_TESTS=1`) so they don't run in CI by default.

### Performance Benchmarks

| Benchmark | Target |
|---|---|
| Evasion engine overhead per request (header transform + session + timing) | < 1ms excluding network I/O and jitter sleep |
| Defense fingerprinting total time (all three probes) | < 30 seconds against a local target |
| Stealth mode 100-request scan | < 5 minutes (at ~1.5 rps with jitter) |
| SARIF emission for 500 findings | < 2 seconds |
| Knowledge graph with 10,000 nodes + 50,000 edges: shortest path query | < 100ms |

---

## 7. Migration and Rollout Order

### Dependency Graph

The following diagram shows which items depend on others. Items at the same level can be parallelized.

```
Level 0 (no dependencies — start here):
  3.7  Remove dead dependencies
  3.6  Unify VulnerabilityClassTarget
  3.5  Replace Cargo.lock parser
  3.8  Add certificate versioning envelope
  4.1  Defense Stack Composer (Docker, independent of Rust crates)

Level 1 (depends on Level 0):
  3.1  Migrate chain-synthesis to petgraph (depends on 3.7 removing petgraph from knowledge-graph)
  3.2  Replace SARIF emitter (depends on nothing, but modifies reporting)
  3.3  Replace OpenAPI parsing
  3.4  Replace GraphQL parsing
  3.9  Add default headers (depends on 3.6 for VulnerabilityClass unification)
  3.10 Validate operation batch

Level 2 (depends on Level 1):
  4.3  Defense fingerprinting module (depends on 3.6 for unified VulnerabilityClass in protocol)
  4.2  Evasion engine (depends on 3.9 for default headers, 3.6 for unified VulnerabilityClass)
  4.4  Stealth fuzzing mode (depends on 3.6 for unified VulnerabilityClass)

Level 3 (depends on Level 2):
  4.5  Evasion feedback loop (depends on 4.2 evasion engine, 4.3 defense fingerprinting)
  4.6  WAF bypass corpus (depends on 4.4 stealth mode for stealth ratings, 3.6 for unified enum)
  4.7  Reporting enhancements (depends on 3.2 SARIF migration, 3.8 certificate versioning, 4.3 defense fingerprinting)

Level 4 (depends on Level 3):
  4.8  Orchestrator CLI (depends on all other components)
```

### Recommended Execution Order

For a single developer working sequentially:

1. **Batch 1 (Foundation):** 3.7, 3.6, 3.5, 3.8 — small, independent refactors. Run `cargo test --workspace` after each.
2. **Batch 2 (Library Migrations):** 3.1, 3.2, 3.3, 3.4 — larger refactors with library swaps. Run full test suite after each.
3. **Batch 3 (Behavioral Changes):** 3.9, 3.10 — changes that alter runtime behavior. Verify carefully.
4. **Batch 4 (Docker + New Crates):** 4.1 (Docker stacks), 4.2 (evasion engine), 4.3 (defense fingerprinting) — can be parallelized if multiple developers.
5. **Batch 5 (Augmentations):** 4.4, 4.5, 4.6 — augment existing crates with Phase 2 features.
6. **Batch 6 (Integration):** 4.7 (reporting), 4.8 (orchestrator) — bring everything together.

### Validation Gates

After each batch, the following must pass before proceeding:

- `cargo test --workspace` — all existing + new tests pass
- `cargo clippy --workspace -- -D warnings` — zero warnings
- `cargo fmt --check` — formatting gate
- `cd hypothesis-engine && uv run pytest src/hypothesis_engine/ -v` — Python tests pass (after Batch 5)

After Batch 6 (orchestrator complete), additionally:
- Run `scan_without_defenses` integration test against a mock HTTP server
- If Docker available: run `scan_with_modsecurity` integration test

### Rollback Plan

Each batch is a set of commits that can be reverted independently. Refactors (Phase 1.5) do not change public API behavior — they change internal implementations. If a refactor introduces a regression that is not caught by tests, revert the batch and investigate.

Phase 2 components are additive — they add new crates and augment existing ones. Reverting a Phase 2 component should not break the Phase 1.5 codebase.

The orchestrator (4.8) is the only component that creates hard dependencies between Phase 2 components. If a Phase 2 component needs to be reverted, the orchestrator's pipeline configuration must be updated to skip the missing phase.
