```markdown
# CLAUDE.md — AEGIS Framework

## Identity

You are building AEGIS, an adversarial vulnerability discovery framework that runs exclusively on localhost. The low-level design document is pasted below this file. Treat it as the sole source of architectural truth.

---

## Prime Directive

**Upon every user message, your first action is to produce or update a task plan.** Before writing any code, before answering any question, generate the full task breakdown for whatever work is being requested. This means:

- Parent tasks representing components or features
- Sub-tasks representing single file modifications (one file per task, no exceptions)
- Dependencies between tasks (which tasks block which)
- Test tasks paired with every implementation task
- Integration test tasks at component boundaries

Every task must be atomic: one file created, one file modified, or one command run. If a task touches two files, split it. No task should take more than one response to complete.

Mark tasks with status: `[ ]` pending, `[~]` in progress, `[x]` complete, `[!]` blocked.

---

## Code Style

**No comments in code. Ever.** Code must be self-documenting through:

- Function names that describe exactly what they do, verbosely if necessary
- Type names that convey their purpose without ambiguity
- Variable names that read as plain English
- Small functions that do one thing (under 40 lines as a hard target)
- Module and file names that map directly to architectural concepts from the LLD
- Enums and types preferred over stringly-typed anything
- Error types that describe what went wrong, not generic wrappers

If you feel the urge to write a comment, rename something instead.

---

## Testing

- Every implementation file has a corresponding test file created in the same task batch
- Unit test coverage target: 95% line coverage minimum
- Run tests after writing them and paste the output
- If tests fail, fix them before marking the task complete
- Integration tests are required at every IPC boundary (between any two processes that communicate)
- Integration tests are required for every confinement layer
- Property-based tests (proptest in Rust, hypothesis in Python) for any function that transforms data
- Fuzz tests for any parser or deserializer
- Test file naming: `{module}_test.rs`, `test_{module}.py`, `{module}.test.ts`

---

## LLM Configuration

Any component that requires LLM inference uses the following:

- **Model:** `global.anthropic.claude-sonnet-4-6`
- **AWS Profile:** `ziya`
- **Provider:** AWS Bedrock
- **Invocation:** Always through the AWS SDK for the relevant language (aws-sdk-bedrockruntime for Rust, boto3 for Python)
- **No hardcoded credentials.** Use the named profile only.
- **Retry with exponential backoff** on throttling (3 retries, 1s/2s/4s base delays)
- **Timeout:** 120 seconds per inference call

When implementing the generative fuzzing engine, hypothesis engine, or any AI-powered module, use Claude as the backing model instead of local open-source models. The LLD's references to local Llama/Qwen models are superseded by this directive.

---

## CLAUDE.md Maintenance

**You must update this file after completing every task.** Updates include:

- Marking the task as complete in the task plan
- Adding any new knowledge, decisions, or patterns discovered during implementation
- Recording any deviations from the LLD with justification
- Updating the dependency graph if new dependencies emerged

**Consolidation rule:** After every 10 completed tasks, review this entire document. Remove stale information. Merge redundant sections. Compress completed task descriptions to one-line summaries. This file must never exceed 500 lines. If it approaches that limit, aggressively summarize older sections while preserving all active task plans and current architectural decisions.

---

## Knowledge Preservation

Maintain these living sections:

### Decisions Log

Record every non-obvious technical decision as a one-liner with date and rationale. Example format:

- `2025-01-15: Chose Cap'n Proto over FlatBuffers — zero-copy AND schema evolution support`

### Discovered Patterns

When you find a pattern that should be reused across the codebase, record it here so you apply it consistently.

### Known Pitfalls

When you encounter a gotcha, library quirk, or non-obvious failure mode, record it here to avoid repeating the mistake.

### Module Dependency Map

Keep an up-to-date ASCII map of which modules depend on which, updated as implementation progresses.

---

## File Organization Rules

- One public type per file maximum in Rust (private helpers are fine)
- Barrel files (mod.rs, **init**.py) contain only re-exports, no logic
- Test files live adjacent to source files, not in a separate tree
- Configuration schemas live in a dedicated `schemas/` directory
- IPC message definitions live in a shared `protocol/` crate used by all Rust components

---

## Build and Run

- Rust workspace with one crate per component
- Python components managed with `uv` (not pip, not poetry)
- `cargo test --workspace` must pass at all times on the main branch
- `cargo clippy --workspace -- -D warnings` must pass (zero warnings policy)
- `cargo fmt --check` must pass
- Python code formatted with `ruff format`, linted with `ruff check`
- Type-checked with `pyright` in strict mode

---

## Git Discipline

- Each completed task is one commit
- Commit message format: `[component] verb phrase describing change`
- Examples: `[knowledge-graph] add edge insertion with dedup`, `[fuzzing] implement coverage bitmap diffing`
- Never commit failing tests

---

## Priority Order

When deciding what to build first, follow this order:

1. Shared protocol definitions (IPC message types)
2. Knowledge Graph engine (everything depends on it)
3. Confinement stack (must exist before any scanning)
4. Passive reconnaissance (feeds the graph with zero risk)
5. Attack surface enumeration (defines what to scan)
6. Taint analysis engine (highest-value static analysis)
7. Generative fuzzing engine (highest-value dynamic analysis)
8. Attack chain synthesis (combines all findings)
9. LLM hypothesis engine (augments all other modules)
10. Reporting (consumes everything)

---

## Current Progress

All core modules implemented. 391 Rust tests passing, 52 Python tests passing. Clippy clean, fmt clean.

**Completed crates (9/9 Rust):**
- [x] protocol — IPC types, node/edge/finding/operation/audit/capability schemas (12 tests)
- [x] knowledge-graph — node store, edge store, finding store, operation log, path queries, reachability, graph facade (91 tests)
- [x] audit-log — SHA3-256 hash chain, HMAC-SHA3-256 signing, append-only log writer, independent log verifier (40 tests)
- [x] supervisor — process manager with backoff restart, capability token issuance/validation (32 tests)
- [x] passive-recon — dependency lock file parsing (5 ecosystems), SQLite vuln database, filesystem walker (58 tests)
- [x] enumeration — multi-framework route parser, OpenAPI/GraphQL introspection, authorization matrix with anomaly detection (47 tests)
- [x] fuzzing — priority queue scheduler, template/bitflip mutator, rate-limited executor, statistical anomaly oracle (41 tests)
- [x] chain-synthesis — attack graph model, Dijkstra shortest path, DFS all simple paths, betweenness centrality (24 tests)
- [x] reporting — composite risk scorer, SARIF 2.1 emitter, CBOR certificate serializer with SHA3-256 hashing (46 tests)

**Completed Python component (1/1):**
- [x] hypothesis-engine — LLM hypothesis generator (Bedrock), hypothesis-to-test compiler, feedback manager with training data export (52 tests)

**Quality gates:**
- [x] cargo clippy --workspace -- -D warnings (zero warnings)
- [x] cargo fmt --check (passes)
- [x] cargo test --workspace (391 passed, 0 failed)
- [x] Python pytest (52 passed, 0 failed)

---

## Decisions Log

- 2025: Chose SHA3-256 over SHA2-256 for hash chain and certificate hashing — aligned with LLD specification
- 2025: Used arena-style Vec storage with u64 indices for node/edge stores — O(1) lookup, cache-friendly
- 2025: Used SQLite in-memory for vuln database — no external dependencies, easy testing
- 2025: Used `let` chains (Rust 2024 edition) for collapsible-if patterns — cleaner code, clippy-clean
- 2025: LLM inference via AWS Bedrock (claude-sonnet-4-6) instead of local models — per CLAUDE.md directive
- 2025: Used CBOR (ciborium) for certificate serialization — compact, self-describing, binary-safe per LLD

---

## Discovered Patterns

- Test file naming: `{module}_test.rs` adjacent to source, included via `#[path]` attribute in lib.rs
- Python test naming: `test_{module}.py` in same package directory
- Builder pattern with `with_*` methods for config structs (ProcessConfig, NodeData, FindingData)
- Epoch-based concurrency: RwLock<Inner> pattern for KnowledgeGraph facade

---

## Known Pitfalls

- Gemfile.lock parsing: must track indent level to avoid picking up sub-dependencies
- Express route handler extraction: trailing `)` and `;` must be stripped
- Authorization matrix anomaly detection: symmetric 200s are correctly flagged — test expectations must account for this
- Pydantic models starting with "Test" trigger pytest collection warnings — harmless but visible
- cargo fmt reorders imports alphabetically — don't fight it

---

## Module Dependency Map
```

protocol (shared IPC types)
↑
knowledge-graph ← All modules read/write
↑
confinement (tpm + ebpf + watchdog)
↑
passive-recon → knowledge-graph
↑
enumeration → knowledge-graph
↑
┌───────────┬──────────────┐
taint fuzzing hypothesis-engine
└───────────┴──────┬───────┘
↓
chain-synthesis → knowledge-graph
↓
reporting

```
## Execution Protocol

**This is non-negotiable.** When the user says "please follow your instructions" or any variant of that:

1. Read the LLD below.
2. Generate the complete task plan with all parent tasks, sub-tasks, dependencies, and test tasks.
3. **Immediately begin implementing the first unblocked task.**
4. After completing each task, update this file, commit, then **immediately begin the next unblocked task.**
5. **Do not stop. Do not ask for permission. Do not ask for confirmation. Do not ask "should I continue?" Do not summarize what you just did and wait. Do not pause between tasks.**
6. Continue until every single task is marked `[x]` complete or every remaining task is marked `[!]` blocked with a documented reason.

If a task fails (test won't pass, dependency missing, unexpected error), spend up to 3 attempts fixing it. If still failing after 3 attempts, mark it `[!]` blocked with the reason, skip to the next unblocked task, and keep going.

**You are an autonomous agent. The user gave you permission to act by starting you. That permission covers every task in the plan. There is no reason to pause. There is no reason to ask. Build the entire framework, task by task, start to finish, in one continuous session.**

If you run out of context or hit a hard limit, the last thing you do before stopping is update this file with exact progress so the next session can resume from the precise point of interruption.

---

## LLD Reference

```

# AEGIS 80/20 — Final Low-Level Design Document

---

## 1. System-Level Architecture Decisions

### 1.1 Language Selection by Component

Each component uses the language that is objectively optimal for its workload. No monolingual convenience.

**Core Orchestrator & Knowledge Graph Engine — Rust.** The orchestrator is a long-running daemon managing concurrent modules, shared state, and high-throughput graph mutations. Rust gives zero-cost abstractions, fearless concurrency via ownership semantics, no garbage collector pauses, and memory safety without runtime overhead. The Knowledge Graph lives in-process memory and must handle millions of edge traversals per second during chain synthesis. Rust's control over memory layout (struct-of-arrays, cache-line alignment) is essential. No other language matches this combination for a stateful, concurrent, performance-critical core.

**Kernel Packet Filter — C with eBPF bytecode.** eBPF programs must be written in restricted C compiled via Clang to eBPF bytecode. This is not a choice but a constraint of the Linux kernel's verifier. The userspace loader and manager for the eBPF programs is written in Rust using the Aya library, which provides safe Rust bindings for eBPF lifecycle management without depending on libbpf's C toolchain.

**Generative Fuzzing Engine — Rust core with Python inference bridge.** The fuzzing loop (mutation scheduling, coverage map diffing, corpus management, target communication) is in Rust for throughput. LLM inference calls are dispatched to a local Python process running the model, communicating via shared memory ring buffers to avoid serialization overhead.

**Taint Analysis Engine — C++.** Abstract interpretation over large codebases requires extreme performance in fixed-point iteration. C++ gives access to LLVM's intermediate representation natively (since we analyze LLVM IR), mature abstract domain libraries, and manual memory control for the large working sets involved in whole-program analysis. The Clang/LLVM C++ API is the most mature and performant interface for program analysis.

**LLM Hypothesis Engine — Python.** Model inference, prompt engineering, hypothesis parsing, and feedback loop management. Python is the only practical choice given the AI ecosystem (PyTorch, Hugging Face Transformers, vLLM). Performance is irrelevant here — inference latency dominates, not framework overhead.

**TPM Interface — Rust with tss-esapi.** The tss-esapi crate provides safe Rust bindings to the TPM2 software stack. Safer than raw C TSS calls, same performance.

**Report Generator — Rust.** Templating, certificate serialization, and graph export are CPU-bound and benefit from Rust's speed. PDF generation via a lightweight binding to a C library (libharu or similar).

### 1.2 Inter-Process Communication Architecture

The system runs as multiple processes, not one monolith. Isolation between components prevents a bug in one module from corrupting another.

**Primary IPC: Unix domain sockets with Cap'n Proto serialization.** Cap'n Proto is zero-copy — the serialized format is the in-memory format. No encode/decode step. This matters when the fuzzing engine is sending thousands of findings per second to the Knowledge Graph. Unix domain sockets are loopback-only by definition (they exist only in the filesystem namespace), which aligns with confinement goals.

**High-throughput path: Shared memory ring buffers.** Between the fuzzing engine and the LLM inference process, and between the fuzzing engine and the coverage collector. Lock-free single-producer single-consumer ring buffers (Lamport queues) in POSIX shared memory. The fuzzing engine writes candidate inputs; the inference process reads, generates, and writes back. No system calls in the hot path.

**Knowledge Graph mutations: Batched append-only operation log.** Modules do not directly mutate the graph. They append typed operations (AddNode, AddEdge, UpdateWeight, AddFinding) to a per-module log. The graph engine consumes these logs in batches, applies them transactionally, and advances a monotonic sequence number. This eliminates write contention entirely and gives deterministic replay for reproducibility.

### 1.3 Process Supervision Model

A root supervisor process (Rust, minimal, auditable) spawns and monitors all component processes. It enforces:

- Each child runs in its own Linux namespace (PID, network, mount, user)
- Each child has a cgroup limiting CPU, memory, and IO
- Each child's network namespace contains only the loopback interface (redundant with eBPF filter — defense in depth)
- Crash of any child is logged, reported, and the child is restarted with backoff
- The supervisor itself is the only process that holds the unsealed TPM session key

The supervisor communicates with children only via the Unix domain socket IPC layer. Children never hold the master key — they receive scoped, time-limited capability tokens for their specific function.

### 1.4 Filesystem Layout

```
/opt/aegis/
├── bin/                    # Compiled binaries per component
├── models/                 # LLM weights (quantized, local only)
├── signatures/             # Component integrity hashes
├── tpm-state/              # TPM-sealed key material (encrypted at rest)
├── ceremony/               # Target binding artifacts
├── graph/                  # Memory-mapped graph backing store
├── corpus/                 # Fuzz corpus (deduplicated)
├── vuln-db/                # Local vulnerability database mirrors
├── logs/                   # Append-only hash-chained audit log
├── reports/                # Generated output
└── plugins/                # Third-party extensions (sandboxed)
```

All directories except `reports` are mounted read-only to non-owner processes. The `tpm-state` directory is accessible only to the supervisor process. The `logs` directory is append-only (enforced via `chattr +a` on Linux and additionally by the hash chain integrity mechanism).

---

## 2. Confinement Stack — Detailed Design

### 2.1 TPM Hardware Binding

**Initialization sequence:**

The supervisor process connects to the TPM via the `/dev/tpm0` device. It reads PCR registers 0 through 7 (BIOS, bootloader, OS kernel, kernel modules). It generates a 256-bit primary seed using the TPM's hardware RNG. It derives a session master key using HKDF-SHA3-256 with the primary seed as input key material and a context string incorporating the PCR values. This master key is then sealed to the current PCR state using the TPM2_Create command with a policy session bound to the PCR values.

**Runtime unsealing:**

On every startup, the supervisor attempts TPM2_Unseal. If PCR values have changed (different hardware, modified boot chain, different kernel), the unseal fails and the framework refuses to start. The operator must perform a new initialization from a verified boot state.

**Machine fingerprint:**

Independent of TPM, the supervisor computes a secondary fingerprint: SHA3-256 of (CPU model + CPU serial via CPUID + motherboard UUID via DMI/SMBIOS + MAC addresses of physical NICs + disk serial numbers). This fingerprint is embedded in the binding token and checked on every ceremony validation. This is defense-in-depth — the TPM seal is the primary lock, the fingerprint is a secondary consistency check.

### 2.2 Kernel Packet Filter

**eBPF program design:**

A single eBPF program attached to the `cgroup/sendmsg4`, `cgroup/sendmsg6`, and `cgroup/connect4`, `cgroup/connect6` hooks for the AEGIS cgroup. These hooks fire before any socket operation leaves userspace.

The program logic (expressed in restricted C, compiled to eBPF bytecode):

For every outbound connection attempt or message send, read the destination address. If IPv4 and not in 127.0.0.0/8, return DENY. If IPv6 and not ::1, return DENY. If the destination port is not in the target's declared port set (stored in an eBPF map populated during ceremony), return DENY. For all passing packets, increment a per-second counter in a BPF map. If the counter exceeds the operator-declared maximum requests per second, return DENY.

**Tamper resistance:**

The eBPF program's bytecode is hashed and the hash is stored in TPM-sealed storage during initialization. Before every scan session, the supervisor re-loads the eBPF program and verifies the bytecode hash against the sealed value. The cgroup to which the program is attached is the AEGIS cgroup — all framework child processes are placed in this cgroup by the supervisor at spawn time.

Detaching the eBPF program requires CAP_BPF and CAP_NET_ADMIN capabilities. The supervisor drops these capabilities for all child processes. Only the supervisor retains them, and the supervisor's own code path never detaches the filter.

### 2.3 Behavioral Watchdog

**Implementation:**

A standalone Rust binary running in its own PID and network namespace. It receives a read-only file descriptor to a raw packet socket on the AEGIS cgroup's network traffic (via BPF_MAP_TYPE_RINGBUF shared from the eBPF program). It passively observes every packet the framework sends without being in the data path.

**Detection rules (evaluated per-packet):**

Rule 1 — Destination not loopback: immediate kill signal to supervisor via a dedicated Unix domain socket. Rule 2 — Any UDP packet to port 53 (DNS): kill. Rule 3 — Any ARP frame: kill. Rule 4 — Any packet to a gateway IP (determined at startup by reading the routing table): kill. Rule 5 — Cumulative bytes sent exceeds the scan plan declaration by more than 10%: kill. Rule 6 — Any ICMP packet not to loopback: kill.

**Kill mechanism:**

The watchdog holds a pre-opened file descriptor to the TPM-sealed key file. On any trigger, it overwrites the key material with zeros via a direct write, then sends SIGKILL to the supervisor's PID (known at startup). The supervisor's death cascades to all children via the PID namespace hierarchy.

**Self-protection:**

The watchdog's own binary hash is verified by the supervisor at launch time against the TPM-sealed manifest. The watchdog runs with minimal capabilities (CAP_NET_RAW only for the packet socket). Its memory is locked (mlockall) to prevent swapping and potential inspection.

---

## 3. Knowledge Graph Engine — Detailed Design

### 3.1 Data Model

**Node structure (Rust):**

Each node has a 64-bit unique ID (monotonic counter), a type tag (enum: Endpoint, Function, DataStore, Role, Dependency, Config, User, Service), a property map (small-string-optimized hashmap storing key-value metadata), and an adjacency list (sorted vector of edge IDs for cache-friendly traversal).

**Edge structure:**

Each edge has a 64-bit unique ID, source node ID, target node ID, a label tag (enum: Calls, Trusts, Authenticates, Reads, Writes, DependsOn, Exposes), a weight (64-bit float encoding severity or confidence), and a provenance tag (which module created it, with sequence number for audit trail).

**Finding structure:**

Findings are a specialized node type linked to the relevant graph nodes. Each finding contains: finding ID, vulnerability class (enum of CWE categories), severity score, confidence score, a certificate (opaque byte blob containing the proof — a concrete input, a taint path, a request/response pair), the provenance module, and a timestamp.

### 3.2 Storage Engine

**In-memory primary store:**

Nodes and edges stored in arena-allocated, cache-line-aligned arrays (struct-of-arrays layout for each field). Node IDs are indices into the array, making lookups O(1). Adjacency lists stored as sorted compressed arrays of edge indices — sorted by target node for binary search, compressed using delta encoding and varint for memory efficiency.

**Memory-mapped persistence:**

The graph is backed by a memory-mapped file (`mmap` with `MAP_SHARED`). On clean shutdown, the graph is flushed. On crash, the graph is reconstructed from the append-only operation logs (which are `fsync`'d after each batch). The mmap file lives on a tmpfs during scanning for speed, with periodic snapshots to persistent storage.

**Expected scale:**

A typical web application produces 10K-100K nodes and 100K-1M edges. At roughly 128 bytes per node and 64 bytes per edge, this fits comfortably in 100-200MB of RAM. The graph engine is designed to handle up to 10M nodes and 100M edges (approximately 10GB) for pathological cases.

### 3.3 Query Engine

**Path queries:**

"All paths from node A to node B with at most N hops" — implemented as bidirectional BFS with depth limiting. For weighted shortest paths, Dijkstra with a Fibonacci heap. For all-pairs shortest paths on the full graph, Johnson's algorithm (Bellman-Ford for reweighting, then per-node Dijkstra).

**Reachability queries:**

"All nodes reachable from node A through edges of types T" — standard BFS/DFS with edge-type filtering. Result cached and invalidated on graph mutation.

**Cut vertex computation:**

Tarjan's bridge-finding algorithm on the subgraph induced by vulnerability edges. Runs in O(V+E) time. Identifies single nodes whose removal disconnects the most attack paths.

**Pattern matching:**

Subgraph isomorphism queries for detecting known vulnerability patterns (e.g., "unauthenticated endpoint → calls function → writes to database without sanitization"). Implemented using the VF3 algorithm for small pattern graphs (under 20 nodes). Patterns are defined in the custom DSL and compiled to VF3 query structures.

### 3.4 Concurrency Model

The graph engine runs in a single writer thread (consuming the batched operation logs) with multiple reader threads (serving queries from other modules). Readers use epoch-based reclamation — they register their epoch on entry, read freely without locks, and the writer defers deallocation of removed nodes/edges until all readers have advanced past the removal epoch. This gives lock-free reads with zero contention.

---

## 4. Passive Reconnaissance — Detailed Design

### 4.1 Traffic Capture

**Mechanism:** The supervisor attaches a BPF_MAP_TYPE_RINGBUF to the loopback interface filtered to the target application's port range. The recon module reads from this ring buffer. This is purely passive — no packets injected.

**Protocol dissection:** A layered protocol dissector chain. Raw bytes → TCP stream reassembly (handling out-of-order segments, retransmissions) → TLS decryption (if the target's TLS key is provided during ceremony; if not, only unencrypted traffic is analyzed) → application protocol identification via magic bytes and heuristics → protocol-specific parsing.

Supported protocols with custom parsers: HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSocket, gRPC (over HTTP/2), GraphQL (over HTTP), PostgreSQL wire protocol, MySQL wire protocol, MongoDB wire protocol, Redis RESP, AMQP 0-9-1, MQTT, memcached binary protocol.

Each parser emits structured events (RequestObserved, ResponseObserved, QueryObserved, MessageObserved) into the Knowledge Graph operation log.

### 4.2 File System Analysis

**Manifest parsing:** The recon module is given the application's root directory path during ceremony. It recursively walks the filesystem and classifies each file by extension and content heuristics.

Parsers for: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml, requirements.txt, Pipfile.lock, poetry.lock, go.mod, go.sum, Cargo.toml, Cargo.lock, pom.xml, build.gradle, Gemfile.lock, composer.lock, Dockerfile, docker-compose.yml, Kubernetes manifests, Terraform files, CloudFormation templates, .env files, nginx.conf, apache configs, application.yml/properties, and generic INI/TOML/YAML/JSON config files.

**Dependency resolution:** From lock files, construct the full transitive dependency tree with exact pinned versions. Each dependency becomes a node in the Knowledge Graph with DependsOn edges. Cross-reference each (package-name, version) tuple against the local vulnerability database.

### 4.3 Local Vulnerability Database

**Content:** Monthly snapshots of NVD (in JSON feed format), OSV database, GitHub Advisory Database, and Snyk's public database. Stored as a SQLite database with full-text search indexes on CVE descriptions and affected package/version ranges.

**Matching:** For each dependency, query: "SELECT findings WHERE package = ? AND version_start <= ? AND version_end >= ?". Semantic versioning range matching implemented in Rust using the semver crate.

**Update mechanism:** The operator manually downloads updated database snapshots and places them in the `vuln-db` directory. AEGIS never fetches these over the network (confinement). The supervisor verifies the snapshot's GPG signature against a set of trusted public keys embedded at build time.

### 4.4 Behavioral Baselining

From observed traffic, the recon module builds:

- **Endpoint inventory:** URL path templates (with parameterized segments identified via clustering — paths that differ by one segment are likely the same endpoint with a path parameter)
- **Per-endpoint profile:** observed HTTP methods, content types, authentication headers present, response status code distribution, response time distribution (mean, p50, p95, p99), response body size distribution
- **Session model:** how session tokens are issued, refreshed, and invalidated based on observed Set-Cookie and Authorization header patterns

This baseline is serialized and stored. The fuzzing oracle uses it as its reference distribution for anomaly detection.

---

## 5. Attack Surface Enumeration — Detailed Design

### 5.1 Endpoint Discovery

**Source-derived routes (highest confidence):** If source code is available, the taint analysis engine (Module 6) extracts route definitions. For common frameworks:

- Express.js: AST pattern match on `app.get/post/put/delete/use` and `router.*`
- Django: parse `urls.py` urlpatterns
- Flask: decorator pattern match on `@app.route`
- Spring: annotation scan for `@RequestMapping`, `@GetMapping`, etc.
- Rails: parse `config/routes.rb`
- FastAPI: decorator pattern match on `@app.get/post` etc.
- Go net/http: pattern match on `http.HandleFunc` and mux registrations

Each discovered route is added to the Knowledge Graph as an Endpoint node with metadata (HTTP method, path pattern, handler function reference).

**Introspection (high confidence):** For applications exposing OpenAPI/Swagger (probe `/openapi.json`, `/swagger.json`, `/api-docs`), GraphQL introspection (probe `/graphql` with introspection query), or gRPC reflection, parse the schema and add all discovered endpoints, parameters, and types.

**Dictionary enumeration (medium confidence):** A wordlist of 50K common path segments, ranked by probability using a small language model trained on web application route corpora. Enumeration uses a priority queue — highest probability paths first. Adaptive: if `/api/v1/users` exists, immediately enqueue `/api/v1/users/{id}`, `/api/v1/users/me`, `/api/v1/users/search`, etc. based on co-occurrence statistics.

**Recursive crawl (medium confidence):** Starting from the root URL and any discovered endpoints, render JavaScript using a headless Chromium instance (controlled via Chrome DevTools Protocol), extract all links, form actions, fetch/XHR calls, and WebSocket connections from the rendered DOM and network activity. Follow links recursively up to a configurable depth.

### 5.2 Parameter Discovery

For each endpoint, systematically test for hidden parameters:

**Reflected parameter mining:** Send requests with candidate parameter names (from a ranked wordlist) and detect reflection in the response body, headers, or timing. A parameter is considered discovered if adding it changes the response in any measurable way (body diff, header diff, status code diff, timing diff beyond 2 standard deviations).

**Content-type alternation:** For each endpoint, attempt the request with different Content-Type headers (application/json, application/x-www-form-urlencoded, multipart/form-data, application/xml) and observe whether the endpoint accepts and processes the alternative format. Many endpoints accept formats they don't document.

### 5.3 Authorization Matrix

The ceremony collects multiple credential sets (e.g., unauthenticated, regular user, admin, service account). For every discovered endpoint × method × credential set, send the request and record the response status. Build a matrix:

| Endpoint          | Unauth | User | Admin | Service |
| ----------------- | ------ | ---- | ----- | ------- |
| GET /users        | 401    | 200  | 200   | 200     |
| DELETE /users/1   | 401    | 403  | 200   | 200     |
| GET /admin/config | 401    | 403  | 200   | 200     |

Any cell where a lower-privilege credential gets 200 where it should get 403 (inferred from the pattern) is flagged as a potential IDOR or privilege escalation. Inference uses a simple heuristic: if the admin gets 200 and the user gets 200 on a path containing "admin", flag it.

---

## 6. Generative Fuzzing Engine — Detailed Design

### 6.1 Architecture

The fuzzing engine consists of four cooperating processes:

**Scheduler (Rust):** Maintains the priority queue of targets (endpoint × parameter × vulnerability class triples). Priority is determined by: Knowledge Graph centrality of the endpoint (more connected = higher priority), number of unexplored vulnerability classes for that endpoint, and LLM hypothesis confidence scores. Dispatches targets to the mutator.

**Mutator (Rust):** For each target, selects a mutation strategy. Two modes:

_Template mode:_ Uses pre-built payload templates for each vulnerability class (SQLi, XSS, SSTI, path traversal, command injection, SSRF, deserialization, header injection, CRLF, open redirect). Templates are parameterized and adapted to the target's technology stack fingerprint. For example, SQLi templates differ for PostgreSQL vs MySQL vs SQLite based on syntax differences.

_Generative mode:_ Sends context (endpoint signature, technology stack, parameter type, vulnerability class) to the LLM inference process and receives a batch of novel payloads. The LLM generates payloads that are grammar-aware — syntactically structured to probe parser boundaries rather than random noise.

The mutator alternates between modes: template mode for breadth (fast, covers known patterns), generative mode for depth (slow, discovers novel patterns).

**Executor (Rust):** Sends crafted requests to the target via the loopback interface. Manages connection pooling, rate limiting (respecting the operator-declared max RPS), timeout handling, and response capture. Each request-response pair is assigned a unique ID and stored in the corpus.

**Oracle (Rust with statistical libraries):** Compares each response against the behavioral baseline:

- **Status code anomaly:** Response code not in the baseline distribution for this endpoint
- **Timing anomaly:** Response time exceeds baseline p99 by more than 3x (potential algorithmic complexity or blind injection indicator)
- **Size anomaly:** Response body size differs from baseline mean by more than 3 standard deviations (potential error-based information disclosure)
- **Content anomaly:** Response body contains patterns not present in baseline responses: stack traces, SQL error messages, file paths, internal IP addresses, debug information. Detected via a pre-compiled set of regex patterns (approximately 500 patterns covering major frameworks and databases)
- **Reflection detection:** The payload (or a transformed version of it) appears in the response body, indicating potential XSS or injection reflection
- **Behavioral sequence anomaly:** A sequence of requests produces a state change that shouldn't be possible (detected by comparing state-dependent responses before and after the sequence)

Each anomaly is scored. Anomalies above threshold are written to the Knowledge Graph as findings with the request-response pair as the certificate.

### 6.2 Coverage Guidance

**Instrumentation:** If the target application can be recompiled with coverage instrumentation (LLVM SanitizerCoverage for C/C++/Rust, JaCoCo for Java, coverage.py for Python, c8/istanbul for Node.js), the fuzzing engine reads the coverage map after each request.

**Coverage map format:** A shared memory region containing a bitmap. Each bit (or byte, for hit-count granularity) corresponds to a basic block or edge in the target's control flow graph. The fuzzing engine diffs the bitmap after each request against the cumulative bitmap. New bits indicate new code paths reached.

**Reinforcement learning loop:** The coverage gain (number of new bits) from each generated input is the reward signal. The LLM generator is fine-tuned using a reward model: inputs that produce coverage gain are upweighted in the training distribution. This is implemented as a lightweight RLHF loop using PPO (Proximal Policy Optimization) applied to the generator model at the end of each fuzzing batch (every ~1000 inputs).

**Corpus management:** Inputs are retained in the corpus only if they contribute unique coverage bits (using the AFL-style favored seed selection algorithm). The corpus is periodically minimized: for each coverage bit, retain only the smallest input that triggers it. This keeps the corpus focused and prevents unbounded growth.

### 6.3 LLM Model Selection

**Primary model:** A locally-hosted Llama 3.1 8B or Qwen 2.5 7B model, quantized to 4-bit (GGUF format) for inference efficiency on consumer GPUs. Fine-tuned on a corpus of:

- Public vulnerability disclosures (CVE descriptions + proof-of-concept inputs)
- Web application security testing payloads (aggregated from SecLists, PayloadsAllTheThings, and HackerOne public reports)
- Grammar specifications for target input formats
- Code patterns associated with each vulnerability class

**Inference engine:** vLLM for batched inference with PagedAttention, maximizing GPU throughput. The model runs as a persistent process, accepting requests via the shared memory ring buffer.

**Fallback:** If no GPU is available, use llama.cpp with CPU-optimized quantization (Q4_K_M). Slower but functional. The scheduler adjusts its generative-vs-template ratio based on inference throughput — if the LLM is slow, lean more on templates.

---

## 7. Taint Analysis Engine — Detailed Design

### 7.1 Analysis Pipeline

**Step 1 — Compilation to IR:** Source code is compiled to LLVM IR using the appropriate frontend. Clang for C/C++, the Rust compiler for Rust (emitting LLVM IR via `--emit=llvm-ir`), and for interpreted languages (Python, JavaScript, Ruby), a custom source-to-IR transpiler that converts the language's AST into a simplified IR capturing data flow semantics. This transpiler does not need to be semantically complete — it needs to accurately model data flow, not compute correct results. For Java/Kotlin, compile to JVM bytecode and convert to IR using the WALA framework's SSA IR.

**Step 2 — Source and sink identification:** Sources are program points where untrusted data enters: HTTP request parameters, headers, body, cookies, database query results, file reads, environment variable reads, deserialized objects. Sinks are program points where data is consumed dangerously: SQL query construction, command execution, file path construction, HTML output, redirect targets, cryptographic key material, log output.

Sources and sinks are identified by matching function signatures against a configurable database of known source/sink functions per framework. For example, in Express.js: `req.params.*`, `req.query.*`, `req.body.*` are sources; `res.send()`, `res.render()`, `db.query()` are sinks. Approximately 2000 source/sink patterns covering 30 major frameworks are shipped by default.

**Step 3 — Taint propagation:** The taint domain is a lattice with elements: Untainted (bottom), Tainted(source_id, transforms[]) (middle), and Top. The transforms list records sanitization/encoding functions the data passed through.

The analysis is a forward data-flow analysis over the LLVM IR's SSA form. Transfer functions:

- Assignment: taint propagates from right-hand side to left-hand side
- Arithmetic/string operations: if any operand is tainted, the result is tainted (union of taint sources)
- Function calls to known sanitizers: the taint's transform list is appended with the sanitizer identity
- Function calls to unknown functions: conservatively, if any argument is tainted, the return value and all mutable reference arguments are tainted (configurable — can be set to optimistic for speed)
- Phi nodes (SSA merge points): union of incoming taints

**Step 4 — Sink checking:** At each sink, check whether the arriving taint has been adequately sanitized for that sink type. A "sanitizer adequacy" database maps (sink type, sanitizer function) → {adequate, inadequate, unknown}. For example:

- SQL sink + parameterized query = adequate
- SQL sink + manual string escaping = flagged as potentially inadequate
- HTML sink + HTML entity encoding = adequate for body context
- HTML sink + HTML entity encoding = inadequate for JavaScript context (needs JS encoding)
- Command sink + any sanitizer = flagged (parameterization preferred over sanitization)

Taint paths arriving at a sink with inadequate or no sanitization are flagged as findings.

**Step 5 — Path-sensitive refinement:** For flagged paths, a lightweight path-sensitive analysis checks whether the path is actually feasible (not guarded by an always-true condition that prevents the tainted data from reaching the sink). This uses a simplified predicate abstraction — tracking boolean conditions on the path and checking for contradictions.

### 7.2 Cross-Language Taint Tracking

Modern applications cross language boundaries: JavaScript frontend calls Python API which calls SQL database. Taint must be tracked across these boundaries.

**Mechanism:** At each language boundary (HTTP call, database query, message queue publish), the analysis identifies:

- What data from the current language's taint state is included in the outgoing message
- What data in the receiving language's entry point corresponds to the incoming message

These correspondences are modeled as "taint bridges" — edges in the Knowledge Graph that connect a sink in one language to a source in another. The analysis runs per-language independently, then the Knowledge Graph engine stitches the per-language taint paths into cross-language paths via these bridges.

For HTTP boundaries, the bridge maps: (request parameter names in the client) ↔ (request parameter access in the server). For database boundaries: (query string in the application) ↔ (column access in the next query that reads the data).

### 7.3 Performance

The analysis is designed to complete in under 10 minutes for a 500KLOC application. Key optimizations:

- **Sparse analysis:** Only track taint for variables that are reachable from a source. Most variables in a program are never tainted — skip them entirely using a pre-pass reachability analysis.
- **Incremental:** Cache per-function summaries (input taint → output taint mapping). On code change, invalidate only the changed function and its transitive callers.
- **Parallelism:** Functions with no data-flow dependency between them are analyzed in parallel using a work-stealing thread pool. The dependency order is determined by the call graph's topological sort (bottom-up analysis: callees before callers).

### 7.4 Tech Stack

- **C++ 20** with LLVM 18 libraries for IR manipulation
- **LLVM PassManager** infrastructure for the analysis passes
- **Custom abstract domain library** implementing the taint lattice with efficient union and subset operations
- **RocksDB** for persisting per-function summaries between incremental runs (LSM-tree gives fast writes for summary updates)
- Results exported to the Knowledge Graph via Cap'n Proto IPC

---

## 8. Attack Chain Synthesis — Detailed Design

### 8.1 Graph Construction

From the Knowledge Graph, extract the "attack graph" — a subgraph where:

- Nodes are security boundaries (authentication gates, authorization checks, network boundaries, privilege levels)
- Edges are vulnerabilities that allow crossing a boundary, weighted by exploitation difficulty (inverse of CVSS exploitability score, normalized to 0-1)

Additionally, create "stepping stone" edges: if vulnerability A gives you credential X, and credential X is sufficient to exploit vulnerability B, create a composite edge A→B.

### 8.2 Algorithms

**Reachability:** BFS from each entry point (unauthenticated endpoints, low-privilege roles) through the attack graph. Output: the set of assets reachable from each entry point.

**Shortest paths:** Dijkstra from each entry point. Output: the minimum total difficulty to reach each asset. This directly answers "what is the easiest attack path to our database?"

**All simple paths (bounded):** Enumerate all simple paths (no repeated nodes) up to length K (default K=8) from entry points to critical assets using DFS with backtracking. Paths are ranked by total weight. This is exponential in K but bounded by the small size of the attack graph (typically under 1000 nodes after reduction to security boundaries).

**Cut vertex analysis:** Run Tarjan's algorithm on the attack graph. For each cut vertex, compute the number of entry-to-asset paths that pass through it. Rank by this count. The top-ranked cut vertex is the single fix that eliminates the most attack paths.

**Betweenness centrality:** Compute the betweenness centrality of each vulnerability node — the fraction of shortest attack paths that pass through it. High betweenness = high-value remediation target.

### 8.3 Probabilistic Analysis

Assign each vulnerability edge a probability of successful exploitation (derived from CVSS exploitability metrics, adjusted by the presence of WAFs, rate limiting, and other mitigating controls observed during enumeration).

Compute per-asset compromise probability using the inclusion-exclusion principle over independent attack paths. For correlated paths (sharing common edges), use a Bayesian network representation and perform exact inference (variable elimination) or approximate inference (loopy belief propagation) depending on graph complexity.

### 8.4 LLM Chain Reasoning

Feed the attack graph (serialized as a structured text representation) to the LLM with the prompt: "Given these vulnerabilities and their relationships, identify attack chains that a skilled attacker could construct, especially chains involving business logic abuse or unconventional technique combinations."

The LLM's output is parsed into candidate chains. Each candidate chain is validated against the Knowledge Graph — every step must correspond to a real vulnerability and a valid edge. Validated chains that the algorithmic analysis missed (because they involve semantic reasoning about business logic rather than pure graph connectivity) are added to the findings.

---

## 9. LLM Hypothesis Engine — Detailed Design

### 9.1 Architecture

Three-stage pipeline: **Generation → Compilation → Execution → Feedback.**

**Generation:** The hypothesis LLM receives a structured context window containing:

- Technology stack summary
- Top 50 highest-centrality nodes from the Knowledge Graph
- All findings so far (summarized)
- Source code snippets for the highest-risk functions (identified by taint analysis)
- The authorization matrix
- Dependency list with known vulnerabilities

It generates 10-20 natural language hypotheses per scan session. Each hypothesis follows a structured format: "IF [condition about the application] THEN [vulnerability class] EXISTS BECAUSE [reasoning] AND CAN BE TESTED BY [approach]."

**Compilation:** A second LLM (or the same model with a different system prompt) converts each hypothesis into a structured test specification: target endpoint, HTTP method, parameter names, payload patterns, expected anomalous response characteristics. The specification is serialized as a JSON document conforming to a strict schema.

**Execution:** The fuzzing engine's scheduler ingests hypothesis test specifications as high-priority targets. They are executed through the normal fuzzing pipeline (executor → oracle → findings).

**Feedback:** After execution, each hypothesis is labeled as confirmed (anomaly detected), refuted (no anomaly), or inconclusive (anomaly detected but below threshold). This labeled dataset is accumulated across scan sessions and used to periodically fine-tune the hypothesis generator using supervised learning (standard cross-entropy loss on confirmed/refuted classification).

### 9.2 Model Selection

**Hypothesis generator:** Requires strong reasoning — use the largest model that fits in local GPU memory. Qwen 2.5 32B at 4-bit quantization (requires ~20GB VRAM) or Llama 3.1 70B at 2-bit quantization (requires ~24GB VRAM). If GPU memory is limited, fall back to the 7-8B class models used by the fuzzing engine.

**Hypothesis compiler:** Lower reasoning requirement, higher instruction-following requirement. A 7-8B instruction-tuned model is sufficient. Can share the fuzzing engine's model instance.

### 9.3 Prompt Engineering

Hypotheses are generated using chain-of-thought prompting with few-shot examples drawn from real vulnerability disclosures. The prompt includes 5 examples of (application context → hypothesis → test → result) drawn from a curated library of 200 real-world vulnerability patterns. Examples are selected by semantic similarity to the current application context using embedding-based retrieval (all-MiniLM-L6-v2 embeddings, FAISS index, cosine similarity).

---

## 10. Reporting — Detailed Design

### 10.1 Vulnerability Certificates

Each finding type produces a different certificate format:

- **Fuzzing findings:** The complete HTTP request (method, URL, headers, body) and the complete HTTP response, plus the specific anomaly detected and its statistical significance (z-score or p-value relative to baseline)
- **Taint findings:** The complete source-to-sink path as a list of (file, line, function, variable, operation) tuples, with the taint state at each step
- **Chain findings:** The ordered list of individual vulnerabilities comprising the chain, with the transition condition between each step
- **Config findings:** The specific configuration key, its current value, and the expected/secure value
- **Dependency findings:** The package name, installed version, vulnerable version range, and CVE identifier

All certificates are serialized as CBOR (Concise Binary Object Representation) — more compact than JSON, self-describing, and supports binary data natively. Each certificate is hashed (SHA3-256) and the hash is included in the append-only audit log.

### 10.2 Risk Scoring

Each finding receives a composite score computed as:

**Exploitability (0-10):** Derived from the vulnerability class's base CVSS exploitability metrics, adjusted by observed attack surface characteristics (is the endpoint authenticated? rate-limited? behind a WAF?).

**Reachability (0-10):** The number of distinct attack paths in the Knowledge Graph that include this vulnerability, normalized logarithmically.

**Blast radius (0-10):** The number of critical assets reachable through attack chains that include this vulnerability, weighted by asset criticality (data stores with PII score highest).

**Confidence (0-1):** Mathematical proof = 1.0. SMT witness = 0.99. Taint path confirmed by path-sensitive analysis = 0.95. Fuzzing anomaly with p < 0.001 = 0.90. LLM hypothesis confirmed = 0.80. Heuristic pattern match = 0.50.

**Composite score:** Exploitability × Reachability × Blast_Radius × Confidence, normalized to 0-100.

### 10.3 Game-Theoretic Remediation Ordering

Model as a Stackelberg game. The defender (operator) moves first by choosing which K vulnerabilities to fix (K = remediation budget). The attacker then observes the resulting attack graph and chooses the optimal attack path.

The defender's objective: choose K fixes that minimize the attacker's maximum achievable damage.

This is solved as a mixed-integer linear program: decision variables are binary (fix/don't fix each vulnerability), the objective function is the minimax damage over all remaining attack paths, and the constraint is the budget K. Solved using an off-the-shelf MIP solver (HiGHS — open source, C++ with Rust bindings, competitive with commercial solvers for moderate problem sizes).

The output is an ordered remediation list: "Fix these vulnerabilities in this order for maximum risk reduction per unit of effort."

### 10.4 Output Formats

- **Machine-readable:** JSON report conforming to SARIF 2.1 (Static Analysis Results Interchange Format) for integration with IDEs, CI systems, and defect trackers
- **Human-readable:** HTML report with interactive Knowledge Graph visualization (using D3.js force-directed layout), filterable finding table, attack path diagrams, and remediation guidance
- **Executive summary:** PDF with top-line metrics, trend charts (if previous scan baselines exist), and LLM-generated plain-language attack narratives for the top 5 critical chains

---

## 11. Audit Log — Detailed Design

**Structure:** Each log entry contains: monotonic sequence number, SHA3-256 hash of the previous entry (forming the hash chain), timestamp, event type (enum: ScanStarted, ModuleStarted, FindingRecorded, ScanCompleted, KeyEvent, ConfigChange), event payload (CBOR-serialized), and HMAC-SHA3-256 of the entire entry using a key derived from the TPM-sealed master key.

**Tamper evidence:** To forge or delete an entry, an attacker would need to recompute the hash chain from the modification point forward AND recompute the HMAC for every affected entry. The HMAC key is TPM-sealed and never exposed to any process except the supervisor's log-writing thread.

**Verification:** An independent verifier tool walks the log, checks that each entry's hash chain link is correct and each HMAC is valid. If any entry has been tampered with, the chain breaks at that point.

---

## 12. Build, Test & Deployment

### 12.1 Build System

**Nix flakes** for fully reproducible builds. Every dependency (Rust toolchain, LLVM, Python, model weights, vulnerability databases) is pinned by content hash. Building AEGIS on any machine with Nix installed produces a bit-for-bit identical binary. This eliminates "works on my machine" issues and enables independent verification of the build.

### 12.2 Testing

- **Confinement tests:** A test harness runs AEGIS in a VM with network monitoring on all interfaces. Verifies that zero packets escape to non-loopback interfaces across 10,000 fuzzing iterations.
- **Detection accuracy tests:** AEGIS is run against OWASP WebGoat, DVWA, Juice Shop, and a custom vulnerable application containing 100 known vulnerabilities across all classes. Measure recall (must be >95%) and precision (target >70%).
- **Performance benchmarks:** Measure end-to-end scan time on reference applications of 10K, 100K, and 500K LOC. Target: under 2 hours for 100K LOC on a machine with 32GB RAM and an RTX 4090.
- **Determinism test:** Run the same scan twice with the same seeds. Diff the outputs. Must be identical.

### 12.3 Deployment

Single command: `nix run .#aegis -- init` performs the Target Ceremony. `nix run .#aegis -- scan` executes the pipeline. All state is local. No cloud dependencies. No telemetry. No phone-home. The binary is fully self-contained.

**Minimum hardware:** 16GB RAM, 4-core CPU, 50GB disk. No GPU required (falls back to CPU inference).

**Recommended hardware:** 64GB RAM, 16-core CPU, NVIDIA GPU with 24GB VRAM, NVMe SSD. Full pipeline including generative fuzzing completes 5-10x faster.

---

## 13. Technology Stack Summary

| Component                  | Language                 | Key Libraries / Tools                                           |
| -------------------------- | ------------------------ | --------------------------------------------------------------- |
| Supervisor / Orchestrator  | Rust                     | tokio, tss-esapi, aya (eBPF), cap'n'proto-rust                  |
| Knowledge Graph Engine     | Rust                     | custom arena allocator, petgraph (algorithms), cap'n'proto-rust |
| Kernel Packet Filter       | C (eBPF) + Rust (loader) | aya, Clang/LLVM eBPF backend                                    |
| Behavioral Watchdog        | Rust                     | libc, mlockall, raw sockets                                     |
| Passive Recon              | Rust                     | httparse, h2, tungstenite, custom protocol parsers              |
| Attack Surface Enumeration | Rust                     | reqwest, headless-chrome (CDP), custom crawl engine             |
| Generative Fuzzing Engine  | Rust                     | custom scheduler, custom executor, custom oracle                |
| LLM Inference              | Python                   | vLLM or llama-cpp-python, PyTorch, transformers                 |
| Taint Analysis             | C++                      | LLVM 18, Clang, custom abstract domain lib, RocksDB             |
| Attack Chain Synthesis     | Rust                     | petgraph, custom Dijkstra/Tarjan/BFS, HiGHS (MIP solver)        |
| LLM Hypothesis Engine      | Python                   | transformers, sentence-transformers, FAISS                      |
| Report Generator           | Rust                     | serde, askama (templates), CBOR serialization, libharu (PDF)    |
| Audit Log                  | Rust                     | SHA3 (tiny-keccak), HMAC, append-only file I/O                  |
| Build System               | Nix                      | Nix flakes for reproducible builds                              |
| Test Targets               | Various                  | OWASP WebGoat, DVWA, Juice Shop                                 |

---

This is the complete low-level design. Every component has a defined language, defined data structures, defined algorithms, defined IPC mechanism, defined performance targets, and defined technology choices. A team of five engineers could begin implementation tomorrow with no architectural ambiguity.
