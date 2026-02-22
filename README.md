# AEGIS - Adversarial Vulnerability Discovery Framework

An automated security scanner for web applications. AEGIS systematically discovers vulnerabilities by sending crafted malicious inputs to your app's endpoints, using controlled experiment testing to eliminate false positives, and generating detailed reports with provenance-tracked confidence scores.

**11 Rust crates + 1 Python package. 2,917 Rust tests, 511 Python tests.**

> **Safety:** AEGIS only targets `localhost` by default. Remote targets require a cryptographically signed scope attestation (see [Remote Scanning](#remote-scanning-scope-attestation)).

---

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture Overview](#architecture-overview)
- [The Scan Pipeline](#the-scan-pipeline)
- [Features In Depth](#features-in-depth)
  - [Knowledge Graph](#1-knowledge-graph)
  - [Passive Recon](#2-passive-recon)
  - [Crawler](#3-crawler)
  - [Fingerprinting / Enumeration](#4-fingerprinting--enumeration)
  - [Fuzzing Engine](#5-fuzzing-engine)
  - [Vulnerability Confirmation](#6-vulnerability-confirmation)
  - [DOM Verification](#7-dom-verification)
  - [Chain Synthesis](#8-chain-synthesis)
  - [Reporting](#9-reporting)
  - [Evasion Engine](#10-evasion-engine)
  - [Audit Log](#11-audit-log)
  - [Distributed Scanning](#12-distributed-scanning)
  - [LLM Hypothesis Engine](#13-llm-hypothesis-engine-python)
  - [Checkpoints and Resume](#14-checkpoints--resume)
  - [Benchmarking and Ground Truth](#15-benchmarking--ground-truth)
- [Remote Scanning (Scope Attestation)](#remote-scanning-scope-attestation)
- [Testing](#testing)
- [Commands](#commands)
- [Project Structure](#project-structure)
- [Key Dependencies](#key-dependencies)

---

## Quick Start

```bash
# Quick scan (no LLM, 1 iteration)
cargo run -p aegis-orchestrator -- --target http://localhost:3000 --preset quick

# Thorough scan with LLM hypothesis generation (3 iterations, convergence detection)
cargo run -p aegis-orchestrator -- --target http://localhost:3000 --preset thorough --graph-db scan.json

# Paranoid stealth scan (5 iterations, evasion mode)
cargo run -p aegis-orchestrator -- --target http://localhost:3000 --preset paranoid --graph-db scan.json

# Without presets (full control)
cargo run -p aegis-orchestrator -- --target http://localhost:3000 --graph-db scan.json --no-llm

# Scan a remote target you own (requires attestation)
cargo run -p aegis-orchestrator -- \
  --target http://your-server:3000 \
  --graph-db scan.json \
  --scope-attestation scope-attestation.json
```

---

## Architecture Overview

```
                    CLI (clap)
                        |
                   orchestrator
                   /    |    \
           pipeline   config  audit-log
           /  |  \              |
     recon crawl fingerprint  supervisor
              |
         fuzz <-> analyze (iterative loop)
              |
        knowledge-graph  <-- shared by all phases
              |
         dom_verify (headless Chrome)
              |
           report -> SARIF / Executive / Security
              |
     hypothesis-engine (Python, via Unix socket IPC)
```

All pipeline phases share a central **knowledge graph** -- a thread-safe, in-memory graph database. Each phase reads context from previous phases and writes its discoveries back. Every action is recorded in a tamper-evident **audit log**.

---

## The Scan Pipeline

AEGIS runs a multi-phase pipeline where each phase feeds into the next:

```
recon -> crawl -> fingerprint -> (fuzz -> analyze)* -> dom_verify -> report
```

1. **Recon** -- scans your project's dependency files for known vulnerable libraries (no network requests)
2. **Crawl** -- visits pages and follows links to discover endpoints
3. **Fingerprint** -- maps your API surface (OpenAPI, GraphQL, auth matrix) and detects defenses (WAFs, rate limiters)
4. **Fuzz -> Analyze** -- sends malicious payloads and uses counterfactual testing to confirm vulnerabilities. Repeats iteratively until convergence.
5. **DOM Verify** -- uses headless Chrome to confirm browser-based vulnerabilities (XSS)
6. **Report** -- generates SARIF, security, or executive reports with risk scoring

The fuzz/analyze loop supports `--max-iterations` (default 1) and `--convergence-threshold` (default 2, consecutive rounds with zero new findings before stopping).

---

## Features In Depth

### 1. Knowledge Graph

The backbone of AEGIS. All phases read from and write to this shared graph.

**What it stores:**

```
[Endpoint: /api/search]  --HasParameter-->  [Parameter: q]
        |                                        |
   ProtectedBy                              VulnerableTo
        |                                        |
[Defense: ModSecurity WAF]              [Finding: SQL Injection, severity 8.5]
```

**9 node types:** Endpoint, Parameter, DataStore, Function, Defense, Finding, Dependency, Service, EntryPoint

**8 edge types:** HasParameter, Calls, ReadsFrom, WritesTo, ProtectedBy, DependsOn, ExposesTo, VulnerableTo

28 valid (source, edge, target) combinations are enforced -- nonsensical edges like `DataStore --Calls--> Function` are rejected at insertion time.

**Implementation:** Arena-style `Vec` storage with `u64` indices for O(1) lookup. Thread-safe via `parking_lot::RwLock` with upgradable read locks for atomic validate-then-apply (no TOCTOU gaps).

---

### 2. Passive Recon

Scans dependency lock files for known vulnerable libraries. **No network requests** -- purely file analysis.

**Supported formats:** `Cargo.lock`, `package-lock.json`, `Gemfile.lock`, `poetry.lock`

**How it works:**
1. Filesystem walker recursively finds lock files
2. Dependency parser extracts (package, version) tuples
3. SQLite in-memory vulnerability database checks for known CVEs
4. Outputs `AddNode` (Dependency) and `AddFinding` operations to the graph

---

### 3. Crawler

BFS (breadth-first search) web crawler that discovers endpoints by following links.

- Starts at the target URL seed
- Extracts links from HTML (`<a href>`, `<form action>`) and JavaScript (`fetch()`, `XMLHttpRequest`)
- Respects depth limits and same-origin policy
- Outputs discovered endpoints as graph operations

---

### 4. Fingerprinting / Enumeration

Maps your app's API surface in detail.

#### OpenAPI Discovery
Parses Swagger/OpenAPI specs to extract every endpoint, method, and parameter automatically.

#### GraphQL Introspection
Sends introspection queries to discover the full schema. When introspection is disabled:
- **Error-based discovery** -- sends malformed queries and parses leaked field names from error messages
- **Common field brute-force** -- tries 21 query fields and 13 mutation fields

#### Auth Matrix Analysis
Sends requests at different privilege levels (none, low, admin) to map authentication requirements per endpoint. Flags anomalies like admin-only endpoints returning 200 to unauthenticated requests.

#### Auth Flow Modeling
Models multi-step login flows with template-based request rendering (`{{variable}}` interpolation). Detects session fixation, weak session IDs, and insecure cookies.

---

### 5. Fuzzing Engine

The core attack system. Sends malicious inputs to endpoints and observes what happens.

#### Priority Scheduler
A binary heap of fuzz targets, each with:
- Target endpoint, method, parameter
- Vulnerability class to test
- Priority score (influenced by severity, UCB1 bandit scores, similar endpoint results)

#### Payload Mutator
Generates payloads tagged with their origin:

| Origin | Description | Example |
|---|---|---|
| Template | Predefined attack patterns | `' OR 1=1--`, `<script>alert(1)</script>` |
| Generative | LLM-generated hypotheses | Context-specific payloads |
| BitFlip | Random mutations of working payloads | Variations of confirmed attacks |
| Boundary | Edge-case values | Empty strings, very long strings, null bytes |
| BypassCorpus | Known WAF bypass techniques | Encoding tricks, alternate syntax |

#### Counterfactual Oracle (Anomaly Detection)

The key innovation for reducing false positives:

```
1. Send: GET /api/search?q=' OR 1=1--     (treatment -- attack payload)
2. Send: GET /api/search?q=normal_search   (control -- benign input)
3. Compare responses
```

**Anomaly types detected:**
- **StatusCodeAnomaly** -- treatment returns 500, control returns 200
- **TimingAnomaly** -- treatment takes 5 seconds, control takes 50ms
- **ReflectionDetected** -- attack payload appears in response body
- **BodySizeAnomaly** -- dramatically different response size
- **HeaderAnomaly** -- unexpected header differences

**Why counterfactual matters:** If BOTH treatment and control return 500, the endpoint is simply broken (a "flaky endpoint"), not vulnerable. This eliminates false positives. Exception: ReflectionDetected is always preserved because reflecting user input is inherently dangerous.

#### UCB1 Payload Selector
Multi-armed bandit algorithm for adaptive payload selection:

```
score = success_rate + C * sqrt(ln(total_pulls) / this_payload_pulls)
```

- First term: exploit historically effective payloads
- Second term: explore untried payloads (bonus for rarely-tested ones)
- Novel payloads get `INFINITY` score -- always tried first

#### Defense Detection
Before fuzzing, AEGIS detects:
- **WAFs** -- identifies vendor (ModSecurity, Cloudflare, etc.) and adjusts payloads
- **Rate limits** -- measures threshold and throttles accordingly
- **Bot detection** -- probes with varying "humanness" levels

#### Streaming Fuzzer
Protocol-aware fuzzing for **WebSocket** and **Server-Sent Events** connections -- understands message framing, not just HTTP request/response.

---

### 6. Vulnerability Confirmation

After the fuzzer flags potential vulnerabilities, class-specific confirmation functions verify them:

| Class | Confirmation Method |
|---|---|
| SQL Injection | Tautology (`' OR 1=1--`) vs contradiction (`' AND 1=0--`). More data from tautology = confirmed. |
| XSS | Sends `<script>` tag, checks if it appears unescaped in response |
| Command Injection | Sends `; echo UNIQUE_MARKER`, checks for marker in response |
| Path Traversal | Sends `../../etc/passwd`, checks for `root:` in response |
| SSTI | Sends `{{7*7}}`, checks if response contains `49` |

Findings get an **evidence level**: Statistical -> Counterfactual -> Confirmed -> Chained (increasing confidence).

---

### 7. DOM Verification

Some vulnerabilities (especially XSS) can only be confirmed in a real browser. A reflected `<script>` tag might be inside an HTML comment and never execute.

AEGIS uses **headless Chrome** via CDP (Chrome DevTools Protocol) to:
1. Navigate to the page with the payload
2. Intercept JavaScript execution
3. Verify the payload actually runs in the DOM

---

### 8. Chain Synthesis

Individual vulnerabilities are concerning. **Chains** of vulnerabilities are catastrophic.

```
[SQLi on /search] --leaks_data--> [Credentials in DB]
                                          |
                                   enables_access
                                          |
                                  [Admin Panel /admin]
                                          |
                                     leads_to
                                          |
                               [CmdInj on /admin/exec]
```

Built on `petgraph` DiGraph. Analysis includes:
- **Shortest paths** from entry points to high-value targets
- **Centrality analysis** to find critical nodes (appear in most attack paths)
- **Mitigation impact estimation** -- "if we fix node X, how many attack paths break?"
- **Defense gap analysis** -- finds unprotected entry points and assets
- **DOT/Graphviz export** for visual attack graph diagrams

---

### 9. Reporting

Three output formats for different audiences:

#### Developer (SARIF)
Standard JSON format that IDEs understand. VS Code, GitHub, Azure DevOps display vulnerabilities inline:
```json
{
  "ruleId": "AEGIS-SQL-001",
  "message": { "text": "SQL Injection on /api/search parameter q" },
  "level": "error",
  "vulnerabilityClass": "SqlInjection",
  "evidenceLevel": "Confirmed",
  "confidence_score": 0.92
}
```

#### Security (ATT&CK-enriched)
SARIF enriched with MITRE ATT&CK framework mappings and CWE references.

#### Executive (Summary JSON)
High-level summary: total findings by severity, top risks, recommended mitigations.

**Risk scoring** is defense-aware and confidence-weighted:
- Base severity score (0-10)
- Adjusted down if defenses are present (WAF blocking that vulnerability category)
- Weighted by confidence (a `Statistical` finding at 0.4 confidence scores lower than `Confirmed` at 0.95)

---

### 10. Evasion Engine

Real apps have defenses. AEGIS must avoid getting blocked before it can test anything.

#### 10 Browser Personas
Each mimics a real browser's full HTTP fingerprint:

| Persona | Key Characteristics |
|---|---|
| ChromeDesktop | Chrome User-Agent, Sec-Fetch headers, Chromium TLS fingerprint |
| FirefoxDesktop | Firefox User-Agent, different header order, Firefox TLS fingerprint |
| Googlebot | Googlebot User-Agent, no Sec-Fetch headers |
| CurlClient | curl User-Agent, minimal headers |
| ... | 6 more variants |

Bot detectors check header order, Sec-Fetch presence, User-Agent consistency, and TLS fingerprints. Each persona matches all of these signals.

#### TLS Fingerprinting
Every TLS client has a unique "fingerprint" (JA3 hash) from its cipher suite and extension offerings. AEGIS maps each persona to the correct JA3 hash so the TLS handshake matches the claimed User-Agent.

#### Timing Controller
Randomized delays between requests:
- **Uniform** -- equal probability of any delay in [min, max]
- **Exponential** -- skews toward shorter delays (most fast, occasional long pause)
- **Normal** -- clusters around the midpoint (mimics human browsing)

Deterministic given the same seed for reproducible scans.

#### Stealth Presets
| Preset | Behavior |
|---|---|
| `default()` | Moderate delays, Chrome persona |
| `aggressive()` | Minimal delays, fast scanning |
| `paranoid()` | Long delays, randomized personas, cover traffic |
| `benchmark()` | No delays, for performance testing |

---

### 11. Audit Log

Every action during a scan is recorded in a tamper-evident log.

**Hash chain:** Each entry includes the hash of the previous entry. Modifying any entry breaks the chain.
```
Entry 0: hash = SHA3-256(event_data_0)
Entry 1: hash = SHA3-256(entry_0.hash + event_data_1)
Entry 2: hash = SHA3-256(entry_1.hash + event_data_2)
```

**HMAC signing:** Each entry is signed with a keyed hash. Even recalculating the chain requires the secret key.

**Serialization:** CBOR (binary, ~40% smaller than JSON).

**Event sourcing:** `replay_from_entries()` reconstructs the entire scan state from the audit log alone. `diff_snapshots()` compares two scan states. Enables post-hoc forensic analysis.

Mandatory by default. `--no-audit` for explicit opt-out.

---

### 12. Distributed Scanning

For large targets, distribute work across multiple machines.

```
Coordinator (TCP server)
    |-- Worker 1 -- fuzzes endpoints A-M
    |-- Worker 2 -- fuzzes endpoints N-Z
    +-- Worker 3 -- spare / rebalancing target
```

**Wire protocol:** JSON over TCP -- Heartbeat, WorkAssignment, FindingsReport, Pause/Resume/Shutdown.

**Partitioning strategies:**
- `RoundRobin` -- endpoints distributed evenly
- `PriorityBased` -- high-priority endpoints to fastest workers
- `VulnerabilityClass` -- group by vulnerability type

**Failure handling:** Heartbeat-based detection with automatic rebalancing when workers go down.

---

### 13. LLM Hypothesis Engine (Python)

Makes fuzzing smarter by using LLMs to generate targeted attack hypotheses.

```
Scan context (endpoints, findings so far)
  -> LLM: "What vulnerabilities might exist here?"
  -> Hypotheses with reasoning traces
  -> Compiled into fuzz payloads
  -> Results fed back for next round
```

**Backends:** AWS Bedrock (Claude), OpenAI-compatible APIs, local ollama.

**Feedback loop:** Confirmed findings lead to more targeted hypotheses. Refuted hypotheses are tracked and never re-tested.

**Uncertainty quantification:** Analyzes LLM reasoning for hedging ("might", "possibly") vs confidence ("clearly", "confirms") and adjusts scores.

Communication with Rust via **Unix Domain Socket IPC** (`BridgeRequest`/`BridgeResponse` JSON messages).

---

### 14. Checkpoints & Resume

Long scans can be interrupted. Checkpoints save progress:

```rust
ScanCheckpoint {
    completed_phases: ["recon", "crawl", "fingerprint", "fuzz:0", "analyze:0"],
    current_iteration: 1,
    total_operations: 42,
    total_findings: 7,
}
```

Saved as JSON alongside the graph database. On `--resume`, completed phases are skipped. Checkpoint is deleted on successful scan completion.

```bash
# Resume an interrupted scan
cargo run -p aegis-orchestrator -- \
  --target http://localhost:3000 \
  --graph-db scan.json \
  --resume
```

---

### 15. Benchmarking & Ground Truth

AEGIS includes intentionally vulnerable web apps with documented vulnerability lists for validation.

**Defense stacks** (`defense-stacks/`):
- Express.js app -- 17 vulnerable endpoints covering all 16 vulnerability classes
- Flask app -- 8 endpoints (SQLi, XSS, CmdInj, PathTraversal, SSTI, Misconfig, OpenRedirect)
- GraphQL app -- SQLi, XSS, PathTraversal, BrokenAuth, with toggleable introspection

Each has a `ground-truth.json`:
```json
[
  {"endpoint": "/api/search?q=", "vulnerability_class": "SqlInjection"},
  {"endpoint": "/api/comments", "vulnerability_class": "CrossSiteScripting"}
]
```

AEGIS computes:
- **Precision** = true positives / (true positives + false positives) -- "of what we flagged, how much was real?"
- **Recall** = true positives / (true positives + false negatives) -- "of what existed, how much did we find?"
- **F1 score** = harmonic mean of precision and recall

Per-class metrics track which vulnerability types are detected well and which need improvement.

---

## Remote Scanning (Scope Attestation)

By default, AEGIS only targets localhost. To scan a remote target you own:

**Step 1: Generate a scope attestation**
```bash
aegis-orchestrator attest \
  --target "http://your-server:3000" \
  --authorized-by "your-name@example.com" \
  --valid-days 30 \
  --key signing.key \
  --output scope-attestation.json
```

This creates an Ed25519-signed document binding your identity, the target URL, and an expiry date. The signing key is generated automatically (stored with 0600 permissions).

**Step 2: Run the scan**
```bash
aegis-orchestrator \
  --target "http://your-server:3000" \
  --scope-attestation scope-attestation.json \
  --graph-db scan.json
```

The transport layer verifies the signature, checks the target URL matches, and confirms the attestation hasn't expired before allowing any requests.

---

## Testing

### Test Tiers

**Tier 1 -- Unit Tests (CI on every PR):**
```bash
cargo test --workspace                                                # 2,917 Rust tests
cargo clippy --workspace -- -D warnings                               # zero warnings policy
cargo fmt --all --check                                               # formatting gate
cd hypothesis-engine && uv run pytest src/hypothesis_engine/ tests/ -v  # 511 Python tests
```

**Tier 2 -- Docker Integration (CI on main):**
```bash
AEGIS_INTEGRATION_TESTS=1 cargo test -p aegis-orchestrator \
  --test docker_integration -- --test-threads=1
```
34 tests spinning up real vulnerable apps in Docker and scanning them end-to-end.

**Ground Truth Validation (manual dispatch):**
```bash
scripts/validate-ground-truth.sh
```

### What's Tested

| Area | What's Verified |
|---|---|
| Knowledge graph | CRUD operations, 28 semantic edge rules, concurrency (10 threads x 100 ops), persistence roundtrips |
| Controlled experiment oracle | Flaky endpoint filtering, reflection preservation, all anomaly types |
| Fuzzing | Scheduler priority ordering, payload mutation, UCB1 bandit convergence |
| Evasion | All 10 personas, timing distributions, TLS fingerprint mapping, localhost enforcement |
| SARIF output | Field extraction, vuln class mapping, empty result handling |
| Checkpoints | Save/load roundtrip, resume skip logic, deletion on completion |
| Benchmarks | Precision/recall/F1 computation, per-class metrics, edge cases (all miss, all match) |
| Audit log | Hash chain integrity, HMAC verification, event sourcing replay |
| Distributed | Full lifecycle, failure detection, rebalancing, wire protocol, pause/resume |
| Docker E2E | Express (8 tests), Flask (4), GraphQL (4), cross-scan (4), report formats (3), stealth (3), audit (2) |

### Test Organization

Every source file `foo.rs` has an adjacent `foo_test.rs`, included via `#[path = "foo_test.rs"]` attribute.

---

## Commands

```bash
# Full scan
aegis-orchestrator --target http://localhost:3000 --graph-db scan.json

# Recon only (no network)
aegis-orchestrator recon --source-dir ./my-project

# Generate scope attestation
aegis-orchestrator attest --target http://example.com --authorized-by you@email.com \
  --valid-days 30 --key signing.key

# Resume interrupted scan
aegis-orchestrator --target http://localhost:3000 --graph-db scan.json --resume

# Scan with stealth mode
aegis-orchestrator --target http://localhost:3000 --graph-db scan.json --stealth paranoid

# Skip LLM hypothesis generation
aegis-orchestrator --target http://localhost:3000 --graph-db scan.json --no-llm

# Disable audit logging
aegis-orchestrator --target http://localhost:3000 --graph-db scan.json --no-audit

# Verbose output
aegis-orchestrator --target http://localhost:3000 --graph-db scan.json --verbose
```

---

## Project Structure

```
crates/
  protocol/           Shared types (VulnerabilityClass, NodeType, EdgeLabel, etc.)
  knowledge-graph/    In-memory graph engine (arena storage, RwLock concurrency)
  audit-log/          SHA3-256 hash-chained, HMAC-signed audit events (CBOR)
  supervisor/         Process lifecycle + capability tokens
  passive-recon/      Lock file parsing + vulnerability database (SQLite)
  enumeration/        Route discovery, OpenAPI, GraphQL, auth matrix
  crawler/            BFS web crawler with DOM extraction
  fuzzing/            Scheduler, mutator, oracle, WAF/rate-limit/bot detection
  chain-synthesis/    Attack graph (petgraph), path analysis, DOT export
  reporting/          SARIF 2.1.0, risk scoring, narratives, CBOR certificates
  evasion-engine/     Persona rotation, TLS fingerprints, timing jitter
  orchestrator/       CLI, pipeline, distributed coordination, benchmarks

hypothesis-engine/    Python LLM hypothesis generation (Bedrock, OpenAI, ollama)

defense-stacks/       Docker fixture apps for integration testing
  express-vuln-app/   17 vulnerable endpoints
  flask-vuln-app/     8 vulnerable endpoints
  graphql-vuln-app/   GraphQL with toggleable introspection
  bot-detection/      Bot detection proxy
  modsecurity/        WAF configuration
  compose/            Docker Compose stacks + nginx configs
```

---

## Key Dependencies

| Crate | Notable Dependencies |
|---|---|
| protocol | serde, sha3, ed25519-dalek |
| knowledge-graph | parking_lot, proptest (dev) |
| audit-log | sha3, hmac, ciborium |
| fuzzing | rand, reqwest, uuid, regex |
| chain-synthesis | petgraph |
| reporting | sarif_rust, ciborium |
| evasion-engine | reqwest, rand |
| orchestrator | clap, tracing, tokio, rusqlite |
| hypothesis-engine | boto3, pydantic |

Rust edition 2024. Python >= 3.12 via `uv`.
