# AEGIS Knowledge Base Index

**Last Updated:** 2026-02-23T00:00:00Z
**Project:** AEGIS — Adversarial Vulnerability Discovery Framework
**Workspace:** `/Users/pranavgk/Documents/temp/adver`
**Documentation Root:** `claudedocs/current_state/`

---

## How to Use This Index

This file is the single entry point for the AEGIS documentation knowledge base. When answering questions about this codebase:

1. **Read this index first** — it contains enough metadata to answer many questions directly
2. **Use the Quick Reference section** to find which file to consult for specific question types
3. **Read the specific document** for detailed information
4. **Check crate_docs/{crate-name}.md** for crate-specific public APIs, module structure, and usage notes

This index is designed so that adding it to context provides sufficient metadata to locate information in any other document without reading them all.

---

## Quick Reference

| Question Type | Primary File | Secondary File |
|--------------|-------------|----------------|
| "How does the scan pipeline work?" | `workflows.md` | `architecture.md` |
| "What CLI flags are available?" | `interfaces.md` | `crate_docs/aegis-orchestrator.md` |
| "What does VulnerabilityClass X mean?" | `type_system.md` | `crate_docs/aegis-protocol.md` |
| "How do I add a new vulnerability class?" | `type_system.md` | `crate_docs/aegis-protocol.md` |
| "What external libraries are used?" | `dependencies.md` | `workspace_info.md` |
| "How does the fuzzing work?" | `crate_docs/aegis-fuzzing.md` | `workflows.md` |
| "How does the LLM integration work?" | `workflows.md` (Hypothesis Bridge section) | `interfaces.md` (Python-Rust IPC) |
| "What's the graph data model?" | `data_models.md` | `crate_docs/aegis-knowledge-graph.md` |
| "How does the audit log work?" | `crate_docs/aegis-audit-log.md` | `data_models.md` |
| "What crates depend on what?" | `workspace_info.md` | `code_analysis/dependency_graph.md` |
| "What is the module tree?" | `code_analysis/module_tree.md` | `workspace_info.md` |
| "How does checkpoint/resume work?" | `workflows.md` (Checkpoint Resume section) | `crate_docs/aegis-orchestrator.md` |
| "What are the design patterns?" | `architecture.md` | `type_system.md` |
| "How does evasion/stealth work?" | `crate_docs/aegis-evasion-engine.md` | `interfaces.md` |
| "How does authorization work?" | `architecture.md` (Security Architecture) | `interfaces.md` |
| "How does crate X work?" | `crate_docs/{crate-name}.md` | `code_analysis/module_tree.md` |
| "What does function X call?" | `code_analysis/call_traces.md` | Source file |
| "What's the SQL schema?" | `data_models.md` | `crate_docs/aegis-passive-recon.md` |
| "How are reports generated?" | `crate_docs/aegis-reporting.md` | `workflows.md` |
| "How does Python-Rust IPC work?" | `interfaces.md` (Python-Rust IPC section) | `workflows.md` |
| "What test infrastructure exists?" | `workflows.md` (Testing Strategy section) | `crate_docs/aegis-test-support.md` |

---

## Crate Quick Reference

| Crate | Purpose | Crate Doc |
|-------|---------|-----------|
| `aegis-protocol` | Shared types (NodeType, VulnerabilityClass, FuzzRequest, etc.) — foundation | `crate_docs/aegis-protocol.md` |
| `aegis-knowledge-graph` | In-memory directed graph engine, thread-safe via RwLock | `crate_docs/aegis-knowledge-graph.md` |
| `aegis-audit-log` | SHA3-256 hash-chained, HMAC-signed audit log (CBOR) | `crate_docs/aegis-audit-log.md` |
| `aegis-supervisor` | Process lifecycle + capability token management | `crate_docs/aegis-supervisor.md` |
| `aegis-passive-recon` | Lock file parsing + OSV vuln DB (SQLite) | `crate_docs/aegis-passive-recon.md` |
| `aegis-enumeration` | Route discovery (OpenAPI, GraphQL, source parsing) | `crate_docs/aegis-enumeration.md` |
| `aegis-fuzzing` | Fuzzing engine: scheduler, mutators, oracle, defense detection | `crate_docs/aegis-fuzzing.md` |
| `aegis-chain-synthesis` | Attack graph (petgraph), path analysis, mitigation estimation | `crate_docs/aegis-chain-synthesis.md` |
| `aegis-reporting` | SARIF generation, risk scoring, CBOR certificates | `crate_docs/aegis-reporting.md` |
| `aegis-evasion-engine` | Persona-based HTTP transport, TLS fingerprints, timing jitter | `crate_docs/aegis-evasion-engine.md` |
| `aegis-orchestrator` | CLI binary, scan pipeline orchestration, all integration | `crate_docs/aegis-orchestrator.md` |
| `aegis-crawler` | Headless Chrome (chromiumoxide) web crawling | `crate_docs/aegis-crawler.md` |
| `aegis-compliance` | CVSS scoring, OWASP/PCI-DSS mapping (dev-only) | `crate_docs/aegis-compliance.md` |
| `aegis-discovery` | Directory brute-forcing, JS endpoint extraction (dev-only) | `crate_docs/aegis-discovery.md` |
| `aegis-exploiter` | Tool wrappers: SQLMap, Nuclei, Nmap, JWT tester (dev-only) | `crate_docs/aegis-exploiter.md` |
| `aegis-proxy` | HTTP recording proxy, 4-mode intruder (standalone) | `crate_docs/aegis-proxy.md` |
| `aegis-test-support` | Test utilities: MockGraphStore, TestServer, VulnerableApp | `crate_docs/aegis-test-support.md` |
| `hypothesis-engine` | Python LLM hypothesis generation (Bedrock/OpenAI/ollama) | `interfaces.md` (Python-Rust IPC) |

---

## Document Summaries

### workspace_info.md
**When to read:** Need overview of project structure, crate listing, binary entry points, or high-level dependency relationships.
**Contents:** Project metadata (edition 2024, MIT, version 0.1.0), all 17 crate descriptions, binary entry points, internal dependency graph, layered architecture view, test counts (4,073 Rust + 511 Python + 34 Docker Tier 2), Python component overview.

### architecture.md
**When to read:** Understanding system design, adding new features that touch multiple crates, refactoring decisions, security model.
**Contents:** High-level architecture diagram, 5 core architectural decisions (knowledge graph as shared state, trait-based boundaries, protocol crate as contract layer, atomic validate-then-apply, localhost enforcement). Design patterns (Builder, Repository, Command, Strategy, Facade, Event Sourcing). Concurrency model (Tokio single-threaded async pipeline, OS threads for blocking work). Pipeline data flow table. Security architecture (defense-in-depth layers). Python-Rust integration diagram. Attack graph and fuzzing architecture.

### type_system.md
**When to read:** Working with protocol types, adding new VulnerabilityClass/NodeType/EdgeLabel variants, understanding confidence/evidence models, implementing trait bounds.
**Contents:** All VulnerabilityClass variants (34), NodeType (9), EdgeLabel (8), EvidenceLevel (4), GraphOperation (4), ModuleIdentifier (7). Core structs (NodeData, EdgeData, FindingData, FuzzRequest, FuzzResponse, OperationLogEntry). Newtype patterns (Confidence, FindingId). FindingConfidence provenance model. All public traits (GraphStore, AuditWriter) with full method signatures. Design patterns. Concurrency model. Error types table. Edge validation whitelist (28 valid triples).

### interfaces.md
**When to read:** Integrating with CLI, understanding IPC protocol, storage schemas, security interfaces.
**Contents:** Full CLI argument reference (all flags, types, defaults, help headings). ScanPreset values table. Python-Rust IPC protocol (BridgeRequest/BridgeResponse JSON format with examples). Scan event bus (ScanEvent variants). Security interfaces (ScopeDocument, SignedConfig JSON schemas). Storage schemas (vuln DB, scan history, graph DB). BusinessContext config file format. AuthFlow config format. Proxy interface.

### data_models.md
**When to read:** Querying the knowledge graph, understanding persistence formats, working with findings or certificates.
**Contents:** Knowledge graph data model (node/edge/finding schemas with common properties). Graph persistence JSON format. Audit log binary format (8+32+4+N+32 bytes per entry). Certificate format (6 CertificateType variants). SARIF output format with property extensions. IPC data structures (ScanContextIpc, HypothesisIpc). Python Pydantic models. Vulnerability database SQLite schema. ScanCheckpoint JSON format. BusinessContext JSON format.

### workflows.md
**When to read:** Understanding execution flow, debugging scan behavior, implementing new phases.
**Contents:** Startup sequence (numbered steps 1-23). Main scan pipeline with phase sequence table. Detailed run_scan_phases execution order (7 phases with sub-steps). Iterative fuzz-analyze loop mechanics. Checkpoint resume flow. Interactive mode commands and state machine. Hypothesis bridge lifecycle (Python subprocess). Subcommand workflows (recon, attest, update-db). Capability/permission system. Testing strategy (Rust #[path] convention, Docker Tier 2, Python tests). Concurrent operations pattern. Error propagation paths.

### dependencies.md
**When to read:** Adding new dependencies, understanding why a dependency was chosen, auditing third-party libs.
**Contents:** Workspace-level dependency table. All external dependencies categorized (async runtime, serialization, HTTP/networking, database, CLI, logging, cryptography, graph, domain-specific parsers, utilities, testing). Notable dependency choices with rationale. Note on no feature flags in this workspace.

### code_analysis/dependency_graph.md
**When to read:** Understanding which crates depend on which, planning cross-crate changes, assessing blast radius of API changes.
**Contents:** Full directed dependency graph (ASCII), layered architecture view, per-crate coupling table, key structural observations (no cycles, protocol as choke point, proxy as isolated, compliance/discovery/exploiter dev-only).

### code_analysis/module_tree.md
**When to read:** Finding where a specific type or function is defined, understanding module visibility.
**Contents:** Full module hierarchy for all 17 crates with public/private visibility annotations, key exported types per module.

### code_analysis/call_traces.md
**When to read:** Understanding execution flow through specific operations, debugging call stack questions.
**Contents:** 7 detailed call traces: full scan execution, fuzz phase, knowledge graph apply_operations, LLM hypothesis IPC, audit log write, SARIF report generation, scan resume from checkpoint. Each trace shows function names and file locations.

---

## Critical Pitfalls (Common Mistakes)

> These are pitfalls that tripped up contributors — read before modifying the codebase.

1. **Adding NodeType/EdgeLabel variants** → Must update `EDGE_WHITELIST` in `edge.rs` AND exhaustive coverage test in `protocol_test.rs`
2. **FindingData.confidence is `FindingConfidence` not `f64`** → Access via `.confidence.composite.value()`
3. **EvidenceLevel::Controlled** has `#[serde(alias = "Counterfactual")]` — don't remove this
4. **Defense-fingerprinting merged into fuzzing** → `use aegis_fuzzing::DefenseProfile` not a separate crate
5. **compliance/discovery/exploiter are dev-only** — not compiled into the production binary
6. **Crawler not wired** — `run_crawl_phase()` uses `CrawlResult::default()` (empty)
7. **reqwest::blocking cannot run inside tokio runtime** — wrap in `std::thread::spawn()`
8. **FuzzScheduler::enqueue() clamps NaN/Inf to 0.0** — don't assume priority_score is exact
9. **KnowledgeGraph::load_from_file()** — operation log is NOT restored (starts fresh)
10. **`--resume` requires `--graph-db`** — without graph-db, resumes as fresh scan with a warning
11. **Chrome120 and Edge120 JA3 hashes are identical** — both Chromium-based
12. **Python: `parse_hypotheses_from_response()`** returns 3-tuple `(str, list, str)` since last update
13. **VulnerabilityClass has 34 variants** — CLAUDE.md says "16 original + 18" but be aware of the total
14. **LLM IPC uses Unix domain socket** — `/tmp/aegis-hypothesis-{pid}-{timestamp}.sock` with 4-byte LE u32 length-prefixed frames (NOT stdin/stdout despite some misleading code in the file)
15. **`ProcessManager` is a pure state machine** — it does NOT call `Command::spawn()`; it only tracks process state transitions. Actual subprocess spawning must be done externally.
16. **`JwtTester::is_available()` always returns `true`** — it's the only native tool wrapper (no subprocess); unlike SQLMap/Nuclei/Nmap which require external tools.
17. **`discovered_params_to_operations()` emits `NodeType::Config`** (not `Endpoint`) for discovered parameter nodes — non-obvious type assignment in the discovery crate.
18. **`compliance_mapper` matches on `Display` strings**, not enum variants — adding a new `VulnerabilityClass` variant will silently miss compliance mappings unless the string is also added to compliance_mapper.
19. **`AttackGraph` type is self-contained** but the `aegis-chain-synthesis` crate DOES have workspace deps on `aegis-protocol` and `aegis-knowledge-graph` (for construction helpers). Multiple analysis tools incorrectly report "zero workspace deps".

---

## Architecture Summary (for quick context)

AEGIS is a **sequential async pipeline** around a **central in-memory knowledge graph**:

```
CLI (clap) → ScanConfig → run_scan()
  ↓
┌── graph: KnowledgeGraph (Arc<RwLock>) ──────────────────────────────┐
│                                                                      │
│  recon → crawl → fingerprint → (fuzz → LLM → analyze)* → report    │
│                                                                      │
│  Each phase: read graph → compute → write OperationLogEntry[] →     │
│              graph.apply_operations() (atomic validate-then-apply)  │
└──────────────────────────────────────────────────────────────────────┘
  ↓
SARIF report + audit log (CBOR, hash-chained)
```

**The 3 key constraints that shape everything:**
1. All mutations go through `apply_operations()` — batch atomic, all-or-nothing
2. Target must be localhost (3 enforcement layers) unless explicitly authorized
3. Audit logging is mandatory by default (hash-chained CBOR file)

**Codebase Scale (verified):**
- 17 Rust crates, 149 modules, 750+ public items
- 1 Python package (hypothesis-engine)
- Orchestrator alone: 30+ modules, 150+ public items

---

## Python hypothesis-engine Summary

```
hypothesis-engine/
├── src/hypothesis_engine/
│   ├── generator.py    LlmBackend ABC, generate_with_consistency(), confidence rubric
│   ├── compiler.py     HypothesisCompiler, XML-structured prompts
│   ├── evasion_mode.py EvasionHypothesisGenerator, bypass corpus
│   ├── feedback.py     FeedbackManager, per-class confirmation thresholds
│   ├── calibration.py  CalibrationReport, ECE, temperature scaling
│   ├── uncertainty.py  structural vs speculative evidence patterns
│   ├── bridge.py       subprocess entry point, BridgeRequest/BridgeResponse handler
│   ├── ipc_types.py    Pydantic models matching Rust IPC types
│   ├── bedrock_client.py AWS Bedrock (global.anthropic.claude-sonnet-4-6)
│   └── openai_client.py OpenAI-compatible (also ollama/vLLM)
└── tests/              Golden fixtures, prompt regression, LLM delta tests
```

---

*This knowledge base was generated on 2026-02-23. To update after significant changes, re-run the documentation generation with `update_mode=true`.*
