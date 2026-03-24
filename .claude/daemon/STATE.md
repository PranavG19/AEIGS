# DAEMON STATE — v3 RESET

## current
priority: PHASE 2 — THE BRAIN (Autonomous LLM Agent)
task: P2b — Tool-use interface (LLM can invoke AEGIS capabilities)
status: NOT STARTED

## g1-roi-ranking (P2b — NEXT)
Option 1: Tool-use interface (P2b)
  - offensive_power: 9, uniqueness: 9, intelligence: 10, cost: 6
  - ROI = (9 × 9 × 10) / 6 = 135.0
Option 2: Memory/knowledge store (P2c)
  - offensive_power: 7, uniqueness: 7, intelligence: 8, cost: 5
  - ROI = (7 × 7 × 8) / 5 = 78.4
Option 3: Mission prompt engineering (P2d)
  - offensive_power: 6, uniqueness: 6, intelligence: 9, cost: 8
  - ROI = (6 × 6 × 9) / 8 = 40.5
WINNER: P2b — Tool-use interface (ROI 135.0)

## phase-status
- PHASE 1 (Ghost Protocol): ✅ PARTIAL (P1a+P1b done, P1c-f deferred — need headless browser)
  - P1a HTTP/2 fingerprint engine: ✅ COMPLETE (28 tests)
  - P1b TLS ClientHello synthesis: ✅ COMPLETE (43 tests)
  - P1c-f: DEFERRED (header ordering exists, Navigator/Canvas/Behavioral need headless)
- PHASE 2 (The Brain): IN PROGRESS
  - P2a Agent loop architecture: ✅ COMPLETE (28 tests)
  - P2b Tool-use interface: NOT STARTED
  - P2c Memory/knowledge store: NOT STARTED
  - P2d Mission prompt engineering: NOT STARTED
  - P2e Multi-model orchestration: NOT STARTED
- PHASE 3 (The Swarm): NOT STARTED
- PHASE 4 (The Arsenal): NOT STARTED
- PHASE 5 (Nerve Center): NOT STARTED
- PHASE ∞ (ROI Loop): WAITING

## test-baseline
- cargo test -p aegis-evasion-engine: 310 lib + 25 integration, 0 failed
- cargo test -p aegis-orchestrator (agent_loop only): 28 passed, 0 failed
- cargo clippy -p aegis-orchestrator: 0 warnings
- total workspace: ~4485+ tests (from prior daemon run)

## preserved-from-v2
- 293 recon scanners shipped
- 10 browser personas in evasion-engine
- JA3/JA3S TLS fingerprint matching (6 profiles)
- UCB1 bandit payload scheduler in fuzzing crate
- Hypothesis engine (Python) with Bedrock/OpenAI/Ollama backends
- Tool wrappers: SQLMap, Nuclei, Nmap, Subfinder, Interactsh, Httpx, Gau, Feroxbuster, Trufflehog, Dalfox, Amass
- Knowledge graph with arena storage + RwLock
- Attack graph via petgraph DiGraph
- SARIF 2.1.0 reporting with CWE+ATT&CK mapping
- Defense-stacks Docker fixtures (Express/Flask/GraphQL)

## known-issues
- eval.rs: dead code (broken benchmark imports)
- defense-fingerprinting dir on disk but excluded from workspace (merged into fuzzing)

## shipped-this-session
### P1a — HTTP/2 Fingerprint Engine (evasion-engine)
- 7 browser HTTP/2 fingerprint profiles
- SETTINGS frame values + ordering, WINDOW_UPDATE sizes, PRIORITY frames, pseudo-header ordering
- Akamai fingerprint format serialization
- Client identification via weighted scoring
- 28 tests

### P1b — TLS ClientHello Full Synthesis (evasion-engine)
- 7 full TLS ClientHello profiles (Chrome 120/125, Firefox 121/125, Safari 17, Edge 120, curl)
- Complete cipher suite ordering, extension ordering, supported groups, signature algorithms
- JA3 string + hash computation (custom MD5, zero deps)
- JA4 fingerprint computation
- Profile validation + cipher-order identification
- 43 tests

### P2a — Agent Loop Architecture (orchestrator)
- OHPEL cycle: Observe → Hypothesize → Plan → Execute → Learn
- AgentObservation: full scan state snapshot (endpoints, findings, defenses, failed attempts)
- AgentAction: 9 action types (FuzzEndpoint, ExploitFinding, DiscoverEndpoints, ChainFindings, AuthenticateFirst, EvadeDefense, DeepAnalyze, GenerateReport, Pause)
- AgentMemory: technique records, WAF bypass patterns, endpoint behaviors, iteration summaries
- Memory analytics: success_rate_for_class(), bypasses_for_defense(), is_stuck(), most_productive_iteration()
- Convergence detection: stuck detection, max iterations, terminal states
- LLM prompt builder: XML-structured hypothesis prompt with scan context + memory
- Fallback plan builder: rule-based planning when no LLM available
- 28 tests

## handoff
PHASE 2 CONTINUE — THE BRAIN
Next task: P2b — Tool-use interface

Build the bidirectional LLM ↔ AEGIS integration:
- Define tool schemas that the LLM can invoke (map to AgentAction variants)
- Request/response serialization for LLM tool calls
- Tool execution dispatcher: routes LLM tool invocations to the correct AEGIS module
- Result formatting: converts AEGIS results back to LLM-digestible context
- Wire to existing hypothesis_bridge.rs for Python LLM backend communication

Location: crates/orchestrator/src/
- agent_tools.rs (tool definitions + dispatcher)
- agent_tools_test.rs (tests)

Wire into: agent_loop.rs (the Execute phase calls the tool dispatcher)
