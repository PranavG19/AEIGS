# DAEMON STATE — v3

## current
priority: ROI LOOP
task: WebSocket state machine fuzzer
status: NOT STARTED

## phase-status
- PHASE 1 (Ghost Protocol): PARTIAL (P1a+P1b done)
  - P1a HTTP/2 fingerprint engine: ✅ COMPLETE (28 tests)
  - P1b TLS ClientHello synthesis: ✅ COMPLETE (43 tests)
- PHASE 2 (The Brain — opencode integration): ✅ COMPLETE
  - P2a Scan context serializer: ✅ COMPLETE (18 tests)
  - P2b opencode bridge: ✅ COMPLETE (18 tests)
  - P2c Mission prompt: ✅ COMPLETE (prompts/aegis_mind.md)
  - P2d Memory store: ✅ EXISTS (agent_memory_store.rs)
  - P2e Feedback loop: ✅ COMPLETE (17 tests)
- PHASE 4 (Arsenal): NEARLY COMPLETE
  - P4a Payload Forge: ✅ COMPLETE (34 tests)
  - P4b Auth Breaker: ✅ COMPLETE (32 tests)
  - P4c Smuggling engine: ✅ COMPLETE (23 tests)
  - P4d Race engine: ✅ COMPLETE (23 tests)
  - P4e SSRF Chain: ✅ COMPLETE (28 tests)
- PHASE 3 (The Swarm): NOT STARTED
- PHASE 5 (Nerve Center): NOT STARTED
- PHASE ∞ (ROI Loop): ACTIVE

## test counts this session
- timing_oracle: 44
- auth_breaker: 32
- ssrf_chain: 28
- differential_response: 31
- xs_leaks: 54
- grammar_fuzzer: 47
- TOTAL NEW THIS SESSION: 236 tests

## completed this session
1. **Timing Oracle Detection** (ROI=126.0) — 44 tests
   - Welch's t-test, Cohen's d, Pearson correlation, outlier removal
   - 8 blind vuln types, 30+ timing payloads, 4-level verdict

2. **Authentication Breaker** (P4b, ROI=75.6) — 32 tests
   - JWT alg:none/confusion/tampering/exp/kid/jku/null-sig (50+ payloads)
   - Session entropy + sequential analysis
   - OAuth redirect_uri manipulation (9 techniques)

3. **SSRF Chain Automation** (P4e, ROI=84.0) — 28 tests
   - 7 cloud providers with metadata endpoints + required headers
   - IP bypass (12 variants) + URL scheme bypasses
   - Credential extraction (AWS/GCP/Azure)

4. **Differential Response Analysis** (ROI=126.0) — 31 tests
   - 14 mutation types, response fingerprinting, WAF rule inference

5. **XS-Leaks Taxonomy Engine** (ROI=88.2) — 54 tests
   - 12 leak categories, 17+ concrete probes with JS/HTML payloads
   - 9 defense types with header detection
   - Differential analysis, probe ranking, risk scoring

6. **Grammar-Based Generative Fuzzing** (ROI=82.3) — 47 tests
   - API grammar extraction from OpenAPI endpoints with production rules
   - 13 slot types with type-aware boundary values (15-20+ per type)
   - 9 mutation strategies: boundary, type confusion, constraint violation,
     payload injection, null injection, overflow, format string, param duplication, negative
   - Attack payload catalog: SQLi, XSS, SSTI, CMDi, NoSQL per slot type
   - Constraint violation engine: min/max length, min/max value, enum, required, nullable
   - Format string payloads: printf, EL, SpEL, OGNL, ERB, Jinja2, Twig
   - Body field injection for POST endpoints with JSON serialization
   - Generation summary with strategy/param/endpoint statistics

## ROI ranking (next)
1. **WebSocket state machine fuzzer** — model state machine, find impossible transitions
   - power=7 uniqueness=9 intelligence=8 cost=6 → ROI=84.0
2. **Injection Engine** (P4f) — NoSQL/LDAP/SSTI/SpEL/OGNL/EL/CRLF
   - power=8 uniqueness=6 intelligence=7 cost=6 → ROI=56.0
3. **DNS rebinding attack automation** — for SSRF chain escalation
   - power=7 uniqueness=8 intelligence=6 cost=5 → ROI=67.2

## handoff
Next session: build WebSocket state machine fuzzer.
Location: crates/orchestrator/src/websocket_fuzzer.rs (new file)
Module covers:
- State machine inference from observed WebSocket message sequences
- State transition graph construction (states × message types)
- Invalid transition probing: send messages that shouldn't be allowed in current state
- Message mutation: valid structure, invalid content (type confusion, injection payloads)
- Race condition detection: parallel messages that violate state ordering
- Authentication bypass: reconnect without auth, reuse old session tokens
