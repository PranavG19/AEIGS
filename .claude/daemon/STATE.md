# DAEMON STATE — v3

## current
priority: ROI LOOP
task: Grammar-based generative fuzzing
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
- TOTAL NEW THIS SESSION: 189 tests

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
   - 14 mutation types: URL encode, double encode, Unicode, HTML entity, case toggle,
     comment insertion, whitespace, null byte, newline, tab, JSON wrap, XML wrap, fragment
   - Response fingerprinting: status, body hash, body length, headers, WAF detection
   - Fingerprint similarity scoring (weighted: status 3x, body 2x, content-type 1x, headers 1x)
   - WAF decision classification: Allowed/Blocked/RateLimited/Challenged/Unknown
   - Rule inference engine: case-sensitive, encoding-unaware, token-based, whitespace-strict, content-type-blind
   - Analysis summary with WAF strictness score and bypass mutation list

5. **XS-Leaks Taxonomy Engine** (ROI=88.2) — 54 tests
   - 12 leak categories: frame counting, error event, cache timing, redirect counting,
     content-type sniffing, performance API, postMessage, window properties, size-based,
     service worker, text fragment, connection pool
   - 17 concrete probes with HTML/JS payloads per category
   - 9 defense types with header detection (XFO, COOP, CORP, COEP, SameSite, Cache-Control, etc.)
   - Defense-aware viability scoring: which categories survive which defenses
   - Differential analysis engine: compare auth vs unauth observations per channel
   - Probe ranking by bypass probability given detected defenses
   - Full target analysis report with risk scoring and summary

## ROI ranking (next)
1. **Grammar-based generative fuzzing** — API grammar inference + malicious generation
   - power=8 uniqueness=8 intelligence=9 cost=7 → ROI=82.3
2. **WebSocket state machine fuzzer** — model state machine, find impossible transitions
   - power=7 uniqueness=9 intelligence=8 cost=6 → ROI=84.0
3. **Injection Engine** (P4f) — NoSQL/LDAP/SSTI/SpEL/OGNL/EL/CRLF
   - power=8 uniqueness=6 intelligence=7 cost=6 → ROI=56.0

## handoff
Next session: build grammar-based generative fuzzing engine.
Location: crates/orchestrator/src/grammar_fuzzer.rs (new file)
Module covers:
- API grammar inference from OpenAPI/GraphQL specs + observed traffic
- Production rule extraction: path templates, parameter types, value constraints
- Malicious input generation: boundary values, type confusion, constraint violations
- Context-free grammar mutation: rule expansion with attack payloads
- Grammar crossover: combine valid API patterns with injection payloads
- Coverage tracking: which grammar rules have been exercised
