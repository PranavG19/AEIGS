# DAEMON STATE — v3 RESET

## current
priority: PHASE 1 — GHOST PROTOCOL (Browser Identity Synthesis)
task: P1c — Header ordering engine
status: NOT STARTED

## g1-roi-ranking (P1c — NEXT)
Option 1: Header ordering engine (P1c)
  - offensive_power: 6, uniqueness: 5, intelligence: 4, cost: 9
  - ROI = (6 × 5 × 4) / 9 = 13.3
Option 2: Navigator property synthesis (P1d)
  - offensive_power: 5, uniqueness: 6, intelligence: 3, cost: 7
  - ROI = (5 × 6 × 3) / 7 = 12.9
Option 3: Canvas/WebGL/Audio fingerprint (P1e)
  - offensive_power: 4, uniqueness: 5, intelligence: 2, cost: 4
  - ROI = (4 × 5 × 2) / 4 = 10.0
WINNER: P1c — Header ordering engine (ROI 13.3)

## phase-status
- PHASE 1 (Ghost Protocol): IN PROGRESS
  - P1a HTTP/2 fingerprint engine: ✅ COMPLETE (28 tests)
  - P1b TLS ClientHello synthesis: ✅ COMPLETE (43 tests)
  - P1c Header ordering engine: NOT STARTED
  - P1d Navigator properties: NOT STARTED
  - P1e Canvas/WebGL/Audio: NOT STARTED
  - P1f Behavioral layer: NOT STARTED
- PHASE 2 (The Brain): NOT STARTED
- PHASE 3 (The Swarm): NOT STARTED
- PHASE 4 (The Arsenal): NOT STARTED
- PHASE 5 (Nerve Center): NOT STARTED
- PHASE ∞ (ROI Loop): WAITING

## test-baseline
- cargo test -p aegis-evasion-engine: 310 lib + 25 integration, 0 failed
- cargo clippy -p aegis-evasion-engine: 0 warnings
- total workspace: ~4485+ tests (from prior daemon run)

## preserved-from-v2
- 293 recon scanners shipped (audit modules, header checks, API surface scanners)
- 10 browser personas in evasion-engine (Chrome/Firefox/Safari/Edge/Googlebot/etc)
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
### P1a — HTTP/2 Fingerprint Engine
Files:
- crates/evasion-engine/src/http2_fingerprint.rs (new, ~600 lines)
- crates/evasion-engine/src/http2_fingerprint_test.rs (new, 28 tests)
- crates/evasion-engine/src/lib.rs (wired module)
- crates/evasion-engine/src/transport.rs (integrated h2_fingerprint field)

Capabilities:
- 7 browser HTTP/2 fingerprint profiles: Chrome 120-125, Firefox 120-125, Safari 17+, Edge 120-125, curl, Go net/http, Python httpx
- SETTINGS frame values + ordering, WINDOW_UPDATE sizes, PRIORITY frames, pseudo-header ordering
- Akamai fingerprint format serialization
- Client identification via weighted scoring (40% settings, 20% WINDOW_UPDATE, 15% order, 15% pseudo-headers, 10% priority)
- Persona-to-H2-fingerprint mapping for all 10 personas
- Transport layer integration

### P1b — TLS ClientHello Full Synthesis
Files:
- crates/evasion-engine/src/tls_clienthello.rs (new, ~820 lines)
- crates/evasion-engine/src/tls_clienthello_test.rs (new, 43 tests)
- crates/evasion-engine/src/lib.rs (wired module)

Capabilities:
- 7 full TLS ClientHello profiles: Chrome 120, Chrome 125, Firefox 121, Firefox 125, Safari 17, Edge 120, curl
- Complete cipher suite ordering per browser (15 ciphers each, order-sensitive)
- Extension ordering per browser (10-16 extensions each, distinct ordering)
- Supported groups: Chrome has X25519_Kyber768 (post-quantum), Firefox has FFDHE groups, Safari has no PQ
- Signature algorithms per browser (8-11 each)
- ALPN protocol ordering
- PSK key exchange modes
- Key share groups (subset validation against supported_groups)
- Compressed certificate support (Chrome only, brotli)
- Delegated credentials + post-handshake auth (Firefox only)
- Record size limit (Firefox only, 16385)
- Encrypt-then-MAC (Safari only)
- JA3 string + hash computation (custom MD5 implementation, zero dependencies)
- JA4 fingerprint computation (simplified format)
- Cipher-order-based client identification
- Profile validation (internal consistency checks)
- TlsFingerprint → ClientHello mapping
- Persona → ClientHello mapping

## handoff
PHASE 1 CONTINUE — GHOST PROTOCOL
Next task: P1c — Header ordering engine

Build browser-specific HTTP header ordering:
- Chrome sends: Host, Connection, Upgrade-Insecure-Requests, User-Agent, Accept, ...
- Firefox sends: Host, User-Agent, Accept, Accept-Language, Accept-Encoding, ...
- Safari sends: yet different order
- The existing header_transformer.rs has persona-based ordering but it's basic
- Enhance to use precise per-version header orderings captured from real traffic
- Integrate with the existing Persona struct (header_order field already exists)

Location: Enhance existing crates/evasion-engine/src/header_transformer.rs
Add data to: crates/evasion-engine/data/default_personas.json (header_order field)
