# DAEMON STATE — v3 RESET

## current
priority: PHASE 1 — GHOST PROTOCOL (Browser Identity Synthesis)
task: P1b — TLS ClientHello full synthesis
status: NOT STARTED

## g1-roi-ranking (P1a — COMPLETED)
Option 1: HTTP/2 fingerprint engine (P1a) ✅ SHIPPED
  - offensive_power: 9 (Akamai/Cloudflare use HTTP/2 SETTINGS fingerprinting to detect bots — this is the #1 reason automated scanners get blocked)
  - uniqueness: 10 (no open-source scanner has this; even Burp sends default h2 frames)
  - intelligence_multiplier: 7 (enables all subsequent evasion; every scan benefits)
  - cost: 8 (single file, well-scoped data structures, ~200 lines)
  - ROI = (9 × 10 × 7) / 8 = 78.75

## g1-roi-ranking (P1b — NEXT)
Option 1: TLS ClientHello full synthesis (P1b)
  - offensive_power: 8, uniqueness: 8, intelligence: 6, cost: 5
  - ROI = (8 × 8 × 6) / 5 = 76.8
Option 2: Header ordering engine (P1c)
  - offensive_power: 6, uniqueness: 5, intelligence: 4, cost: 9
  - ROI = (6 × 5 × 4) / 9 = 13.3
Option 3: Navigator property synthesis (P1d)
  - offensive_power: 5, uniqueness: 6, intelligence: 3, cost: 7
  - ROI = (5 × 6 × 3) / 7 = 12.9
WINNER: P1b — TLS ClientHello full synthesis (ROI 76.8)

## phase-status
- PHASE 1 (Ghost Protocol): IN PROGRESS
  - P1a HTTP/2 fingerprint engine: ✅ COMPLETE
  - P1b TLS ClientHello synthesis: NOT STARTED
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
- cargo test -p aegis-evasion-engine: 267 lib + 25 integration, 0 failed
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
- SETTINGS frame values + ordering per browser (HeaderTableSize, EnablePush, MaxConcurrentStreams, InitialWindowSize, MaxFrameSize, MaxHeaderListSize)
- WINDOW_UPDATE sizes unique per browser (Chrome=15663105, Firefox=12517377, Safari=10485760, curl=33488897, Go=1073741824)
- PRIORITY frame patterns per browser (Chrome: 3 frames with exclusive deps, Firefox: 5 frames with group deps, Safari: 1 frame)
- Pseudo-header ordering: Chromium m/a/s/p, Mozilla m/p/a/s, WebKit m/s/p/a
- Akamai fingerprint format serialization
- Client identification via observed parameters matching (weighted scoring: 40% settings, 20% window_update, 15% settings_order, 15% pseudo-headers, 10% priority)
- Persona-to-H2-fingerprint mapping for all 10 personas
- Transport layer integration: h2_fingerprint field auto-set on build, rotated with persona

## handoff
PHASE 1 CONTINUE — GHOST PROTOCOL
Next task: P1b — TLS ClientHello full synthesis

Build full TLS ClientHello profiles beyond JA3 hash matching:
- Extension ordering per browser (SNI, supported_groups, signature_algorithms, ALPN, key_share, psk_key_exchange_modes, etc.)
- JA3, JA3S, JA4, JA4H fingerprint computation + matching
- Supported groups (curves): Chrome uses x25519/P-256/P-384, Firefox adds x25519_kyber768
- Signature algorithms per browser
- ALPN protocol list ordering
- Each identity = coherent browser TLS + HTTP/2 + headers

Location: crates/evasion-engine/src/ — new files:
- tls_clienthello.rs (full ClientHello synthesis database)
- tls_clienthello_test.rs (verify profiles match real browser captures)

Wire into: tls_config.rs (extend existing TLS config with full ClientHello parameters)
