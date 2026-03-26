# AEGIS
### Autonomous Adversarial Intelligence Platform

> *The most comprehensive AI-powered offensive security framework ever built.*

**19 Rust crates · 1 Python package · 1,758 source files · 849 test files · 624 commits**

Built for authorized government red team operations and enterprise security research.
Every capability is designed for authorized penetration testing — `localhost` only by default.

---

## What AEGIS Can Do

```bash
aegis scan   --target https://target.com --profile deep --i-am-authorized
aegis auto   --target https://target.com --objective "domain admin"
aegis-scan-tui --target https://target.com
aegis-web-ui --target https://target.com --port 7777
aegis-c2     --listen 0.0.0.0:8443
```

---

## Architecture

```
aegis              ← main CLI binary
aegis-scan-tui     ← real-time 5-panel terminal dashboard (ratatui)
aegis-web-ui       ← live D3.js attack graph in browser (axum + SSE)
aegis-c2           ← C2 operator console + DNS/HTTPS covert channels
aegis-proxy-tui    ← intercepting proxy with 6 tabs (ratatui)
```

```
orchestrator     Full scan pipeline · LLM autonomous brain · kill chain executor
├─ evasion-engine    Ghost Protocol: TLS/HTTP2/browser fingerprinting · 60+ anti-detection modules
├─ fuzzing           UCB1 scheduler · coverage-guided · 1,000+ payload templates
├─ exploiter         80+ exploit modules · AD attacks · cloud security · post-exploitation
├─ discovery         OSINT · subdomain enum · CT monitor · data sinkholes · threat intel
├─ enumeration       GraphQL · OAuth · gRPC · API security · gateway bypass
├─ crawler           Headless browser · SPA · multi-bot coordinator · JS analysis
├─ chain-synthesis   Probabilistic attack graphs · kill chain · SSRF pivoting
├─ reporting         SARIF 2.1.0 · HTML · executive reports · attack narratives
├─ compliance        CVSS · OWASP · STRIDE · MITRE ATT&CK · regulatory checker
├─ passive-recon     Temporal correlation · financial footprint · supply chain shadow
├─ proxy             Recording proxy · intruder · repeater · mutation replay
├─ knowledge-graph   Arena storage · RwLock · semantic edge validation
└─ hypothesis-engine LLM hypothesis gen · adversarial compiler (Python/Bedrock/OpenAI/Ollama)
```

---

## The ROI-100: Every Capability

### Tier 1 — Ghost Protocol: Undetectable Operations (36 modules)

| Module | What It Does |
|--------|-------------|
| `zero_disk_mode` | Everything in memory — mlock, secure wipe on exit, never touches disk |
| `traffic_normalizer` | Learn target's traffic baseline, enforce statistical conformance — defeats Darktrace/Vectra |
| `polymorphic_signer` | No two scans look identical to ML classifiers — UCB1 parameter randomization |
| `ephemeral_executor` | Run Terraform to spin up/destroy infrastructure per scan phase |
| `forward_secrecy` | X25519 ECDH + HKDF-SHA256 key ratchet — past sessions mathematically irrecoverable |
| `hw_key_storage` | macOS Keychain / Linux TPM2 / Windows CNG — keys never extractable |
| `log_poisoner` | Inject false timeline entries — confuse forensic reconstruction |
| `opsec_gate` | Hard pre-flight: DNS leak, WebRTC, IPv6, hostname, processes, MAC check |
| `post_op_cleanup` | One command wipes all local + remote forensic artifacts (DoD 5220.22-M) |
| `counter_attribution` | Plant APT29/APT41/Lazarus false-flag indicators |
| `process_hollow` | Process hollowing: inject into svchost/explorer without touching disk |
| `direct_syscall` | Hell's Gate direct syscalls — bypass EDR userland hooks |
| `memory_loader` | Reflective PE loading, Linux memfd_create ELF, module stomping |
| `lolbin_generator` | Chain certutil/regsvr32/mshta/rundll32/awk/curl for fileless execution |
| `timestomper` | Match file timestamps to surrounding files ±jitter (NTFS + Linux) |
| `anti_memory_forensics` | String encryption at runtime, ASLR-aware heap, pool tag manipulation |
| `ja4_impersonator` | JA4/JA4H/JA4T/JA4X: full vector consistency per browser identity |
| `tcpip_spoofer` | Match Windows/Linux/macOS TCP/IP stack fingerprints exactly |
| `doh_enforcer` | All DNS through DoH (RFC 8484) — zero UDP port 53 queries |
| `asn_router` | Route through non-monitored ASNs in non-MLAT jurisdictions |
| `biometric_mimicry` | Bezier mouse curves, Gaussian keystroke timing, scroll velocity |
| `fingerprint_consistency` | Per-identity canvas/WebGL/AudioContext hash, GPU renderer strings |
| `navigator_synthesizer` | Complete navigator property set matching claimed device/OS/browser |
| `cover_traffic_v2` | Real Alexa-10k browsing mixed with attack traffic |
| `jitter_controller` | Pareto-distributed request intervals — defeats timing correlation |
| `quic_transport` | HTTP/3 QUIC — most security tools don't inspect QUIC traffic |
| `ech_transport` | TLS Encrypted Client Hello — hide target domain from DPI |
| `webrtc_disabler` | Override RTCPeerConnection, suppress all ICE candidates |
| `accel_detector` | RDTSC delta vs wall clock — detect sandbox sleep acceleration |
| `anti_debug_v2` | ptrace, TracerPid, timing, debug registers, parent process |
| `vm_detector` | CPUID hypervisor, VMware/VBox/Hyper-V/KVM, MAC OUI, DMI |
| `canary_detector_v2` | AWS keys, tracking pixels, honeydoc markers in every response |
| `honeypot_scorer_v2` | Probabilistic scoring — abort if target looks like honeypot |
| `rate_adaptive_throttle` | Binary search threshold, stay at 85%, adapt in real-time |
| `jurisdiction_planner` | MLAT treaty DB, Five Eyes avoidance, Iceland/Switzerland routing |
| `session_compartment` | New identity per session — zero cross-session correlation |

### Tier 2 — Scan Effectiveness (24 modules)

| Module | What It Does |
|--------|-------------|
| `gpu_browser` | Real GPU rendering in headless Chrome — bypasses canvas fingerprinting |
| `js_engine` | Embedded V8 — execute JS in-process, capture all fetch/XHR calls |
| `ws_state_machine_v2` | Infer WebSocket state machine, fuzz transitions, subscription abuse |
| `grpc_exploiter` | Reflection enumeration, auth bypass, metadata injection, stream exhaustion |
| `graphql_reconstructor` | Full schema reconstruction without introspection via error suggestion |
| `timing_oracle_v2` | Welch's t-test, adaptive sampling, sub-millisecond, blind char extraction |
| `h2_push_exploit` | HTTP/2 push cache poisoning — inject malicious pushed content |
| `hpack_bomb_v2` | HPACK decompression bombs, dynamic table exhaustion |
| `code_path_analyzer` | Find hidden code paths via semantic diff of equivalent requests |
| `race_window_detector` | Automated TOCTOU detection via HTTP/2 single-packet attack |
| `lfi_rce_chain` | LFI → log poison → PHP execution → RCE automated chain |
| `ssti_rce` | Polyglot detection → engine ID → Jinja2/Twig/Freemarker/Mako RCE |
| `blind_ssrf_v2` | OOB callback, all cloud metadata paths, protocol handlers, full chain |
| `oauth_leakage_detector` | Token in fragment, Referer, cache, postMessage, implicit flows |
| `csrf_entropy_v2` | Mersenne Twister recovery from 624 outputs, next-token prediction |
| `gadget_finder_v2` | Trace __proto__ to child_process/eval — PP → confirmed RCE chains |
| `graphql_bypass_v3` | Method override, fragment alias, batch split, error-based type discovery |
| `api_schema_drift_v2` | Mass assignment, undocumented endpoints, v1→v2 security regressions |
| `second_order_tracer_v2` | Store → trigger → correlate injection chains across async operations |
| `biz_logic_fuzzer_v2` | Workflow skip, price manipulation, state reordering, concurrent duplicates |
| `mass_assign_predictor` | ML-predicted hidden field names from framework patterns |
| `method_override_v2` | 100 source×target method combos, all override headers, XST detection |
| `cache_deception_v2` | Path confusion, delimiter abuse, Vary bypass, victim simulation |
| `subdomain_takeover_v3` | 30+ cloud signatures, HTTPS detection, proof generation, 10k concurrent |

### Tier 3 — Intelligence & OSINT (15 modules)

| Module | What It Does |
|--------|-------------|
| `breach_correlator` | HIBP k-anonymity SHA1 prefix queries — check credentials against breach DBs |
| `darkweb_monitor` | .onion paste patterns, Tor search formats, leaked credential parsing |
| `executive_profiler` | C-suite targeting: conference bios, SEC filings, email format inference |
| `supply_chain_attacker` | Abandoned maintainer accounts, expired domains, typosquat scoring |
| `shodan_live` | Real Shodan API: host lookup, search, port/banner/vuln parsing |
| `passive_dns` | SecurityTrails/DNSDB/Farsight aggregation, historical IP→hostname mapping |
| `bgp_history` | RIPE RIS/RouteViews parsing, AS path analysis, IP space reuse detection |
| `email_validator_v3` | Catch-all detection, SMTP timing oracle, greylisting bypass |
| `social_correlator` | Post timing timezone, stylometric fingerprinting, content reuse detection |
| `github_scanner_v3` | Full commit history including deleted branches, blob entropy search |
| `cloud_enum_v3` | Company name + 50 suffixes across all major cloud providers |
| `iot_fingerprinter` | 100-device default credential DB, Telnet/SSH banner analysis |
| `financial_intel_v2` | SEC EDGAR API, subsidiary extraction, org chart reconstruction |
| `job_intel_v2` | Job posting tech stack extraction, security maturity inference |
| `ct_monitor_v2` | crt.sh streaming — new cert alerts within seconds of issuance |

### Tier 4 — Exploitation Depth (25 modules)

| Module | What It Does |
|--------|-------------|
| `kerberos_delegation` | Unconstrained/constrained/RBCD delegation abuse with S4U2Proxy chains |
| `adcs_exploiter` | AD CS ESC1-ESC13: certificate template abuse, NTLM relay to CA |
| `shadow_credentials` | msDS-KeyCredentialLink manipulation → PKINIT TGT extraction |
| `ntlm_coercion` | PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce — force NTLM auth |
| `dcom_lateral` | MMC20, ShellWindows, ShellBrowserWindow, Outlook/Excel DCOM execution |
| `wmi_persistence` | EventFilter + ActiveScriptConsumer + FilterToConsumerBinding |
| `gpo_abuser` | Writable GPO detection → scheduled task, startup script, registry |
| `exchange_proxyshell_v2` | ProxyShell, ProxyNotShell, ProxyLogon chains with web shell upload |
| `enterprise_app_rce` | Confluence/Jira/GitLab/Jenkins/Zimbra RCE chains |
| `cloud_privesc_v3` | All 40+ AWS IAM escalation paths, GCP service account, Azure AD |
| `container_breakout_v3` | cgroups v2, eBPF abuse, runc CVE-2024-21626, overlayfs, namespace escape |
| `k8s_pod_mutation` | Rogue admission webhook, sidecar injection, RBAC escalation |
| `extension_rce_chain` | Content script XSS → background page → native messaging → OS RCE |
| `electron_exploiter` | nodeIntegration, contextIsolation, preload injection, IPC abuse |
| `hash_cracker` | Universal hashcat/john wrapper — Kerberos/NTLM/WPA2/bcrypt/MD5 |
| `kerberos_chain` | TGS request → crack → LDAP auth → group check → DCSync chain |
| `ntlm_relay` | Responder parsing, ntlmrelayx configs, PtH commands, NTLMv2 cracking |
| `wifi_credential_pipeline` | pcapng → hashcat mode 22000 → wpa_supplicant config → connect |
| `credential_reuse` | Pattern extraction, variation generation, cross-service testing |
| `ad_attack_suite` | Kerberoasting, AS-REP roasting, DCSync, golden/silver ticket, cert abuse |
| `database_exploiter` | MySQL UDF, PostgreSQL COPY, MSSQL xp_cmdshell, MongoDB $where, Redis SLAVEOF |
| `post_exploitation` | Persistence, privesc enum, data harvest, C2 beacons, cleanup |
| `gadget_scanner` | PP → gadget chain discovery (child_process, eval, Function sinks) |
| `llm_deep_exploiter` | Prompt injection chains, training data extraction, tool-use hijacking |
| `adversarial_ml_attacks` | Model inversion, membership inference, adversarial WAF bypass, data poisoning |

### Tier 5 — Infrastructure & Platform (11 modules)

| Module | What It Does |
|--------|-------------|
| `mesh_c2` | P2P C2 with DHT peer discovery, onion routing, gossip protocol — no central server |
| `multi_operator` | RBAC team collaboration, session sharing, conflict prevention, audit trail |
| `campaign_manager_v2` | Multi-target coordinated campaigns with dependency management |
| `collab_protocol` | WebSocket real-time team sync: live attack graph, findings, chat |
| `mobile_api` | REST + WebSocket API for mobile operator console (JWT auth) |
| `plugin_loader` | Dynamic module loading via libloading — hot-reload without restart |
| `k8s_operator` | AegisScan CRD, reconciler, Helm chart generation, horizontal scaling |
| `ai_fine_tuner` | Track successful LLM hypotheses → JSONL fine-tuning datasets |
| `kill_chain_executor` | `aegis auto --objective "domain admin"` — fully autonomous end-to-end |
| `aegis-scan-tui` | 5-panel ratatui dashboard with live findings, attack chains, log stream |
| `aegis-web-ui` | D3.js force-directed attack graph in browser with SSE streaming |

### Tier 6 — AI/LLM Brain (8 modules)

| Module | What It Does |
|--------|-------------|
| `autonomous_recon` | LLM-driven investigation: goal → multi-source → iterative → dossier |
| `exploit_compiler` | LLM generates working target-specific PoC exploits from confirmed vulns |
| `adaptive_defense_planner` | Real-time WAF/rate-limit evasion replanning after each blocked request |
| `multi_vector_coordinator` | AI chains findings into compound attack paths autonomously |
| `novel_vuln_reasoner` | First-principles logic flaw detection beyond known CWE patterns |
| `persistence_manager` | Post-exploitation: select/deploy/monitor/rotate persistence mechanisms |
| `opencode_spawner` | Spawn opencode as autonomous pentester brain via subprocess |
| `aegis_mind_prompt` | Red team operator persona with OWASP/CWE/ATT&CK knowledge base |

---

## Binaries

```bash
aegis scan --target https://target.com --profile deep --i-am-authorized
aegis auto --target https://target.com --objective "domain admin"
aegis recon --target target.com
aegis-scan-tui --target https://target.com        # terminal dashboard
aegis-web-ui --target https://target.com          # browser D3.js graph
aegis-c2 --listen 0.0.0.0:8443                   # C2 operator console
aegis-proxy-tui                                   # intercepting proxy
```

---

## By The Numbers

| Metric | Count |
|--------|-------|
| Rust source files | **1,758** |
| Python files | **847** |
| Test files | **849** |
| Git commits | **624** |
| Crates | **19** |
| Attack modules | **250+** |
| Evasion techniques | **150+** |
| Payload templates | **1,000+** |
| Vulnerability classes | **34** |
| ROI-100 features | **100** |
| Cloud providers supported | **5** |
| C2 channels | **6** |

---

## Quick Start

```bash
# Build
cargo build --release

# Run tests
cargo test --workspace

# Scan localhost fixture
aegis scan --target http://localhost:3000 --profile quick

# Full autonomous engagement (requires --i-am-authorized for remote)
aegis auto --target https://authorized-target.com \
           --objective "database access" \
           --i-am-authorized

# Live web dashboard (demo mode — no real target needed)
aegis-web-ui --demo --port 7777
# open http://localhost:7777

# Demo the scan TUI
aegis-scan-tui --demo
```

---

## Development

```bash
cargo test --workspace                           # ~25,000 tests
cargo clippy --workspace -- -D warnings          # zero warnings
cargo fmt --all --check                          # formatting gate
cd hypothesis-engine && uv run pytest -v         # Python tests
```

---

## Safety

All scans target `localhost`/`127.0.0.1`/`::1` by default.
Remote scanning requires `--i-am-authorized` — logged to SHA3-256 hash-chain audit trail.
Scope restricted via Ed25519-signed attestation documents.

**For authorized security testing only.**
