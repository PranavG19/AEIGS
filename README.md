# AEGIS — Autonomous Adversarial Intelligence Platform

The most comprehensive AI-powered offensive security framework ever built. 18 Rust crates + 1 Python package. **1,489 Rust source files. 24,601+ tests. 0 clippy warnings.**

AEGIS doesn't just scan for vulnerabilities — it thinks like a nation-state red team operator. An LLM-powered brain reasons about targets, chains findings into multi-step exploits, adapts to defenses in real-time, and generates proof-of-concept exploits autonomously.

> **Safety:** AEGIS only targets `localhost` by default. Remote targets require `--i-am-authorized` or a cryptographically signed scope attestation. This tool is for authorized security testing only.

---

## Architecture

```
orchestrator        CLI binary + full scan pipeline + LLM autonomous agent brain
├─ knowledge-graph  Arena Vec storage + parking_lot::RwLock; semantic edge validation
│  ├─ audit-log     SHA3-256 hash-chain + HMAC + CBOR event sourcing
│  │  └─ supervisor Process lifecycle + capability tokens
│  ├─ passive-recon Dependency parsing, SQLite vuln DB, filesystem walk, temporal correlation
│  ├─ enumeration   OpenAPI/GraphQL/gRPC route discovery, OAuth attacks, API security suite
│  ├─ crawler       BFS web crawler + headless browser + SPA crawler + multi-bot coordinator
│  ├─ fuzzing       UCB1 scheduler, coverage-guided, grammar-aware, payload encyclopedias
│  ├─ chain-synthesis  petgraph attack graph, probabilistic chains, kill chain mapping
│  ├─ reporting     SARIF 2.1.0, HTML reports, executive summaries, attack narratives
│  ├─ evasion-engine   Ghost Protocol (TLS/HTTP2/browser fingerprinting), WAF bypass, anti-attribution
│  ├─ discovery     OSINT, subdomain enum, CT monitor, honeypot detection, data sinkholes
│  ├─ exploiter     70+ exploit modules, cloud security, AD attacks, post-exploitation
│  ├─ compliance    CVSS, OWASP, PCI-DSS, STRIDE threat modeling, regulatory compliance
│  ├─ proxy         Recording proxy, intruder, repeater, mutation replay
│  ├─ proxy-tui     ratatui TUI binary (6 tabs)
│  └─ test-support  Mock infrastructure, vulnerable apps, benchmark suite
hypothesis-engine   LLM hypothesis generation (Bedrock/OpenAI/Ollama), adversarial compiler
```

---

## Capability Inventory (~200+ modules across 18 crates)

### Scan Pipeline (orchestrator)
- **Full Scan Entrypoint** — Single URL → complete vulnerability assessment
- **Auto-Module Selection** — Tech stack detection → appropriate attack module activation
- **Concurrent Scanner** — 50+ simultaneous endpoint testing with priority queue
- **LLM Autonomous Brain** — opencode-powered agent that reasons about targets like a human pentester
- **Multi-Vector Attack Coordinator** — Chains findings into compound exploit paths autonomously
- **Novel Vulnerability Reasoner** — First-principles logic flaw detection beyond known CWE patterns
- **Adaptive Defense Planner** — Real-time WAF/rate-limit evasion strategy adaptation
- **Autonomous Exploit Compiler** — LLM generates working target-specific PoC exploits
- **Distributed Scanning** — Coordinator/worker architecture for multi-node scanning
- **Continuous Monitoring** — Scheduled recurring scans with change detection and alerting
- **Pentest Playbook Engine** — Automated pentesting workflows with conditional logic
- **Scan Profiles** — Quick/Standard/Deep/Stealth presets
- **Persistence Manager** — Post-exploitation persistence mechanism deployment
- **Evidence Chain Builder** — Forensic-quality evidence for every finding
- **293 Browser API Audit Scanners** — Comprehensive browser security surface analysis

### Ghost Protocol — Anti-Detection (evasion-engine, 47 modules)
- **HTTP/2 Fingerprint Engine** — 7 browser profiles with SETTINGS/WINDOW_UPDATE/PRIORITY frames
- **TLS ClientHello Synthesis** — Full extension ordering, JA3/JA4/JA4H fingerprint matching
- **JA4+ Fingerprint Database** — 50+ real browser fingerprint entries
- **Browser Fingerprint Rotator** — Internally consistent identity rotation per-session
- **WAF Grammar Inference** — Reverse-engineer WAF rules via binary search probing
- **Adaptive Evasion Controller** — Real-time learning of which techniques work
- **105-Technique Evasion Catalogue** — Tagged by vendor, payload type, stealth level
- **Proxy Chain Manager** — SOCKS5/HTTP/Tor multi-hop chains with failover
- **Traffic Camouflage** — Domain fronting, Encrypted SNI, cover story traffic
- **Baseline Traffic Mimicry** — Learn normal traffic patterns, scan within statistical norms
- **ML Adversarial Perturbation** — Attack NDR classifier feature vectors directly
- **Living-off-the-Land Protocols** — Embed payloads in LDAP/SMB/WinRM enterprise traffic
- **Encrypted Channel Blending** — Tunnel via DoH/DoT/ECH to trusted providers
- **SaaS Dead Drops** — C2/exfil via Slack/Teams/S3/Sheets/Discord/Telegram
- **Anti-Forensics** — Minimize forensic evidence, memory-only operations
- **Identity Rotation Engine** — Full-stack identity lifecycle management
- **OPSEC Validator** — Pre-scan checklist (DNS leaks, WebRTC, IPv6, kill switch)
- **Ephemeral Infrastructure Generator** — Terraform configs for disposable scan nodes
- **Payload Obfuscator** — 10+ composable encoding/obfuscation transforms
- **Rate Limit Bypass** — 10+ header rotation and endpoint aliasing techniques
- **CORS/CSP/CSRF Bypass Engines** — Active exploitation of browser security mechanisms

### Exploitation Arsenal (exploiter, 70 modules)
- **JWT Attack Suite** — alg:none, key confusion, JWK injection, kid injection, claim tampering
- **SAML Attack Engine** — Signature wrapping, exclusion, comment injection, replay
- **OAuth/OIDC Flow Attacks** — 9 attack categories covering the full 47-page RFC
- **MFA Bypass Engine** — OTP brute-force, push fatigue, backup code enumeration
- **Active Directory Suite** — Kerberoasting, AS-REP roasting, DCSync, golden/silver ticket, ACL abuse, cert abuse
- **Database Exploiter** — MySQL UDF, PostgreSQL COPY, MSSQL xp_cmdshell, Oracle UTL_HTTP, MongoDB $where, Redis SLAVEOF
- **Container & K8s Attacks** — Docker socket exploitation, pod escape, RBAC abuse, registry attacks
- **CI/CD Exploitation** — GitHub Actions injection, GitLab CI include injection, Jenkins Groovy, build poisoning
- **Cloud Security Suite** — AWS S3/Lambda, Azure AD/Entra, GCP service accounts, K8s, cloud metadata
- **Post-Exploitation Framework** — Persistence, privilege escalation, data harvesting, C2 beacons, cleanup
- **LLM Deep Exploiter** — Prompt injection chains, training data extraction, tool-use hijacking
- **MCP Schema Exploiter** — Model Context Protocol tool hijacking, parameter injection, confused deputy
- **AI Coding Agent Exploiter** — Poisoned repo artifacts that hijack Claude Code/Cursor/Copilot
- **Reverse Shell Generator** — 9 languages × 3+ techniques × 4 encodings
- **File Upload Exploitation** — Extension bypass, magic bytes, polyglot files, web shells
- **Email System Exploitation** — Exchange ProxyLogon/ProxyShell, O365 attacks, SMTP exploitation
- **WiFi Attack Library** — WPA2 handshake, PMKID, evil twin, karma, deauth, WPS, captive portal
- **IoT Attack Library** — UPnP, MQTT, CoAP, Zigbee/Z-Wave, IP cameras, SCADA/Modbus
- **VPN Attack Library** — IKE aggressive mode, OpenVPN audit, tunnel escape, SSL VPN CVEs
- **Physical Access Payloads** — BadUSB, HID injection, WiFi Pineapple, rogue devices
- **Signal Intelligence** — WiFi probe analysis, BLE tracking, SDR commands, traffic analysis
- **Padding Oracle Engine** — CBC padding oracle byte-by-byte decryption
- **Credential Testing** — Default creds, password spray, lockout-aware, multi-protocol

### Fuzzing Engine (fuzzing, 54 modules)
- **Coverage-Guided HTTP Fuzzer** — AFL-style behavioral coverage for black-box web testing
- **Grammar-Aware Protocol Fuzzer** — HTTP/1.1, HTTP/2, WebSocket, TLS record fuzzing
- **UCB1 Bandit Payload Scheduler** — Exploration/exploitation balance for payload selection
- **Jailbreak Tournament** — UCB1-driven evolutionary LLM jailbreak discovery
- **Payload Encyclopedias** — XSS (50+), SQLi (200+), SSTI (10 engines), SSRF (100+), CmdI (200+)
- **Single-Packet Race Engine** — HTTP/2 single-frame race condition exploitation
- **GraphQL Deep Exploit Suite** — Batch cost attacks, field auth bypass, subscription SSRF
- **Prototype Pollution Gadget Scanner** — Trace __proto__ taint to child_process/eval sinks
- **ReDoS Engine** — Detect catastrophic backtracking via timing analysis
- **HTTP/2 Protocol Attacks** — CONTINUATION flood, Rapid Reset, SETTINGS flood, HPACK bombing
- **Deserialization Attacks** — Java/Python/PHP/.NET/Ruby/Node.js gadget chains
- **Campaign Manager** — Save/resume fuzzing campaigns, corpus evolution, plateau detection

### Intelligence & Reconnaissance (discovery + passive-recon, 61 modules)
- **Person Profiler** — 500+ platform username correlation, breach check, social graph
- **Organization Mapper** — Domain, IP range, employee, vendor, subsidiary discovery
- **Target Dossier Generator** — Combined actionable intelligence report
- **Temporal Infrastructure Correlator** — Cross-time DNS/WHOIS/CT/BGP correlation
- **Financial Footprint Mapper** — Payment processor, crypto wallet, merchant ID extraction
- **Supply Chain Shadow Mapper** — Build plugins, CI/CD deps, Docker lineage, maintainer trust chains
- **Credential Intelligence** — Breach databases, API key search, cloud credential patterns
- **Social Engineering Profile Builder** — Interests, communication style, phishing templates
- **CT Monitor & Bulk DNS** — Certificate transparency + concurrent async resolution
- **Subdomain Takeover at Scale** — CNAME chain analysis, 10+ cloud service signatures
- **Honeypot/IDS/Canary Detection** — Identify deception infrastructure before scanning
- **Data Sinkhole Detector** — Find exposed Elasticsearch, Redis, Firebase, K8s dashboards
- **Exposed Database Scanner** — MongoDB, Redis, Elasticsearch, CouchDB, Memcached
- **Cloud Storage Scanner** — S3, Azure Blob, GCP bucket misconfiguration
- **API Secret Exposure** — GitHub, GitLab, Pastebin, Docker Hub, Postman, npm secrets
- **Threat Intelligence Feed** — CVE/Exploit-DB/CISA KEV correlation with discovered tech

### Chain Synthesis & Attack Graphs (chain-synthesis, 23 modules)
- **Probabilistic Attack Chains** — Bayesian probability propagation on attack graph
- **Kill Chain Mapper** — Map findings to Cyber Kill Chain phases
- **Attack Tree Generator** — AND/OR attack trees with minimum cost paths
- **Impact Propagation** — Cascading compromise modeling
- **SSRF Cloud Pivoting** — AWS/GCP/Azure credential chain resolution
- **DNS Exfiltration** — Data encoding in DNS queries for firewalled environments
- **Business Logic Tester** — State machine inference, workflow skip attacks
- **Credential Harvesting Coordinator** — Aggregate all credential sources
- **Remediation Prioritizer** — Fix ranking by maximum risk reduction on graph

### Compliance & Reporting (compliance + reporting, 30 modules)
- **STRIDE Threat Model Generator** — Automated threat modeling from discovered architecture
- **Risk Quantification** — Monte Carlo probability × impact with confidence intervals
- **Regulatory Compliance** — SOC2, ISO 27001, GDPR, HIPAA, FedRAMP mapping
- **MITRE ATT&CK Mapper** — Technique/tactic mapping with navigator layer export
- **HTML Report Template** — Dark theme, collapsible sections, embedded attack diagrams
- **Executive Report** — Risk score 0-100, top findings, remediation roadmap
- **Attack Narrative Generator** — Human-readable exploit chain stories
- **SARIF 2.1.0** — CWE + ATT&CK enriched standard output

### API Security Suite (enumeration, 24 modules)
- **OpenAPI Security Analyzer** — Auth gaps, validation gaps, rate limit gaps, schema bypass
- **gRPC Security Tester** — Reflection enumeration, auth testing, metadata injection
- **GraphQL Full Stack** — Introspection, field auth, mutations, persisted queries, subscriptions
- **OAuth/OIDC Flow Attacks** — Redirect manipulation, PKCE bypass, scope escalation
- **API Gateway Bypass** — Direct backend access, path normalization, rate limit circumvention
- **Webhook Security** — SSRF, replay, signature bypass, callback manipulation
- **API Version Diffing** — Security regression detection across API versions

### Browser Automation (crawler, 22 modules)
- **Headless Browser Controller** — Chrome/Firefox with custom fingerprint profiles
- **SPA Crawler** — React/Angular/Vue/Svelte detection and dynamic content discovery
- **Multi-Bot Coordinator** — Distributed browser instances with shared state
- **Form Auto-Filler** — Context-aware field filling with CAPTCHA detection
- **JS Executor** — Static + dynamic JavaScript analysis, source map deobfuscation
- **Authentication Automator** — Multi-protocol auth handling with session management
- **DOM XSS Detection** — postMessage attacks, DOM clobbering, client-side template injection

### Autonomous AI Agent (hypothesis-engine + orchestrator)
- **opencode Integration** — Spawn opencode as autonomous pentester brain
- **AEGIS-MIND Mission Prompt** — Red team operator persona with OWASP/CWE knowledge
- **Agent Memory Database** — Cross-session learning with temporal decay
- **Multi-Model Router** — Claude for reasoning, GPT-4 for breadth, Ollama for speed
- **Feedback Loop** — Brief → reason → test → learn → repeat with convergence detection
- **Adversarial Prompt Compiler** — Defense-aware hypothesis reformulation
- **Counter-Intelligence** — Detect if scanner is being monitored, honeypot detection

---

## Commands

```bash
cargo test --workspace                              # all Rust tests (~24,601)
cargo clippy --workspace -- -D warnings             # zero warnings
cargo fmt --all --check                             # formatting gate
cd hypothesis-engine && uv run pytest -v            # Python tests
```

## Safety

- Target validation at 3 layers: protocol, evasion-engine transport, fuzzing executor
- `localhost`/`127.0.0.1`/`::1` only by default
- `--i-am-authorized` flag for remote scanning; logged to audit trail
- `--no-audit` to disable mandatory audit log
- Ed25519-signed scope attestation for authorized engagements
- **This tool is for authorized security testing and research only**

## Development Stats

| Metric | Count |
|--------|-------|
| Rust source files | 1,489 |
| Python files | 847 |
| Test files | 693 |
| Tests passing | 24,601+ |
| Clippy warnings | 0 |
| Crates | 18 |
| Attack modules | 200+ |
| Vulnerability classes | 34 |
| Browser API auditors | 293 |
| Evasion techniques | 105+ |
| Payload templates | 1,000+ |
| Mega merges | 10 |
