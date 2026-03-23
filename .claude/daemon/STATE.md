# DAEMON STATE

## current
priority: P8 (CONTINUOUS_IMPROVEMENT)
task: continue P8 recon features
status: in-progress

## test-results
- cargo test -p aegis-orchestrator: 1543 lib, 0 failed
- cargo clippy -p aegis-orchestrator: 0 warnings
- cargo fmt --all --check: 0 diffs

## priority-clearance
- P0: CLEAR — P1: CLEAR — P3: CLEAR
- P4: COMPLETE — P5: COMPLETE — P6: CLEAR
- P7: BLOCKED (Docker daemon not running, need `colima start`)
- P8: IN PROGRESS
- P2: CLEAR — all 52 source files have ≥3 tests each

## P8-progress (21 features shipped)
- [x] TLS scanner, header audit, robots/sitemap parser
- [x] DNS enumeration, CORS scanner, cookie audit
- [x] HTTP method enum, open redirect, info disclosure
- [x] Subdomain takeover, email security, CSP analysis
- [x] HSTS preload, HTTP version detect, WAF detection
- [x] Rate limit detection, security.txt parser
- [x] Technology/CMS fingerprinting, Permissions-Policy audit
- [x] Cache-control header audit
- [x] G14 consolidation: recon_client.rs (shared helpers for 20 modules)
- [x] JS library version detection scanner
- [x] Subresource integrity (SRI) checker
- [x] Mixed content detection (HTTP resources on HTTPS pages)
- [x] Form security audit (CSRF, insecure action, autocomplete)
- [x] HTML comment leak scanner (credentials, paths, debug info)
- [x] Source map file exposure detector
- [x] Meta tag security audit (generator, robots, set-cookie)
- [x] Iframe sandbox audit (missing sandbox, permissive flags, HTTP src)
- [x] G14 consolidation: html_parser.rs (TagIter + extract_attr)
  All 6 tag scanners now use shared html_parser helpers
- [x] Base tag hijack detection (external, HTTP, multiple)
- [x] Window.opener vulnerability detection (target=_blank)
- [x] Inline event handler detection (XSS indicator)
- [x] Dangerous JS pattern detection (eval, innerHTML, document.write)
- [x] Link preconnect/dns-prefetch audit
- [x] Error page info leak scanner (stack traces, debug info, SQL errors)
- [x] Referrer-Policy value audit (unsafe-url, downgrade, invalid)
- [x] X-Frame-Options value audit (ALLOWALL, ALLOW-FROM, invalid, multiple)
- [x] COOP/COEP header audit (missing, unsafe-none)
- [x] CORP header audit (missing, cross-origin, invalid)
- [x] Cookie SameSite=None detection (added to existing cookie_audit)
- [x] CORS credentials+reflection detection (severity 8.0, highest)
- [x] Content-Type/X-Content-Type-Options audit (nosniff, charset, MIME)
- [x] Server-Timing header leak detection (db, cache, internal metrics)

## G14-deferred
- 13 HTML-body scanners each independently fetch the same target URL
- Consolidation: fetch once → pass body to all body-analyzers
- Size: L (200+ lines, 13+ files). Deferred to dedicated session.

## handoff
NEXT STEPS (in order):
1. Continue P8: expect-ct deprecation, feature-policy deprecation,
   access-control-expose-headers audit, nel/report-to audit.
2. G14 body-fetch consolidation (L-sized, next dedicated session).
