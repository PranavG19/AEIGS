# DAEMON STATE

## current
priority: P8 (CONTINUOUS_IMPROVEMENT)
task: continue P8 recon features
status: in-progress

## test-results
- cargo test -p aegis-orchestrator: 1667 lib, 0 failed
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
- [x] Deprecated header audit (Expect-CT, Feature-Policy, HPKP, X-XSS-Protection)
- [x] Access-Control-Expose-Headers audit (sensitive header leak)
- [x] document.domain detection (deprecated API, XSS relaxation)
- [x] NEL/Report-To header audit (external collectors, HTTP endpoints, high sample rates)
- [x] Link header audit (external preload/prefetch, HTTP resources, dns-prefetch)
- [x] Reporting-Endpoints audit (external collectors, HTTP endpoints)
- [x] Timing-Allow-Origin audit (wildcard, HTTP origins, many origins)
- [x] Clear-Site-Data audit (wildcard, cookies/storage/cache on GET, HTTP)
- [x] SourceMap response header audit (SourceMap + X-SourceMap headers)
- [x] ETag leak detection (Apache inode, weak ETags, unusually long ETags)
- [x] WWW-Authenticate audit (Basic over HTTP, Digest w/o qop, realm info leak)
- [x] Proxy header audit (Via chain, Age, X-Cache, X-Forwarded-For)

## G14-deferred
- 13 HTML-body scanners each independently fetch the same target URL
- Consolidation: fetch once → pass body to all body-analyzers
- Size: L (200+ lines, 13+ files). Deferred to dedicated session.

## P9 — SIMPLIFY PASS (after P8 wraps current batch)
Run `/simplify` skill on each recon feature module one by one.
Review for reuse, quality, efficiency. Fix issues before moving on.
Work through all P8 features systematically (newest first).

## P10 — ORCHESTRATION CONSOLIDATION
Consolidate all recon orchestration management in phase_recon.rs.
- G14 body-fetch consolidation (13 HTML scanners share one fetch)
- Unify scanner registration/dispatch pattern
- Reduce boilerplate in thread spawn + join + extend pattern
- Single entry point for all recon scanners

## P11 — TEST LINE COVERAGE 90%+
Get all test line coverage to 90%+ per source file.
- Use `cargo llvm-cov` or `cargo tarpaulin` to measure per-file coverage
- Identify files below 90% threshold
- Add targeted tests for uncovered branches/paths
- Re-measure and iterate until all files pass 90%

## P12 — SECURITY HARDENING
Address findings from codebase security audit.

### P12a — Trufflehog path traversal (HIGH)
- crates/exploiter/src/trufflehog_wrapper.rs: `context.endpoint` passed as
  filesystem path without validation. Canonicalize path, reject `..` components,
  ensure path stays within scan root.

### P12b — Auth header/cookie sanitization (MEDIUM)
- crates/exploiter/src/sqlmap_wrapper.rs, httpx_wrapper.rs, feroxbuster_wrapper.rs:
  auth headers/cookies passed to external tools without validating for control
  characters (newlines, nulls). Add `validate_header_value()` guard that rejects
  control chars before passing to any ToolWrapper.

### P12c — Obfuscation bypass test coverage (MEDIUM)
- crates/protocol/src/target_validation.rs: Add regression tests for hex IP
  (0x7f000001), octal IP (016777343), decimal IP (2130706433), double-encoding,
  Unicode normalization attacks, DNS rebinding via nip.io variants.

### P12d — Scope attestation date parsing (LOW)
- crates/protocol/src/scope_attestation.rs: Replace string comparison for expiry
  with chrono::NaiveDate::parse(). Clarify UTC assumption.

## P13 — ARCHITECTURE IMPROVEMENTS
Address findings from architecture audit.

### P13a — Extract Phase trait (HIGH)
- Define `Phase` trait with `async fn run(&mut self, ctx: &mut ScanContext) -> Result<PhaseResult, PhaseError>`
- Implement for each phase (ReconPhase, CrawlPhase, FuzzPhase<T>, etc.)
- Orchestrator becomes an executor loop, not explicit function calls
- Enables cross-cutting concerns (retry, metrics, timeout) without touching each call site

### P13b — Parameterize I/O in fuzzing crate (MEDIUM)
- fuzzing/src/bot_detection_probe.rs, cloud_detector.rs, cors_detector.rs,
  graphql_tester.rs: Extract `HttpClient` trait, parameterize detectors over it.
  Enables unit testing heuristic logic without reqwest/wiremock.

### P13c — Move scanners out of orchestrator (MEDIUM)
- Move 30+ recon scanners from crates/orchestrator/src/ to crates/passive-recon/src/
- Move cve_correlator, idor_analyzer, subdomain_takeover to new crates/security-analysis/
- Target: orchestrator down to ~20 core files (phases, pipeline, coordination)

### P13d — Standardize error types (LOW)
- Replace remaining Result<T, String> with domain-specific error enums
- FuzzTransport error should be Result<FuzzResponse, FuzzError>, not String

## P14 — RECON SCANNER POLISH
Address findings from recon scanner audit.

### P14a — Cache compiled regexes (LOW)
- js_library_scanner.rs: Regex::new() called per scan. Use once_cell::sync::Lazy
  for compiled regex map.

### P14b — Add error logging to scanners (LOW)
- All 31 scanners silently return Vec::new() on HTTP errors. Add tracing::warn!
  for network failures so false negatives are debuggable.

### P14c — Reduce false positives in error_page_audit (LOW)
- Check Content-Type is text/html before pattern matching. "syntax error" in
  JSON API responses currently triggers false positive.

## handoff
NEXT STEPS (in order):
1. G14 check due: 5+ header scanners since last consolidation.
2. Continue P8: x-dns-prefetch-control audit, content-disposition audit.
3. When P8 batch complete → move to P9 (simplify pass).
4. Then P10 (orchestration consolidation).
5. Then P11 (90%+ test coverage per file).
6. Then P12 (security hardening — P12a first).
7. Then P13 (architecture improvements — P13a first).
8. Then P14 (recon scanner polish).
