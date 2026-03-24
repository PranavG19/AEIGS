# Testing Improvements

Generated: 2026-02-23 | Source depth: 2

---

### TEST-001: Zero Doc Test Examples Across Entire Codebase
**Severity:** high
**Effort:** medium
**Affected:** all library crates (especially aegis-protocol, aegis-knowledge-graph)
**Source confirmed:** yes (grep found 0 `/// # Examples` with code blocks)

No public API in the codebase has example code in doc comments. Doc tests (`///` examples) serve as both documentation and lightweight integration tests, and are run by `cargo test`. For a library with complex APIs like `KnowledgeGraph`, `Confidence`, and `GraphOperation`, doc tests would significantly improve discoverability.

**Recommendation:** Add doc tests to the 10 most commonly used public APIs. Start with:
```rust
/// # Examples
/// ```
/// use aegis_protocol::finding::{Confidence, EvidenceLevel};
/// let conf = Confidence::from_evidence(EvidenceLevel::Statistical);
/// assert_eq!(conf.value(), 0.4);
/// ```
```

Priority targets: `Confidence::new()`, `KnowledgeGraph::apply_operations()`, `FuzzScheduler::enqueue()`, `AuditLogWriter::create()`.

---

### TEST-002: Crawler Coverage — CrawlResult::default() Stub Goes Untested
**Severity:** high
**Effort:** medium
**Affected:** aegis-orchestrator, aegis-crawler
**Source confirmed:** yes (pipeline.rs:1533 uses default())

The crawl phase is silently disabled (using `CrawlResult::default()`). When the crawler is wired, there are no integration tests validating that:
1. The crawler correctly discovers endpoints from a real web application
2. The knowledge graph correctly incorporates crawl results
3. The pipeline handles crawl errors gracefully

**Recommendation:** Add Docker Tier 2 tests that:
- Spin up the Express test app
- Run a scan WITH the real crawler enabled
- Verify endpoints discovered via crawl appear in the scan results
Until the crawler is wired, add a test that verifies `CrawlResult::default()` produces zero operations (to prevent silent empty-result bugs).

---

### TEST-003: Convergence Detection Logic Has Edge Case Coverage Gaps
**Severity:** medium
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** partial

`update_convergence()` increments `consecutive_zero_findings` when both fuzz and analyze phases produce zero findings. Key edge cases to test:
- Does the convergence counter reset when analyze finds something even if fuzz finds nothing?
- Does `convergence_threshold = 1` stop after the first zero-finding iteration?
- Does resuming from a checkpoint correctly restore the convergence counter?

**Recommendation:** Add unit tests in `convergence_test.rs` covering:
```rust
fn test_convergence_resets_when_analyze_finds_new()
fn test_convergence_threshold_one_stops_immediately()
fn test_convergence_restored_from_checkpoint()
```

---

### TEST-004: HypothesisBridge Needs a Mock Server Test
**Severity:** medium
**Effort:** medium
**Affected:** aegis-orchestrator
**Source confirmed:** partial

Tests for `HypothesisBridge` likely require a real Python process or mock. The IPC protocol (Unix socket, length-prefixed frames) should be tested in isolation:
- `write_ipc_frame` → `read_ipc_frame` round-trip
- Handling of oversized frames (> 64 MiB limit)
- Timeout behavior when server hangs
- Socket cleanup on Drop when Python has already exited

**Recommendation:** Create a `MockBridgeServer` in test-support that:
1. Listens on a Unix socket
2. Reads a `BridgeRequest` frame
3. Returns a canned `BridgeResponse`
Then test `HypothesisBridge::generate_hypotheses()` against the mock server without requiring Python.

---

### TEST-005: Audit Log Tamper Detection Tests
**Severity:** medium
**Effort:** small
**Affected:** aegis-audit-log
**Source confirmed:** partial

The audit log verification (`verify_log()`) should have tests that:
- Detect a modified entry (payload byte flipped)
- Detect a deleted entry (sequence gap)
- Detect an inserted entry (sequence mismatch)
- Detect HMAC failure (key mismatch)

These tests verify the security property that the audit log provides tamper evidence.

**Recommendation:** Add tests in `log_verifier_test.rs`:
```rust
fn test_detect_modified_payload()
fn test_detect_deleted_entry()
fn test_detect_wrong_hmac_key()
fn test_verify_clean_log_succeeds()
```

---

### TEST-006: Risk Scorer Defense Adjustment Constants Not Tested
**Severity:** medium
**Effort:** small
**Affected:** aegis-reporting
**Source confirmed:** yes (constants -30%, -20%, -40% confirmed in source)

The risk scorer applies defense adjustments (authentication -30%, rate-limiting -20%, WAF -40%). While the constants exist in source, there should be explicit tests verifying the math:
- A finding with severity 8.0 and WAF protection should score ≈ 4.8
- Combined defense adjustments should compound correctly
- A fully defended endpoint should have a minimum floor score (not reach 0)

**Recommendation:** Add test cases:
```rust
fn test_waf_applies_40_percent_reduction()
fn test_combined_defenses_compound()
fn test_defense_floor_is_nonzero()
```

---

### TEST-007: Property-Based Testing for GraphOperation Validation
**Severity:** medium
**Effort:** medium
**Affected:** aegis-knowledge-graph
**Source confirmed:** yes (proptest already used in knowledge-graph dev-deps)

`knowledge-graph` already includes `proptest` as a dev-dependency. The graph validation logic (edge whitelist, weight bounds, confidence bounds) would benefit from property-based testing to find edge cases:
- `prop_always_valid_edge_accepted()` — random valid triples never rejected
- `prop_invalid_edge_never_accepted()` — random invalid triples always rejected
- `prop_confidence_bounds_always_enforced()` — random f64 values are clamped

**Recommendation:** Expand the existing proptest coverage in `knowledge-graph` to cover all 28 valid edge triples and the bounds validation logic.

---

### TEST-008: Checkpoint Resume Integration Test
**Severity:** medium
**Effort:** medium
**Affected:** aegis-orchestrator
**Source confirmed:** partial

The CLAUDE.md says "4 Cross-scan tests: checkpoint resume, diff-mode SARIF..." are in Docker Tier 2 tests. However, checkpoint resume without Docker (unit-testable level) should verify:
- A scan interrupted at phase N resumes from phase N
- Phases already completed are actually skipped
- The checkpoint file is deleted on successful completion
- The convergence counter is correctly restored

**Recommendation:** Add tests that mock the phase execution functions and verify checkpoint skip logic without Docker.

---

### TEST-009: VulnerabilityClass Exhaustiveness Tests
**Severity:** medium
**Effort:** small
**Affected:** aegis-compliance, aegis-reporting
**Source confirmed:** yes (34 variants; compliance_mapper uses string matching)

There should be tests verifying that all 34 `VulnerabilityClass` variants are handled by:
- `compliance_mapper` (CWE mapping coverage)
- `class_mapper` (OWASP mapping coverage)
- `sarif_emitter` (rule ID generation)
- LLM prompt (all classes mentioned in system prompt)

**Recommendation:**
```rust
fn test_all_vulnerability_classes_have_cwe_mapping() {
    for class in VulnerabilityClass::iter() {  // requires strum
        assert!(cwe_for(class).is_some(), "{class} missing CWE mapping");
    }
}
```

---

### TEST-010: benchmark.rs Missing Criterion Integration
**Severity:** low
**Effort:** medium
**Affected:** aegis-knowledge-graph, aegis-fuzzing
**Source confirmed:** partial

Performance-sensitive code paths lack `criterion` benchmarks:
- `KnowledgeGraph::apply_operations()` with large batches
- `FuzzScheduler::enqueue()` / `dequeue()` under high load
- Regex-based endpoint extraction in discovery crate
- GraphQL field brute-force in enumeration crate

**Recommendation:** Add `[[bench]]` targets to the relevant crates and implement criterion benchmarks for the 3-5 most performance-sensitive operations.

---

### TEST-011: CBOR Certificate Round-Trip Tests
**Severity:** low
**Effort:** small
**Affected:** aegis-reporting
**Source confirmed:** partial

CBOR certificate serialization (`serialize_certificate()` / `deserialize_certificate()`) should have explicit round-trip tests for all 6 `CertificateType` variants. Serialization bugs in this code would silently corrupt evidence.

**Recommendation:**
```rust
fn test_fuzzing_certificate_round_trip()
fn test_chain_certificate_round_trip()
// ... for each CertificateType variant
```

---

### TEST-012: Integration Tests For All 34 VulnerabilityClass Variants
**Severity:** low
**Effort:** large
**Affected:** aegis-orchestrator (Docker Tier 2)
**Source confirmed:** yes (16 findings in express app ground truth, not all 34)

The Express Docker fixture app covers 16-17 of 34 vulnerability classes. The remaining ~17 classes (NoSqlInjection, XmlExternalEntity, CrossOriginMisconfiguration, RaceCondition, PrototypePollution, etc.) have no ground truth Docker test app.

**Recommendation:** Create additional Docker fixture apps (or extend existing ones) to cover the remaining vulnerability classes. This would allow automated regression testing for all 34 detection capabilities.
