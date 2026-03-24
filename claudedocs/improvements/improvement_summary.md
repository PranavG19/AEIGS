# AEGIS Improvement Analysis Summary

Generated: 2026-02-23
Source documentation: `claudedocs/current_state/`
Source depth: 2 (high/critical findings verified against source code)

---

## Finding Counts

| Category | Critical | High | Medium | Low | Total |
|----------|---------|------|--------|-----|-------|
| Architecture | 0 | 2 | 4 | 5 | 11 |
| Type System | 0 | 1 | 4 | 7 | 12 |
| Performance | 0 | 1 | 2 | 5 | 8 |
| Simplification | 0 | 1 | 2 | 7 | 10 |
| Safety | 0 | 1 | 3 | 5 | 9 |
| Idiom | 0 | 0 | 2 | 9 | 11 |
| Testing | 0 | 2 | 3 | 7 | 12 |
| Dependencies | 0 | 0 | 2 | 8 | 10 |
| **TOTAL** | **0** | **8** | **22** | **53** | **83** |

**No critical issues found.** The codebase is architecturally sound with no safety-critical bugs. The high-severity issues are primarily architectural debt and correctness improvements.

---

## Top 10 Highest-Impact Improvements

### 1. [HIGH] Wire the Three Unintegrated Feature Modules (ARCH-002)
Three implemented features (1,585 lines with tests) are publicly exported but not called from `run_scan()`: `IdorAnalyzer`, `AdaptiveScanStrategy`, and distributed scanning. Users who set `--distributed` get no behavior. This is the most confusing gap in the codebase.

### 2. [HIGH] Blocking std::fs I/O on Tokio Async Thread (SAFETY-001 / PERF-001)
Zero uses of `tokio::fs` or `spawn_blocking` in the entire codebase. Checkpoint writes, SARIF output, and telemetry all block the async runtime. Combined with frequent audit log writes, this could cause measurable latency spikes on slower storage.

### 3. [HIGH] Wire the Crawler into the Scan Pipeline (ARCH-005)
`run_crawl_phase()` always uses `CrawlResult::default()` — an empty result. The crawler crate (with chromiumoxide CDP) is compiled and tested but never invoked in production. Every scan silently skips the crawl phase.

### 4. [HIGH] Orchestrator God Crate (ARCH-001)
30+ modules in a single crate. Testing is harder because all these modules share one compilation unit. Separating `llm-bridge`, `pipeline-core`, and public scan API would improve testability and build times.

### 5. [HIGH] GraphOperation::AddFinding Bypasses Confidence Type (TYPE-001)
`GraphOperation::AddFinding` uses `confidence: f64` instead of `Confidence`. The validated type is unwrapped at call sites and the graph operation log re-validates. This loses the type safety benefit of the `Confidence` newtype for the most critical operation in the pipeline.

### 6. [HIGH] std::sync::Mutex Poisoning Risk (SAFETY-002)
Interactive session uses `std::sync::Mutex` with 6 `lock().unwrap()` calls. If any thread holding the lock panics, all future lock attempts panic too — crashing the scan. Use parking_lot::Mutex.

### 7. [HIGH] Zero Doc Test Examples (TEST-001)
No public API has `/// # Examples` documentation. For a library with complex invariants (`Confidence::new()` validates bounds, `KnowledgeGraph::apply_operations()` validates semantics), doc tests are the first line of defense and the primary discoverability mechanism.

### 8. [HIGH] Crawler Test Coverage Gap (TEST-002)
No integration tests cover the crawl phase behavior. When the crawler is wired, there will be no regression safety net.

### 9. [MEDIUM] compliance_mapper String Matching Bypass (ARCH-009)
`compliance_mapper` matches on Display strings, not enum variants. Adding a `VulnerabilityClass` variant silently produces no compliance mapping. This is a hidden maintenance trap.

### 10. [MEDIUM] StealthLevel Stored as String Instead of Enum (TYPE-006 / IDIOM-002)
`StealthOptions::stealth_level: String` exists alongside `StealthLevel` enum. Invalid values are caught late (at pipeline start), and the enum variant's compile-time exhaustiveness checking is not leveraged.

---

## Quick Wins (High Impact, Small Effort)

These can be done in hours each without risk of regression:

| ID | Change | Benefit |
|----|--------|---------|
| ARCH-011 | Fix `WORKSPACE_CRATE_COUNT = 11` → `17` | Telemetry accuracy |
| TYPE-001 | `GraphOperation::AddFinding::confidence: Confidence` not `f64` | Type safety |
| TYPE-004 | Remove `ScanContextJson` alias, use `ScanContextIpc` directly | Clarity |
| TYPE-006 | `StealthOptions::stealth_level: StealthLevel` with clap ValueEnum | Early validation |
| TYPE-007 | Name the EvidenceLevel confidence constants | Documentation |
| TYPE-011 | Add `TryFrom<&str>` for `StealthLevel`, `PersonaId`, `ReportFormat` | Idiomatic API |
| SAFETY-002 | Replace `std::sync::Mutex` with `parking_lot::Mutex` for interactive session | Safety |
| SAFETY-008 | Add `zeroize` feature to `ed25519-dalek` | Security hygiene |
| SIMP-004 | Fix stale `WORKSPACE_CRATE_COUNT` constant | Accuracy |
| SIMP-006 | Make `auth_session` `pub(crate)` (not `pub mod`) | Smaller public API |
| IDIOM-001 | Add `TryFrom<&str>` for conversion functions | Idiomatic |
| IDIOM-007 | Add `#[must_use]` to all builder methods | Prevents bugs |
| IDIOM-011 | Add `[workspace.lints.clippy]` configuration | Zero-warnings enforcement |
| DEP-001 | Replace `tokio = {features = ["full"]}` with specific features | Compile time |
| DEP-004 | Standardize on parking_lot for all Mutex uses | Consistency |
| DEP-008 | Add `zeroize` feature to ed25519-dalek | Security |
| TEST-003 | Add convergence edge case unit tests | Test coverage |
| TEST-005 | Add audit log tamper detection tests | Security validation |
| TEST-006 | Add risk scorer defense constant tests | Correctness |
| TEST-011 | Add CBOR certificate round-trip tests | Serialization safety |
| ARCH-009 | Fix `compliance_mapper` to match enum variants | Compile-time safety |

**Estimated total quick wins effort: 4-6 engineering days**

---

## Strategic Improvements (High Impact, High Effort)

These require planning but have the highest architectural impact:

| ID | Change | Estimated Effort | Impact |
|----|--------|-----------------|--------|
| ARCH-001 | Extract orchestrator god crate | 2-3 weeks | Testability, compile time |
| ARCH-002 | Wire distributed scanning + IdorAnalyzer + AdaptiveScanStrategy | 1 week | Feature completeness |
| ARCH-005 | Wire crawler into scan pipeline | 1 week | Discovery capability |
| PERF-001 | Replace blocking std::fs with tokio::fs | 3-4 days | Runtime correctness |
| TYPE-002 | Replace NodeData property bag with typed properties | 2 weeks | Type safety across all phases |
| TEST-012 | Add Docker fixture apps for remaining vuln classes | 2 weeks | Detection coverage |

---

## "While You're There" Improvements

Group these with related changes to maximize developer context:

**When working on the fuzz phase (phase_fuzz.rs):**
- SIMP-006: Make `auth_session` pub(crate)
- PERF-003: Add combined generate_and_compile() RPC to hypothesis bridge
- TEST-004: Add MockBridgeServer for HypothesisBridge tests

**When adding a new VulnerabilityClass variant:**
- ARCH-009: Fix compliance_mapper string matching → enum matching
- TYPE-009: Add Crawler and DomVerify to ModuleIdentifier
- TEST-009: Add VulnerabilityClass exhaustiveness test

**When working on the knowledge graph:**
- TYPE-001: Fix AddFinding confidence f64 → Confidence
- PERF-005: Add batch query methods to GraphStore
- TEST-007: Add proptest coverage for validation logic

**When improving error handling:**
- TYPE-003: Convert String error variants to structured variants with thiserror
- SAFETY-003: Add INVARIANT: comments to undocumented unwrap() calls
- IDIOM-001: Add TryFrom for string-to-enum conversions

---

## Priority Matrix

```
                HIGH IMPACT
                    │
    ARCH-002 ───────┼──────── ARCH-001
    ARCH-005        │         PERF-001
    SAFETY-001      │         TYPE-002
                    │
SMALL ──────────────┼──────────────── LARGE
EFFORT              │                 EFFORT
    TYPE-001 ───────┼────────── ARCH-005
    SAFETY-002      │           TEST-012
    TYPE-006        │
    Quick wins      │
                    │
                LOW IMPACT
```

---

## Impact by Crate

| Crate | Finding Count | Highest Severity |
|-------|-------------|-----------------|
| aegis-orchestrator | 31 | High |
| aegis-protocol | 12 | High |
| aegis-knowledge-graph | 8 | Medium |
| aegis-fuzzing | 6 | Medium |
| aegis-reporting | 5 | Medium |
| aegis-audit-log | 4 | Medium |
| aegis-evasion-engine | 4 | Low |
| aegis-compliance | 3 | Medium |
| aegis-supervisor | 3 | Medium |
| aegis-crawler | 3 | High |

The orchestrator crate accounts for 37% of all findings — consistent with its god-crate status.

---

## Phased Improvement Plan

### Phase 1: Safety + Quick Wins (1-2 weeks)
Eliminate correctness risks and fix the lowest-effort issues:
1. Fix `std::sync::Mutex` → `parking_lot::Mutex` (SAFETY-002)
2. Fix blocking I/O in async context (SAFETY-001 / PERF-001)
3. Fix `WORKSPACE_CRATE_COUNT` constant (ARCH-011)
4. Add `TryFrom` for StealthLevel, PersonaId, ReportFormat (TYPE-011)
5. Fix `compliance_mapper` string matching (ARCH-009)
6. Add `#[must_use]` to builder methods (IDIOM-007)
7. Configure workspace lints (IDIOM-011)

### Phase 2: Core Type Safety + Wiring (2-4 weeks)
Fix the type system gaps and wire the incomplete features:
1. `GraphOperation::AddFinding::confidence: Confidence` (TYPE-001)
2. `StealthOptions::stealth_level: StealthLevel` (TYPE-006)
3. Wire crawler into scan pipeline (ARCH-005)
4. Wire IdorAnalyzer into pipeline or document as unintegrated (ARCH-002)
5. Add doc tests for top 10 APIs (TEST-001)
6. Add audit log tamper tests (TEST-005)

### Phase 3: Architecture + Advanced (Ongoing)
The larger structural improvements:
1. Extract orchestrator god crate (ARCH-001)
2. Replace NodeData property bag (TYPE-002)
3. Wire distributed scanning or formally deprecate (ARCH-002 distributed component)
4. Add Docker fixture apps for remaining vuln classes (TEST-012)
