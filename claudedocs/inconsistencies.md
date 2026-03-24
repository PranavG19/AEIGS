# AEGIS Documentation Inconsistencies

Generated: 2026-02-23
Cross-document consistency review.

## Issues Found

### 1. Crate Count Discrepancy (Low Severity)

**Location:** CLAUDE.md says "15 Rust crates" but workspace has 17 members.

**Details:**
- CLAUDE.md headline: "15 Rust crates + 1 Python package"
- Actual workspace: 17 Rust crates (includes `crawler`, `test-support`)
- `WORKSPACE_CRATE_COUNT = 11` constant in `crates/orchestrator/src/pipeline.rs:1705` is further outdated

**Resolution:** CLAUDE.md and the constant are outdated documentation. The workspace_info.md is correct (17 crates).

---

### 2. Crawler Integration Status (Medium Severity)

**Location:** `crates/orchestrator/src/pipeline.rs:1533`, `crate_docs/aegis-crawler.md`, `workflows.md`

**Details:**
- CLAUDE.md states: `crawler: Directory brute-forcing (2,013 paths), JS endpoint extraction (7 regex patterns)...`
- This description actually describes `aegis-discovery`, not `aegis-crawler`
- `aegis-crawler` is a headless browser crawler (chromiumoxide/CDP)
- `run_crawl_phase()` currently uses `CrawlResult::default()` — crawler not wired into live scan
- The crawler crate is more capable than documented in CLAUDE.md

**Resolution:** `workflows.md` and `crate_docs/aegis-crawler.md` document the actual state. The CLAUDE.md conflates discovery and crawler crates.

---

### 3. FuzzRequest/FuzzResponse Re-export Note (Low Severity)

**Location:** CLAUDE.md "Known Pitfalls", `crate_docs/aegis-fuzzing.md`

**Details:**
- CLAUDE.md says: "FuzzRequest/FuzzResponse in protocol crate — shared HTTP types avoid backwards dependency from evasion-engine to fuzzing; re-exported by fuzzing for backwards compatibility"
- This is accurate but the re-export pattern is inconsistently documented: `type_system.md` says "Re-exported by fuzzing crate for backwards compatibility" which is correct

**Resolution:** No action needed — consistent.

---

### 4. `EvidenceLevel::Controlled` Naming (Low Severity)

**Location:** `crates/protocol/src/finding.rs:151`, `type_system.md`, CLAUDE.md

**Details:**
- The current variant name is `Controlled` with `#[serde(alias = "Counterfactual")]`
- CLAUDE.md correctly documents this
- `type_system.md` correctly documents this
- However, CLAUDE.md also says "the anomaly oracle still uses 'counterfactual' in method names" which is consistent

**Resolution:** No inconsistency. Documentation is aligned.

---

### 5. Fuzzing Crate Module Count (Low Severity)

**Location:** CLAUDE.md Architecture section, `crate_docs/aegis-fuzzing.md`, `code_analysis/module_tree.md`

**Details:**
- CLAUDE.md lists fuzzing modules but omits several new ones present in `lib.rs`:
  `confirmation`, `cors_detector`, `graphql_tester`, `header_analyzer`, `idor_tester`, `mass_assignment_tester`, `race_tester`, `cloud_detector`, `subdomain_takeover`
- These are public modules re-exported via `pub use` wildcard
- The new modules implement VulnerabilityClass-specific testers (CorsMisconfiguration, GraphQlAbuse, etc.)

**Resolution:** `crate_docs/aegis-fuzzing.md` and `module_tree.md` document the actual state. CLAUDE.md is outdated.

---

### 6. `phase_dom_verify` Phase (Low Severity)

**Location:** `crates/orchestrator/src/pipeline.rs`, `workflows.md`, CLAUDE.md

**Details:**
- CLAUDE.md scan pipeline: `recon → crawl → fingerprint → (fuzz → analyze)* → dom_verify → report`
- `pipeline.rs` imports `use crate::phase_dom_verify::run_dom_verify;`
- The `phase_dom_verify` module exists and is called in the pipeline
- CLAUDE.md does not list this module in the orchestrator module listing
- `workflows.md` documents this correctly

**Resolution:** `workflows.md` is accurate. `crate_docs/aegis-orchestrator.md` includes `phase_dom_verify` in the module table.

---

### 7. `ScanContextJson` Type Alias (Low Severity)

**Location:** CLAUDE.md "Known Pitfalls", `crate_docs/aegis-orchestrator.md`

**Details:**
- CLAUDE.md: "`ScanContextJson` (type alias for `ScanContextIpc`)"
- This is correct — `hypothesis_bridge.rs` re-exports `ScanContextIpc` as `ScanContextJson`
- `interfaces.md` documents `ScanContextIpc` as the canonical type (correct)

**Resolution:** No inconsistency. The type alias is implementation detail.

---

---

### 8. aegis-chain-synthesis Dependency Declaration (Low Severity — Fixed)

**Location:** `crate_docs/aegis-chain-synthesis.md`

**Details:**
- An earlier draft of the chain-synthesis crate doc stated "None. This crate has no internal workspace dependencies"
- `crates/chain-synthesis/Cargo.toml` lists `aegis-protocol` and `aegis-knowledge-graph` as dependencies
- **This was corrected** in `crate_docs/aegis-chain-synthesis.md` — the dependencies are now accurately documented
- The `AttackGraph` type itself is self-contained, but the crate does use protocol/knowledge-graph types for construction helpers

---

---

### 9. IPC Transport: RESOLVED — was analysis error (Low Severity)

**Location:** `crates/orchestrator/src/hypothesis_bridge.rs`

**Details:**
- Initial documentation incorrectly stated the IPC transport was "stdin/stdout JSON lines"
- The correct transport is **Unix domain socket** at `/tmp/aegis-hypothesis-{pid}-{timestamp}.sock` with 4-byte LE u32 length-prefixed JSON frames
- `hypothesis_bridge.rs` contains BOTH: an older inline stdin/stdout helper function AND the current `HypothesisBridge` struct (persistent socket)
- Pipeline.rs calls `HypothesisBridge::start()` which uses the socket implementation

**Resolution:** `interfaces.md` has been corrected. The doc comment in `hypothesis_ipc.rs` was correct all along — the initial analysis misread the file.

---

### 10. `ScanCheckpoint` Field Names (Low Severity)

**Location:** `crates/orchestrator/src/pipeline.rs:770-780`, `crates/orchestrator/src/checkpoint.rs`

**Details:**
- `data_models.md` documents `ScanCheckpoint` with fields `completed_phases`, `current_iteration`, `total_operations`, `total_findings`, `consecutive_zero_findings`, `timestamp_unix_ms`
- An analysis agent documented it differently as `completed_phases`, `iteration_count`, `findings_count`
- The pipeline.rs construction site (`pipeline.rs:770-780`) confirms the longer field set is correct

**Resolution:** `data_models.md` reflects the accurate fields.

---

---

### 11. `compliance_mapper` Matches on Display Strings (Medium Severity — Maintenance Risk)

**Location:** `crates/compliance/src/compliance_mapper.rs`

**Details:**
- `compliance_mapper` matches on `VulnerabilityClass::Display` strings rather than enum variants
- `class_mapper` and `compliance_mapper` have exhaustive `match` expressions over all 34 `VulnerabilityClass` variants for CWE/OWASP mappings
- However, the `compliance_mapper` matching pattern means adding a new `VulnerabilityClass` variant will NOT produce a compile-time error — it will silently produce no compliance mapping
- This is a silent maintenance failure mode (no exhaustiveness check by the compiler)

**Resolution:** When adding a new `VulnerabilityClass` variant, must also update `compliance_mapper` string matching manually. Add to checklist in CLAUDE.md.

---

## No Critical Inconsistencies Found

The documentation is broadly consistent. The issues above are primarily:
- Outdated counts in CLAUDE.md (not in the new documentation)
- Implementation gaps (crawler not fully wired) that are accurately documented
- New modules added since CLAUDE.md was last updated
