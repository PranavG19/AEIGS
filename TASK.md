# WORKER TASK — Coverage-Guided Response Diffing

## status: DONE

## feature
AFL-style behavioral coverage tracking for black-box web fuzzing.

## crate
fuzzing

## files
- crates/fuzzing/src/coverage_tracker.rs
- crates/fuzzing/src/coverage_tracker_test.rs
- Wire into crates/fuzzing/src/lib.rs (pub mod coverage_tracker)

## what-it-does
Tracks "behavioral coverage" by hashing response structure (status code + header set + body
structure fingerprint + timing bucket + error message class). When a payload triggers a new
behavioral signature never seen before, it gets priority-boosted in the UCB1 scheduler.

This is AFL-style coverage guidance applied to black-box web testing. Each new response "shape"
indicates a new code path was hit, focusing the fuzzer on inputs that actually explore new
server behavior rather than hammering the same error page.

## architecture
```rust
/// Fingerprint of a response's behavioral signature
pub struct BehavioralSignature {
    pub status_bucket: u16,         // 2xx, 3xx, 4xx, 5xx
    pub header_set_hash: u64,       // hash of sorted header names
    pub body_structure_hash: u64,   // hash of body structure (tag tree for HTML, key tree for JSON)
    pub timing_bucket: u8,          // <10ms, <100ms, <500ms, <1s, >1s
    pub error_class: Option<String>, // extracted error type if present
    pub content_length_bucket: u8,  // bucketed response size
}

pub struct CoverageTracker {
    seen_signatures: HashSet<u64>,   // hash of BehavioralSignature
    signature_history: Vec<(BehavioralSignature, String)>, // sig → payload that triggered it
}

impl CoverageTracker {
    pub fn new() -> Self;
    pub fn record(&mut self, response: &FuzzResponse, payload: &str) -> CoverageResult;
    pub fn is_novel(&self, sig: &BehavioralSignature) -> bool;
    pub fn coverage_count(&self) -> usize;
    pub fn priority_boost(result: &CoverageResult) -> f64; // for UCB1 scheduler
}

pub enum CoverageResult {
    Novel(BehavioralSignature),  // new behavior discovered
    Known(u64),                   // already seen this signature
}
```

## acceptance-criteria
1. Given a mock server with 8 distinct code paths, identify all 8 as distinct behavioral signatures
2. Priority-boost payloads that trigger new signatures (boost value > 0)
3. Known signatures return zero boost
4. Body structure hashing works for HTML, JSON, and plain text
5. Timing buckets correctly classify response times
6. 20+ tests covering all signature components
7. Zero clippy warnings, cargo fmt clean

## patterns-to-follow
- Read existing crates/fuzzing/src/ for patterns (scheduler.rs, mutator.rs, oracle.rs)
- Use existing FuzzResponse type from protocol crate
- One public type per file
- Adjacent test file
- Builder pattern with `with_*` for config

## do-not
- Do NOT modify existing fuzzing files (scheduler.rs, mutator.rs, etc.)
- Do NOT modify protocol types
- Do NOT add heavy dependencies
