# aegis-fuzzing

<!-- metadata: crate purpose, public API, modules, fuzz scheduler, payload mutation, anomaly oracle, defense detection, WAF, rate limiting, bot detection, WebSocket, UCB1 -->

## Purpose

Core fuzzing engine for AEGIS. Implements the full fuzz execution pipeline: priority-based target scheduling (UCB1 BinaryHeap), payload mutation and generation (5 strategies), rate-limited HTTP execution via evasion transport, counterfactual anomaly detection, and defense detection (WAF/rate-limit/bot). Also contains merged defense-fingerprinting types (originally a separate crate). Includes specialized testers for specific vulnerability classes (GraphQL, IDOR, race conditions, CORS, mass assignment, subdomain takeover).

## Crate Type
Library

## Dependencies on Workspace Crates
- `aegis-knowledge-graph` — for reading endpoint nodes and writing finding nodes
- `aegis-protocol` — `FuzzRequest`, `FuzzResponse`, `VulnerabilityClass`, `OperationLogEntry`

## External Dependencies
- `reqwest` 0.12 (json) — HTTP client for fuzz requests
- `rand` 0.9 — payload randomization, mutation
- `regex` 1 — pattern-based payload generation
- `base64` 0.22 — payload encoding transforms
- `url` 2 — URL manipulation in payloads
- `uuid` 1 (v4) — request correlation IDs
- `serde`, `serde_json` — serialization
- `tokio` 1 — async execution
- `tracing` — structured logging

## Module Structure

| Module | Re-exported | Description |
|--------|-------------|-------------|
| `scheduler` | No | FuzzTarget priority queue (BinaryHeap, UCB1 scoring) |
| `mutator` | No | Payload mutation (5 MutationOrigin strategies) |
| `executor` | No | Async HTTP fuzzing with rate limiting |
| `oracle` | No | Counterfactual anomaly detection |
| `stealth_config` | No | StealthConfig presets (default/aggressive/paranoid/benchmark) |
| `defense_profile` | Yes | DefenseProfile builder (WAF + rate limit + bot detection) |
| `waf_fingerprinter` | Yes | WAF detection via response analysis |
| `rate_limit_detector` | Yes | Rate limit probing and measurement |
| `bot_detection_probe` | Yes | Bot detection fingerprinting |
| `payload_selector` | No | UCB1 multi-armed bandit for payload selection |
| `streaming_fuzzer` | No | WebSocket/SSE protocol-aware fuzzer |
| `request_patterns` | No | Concurrent request patterns (cover traffic) |
| `confirmation` | No | Finding confirmation (retest to reduce false positives) |
| `cors_detector` | Yes | CORS misconfiguration detection |
| `graphql_tester` | Yes | GraphQL-specific vulnerability testing |
| `header_analyzer` | Yes | HTTP security header analysis |
| `idor_tester` | Yes | IDOR heuristic detection |
| `mass_assignment_tester` | Yes | Mass assignment vulnerability testing |
| `race_tester` | Yes | Race condition testing (concurrent requests) |
| `cloud_detector` | Yes | Cloud misconfiguration detection |
| `subdomain_takeover` | Yes | Subdomain takeover detection |

## Public API Summary

### FuzzTarget

```rust
pub struct FuzzTarget {
    pub endpoint: String,
    pub method: String,
    pub parameter: String,
    pub parameter_location: ParameterLocation,
    pub vulnerability_class: VulnerabilityClass,
    pub priority_score: f64,    // Must be finite; NaN/Inf clamped to 0.0 on enqueue
    pub attempts: u32,
    pub max_attempts: u32,
}
```

### FuzzScheduler

```rust
pub struct FuzzScheduler {
    // private: BinaryHeap<PrioritizedTarget>, HashSet<DeduplicationKey>
}

impl FuzzScheduler {
    pub fn new() -> Self
    pub fn with_avoid_signatures(avoid: bool) -> Self
    pub fn enqueue(&mut self, target: FuzzTarget)     // deduplicates by (endpoint, method, vuln_class)
    pub fn dequeue(&mut self) -> Option<FuzzTarget>   // highest priority first
    pub fn len(&self) -> usize
    pub fn is_empty(&self) -> bool
    pub fn completed_count(&self) -> u64
    pub fn skipped_count(&self) -> u64
}
```

**Deduplication key:** `(endpoint, method, vulnerability_class)` — prevents scheduling the same endpoint+method+class pair twice.

**Priority:** Targets use `priority_score` ordering in a max-heap. NaN/Inf values are clamped to 0.0.

### MutationOrigin (5 strategies)

```rust
pub enum MutationOrigin {
    Template,      // Fixed payload templates per vulnerability class
    Generative,    // Pattern-generated variations
    BitFlip,       // Bit-level mutations of existing payloads
    Boundary,      // Boundary/edge case values (empty, max-length, etc.)
    BypassCorpus,  // WAF bypass examples from corpus JSON
}

pub struct TaggedPayload {
    pub payload: String,
    pub origin: MutationOrigin,
}
```

### DefenseProfile (merged from defense-fingerprinting)

```rust
pub struct DefenseProfile {
    pub waf: Option<WafFingerprint>,
    pub rate_limit: Option<RateLimitProfile>,
    pub bot_detection: Option<BotDetectionResult>,
    // builder: with_waf(), with_rate_limit(), with_bot_detection()
}
```

### StealthConfig

```rust
pub struct StealthConfig {
    // presets:
    pub fn default() -> Self          // Standard timing, no jitter
    pub fn aggressive() -> Self       // Faster, less jitter
    pub fn paranoid() -> Self         // Slow, maximum jitter
    pub fn benchmark() -> Self        // No delays for benchmarking
    // builder methods: with_max_rps(), with_jitter_ms(), ...
}
```

### PayloadSelector (UCB1)

```rust
pub struct PayloadSelector {
    // UCB1 multi-armed bandit
}
impl PayloadSelector {
    pub fn ucb1_score(&self, arm_index: usize) -> f64  // Infinite for novel payloads
    pub fn record_outcome(&mut self, arm_index: usize, success: bool)
    pub fn select_arm(&self) -> usize
}
```

## Key Implementation Notes

- **Defense-fingerprinting merged**: WAF/rate-limit/bot-detection types were merged into this crate. Use `use aegis_fuzzing::DefenseProfile` (not a separate crate import).
- **FuzzRequest/FuzzResponse re-exported** from `aegis-protocol` for backwards compatibility: `use aegis_fuzzing::FuzzRequest` works.
- **Counterfactual oracle**: For each test payload, a paired "control" request with benign payload is sent. Anomaly detected when treatment ≠ control — eliminates false positives from broken endpoints.
- **UCB1 bandit scoring**: Novel payloads (zero trials) get `f64::INFINITY` score — always selected first. Standard UCB1: `mean + C * sqrt(ln(total) / trials)` where `C = sqrt(2)`.
- **MAX_BATCH_SIZE = 64** in `request_patterns` — burst/parallel batches clamped at this limit.
- **NaN handling in scheduler**: `enqueue()` clamps non-finite `priority_score` to 0.0 before insertion (prevents heap ordering panics).

## Usage Context

Used in the `fuzz` phase of the scan pipeline. `run_fuzz()` in `crates/orchestrator/src/phase_fuzz.rs` calls the scheduler, mutator, and executor. The phase returns `FuzzPhaseResult` containing `Vec<OperationLogEntry>` with discovered findings.
