# WORKER TASK — Adaptive WAF Grammar Inference

## status: IN PROGRESS

## feature
Adaptive WAF Grammar Inference Engine — reverse-engineers WAF rule grammars in real-time.

## crate
evasion-engine

## files
- crates/evasion-engine/src/waf_grammar.rs (main implementation)
- crates/evasion-engine/src/waf_grammar_test.rs (tests)
- Wire into crates/evasion-engine/src/lib.rs (pub mod waf_grammar)

## what-it-does
Sends probe sequences to a target and observes block/allow patterns to reverse-engineer WAF rules.
Builds a formal grammar model of what the WAF rejects. Uses binary-search-style probing to find
exact rule boundaries, then generates minimal bypass payloads that thread the needle.

No public tool does automated WAF grammar extraction — they all use static bypass lists.
This makes every other AEGIS module smarter because it feeds learned grammars back to the
payload forge and fuzzer.

## architecture
```rust
/// A single WAF rule recovered from probing
pub struct InferredWafRule {
    pub pattern: String,           // regex-like pattern the WAF matches
    pub confidence: f64,           // 0.0-1.0 how certain we are
    pub blocked_samples: Vec<String>,  // payloads that triggered this rule
    pub allowed_samples: Vec<String>,  // payloads that bypassed this rule
    pub boundary_chars: Vec<char>,     // chars at the rule boundary
}

/// The complete grammar model
pub struct WafGrammar {
    pub rules: Vec<InferredWafRule>,
    pub probe_count: usize,
    pub false_positive_rate: f64,
}

/// Probe strategies
pub enum ProbeStrategy {
    BinarySearch,      // bisect payloads to find exact boundary
    CharSubstitution,  // swap chars to find what triggers/bypasses
    EncodingLadder,    // try none→URL→double-URL→Unicode→hex
    CaseMutation,      // case variations to find case-sensitivity
    NullByteInsertion, // insert null bytes at positions
    WhitespaceProbing, // different whitespace chars (tab, nbsp, etc.)
    CommentInjection,  // SQL/HTML/JS comments between tokens
    TokenSplitting,    // break tokens across encoding boundaries
}

/// Main engine
pub struct WafGrammarInference {
    // Takes a function that sends a probe and returns blocked/allowed
    // This lets it work with any HTTP backend
}

impl WafGrammarInference {
    pub fn new() -> Self;
    pub fn infer_grammar(probes: &[ProbeResult]) -> WafGrammar;
    pub fn generate_bypass(grammar: &WafGrammar, payload: &str) -> Vec<String>;
    pub fn suggest_next_probe(grammar: &WafGrammar) -> Vec<String>;
}
```

## acceptance-criteria
1. Given a mock WAF that blocks patterns matching 5+ regex rules, recover ≥80% of rule boundaries within 200 probes
2. Generate at least 1 bypass payload per recovered rule
3. Export grammar model as a serializable struct other modules can consume
4. 8+ probe strategies implemented (binary search, char substitution, encoding ladder, case mutation, null bytes, whitespace, comments, token splitting)
5. 20+ tests covering rule recovery, false-positive handling, bypass generation
6. Zero clippy warnings, cargo fmt clean
7. All existing evasion-engine tests still pass

## patterns-to-follow
- One public type per file (WafGrammarInference is the main public type)
- Adjacent test file: waf_grammar_test.rs
- Builder pattern with `with_*` for config
- Follow existing evasion-engine patterns (see persona.rs, tls_config.rs)
- `///` doc comments on public types with invariants/contracts
- Functions ≤40 lines

## do-not
- Do NOT modify any files outside evasion-engine
- Do NOT touch lib.rs beyond adding `pub mod waf_grammar`
- Do NOT add new dependencies to Cargo.toml unless absolutely necessary
- Do NOT run scans against real targets
