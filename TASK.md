# WORKER TASK — Probabilistic Attack Chain Synthesis

## status: DONE

## feature
Extend the existing petgraph attack graph in chain-synthesis with Bayesian probability propagation.

## crate
chain-synthesis

## files
- crates/chain-synthesis/src/probabilistic_chains.rs
- crates/chain-synthesis/src/probabilistic_chains_test.rs
- Wire into crates/chain-synthesis/src/lib.rs (pub mod probabilistic_chains)

## what-it-does
Each edge in the attack graph carries a success probability. The engine computes
expected-value-optimal attack paths, not just shortest paths. Answers: "Given an XSS on
/api/user and a weak JWT, what's the probability of reaching admin RCE through a 3-step chain,
and which intermediate step should we invest fuzzing time in?"

This is the intelligence layer that makes the Brain's chain reasoning quantitative instead of
vibes-based. No public tool does probabilistic multi-step attack planning.

## architecture
```rust
pub struct ProbabilisticEdge {
    pub success_probability: f64,  // 0.0-1.0
    pub evidence_count: usize,     // how many times tested
    pub last_updated: u64,         // timestamp
}

pub struct ProbabilisticChainEngine {
    // wraps existing petgraph DiGraph, adds probability layer
}

impl ProbabilisticChainEngine {
    pub fn new() -> Self;
    /// Top-K paths by expected value (product of edge probabilities)
    pub fn highest_ev_paths(&self, source: NodeIndex, target: NodeIndex, k: usize) -> Vec<(Vec<NodeIndex>, f64)>;
    /// Which edge, if probed next, would reduce the most uncertainty?
    pub fn most_informative_probe(&self) -> Option<EdgeIndex>;
    /// Update edge probability after a probe succeeds or fails
    pub fn update_posterior(&mut self, edge: EdgeIndex, succeeded: bool);
    /// Expected value of reaching target from source
    pub fn expected_value(&self, source: NodeIndex, target: NodeIndex) -> f64;
}
```

## acceptance-criteria
1. Given a graph with 20+ nodes and known edge probabilities, correctly compute top-3 highest EV paths
2. "Most informative next probe" returns the edge with highest variance reduction
3. Posterior updates after probe success/failure match Bayesian calculation
4. Compare against manual calculation on 3 fixture graphs
5. 25+ tests
6. Zero clippy warnings, cargo fmt clean

## patterns-to-follow
- Read existing crates/chain-synthesis/src/ for patterns (attack_graph.rs, path_analysis.rs)
- One public type per file
- Adjacent test file
- Use petgraph types from existing code
- `///` doc comments on public types

## do-not
- Do NOT modify files outside chain-synthesis crate
- Do NOT modify attack_graph.rs or path_analysis.rs (only add new file)
- Do NOT add heavy dependencies
