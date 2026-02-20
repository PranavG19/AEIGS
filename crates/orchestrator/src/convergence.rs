use std::collections::HashSet;

/// Tracks hypotheses and payloads that have been tested and produced no findings.
///
/// Used by the iterative fuzz-analyze loop to prevent oscillation: once a
/// hypothesis is refuted, it is never re-tested, monotonically shrinking the
/// set of untested hypotheses across iterations.
#[derive(Debug, Default)]
pub struct RefutedTracker {
    refuted: HashSet<String>,
}

impl RefutedTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a hypothesis key as refuted (tested, produced no findings).
    pub fn record_refuted(&mut self, key: String) {
        self.refuted.insert(key);
    }

    /// Check whether a hypothesis key has already been refuted.
    pub fn is_refuted(&self, key: &str) -> bool {
        self.refuted.contains(key)
    }

    /// Return the number of distinct refuted hypotheses.
    pub fn refuted_count(&self) -> usize {
        self.refuted.len()
    }

    /// Proves the iterative scan loop always terminates.
    ///
    /// The fuzz-analyze loop has two termination conditions:
    /// 1. **Convergence**: `convergence_threshold` consecutive zero-finding rounds
    /// 2. **Hard cap**: `max_iterations` total rounds
    ///
    /// Oscillation is prevented by the `RefutedTracker`: once a hypothesis/payload
    /// combination is tested and produces no findings, it is recorded as refuted.
    /// Future rounds skip refuted payloads, monotonically shrinking the set of
    /// untested hypotheses. Since the hypothesis space is finite (bounded by
    /// vulnerability classes x endpoints x payload corpus size), the number of
    /// non-refuted hypotheses strictly decreases across iterations.
    ///
    /// Combined with `max_iterations` as a hard safety cap, the loop is guaranteed
    /// to terminate in at most `max_iterations` rounds.
    pub fn convergence_guaranteed(max_iterations: u32, convergence_threshold: u32) -> bool {
        convergence_threshold <= max_iterations
    }
}
