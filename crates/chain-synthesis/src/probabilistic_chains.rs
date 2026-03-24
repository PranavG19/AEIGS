use petgraph::graph::{DiGraph, EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};

/// An edge in the probabilistic attack graph carrying a Bayesian success probability.
///
/// Uses a Beta distribution model: `success_probability = alpha / (alpha + beta)`.
/// `evidence_count` tracks total observations. Priors default to Beta(1,1) (uniform).
/// `last_updated` is a Unix-epoch millisecond timestamp.
#[derive(Debug, Clone)]
pub struct ProbabilisticEdge {
    pub success_probability: f64,
    pub evidence_count: usize,
    pub last_updated: u64,
    alpha: f64,
    beta: f64,
}

impl ProbabilisticEdge {
    /// Create an edge with a known success probability and optional prior observations.
    /// `alpha` and `beta` are derived so that the mean matches `probability`.
    /// With zero evidence, they default to Beta(1,1) scaled by the given probability.
    pub fn new(probability: f64, evidence_count: usize, timestamp: u64) -> Self {
        let probability = probability.clamp(0.0, 1.0);
        let (alpha, beta) = if evidence_count == 0 {
            (1.0, 1.0)
        } else {
            let n = evidence_count as f64;
            (probability * n, (1.0 - probability) * n)
        };
        Self {
            success_probability: probability,
            evidence_count,
            last_updated: timestamp,
            alpha,
            beta,
        }
    }

    /// Variance of the Beta distribution: Var = alpha*beta / ((alpha+beta)^2 * (alpha+beta+1))
    pub fn variance(&self) -> f64 {
        let sum = self.alpha + self.beta;
        if sum <= 0.0 {
            return 0.0;
        }
        (self.alpha * self.beta) / (sum * sum * (sum + 1.0))
    }

    /// Update the edge probability via Bayesian posterior after observing a probe result.
    pub fn bayesian_update(&mut self, succeeded: bool, timestamp: u64) {
        if succeeded {
            self.alpha += 1.0;
        } else {
            self.beta += 1.0;
        }
        self.evidence_count += 1;
        self.success_probability = self.alpha / (self.alpha + self.beta);
        self.last_updated = timestamp;
    }

    pub fn alpha(&self) -> f64 {
        self.alpha
    }

    pub fn beta_param(&self) -> f64 {
        self.beta
    }
}

/// A node label in the probabilistic attack graph.
#[derive(Debug, Clone)]
pub struct ProbNode {
    pub label: String,
}

/// Entry in the Dijkstra-style priority queue for highest-EV path search.
/// Ordered by *descending* cumulative probability so BinaryHeap yields max-prob first.
#[derive(Debug, Clone)]
struct EvState {
    node: NodeIndex,
    cumulative_prob: f64,
    path: Vec<NodeIndex>,
}

impl PartialEq for EvState {
    fn eq(&self, other: &Self) -> bool {
        self.cumulative_prob == other.cumulative_prob
    }
}

impl Eq for EvState {}

impl PartialOrd for EvState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EvState {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cumulative_prob
            .partial_cmp(&other.cumulative_prob)
            .unwrap_or(Ordering::Equal)
    }
}

/// Engine for probabilistic attack-chain analysis over a petgraph DiGraph.
///
/// Wraps a directed graph where nodes represent attack stages and edges carry
/// Bayesian success probabilities. Supports:
/// - Top-K highest expected-value path enumeration
/// - Information-theoretic next-probe selection (maximum variance reduction)
/// - Online Bayesian posterior updates after probe success/failure
/// - Point expected-value queries between any source and target
pub struct ProbabilisticChainEngine {
    graph: DiGraph<ProbNode, ProbabilisticEdge>,
    label_map: HashMap<String, NodeIndex>,
}

impl ProbabilisticChainEngine {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            label_map: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, label: impl Into<String>) -> NodeIndex {
        let label = label.into();
        let idx = self.graph.add_node(ProbNode {
            label: label.clone(),
        });
        self.label_map.insert(label, idx);
        idx
    }

    pub fn add_edge(
        &mut self,
        source: NodeIndex,
        target: NodeIndex,
        probability: f64,
        evidence_count: usize,
        timestamp: u64,
    ) -> EdgeIndex {
        let edge = ProbabilisticEdge::new(probability, evidence_count, timestamp);
        self.graph.add_edge(source, target, edge)
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    pub fn node_by_label(&self, label: &str) -> Option<NodeIndex> {
        self.label_map.get(label).copied()
    }

    pub fn node_label(&self, idx: NodeIndex) -> &str {
        &self.graph[idx].label
    }

    pub fn edge_weight(&self, idx: EdgeIndex) -> Option<&ProbabilisticEdge> {
        self.graph.edge_weight(idx)
    }

    pub fn edge_weight_mut(&mut self, idx: EdgeIndex) -> Option<&mut ProbabilisticEdge> {
        self.graph.edge_weight_mut(idx)
    }

    pub fn inner_graph(&self) -> &DiGraph<ProbNode, ProbabilisticEdge> {
        &self.graph
    }

    /// Enumerate the top-K paths from `source` to `target` ranked by expected value
    /// (the product of edge success probabilities along the path).
    ///
    /// Uses a modified Dijkstra/BFS that explores paths in descending probability order.
    /// Each path is *simple* (no repeated nodes). The search terminates after `k` paths
    /// are found or all reachable simple paths are exhausted.
    pub fn highest_ev_paths(
        &self,
        source: NodeIndex,
        target: NodeIndex,
        k: usize,
    ) -> Vec<(Vec<NodeIndex>, f64)> {
        if k == 0 {
            return Vec::new();
        }

        let mut results: Vec<(Vec<NodeIndex>, f64)> = Vec::new();
        let mut heap = BinaryHeap::new();

        heap.push(EvState {
            node: source,
            cumulative_prob: 1.0,
            path: vec![source],
        });

        let max_iterations = 500_000;
        let mut iterations = 0;

        while let Some(state) = heap.pop() {
            iterations += 1;
            if iterations > max_iterations {
                break;
            }

            if state.node == target && state.path.len() > 1 {
                results.push((state.path.clone(), state.cumulative_prob));
                if results.len() >= k {
                    break;
                }
                continue;
            }

            let visited: HashSet<NodeIndex> = state.path.iter().copied().collect();

            for edge_ref in self.graph.edges_directed(state.node, Direction::Outgoing) {
                let next = edge_ref.target();
                if visited.contains(&next) {
                    continue;
                }
                let prob = edge_ref.weight().success_probability;
                let new_prob = state.cumulative_prob * prob;

                if new_prob < 1e-15 {
                    continue;
                }

                let mut new_path = state.path.clone();
                new_path.push(next);
                heap.push(EvState {
                    node: next,
                    cumulative_prob: new_prob,
                    path: new_path,
                });
            }
        }

        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
        results.truncate(k);
        results
    }

    /// Returns the edge whose probability has the highest variance — probing it
    /// would yield the greatest reduction in uncertainty about the attack graph.
    ///
    /// Variance of a Beta(α,β) is α·β / ((α+β)² · (α+β+1)). High variance means
    /// we're most uncertain about that step's success rate, so probing it is most informative.
    pub fn most_informative_probe(&self) -> Option<EdgeIndex> {
        self.graph.edge_indices().max_by(|&a, &b| {
            let va = self.graph[a].variance();
            let vb = self.graph[b].variance();
            va.partial_cmp(&vb).unwrap_or(Ordering::Equal)
        })
    }

    /// Update the posterior probability of an edge after observing a probe result.
    /// Uses conjugate Beta-Binomial update: success increments α, failure increments β.
    pub fn update_posterior(&mut self, edge: EdgeIndex, succeeded: bool) {
        let timestamp = current_timestamp_ms();
        if let Some(weight) = self.graph.edge_weight_mut(edge) {
            weight.bayesian_update(succeeded, timestamp);
        }
    }

    /// Compute the expected value (max-product probability) of reaching `target` from `source`.
    /// Returns the probability of the single highest-EV path, or 0.0 if unreachable.
    pub fn expected_value(&self, source: NodeIndex, target: NodeIndex) -> f64 {
        if source == target {
            return 1.0;
        }
        let paths = self.highest_ev_paths(source, target, 1);
        paths.first().map(|(_, p)| *p).unwrap_or(0.0)
    }

    /// Returns all edge indices in the graph, useful for iteration/inspection.
    pub fn all_edges(&self) -> Vec<EdgeIndex> {
        self.graph.edge_indices().collect()
    }

    /// Returns the endpoints (source, target NodeIndex) for a given edge.
    pub fn edge_endpoints(&self, idx: EdgeIndex) -> Option<(NodeIndex, NodeIndex)> {
        self.graph.edge_endpoints(idx)
    }

    /// Rank all edges by their variance (descending). Useful for batch probe planning.
    pub fn edges_by_uncertainty(&self) -> Vec<(EdgeIndex, f64)> {
        let mut edges: Vec<(EdgeIndex, f64)> = self
            .graph
            .edge_indices()
            .map(|idx| (idx, self.graph[idx].variance()))
            .collect();
        edges.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
        edges
    }

    /// Compute the expected value of all simple paths from source to target (sum of path
    /// probabilities). This represents the overall likelihood of *any* successful attack chain.
    pub fn total_path_probability(
        &self,
        source: NodeIndex,
        target: NodeIndex,
        max_paths: usize,
    ) -> f64 {
        let paths = self.highest_ev_paths(source, target, max_paths);
        paths.iter().map(|(_, p)| *p).sum()
    }
}

impl Default for ProbabilisticChainEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
