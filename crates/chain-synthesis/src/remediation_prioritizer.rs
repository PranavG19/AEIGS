use std::cmp::Ordering;
use std::collections::HashSet;

use crate::attack_graph::{AttackGraph, AttackNodeType};
use crate::path_analysis::all_simple_paths;

/// A single remediation recommendation with cost-benefit analysis.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RemediationItem {
    pub node_id: u64,
    pub label: String,
    pub attack_paths_removed: usize,
    pub attack_paths_remaining: usize,
    pub risk_reduction_pct: f64,
    pub priority_rank: usize,
}

/// Full remediation prioritization report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RemediationPlan {
    pub items: Vec<RemediationItem>,
    pub total_paths_before: usize,
    pub optimal_fix_order: Vec<u64>,
    pub cumulative_risk_reduction: Vec<f64>,
}

/// Prioritizes remediations by maximum risk reduction.
///
/// For each vulnerability node, simulates its removal from the graph
/// and measures how many attack paths disappear. Nodes whose removal
/// eliminates the most paths are prioritized first. Uses greedy
/// sequential removal to account for overlapping path coverage.
pub struct RemediationPrioritizer<'a> {
    graph: &'a AttackGraph,
    max_path_depth: usize,
}

impl<'a> RemediationPrioritizer<'a> {
    pub fn new(graph: &'a AttackGraph) -> Self {
        Self {
            graph,
            max_path_depth: 8,
        }
    }

    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_path_depth = depth;
        self
    }

    /// Produce a prioritized remediation plan.
    pub fn prioritize(&self) -> RemediationPlan {
        let entries = self.graph.entry_points();
        let assets = self.graph.assets();
        let all_paths = self.collect_all_paths(&entries, &assets);
        let total_before = all_paths.len();

        if total_before == 0 {
            return RemediationPlan {
                items: Vec::new(),
                total_paths_before: 0,
                optimal_fix_order: Vec::new(),
                cumulative_risk_reduction: Vec::new(),
            };
        }

        let vulns = self.graph.nodes_by_type(AttackNodeType::Vulnerability);
        let mut items: Vec<RemediationItem> = vulns
            .iter()
            .map(|&vid| {
                let paths_through = all_paths.iter().filter(|p| p.contains(&vid)).count();
                let remaining = total_before - paths_through;
                let reduction = paths_through as f64 / total_before as f64 * 100.0;

                RemediationItem {
                    node_id: vid,
                    label: self
                        .graph
                        .node(vid)
                        .map(|n| n.label.clone())
                        .unwrap_or_default(),
                    attack_paths_removed: paths_through,
                    attack_paths_remaining: remaining,
                    risk_reduction_pct: reduction,
                    priority_rank: 0,
                }
            })
            .collect();

        items.sort_by(|a, b| {
            b.attack_paths_removed
                .cmp(&a.attack_paths_removed)
                .then_with(|| {
                    b.risk_reduction_pct
                        .partial_cmp(&a.risk_reduction_pct)
                        .unwrap_or(Ordering::Equal)
                })
        });

        for (i, item) in items.iter_mut().enumerate() {
            item.priority_rank = i + 1;
        }

        let (optimal_order, cumulative_reduction) =
            self.greedy_sequential_removal(&all_paths, &vulns, total_before);

        RemediationPlan {
            items,
            total_paths_before: total_before,
            optimal_fix_order: optimal_order,
            cumulative_risk_reduction: cumulative_reduction,
        }
    }

    /// Greedy removal: at each step, remove the vulnerability that eliminates
    /// the most remaining paths. Accounts for overlapping coverage.
    fn greedy_sequential_removal(
        &self,
        all_paths: &[Vec<u64>],
        vulns: &[u64],
        total_before: usize,
    ) -> (Vec<u64>, Vec<f64>) {
        let mut remaining_paths: Vec<Vec<u64>> = all_paths.to_vec();
        let mut fixed: HashSet<u64> = HashSet::new();
        let mut order = Vec::new();
        let mut cumulative = Vec::new();
        let mut total_removed = 0usize;

        let available: Vec<u64> = vulns.to_vec();

        for _ in 0..available.len() {
            let mut best_id = None;
            let mut best_count = 0;

            for &vid in &available {
                if fixed.contains(&vid) {
                    continue;
                }
                let count = remaining_paths.iter().filter(|p| p.contains(&vid)).count();
                if count > best_count {
                    best_count = count;
                    best_id = Some(vid);
                }
            }

            let Some(chosen) = best_id else {
                break;
            };

            if best_count == 0 {
                break;
            }

            remaining_paths.retain(|p| !p.contains(&chosen));
            fixed.insert(chosen);
            total_removed += best_count;
            order.push(chosen);
            cumulative.push(total_removed as f64 / total_before as f64 * 100.0);
        }

        (order, cumulative)
    }

    fn collect_all_paths(&self, entries: &[u64], assets: &[u64]) -> Vec<Vec<u64>> {
        let mut paths = Vec::new();
        for &entry in entries {
            for &asset in assets {
                let found = all_simple_paths(self.graph, entry, asset, self.max_path_depth);
                for p in found {
                    paths.push(p.nodes);
                }
            }
        }
        paths
    }
}
