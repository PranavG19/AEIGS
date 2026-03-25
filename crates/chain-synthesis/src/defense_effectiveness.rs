use crate::attack_graph::{AttackGraph, AttackNodeType};
use crate::path_analysis::all_simple_paths;

/// Per-defense effectiveness metrics.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DefenseScore {
    pub defense_node_id: u64,
    pub defense_label: String,
    pub attacks_blocked: usize,
    pub attacks_total: usize,
    pub block_rate: f64,
    pub protected_assets: Vec<u64>,
    pub weakness_notes: Vec<String>,
}

/// Overall defense effectiveness report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DefenseEffectivenessReport {
    pub defense_scores: Vec<DefenseScore>,
    pub weakest_defense: Option<String>,
    pub strongest_defense: Option<String>,
    pub overall_block_rate: f64,
    pub unprotected_paths: usize,
    pub total_paths: usize,
}

/// Scores defense effectiveness based on attack path analysis.
///
/// For each security boundary node, counts how many attack paths it
/// blocks versus how many bypass it. Identifies the weakest link in
/// the defensive posture.
pub struct DefenseEffectivenessScorer<'a> {
    graph: &'a AttackGraph,
    max_path_depth: usize,
}

impl<'a> DefenseEffectivenessScorer<'a> {
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

    /// Score all defense (SecurityBoundary) nodes in the graph.
    pub fn score(&self) -> DefenseEffectivenessReport {
        let entry_points = self.graph.entry_points();
        let assets = self.graph.assets();
        let defenses = self.graph.nodes_by_type(AttackNodeType::SecurityBoundary);

        let all_paths = self.collect_all_paths(&entry_points, &assets);
        let total_paths = all_paths.len();

        let mut defense_scores: Vec<DefenseScore> = defenses
            .iter()
            .map(|&def_id| self.score_defense(def_id, &all_paths, &assets))
            .collect();

        defense_scores.sort_by(|a, b| {
            a.block_rate
                .partial_cmp(&b.block_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let unprotected = all_paths
            .iter()
            .filter(|path| {
                !path.iter().any(|&node_id| {
                    self.graph
                        .node(node_id)
                        .map(|n| n.node_type == AttackNodeType::SecurityBoundary)
                        .unwrap_or(false)
                })
            })
            .count();

        let overall_block_rate = if total_paths > 0 {
            1.0 - (unprotected as f64 / total_paths as f64)
        } else {
            0.0
        };

        let weakest = defense_scores.first().map(|d| d.defense_label.clone());
        let strongest = defense_scores.last().map(|d| d.defense_label.clone());

        DefenseEffectivenessReport {
            defense_scores,
            weakest_defense: weakest,
            strongest_defense: strongest,
            overall_block_rate,
            unprotected_paths: unprotected,
            total_paths,
        }
    }

    fn score_defense(&self, def_id: u64, all_paths: &[Vec<u64>], assets: &[u64]) -> DefenseScore {
        let node = self.graph.node(def_id).expect("defense node must exist");

        let paths_through: Vec<&Vec<u64>> = all_paths
            .iter()
            .filter(|path| path.contains(&def_id))
            .collect();

        let paths_bypassing: Vec<&Vec<u64>> = all_paths
            .iter()
            .filter(|path| !path.contains(&def_id))
            .collect();

        let attacks_total = paths_through.len() + paths_bypassing.len();
        let attacks_blocked = paths_through.len();

        let block_rate = if attacks_total > 0 {
            attacks_blocked as f64 / attacks_total as f64
        } else {
            0.0
        };

        let asset_set: std::collections::HashSet<u64> = assets.iter().copied().collect();
        let protected_assets: Vec<u64> = paths_through
            .iter()
            .filter_map(|path| path.last().copied())
            .filter(|&last| asset_set.contains(&last))
            .collect::<std::collections::HashSet<u64>>()
            .into_iter()
            .collect();

        let mut weakness_notes = Vec::new();
        if block_rate < 0.3 {
            weakness_notes.push(format!(
                "Very low block rate ({:.0}%): most paths bypass this defense",
                block_rate * 100.0
            ));
        }
        if paths_bypassing.len() > paths_through.len() * 2 {
            weakness_notes.push("More than 2x paths bypass than traverse this defense".into());
        }

        DefenseScore {
            defense_node_id: def_id,
            defense_label: node.label.clone(),
            attacks_blocked,
            attacks_total,
            block_rate,
            protected_assets,
            weakness_notes,
        }
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
