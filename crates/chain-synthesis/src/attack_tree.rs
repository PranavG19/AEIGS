use std::collections::HashSet;
use std::fmt::Write;

use crate::attack_graph::AttackGraph;

/// Logical gate type for attack tree nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GateType {
    /// All children must succeed (required steps).
    And,
    /// Any one child suffices (alternative paths).
    Or,
    /// Leaf node — concrete attack step with no children.
    Leaf,
}

impl std::fmt::Display for GateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::And => write!(f, "AND"),
            Self::Or => write!(f, "OR"),
            Self::Leaf => write!(f, "LEAF"),
        }
    }
}

/// Single node within an AND/OR attack tree.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttackTreeNode {
    pub id: u64,
    pub label: String,
    pub gate: GateType,
    pub difficulty: f64,
    pub children: Vec<AttackTreeNode>,
}

/// Complete attack tree rooted at a goal (asset).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttackTree {
    pub goal: String,
    pub root: AttackTreeNode,
    pub minimum_cost_path: Vec<u64>,
    pub minimum_cost: f64,
}

/// Builds AND/OR attack trees from an `AttackGraph`.
///
/// OR nodes represent alternative paths to reach a sub-goal; AND nodes
/// represent required sequential steps. Leaf nodes map to concrete
/// vulnerabilities or entry points.
pub struct AttackTreeGenerator<'a> {
    graph: &'a AttackGraph,
}

impl<'a> AttackTreeGenerator<'a> {
    pub fn new(graph: &'a AttackGraph) -> Self {
        Self { graph }
    }

    /// Generate an attack tree for reaching `target_id` from any entry point.
    pub fn generate(&self, target_id: u64) -> Option<AttackTree> {
        let target_node = self.graph.node(target_id)?;
        let goal_label = target_node.label.clone();

        let entry_points = self.graph.entry_points();
        if entry_points.is_empty() {
            return None;
        }

        let mut visited = HashSet::new();
        visited.insert(target_id);
        let root = self.build_subtree_reverse(target_id, &mut visited);
        let (min_cost, min_path) = self.minimum_cost_path(&root);

        Some(AttackTree {
            goal: goal_label,
            root,
            minimum_cost_path: min_path,
            minimum_cost: min_cost,
        })
    }

    /// Build the tree in reverse — from target backwards toward entry points.
    /// Each node with multiple parents becomes an OR gate (alternative paths).
    /// Sequential chains become AND gates (all steps required).
    fn build_subtree_reverse(&self, node_id: u64, visited: &mut HashSet<u64>) -> AttackTreeNode {
        let node = self.graph.node(node_id).expect("node must exist");
        let predecessors = self.predecessors(node_id);

        let unvisited_preds: Vec<u64> = predecessors
            .into_iter()
            .filter(|id| !visited.contains(id))
            .collect();

        if unvisited_preds.is_empty() {
            return AttackTreeNode {
                id: node_id,
                label: node.label.clone(),
                gate: GateType::Leaf,
                difficulty: self.incoming_difficulty(node_id),
                children: Vec::new(),
            };
        }

        let children: Vec<AttackTreeNode> = unvisited_preds
            .iter()
            .map(|&pred_id| {
                visited.insert(pred_id);
                let child = self.build_chain(pred_id, visited);
                visited.remove(&pred_id);
                child
            })
            .collect();

        let gate = if children.len() == 1 {
            GateType::And
        } else {
            GateType::Or
        };

        AttackTreeNode {
            id: node_id,
            label: node.label.clone(),
            gate,
            difficulty: self.incoming_difficulty(node_id),
            children,
        }
    }

    /// Build an AND-chain from a node backwards: if there is exactly one
    /// predecessor, extend the chain; otherwise branch into an OR subtree.
    fn build_chain(&self, node_id: u64, visited: &mut HashSet<u64>) -> AttackTreeNode {
        let node = self.graph.node(node_id).expect("node must exist");
        let predecessors = self.predecessors(node_id);

        let unvisited_preds: Vec<u64> = predecessors
            .into_iter()
            .filter(|id| !visited.contains(id))
            .collect();

        if unvisited_preds.is_empty() {
            return AttackTreeNode {
                id: node_id,
                label: node.label.clone(),
                gate: GateType::Leaf,
                difficulty: self.incoming_difficulty(node_id),
                children: Vec::new(),
            };
        }

        let children: Vec<AttackTreeNode> = unvisited_preds
            .iter()
            .map(|&pred_id| {
                visited.insert(pred_id);
                let child = self.build_subtree_reverse(pred_id, visited);
                visited.remove(&pred_id);
                child
            })
            .collect();

        let gate = if children.len() > 1 {
            GateType::Or
        } else {
            GateType::And
        };

        AttackTreeNode {
            id: node_id,
            label: node.label.clone(),
            gate,
            difficulty: self.incoming_difficulty(node_id),
            children,
        }
    }

    /// Compute the minimum cost path through the tree.
    /// AND gates sum children costs; OR gates pick the cheapest child.
    fn minimum_cost_path(&self, node: &AttackTreeNode) -> (f64, Vec<u64>) {
        if node.children.is_empty() {
            return (node.difficulty, vec![node.id]);
        }

        match node.gate {
            GateType::Leaf => (node.difficulty, vec![node.id]),
            GateType::Or => {
                let mut best_cost = f64::INFINITY;
                let mut best_path = Vec::new();
                for child in &node.children {
                    let (cost, mut path) = self.minimum_cost_path(child);
                    let total = node.difficulty + cost;
                    if total < best_cost {
                        best_cost = total;
                        path.push(node.id);
                        best_path = path;
                    }
                }
                (best_cost, best_path)
            }
            GateType::And => {
                let mut total_cost = node.difficulty;
                let mut combined_path = Vec::new();
                for child in &node.children {
                    let (cost, path) = self.minimum_cost_path(child);
                    total_cost += cost;
                    combined_path.extend(path);
                }
                combined_path.push(node.id);
                (total_cost, combined_path)
            }
        }
    }

    fn predecessors(&self, node_id: u64) -> Vec<u64> {
        self.graph
            .all_edges()
            .iter()
            .filter(|e| e.target == node_id)
            .map(|e| e.source)
            .collect()
    }

    fn incoming_difficulty(&self, node_id: u64) -> f64 {
        let edges: Vec<_> = self
            .graph
            .all_edges()
            .into_iter()
            .filter(|e| e.target == node_id)
            .collect();

        if edges.is_empty() {
            return 0.0;
        }

        edges
            .iter()
            .map(|e| e.exploitation_difficulty)
            .fold(f64::INFINITY, f64::min)
            .max(0.0)
    }
}

/// Export an attack tree as a Graphviz DOT string.
pub fn attack_tree_to_dot(tree: &AttackTree) -> String {
    let mut out = String::from("digraph attack_tree {\n    rankdir=TB;\n");
    writeln!(out, "    label=\"Goal: {}\";", dot_escape(&tree.goal)).unwrap();
    write_dot_node(&mut out, &tree.root);
    out.push_str("}\n");
    out
}

fn write_dot_node(out: &mut String, node: &AttackTreeNode) {
    let shape = match node.gate {
        GateType::And => "trapezium",
        GateType::Or => "invtriangle",
        GateType::Leaf => "ellipse",
    };
    let color = match node.gate {
        GateType::And => "#ffcccc",
        GateType::Or => "#ccccff",
        GateType::Leaf => "#ccffcc",
    };
    writeln!(
        out,
        "    n{} [label=\"{} [{}]\\nd={:.1}\" shape={} style=filled fillcolor=\"{}\"];",
        node.id,
        dot_escape(&node.label),
        node.gate,
        node.difficulty,
        shape,
        color
    )
    .unwrap();

    for child in &node.children {
        writeln!(out, "    n{} -> n{};", node.id, child.id).unwrap();
        write_dot_node(out, child);
    }
}

/// Export an attack tree as JSON.
pub fn attack_tree_to_json(tree: &AttackTree) -> String {
    serde_json::to_string_pretty(tree).unwrap_or_default()
}

/// Export an attack tree as a Mermaid diagram.
pub fn attack_tree_to_mermaid(tree: &AttackTree) -> String {
    let mut out = String::from("graph TD\n");
    writeln!(out, "    title[\"Goal: {}\"]", mermaid_escape(&tree.goal)).unwrap();
    let mut counter = 0u64;
    write_mermaid_node(&mut out, &tree.root, &mut counter, None);
    out
}

fn write_mermaid_node(
    out: &mut String,
    node: &AttackTreeNode,
    counter: &mut u64,
    parent_key: Option<String>,
) {
    let key = format!("N{}", node.id);
    let shape_open = match node.gate {
        GateType::And => "{",
        GateType::Or => "{{",
        GateType::Leaf => "(",
    };
    let shape_close = match node.gate {
        GateType::And => "}",
        GateType::Or => "}}",
        GateType::Leaf => ")",
    };
    writeln!(
        out,
        "    {}{}\"{} [{}] d={:.1}\"{}",
        key,
        shape_open,
        mermaid_escape(&node.label),
        node.gate,
        node.difficulty,
        shape_close,
    )
    .unwrap();

    if let Some(parent) = parent_key {
        writeln!(out, "    {} --> {}", parent, key).unwrap();
    }

    for child in &node.children {
        *counter += 1;
        write_mermaid_node(out, child, counter, Some(key.clone()));
    }
}

fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn mermaid_escape(s: &str) -> String {
    s.replace('"', "'").replace('\n', " ")
}
