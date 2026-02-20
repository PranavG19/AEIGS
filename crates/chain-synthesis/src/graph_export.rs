use std::fmt::Write;

use crate::attack_graph::{AttackGraph, AttackNodeType};

/// Unprotected entry points and assets discovered by defense gap analysis.
///
/// A node is "unprotected" when none of its direct neighbors (incoming or
/// outgoing) is a `SecurityBoundary`. This heuristic identifies attack surface
/// that lacks any modeled defensive control.
#[derive(Debug, Clone, PartialEq)]
pub struct DefenseGapReport {
    pub unprotected_entry_points: Vec<u64>,
    pub unprotected_assets: Vec<u64>,
    pub total_entry_points: usize,
    pub total_assets: usize,
}

/// Exports the attack graph in Graphviz DOT format.
///
/// Nodes are colored and shaped by type; edges are colored by exploitation
/// difficulty (green < 3.0, orange 3.0..=7.0, red > 7.0).
pub fn export_dot(graph: &AttackGraph) -> String {
    let mut out = String::from("digraph attack_graph {\n    rankdir=LR;\n");

    for node_id in all_node_ids(graph) {
        let Some(node) = graph.node(node_id) else {
            continue;
        };
        let (color, shape) = node_style(node.node_type);
        let label = dot_escape(&node.label);
        writeln!(
            out,
            "    n{} [label=\"{}\" shape={} style=filled fillcolor=\"{}\"];",
            node.id, label, shape, color
        )
        .unwrap();
    }

    for edge in graph.all_edges() {
        let edge_color = difficulty_color(edge.exploitation_difficulty);
        writeln!(
            out,
            "    n{} -> n{} [label=\"{:.1}\" color=\"{}\"];",
            edge.source, edge.target, edge.exploitation_difficulty, edge_color
        )
        .unwrap();
    }

    out.push_str("}\n");
    out
}

/// Exports the attack graph as D3.js-compatible JSON.
///
/// Produces `{"nodes": [...], "links": [...]}` where node colors map to
/// `AttackNodeType` and link colors map to exploitation difficulty.
pub fn export_d3_json(graph: &AttackGraph) -> String {
    let mut nodes = Vec::new();
    for node_id in all_node_ids(graph) {
        let Some(node) = graph.node(node_id) else {
            continue;
        };
        let color = node_hex_color(node.node_type);
        nodes.push(serde_json::json!({
            "id": node.id,
            "label": node.label,
            "type": format!("{:?}", node.node_type),
            "color": color,
        }));
    }

    let mut links = Vec::new();
    for edge in graph.all_edges() {
        let color = difficulty_hex_color(edge.exploitation_difficulty);
        links.push(serde_json::json!({
            "source": edge.source,
            "target": edge.target,
            "difficulty": edge.exploitation_difficulty,
            "vulnerability_id": edge.vulnerability_id,
            "color": color,
        }));
    }

    serde_json::to_string_pretty(&serde_json::json!({
        "nodes": nodes,
        "links": links,
    }))
    .expect("serialization of graph JSON should never fail")
}

/// Identifies entry points and assets with no adjacent `SecurityBoundary`.
pub fn analyze_defense_gaps(graph: &AttackGraph) -> DefenseGapReport {
    let boundary_ids: std::collections::HashSet<u64> = graph
        .nodes_by_type(AttackNodeType::SecurityBoundary)
        .into_iter()
        .collect();

    let entry_points = graph.entry_points();
    let assets = graph.assets();

    let unprotected_entry_points: Vec<u64> = entry_points
        .iter()
        .filter(|&&id| !has_boundary_neighbor(graph, id, &boundary_ids))
        .copied()
        .collect();

    let unprotected_assets: Vec<u64> = assets
        .iter()
        .filter(|&&id| !has_boundary_neighbor(graph, id, &boundary_ids))
        .copied()
        .collect();

    DefenseGapReport {
        total_entry_points: entry_points.len(),
        total_assets: assets.len(),
        unprotected_entry_points,
        unprotected_assets,
    }
}

fn has_boundary_neighbor(
    graph: &AttackGraph,
    node_id: u64,
    boundary_ids: &std::collections::HashSet<u64>,
) -> bool {
    let inner = graph.inner_graph();
    let Some(idx) = graph.node_index(node_id) else {
        return false;
    };

    use petgraph::Direction;
    for neighbor in inner.neighbors_directed(idx, Direction::Outgoing) {
        if boundary_ids.contains(&inner[neighbor].id) {
            return true;
        }
    }
    for neighbor in inner.neighbors_directed(idx, Direction::Incoming) {
        if boundary_ids.contains(&inner[neighbor].id) {
            return true;
        }
    }
    false
}

fn all_node_ids(graph: &AttackGraph) -> Vec<u64> {
    graph.inner_graph().node_weights().map(|n| n.id).collect()
}

fn node_style(node_type: AttackNodeType) -> (&'static str, &'static str) {
    match node_type {
        AttackNodeType::EntryPoint => ("green", "diamond"),
        AttackNodeType::SecurityBoundary => ("blue", "hexagon"),
        AttackNodeType::Vulnerability => ("red", "octagon"),
        AttackNodeType::Asset => ("gold", "box"),
    }
}

fn node_hex_color(node_type: AttackNodeType) -> &'static str {
    match node_type {
        AttackNodeType::EntryPoint => "#2ecc71",
        AttackNodeType::SecurityBoundary => "#3498db",
        AttackNodeType::Vulnerability => "#e74c3c",
        AttackNodeType::Asset => "#f1c40f",
    }
}

fn difficulty_color(difficulty: f64) -> &'static str {
    if difficulty < 3.0 {
        "green"
    } else if difficulty <= 7.0 {
        "orange"
    } else {
        "red"
    }
}

fn difficulty_hex_color(difficulty: f64) -> &'static str {
    if difficulty < 3.0 {
        "#2ecc71"
    } else if difficulty <= 7.0 {
        "#f39c12"
    } else {
        "#e74c3c"
    }
}

fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
