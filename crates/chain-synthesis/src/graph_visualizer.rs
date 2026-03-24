use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write;

use serde::{Deserialize, Serialize};

use crate::attack_graph::{AttackGraph, AttackNodeType};
use crate::path_analysis::shortest_attack_path;

/// Visualization-ready node with display metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisNode {
    pub id: u64,
    pub label: String,
    pub node_type: String,
    pub color: String,
    pub shape: String,
    pub layer: u32,
    pub details: Option<NodeDetails>,
}

/// Interactive detail payload revealed on node click.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDetails {
    pub description: String,
    pub finding_ids: Vec<u64>,
    pub risk_score: Option<f64>,
}

/// Visualization-ready edge with display metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisEdge {
    pub source: u64,
    pub target: u64,
    pub edge_type: String,
    pub label: String,
    pub color: String,
    pub width: f64,
}

/// Complete visualization data for rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphVisualization {
    pub nodes: Vec<VisNode>,
    pub edges: Vec<VisEdge>,
    pub layers: Vec<Vec<u64>>,
    pub metadata: VisualizationMetadata,
}

/// Summary statistics for the visualization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualizationMetadata {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub max_depth: u32,
    pub entry_point_count: usize,
    pub asset_count: usize,
}

/// Builds a full visualization from the attack graph.
///
/// BFS from every entry point assigns hierarchical layers. Nodes unreachable
/// from any entry point are placed on `max_depth + 1`.
pub fn build_visualization(graph: &AttackGraph) -> GraphVisualization {
    let layer_map = assign_layers(graph);
    let max_depth = layer_map.values().copied().max().unwrap_or(0);

    let all_ids = all_node_ids(graph);
    let nodes: Vec<VisNode> = all_ids
        .iter()
        .filter_map(|&id| {
            let node = graph.node(id)?;
            let layer = layer_map.get(&id).copied().unwrap_or(max_depth + 1);
            Some(build_vis_node(node.id, &node.label, node.node_type, layer))
        })
        .collect();

    let edges: Vec<VisEdge> = graph
        .all_edges()
        .iter()
        .map(|e| {
            build_vis_edge(
                e.source,
                e.target,
                e.exploitation_difficulty,
                e.vulnerability_id,
            )
        })
        .collect();

    let layers = collect_layers(&layer_map, max_depth);

    let entry_point_count = graph.entry_points().len();
    let asset_count = graph.assets().len();

    GraphVisualization {
        metadata: VisualizationMetadata {
            total_nodes: nodes.len(),
            total_edges: edges.len(),
            max_depth,
            entry_point_count,
            asset_count,
        },
        nodes,
        edges,
        layers,
    }
}

/// Extracts a subgraph visualization along the shortest path from `from` to `to`.
///
/// Returns an empty visualization when no path exists.
pub fn extract_subgraph(graph: &AttackGraph, from: u64, to: u64) -> GraphVisualization {
    let path = match shortest_attack_path(graph, from, to) {
        Some(p) => p,
        None => return empty_visualization(),
    };

    let path_set: HashSet<u64> = path.nodes.iter().copied().collect();

    let mut layer_map: HashMap<u64, u32> = HashMap::new();
    for (depth, &nid) in path.nodes.iter().enumerate() {
        layer_map.insert(nid, depth as u32);
    }

    let max_depth = path.nodes.len().saturating_sub(1) as u32;

    let nodes: Vec<VisNode> = path
        .nodes
        .iter()
        .filter_map(|&id| {
            let node = graph.node(id)?;
            let layer = layer_map.get(&id).copied().unwrap_or(0);
            Some(build_vis_node(node.id, &node.label, node.node_type, layer))
        })
        .collect();

    let edges: Vec<VisEdge> = graph
        .all_edges()
        .iter()
        .filter(|e| path_set.contains(&e.source) && path_set.contains(&e.target))
        .filter(|e| {
            path.nodes
                .windows(2)
                .any(|w| w[0] == e.source && w[1] == e.target)
        })
        .map(|e| {
            build_vis_edge(
                e.source,
                e.target,
                e.exploitation_difficulty,
                e.vulnerability_id,
            )
        })
        .collect();

    let layers = collect_layers(&layer_map, max_depth);

    let entry_count = nodes
        .iter()
        .filter(|n| n.node_type == "entry-point")
        .count();
    let asset_count = nodes.iter().filter(|n| n.node_type == "asset").count();

    GraphVisualization {
        metadata: VisualizationMetadata {
            total_nodes: nodes.len(),
            total_edges: edges.len(),
            max_depth,
            entry_point_count: entry_count,
            asset_count,
        },
        nodes,
        edges,
        layers,
    }
}

/// Exports DOT format from a pre-built visualization.
pub fn export_vis_dot(vis: &GraphVisualization) -> String {
    let mut out = String::from("digraph attack_graph {\n    rankdir=TB;\n");

    for node in &vis.nodes {
        let label = dot_escape(&node.label);
        writeln!(
            out,
            "    n{} [label=\"{}\" shape={} style=filled fillcolor=\"{}\"];",
            node.id, label, node.shape, node.color
        )
        .unwrap();
    }

    for edge in &vis.edges {
        let pen_width = format!("{:.1}", edge.width);
        writeln!(
            out,
            "    n{} -> n{} [label=\"{}\" color=\"{}\" penwidth={}];",
            edge.source,
            edge.target,
            dot_escape(&edge.label),
            edge.color,
            pen_width
        )
        .unwrap();
    }

    out.push_str("}\n");
    out
}

/// Exports D3.js-compatible JSON from a pre-built visualization.
pub fn export_vis_d3_json(vis: &GraphVisualization) -> String {
    let nodes: Vec<serde_json::Value> = vis
        .nodes
        .iter()
        .map(|n| {
            serde_json::json!({
                "id": n.id,
                "label": n.label,
                "type": n.node_type,
                "color": n.color,
                "shape": n.shape,
                "layer": n.layer,
                "details": n.details,
            })
        })
        .collect();

    let links: Vec<serde_json::Value> = vis
        .edges
        .iter()
        .map(|e| {
            serde_json::json!({
                "source": e.source,
                "target": e.target,
                "edge_type": e.edge_type,
                "label": e.label,
                "color": e.color,
                "width": e.width,
            })
        })
        .collect();

    serde_json::to_string_pretty(&serde_json::json!({
        "nodes": nodes,
        "links": links,
        "layers": vis.layers,
        "metadata": vis.metadata,
    }))
    .expect("serialization of visualization JSON should never fail")
}

/// Exports Mermaid markdown from a pre-built visualization.
///
/// Node shapes follow Mermaid syntax: `{{}}`=hexagon, `{{...}}`=diamond,
/// `[/...\\]`=trapezoid, `[...]`=rectangle. We use reasonable Mermaid
/// approximations for each `AttackNodeType`.
pub fn export_vis_mermaid(vis: &GraphVisualization) -> String {
    let mut out = String::from("graph TD\n");

    for node in &vis.nodes {
        let safe_label = mermaid_escape(&node.label);
        let shape = mermaid_node_shape(&node.node_type, node.id, &safe_label);
        writeln!(out, "    {shape}").unwrap();
    }

    for edge in &vis.edges {
        let safe_label = mermaid_escape(&edge.label);
        writeln!(
            out,
            "    n{} -->|{}| n{}",
            edge.source, safe_label, edge.target
        )
        .unwrap();
    }

    for node in &vis.nodes {
        let style_class = match node.node_type.as_str() {
            "entry-point" => format!("style n{} fill:{},stroke:#333", node.id, node.color),
            "security-boundary" => format!("style n{} fill:{},stroke:#333", node.id, node.color),
            "vulnerability" => format!("style n{} fill:{},stroke:#333", node.id, node.color),
            "asset" => format!("style n{} fill:{},stroke:#333", node.id, node.color),
            _ => continue,
        };
        writeln!(out, "    {style_class}").unwrap();
    }

    out
}

fn assign_layers(graph: &AttackGraph) -> HashMap<u64, u32> {
    let entry_points = graph.entry_points();
    let mut layer_map: HashMap<u64, u32> = HashMap::new();
    let mut queue: VecDeque<(u64, u32)> = VecDeque::new();

    for &ep in &entry_points {
        layer_map.insert(ep, 0);
        queue.push_back((ep, 0));
    }

    let inner = graph.inner_graph();
    while let Some((current, depth)) = queue.pop_front() {
        let Some(idx) = graph.node_index(current) else {
            continue;
        };
        for neighbor_idx in inner.neighbors_directed(idx, petgraph::Direction::Outgoing) {
            let neighbor_id = inner[neighbor_idx].id;
            if let std::collections::hash_map::Entry::Vacant(e) = layer_map.entry(neighbor_id) {
                e.insert(depth + 1);
                queue.push_back((neighbor_id, depth + 1));
            }
        }
    }

    layer_map
}

fn collect_layers(layer_map: &HashMap<u64, u32>, max_depth: u32) -> Vec<Vec<u64>> {
    let mut layers: Vec<Vec<u64>> = (0..=max_depth).map(|_| Vec::new()).collect();
    let mut sorted_entries: Vec<(&u64, &u32)> = layer_map.iter().collect();
    sorted_entries.sort_by_key(|&(&id, _)| id);
    for (&id, &layer) in sorted_entries {
        if (layer as usize) < layers.len() {
            layers[layer as usize].push(id);
        }
    }
    layers
}

fn build_vis_node(id: u64, label: &str, node_type: AttackNodeType, layer: u32) -> VisNode {
    let type_str = node_type.to_string();
    let color = node_hex_color(node_type);
    let shape = node_shape(node_type);

    let details = match node_type {
        AttackNodeType::Vulnerability => Some(NodeDetails {
            description: format!("Vulnerability: {label}"),
            finding_ids: Vec::new(),
            risk_score: None,
        }),
        AttackNodeType::Asset => Some(NodeDetails {
            description: format!("Data asset: {label}"),
            finding_ids: Vec::new(),
            risk_score: None,
        }),
        _ => None,
    };

    VisNode {
        id,
        label: label.to_string(),
        node_type: type_str,
        color: color.to_string(),
        shape: shape.to_string(),
        layer,
        details,
    }
}

fn build_vis_edge(source: u64, target: u64, difficulty: f64, vuln_id: Option<u64>) -> VisEdge {
    let edge_type = match vuln_id {
        Some(_) => "exploits",
        None => "chains-to",
    };

    let label = format!("{difficulty:.1}");
    let color = difficulty_hex_color(difficulty);
    let width = edge_width(difficulty);

    VisEdge {
        source,
        target,
        edge_type: edge_type.to_string(),
        label,
        color: color.to_string(),
        width,
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

fn node_shape(node_type: AttackNodeType) -> &'static str {
    match node_type {
        AttackNodeType::EntryPoint => "diamond",
        AttackNodeType::SecurityBoundary => "hexagon",
        AttackNodeType::Vulnerability => "octagon",
        AttackNodeType::Asset => "box",
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

fn edge_width(difficulty: f64) -> f64 {
    let clamped = difficulty.clamp(1.0, 10.0);
    1.0 + 4.0 * (1.0 - (clamped - 1.0) / 9.0)
}

fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn mermaid_escape(s: &str) -> String {
    s.replace('"', "'").replace('[', "(").replace(']', ")")
}

fn mermaid_node_shape(node_type: &str, id: u64, label: &str) -> String {
    match node_type {
        "entry-point" => format!("n{id}{{{{{label}}}}}"),
        "security-boundary" => format!("n{id}[/{label}\\]"),
        "vulnerability" => format!("n{id}(({label}))"),
        "asset" => format!("n{id}[{label}]"),
        _ => format!("n{id}[{label}]"),
    }
}

fn empty_visualization() -> GraphVisualization {
    GraphVisualization {
        nodes: Vec::new(),
        edges: Vec::new(),
        layers: Vec::new(),
        metadata: VisualizationMetadata {
            total_nodes: 0,
            total_edges: 0,
            max_depth: 0,
            entry_point_count: 0,
            asset_count: 0,
        },
    }
}

fn all_node_ids(graph: &AttackGraph) -> Vec<u64> {
    graph.inner_graph().node_weights().map(|n| n.id).collect()
}
