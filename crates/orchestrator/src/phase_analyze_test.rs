use super::*;

use aegis_chain_synthesis::attack_graph::{AttackGraph, AttackNodeType};
use aegis_knowledge_graph::graph::KnowledgeGraph;
use aegis_knowledge_graph::graph_store::GraphStore;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};
use clap::Parser;
use std::collections::HashMap;

use crate::phase_analyze::{build_attack_graph_from_knowledge_graph, timestamp_ms};

fn make_context() -> ScanContext {
    let config =
        ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080"]).unwrap();
    ScanContext {
        config,
        graph: Box::new(KnowledgeGraph::new()),
        defense_profile: None,
    }
}

fn add_endpoint(graph: &mut dyn GraphStore, seq: u64, path: &str) {
    let entry = OperationLogEntry {
        sequence_number: seq,
        module: ModuleIdentifier::Enumeration,
        operation: GraphOperation::AddNode {
            node_type: NodeType::Endpoint,
            properties: vec![("path".to_string(), path.to_string())],
        },
        timestamp_unix_ms: 1,
    };
    graph.apply_operations(&[entry]).unwrap();
}

fn add_datastore(graph: &mut dyn GraphStore, seq: u64, name: &str) {
    let entry = OperationLogEntry {
        sequence_number: seq,
        module: ModuleIdentifier::Enumeration,
        operation: GraphOperation::AddNode {
            node_type: NodeType::DataStore,
            properties: vec![("name".to_string(), name.to_string())],
        },
        timestamp_unix_ms: 1,
    };
    graph.apply_operations(&[entry]).unwrap();
}

#[test]
fn run_analyze_empty_graph_returns_zero_findings() {
    let mut ctx = make_context();
    let result = run_analyze(&mut ctx).unwrap();
    assert_eq!(result.findings_count, 0);
    assert_eq!(result.operations_applied, 0);
}

#[test]
fn run_analyze_endpoints_only_returns_zero_findings() {
    let mut ctx = make_context();
    add_endpoint(&mut *ctx.graph, 1, "/api/users");
    add_endpoint(&mut *ctx.graph, 2, "/api/admin");

    let result = run_analyze(&mut ctx).unwrap();
    assert_eq!(result.findings_count, 0);
    assert_eq!(result.operations_applied, 0);
}

#[test]
fn build_attack_graph_empty_knowledge_graph() {
    let ctx = make_context();
    let mut ag = AttackGraph::new();
    let mut mapping = HashMap::new();

    build_attack_graph_from_knowledge_graph(&ctx, &mut ag, &mut mapping);

    assert_eq!(ag.node_count(), 0);
    assert_eq!(ag.edge_count(), 0);
    assert!(mapping.is_empty());
}

#[test]
fn build_attack_graph_maps_endpoints_to_entry_points() {
    let mut ctx = make_context();
    add_endpoint(&mut *ctx.graph, 1, "/login");

    let mut ag = AttackGraph::new();
    let mut mapping = HashMap::new();

    build_attack_graph_from_knowledge_graph(&ctx, &mut ag, &mut mapping);

    assert_eq!(ag.entry_points().len(), 1);
    let ag_id = ag.entry_points()[0];
    let node = ag.node(ag_id).unwrap();
    assert_eq!(node.node_type, AttackNodeType::EntryPoint);
    assert_eq!(node.label, "/login");
}

#[test]
fn build_attack_graph_maps_datastores_to_assets() {
    let mut ctx = make_context();
    add_datastore(&mut *ctx.graph, 1, "users_db");

    let mut ag = AttackGraph::new();
    let mut mapping = HashMap::new();

    build_attack_graph_from_knowledge_graph(&ctx, &mut ag, &mut mapping);

    assert_eq!(ag.assets().len(), 1);
    let ag_id = ag.assets()[0];
    let node = ag.node(ag_id).unwrap();
    assert_eq!(node.node_type, AttackNodeType::Asset);
    assert_eq!(node.label, "users_db");
}

#[test]
fn timestamp_ms_returns_nonzero() {
    let ts = timestamp_ms();
    assert!(ts > 0);
}

#[test]
fn run_analyze_with_endpoint_and_datastore_no_edges_returns_zero_findings() {
    let mut ctx = make_context();
    add_endpoint(&mut *ctx.graph, 1, "/api/login");
    add_datastore(&mut *ctx.graph, 2, "users_db");

    let result = run_analyze(&mut ctx).unwrap();
    assert_eq!(result.findings_count, 0);
    assert_eq!(result.operations_applied, 0);
}

#[test]
fn build_attack_graph_endpoint_without_path_property_uses_node_id_label() {
    let mut ctx = make_context();
    let entry = OperationLogEntry {
        sequence_number: 1,
        module: ModuleIdentifier::Enumeration,
        operation: GraphOperation::AddNode {
            node_type: NodeType::Endpoint,
            properties: vec![],
        },
        timestamp_unix_ms: 1,
    };
    ctx.graph.apply_operations(&[entry]).unwrap();

    let endpoint_ids = ctx.graph.nodes_by_type(NodeType::Endpoint).unwrap();
    let node_id = endpoint_ids[0];

    let mut ag = AttackGraph::new();
    let mut mapping = HashMap::new();
    build_attack_graph_from_knowledge_graph(&ctx, &mut ag, &mut mapping);

    assert_eq!(ag.entry_points().len(), 1);
    let ag_node_id = ag.entry_points()[0];
    let node = ag.node(ag_node_id).unwrap();
    assert_eq!(node.label, format!("node-{node_id}"));
}

#[test]
fn build_attack_graph_datastore_without_name_property_uses_asset_id_label() {
    let mut ctx = make_context();
    let entry = OperationLogEntry {
        sequence_number: 1,
        module: ModuleIdentifier::Enumeration,
        operation: GraphOperation::AddNode {
            node_type: NodeType::DataStore,
            properties: vec![],
        },
        timestamp_unix_ms: 1,
    };
    ctx.graph.apply_operations(&[entry]).unwrap();

    let datastore_ids = ctx.graph.nodes_by_type(NodeType::DataStore).unwrap();
    let node_id = datastore_ids[0];

    let mut ag = AttackGraph::new();
    let mut mapping = HashMap::new();
    build_attack_graph_from_knowledge_graph(&ctx, &mut ag, &mut mapping);

    assert_eq!(ag.assets().len(), 1);
    let ag_node_id = ag.assets()[0];
    let node = ag.node(ag_node_id).unwrap();
    assert_eq!(node.label, format!("asset-{node_id}"));
}

#[test]
fn run_analyze_with_chain_finding_applies_to_graph() {
    use aegis_chain_synthesis::attack_graph::AttackNodeType;

    let mut ctx = make_context();

    add_endpoint(&mut *ctx.graph, 1, "/api/login");
    add_datastore(&mut *ctx.graph, 2, "users_db");

    let mut ag = AttackGraph::new();
    let mut mapping = HashMap::new();
    build_attack_graph_from_knowledge_graph(&ctx, &mut ag, &mut mapping);

    let endpoint_ids = ctx.graph.nodes_by_type(NodeType::Endpoint).unwrap();
    let datastore_ids = ctx.graph.nodes_by_type(NodeType::DataStore).unwrap();
    let ep_ag_id = mapping[&endpoint_ids[0]];
    let ds_ag_id = mapping[&datastore_ids[0]];

    ag.add_edge(ep_ag_id, ds_ag_id, 1.0, None);

    let entry_points = ag.entry_points();
    let assets = ag.assets();

    assert_eq!(entry_points.len(), 1);
    assert_eq!(assets.len(), 1);

    use aegis_chain_synthesis::path_analysis::shortest_attack_path;
    let path = shortest_attack_path(&ag, entry_points[0], assets[0]);
    assert!(path.is_some());
}

#[test]
fn build_attack_graph_multiple_endpoints_maps_all() {
    let mut ctx = make_context();
    add_endpoint(&mut *ctx.graph, 1, "/api/users");
    add_endpoint(&mut *ctx.graph, 2, "/api/admin");
    add_endpoint(&mut *ctx.graph, 3, "/api/login");

    let mut ag = AttackGraph::new();
    let mut mapping = HashMap::new();
    build_attack_graph_from_knowledge_graph(&ctx, &mut ag, &mut mapping);

    assert_eq!(ag.entry_points().len(), 3);
    assert_eq!(mapping.len(), 3);
}

#[test]
fn build_attack_graph_multiple_datastores_maps_all() {
    let mut ctx = make_context();
    add_datastore(&mut *ctx.graph, 1, "users_db");
    add_datastore(&mut *ctx.graph, 2, "sessions_db");

    let mut ag = AttackGraph::new();
    let mut mapping = HashMap::new();
    build_attack_graph_from_knowledge_graph(&ctx, &mut ag, &mut mapping);

    assert_eq!(ag.assets().len(), 2);
    assert_eq!(mapping.len(), 2);
}
