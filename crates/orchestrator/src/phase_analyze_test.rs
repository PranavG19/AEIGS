use super::*;

use aegis_chain_synthesis::attack_graph::{AttackGraph, AttackNodeType};
use aegis_knowledge_graph::graph::KnowledgeGraph;
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
        graph: KnowledgeGraph::new(),
        defense_profile: None,
    }
}

fn add_endpoint(graph: &KnowledgeGraph, seq: u64, path: &str) {
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

fn add_datastore(graph: &KnowledgeGraph, seq: u64, name: &str) {
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
    add_endpoint(&ctx.graph, 1, "/api/users");
    add_endpoint(&ctx.graph, 2, "/api/admin");

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
    let ctx = make_context();
    add_endpoint(&ctx.graph, 1, "/login");

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
    let ctx = make_context();
    add_datastore(&ctx.graph, 1, "users_db");

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
