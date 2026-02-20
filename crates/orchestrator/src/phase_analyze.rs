use aegis_chain_synthesis::attack_graph::{AttackGraph, AttackNodeType};
use aegis_chain_synthesis::path_analysis::{
    betweenness_centrality, reachable_assets, shortest_attack_path,
};
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;
use crate::pipeline::{PhaseResult, ScanContext};

pub fn run_analyze(ctx: &mut ScanContext) -> Result<PhaseResult, String> {
    let mut attack_graph = AttackGraph::new();
    let mut kg_to_ag: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();

    build_attack_graph_from_knowledge_graph(ctx, &mut attack_graph, &mut kg_to_ag);

    let _reachable = reachable_assets(&attack_graph);
    let _centrality = betweenness_centrality(&attack_graph);

    let entry_points = attack_graph.entry_points();
    let assets = attack_graph.assets();
    let mut chain_findings = Vec::new();
    let mut sequence = ctx
        .graph
        .total_operations_applied()
        .map_err(|e| format!("{e:?}"))?;

    for &entry in &entry_points {
        for &asset in &assets {
            if let Some(path) = shortest_attack_path(&attack_graph, entry, asset) {
                sequence += 1;
                chain_findings.push(OperationLogEntry {
                    sequence_number: sequence,
                    module: ModuleIdentifier::ChainSynthesis,
                    operation: GraphOperation::AddFinding {
                        linked_node_ids: path.nodes.clone(),
                        vulnerability_class: VulnerabilityClass::BrokenAuthorization,
                        severity: 1.0 / path.total_difficulty.max(0.01),
                        confidence: 0.7,
                        certificate: Vec::new(),
                    },
                    timestamp_unix_ms: timestamp_ms(),
                });
            }
        }
    }

    let findings_count = chain_findings.len() as u64;
    if !chain_findings.is_empty() {
        ctx.graph
            .apply_operations(&chain_findings)
            .map_err(|e| format!("{e:?}"))?;
    }

    Ok(PhaseResult {
        operations_applied: chain_findings.len() as u64,
        findings_count,
    })
}

pub(crate) fn build_attack_graph_from_knowledge_graph(
    ctx: &ScanContext,
    ag: &mut AttackGraph,
    kg_to_ag: &mut std::collections::HashMap<u64, u64>,
) {
    let endpoint_ids = ctx
        .graph
        .nodes_by_type(NodeType::Endpoint)
        .unwrap_or_default();
    for &id in &endpoint_ids {
        if let Some(node) = ctx.graph.get_node(id).ok().flatten() {
            let label = node
                .properties
                .get("path")
                .cloned()
                .unwrap_or_else(|| format!("node-{id}"));
            let ag_id = ag.add_node(label, AttackNodeType::EntryPoint);
            kg_to_ag.insert(id, ag_id);
        }
    }

    let datastore_ids = ctx
        .graph
        .nodes_by_type(NodeType::DataStore)
        .unwrap_or_default();
    for &id in &datastore_ids {
        if let Some(node) = ctx.graph.get_node(id).ok().flatten() {
            let label = node
                .properties
                .get("name")
                .cloned()
                .unwrap_or_else(|| format!("asset-{id}"));
            let ag_id = ag.add_node(label, AttackNodeType::Asset);
            kg_to_ag.insert(id, ag_id);
        }
    }
}
