use aegis_fuzzing::DefenseProfile;
use aegis_protocol::edge::EdgeLabel;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::pipeline::{PhaseResult, ScanContext};

pub fn run_fingerprint(ctx: &mut ScanContext) -> Result<PhaseResult, String> {
    let profile = DefenseProfile::empty(timestamp_ms());
    let mut entries = Vec::new();
    let mut sequence = ctx
        .graph
        .total_operations_applied()
        .map_err(|e| format!("{e:?}"))?;

    sequence += 1;
    entries.push(OperationLogEntry {
        sequence_number: sequence,
        module: ModuleIdentifier::Enumeration,
        operation: GraphOperation::AddNode {
            node_type: NodeType::Defense,
            properties: defense_properties(&profile),
        },
        timestamp_unix_ms: timestamp_ms(),
    });

    let ops_count = entries.len() as u64;
    if !entries.is_empty() {
        ctx.graph
            .apply_operations(&entries)
            .map_err(|e| format!("{e:?}"))?;
    }

    ctx.defense_profile = Some(profile);
    Ok(PhaseResult {
        operations_applied: ops_count,
        findings_count: 0,
    })
}

pub(crate) fn defense_properties(profile: &DefenseProfile) -> Vec<(String, String)> {
    let mut props = Vec::new();
    if let Some(waf) = &profile.waf {
        props.push(("waf_vendor".to_string(), format!("{:?}", waf.vendor)));
        props.push((
            "waf_blocked_code".to_string(),
            waf.blocked_response_code.to_string(),
        ));
    }
    if let Some(rl) = &profile.rate_limit {
        props.push((
            "rate_limit_code".to_string(),
            rl.limit_response_code.to_string(),
        ));
    }
    if let Some(bd) = &profile.bot_detection {
        props.push(("bot_detected".to_string(), bd.detected.to_string()));
    }
    props
}

pub fn build_protected_by_edges(
    defense_node_id: u64,
    endpoint_node_ids: &[u64],
    sequence_start: u64,
) -> Vec<OperationLogEntry> {
    endpoint_node_ids
        .iter()
        .enumerate()
        .map(|(i, &endpoint_id)| OperationLogEntry {
            sequence_number: sequence_start + i as u64 + 1,
            module: ModuleIdentifier::Enumeration,
            operation: GraphOperation::AddEdge {
                source_node_id: endpoint_id,
                target_node_id: defense_node_id,
                label: EdgeLabel::ProtectedBy,
                weight: 1.0,
            },
            timestamp_unix_ms: timestamp_ms(),
        })
        .collect()
}

fn timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
