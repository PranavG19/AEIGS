use std::time::{SystemTime, UNIX_EPOCH};

use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::brute_forcer::DiscoveredPath;

pub fn discovered_paths_to_operations(
    paths: &[DiscoveredPath],
    start_sequence: u64,
) -> Vec<OperationLogEntry> {
    paths
        .iter()
        .enumerate()
        .map(|(i, path)| {
            let mut properties = vec![
                ("path".to_string(), path.path.clone()),
                ("method".to_string(), "GET".to_string()),
                ("discovery_source".to_string(), "brute_force".to_string()),
                ("status_code".to_string(), path.status_code.to_string()),
                (
                    "content_length".to_string(),
                    path.content_length.to_string(),
                ),
            ];

            if let Some(ct) = &path.content_type {
                properties.push(("content_type".to_string(), ct.clone()));
            }

            if path.interesting {
                properties.push(("interesting".to_string(), "true".to_string()));
            }

            OperationLogEntry {
                sequence_number: start_sequence + i as u64 + 1,
                module: ModuleIdentifier::Discovery,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties,
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

fn timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
