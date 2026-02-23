use std::time::{SystemTime, UNIX_EPOCH};

use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::backup_scanner::BackupFinding;
use crate::brute_forcer::DiscoveredPath;
use crate::js_extractor::ExtractedEndpoint;

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

pub fn extracted_endpoints_to_operations(
    endpoints: &[ExtractedEndpoint],
    start_sequence: u64,
) -> Vec<OperationLogEntry> {
    endpoints
        .iter()
        .enumerate()
        .map(|(i, ep)| {
            let mut properties = vec![
                ("path".to_string(), ep.url.clone()),
                (
                    "discovery_source".to_string(),
                    "javascript_analysis".to_string(),
                ),
            ];

            if let Some(method) = &ep.method {
                properties.push(("method".to_string(), method.clone()));
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

pub fn backup_findings_to_operations(
    findings: &[BackupFinding],
    start_sequence: u64,
) -> Vec<OperationLogEntry> {
    findings
        .iter()
        .enumerate()
        .map(|(i, finding)| {
            let properties = vec![
                ("path".to_string(), finding.path.clone()),
                ("method".to_string(), "GET".to_string()),
                ("discovery_source".to_string(), "backup_scan".to_string()),
                ("status_code".to_string(), finding.status_code.to_string()),
                (
                    "content_length".to_string(),
                    finding.content_length.to_string(),
                ),
                (
                    "backup_type".to_string(),
                    format!("{:?}", finding.finding_type),
                ),
                ("severity".to_string(), finding.severity.to_string()),
                ("interesting".to_string(), "true".to_string()),
            ];

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

pub(crate) fn timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
