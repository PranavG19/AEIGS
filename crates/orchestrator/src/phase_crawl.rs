use aegis_crawler::CrawlResult;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;

/// Converts crawl-discovered endpoints into knowledge graph operations.
///
/// Each `DiscoveredEndpoint` becomes an `AddNode` with `NodeType::Endpoint`
/// and properties for path, method, and discovery source.
pub fn crawl_result_to_operations(result: &CrawlResult, seq: &mut u64) -> Vec<OperationLogEntry> {
    result
        .discovered_endpoints
        .iter()
        .map(|ep| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::Enumeration,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: crawl_endpoint_properties(ep),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

fn crawl_endpoint_properties(
    endpoint: &aegis_crawler::DiscoveredEndpoint,
) -> Vec<(String, String)> {
    vec![
        ("path".to_string(), endpoint.url.clone()),
        ("method".to_string(), endpoint.method.clone()),
        (
            "discovery_source".to_string(),
            format!("{:?}", endpoint.source),
        ),
    ]
}
