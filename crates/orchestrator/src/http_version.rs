use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::recon_client;
use crate::util::timestamp_ms;

#[derive(Debug, Clone)]
pub struct HttpVersionInfo {
    pub version: String,
    pub supports_h2: bool,
}

pub fn detect_http_version(target: &str) -> Option<HttpVersionInfo> {
    recon_client::validated_domain(target)?;
    let client = recon_client::default_client()?;

    let resp = client.get(target).send().ok()?;
    let version = format!("{:?}", resp.version());
    let supports_h2 = resp.version() == reqwest::Version::HTTP_2;

    Some(HttpVersionInfo {
        version,
        supports_h2,
    })
}

pub fn version_to_operations(info: &HttpVersionInfo, seq: &mut u64) -> Vec<OperationLogEntry> {
    *seq += 1;
    vec![OperationLogEntry {
        sequence_number: *seq,
        module: ModuleIdentifier::PassiveRecon,
        operation: GraphOperation::AddNode {
            node_type: NodeType::Service,
            properties: vec![
                ("http_version".to_string(), info.version.clone()),
                ("supports_h2".to_string(), info.supports_h2.to_string()),
                ("source".to_string(), "http_version_detect".to_string()),
            ],
        },
        timestamp_unix_ms: timestamp_ms(),
    }]
}
