use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::recon_client;
use crate::util::timestamp_ms;

const RATE_LIMIT_HEADERS: &[&str] = &[
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "x-rate-limit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "retry-after",
];

#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub headers: Vec<(String, String)>,
}

pub fn detect_rate_limits(target: &str) -> Option<RateLimitInfo> {
    recon_client::validated_domain(target)?;
    let client = recon_client::default_client()?;

    let resp = client.get(target).send().ok()?;
    let mut found_headers = Vec::new();

    for name in RATE_LIMIT_HEADERS {
        if let Some(val) = resp.headers().get(*name).and_then(|v| v.to_str().ok()) {
            found_headers.push((name.to_string(), val.to_string()));
        }
    }

    if found_headers.is_empty() {
        None
    } else {
        Some(RateLimitInfo {
            headers: found_headers,
        })
    }
}

pub fn rate_limit_to_operations(info: &RateLimitInfo, seq: &mut u64) -> Vec<OperationLogEntry> {
    *seq += 1;
    let props: Vec<(String, String)> = info
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .chain(std::iter::once((
            "source".to_string(),
            "rate_limit_detect".to_string(),
        )))
        .collect();

    vec![OperationLogEntry {
        sequence_number: *seq,
        module: ModuleIdentifier::PassiveRecon,
        operation: GraphOperation::AddNode {
            node_type: NodeType::Defense,
            properties: props,
        },
        timestamp_unix_ms: timestamp_ms(),
    }]
}
