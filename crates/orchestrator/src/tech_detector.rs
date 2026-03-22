use std::time::Duration;

use aegis_discovery::{DetectedTech, fingerprint_from_headers, fingerprint_from_html};
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;

const DETECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct TechDetection {
    pub name: String,
    pub version: Option<String>,
    pub category: String,
    pub confidence: f64,
    pub evidence: String,
}

pub fn detect_technologies(target: &str) -> Vec<TechDetection> {
    let domain = match aegis_exploiter::extract_domain(target) {
        Some(d) => d,
        None => return Vec::new(),
    };
    if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
        return Vec::new();
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(DETECT_TIMEOUT)
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body = resp.text().unwrap_or_default();

    let mut detections: Vec<DetectedTech> = fingerprint_from_headers(&headers);
    detections.extend(fingerprint_from_html(&body));

    dedup_detections(&detections)
}

fn dedup_detections(detections: &[DetectedTech]) -> Vec<TechDetection> {
    let mut seen = std::collections::HashSet::new();
    detections
        .iter()
        .filter(|d| seen.insert(d.name.clone()))
        .map(|d| TechDetection {
            name: d.name.clone(),
            version: d.version.clone(),
            category: d.category.to_string(),
            confidence: d.confidence,
            evidence: d.evidence.clone(),
        })
        .collect()
}

pub fn tech_to_operations(
    detections: &[TechDetection],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    detections
        .iter()
        .map(|d| {
            *seq += 1;
            let mut props = vec![
                ("name".to_string(), d.name.clone()),
                ("category".to_string(), d.category.clone()),
                ("confidence".to_string(), format!("{:.2}", d.confidence)),
                ("evidence".to_string(), d.evidence.clone()),
                ("source".to_string(), "tech_detect".to_string()),
            ];
            if let Some(v) = &d.version {
                props.push(("version".to_string(), v.clone()));
            }
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Service,
                    properties: props,
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}
