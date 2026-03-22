use std::time::Duration;

use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;

const WAF_TIMEOUT: Duration = Duration::from_secs(10);

const WAF_SIGNATURES: &[(&str, &str)] = &[
    ("cloudflare", "cf-ray"),
    ("akamai", "x-akamai-transformed"),
    ("aws-waf", "x-amzn-requestid"),
    ("sucuri", "x-sucuri-id"),
    ("incapsula", "x-cdn"),
    ("stackpath", "x-sp-"),
    ("barracuda", "barra_counter_session"),
    ("f5-bigip", "x-wa-info"),
    ("fortiweb", "fortiwafsid"),
    ("wallarm", "x-wallarm-"),
];

const WAF_SERVER_VALUES: &[(&str, &str)] = &[
    ("cloudflare", "cloudflare"),
    ("nginx", "nginx"),
    ("apache", "apache"),
    ("microsoft-iis", "microsoft-iis"),
    ("openresty", "openresty"),
    ("litespeed", "litespeed"),
    ("envoy", "envoy"),
    ("varnish", "varnish"),
];

#[derive(Debug, Clone)]
pub struct WafDetection {
    pub waf_name: String,
    pub evidence: String,
}

pub fn detect_waf(target: &str) -> Vec<WafDetection> {
    let domain = match aegis_exploiter::extract_domain(target) {
        Some(d) => d,
        None => return Vec::new(),
    };
    if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
        return Vec::new();
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(WAF_TIMEOUT)
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

    let mut detections = Vec::new();
    let headers = resp.headers();

    for (waf, sig_header) in WAF_SIGNATURES {
        for (name, _value) in headers.iter() {
            if name.as_str().contains(sig_header) {
                detections.push(WafDetection {
                    waf_name: waf.to_string(),
                    evidence: format!("header: {}", name.as_str()),
                });
                break;
            }
        }
    }

    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        let lower = server.to_ascii_lowercase();
        for (name, pattern) in WAF_SERVER_VALUES {
            if lower.contains(pattern) {
                detections.push(WafDetection {
                    waf_name: name.to_string(),
                    evidence: format!("server: {server}"),
                });
                break;
            }
        }
    }

    detections
}

pub fn waf_to_operations(
    detections: &[WafDetection],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    detections
        .iter()
        .map(|d| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Defense,
                    properties: vec![
                        ("waf_name".to_string(), d.waf_name.clone()),
                        ("evidence".to_string(), d.evidence.clone()),
                        ("source".to_string(), "waf_detect".to_string()),
                    ],
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}
