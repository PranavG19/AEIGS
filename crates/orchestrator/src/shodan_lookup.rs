use std::net::ToSocketAddrs;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::recon_client;
use crate::util::timestamp_ms;

#[derive(Debug, Clone)]
pub struct ShodanResult {
    pub ip: String,
    pub ports: Vec<u16>,
    pub hostnames: Vec<String>,
    pub vulns: Vec<String>,
    pub cpes: Vec<String>,
    pub tags: Vec<String>,
}

pub fn resolve_ip(domain: &str) -> Option<String> {
    let addr = format!("{domain}:80");
    addr.to_socket_addrs().ok()?.find_map(|a| {
        let ip = a.ip();
        if ip.is_loopback() {
            None
        } else {
            Some(ip.to_string())
        }
    })
}

pub fn query_internetdb(ip: &str) -> Option<ShodanResult> {
    let url = format!("https://internetdb.shodan.io/{ip}");
    let client = recon_client::default_client()?;
    let resp = client.get(&url).send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().ok()?;
    parse_internetdb_response(&body, ip)
}

pub(crate) fn parse_internetdb_response(body: &str, ip: &str) -> Option<ShodanResult> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    let obj = json.as_object()?;
    let ports = obj
        .get("ports")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u16))
                .collect()
        })
        .unwrap_or_default();
    let hostnames = obj
        .get("hostnames")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let vulns = obj
        .get("vulns")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let cpes = obj
        .get("cpes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let tags = obj
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Some(ShodanResult {
        ip: ip.to_string(),
        ports,
        hostnames,
        vulns,
        cpes,
        tags,
    })
}

pub fn shodan_lookup(target: &str) -> Option<ShodanResult> {
    let domain = recon_client::validated_domain(target)?;
    let ip = resolve_ip(&domain)?;
    query_internetdb(&ip)
}

pub fn shodan_to_operations(result: &ShodanResult, seq: &mut u64) -> Vec<OperationLogEntry> {
    let mut entries = Vec::new();
    for &port in &result.ports {
        *seq += 1;
        entries.push(OperationLogEntry {
            sequence_number: *seq,
            module: ModuleIdentifier::PassiveRecon,
            operation: GraphOperation::AddNode {
                node_type: NodeType::Service,
                properties: vec![
                    ("hostname".to_string(), result.ip.clone()),
                    ("port".to_string(), port.to_string()),
                    ("source".to_string(), "shodan-internetdb".to_string()),
                ],
            },
            timestamp_unix_ms: timestamp_ms(),
        });
    }
    for _vuln in &result.vulns {
        entries.push(recon_client::finding_entry(
            seq,
            VulnerabilityClass::KnownVulnerableDependency,
            7.0,
            0.7,
        ));
    }
    entries
}
