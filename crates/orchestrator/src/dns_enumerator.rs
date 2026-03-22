use std::net::ToSocketAddrs;
use std::process::Command;

use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;

const DIG_TIMEOUT_SECS: u64 = 5;

#[derive(Debug, Clone, PartialEq)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
}

pub fn enumerate_dns(target: &str) -> Vec<DnsRecord> {
    let domain = match aegis_exploiter::extract_domain(target) {
        Some(d) => d,
        None => return Vec::new(),
    };
    if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
        return Vec::new();
    }

    let mut records = Vec::new();
    records.extend(resolve_a_aaaa(&domain));
    for rtype in &["MX", "TXT", "NS", "CNAME"] {
        records.extend(query_dig(&domain, rtype));
    }
    records
}

fn resolve_a_aaaa(domain: &str) -> Vec<DnsRecord> {
    let addr = format!("{domain}:80");
    let Ok(addrs) = addr.to_socket_addrs() else {
        return Vec::new();
    };
    let mut records = Vec::new();
    for a in addrs {
        let ip = a.ip();
        if ip.is_loopback() {
            continue;
        }
        let rtype = if ip.is_ipv4() { "A" } else { "AAAA" };
        let rec = DnsRecord {
            record_type: rtype.to_string(),
            value: ip.to_string(),
        };
        if !records.contains(&rec) {
            records.push(rec);
        }
    }
    records
}

fn query_dig(domain: &str, record_type: &str) -> Vec<DnsRecord> {
    let output = Command::new("dig")
        .args([
            "+short",
            &format!("+time={DIG_TIMEOUT_SECS}"),
            "+tries=1",
            domain,
            record_type,
        ])
        .output();
    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_dig_output(&stdout, record_type)
}

pub(crate) fn parse_dig_output(stdout: &str, record_type: &str) -> Vec<DnsRecord> {
    stdout
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with(';'))
        .map(|l| DnsRecord {
            record_type: record_type.to_string(),
            value: l.trim_end_matches('.').to_string(),
        })
        .collect()
}

pub fn dns_to_operations(records: &[DnsRecord], seq: &mut u64) -> Vec<OperationLogEntry> {
    records
        .iter()
        .map(|rec| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Service,
                    properties: vec![
                        ("dns_type".to_string(), rec.record_type.clone()),
                        ("value".to_string(), rec.value.clone()),
                        ("source".to_string(), "dns".to_string()),
                    ],
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}
