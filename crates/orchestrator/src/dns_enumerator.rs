use std::net::ToSocketAddrs;
use std::process::Command;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::recon_client;
use crate::util::timestamp_ms;

const DIG_TIMEOUT_SECS: u64 = 5;

#[derive(Debug, Clone, PartialEq)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
}

pub fn enumerate_dns(target: &str) -> Vec<DnsRecord> {
    let Some(domain) = recon_client::validated_domain(target) else {
        return Vec::new();
    };

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

pub fn parse_dig_output(stdout: &str, record_type: &str) -> Vec<DnsRecord> {
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

#[derive(Debug, Clone, PartialEq)]
pub enum DnsIssue {
    OpenResolver { nameserver: String },
    ZoneTransferPossible { nameserver: String },
    MissingSpf,
    WeakSpf { record: String },
    MissingDmarc,
    WeakDmarc { policy: String },
    DanglingCname { cname: String },
    InternalIpLeak { ip: String },
    WildcardDns,
    MissingDnssec,
    LowTtl { record_type: String, value: String },
}

impl std::fmt::Display for DnsIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsIssue::OpenResolver { nameserver } => {
                write!(f, "open_resolver: {nameserver}")
            }
            DnsIssue::ZoneTransferPossible { nameserver } => {
                write!(f, "zone_transfer_possible: {nameserver}")
            }
            DnsIssue::MissingSpf => write!(f, "missing_spf"),
            DnsIssue::WeakSpf { record } => write!(f, "weak_spf: {record}"),
            DnsIssue::MissingDmarc => write!(f, "missing_dmarc"),
            DnsIssue::WeakDmarc { policy } => write!(f, "weak_dmarc: {policy}"),
            DnsIssue::DanglingCname { cname } => {
                write!(f, "dangling_cname: {cname}")
            }
            DnsIssue::InternalIpLeak { ip } => {
                write!(f, "internal_ip_leak: {ip}")
            }
            DnsIssue::WildcardDns => write!(f, "wildcard_dns"),
            DnsIssue::MissingDnssec => write!(f, "missing_dnssec"),
            DnsIssue::LowTtl { record_type, value } => write!(f, "low_ttl: {record_type} {value}"),
        }
    }
}

pub fn dns_issue_severity(issue: &DnsIssue) -> f64 {
    match issue {
        DnsIssue::ZoneTransferPossible { .. } => 9.0,
        DnsIssue::OpenResolver { .. } => 7.0,
        DnsIssue::DanglingCname { .. } => 6.5,
        DnsIssue::InternalIpLeak { .. } => 6.0,
        DnsIssue::WeakSpf { .. } => 5.0,
        DnsIssue::WeakDmarc { .. } => 4.5,
        DnsIssue::MissingSpf => 4.0,
        DnsIssue::MissingDmarc => 3.5,
        DnsIssue::WildcardDns => 3.0,
        DnsIssue::MissingDnssec => 2.5,
        DnsIssue::LowTtl { .. } => 2.0,
    }
}

pub fn analyze_dns_records(records: &[DnsRecord]) -> Vec<DnsIssue> {
    let mut issues = Vec::new();

    let txt_records: Vec<&DnsRecord> = records.iter().filter(|r| r.record_type == "TXT").collect();

    let has_spf = txt_records.iter().any(|r| r.value.starts_with("v=spf1"));
    if !has_spf {
        issues.push(DnsIssue::MissingSpf);
    } else {
        for rec in &txt_records {
            if rec.value.starts_with("v=spf1") && rec.value.contains("+all") {
                issues.push(DnsIssue::WeakSpf {
                    record: rec.value.clone(),
                });
            }
        }
    }

    let has_dmarc = txt_records.iter().any(|r| r.value.starts_with("v=DMARC1"));
    if !has_dmarc {
        issues.push(DnsIssue::MissingDmarc);
    } else {
        for rec in &txt_records {
            if rec.value.starts_with("v=DMARC1") && rec.value.contains("p=none") {
                issues.push(DnsIssue::WeakDmarc {
                    policy: "none".to_string(),
                });
            }
        }
    }

    for rec in records {
        if (rec.record_type == "A" || rec.record_type == "AAAA") && is_internal_ip(&rec.value) {
            issues.push(DnsIssue::InternalIpLeak {
                ip: rec.value.clone(),
            });
        }
    }

    issues
}

fn is_internal_ip(ip: &str) -> bool {
    if let Some(rest) = ip.strip_prefix("10.") {
        return rest.split('.').count() == 3;
    }
    if let Some(rest) = ip.strip_prefix("192.168.") {
        return rest.split('.').count() == 2;
    }
    if let Some(rest) = ip.strip_prefix("172.") {
        let parts: Vec<&str> = rest.split('.').collect();
        if parts.len() == 3
            && let Ok(second) = parts[0].parse::<u8>()
        {
            return (16..=31).contains(&second);
        }
    }
    false
}

pub fn dns_issues_to_operations(issues: &[DnsIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                dns_issue_severity(issue),
                0.5,
            )
        })
        .collect()
}
