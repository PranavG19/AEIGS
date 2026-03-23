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

pub fn parse_internetdb_response(body: &str, ip: &str) -> Option<ShodanResult> {
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

#[derive(Debug, Clone, PartialEq)]
pub enum ShodanIssue {
    HighRiskPort { port: u16 },
    KnownCve { cve_id: String },
    MultipleCves { count: usize },
    OutdatedCpe { cpe: String, technology: String },
    CloudHosted { provider: String },
    HoneypotIndicator { tag: String },
    ExposiveService { port: u16, service: String },
    HighPortCount { count: usize },
}

impl std::fmt::Display for ShodanIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HighRiskPort { port } => write!(f, "high_risk_port:{port}"),
            Self::KnownCve { cve_id } => write!(f, "known_cve:{cve_id}"),
            Self::MultipleCves { count } => write!(f, "multiple_cves:{count}"),
            Self::OutdatedCpe { cpe, technology } => write!(f, "outdated_cpe:{technology}:{cpe}"),
            Self::CloudHosted { provider } => write!(f, "cloud_hosted:{provider}"),
            Self::HoneypotIndicator { tag } => write!(f, "honeypot:{tag}"),
            Self::ExposiveService { port, service } => {
                write!(f, "exposed_service:{service}:{port}")
            }
            Self::HighPortCount { count } => write!(f, "high_port_count:{count}"),
        }
    }
}

const HIGH_RISK_PORTS: &[u16] = &[
    21, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017,
];

const CLOUD_PROVIDERS: &[(&str, &str)] = &[
    ("amazon", "AWS"),
    ("azure", "Azure"),
    ("google", "GCP"),
    ("digitalocean", "DigitalOcean"),
    ("linode", "Linode"),
    ("vultr", "Vultr"),
];

const EXPOSED_SERVICES: &[(u16, &str)] = &[
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (27017, "MongoDB"),
    (9200, "Elasticsearch"),
    (11211, "Memcached"),
    (5900, "VNC"),
    (3389, "RDP"),
];

pub fn shodan_issue_severity(issue: &ShodanIssue) -> f64 {
    match issue {
        ShodanIssue::KnownCve { .. } => 8.0,
        ShodanIssue::MultipleCves { count } => {
            if *count > 10 {
                9.0
            } else {
                7.5
            }
        }
        ShodanIssue::ExposiveService { .. } => 7.0,
        ShodanIssue::HighRiskPort { .. } => 6.0,
        ShodanIssue::HoneypotIndicator { .. } => 5.0,
        ShodanIssue::OutdatedCpe { .. } => 6.5,
        ShodanIssue::HighPortCount { .. } => 5.5,
        ShodanIssue::CloudHosted { .. } => 2.0,
    }
}

pub fn analyze_shodan_result(result: &ShodanResult) -> Vec<ShodanIssue> {
    let mut issues = Vec::new();

    for &port in &result.ports {
        if HIGH_RISK_PORTS.contains(&port) {
            issues.push(ShodanIssue::HighRiskPort { port });
        }
        if let Some(&(_, service)) = EXPOSED_SERVICES.iter().find(|&&(p, _)| p == port) {
            issues.push(ShodanIssue::ExposiveService {
                port,
                service: service.to_string(),
            });
        }
    }

    if result.ports.len() > 20 {
        issues.push(ShodanIssue::HighPortCount {
            count: result.ports.len(),
        });
    }

    for vuln in &result.vulns {
        issues.push(ShodanIssue::KnownCve {
            cve_id: vuln.clone(),
        });
    }
    if result.vulns.len() > 3 {
        issues.push(ShodanIssue::MultipleCves {
            count: result.vulns.len(),
        });
    }

    for cpe in &result.cpes {
        if let Some(tech) = extract_cpe_technology(cpe) {
            issues.push(ShodanIssue::OutdatedCpe {
                cpe: cpe.clone(),
                technology: tech,
            });
        }
    }

    for tag in &result.tags {
        let lower = tag.to_ascii_lowercase();
        if lower.contains("honeypot") || lower.contains("self-signed") {
            issues.push(ShodanIssue::HoneypotIndicator { tag: tag.clone() });
        }
    }

    for hostname in &result.hostnames {
        let lower = hostname.to_ascii_lowercase();
        for &(pattern, provider) in CLOUD_PROVIDERS {
            if lower.contains(pattern) {
                issues.push(ShodanIssue::CloudHosted {
                    provider: provider.to_string(),
                });
                break;
            }
        }
    }

    issues
}

fn extract_cpe_technology(cpe: &str) -> Option<String> {
    // cpe format: cpe:/a:vendor:product:version or cpe:2.3:a:vendor:product:version
    let parts: Vec<&str> = cpe.split(':').collect();
    if parts.len() >= 4 {
        // For cpe:/a:vendor:product format
        let product = if cpe.starts_with("cpe:2.3") && parts.len() >= 5 {
            parts[4]
        } else if cpe.starts_with("cpe:/") && parts.len() >= 4 {
            parts[3]
        } else {
            return None;
        };
        if !product.is_empty() {
            return Some(product.replace('_', " "));
        }
    }
    None
}

pub fn shodan_issues_to_operations(
    issues: &[ShodanIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                shodan_issue_severity(issue),
                0.5,
            )
        })
        .collect()
}
