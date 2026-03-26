use std::collections::HashMap;
use std::fmt;

/// DNS record type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Txt,
    Soa,
    Ptr,
    Srv,
    Dnskey,
    Ds,
    Rrsig,
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::Aaaa => write!(f, "AAAA"),
            Self::Cname => write!(f, "CNAME"),
            Self::Mx => write!(f, "MX"),
            Self::Ns => write!(f, "NS"),
            Self::Txt => write!(f, "TXT"),
            Self::Soa => write!(f, "SOA"),
            Self::Ptr => write!(f, "PTR"),
            Self::Srv => write!(f, "SRV"),
            Self::Dnskey => write!(f, "DNSKEY"),
            Self::Ds => write!(f, "DS"),
            Self::Rrsig => write!(f, "RRSIG"),
        }
    }
}

/// Source of passive DNS data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PassiveDnsSource {
    SecurityTrails,
    Dnsdb,
    Farsight,
    VirusTotal,
    RiskIq,
    Robtex,
    DnsDumpster,
}

impl fmt::Display for PassiveDnsSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecurityTrails => write!(f, "SecurityTrails"),
            Self::Dnsdb => write!(f, "DNSDB"),
            Self::Farsight => write!(f, "Farsight"),
            Self::VirusTotal => write!(f, "VirusTotal"),
            Self::RiskIq => write!(f, "RiskIQ"),
            Self::Robtex => write!(f, "Robtex"),
            Self::DnsDumpster => write!(f, "DNSDumpster"),
        }
    }
}

/// A single passive DNS record observation.
#[derive(Debug, Clone, PartialEq)]
pub struct PassiveDnsRecord {
    pub query_name: String,
    pub record_type: DnsRecordType,
    pub record_value: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub count: u64,
    pub source: PassiveDnsSource,
}

/// Historical DNS change event.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsChange {
    pub domain: String,
    pub record_type: DnsRecordType,
    pub old_value: String,
    pub new_value: String,
    pub change_date: String,
    pub source: PassiveDnsSource,
}

/// DNS infrastructure mapping.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsInfrastructure {
    pub domain: String,
    pub nameservers: Vec<String>,
    pub mail_servers: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub subdomains: Vec<String>,
    pub cname_chains: Vec<Vec<String>>,
    pub shared_ips: HashMap<String, Vec<String>>,
}

/// Full passive DNS report.
#[derive(Debug, Clone, PartialEq)]
pub struct PassiveDnsReport {
    pub target_domain: String,
    pub records: Vec<PassiveDnsRecord>,
    pub changes: Vec<DnsChange>,
    pub infrastructure: DnsInfrastructure,
    pub total_records: usize,
    pub unique_ips: usize,
    pub unique_subdomains: usize,
    pub sources_queried: Vec<PassiveDnsSource>,
    pub historical_depth_days: u64,
}

/// Parses SecurityTrails API JSON response.
pub fn parse_security_trails_response(json_body: &str, domain: &str) -> Vec<PassiveDnsRecord> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(json_body) else {
        return Vec::new();
    };

    let mut records = Vec::new();

    if let Some(current) = val.get("current_dns") {
        let record_types = [
            ("a", DnsRecordType::A),
            ("aaaa", DnsRecordType::Aaaa),
            ("mx", DnsRecordType::Mx),
            ("ns", DnsRecordType::Ns),
            ("txt", DnsRecordType::Txt),
            ("soa", DnsRecordType::Soa),
            ("cname", DnsRecordType::Cname),
        ];

        for (key, rtype) in &record_types {
            if let Some(section) = current.get(*key) {
                if let Some(values) = section.get("values").and_then(|v| v.as_array()) {
                    for v in values {
                        let value = v
                            .get("ip")
                            .or_else(|| v.get("value"))
                            .or_else(|| v.get("host"))
                            .and_then(|x| x.as_str())
                            .unwrap_or("");
                        if !value.is_empty() {
                            records.push(PassiveDnsRecord {
                                query_name: domain.to_string(),
                                record_type: *rtype,
                                record_value: value.to_string(),
                                first_seen: section
                                    .get("first_seen")
                                    .and_then(|v| v.as_str())
                                    .map(String::from),
                                last_seen: None,
                                count: 1,
                                source: PassiveDnsSource::SecurityTrails,
                            });
                        }
                    }
                }
            }
        }
    }

    if let Some(subdomains) = val.get("subdomains").and_then(|v| v.as_array()) {
        for sub in subdomains {
            if let Some(name) = sub.as_str() {
                records.push(PassiveDnsRecord {
                    query_name: format!("{}.{}", name, domain),
                    record_type: DnsRecordType::A,
                    record_value: String::new(),
                    first_seen: None,
                    last_seen: None,
                    count: 0,
                    source: PassiveDnsSource::SecurityTrails,
                });
            }
        }
    }

    records
}

/// Parses DNSDB (Farsight) lookup response.
/// DNSDB uses JSON lines (NDJSON) format.
pub fn parse_dnsdb_response(ndjson_body: &str) -> Vec<PassiveDnsRecord> {
    let mut records = Vec::new();

    for line in ndjson_body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };

        let query_name = val
            .get("rrname")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim_end_matches('.')
            .to_string();

        let rrtype_str = val.get("rrtype").and_then(|v| v.as_str()).unwrap_or("");
        let record_type = parse_record_type(rrtype_str);

        let rdata = val.get("rdata");
        let values: Vec<String> = match rdata {
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.trim_end_matches('.').to_string()))
                .collect(),
            Some(serde_json::Value::String(s)) => vec![s.trim_end_matches('.').to_string()],
            _ => vec![],
        };

        let count = val.get("count").and_then(|v| v.as_u64()).unwrap_or(1);
        let first_seen = val
            .get("time_first")
            .and_then(|v| v.as_u64())
            .map(|ts| format_timestamp(ts));
        let last_seen = val
            .get("time_last")
            .and_then(|v| v.as_u64())
            .map(|ts| format_timestamp(ts));

        for value in values {
            records.push(PassiveDnsRecord {
                query_name: query_name.clone(),
                record_type,
                record_value: value,
                first_seen: first_seen.clone(),
                last_seen: last_seen.clone(),
                count,
                source: PassiveDnsSource::Dnsdb,
            });
        }
    }

    records
}

/// Parses Farsight DNSDB response (same as DNSDB but with source tag).
pub fn parse_farsight_response(ndjson_body: &str) -> Vec<PassiveDnsRecord> {
    let mut records = parse_dnsdb_response(ndjson_body);
    for r in &mut records {
        r.source = PassiveDnsSource::Farsight;
    }
    records
}

/// Parses a DNS record type string.
pub fn parse_record_type(rrtype: &str) -> DnsRecordType {
    match rrtype.to_uppercase().as_str() {
        "A" => DnsRecordType::A,
        "AAAA" => DnsRecordType::Aaaa,
        "CNAME" => DnsRecordType::Cname,
        "MX" => DnsRecordType::Mx,
        "NS" => DnsRecordType::Ns,
        "TXT" => DnsRecordType::Txt,
        "SOA" => DnsRecordType::Soa,
        "PTR" => DnsRecordType::Ptr,
        "SRV" => DnsRecordType::Srv,
        "DNSKEY" => DnsRecordType::Dnskey,
        "DS" => DnsRecordType::Ds,
        "RRSIG" => DnsRecordType::Rrsig,
        _ => DnsRecordType::A,
    }
}

fn format_timestamp(unix_ts: u64) -> String {
    let secs = unix_ts;
    let days = secs / 86400;
    let years = 1970 + days / 365;
    format!("{}-01-01", years)
}

/// Deduplicates records by (query_name, record_type, record_value), keeping highest count.
pub fn deduplicate_records(records: Vec<PassiveDnsRecord>) -> Vec<PassiveDnsRecord> {
    let mut map: HashMap<(String, String, String), PassiveDnsRecord> = HashMap::new();

    for r in records {
        let key = (
            r.query_name.clone(),
            r.record_type.to_string(),
            r.record_value.clone(),
        );
        let entry = map.entry(key).or_insert(r.clone());
        if r.count > entry.count {
            entry.count = r.count;
        }
        if entry.first_seen.is_none() && r.first_seen.is_some() {
            entry.first_seen = r.first_seen;
        }
        if r.last_seen.is_some() {
            entry.last_seen = r.last_seen;
        }
    }

    map.into_values().collect()
}

/// Detects DNS changes by comparing historical records.
pub fn detect_changes(
    old_records: &[PassiveDnsRecord],
    new_records: &[PassiveDnsRecord],
) -> Vec<DnsChange> {
    let mut changes = Vec::new();

    let old_map: HashMap<(String, String), String> = old_records
        .iter()
        .filter(|r| !r.record_value.is_empty())
        .map(|r| {
            (
                (r.query_name.clone(), r.record_type.to_string()),
                r.record_value.clone(),
            )
        })
        .collect();

    let new_map: HashMap<(String, String), String> = new_records
        .iter()
        .filter(|r| !r.record_value.is_empty())
        .map(|r| {
            (
                (r.query_name.clone(), r.record_type.to_string()),
                r.record_value.clone(),
            )
        })
        .collect();

    for (key, old_val) in &old_map {
        if let Some(new_val) = new_map.get(key) {
            if old_val != new_val {
                changes.push(DnsChange {
                    domain: key.0.clone(),
                    record_type: parse_record_type(&key.1),
                    old_value: old_val.clone(),
                    new_value: new_val.clone(),
                    change_date: "detected".to_string(),
                    source: PassiveDnsSource::SecurityTrails,
                });
            }
        }
    }

    changes
}

/// Builds DNS infrastructure mapping from records.
pub fn build_infrastructure(domain: &str, records: &[PassiveDnsRecord]) -> DnsInfrastructure {
    let mut nameservers = Vec::new();
    let mut mail_servers = Vec::new();
    let mut ip_addresses = Vec::new();
    let mut subdomains = Vec::new();
    let mut cname_chains: Vec<Vec<String>> = Vec::new();
    let mut ip_to_domains: HashMap<String, Vec<String>> = HashMap::new();

    for r in records {
        match r.record_type {
            DnsRecordType::Ns => {
                if !nameservers.contains(&r.record_value) {
                    nameservers.push(r.record_value.clone());
                }
            }
            DnsRecordType::Mx => {
                if !mail_servers.contains(&r.record_value) {
                    mail_servers.push(r.record_value.clone());
                }
            }
            DnsRecordType::A | DnsRecordType::Aaaa => {
                if !r.record_value.is_empty() && !ip_addresses.contains(&r.record_value) {
                    ip_addresses.push(r.record_value.clone());
                }
                ip_to_domains
                    .entry(r.record_value.clone())
                    .or_default()
                    .push(r.query_name.clone());
            }
            DnsRecordType::Cname => {
                cname_chains.push(vec![r.query_name.clone(), r.record_value.clone()]);
            }
            _ => {}
        }

        if r.query_name != domain
            && r.query_name.ends_with(domain)
            && !subdomains.contains(&r.query_name)
        {
            subdomains.push(r.query_name.clone());
        }
    }

    let shared_ips: HashMap<String, Vec<String>> = ip_to_domains
        .into_iter()
        .filter(|(_, domains)| domains.len() > 1)
        .collect();

    nameservers.sort();
    mail_servers.sort();
    ip_addresses.sort();
    subdomains.sort();

    DnsInfrastructure {
        domain: domain.to_string(),
        nameservers,
        mail_servers,
        ip_addresses,
        subdomains,
        cname_chains,
        shared_ips,
    }
}

/// Builds a full passive DNS report.
pub fn build_passive_dns_report(
    target_domain: &str,
    records: Vec<PassiveDnsRecord>,
    changes: Vec<DnsChange>,
    sources: Vec<PassiveDnsSource>,
) -> PassiveDnsReport {
    let infrastructure = build_infrastructure(target_domain, &records);
    let total_records = records.len();
    let unique_ips = infrastructure.ip_addresses.len();
    let unique_subdomains = infrastructure.subdomains.len();

    PassiveDnsReport {
        target_domain: target_domain.to_string(),
        records,
        changes,
        infrastructure,
        total_records,
        unique_ips,
        unique_subdomains,
        sources_queried: sources,
        historical_depth_days: 365,
    }
}
