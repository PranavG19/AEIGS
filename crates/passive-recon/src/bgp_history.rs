use std::collections::HashMap;
use std::fmt;

/// BGP data source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BgpSource {
    RipeRis,
    RouteViews,
    Bgpstream,
    TeamCymru,
    Hurricane,
}

impl fmt::Display for BgpSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RipeRis => write!(f, "RIPE RIS"),
            Self::RouteViews => write!(f, "RouteViews"),
            Self::Bgpstream => write!(f, "BGPStream"),
            Self::TeamCymru => write!(f, "Team Cymru"),
            Self::Hurricane => write!(f, "Hurricane Electric"),
        }
    }
}

/// Risk level for BGP findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BgpRisk {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for BgpRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "Info"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// An Autonomous System (AS).
#[derive(Debug, Clone, PartialEq)]
pub struct AutonomousSystem {
    pub asn: u32,
    pub name: Option<String>,
    pub country: Option<String>,
    pub description: Option<String>,
    pub prefix_count: usize,
}

/// A BGP prefix announcement.
#[derive(Debug, Clone, PartialEq)]
pub struct BgpPrefix {
    pub prefix: String,
    pub prefix_length: u8,
    pub origin_asn: u32,
    pub as_path: Vec<u32>,
    pub next_hop: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub source: BgpSource,
}

/// A BGP route change event.
#[derive(Debug, Clone, PartialEq)]
pub struct BgpRouteChange {
    pub prefix: String,
    pub change_type: RouteChangeType,
    pub old_asn: Option<u32>,
    pub new_asn: u32,
    pub old_path: Vec<u32>,
    pub new_path: Vec<u32>,
    pub timestamp: String,
    pub source: BgpSource,
}

/// Type of BGP route change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteChangeType {
    Announcement,
    Withdrawal,
    PathChange,
    OriginChange,
    MoreSpecific,
    Hijack,
}

impl fmt::Display for RouteChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Announcement => write!(f, "Announcement"),
            Self::Withdrawal => write!(f, "Withdrawal"),
            Self::PathChange => write!(f, "Path Change"),
            Self::OriginChange => write!(f, "Origin Change"),
            Self::MoreSpecific => write!(f, "More Specific"),
            Self::Hijack => write!(f, "Possible Hijack"),
        }
    }
}

/// IP address reuse/history record.
#[derive(Debug, Clone, PartialEq)]
pub struct IpReuseRecord {
    pub ip_prefix: String,
    pub historical_owners: Vec<(u32, String)>,
    pub current_owner: Option<u32>,
    pub owner_changes: usize,
    pub risk: BgpRisk,
}

/// AS path analysis result.
#[derive(Debug, Clone, PartialEq)]
pub struct AsPathAnalysis {
    pub prefix: String,
    pub path: Vec<u32>,
    pub path_length: usize,
    pub has_prepending: bool,
    pub prepend_count: usize,
    pub transit_asns: Vec<u32>,
    pub origin_asn: u32,
    pub upstream_asns: Vec<u32>,
    pub anomalies: Vec<String>,
}

/// Full BGP history report.
#[derive(Debug, Clone, PartialEq)]
pub struct BgpHistoryReport {
    pub target_prefixes: Vec<String>,
    pub autonomous_systems: Vec<AutonomousSystem>,
    pub current_prefixes: Vec<BgpPrefix>,
    pub route_changes: Vec<BgpRouteChange>,
    pub ip_reuse: Vec<IpReuseRecord>,
    pub path_analyses: Vec<AsPathAnalysis>,
    pub total_prefixes: usize,
    pub total_changes: usize,
    pub risk_summary: HashMap<BgpRisk, usize>,
    pub overall_risk: BgpRisk,
}

/// Parses RIPE RIS looking glass JSON response.
pub fn parse_ripe_ris_response(json_body: &str) -> Vec<BgpPrefix> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(json_body) else {
        return Vec::new();
    };

    let mut prefixes = Vec::new();

    let ris_data = val
        .get("data")
        .and_then(|d| d.get("rrcs"))
        .and_then(|r| r.as_object());

    if let Some(rrcs) = ris_data {
        for (_rrc_id, rrc_data) in rrcs {
            if let Some(peers) = rrc_data.get("peers").and_then(|p| p.as_array()) {
                for peer in peers {
                    let as_path_str = peer.get("as_path").and_then(|v| v.as_str()).unwrap_or("");
                    let as_path = parse_as_path(as_path_str);
                    let prefix = peer
                        .get("prefix")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let origin = as_path.last().copied().unwrap_or(0);

                    if !prefix.is_empty() {
                        let prefix_len = prefix
                            .split('/')
                            .nth(1)
                            .and_then(|s| s.parse::<u8>().ok())
                            .unwrap_or(0);

                        prefixes.push(BgpPrefix {
                            prefix: prefix.clone(),
                            prefix_length: prefix_len,
                            origin_asn: origin,
                            as_path,
                            next_hop: peer
                                .get("next_hop")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                            first_seen: None,
                            last_seen: None,
                            source: BgpSource::RipeRis,
                        });
                    }
                }
            }
        }
    }

    if let Some(rdata) = val
        .get("data")
        .and_then(|d| d.get("prefixes"))
        .and_then(|p| p.as_array())
    {
        for entry in rdata {
            let prefix = entry
                .get("prefix")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let origin_str = entry.get("origin").and_then(|v| v.as_str()).unwrap_or("0");
            let origin = origin_str
                .trim_start_matches("AS")
                .parse::<u32>()
                .unwrap_or(0);
            let prefix_len = prefix
                .split('/')
                .nth(1)
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(0);

            if !prefix.is_empty() {
                prefixes.push(BgpPrefix {
                    prefix,
                    prefix_length: prefix_len,
                    origin_asn: origin,
                    as_path: vec![origin],
                    next_hop: None,
                    first_seen: entry
                        .get("timelines")
                        .and_then(|t| t.as_array())
                        .and_then(|a| a.first())
                        .and_then(|t| t.get("starttime"))
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    last_seen: entry
                        .get("timelines")
                        .and_then(|t| t.as_array())
                        .and_then(|a| a.last())
                        .and_then(|t| t.get("endtime"))
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    source: BgpSource::RipeRis,
                });
            }
        }
    }

    prefixes
}

/// Parses RouteViews MRT dump summary (simplified text format).
pub fn parse_routeviews_text(text: &str) -> Vec<BgpPrefix> {
    let mut prefixes = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("STATUS") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        let prefix = parts[0].to_string();
        let prefix_len = prefix
            .split('/')
            .nth(1)
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(0);

        let as_path: Vec<u32> = parts[1..]
            .iter()
            .filter_map(|s| s.parse::<u32>().ok())
            .collect();

        let origin = as_path.last().copied().unwrap_or(0);

        prefixes.push(BgpPrefix {
            prefix,
            prefix_length: prefix_len,
            origin_asn: origin,
            as_path,
            next_hop: None,
            first_seen: None,
            last_seen: None,
            source: BgpSource::RouteViews,
        });
    }

    prefixes
}

/// Parses a space-separated AS path string.
pub fn parse_as_path(path_str: &str) -> Vec<u32> {
    path_str
        .split_whitespace()
        .filter_map(|s| s.trim_start_matches("AS").parse::<u32>().ok())
        .collect()
}

/// Analyzes an AS path for anomalies.
pub fn analyze_as_path(prefix: &str, as_path: &[u32]) -> AsPathAnalysis {
    let path_length = as_path.len();
    let origin_asn = as_path.last().copied().unwrap_or(0);

    let mut has_prepending = false;
    let mut prepend_count = 0;
    let mut prev = 0u32;
    for &asn in as_path {
        if asn == prev && asn != 0 {
            has_prepending = true;
            prepend_count += 1;
        }
        prev = asn;
    }

    let transit_asns: Vec<u32> = if as_path.len() > 2 {
        as_path[1..as_path.len() - 1].to_vec()
    } else {
        Vec::new()
    };

    let upstream_asns: Vec<u32> = if as_path.len() > 1 {
        vec![as_path[as_path.len() - 2]]
    } else {
        Vec::new()
    };

    let mut anomalies = Vec::new();
    if path_length > 8 {
        anomalies.push(format!("Unusually long AS path: {} hops", path_length));
    }
    if prepend_count > 3 {
        anomalies.push(format!("Excessive prepending: {} times", prepend_count));
    }

    let mut deduped = as_path.to_vec();
    deduped.dedup();
    if deduped.len() < as_path.len() / 2 && as_path.len() > 4 {
        anomalies.push("Suspicious path inflation detected".to_string());
    }

    AsPathAnalysis {
        prefix: prefix.to_string(),
        path: as_path.to_vec(),
        path_length,
        has_prepending,
        prepend_count,
        transit_asns,
        origin_asn,
        upstream_asns,
        anomalies,
    }
}

/// Detects IP prefix reuse from historical BGP data.
pub fn detect_ip_reuse(prefix: &str, historical_prefixes: &[BgpPrefix]) -> IpReuseRecord {
    let relevant: Vec<&BgpPrefix> = historical_prefixes
        .iter()
        .filter(|p| p.prefix == prefix)
        .collect();

    let mut owners: Vec<(u32, String)> = Vec::new();
    let mut seen_asns = std::collections::HashSet::new();

    for p in &relevant {
        if seen_asns.insert(p.origin_asn) {
            let date = p
                .first_seen
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            owners.push((p.origin_asn, date));
        }
    }

    let current_owner = relevant.last().map(|p| p.origin_asn);
    let owner_changes = if owners.len() > 1 {
        owners.len() - 1
    } else {
        0
    };

    let risk = match owner_changes {
        0 => BgpRisk::Info,
        1 => BgpRisk::Low,
        2..=3 => BgpRisk::Medium,
        4..=5 => BgpRisk::High,
        _ => BgpRisk::Critical,
    };

    IpReuseRecord {
        ip_prefix: prefix.to_string(),
        historical_owners: owners,
        current_owner,
        owner_changes,
        risk,
    }
}

/// Detects route changes between two snapshots.
pub fn detect_route_changes(
    old_prefixes: &[BgpPrefix],
    new_prefixes: &[BgpPrefix],
) -> Vec<BgpRouteChange> {
    let mut changes = Vec::new();

    let old_map: HashMap<&str, &BgpPrefix> = old_prefixes
        .iter()
        .map(|p| (p.prefix.as_str(), p))
        .collect();

    let new_map: HashMap<&str, &BgpPrefix> = new_prefixes
        .iter()
        .map(|p| (p.prefix.as_str(), p))
        .collect();

    for (prefix, new_entry) in &new_map {
        if let Some(old_entry) = old_map.get(prefix) {
            if old_entry.origin_asn != new_entry.origin_asn {
                changes.push(BgpRouteChange {
                    prefix: prefix.to_string(),
                    change_type: RouteChangeType::OriginChange,
                    old_asn: Some(old_entry.origin_asn),
                    new_asn: new_entry.origin_asn,
                    old_path: old_entry.as_path.clone(),
                    new_path: new_entry.as_path.clone(),
                    timestamp: "detected".to_string(),
                    source: new_entry.source,
                });
            } else if old_entry.as_path != new_entry.as_path {
                changes.push(BgpRouteChange {
                    prefix: prefix.to_string(),
                    change_type: RouteChangeType::PathChange,
                    old_asn: Some(old_entry.origin_asn),
                    new_asn: new_entry.origin_asn,
                    old_path: old_entry.as_path.clone(),
                    new_path: new_entry.as_path.clone(),
                    timestamp: "detected".to_string(),
                    source: new_entry.source,
                });
            }
        } else {
            changes.push(BgpRouteChange {
                prefix: prefix.to_string(),
                change_type: RouteChangeType::Announcement,
                old_asn: None,
                new_asn: new_entry.origin_asn,
                old_path: vec![],
                new_path: new_entry.as_path.clone(),
                timestamp: "detected".to_string(),
                source: new_entry.source,
            });
        }
    }

    for prefix in old_map.keys() {
        if !new_map.contains_key(prefix) {
            let old_entry = old_map[prefix];
            changes.push(BgpRouteChange {
                prefix: prefix.to_string(),
                change_type: RouteChangeType::Withdrawal,
                old_asn: Some(old_entry.origin_asn),
                new_asn: 0,
                old_path: old_entry.as_path.clone(),
                new_path: vec![],
                timestamp: "detected".to_string(),
                source: old_entry.source,
            });
        }
    }

    changes
}

/// Builds a full BGP history report.
pub fn build_bgp_report(
    target_prefixes: Vec<String>,
    autonomous_systems: Vec<AutonomousSystem>,
    current_prefixes: Vec<BgpPrefix>,
    route_changes: Vec<BgpRouteChange>,
    ip_reuse: Vec<IpReuseRecord>,
) -> BgpHistoryReport {
    let path_analyses: Vec<AsPathAnalysis> = current_prefixes
        .iter()
        .map(|p| analyze_as_path(&p.prefix, &p.as_path))
        .collect();

    let total_prefixes = current_prefixes.len();
    let total_changes = route_changes.len();

    let mut risk_summary: HashMap<BgpRisk, usize> = HashMap::new();
    for r in &ip_reuse {
        *risk_summary.entry(r.risk).or_insert(0) += 1;
    }
    for a in &path_analyses {
        if !a.anomalies.is_empty() {
            *risk_summary.entry(BgpRisk::Medium).or_insert(0) += 1;
        }
    }
    for c in &route_changes {
        let risk = match c.change_type {
            RouteChangeType::Hijack => BgpRisk::Critical,
            RouteChangeType::OriginChange => BgpRisk::High,
            RouteChangeType::Withdrawal => BgpRisk::Medium,
            _ => BgpRisk::Low,
        };
        *risk_summary.entry(risk).or_insert(0) += 1;
    }

    let overall_risk = risk_summary.keys().max().copied().unwrap_or(BgpRisk::Info);

    BgpHistoryReport {
        target_prefixes,
        autonomous_systems,
        current_prefixes,
        route_changes,
        ip_reuse,
        path_analyses,
        total_prefixes,
        total_changes,
        risk_summary,
        overall_risk,
    }
}
