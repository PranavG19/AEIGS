use std::collections::{HashMap, HashSet};

/// Threat severity level for an actor or campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatLevel {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Classification of anomalous behavior that may indicate a zero-day.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ZeroDayType {
    AnomalousBehavior,
    UnknownCrash,
    MemoryCorruption,
    UnexpectedOutput,
    TimingAnomaly,
    ResourceExhaustion,
}

impl ZeroDayType {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "anomalous_behavior" | "anomalousbehavior" => Self::AnomalousBehavior,
            "unknown_crash" | "unknowncrash" => Self::UnknownCrash,
            "memory_corruption" | "memorycorruption" => Self::MemoryCorruption,
            "unexpected_output" | "unexpectedoutput" => Self::UnexpectedOutput,
            "timing_anomaly" | "timinganomaly" => Self::TimingAnomaly,
            "resource_exhaustion" | "resourceexhaustion" => Self::ResourceExhaustion,
            _ => Self::AnomalousBehavior,
        }
    }
}

impl std::fmt::Display for ZeroDayType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AnomalousBehavior => write!(f, "Anomalous Behavior"),
            Self::UnknownCrash => write!(f, "Unknown Crash"),
            Self::MemoryCorruption => write!(f, "Memory Corruption"),
            Self::UnexpectedOutput => write!(f, "Unexpected Output"),
            Self::TimingAnomaly => write!(f, "Timing Anomaly"),
            Self::ResourceExhaustion => write!(f, "Resource Exhaustion"),
        }
    }
}

/// Where a public exploit was sourced from.
#[derive(Debug, Clone, PartialEq)]
pub enum ExploitSourceType {
    ExploitDb,
    GitHub,
    Metasploit,
    NucleiTemplate,
    PacketStorm,
    Custom(String),
}

impl std::fmt::Display for ExploitSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExploitDb => write!(f, "Exploit-DB"),
            Self::GitHub => write!(f, "GitHub"),
            Self::Metasploit => write!(f, "Metasploit"),
            Self::NucleiTemplate => write!(f, "Nuclei Template"),
            Self::PacketStorm => write!(f, "Packet Storm"),
            Self::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

/// Maturity level of a known exploit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExploitMaturity {
    Unproven,
    ProofOfConcept,
    FunctionalExploit,
    Weaponized,
}

impl std::fmt::Display for ExploitMaturity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unproven => write!(f, "Unproven"),
            Self::ProofOfConcept => write!(f, "Proof of Concept"),
            Self::FunctionalExploit => write!(f, "Functional Exploit"),
            Self::Weaponized => write!(f, "Weaponized"),
        }
    }
}

/// A CVE entry from a vulnerability database.
#[derive(Debug, Clone, PartialEq)]
pub struct CveEntry {
    pub cve_id: String,
    pub description: String,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub published_date: Option<String>,
    pub affected_product: String,
    pub affected_versions: Vec<String>,
    pub cwe_ids: Vec<String>,
}

/// EPSS (Exploit Prediction Scoring System) probability for a CVE.
#[derive(Debug, Clone, PartialEq)]
pub struct EpssScore {
    pub cve_id: String,
    pub probability: f64,
    pub percentile: f64,
    pub last_updated: Option<String>,
}

/// A threat actor or campaign known to target specific technologies.
#[derive(Debug, Clone, PartialEq)]
pub struct ThreatActor {
    pub name: String,
    pub aliases: Vec<String>,
    pub targeted_sectors: Vec<String>,
    pub targeted_technologies: Vec<String>,
    pub ttps: Vec<String>,
    pub risk_level: ThreatLevel,
    pub description: String,
}

/// An indicator suggesting possible zero-day exploitation.
#[derive(Debug, Clone, PartialEq)]
pub struct ZeroDayIndicator {
    pub indicator_type: ZeroDayType,
    pub description: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub affected_component: String,
}

/// Information about exploit availability for a CVE.
#[derive(Debug, Clone, PartialEq)]
pub struct ExploitAvailability {
    pub cve_id: String,
    pub public_exploit: bool,
    pub exploit_sources: Vec<ExploitSource>,
    pub exploit_maturity: ExploitMaturity,
    pub weaponized: bool,
}

/// A single source where an exploit was found.
#[derive(Debug, Clone, PartialEq)]
pub struct ExploitSource {
    pub name: String,
    pub url: Option<String>,
    pub source_type: ExploitSourceType,
    pub reliability: f64,
}

/// A matched vulnerability with enrichment data attached.
#[derive(Debug, Clone, PartialEq)]
pub struct VulnMatch {
    pub asset_identifier: String,
    pub asset_version: Option<String>,
    pub cve: CveEntry,
    pub epss: Option<EpssScore>,
    pub exploits: Vec<ExploitAvailability>,
    pub threat_actors: Vec<String>,
    pub priority_score: f64,
}

/// Complete vulnerability intelligence report for a target.
#[derive(Debug, Clone, PartialEq)]
pub struct VulnIntelReport {
    pub target: String,
    pub matches: Vec<VulnMatch>,
    pub zero_day_indicators: Vec<ZeroDayIndicator>,
    pub threat_actors: Vec<ThreatActor>,
    pub total_cves: usize,
    pub critical_count: usize,
    pub exploitable_count: usize,
    pub risk_score: f64,
}

const WEIGHT_CVSS: f64 = 0.30;
const WEIGHT_EPSS: f64 = 0.30;
const WEIGHT_EXPLOIT: f64 = 0.25;
const WEIGHT_WEAPONIZED: f64 = 0.15;

/// Match discovered software against a CVE database using product name
/// substring matching and basic version containment checks.
pub fn match_cves(
    discovered_software: &[(&str, Option<&str>)],
    cve_database: &[CveEntry],
) -> Vec<VulnMatch> {
    let mut matches = Vec::new();
    for &(product, version) in discovered_software {
        let product_lower = product.to_lowercase();
        for cve in cve_database {
            if !product_matches(&product_lower, &cve.affected_product) {
                continue;
            }
            if !version_matches(version, &cve.affected_versions) {
                continue;
            }
            let priority = calculate_priority_score(cve, None, false, false);
            matches.push(VulnMatch {
                asset_identifier: product.to_string(),
                asset_version: version.map(String::from),
                cve: cve.clone(),
                epss: None,
                exploits: Vec::new(),
                threat_actors: Vec::new(),
                priority_score: priority,
            });
        }
    }
    matches
}

/// Enrich existing CVE matches with EPSS probability scores and recalculate
/// priority using the new data.
pub fn enrich_with_epss(matches: &mut [VulnMatch], epss_data: &[EpssScore]) {
    let epss_map: HashMap<&str, &EpssScore> =
        epss_data.iter().map(|e| (e.cve_id.as_str(), e)).collect();

    for vuln_match in matches.iter_mut() {
        if let Some(epss) = epss_map.get(vuln_match.cve.cve_id.as_str()) {
            vuln_match.epss = Some((*epss).clone());
            let has_exploit = !vuln_match.exploits.is_empty();
            let weaponized = vuln_match.exploits.iter().any(|e| e.weaponized);
            vuln_match.priority_score =
                calculate_priority_score(&vuln_match.cve, Some(epss), has_exploit, weaponized);
        }
    }
}

/// Enrich existing CVE matches with exploit availability data and recalculate
/// priority scores.
pub fn enrich_with_exploits(matches: &mut [VulnMatch], exploit_data: &[ExploitAvailability]) {
    let exploit_map: HashMap<&str, Vec<&ExploitAvailability>> = {
        let mut map: HashMap<&str, Vec<&ExploitAvailability>> = HashMap::new();
        for exploit in exploit_data {
            map.entry(exploit.cve_id.as_str())
                .or_default()
                .push(exploit);
        }
        map
    };

    for vuln_match in matches.iter_mut() {
        if let Some(exploits) = exploit_map.get(vuln_match.cve.cve_id.as_str()) {
            vuln_match.exploits = exploits.iter().map(|e| (*e).clone()).collect();
            let has_exploit = true;
            let weaponized = exploits.iter().any(|e| e.weaponized);
            vuln_match.priority_score = calculate_priority_score(
                &vuln_match.cve,
                vuln_match.epss.as_ref(),
                has_exploit,
                weaponized,
            );
        }
    }
}

/// Find threat actors known to target the given technology stack by matching
/// against each actor's targeted_technologies list.
pub fn correlate_threat_actors(
    tech_stack: &[&str],
    threat_actors: &[ThreatActor],
) -> Vec<ThreatActor> {
    let stack_lower: HashSet<String> = tech_stack.iter().map(|t| t.to_lowercase()).collect();

    threat_actors
        .iter()
        .filter(|actor| {
            actor
                .targeted_technologies
                .iter()
                .any(|tech| stack_lower.contains(&tech.to_lowercase()))
        })
        .cloned()
        .collect()
}

/// Process raw anomaly observations into structured zero-day indicators.
/// Each tuple contains (indicator_type_str, description, confidence, evidence_items).
pub fn detect_zero_day_indicators(
    anomalies: &[(&str, &str, f64, &[&str])],
) -> Vec<ZeroDayIndicator> {
    anomalies
        .iter()
        .filter(|(_, _, confidence, _)| *confidence > 0.0)
        .map(|(type_str, desc, confidence, evidence)| {
            let clamped_confidence = confidence.clamp(0.0, 1.0);
            let affected = extract_affected_component(desc);
            ZeroDayIndicator {
                indicator_type: ZeroDayType::from_str(type_str),
                description: desc.to_string(),
                confidence: clamped_confidence,
                evidence: evidence.iter().map(|e| e.to_string()).collect(),
                affected_component: affected,
            }
        })
        .collect()
}

/// Calculate a 0.0–10.0 priority score for a single CVE using weighted factors:
/// CVSS (0.30), EPSS (0.30), exploit availability (0.25), weaponization (0.15).
pub fn calculate_priority_score(
    cve: &CveEntry,
    epss: Option<&EpssScore>,
    has_exploit: bool,
    weaponized: bool,
) -> f64 {
    let cvss_component = cve.cvss_score.unwrap_or(0.0).clamp(0.0, 10.0);
    let epss_component = epss
        .map(|e| e.probability.clamp(0.0, 1.0) * 10.0)
        .unwrap_or(0.0);
    let exploit_component = if has_exploit { 10.0 } else { 0.0 };
    let weaponized_component = if weaponized { 10.0 } else { 0.0 };

    let raw = (WEIGHT_CVSS * cvss_component)
        + (WEIGHT_EPSS * epss_component)
        + (WEIGHT_EXPLOIT * exploit_component)
        + (WEIGHT_WEAPONIZED * weaponized_component);

    raw.clamp(0.0, 10.0)
}

/// Calculate an overall 0.0–1.0 risk score for a complete vulnerability
/// intelligence report factoring in critical CVEs, exploitability, threat
/// actor presence, and zero-day indicators.
pub fn calculate_risk_score(report: &VulnIntelReport) -> f64 {
    if report.total_cves == 0
        && report.zero_day_indicators.is_empty()
        && report.threat_actors.is_empty()
    {
        return 0.0;
    }

    let critical_ratio = if report.total_cves > 0 {
        (report.critical_count as f64 / report.total_cves as f64).min(1.0)
    } else {
        0.0
    };

    let exploit_ratio = if report.total_cves > 0 {
        (report.exploitable_count as f64 / report.total_cves as f64).min(1.0)
    } else {
        0.0
    };

    let actor_signal = if report.threat_actors.is_empty() {
        0.0
    } else {
        (report.threat_actors.len() as f64 * 0.2).min(1.0)
    };

    let zero_day_signal = if report.zero_day_indicators.is_empty() {
        0.0
    } else {
        let avg_confidence: f64 = report
            .zero_day_indicators
            .iter()
            .map(|z| z.confidence)
            .sum::<f64>()
            / report.zero_day_indicators.len() as f64;
        avg_confidence.min(1.0)
    };

    let raw = (critical_ratio * 0.35)
        + (exploit_ratio * 0.30)
        + (actor_signal * 0.15)
        + (zero_day_signal * 0.20);

    raw.clamp(0.0, 1.0)
}

/// Main entry point: correlate all vulnerability intelligence sources into a
/// unified report for the given target.
#[allow(clippy::too_many_arguments)]
pub fn correlate_vulnerabilities(
    target: &str,
    software: &[(&str, Option<&str>)],
    cve_db: &[CveEntry],
    epss_data: &[EpssScore],
    exploit_data: &[ExploitAvailability],
    threat_actors: &[ThreatActor],
    anomalies: &[(&str, &str, f64, &[&str])],
    tech_stack: &[&str],
) -> VulnIntelReport {
    let mut matches = match_cves(software, cve_db);
    enrich_with_epss(&mut matches, epss_data);
    enrich_with_exploits(&mut matches, exploit_data);

    let correlated_actors = correlate_threat_actors(tech_stack, threat_actors);
    let actor_names: HashSet<String> = correlated_actors.iter().map(|a| a.name.clone()).collect();

    for vuln_match in &mut matches {
        vuln_match.threat_actors = actor_names.iter().cloned().collect();
    }

    let zero_day_indicators = detect_zero_day_indicators(anomalies);

    let total_cves = matches.len();
    let critical_count = matches
        .iter()
        .filter(|m| m.cve.cvss_score.unwrap_or(0.0) >= 9.0)
        .count();
    let exploitable_count = matches.iter().filter(|m| !m.exploits.is_empty()).count();

    let mut report = VulnIntelReport {
        target: target.to_string(),
        matches,
        zero_day_indicators,
        threat_actors: correlated_actors,
        total_cves,
        critical_count,
        exploitable_count,
        risk_score: 0.0,
    };

    report.risk_score = calculate_risk_score(&report);
    report
}

fn product_matches(discovered: &str, cve_product: &str) -> bool {
    let cve_lower = cve_product.to_lowercase();
    discovered.contains(&cve_lower) || cve_lower.contains(discovered)
}

fn version_matches(discovered_version: Option<&str>, affected_versions: &[String]) -> bool {
    if affected_versions.is_empty() {
        return true;
    }
    let version = match discovered_version {
        Some(v) => v,
        None => return true,
    };
    for affected in affected_versions {
        if affected == "*" || affected == "all" {
            return true;
        }
        if version_in_range(version, affected) {
            return true;
        }
    }
    false
}

fn version_in_range(version: &str, range_spec: &str) -> bool {
    if version == range_spec {
        return true;
    }
    if let Some(prefix) = range_spec.strip_suffix(".*") {
        return version.starts_with(prefix);
    }
    if let Some(bound) = range_spec.strip_prefix("<=") {
        return compare_version_strings(version, bound) != std::cmp::Ordering::Greater;
    }
    if let Some(bound) = range_spec.strip_prefix(">=") {
        return compare_version_strings(version, bound) != std::cmp::Ordering::Less;
    }
    if let Some(bound) = range_spec.strip_prefix('<') {
        return compare_version_strings(version, bound) == std::cmp::Ordering::Less;
    }
    if let Some(bound) = range_spec.strip_prefix('>') {
        return compare_version_strings(version, bound) == std::cmp::Ordering::Greater;
    }
    false
}

fn compare_version_strings(a: &str, b: &str) -> std::cmp::Ordering {
    let parse_parts = |s: &str| -> Vec<u64> {
        s.split('.')
            .map(|p| {
                p.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse::<u64>()
                    .unwrap_or(0)
            })
            .collect()
    };
    let a_parts = parse_parts(a);
    let b_parts = parse_parts(b);
    let max_len = a_parts.len().max(b_parts.len());
    for i in 0..max_len {
        let av = a_parts.get(i).copied().unwrap_or(0);
        let bv = b_parts.get(i).copied().unwrap_or(0);
        match av.cmp(&bv) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

fn extract_affected_component(description: &str) -> String {
    let lower = description.to_lowercase();
    let keywords = [
        "in ",
        "affects ",
        "component ",
        "module ",
        "service ",
        "endpoint ",
    ];
    for keyword in &keywords {
        if let Some(pos) = lower.find(keyword) {
            let start = pos + keyword.len();
            let component: String = description[start..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '/')
                .collect();
            if component.len() >= 2 {
                return component;
            }
        }
    }
    "unknown".to_string()
}
