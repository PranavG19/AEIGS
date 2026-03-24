/// Passive subdomain enumeration from multiple sources.
///
/// Aggregates subdomain discovery without direct DNS queries.
/// Each source has a dedicated parser that extracts subdomains
/// from its specific response format. Results are deduplicated,
/// normalized, and scored by cross-source confirmation count.
use std::collections::{HashMap, HashSet};

use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

/// Which passive source discovered a subdomain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubdomainSource {
    CrtSh,
    SecurityTrails,
    DnsDumpster,
    VirusTotal,
    WaybackMachine,
    DnsZoneTransfer,
    DnsRecordExtraction,
    SearchEngineDork,
    SourceCodeReference,
    FaviconHash,
}

impl std::fmt::Display for SubdomainSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CrtSh => write!(f, "crt.sh"),
            Self::SecurityTrails => write!(f, "SecurityTrails"),
            Self::DnsDumpster => write!(f, "DNSDumpster"),
            Self::VirusTotal => write!(f, "VirusTotal"),
            Self::WaybackMachine => write!(f, "Wayback Machine"),
            Self::DnsZoneTransfer => write!(f, "DNS Zone Transfer"),
            Self::DnsRecordExtraction => write!(f, "DNS Record Extraction"),
            Self::SearchEngineDork => write!(f, "Search Engine Dork"),
            Self::SourceCodeReference => write!(f, "Source Code Reference"),
            Self::FaviconHash => write!(f, "Favicon Hash"),
        }
    }
}

/// A single discovered subdomain with attribution metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredSubdomain {
    pub subdomain: String,
    pub sources: HashSet<SubdomainSource>,
    pub confidence: f64,
    pub first_seen_source: SubdomainSource,
}

impl DiscoveredSubdomain {
    fn new(subdomain: String, source: SubdomainSource) -> Self {
        let mut sources = HashSet::new();
        sources.insert(source.clone());
        Self {
            subdomain,
            confidence: confidence_for_source_count(1),
            first_seen_source: source,
            sources,
        }
    }

    fn add_source(&mut self, source: SubdomainSource) {
        self.sources.insert(source);
        self.confidence = confidence_for_source_count(self.sources.len());
    }
}

/// Confidence score based on how many independent sources confirmed a subdomain.
/// Single source = 0.2, each additional adds diminishing returns up to 1.0.
pub(crate) fn confidence_for_source_count(count: usize) -> f64 {
    match count {
        0 => 0.0,
        1 => 0.2,
        2 => 0.4,
        3 => 0.6,
        4 => 0.75,
        5 => 0.85,
        6 => 0.9,
        7 => 0.93,
        8 => 0.96,
        9 => 0.98,
        _ => 1.0,
    }
}

/// Aggregator that collects subdomains from multiple parsers.
#[derive(Debug)]
pub struct SubdomainEnumerator {
    target_domain: String,
    results: HashMap<String, DiscoveredSubdomain>,
}

impl SubdomainEnumerator {
    pub fn new(target_domain: &str) -> Self {
        let normalized = normalize_domain(target_domain);
        Self {
            target_domain: normalized,
            results: HashMap::new(),
        }
    }

    /// Target domain this enumerator searches for.
    pub fn target_domain(&self) -> &str {
        &self.target_domain
    }

    /// Ingest raw subdomains from a given source.
    pub fn ingest(&mut self, subdomains: &[String], source: SubdomainSource) {
        for raw in subdomains {
            let normalized = normalize_domain(raw);
            if !is_valid_subdomain(&normalized, &self.target_domain) {
                continue;
            }
            match self.results.get_mut(&normalized) {
                Some(existing) => existing.add_source(source.clone()),
                None => {
                    self.results.insert(
                        normalized.clone(),
                        DiscoveredSubdomain::new(normalized, source.clone()),
                    );
                }
            }
        }
    }

    /// Ingest results from crt.sh JSON response.
    pub fn ingest_crtsh(&mut self, json_body: &str) {
        let subs = parse_crtsh_response(json_body, &self.target_domain);
        self.ingest(&subs, SubdomainSource::CrtSh);
    }

    /// Ingest results from SecurityTrails JSON response.
    pub fn ingest_securitytrails(&mut self, json_body: &str) {
        let subs = parse_securitytrails_response(json_body, &self.target_domain);
        self.ingest(&subs, SubdomainSource::SecurityTrails);
    }

    /// Ingest results from DNSDumpster HTML response.
    pub fn ingest_dnsdumpster(&mut self, html_body: &str) {
        let subs = parse_dnsdumpster_response(html_body, &self.target_domain);
        self.ingest(&subs, SubdomainSource::DnsDumpster);
    }

    /// Ingest results from VirusTotal JSON response.
    pub fn ingest_virustotal(&mut self, json_body: &str) {
        let subs = parse_virustotal_response(json_body, &self.target_domain);
        self.ingest(&subs, SubdomainSource::VirusTotal);
    }

    /// Ingest results from Wayback Machine CDX API response.
    pub fn ingest_wayback(&mut self, cdx_body: &str) {
        let subs = parse_wayback_response(cdx_body, &self.target_domain);
        self.ingest(&subs, SubdomainSource::WaybackMachine);
    }

    /// Ingest results from DNS zone transfer (AXFR) output.
    pub fn ingest_zone_transfer(&mut self, axfr_output: &str) {
        let subs = parse_zone_transfer_output(axfr_output, &self.target_domain);
        self.ingest(&subs, SubdomainSource::DnsZoneTransfer);
    }

    /// Ingest results from TXT/MX/NS DNS record data.
    pub fn ingest_dns_records(&mut self, dns_output: &str) {
        let subs = parse_dns_record_output(dns_output, &self.target_domain);
        self.ingest(&subs, SubdomainSource::DnsRecordExtraction);
    }

    /// Ingest results from search engine dork output.
    pub fn ingest_search_dork(&mut self, dork_results: &str) {
        let subs = parse_search_dork_results(dork_results, &self.target_domain);
        self.ingest(&subs, SubdomainSource::SearchEngineDork);
    }

    /// Ingest results from source code (JS/HTML) analysis.
    pub fn ingest_source_code(&mut self, source_code: &str) {
        let subs = parse_source_code_references(source_code, &self.target_domain);
        self.ingest(&subs, SubdomainSource::SourceCodeReference);
    }

    /// Ingest results from favicon hash matching output.
    pub fn ingest_favicon_hashes(&mut self, favicon_output: &str) {
        let subs = parse_favicon_hash_output(favicon_output, &self.target_domain);
        self.ingest(&subs, SubdomainSource::FaviconHash);
    }

    /// All unique discovered subdomains sorted by confidence descending.
    pub fn results(&self) -> Vec<&DiscoveredSubdomain> {
        let mut out: Vec<_> = self.results.values().collect();
        out.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.subdomain.cmp(&b.subdomain))
        });
        out
    }

    /// Total unique subdomains discovered.
    pub fn count(&self) -> usize {
        self.results.len()
    }

    /// Subdomains confirmed by at least `min_sources` independent sources.
    pub fn high_confidence(&self, min_sources: usize) -> Vec<&DiscoveredSubdomain> {
        self.results()
            .into_iter()
            .filter(|s| s.sources.len() >= min_sources)
            .collect()
    }
}

/// Normalize a domain string: lowercase, strip trailing dot, strip leading wildcard.
pub(crate) fn normalize_domain(domain: &str) -> String {
    let mut d = domain.trim().to_lowercase();
    if let Some(stripped) = d.strip_suffix('.') {
        d = stripped.to_string();
    }
    if let Some(stripped) = d.strip_prefix("*.") {
        d = stripped.to_string();
    }
    d
}

/// Check if `candidate` is a valid subdomain of `parent`.
pub(crate) fn is_valid_subdomain(candidate: &str, parent: &str) -> bool {
    if candidate.is_empty() || parent.is_empty() {
        return false;
    }
    if candidate == parent {
        return true;
    }
    candidate.ends_with(&format!(".{parent}"))
}

// ---------------------------------------------------------------------------
// Source parsers
// ---------------------------------------------------------------------------

/// Parse crt.sh JSON response.
/// Format: `[{"name_value": "*.example.com\nexample.com", ...}, ...]`
pub fn parse_crtsh_response(json_body: &str, target: &str) -> Vec<String> {
    let target_norm = normalize_domain(target);
    let entries: Vec<serde_json::Value> = match serde_json::from_str(json_body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut found = HashSet::new();
    for entry in &entries {
        if let Some(name_value) = entry.get("name_value").and_then(|v| v.as_str()) {
            for line in name_value.lines() {
                let normalized = normalize_domain(line);
                if is_valid_subdomain(&normalized, &target_norm) {
                    found.insert(normalized);
                }
            }
        }
        if let Some(common_name) = entry.get("common_name").and_then(|v| v.as_str()) {
            let normalized = normalize_domain(common_name);
            if is_valid_subdomain(&normalized, &target_norm) {
                found.insert(normalized);
            }
        }
    }
    found.into_iter().collect()
}

/// Parse SecurityTrails API response.
/// Format: `{"subdomains": ["www", "api", "mail"], "endpoint": "..."}`
pub fn parse_securitytrails_response(json_body: &str, target: &str) -> Vec<String> {
    let target_norm = normalize_domain(target);
    let parsed: serde_json::Value = match serde_json::from_str(json_body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut found = Vec::new();
    if let Some(subs) = parsed.get("subdomains").and_then(|v| v.as_array()) {
        for sub in subs {
            if let Some(prefix) = sub.as_str() {
                let full = format!("{prefix}.{target_norm}");
                if is_valid_subdomain(&full, &target_norm) {
                    found.push(full);
                }
            }
        }
    }
    found
}

/// Parse DNSDumpster HTML response.
/// Extracts hostnames matching the target from table cells.
pub fn parse_dnsdumpster_response(html_body: &str, target: &str) -> Vec<String> {
    let target_norm = normalize_domain(target);
    let pattern = format!(
        r"([a-zA-Z0-9][-a-zA-Z0-9]*\.)*{}",
        regex::escape(&target_norm)
    );
    let re = Regex::new(&pattern).expect("valid regex for dnsdumpster");

    let mut found = HashSet::new();
    for mat in re.find_iter(html_body) {
        let normalized = normalize_domain(mat.as_str());
        if is_valid_subdomain(&normalized, &target_norm) {
            found.insert(normalized);
        }
    }
    found.into_iter().collect()
}

/// Parse VirusTotal domain report JSON.
/// Format: `{"data": [{"id": "api.example.com", "type": "domain"}, ...]}`
pub fn parse_virustotal_response(json_body: &str, target: &str) -> Vec<String> {
    let target_norm = normalize_domain(target);
    let parsed: serde_json::Value = match serde_json::from_str(json_body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut found = Vec::new();
    if let Some(data) = parsed.get("data").and_then(|v| v.as_array()) {
        for item in data {
            if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                let normalized = normalize_domain(id);
                if is_valid_subdomain(&normalized, &target_norm) {
                    found.push(normalized);
                }
            }
        }
    }
    found
}

/// Parse Wayback Machine CDX API response.
/// Format: newline-separated records, second field is URL.
/// `com,example)/path 20200101120000 https://sub.example.com/page ...`
/// Alternative: just plain URLs one per line.
pub fn parse_wayback_response(cdx_body: &str, target: &str) -> Vec<String> {
    let target_norm = normalize_domain(target);
    let url_re =
        Regex::new(r"https?://([a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9])").expect("valid url regex");

    let mut found = HashSet::new();
    for line in cdx_body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        for cap in url_re.captures_iter(line) {
            if let Some(host_match) = cap.get(1) {
                let normalized = normalize_domain(host_match.as_str());
                if is_valid_subdomain(&normalized, &target_norm) {
                    found.insert(normalized);
                }
            }
        }
    }
    found.into_iter().collect()
}

/// Parse DNS zone transfer (AXFR) output.
/// Format: `subdomain.example.com. 3600 IN A 1.2.3.4`
pub fn parse_zone_transfer_output(axfr_output: &str, target: &str) -> Vec<String> {
    let target_norm = normalize_domain(target);
    let record_re =
        Regex::new(r"^([a-zA-Z0-9][-a-zA-Z0-9.]*)\.\s+\d+\s+IN\s+").expect("valid axfr regex");

    let mut found = HashSet::new();
    for line in axfr_output.lines() {
        let line = line.trim();
        if let Some(caps) = record_re.captures(line)
            && let Some(hostname) = caps.get(1)
        {
            let normalized = normalize_domain(hostname.as_str());
            if is_valid_subdomain(&normalized, &target_norm) {
                found.insert(normalized);
            }
        }
    }
    found.into_iter().collect()
}

/// Parse DNS TXT/MX/NS record output for subdomain references.
/// Scans for hostnames matching target within free-form DNS record text.
pub fn parse_dns_record_output(dns_output: &str, target: &str) -> Vec<String> {
    let target_norm = normalize_domain(target);
    let pattern = format!(
        r"([a-zA-Z0-9][-a-zA-Z0-9]*\.)+{}",
        regex::escape(&target_norm)
    );
    let re = Regex::new(&pattern).expect("valid dns record regex");

    let mut found = HashSet::new();
    for mat in re.find_iter(dns_output) {
        let normalized = normalize_domain(mat.as_str());
        if is_valid_subdomain(&normalized, &target_norm) {
            found.insert(normalized);
        }
    }
    found.into_iter().collect()
}

/// Parse search engine dork results (URLs).
/// Expects newline-separated URLs from `site:target -www` queries.
pub fn parse_search_dork_results(dork_results: &str, target: &str) -> Vec<String> {
    let target_norm = normalize_domain(target);

    let mut found = HashSet::new();
    for line in dork_results.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(parsed_url) = Url::parse(line)
            && let Some(host) = parsed_url.host_str()
        {
            let normalized = normalize_domain(host);
            if is_valid_subdomain(&normalized, &target_norm) {
                found.insert(normalized);
            }
        }
    }
    found.into_iter().collect()
}

/// Extract subdomain references from JavaScript bundles and HTML source.
/// Looks for quoted strings and attribute values containing target subdomains.
pub fn parse_source_code_references(source_code: &str, target: &str) -> Vec<String> {
    let target_norm = normalize_domain(target);
    let pattern = format!(
        r"([a-zA-Z0-9][-a-zA-Z0-9]*\.)*{}",
        regex::escape(&target_norm)
    );
    let re = Regex::new(&pattern).expect("valid source code regex");

    let mut found = HashSet::new();
    for mat in re.find_iter(source_code) {
        let candidate = normalize_domain(mat.as_str());
        if is_valid_subdomain(&candidate, &target_norm) && candidate != target_norm {
            found.insert(candidate);
        }
    }
    found.into_iter().collect()
}

/// Parse favicon hash matching output.
/// Format: newline-separated `hash:hostname` or just hostnames.
pub fn parse_favicon_hash_output(favicon_output: &str, target: &str) -> Vec<String> {
    let target_norm = normalize_domain(target);

    let mut found = HashSet::new();
    for line in favicon_output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let hostname = if let Some((_hash, host)) = line.split_once(':') {
            host.trim()
        } else {
            line
        };
        let normalized = normalize_domain(hostname);
        if is_valid_subdomain(&normalized, &target_norm) {
            found.insert(normalized);
        }
    }
    found.into_iter().collect()
}

/// Generate search engine dork queries for a target domain.
pub fn generate_dork_queries(target: &str) -> Vec<String> {
    let t = normalize_domain(target);
    vec![
        format!("site:{t} -www"),
        format!("site:{t} -www -mail"),
        format!("site:*.{t}"),
        format!("intitle:\"index of\" site:{t}"),
        format!("inurl:{t} -www"),
    ]
}
