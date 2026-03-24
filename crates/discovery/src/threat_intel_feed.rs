use std::collections::HashMap;

use serde::Deserialize;

/// Severity rating for a CVE entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CveSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for CveSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A parsed CVE record from NVD JSON format.
#[derive(Debug, Clone, PartialEq)]
pub struct CveRecord {
    pub cve_id: String,
    pub description: String,
    pub severity: CveSeverity,
    pub cvss_score: f64,
    pub affected_product: String,
    pub affected_vendor: String,
    pub version_start: Option<SemVer>,
    pub version_end_excluding: Option<SemVer>,
    pub version_end_including: Option<SemVer>,
}

/// A parsed Exploit-DB entry from CSV format.
#[derive(Debug, Clone, PartialEq)]
pub struct ExploitDbEntry {
    pub edb_id: String,
    pub description: String,
    pub platform: String,
    pub exploit_type: String,
    pub associated_cves: Vec<String>,
    pub verified: bool,
}

/// A CISA Known Exploited Vulnerability entry.
#[derive(Debug, Clone, PartialEq)]
pub struct CisaKevEntry {
    pub cve_id: String,
    pub vendor: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub due_date: String,
    pub required_action: String,
}

/// Result of correlating threat intel against a discovered tech stack.
#[derive(Debug, Clone, PartialEq)]
pub struct ThreatIntelMatch {
    pub source: ThreatIntelSource,
    pub matched_product: String,
    pub matched_version: String,
    pub reference_id: String,
    pub severity: CveSeverity,
    pub description: String,
}

/// Where the threat intel came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatIntelSource {
    Nvd,
    ExploitDb,
    CisaKev,
    NucleiTemplate,
    AbuseIpDb,
    MalwareC2,
    EmergingThreat,
}

impl std::fmt::Display for ThreatIntelSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nvd => write!(f, "NVD"),
            Self::ExploitDb => write!(f, "Exploit-DB"),
            Self::CisaKev => write!(f, "CISA KEV"),
            Self::NucleiTemplate => write!(f, "Nuclei"),
            Self::AbuseIpDb => write!(f, "AbuseIPDB"),
            Self::MalwareC2 => write!(f, "Malware C2"),
            Self::EmergingThreat => write!(f, "Emerging Threat"),
        }
    }
}

/// A nuclei template stub matched against a tech stack.
#[derive(Debug, Clone, PartialEq)]
pub struct NucleiTemplateMatch {
    pub template_id: String,
    pub template_name: String,
    pub severity: CveSeverity,
    pub matched_product: String,
}

/// Known malware C2 indicator.
#[derive(Debug, Clone, PartialEq)]
pub struct MalwareC2Indicator {
    pub indicator: String,
    pub indicator_type: IndicatorType,
    pub malware_family: String,
    pub confidence: f64,
    pub last_seen: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndicatorType {
    IpAddress,
    Domain,
    Url,
}

/// Abuse IP database entry.
#[derive(Debug, Clone, PartialEq)]
pub struct AbuseIpEntry {
    pub ip_address: String,
    pub abuse_confidence_score: u8,
    pub country_code: String,
    pub total_reports: u32,
    pub last_reported: String,
}

/// An emerging threat — recently published CVE with high EPSS score.
#[derive(Debug, Clone, PartialEq)]
pub struct EmergingThreat {
    pub cve_id: String,
    pub epss_score: f64,
    pub published_date: String,
    pub affected_product: String,
    pub severity: CveSeverity,
}

/// Semver representation for version comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemVer {
    /// Parse a version string like "1.2.3", "1.2", or "1".
    pub fn parse(s: &str) -> Option<SemVer> {
        let s = s.trim().trim_start_matches('v');
        let parts: Vec<&str> = s.split('.').collect();
        if parts.is_empty() || parts.len() > 3 {
            return None;
        }
        let major = parts[0].parse::<u32>().ok()?;
        let minor = if parts.len() > 1 {
            parts[1].parse::<u32>().ok()?
        } else {
            0
        };
        let patch = if parts.len() > 2 {
            // Handle pre-release suffixes like "1.2.3-rc1"
            let patch_str = parts[2].split('-').next().unwrap_or("0");
            patch_str.parse::<u32>().ok()?
        } else {
            0
        };
        Some(SemVer {
            major,
            minor,
            patch,
        })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
    }
}

/// NVD JSON deserialization structures (simplified NVD 2.0 schema).
#[derive(Deserialize)]
pub struct NvdFeed {
    pub vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Deserialize)]
pub struct NvdVulnerability {
    pub cve: NvdCve,
}

#[derive(Deserialize)]
pub struct NvdCve {
    pub id: String,
    #[serde(default)]
    pub descriptions: Vec<NvdDescription>,
    #[serde(default)]
    pub metrics: NvdMetrics,
    #[serde(default)]
    pub configurations: Vec<NvdConfiguration>,
}

#[derive(Deserialize, Default)]
pub struct NvdMetrics {
    #[serde(default, rename = "cvssMetricV31")]
    pub cvss_v31: Vec<NvdCvssV31>,
}

#[derive(Deserialize)]
pub struct NvdCvssV31 {
    #[serde(rename = "cvssData")]
    pub cvss_data: NvdCvssData,
}

#[derive(Deserialize)]
pub struct NvdCvssData {
    #[serde(rename = "baseScore")]
    pub base_score: f64,
    #[serde(rename = "baseSeverity")]
    pub base_severity: String,
}

#[derive(Deserialize)]
pub struct NvdDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Deserialize)]
pub struct NvdConfiguration {
    pub nodes: Vec<NvdNode>,
}

#[derive(Deserialize)]
pub struct NvdNode {
    #[serde(default, rename = "cpeMatch")]
    pub cpe_match: Vec<NvdCpeMatch>,
}

#[derive(Deserialize)]
pub struct NvdCpeMatch {
    pub vulnerable: bool,
    pub criteria: String,
    #[serde(default, rename = "versionStartIncluding")]
    pub version_start_including: Option<String>,
    #[serde(default, rename = "versionEndExcluding")]
    pub version_end_excluding: Option<String>,
    #[serde(default, rename = "versionEndIncluding")]
    pub version_end_including: Option<String>,
}

/// CISA KEV JSON deserialization structures.
#[derive(Deserialize)]
pub struct CisaKevFeed {
    pub vulnerabilities: Vec<CisaKevRaw>,
}

#[derive(Deserialize)]
pub struct CisaKevRaw {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    #[serde(rename = "vendorProject")]
    pub vendor_project: String,
    pub product: String,
    #[serde(rename = "vulnerabilityName")]
    pub vulnerability_name: String,
    #[serde(rename = "dateAdded")]
    pub date_added: String,
    #[serde(rename = "dueDate")]
    pub due_date: String,
    #[serde(rename = "requiredAction")]
    pub required_action: String,
}

/// Main aggregator for threat intelligence feeds.
#[derive(Debug)]
pub struct ThreatIntelFeed {
    cves: Vec<CveRecord>,
    exploits: Vec<ExploitDbEntry>,
    kev_entries: Vec<CisaKevEntry>,
    nuclei_templates: Vec<NucleiTemplateMatch>,
    c2_indicators: Vec<MalwareC2Indicator>,
    abuse_ips: Vec<AbuseIpEntry>,
    emerging_threats: Vec<EmergingThreat>,
}

impl ThreatIntelFeed {
    pub fn new() -> Self {
        Self {
            cves: Vec::new(),
            exploits: Vec::new(),
            kev_entries: Vec::new(),
            nuclei_templates: Vec::new(),
            c2_indicators: Vec::new(),
            abuse_ips: Vec::new(),
            emerging_threats: Vec::new(),
        }
    }

    /// Parse NVD JSON feed into CVE records.
    pub fn ingest_nvd_json(&mut self, json_data: &str) -> Result<usize, ThreatIntelError> {
        let feed: NvdFeed =
            serde_json::from_str(json_data).map_err(|e| ThreatIntelError::ParseError {
                source: "NVD".to_string(),
                detail: e.to_string(),
            })?;

        let mut count = 0;
        for vuln in &feed.vulnerabilities {
            let cve = &vuln.cve;
            let description = cve
                .descriptions
                .iter()
                .find(|d| d.lang == "en")
                .map(|d| d.value.clone())
                .unwrap_or_default();

            let (cvss_score, severity) = cve
                .metrics
                .cvss_v31
                .first()
                .map(|m| {
                    let score = m.cvss_data.base_score;
                    let sev = parse_severity(&m.cvss_data.base_severity);
                    (score, sev)
                })
                .unwrap_or((0.0, CveSeverity::Low));

            for config in &cve.configurations {
                for node in &config.nodes {
                    for cpe in &node.cpe_match {
                        if !cpe.vulnerable {
                            continue;
                        }
                        let (vendor, product) = parse_cpe_vendor_product(&cpe.criteria);
                        let record = CveRecord {
                            cve_id: cve.id.clone(),
                            description: description.clone(),
                            severity,
                            cvss_score,
                            affected_product: product,
                            affected_vendor: vendor,
                            version_start: cpe
                                .version_start_including
                                .as_deref()
                                .and_then(SemVer::parse),
                            version_end_excluding: cpe
                                .version_end_excluding
                                .as_deref()
                                .and_then(SemVer::parse),
                            version_end_including: cpe
                                .version_end_including
                                .as_deref()
                                .and_then(SemVer::parse),
                        };
                        self.cves.push(record);
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }

    /// Parse Exploit-DB CSV format.
    /// Expected columns: id,description,platform,type,cve_list,verified
    pub fn ingest_exploitdb_csv(&mut self, csv_data: &str) -> Result<usize, ThreatIntelError> {
        let mut count = 0;
        for (line_no, line) in csv_data.lines().enumerate() {
            if line_no == 0 || line.trim().is_empty() {
                continue; // skip header
            }
            let fields = parse_csv_line(line);
            if fields.len() < 6 {
                return Err(ThreatIntelError::ParseError {
                    source: "Exploit-DB".to_string(),
                    detail: format!(
                        "line {}: expected 6 fields, got {}",
                        line_no + 1,
                        fields.len()
                    ),
                });
            }
            let cve_list: Vec<String> = fields[4]
                .split(';')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let verified = fields[5].trim().eq_ignore_ascii_case("true") || fields[5].trim() == "1";

            let entry = ExploitDbEntry {
                edb_id: fields[0].trim().to_string(),
                description: fields[1].trim().to_string(),
                platform: fields[2].trim().to_string(),
                exploit_type: fields[3].trim().to_string(),
                associated_cves: cve_list,
                verified,
            };
            self.exploits.push(entry);
            count += 1;
        }
        Ok(count)
    }

    /// Parse CISA KEV JSON feed.
    pub fn ingest_cisa_kev_json(&mut self, json_data: &str) -> Result<usize, ThreatIntelError> {
        let feed: CisaKevFeed =
            serde_json::from_str(json_data).map_err(|e| ThreatIntelError::ParseError {
                source: "CISA KEV".to_string(),
                detail: e.to_string(),
            })?;

        let count = feed.vulnerabilities.len();
        for raw in feed.vulnerabilities {
            let entry = CisaKevEntry {
                cve_id: raw.cve_id,
                vendor: raw.vendor_project,
                product: raw.product,
                vulnerability_name: raw.vulnerability_name,
                date_added: raw.date_added,
                due_date: raw.due_date,
                required_action: raw.required_action,
            };
            self.kev_entries.push(entry);
        }
        Ok(count)
    }

    /// Filter CISA KEV entries added after a given date (YYYY-MM-DD format).
    pub fn kev_entries_after(&self, after_date: &str) -> Vec<&CisaKevEntry> {
        self.kev_entries
            .iter()
            .filter(|e| e.date_added.as_str() >= after_date)
            .collect()
    }

    /// Add nuclei template matches directly.
    pub fn add_nuclei_templates(&mut self, templates: Vec<NucleiTemplateMatch>) {
        self.nuclei_templates.extend(templates);
    }

    /// Add malware C2 indicators directly.
    pub fn add_c2_indicators(&mut self, indicators: Vec<MalwareC2Indicator>) {
        self.c2_indicators.extend(indicators);
    }

    /// Add abuse IP entries directly.
    pub fn add_abuse_ips(&mut self, entries: Vec<AbuseIpEntry>) {
        self.abuse_ips.extend(entries);
    }

    /// Add emerging threats directly.
    pub fn add_emerging_threats(&mut self, threats: Vec<EmergingThreat>) {
        self.emerging_threats.extend(threats);
    }

    /// Correlate all ingested feeds against a discovered tech stack.
    /// `tech_stack` maps product names (lowercase) to version strings.
    pub fn correlate(&self, tech_stack: &HashMap<String, String>) -> Vec<ThreatIntelMatch> {
        let mut matches = Vec::new();

        // CVE matching
        for cve in &self.cves {
            let product_key = cve.affected_product.to_lowercase();
            if let Some(version_str) = tech_stack.get(&product_key)
                && let Some(version) = SemVer::parse(version_str)
                && is_version_affected(&version, cve)
            {
                matches.push(ThreatIntelMatch {
                    source: ThreatIntelSource::Nvd,
                    matched_product: product_key.clone(),
                    matched_version: version_str.clone(),
                    reference_id: cve.cve_id.clone(),
                    severity: cve.severity,
                    description: cve.description.clone(),
                });
            }
        }

        // Exploit-DB cross-reference with matched CVEs
        let matched_cve_ids: Vec<String> = matches
            .iter()
            .filter(|m| m.source == ThreatIntelSource::Nvd)
            .map(|m| m.reference_id.clone())
            .collect();

        for exploit in &self.exploits {
            for cve_id in &exploit.associated_cves {
                if matched_cve_ids.contains(cve_id) {
                    let severity = if exploit.verified {
                        CveSeverity::High
                    } else {
                        CveSeverity::Medium
                    };
                    matches.push(ThreatIntelMatch {
                        source: ThreatIntelSource::ExploitDb,
                        matched_product: cve_id.clone(),
                        matched_version: String::new(),
                        reference_id: exploit.edb_id.clone(),
                        severity,
                        description: exploit.description.clone(),
                    });
                }
            }
        }

        // CISA KEV cross-reference
        for kev in &self.kev_entries {
            let product_key = kev.product.to_lowercase();
            if tech_stack.contains_key(&product_key) {
                matches.push(ThreatIntelMatch {
                    source: ThreatIntelSource::CisaKev,
                    matched_product: product_key,
                    matched_version: String::new(),
                    reference_id: kev.cve_id.clone(),
                    severity: CveSeverity::Critical,
                    description: kev.vulnerability_name.clone(),
                });
            }
        }

        // Nuclei template matching
        for tmpl in &self.nuclei_templates {
            let product_key = tmpl.matched_product.to_lowercase();
            if tech_stack.contains_key(&product_key) {
                matches.push(ThreatIntelMatch {
                    source: ThreatIntelSource::NucleiTemplate,
                    matched_product: product_key,
                    matched_version: String::new(),
                    reference_id: tmpl.template_id.clone(),
                    severity: tmpl.severity,
                    description: tmpl.template_name.clone(),
                });
            }
        }

        // Emerging threats
        for threat in &self.emerging_threats {
            let product_key = threat.affected_product.to_lowercase();
            if tech_stack.contains_key(&product_key) {
                matches.push(ThreatIntelMatch {
                    source: ThreatIntelSource::EmergingThreat,
                    matched_product: product_key,
                    matched_version: String::new(),
                    reference_id: threat.cve_id.clone(),
                    severity: threat.severity,
                    description: format!("EPSS score {:.4} — {}", threat.epss_score, threat.cve_id),
                });
            }
        }

        matches
    }

    /// Check if any discovered IPs or domains match C2 indicators.
    pub fn check_c2_indicators(&self, targets: &[&str]) -> Vec<&MalwareC2Indicator> {
        self.c2_indicators
            .iter()
            .filter(|ind| targets.contains(&ind.indicator.as_str()))
            .collect()
    }

    /// Check if any discovered IPs match abuse IP database entries.
    pub fn check_abuse_ips(&self, ips: &[&str]) -> Vec<&AbuseIpEntry> {
        self.abuse_ips
            .iter()
            .filter(|entry| ips.contains(&entry.ip_address.as_str()))
            .collect()
    }

    /// Get all ingested CVE records.
    pub fn cve_records(&self) -> &[CveRecord] {
        &self.cves
    }

    /// Get all ingested exploit records.
    pub fn exploit_records(&self) -> &[ExploitDbEntry] {
        &self.exploits
    }

    /// Get all KEV entries.
    pub fn kev_entries(&self) -> &[CisaKevEntry] {
        &self.kev_entries
    }

    /// Total number of ingested indicators across all feeds.
    pub fn total_indicators(&self) -> usize {
        self.cves.len()
            + self.exploits.len()
            + self.kev_entries.len()
            + self.nuclei_templates.len()
            + self.c2_indicators.len()
            + self.abuse_ips.len()
            + self.emerging_threats.len()
    }
}

impl Default for ThreatIntelFeed {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors from threat intel feed parsing.
#[derive(Debug)]
pub enum ThreatIntelError {
    ParseError { source: String, detail: String },
}

impl std::fmt::Display for ThreatIntelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError { source, detail } => {
                write!(f, "threat intel parse error from {source}: {detail}")
            }
        }
    }
}

impl std::error::Error for ThreatIntelError {}

/// Check if a given version falls within the affected range of a CVE record.
fn is_version_affected(version: &SemVer, cve: &CveRecord) -> bool {
    // If both start and end are None, we consider only exact product match (no version filter).
    if cve.version_start.is_none()
        && cve.version_end_excluding.is_none()
        && cve.version_end_including.is_none()
    {
        return true;
    }

    // Check lower bound: version >= version_start (if present).
    if let Some(start) = &cve.version_start
        && version < start
    {
        return false;
    }

    // Check upper bound: version < version_end_excluding OR version <= version_end_including.
    if let Some(end_excl) = &cve.version_end_excluding
        && version >= end_excl
    {
        return false;
    }
    if let Some(end_incl) = &cve.version_end_including
        && version > end_incl
    {
        return false;
    }

    true
}

/// Parse severity string from NVD into our enum.
fn parse_severity(s: &str) -> CveSeverity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => CveSeverity::Critical,
        "HIGH" => CveSeverity::High,
        "MEDIUM" => CveSeverity::Medium,
        _ => CveSeverity::Low,
    }
}

/// Extract vendor and product from a CPE 2.3 URI string.
/// Format: cpe:2.3:a:vendor:product:version:...
fn parse_cpe_vendor_product(cpe: &str) -> (String, String) {
    let parts: Vec<&str> = cpe.split(':').collect();
    if parts.len() >= 5 {
        (parts[3].to_string(), parts[4].to_string())
    } else {
        (String::new(), String::new())
    }
}

/// Minimal CSV line parser that handles quoted fields.
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes {
                    if chars.peek() == Some(&'"') {
                        current.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                } else {
                    in_quotes = true;
                }
            }
            ',' if !in_quotes => {
                fields.push(current.clone());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    fields.push(current);
    fields
}
