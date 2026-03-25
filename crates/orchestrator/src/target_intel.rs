/// Target intelligence aggregator: unified model of all intel about a scan target.
///
/// Aggregates tech stack, endpoints, findings, defenses, credentials, and
/// attack paths into a single cohesive target model that all modules contribute to.
use aegis_protocol::finding::{EvidenceLevel, VulnerabilityClass};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A detected technology in the target's stack.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TechStackEntry {
    pub name: String,
    pub version: Option<String>,
    pub category: TechCategory,
    pub confidence: u8,
}

/// Category of a detected technology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TechCategory {
    WebServer,
    Framework,
    Language,
    Database,
    Cdn,
    Waf,
    Os,
    Cms,
    JsLibrary,
    Other,
}

/// A discovered endpoint with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelEndpoint {
    pub url: String,
    pub method: String,
    pub parameters: Vec<String>,
    pub auth_required: bool,
    pub response_codes: Vec<u16>,
    pub content_type: Option<String>,
    pub discovery_source: String,
}

/// A finding as represented in the intel model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelFinding {
    pub id: u64,
    pub vulnerability_class: VulnerabilityClass,
    pub endpoint: String,
    pub severity: f64,
    pub confidence: f64,
    pub evidence_level: EvidenceLevel,
    pub parameter: Option<String>,
    pub verified: bool,
}

/// A detected defense mechanism.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelDefense {
    pub defense_type: DefenseType,
    pub vendor: Option<String>,
    pub effectiveness: f64,
    pub bypassed: bool,
    pub bypass_technique: Option<String>,
}

/// Type of defense mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DefenseType {
    Waf,
    RateLimiter,
    BotDetection,
    Csp,
    Cors,
    AuthNLayer,
    Captcha,
    IpBlocklist,
}

/// A discovered or inferred credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelCredential {
    pub credential_type: CredentialType,
    pub location: String,
    pub value_hint: String,
    pub source: String,
}

/// Type of credential found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CredentialType {
    ApiKey,
    SessionToken,
    JwtSecret,
    DatabasePassword,
    AdminPassword,
    OauthToken,
    SshKey,
}

/// A potential attack path through the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelAttackPath {
    pub name: String,
    pub steps: Vec<AttackPathStep>,
    pub total_severity: f64,
    pub likelihood: f64,
}

/// A single step in an attack path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathStep {
    pub description: String,
    pub vulnerability_class: Option<VulnerabilityClass>,
    pub endpoint: Option<String>,
    pub requires_auth: bool,
}

/// The unified target intelligence model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetIntel {
    pub target_url: String,
    pub scan_id: String,
    pub tech_stack: Vec<TechStackEntry>,
    pub endpoints: Vec<IntelEndpoint>,
    pub findings: Vec<IntelFinding>,
    pub defenses: Vec<IntelDefense>,
    pub credentials: Vec<IntelCredential>,
    pub attack_paths: Vec<IntelAttackPath>,
    pub metadata: HashMap<String, String>,
    pub last_updated_ms: u64,
}

/// Summary statistics of target intelligence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelSummary {
    pub total_endpoints: usize,
    pub total_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub tech_stack_size: usize,
    pub defense_count: usize,
    pub credential_count: usize,
    pub attack_path_count: usize,
    pub vuln_class_distribution: HashMap<String, usize>,
    pub top_severity: f64,
}

impl TargetIntel {
    pub fn new(target_url: impl Into<String>, scan_id: impl Into<String>) -> Self {
        Self {
            target_url: target_url.into(),
            scan_id: scan_id.into(),
            tech_stack: Vec::new(),
            endpoints: Vec::new(),
            findings: Vec::new(),
            defenses: Vec::new(),
            credentials: Vec::new(),
            attack_paths: Vec::new(),
            metadata: HashMap::new(),
            last_updated_ms: 0,
        }
    }

    pub fn add_tech(&mut self, entry: TechStackEntry) {
        if !self.tech_stack.contains(&entry) {
            self.tech_stack.push(entry);
        }
    }

    pub fn add_endpoint(&mut self, endpoint: IntelEndpoint) {
        let exists = self
            .endpoints
            .iter()
            .any(|e| e.url == endpoint.url && e.method == endpoint.method);
        if !exists {
            self.endpoints.push(endpoint);
        }
    }

    pub fn add_finding(&mut self, finding: IntelFinding) {
        self.findings.push(finding);
    }

    pub fn add_defense(&mut self, defense: IntelDefense) {
        self.defenses.push(defense);
    }

    pub fn add_credential(&mut self, cred: IntelCredential) {
        self.credentials.push(cred);
    }

    pub fn add_attack_path(&mut self, path: IntelAttackPath) {
        self.attack_paths.push(path);
    }

    /// Unique vulnerability classes present in findings.
    pub fn unique_vuln_classes(&self) -> HashSet<VulnerabilityClass> {
        self.findings
            .iter()
            .map(|f| f.vulnerability_class)
            .collect()
    }

    /// Findings filtered by minimum severity threshold.
    pub fn findings_above_severity(&self, threshold: f64) -> Vec<&IntelFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity >= threshold)
            .collect()
    }

    /// Endpoints that have at least one associated finding.
    pub fn vulnerable_endpoints(&self) -> Vec<&str> {
        let vuln_eps: HashSet<&str> = self.findings.iter().map(|f| f.endpoint.as_str()).collect();
        let mut result: Vec<&str> = vuln_eps.into_iter().collect();
        result.sort();
        result
    }

    /// Defenses that have been successfully bypassed.
    pub fn bypassed_defenses(&self) -> Vec<&IntelDefense> {
        self.defenses.iter().filter(|d| d.bypassed).collect()
    }

    /// Has a WAF been detected?
    pub fn has_waf(&self) -> bool {
        self.defenses
            .iter()
            .any(|d| d.defense_type == DefenseType::Waf)
    }

    /// Produce a summary of all collected intelligence.
    pub fn summarize(&self) -> IntelSummary {
        let mut vuln_dist: HashMap<String, usize> = HashMap::new();
        let mut top_sev: f64 = 0.0;
        let mut critical = 0;
        let mut high = 0;

        for f in &self.findings {
            *vuln_dist
                .entry(f.vulnerability_class.to_string())
                .or_insert(0) += 1;
            if f.severity > top_sev {
                top_sev = f.severity;
            }
            if f.severity >= 9.0 {
                critical += 1;
            } else if f.severity >= 7.0 {
                high += 1;
            }
        }

        IntelSummary {
            total_endpoints: self.endpoints.len(),
            total_findings: self.findings.len(),
            critical_findings: critical,
            high_findings: high,
            tech_stack_size: self.tech_stack.len(),
            defense_count: self.defenses.len(),
            credential_count: self.credentials.len(),
            attack_path_count: self.attack_paths.len(),
            vuln_class_distribution: vuln_dist,
            top_severity: top_sev,
        }
    }

    /// Merge another TargetIntel into this one (additive).
    pub fn merge(&mut self, other: &TargetIntel) {
        for tech in &other.tech_stack {
            self.add_tech(tech.clone());
        }
        for ep in &other.endpoints {
            self.add_endpoint(ep.clone());
        }
        for f in &other.findings {
            self.add_finding(f.clone());
        }
        for d in &other.defenses {
            self.add_defense(d.clone());
        }
        for c in &other.credentials {
            self.add_credential(c.clone());
        }
        for ap in &other.attack_paths {
            self.add_attack_path(ap.clone());
        }
        if other.last_updated_ms > self.last_updated_ms {
            self.last_updated_ms = other.last_updated_ms;
        }
    }

    /// JSON serialization.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("serialize error: {e}"))
    }
}
