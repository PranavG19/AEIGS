/// Finding correlation engine for deduplication, chain suggestion, and false-positive detection.
///
/// Groups findings by vulnerability class and severity, boosts confidence when
/// multiple modules confirm the same issue, identifies scanner artifacts via
/// low-variance heuristic, and suggests attack chains from co-occurring classes.
use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use std::collections::{HashMap, HashSet};

/// A group of correlated findings.
#[derive(Debug, Clone)]
pub struct CorrelatedFinding {
    pub primary: FindingSnapshot,
    pub related_locations: Vec<String>,
    pub occurrence_count: usize,
    pub boosted_confidence: f64,
    pub is_likely_false_positive: bool,
}

/// Lightweight snapshot of a finding for correlation purposes.
#[derive(Debug, Clone)]
pub struct FindingSnapshot {
    pub finding_id: u64,
    pub vulnerability_class: String,
    pub severity: f64,
    pub confidence: f64,
    pub endpoint: String,
}

/// Suggested attack chain from correlated findings.
#[derive(Debug, Clone)]
pub struct SuggestedChain {
    pub name: String,
    pub findings: Vec<u64>,
    pub description: String,
    pub combined_severity: f64,
}

/// Result of the correlation process.
#[derive(Debug, Clone)]
pub struct CorrelationResult {
    pub deduplicated: Vec<CorrelatedFinding>,
    pub suggested_chains: Vec<SuggestedChain>,
    pub false_positive_candidates: Vec<u64>,
    pub original_count: usize,
    pub deduplicated_count: usize,
}

/// Extract the endpoint path from a finding's linked nodes.
/// Falls back to finding id as string if no endpoint can be resolved.
fn extract_endpoint(finding: &FindingData, endpoints: &HashMap<u64, String>) -> String {
    for &node_id in &finding.linked_node_ids {
        if let Some(ep) = endpoints.get(&node_id) {
            return ep.clone();
        }
    }
    format!("finding:{}", finding.id)
}

/// Deduplicate findings: group by (vulnerability_class, severity_bucket).
/// Same vuln on different endpoints becomes a single finding with multiple locations.
pub fn deduplicate_findings(
    findings: &[FindingData],
    endpoints: &HashMap<u64, String>,
) -> Vec<CorrelatedFinding> {
    let mut groups: HashMap<String, Vec<(FindingSnapshot, String)>> = HashMap::new();

    for finding in findings {
        let endpoint = extract_endpoint(finding, endpoints);
        let key = format!("{}:{:.1}", finding.vulnerability_class, finding.severity);
        let snapshot = FindingSnapshot {
            finding_id: finding.id,
            vulnerability_class: format!("{}", finding.vulnerability_class),
            severity: finding.severity,
            confidence: finding.confidence.composite.value(),
            endpoint: endpoint.clone(),
        };
        groups.entry(key).or_default().push((snapshot, endpoint));
    }

    groups
        .into_values()
        .map(|members| {
            let count = members.len();
            let primary = members[0].0.clone();
            let locations: Vec<String> = members.iter().map(|(_, ep)| ep.clone()).collect();

            // Boost confidence when multiple modules find the same thing.
            // Each extra occurrence adds 0.1, capped at +0.3.
            let max_confidence = members
                .iter()
                .map(|(s, _)| s.confidence)
                .fold(0.0f64, f64::max);
            let boosted = (max_confidence + 0.1 * (count as f64 - 1.0).min(3.0)).min(1.0);

            // False positive heuristic: identical finding across >10 endpoints
            // usually indicates a scanner artefact rather than a real vuln.
            let is_fp = count > 10;

            CorrelatedFinding {
                primary,
                related_locations: locations,
                occurrence_count: count,
                boosted_confidence: boosted,
                is_likely_false_positive: is_fp,
            }
        })
        .collect()
}

/// Identify suggested attack chains from finding combinations.
///
/// Each chain represents a known escalation path that becomes exploitable
/// when the constituent vulnerability classes co-exist on the same target.
pub fn suggest_chains(findings: &[FindingData]) -> Vec<SuggestedChain> {
    let mut chains = Vec::new();
    let class_set: HashSet<&VulnerabilityClass> =
        findings.iter().map(|f| &f.vulnerability_class).collect();

    let class_ids: HashMap<&VulnerabilityClass, Vec<u64>> = {
        let mut map: HashMap<&VulnerabilityClass, Vec<u64>> = HashMap::new();
        for f in findings {
            map.entry(&f.vulnerability_class).or_default().push(f.id);
        }
        map
    };

    // XSS → Account Takeover via session hijacking
    if let Some(xss_ids) = class_ids.get(&VulnerabilityClass::CrossSiteScripting) {
        chains.push(SuggestedChain {
            name: "account_takeover_xss".into(),
            findings: xss_ids.clone(),
            description: "XSS can be chained with session hijacking for account takeover".into(),
            combined_severity: 9.0,
        });
    }

    // SQLi + BrokenAuth → Full Database Access
    if class_set.contains(&VulnerabilityClass::SqlInjection)
        && class_set.contains(&VulnerabilityClass::BrokenAuthentication)
    {
        let mut ids = Vec::new();
        if let Some(sqli) = class_ids.get(&VulnerabilityClass::SqlInjection) {
            ids.extend(sqli);
        }
        if let Some(auth) = class_ids.get(&VulnerabilityClass::BrokenAuthentication) {
            ids.extend(auth);
        }
        chains.push(SuggestedChain {
            name: "full_db_access".into(),
            findings: ids,
            description: "SQL injection combined with broken auth enables full database access"
                .into(),
            combined_severity: 10.0,
        });
    }

    // SSRF + PathTraversal → Internal Network Pivot
    if class_set.contains(&VulnerabilityClass::ServerSideRequestForgery)
        && class_set.contains(&VulnerabilityClass::PathTraversal)
    {
        let mut ids = Vec::new();
        if let Some(s) = class_ids.get(&VulnerabilityClass::ServerSideRequestForgery) {
            ids.extend(s);
        }
        if let Some(p) = class_ids.get(&VulnerabilityClass::PathTraversal) {
            ids.extend(p);
        }
        chains.push(SuggestedChain {
            name: "internal_pivot".into(),
            findings: ids,
            description: "SSRF + path traversal enables internal network access and file read"
                .into(),
            combined_severity: 9.5,
        });
    }

    // OpenRedirect + BrokenAuth → Credential Theft
    if class_set.contains(&VulnerabilityClass::OpenRedirect)
        && class_set.contains(&VulnerabilityClass::BrokenAuthentication)
    {
        let mut ids = Vec::new();
        if let Some(r) = class_ids.get(&VulnerabilityClass::OpenRedirect) {
            ids.extend(r);
        }
        if let Some(a) = class_ids.get(&VulnerabilityClass::BrokenAuthentication) {
            ids.extend(a);
        }
        chains.push(SuggestedChain {
            name: "credential_theft".into(),
            findings: ids,
            description: "Open redirect with auth flaws enables credential phishing/theft".into(),
            combined_severity: 8.5,
        });
    }

    // SSRF alone → Cloud Metadata Access
    if let Some(ssrf_ids) = class_ids.get(&VulnerabilityClass::ServerSideRequestForgery) {
        chains.push(SuggestedChain {
            name: "cloud_metadata_access".into(),
            findings: ssrf_ids.clone(),
            description: "SSRF can access cloud metadata endpoints (169.254.169.254)".into(),
            combined_severity: 8.0,
        });
    }

    chains
}

/// Identify likely false positive finding IDs.
///
/// Heuristic: if the same vuln class appears in >10 endpoints with low
/// confidence variance, the findings are probably scanner artefacts rather
/// than genuine vulnerabilities.
pub fn detect_false_positives(
    findings: &[FindingData],
    _endpoints: &HashMap<u64, String>,
) -> Vec<u64> {
    let mut by_class: HashMap<String, Vec<&FindingData>> = HashMap::new();
    for f in findings {
        let key = format!("{}", f.vulnerability_class);
        by_class.entry(key).or_default().push(f);
    }

    let mut fp_ids = Vec::new();
    for group in by_class.values() {
        if group.len() > 10 {
            let confidences: Vec<f64> = group
                .iter()
                .map(|f| f.confidence.composite.value())
                .collect();
            let mean = confidences.iter().sum::<f64>() / confidences.len() as f64;
            let variance = confidences.iter().map(|c| (c - mean).powi(2)).sum::<f64>()
                / confidences.len() as f64;
            // Low variance means all findings have near-identical confidence
            if variance < 0.01 {
                fp_ids.extend(group.iter().map(|f| f.id));
            }
        }
    }
    fp_ids
}

/// Run the full correlation pipeline: deduplicate, suggest chains, detect FPs.
pub fn correlate_findings(
    findings: &[FindingData],
    endpoints: &HashMap<u64, String>,
) -> CorrelationResult {
    let original_count = findings.len();
    let deduplicated = deduplicate_findings(findings, endpoints);
    let suggested_chains = suggest_chains(findings);
    let false_positive_candidates = detect_false_positives(findings, endpoints);
    let deduplicated_count = deduplicated.len();

    CorrelationResult {
        deduplicated,
        suggested_chains,
        false_positive_candidates,
        original_count,
        deduplicated_count,
    }
}
