/// Scan comparison intelligence: correlate findings across multiple targets.
///
/// Compares scans across different targets to detect systemic issues ("all 5
/// targets have the same misconfigured CORS"), shared technology patterns, and
/// vulnerability clustering that indicates organizational-level problems.
use aegis_protocol::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A single target's scan results for cross-comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetScanData {
    pub target_url: String,
    pub scan_id: String,
    pub findings: Vec<ComparisonFinding>,
    pub tech_stack: Vec<String>,
    pub timestamp_ms: u64,
}

/// Simplified finding for comparison purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonFinding {
    pub vulnerability_class: VulnerabilityClass,
    pub endpoint_pattern: String,
    pub severity: f64,
    pub confidence: f64,
    pub parameter: Option<String>,
}

/// A vulnerability that appears across multiple targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemicIssue {
    pub vulnerability_class: VulnerabilityClass,
    pub affected_targets: Vec<String>,
    pub occurrence_count: usize,
    pub average_severity: f64,
    pub is_systemic: bool,
    pub description: String,
}

/// A technology found across multiple targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedTechnology {
    pub technology: String,
    pub targets: Vec<String>,
    pub prevalence: f64,
    pub associated_vulns: Vec<VulnerabilityClass>,
}

/// Correlation between findings across targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossTargetCorrelation {
    pub pattern_name: String,
    pub targets_involved: Vec<String>,
    pub vulnerability_classes: Vec<VulnerabilityClass>,
    pub correlation_strength: f64,
    pub description: String,
}

/// Full comparison result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanComparisonResult {
    pub targets_compared: usize,
    pub systemic_issues: Vec<SystemicIssue>,
    pub shared_technologies: Vec<SharedTechnology>,
    pub correlations: Vec<CrossTargetCorrelation>,
    pub unique_to_target: HashMap<String, Vec<VulnerabilityClass>>,
    pub overall_risk_assessment: String,
}

/// Compare scans across multiple targets.
pub fn compare_scans(scans: &[TargetScanData]) -> ScanComparisonResult {
    let target_count = scans.len();
    let systemic = find_systemic_issues(scans);
    let shared_tech = find_shared_technologies(scans);
    let correlations = find_correlations(scans);
    let unique = find_unique_vulns(scans);
    let risk = assess_overall_risk(&systemic, target_count);

    ScanComparisonResult {
        targets_compared: target_count,
        systemic_issues: systemic,
        shared_technologies: shared_tech,
        correlations,
        unique_to_target: unique,
        overall_risk_assessment: risk,
    }
}

fn find_systemic_issues(scans: &[TargetScanData]) -> Vec<SystemicIssue> {
    let target_count = scans.len();
    if target_count < 2 {
        return Vec::new();
    }

    let mut class_targets: HashMap<VulnerabilityClass, Vec<(String, f64)>> = HashMap::new();
    for scan in scans {
        let mut seen_classes: HashSet<VulnerabilityClass> = HashSet::new();
        for finding in &scan.findings {
            if seen_classes.insert(finding.vulnerability_class) {
                class_targets
                    .entry(finding.vulnerability_class)
                    .or_default()
                    .push((scan.target_url.clone(), finding.severity));
            }
        }
    }

    let threshold = if target_count <= 3 {
        2
    } else {
        target_count / 2
    };

    class_targets
        .into_iter()
        .filter(|(_, targets)| targets.len() >= threshold)
        .map(|(class, targets)| {
            let avg_severity = targets.iter().map(|(_, s)| s).sum::<f64>() / targets.len() as f64;
            let affected: Vec<String> = targets.iter().map(|(t, _)| t.clone()).collect();
            let count = affected.len();
            let is_systemic = count as f64 / scans.len() as f64 >= 0.5;
            let desc = format!(
                "{} found across {}/{} targets — {}",
                class,
                count,
                scans.len(),
                if is_systemic {
                    "likely a systemic organizational issue"
                } else {
                    "appears in multiple targets"
                }
            );
            SystemicIssue {
                vulnerability_class: class,
                affected_targets: affected,
                occurrence_count: count,
                average_severity: avg_severity,
                is_systemic,
                description: desc,
            }
        })
        .collect()
}

fn find_shared_technologies(scans: &[TargetScanData]) -> Vec<SharedTechnology> {
    let mut tech_targets: HashMap<String, Vec<String>> = HashMap::new();
    for scan in scans {
        for tech in &scan.tech_stack {
            tech_targets
                .entry(tech.clone())
                .or_default()
                .push(scan.target_url.clone());
        }
    }

    let total = scans.len() as f64;

    tech_targets
        .into_iter()
        .filter(|(_, targets)| targets.len() > 1)
        .map(|(tech, targets)| {
            let prevalence = targets.len() as f64 / total;
            let associated = find_vulns_for_tech(&tech, scans);
            SharedTechnology {
                technology: tech,
                targets,
                prevalence,
                associated_vulns: associated,
            }
        })
        .collect()
}

fn find_vulns_for_tech(tech: &str, scans: &[TargetScanData]) -> Vec<VulnerabilityClass> {
    let mut vulns: HashSet<VulnerabilityClass> = HashSet::new();
    for scan in scans {
        if scan.tech_stack.iter().any(|t| t == tech) {
            for f in &scan.findings {
                vulns.insert(f.vulnerability_class);
            }
        }
    }
    vulns.into_iter().collect()
}

fn find_correlations(scans: &[TargetScanData]) -> Vec<CrossTargetCorrelation> {
    let mut correlations = Vec::new();

    let mut endpoint_patterns: HashMap<String, Vec<(String, VulnerabilityClass)>> = HashMap::new();
    for scan in scans {
        for finding in &scan.findings {
            let normalized = normalize_endpoint(&finding.endpoint_pattern);
            endpoint_patterns
                .entry(normalized)
                .or_default()
                .push((scan.target_url.clone(), finding.vulnerability_class));
        }
    }

    for (pattern, entries) in &endpoint_patterns {
        let unique_targets: HashSet<&str> = entries.iter().map(|(t, _)| t.as_str()).collect();
        if unique_targets.len() > 1 {
            let targets: Vec<String> = unique_targets.into_iter().map(String::from).collect();
            let classes: Vec<VulnerabilityClass> = entries
                .iter()
                .map(|(_, c)| *c)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            let strength = targets.len() as f64 / scans.len() as f64;
            correlations.push(CrossTargetCorrelation {
                pattern_name: format!("Shared endpoint pattern: {pattern}"),
                targets_involved: targets,
                vulnerability_classes: classes,
                correlation_strength: strength,
                description: format!(
                    "Multiple targets share vulnerable endpoint pattern '{pattern}'"
                ),
            });
        }
    }

    correlations
}

fn normalize_endpoint(endpoint: &str) -> String {
    let parts: Vec<&str> = endpoint.split('/').collect();
    parts
        .iter()
        .map(|p| {
            if p.chars().all(|c| c.is_ascii_digit()) {
                "{id}"
            } else {
                p
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn find_unique_vulns(scans: &[TargetScanData]) -> HashMap<String, Vec<VulnerabilityClass>> {
    let mut all_classes: HashMap<VulnerabilityClass, HashSet<String>> = HashMap::new();
    for scan in scans {
        for f in &scan.findings {
            all_classes
                .entry(f.vulnerability_class)
                .or_default()
                .insert(scan.target_url.clone());
        }
    }

    let mut unique: HashMap<String, Vec<VulnerabilityClass>> = HashMap::new();
    for (class, targets) in &all_classes {
        if targets.len() == 1 {
            let target = targets.iter().next().unwrap();
            unique.entry(target.clone()).or_default().push(*class);
        }
    }
    unique
}

fn assess_overall_risk(systemic: &[SystemicIssue], target_count: usize) -> String {
    if target_count < 2 {
        return "Insufficient targets for cross-scan comparison".to_string();
    }

    let critical_systemic = systemic
        .iter()
        .filter(|i| i.is_systemic && i.average_severity >= 7.0)
        .count();

    if critical_systemic >= 3 {
        "CRITICAL: Multiple high-severity systemic vulnerabilities detected across targets. Organizational-level remediation required.".to_string()
    } else if critical_systemic >= 1 {
        "HIGH: Systemic vulnerabilities present. Shared infrastructure or development practices likely contributing to repeated issues.".to_string()
    } else if !systemic.is_empty() {
        "MODERATE: Some shared vulnerability patterns detected. Review common components and deployment configurations.".to_string()
    } else {
        "LOW: No significant systemic patterns detected across targets.".to_string()
    }
}

/// Find the most common vulnerability class across all scans.
pub fn most_common_vuln(scans: &[TargetScanData]) -> Option<(VulnerabilityClass, usize)> {
    let mut counts: HashMap<VulnerabilityClass, usize> = HashMap::new();
    for scan in scans {
        for f in &scan.findings {
            *counts.entry(f.vulnerability_class).or_insert(0) += 1;
        }
    }
    counts.into_iter().max_by_key(|(_, count)| *count)
}
