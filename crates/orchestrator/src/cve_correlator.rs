use std::collections::HashMap;
use std::fmt;

use aegis_protocol::finding::{Confidence, VulnerabilityClass};
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::recon_client;
use crate::util::timestamp_ms;

const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_TIMEOUT_SECS: u64 = 30;
const NVD_REQUEST_DELAY_MS: u64 = 6500;

/// Queries the NVD API for CVEs matching the given technologies.
///
/// Uses keyword search with no API key (5 requests/30s rate limit).
/// Set `NVD_API_KEY` env var for higher rate limits (50 req/30s).
pub fn correlate_cves(technologies: &[String]) -> Vec<NvdCveMatch> {
    if technologies.is_empty() {
        return Vec::new();
    }
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(NVD_TIMEOUT_SECS))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "failed to build HTTP client for NVD API");
            return Vec::new();
        }
    };
    let api_key = std::env::var("NVD_API_KEY").ok();
    let mut all_matches = Vec::new();

    for tech in technologies {
        let matches = query_nvd_for_tech(&client, tech, api_key.as_deref());
        all_matches.extend(matches);
        if technologies.len() > 1 {
            std::thread::sleep(std::time::Duration::from_millis(NVD_REQUEST_DELAY_MS));
        }
    }

    if !all_matches.is_empty() {
        tracing::info!(
            count = all_matches.len(),
            "NVD CVE correlation found matches"
        );
    }
    all_matches
}

fn query_nvd_for_tech(
    client: &reqwest::blocking::Client,
    tech: &str,
    api_key: Option<&str>,
) -> Vec<NvdCveMatch> {
    let mut request = client
        .get(NVD_API_BASE)
        .query(&[("keywordSearch", tech), ("resultsPerPage", "5")]);
    if let Some(key) = api_key {
        request = request.header("apiKey", key);
    }
    let response = match request.send() {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(tech = %tech, error = %e, "NVD query failed");
            return Vec::new();
        }
    };
    if !response.status().is_success() {
        tracing::debug!(
            tech = %tech,
            status = %response.status(),
            "NVD returned non-success"
        );
        return Vec::new();
    }
    let body = match response.text() {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    parse_nvd_response(&body, tech)
}

#[derive(Debug, Clone)]
pub struct NvdCveMatch {
    pub cve_id: String,
    pub description: String,
    pub cvss_score: Option<f64>,
    pub technology: String,
}

pub fn parse_nvd_response(body: &str, tech: &str) -> Vec<NvdCveMatch> {
    let response: NvdResponse = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => {
            tracing::debug!("failed to parse NVD JSON response");
            return Vec::new();
        }
    };
    response
        .vulnerabilities
        .into_iter()
        .filter_map(|vuln| {
            let cve = vuln.cve?;
            let cve_id = cve.id?;
            let description = cve
                .descriptions
                .into_iter()
                .find(|d| d.lang.as_deref() == Some("en"))
                .and_then(|d| d.value)
                .unwrap_or_default();
            let cvss_score = cve.metrics.and_then(extract_cvss_score);
            Some(NvdCveMatch {
                cve_id,
                description,
                cvss_score,
                technology: tech.to_string(),
            })
        })
        .collect()
}

fn extract_cvss_score(metrics: NvdMetrics) -> Option<f64> {
    metrics
        .cvss_metric_v31
        .and_then(|m| m.into_iter().next())
        .and_then(|m| m.cvss_data)
        .and_then(|d| d.base_score)
        .or_else(|| {
            metrics
                .cvss_metric_v2
                .and_then(|m| m.into_iter().next())
                .and_then(|m| m.cvss_data)
                .and_then(|d| d.base_score)
        })
}

pub fn cve_matches_to_operations(matches: &[NvdCveMatch], seq: &mut u64) -> Vec<OperationLogEntry> {
    matches
        .iter()
        .map(|m| {
            *seq += 1;
            let severity = m.cvss_score.unwrap_or(5.0);
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: vec![],
                    vulnerability_class: VulnerabilityClass::KnownVulnerableDependency,
                    severity,
                    confidence: Confidence::new(0.8).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum CveIssue {
    KnownCve {
        cve_id: String,
        technology: String,
        cvss_score: f64,
    },
    CriticalCve {
        cve_id: String,
        technology: String,
        cvss_score: f64,
    },
    ExploitAvailable {
        cve_id: String,
        technology: String,
    },
    RemoteCodeExecution {
        cve_id: String,
        technology: String,
    },
    AuthBypass {
        cve_id: String,
        technology: String,
    },
    OutdatedTechnology {
        technology: String,
        latest_cve_year: u16,
    },
    HighCveCount {
        technology: String,
        count: usize,
    },
    NoScoreAvailable {
        cve_id: String,
        technology: String,
    },
}

impl fmt::Display for CveIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KnownCve {
                cve_id,
                technology,
                cvss_score,
            } => write!(f, "known_cve:{cve_id}:{technology}:{cvss_score}"),
            Self::CriticalCve {
                cve_id,
                technology,
                cvss_score,
            } => write!(f, "critical_cve:{cve_id}:{technology}:{cvss_score}"),
            Self::ExploitAvailable { cve_id, technology } => {
                write!(f, "exploit_available:{cve_id}:{technology}")
            }
            Self::RemoteCodeExecution { cve_id, technology } => {
                write!(f, "remote_code_execution:{cve_id}:{technology}")
            }
            Self::AuthBypass { cve_id, technology } => {
                write!(f, "auth_bypass:{cve_id}:{technology}")
            }
            Self::OutdatedTechnology {
                technology,
                latest_cve_year,
            } => write!(f, "outdated_technology:{technology}:{latest_cve_year}"),
            Self::HighCveCount { technology, count } => {
                write!(f, "high_cve_count:{technology}:{count}")
            }
            Self::NoScoreAvailable { cve_id, technology } => {
                write!(f, "no_score_available:{cve_id}:{technology}")
            }
        }
    }
}

pub fn cve_issue_severity(issue: &CveIssue) -> f64 {
    match issue {
        CveIssue::CriticalCve { cvss_score, .. } => *cvss_score,
        CveIssue::RemoteCodeExecution { .. } => 9.5,
        CveIssue::AuthBypass { .. } => 8.5,
        CveIssue::ExploitAvailable { .. } => 8.0,
        CveIssue::KnownCve { cvss_score, .. } => *cvss_score,
        CveIssue::HighCveCount { .. } => 7.0,
        CveIssue::OutdatedTechnology { .. } => 6.0,
        CveIssue::NoScoreAvailable { .. } => 5.0,
    }
}

pub fn analyze_cve_matches(matches: &[NvdCveMatch]) -> Vec<CveIssue> {
    let mut issues = Vec::new();
    let mut tech_counts: HashMap<&str, usize> = HashMap::new();
    let mut tech_latest_year: HashMap<&str, u16> = HashMap::new();
    let current_year = current_year();

    for m in matches {
        *tech_counts.entry(&m.technology).or_insert(0) += 1;

        if let Some(year) = extract_cve_year(&m.cve_id) {
            let entry = tech_latest_year.entry(&m.technology).or_insert(0);
            if year > *entry {
                *entry = year;
            }
        }

        if let Some(score) = m.cvss_score {
            issues.push(CveIssue::KnownCve {
                cve_id: m.cve_id.clone(),
                technology: m.technology.clone(),
                cvss_score: score,
            });

            if score >= 9.0 {
                issues.push(CveIssue::CriticalCve {
                    cve_id: m.cve_id.clone(),
                    technology: m.technology.clone(),
                    cvss_score: score,
                });
            }
        } else {
            issues.push(CveIssue::NoScoreAvailable {
                cve_id: m.cve_id.clone(),
                technology: m.technology.clone(),
            });
        }

        let desc_lower = m.description.to_ascii_lowercase();

        if desc_lower.contains("remote code execution") || desc_lower.contains("rce") {
            issues.push(CveIssue::RemoteCodeExecution {
                cve_id: m.cve_id.clone(),
                technology: m.technology.clone(),
            });
        }

        if desc_lower.contains("authentication bypass") || desc_lower.contains("auth bypass") {
            issues.push(CveIssue::AuthBypass {
                cve_id: m.cve_id.clone(),
                technology: m.technology.clone(),
            });
        }

        if desc_lower.contains("exploit")
            || desc_lower.contains("proof of concept")
            || desc_lower.contains("poc")
        {
            issues.push(CveIssue::ExploitAvailable {
                cve_id: m.cve_id.clone(),
                technology: m.technology.clone(),
            });
        }
    }

    for (tech, count) in &tech_counts {
        if *count > 5 {
            issues.push(CveIssue::HighCveCount {
                technology: tech.to_string(),
                count: *count,
            });
        }
    }

    for (tech, year) in &tech_latest_year {
        if *year >= current_year - 1 {
            issues.push(CveIssue::OutdatedTechnology {
                technology: tech.to_string(),
                latest_cve_year: *year,
            });
        }
    }

    issues
}

pub fn cve_issues_to_operations(issues: &[CveIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::KnownVulnerableDependency,
                cve_issue_severity(issue),
                0.5,
            )
        })
        .collect()
}

fn extract_cve_year(cve_id: &str) -> Option<u16> {
    let parts: Vec<&str> = cve_id.split('-').collect();
    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

fn current_year() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // 31_557_600 = 365.25 * 86400 (average seconds per year)
    (1970 + secs / 31_557_600) as u16
}

#[derive(serde::Deserialize)]
struct NvdResponse {
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(serde::Deserialize)]
struct NvdVulnerability {
    cve: Option<NvdCve>,
}

#[derive(serde::Deserialize)]
struct NvdCve {
    id: Option<String>,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
    metrics: Option<NvdMetrics>,
}

#[derive(serde::Deserialize)]
struct NvdDescription {
    lang: Option<String>,
    value: Option<String>,
}

#[derive(serde::Deserialize)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31")]
    cvss_metric_v31: Option<Vec<NvdCvssMetric>>,
    #[serde(rename = "cvssMetricV2")]
    cvss_metric_v2: Option<Vec<NvdCvssMetric>>,
}

#[derive(serde::Deserialize)]
struct NvdCvssMetric {
    #[serde(rename = "cvssData")]
    cvss_data: Option<NvdCvssData>,
}

#[derive(serde::Deserialize)]
struct NvdCvssData {
    #[serde(rename = "baseScore")]
    base_score: Option<f64>,
}
