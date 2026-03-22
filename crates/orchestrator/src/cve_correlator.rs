use aegis_protocol::finding::{Confidence, VulnerabilityClass};
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

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

pub(crate) fn parse_nvd_response(body: &str, tech: &str) -> Vec<NvdCveMatch> {
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

pub(crate) fn cve_matches_to_operations(
    matches: &[NvdCveMatch],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
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
