use std::collections::{HashMap, HashSet};
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};

/// A subdomain discovered from certificate transparency logs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CtDiscoveredSubdomain {
    pub name: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
}

/// A single entry from the crt.sh JSON API response.
#[derive(Debug, Clone, Deserialize)]
pub struct CrtShJsonEntry {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub issuer_name: String,
    #[serde(default, alias = "name_value")]
    pub name_value: String,
    #[serde(default)]
    pub not_before: String,
    #[serde(default)]
    pub not_after: String,
}

/// DNS resolution result for a subdomain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolutionResult {
    pub hostname: String,
    pub record_type: DnsRecordType,
    pub values: Vec<String>,
    pub resolved: bool,
}

/// Type of DNS record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
}

impl std::fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::AAAA => write!(f, "AAAA"),
            Self::CNAME => write!(f, "CNAME"),
            Self::MX => write!(f, "MX"),
            Self::TXT => write!(f, "TXT"),
            Self::NS => write!(f, "NS"),
        }
    }
}

/// A single Wayback Machine CDX entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaybackEntry {
    pub url: String,
    pub timestamp: String,
    pub status_code: String,
    pub mime_type: String,
    pub length: Option<String>,
}

/// Cloud storage bucket discovery result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudBucketResult {
    pub bucket_name: String,
    pub provider: CloudProvider,
    pub url: String,
    pub exists: bool,
    pub public: bool,
}

/// Cloud storage providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloudProvider {
    AwsS3,
    AzureBlob,
    GcpStorage,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwsS3 => write!(f, "AWS S3"),
            Self::AzureBlob => write!(f, "Azure Blob"),
            Self::GcpStorage => write!(f, "GCP Storage"),
        }
    }
}

/// Aggregated real-time intelligence for a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeIntelligence {
    pub domain: String,
    pub ct_subdomains: Vec<CtDiscoveredSubdomain>,
    pub dns_results: Vec<DnsResolutionResult>,
    pub wayback_entries: Vec<WaybackEntry>,
    pub cloud_buckets: Vec<CloudBucketResult>,
    pub unique_subdomains: Vec<String>,
    pub unique_ips: Vec<String>,
    pub summary: IntelSummary,
}

/// Summary statistics for the intelligence gathering.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntelSummary {
    pub total_subdomains: usize,
    pub total_resolved: usize,
    pub total_wayback_urls: usize,
    pub total_cloud_buckets_found: usize,
    pub total_cloud_buckets_public: usize,
}

/// Configuration for the real-time intelligence aggregator.
#[derive(Debug, Clone)]
pub struct RealtimeIntelConfig {
    pub query_ct_logs: bool,
    pub resolve_dns: bool,
    pub query_wayback: bool,
    pub check_cloud_buckets: bool,
    pub max_subdomains_to_resolve: usize,
    pub dns_concurrency: usize,
    pub timeout_secs: u64,
    pub user_agent: String,
}

impl Default for RealtimeIntelConfig {
    fn default() -> Self {
        Self {
            query_ct_logs: true,
            resolve_dns: true,
            query_wayback: true,
            check_cloud_buckets: true,
            max_subdomains_to_resolve: 500,
            dns_concurrency: 50,
            timeout_secs: 15,
            user_agent: "Mozilla/5.0 (compatible; OSINT-RealtimeIntel/1.0)".into(),
        }
    }
}

/// The main real-time intelligence aggregator.
pub struct RealtimeIntelAggregator {
    client: reqwest::Client,
    config: RealtimeIntelConfig,
}

impl RealtimeIntelAggregator {
    pub fn new(config: RealtimeIntelConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .expect("failed to build HTTP client");

        Self { client, config }
    }

    /// Gather all real-time intelligence for a domain.
    pub async fn gather(&self, domain: &str) -> RealtimeIntelligence {
        let ct_subdomains = if self.config.query_ct_logs {
            self.query_crtsh(domain).await.unwrap_or_default()
        } else {
            Vec::new()
        };

        let unique_subdomains = extract_unique_subdomains(&ct_subdomains, domain);

        let dns_results = if self.config.resolve_dns {
            let to_resolve: Vec<&str> = unique_subdomains
                .iter()
                .take(self.config.max_subdomains_to_resolve)
                .map(|s| s.as_str())
                .collect();
            self.resolve_dns_batch(&to_resolve).await
        } else {
            Vec::new()
        };

        let unique_ips = extract_unique_ips(&dns_results);

        let wayback_entries = if self.config.query_wayback {
            self.query_wayback(domain).await.unwrap_or_default()
        } else {
            Vec::new()
        };

        let cloud_buckets = if self.config.check_cloud_buckets {
            self.check_cloud_storage(domain).await
        } else {
            Vec::new()
        };

        let summary = IntelSummary {
            total_subdomains: unique_subdomains.len(),
            total_resolved: dns_results.iter().filter(|r| r.resolved).count(),
            total_wayback_urls: wayback_entries.len(),
            total_cloud_buckets_found: cloud_buckets.iter().filter(|b| b.exists).count(),
            total_cloud_buckets_public: cloud_buckets.iter().filter(|b| b.public).count(),
        };

        RealtimeIntelligence {
            domain: domain.to_string(),
            ct_subdomains,
            dns_results,
            wayback_entries,
            cloud_buckets,
            unique_subdomains,
            unique_ips,
            summary,
        }
    }

    /// Query crt.sh certificate transparency logs.
    pub async fn query_crtsh(&self, domain: &str) -> Result<Vec<CtDiscoveredSubdomain>, String> {
        let url = format!("https://crt.sh/?q=%25.{domain}&output=json");
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_str(&self.config.user_agent)
            .unwrap_or_else(|_| HeaderValue::from_static("Mozilla/5.0")));

        let resp = self.client.get(&url).headers(headers).send().await.map_err(|e| e.to_string())?;

        if !resp.status().is_success() {
            return Err(format!("crt.sh returned status {}", resp.status()));
        }

        let entries: Vec<CrtShJsonEntry> = resp.json().await.map_err(|e| e.to_string())?;

        let mut seen = HashSet::new();
        let mut results = Vec::new();

        for entry in &entries {
            for name in entry.name_value.split('\n') {
                let name = name.trim().to_lowercase();
                if name.is_empty() || name.contains('*') {
                    continue;
                }
                if !name.ends_with(domain) && name != *domain {
                    continue;
                }
                if seen.insert(name.clone()) {
                    results.push(CtDiscoveredSubdomain {
                        name,
                        issuer: entry.issuer_name.clone(),
                        not_before: entry.not_before.clone(),
                        not_after: entry.not_after.clone(),
                    });
                }
            }
        }

        Ok(results)
    }

    /// Resolve DNS records for a batch of hostnames using Google DNS-over-HTTPS.
    pub async fn resolve_dns_batch(&self, hostnames: &[&str]) -> Vec<DnsResolutionResult> {
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(self.config.dns_concurrency));
        let mut handles = Vec::new();

        for hostname in hostnames {
            let sem = semaphore.clone();
            let client = self.client.clone();
            let ua = self.config.user_agent.clone();
            let host = hostname.to_string();

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.expect("semaphore closed");
                resolve_single_host(&client, &host, &ua).await
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            if let Ok(mut batch) = handle.await {
                results.append(&mut batch);
            }
        }
        results
    }

    /// Query the Wayback Machine CDX API.
    pub async fn query_wayback(&self, domain: &str) -> Result<Vec<WaybackEntry>, String> {
        let url = format!(
            "http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&limit=500&fl=original,timestamp,statuscode,mimetype,length"
        );

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_str(&self.config.user_agent)
            .unwrap_or_else(|_| HeaderValue::from_static("Mozilla/5.0")));

        let resp = self.client.get(&url).headers(headers).send().await.map_err(|e| e.to_string())?;

        if !resp.status().is_success() {
            return Err(format!("Wayback CDX returned status {}", resp.status()));
        }

        let json: Vec<Vec<String>> = resp.json().await.map_err(|e| e.to_string())?;

        let mut entries = Vec::new();
        for (idx, row) in json.iter().enumerate() {
            if idx == 0 {
                continue;
            }
            if row.len() >= 4 {
                entries.push(WaybackEntry {
                    url: row[0].clone(),
                    timestamp: row[1].clone(),
                    status_code: row[2].clone(),
                    mime_type: row[3].clone(),
                    length: row.get(4).cloned(),
                });
            }
        }

        Ok(entries)
    }

    /// Check common cloud storage bucket names for a target.
    pub async fn check_cloud_storage(&self, domain: &str) -> Vec<CloudBucketResult> {
        let base_name = domain.split('.').next().unwrap_or(domain);
        let variations = generate_bucket_variations(base_name);
        let mut results = Vec::new();

        for (bucket_name, provider, url) in &variations {
            let exists = self.check_bucket_exists(url).await;
            let public = if exists {
                self.check_bucket_public(url, *provider).await
            } else {
                false
            };

            results.push(CloudBucketResult {
                bucket_name: bucket_name.clone(),
                provider: *provider,
                url: url.clone(),
                exists,
                public,
            });
        }

        results
    }

    async fn check_bucket_exists(&self, url: &str) -> bool {
        match self.client.head(url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                status != 404 && status != 0
            }
            Err(_) => false,
        }
    }

    async fn check_bucket_public(&self, url: &str, _provider: CloudProvider) -> bool {
        match self.client.get(url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                status == 200
            }
            Err(_) => false,
        }
    }
}

async fn resolve_single_host(
    client: &reqwest::Client,
    hostname: &str,
    user_agent: &str,
) -> Vec<DnsResolutionResult> {
    let mut results = Vec::new();

    for (record_type, type_str) in &[
        (DnsRecordType::A, "A"),
        (DnsRecordType::AAAA, "AAAA"),
        (DnsRecordType::CNAME, "CNAME"),
        (DnsRecordType::MX, "MX"),
        (DnsRecordType::TXT, "TXT"),
    ] {
        let url = format!("https://dns.google/resolve?name={hostname}&type={type_str}");
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_str(user_agent)
            .unwrap_or_else(|_| HeaderValue::from_static("Mozilla/5.0")));

        let resp = match client.get(&url).headers(headers).send().await {
            Ok(r) => r,
            Err(_) => {
                results.push(DnsResolutionResult {
                    hostname: hostname.to_string(),
                    record_type: *record_type,
                    values: Vec::new(),
                    resolved: false,
                });
                continue;
            }
        };

        let json: serde_json::Value = match resp.json().await {
            Ok(j) => j,
            Err(_) => continue,
        };

        let values: Vec<String> = json
            .get("Answer")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|entry| {
                        entry.get("data").and_then(|d| d.as_str()).map(|s| s.trim_end_matches('.').to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();

        let resolved = !values.is_empty();
        results.push(DnsResolutionResult {
            hostname: hostname.to_string(),
            record_type: *record_type,
            values,
            resolved,
        });
    }

    results
}

/// Extract unique subdomain names from CT results.
pub fn extract_unique_subdomains(ct_results: &[CtDiscoveredSubdomain], base_domain: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut subdomains = Vec::new();

    seen.insert(base_domain.to_string());
    subdomains.push(base_domain.to_string());

    for entry in ct_results {
        if seen.insert(entry.name.clone()) {
            subdomains.push(entry.name.clone());
        }
    }

    subdomains.sort();
    subdomains
}

/// Extract unique IPs from DNS resolution results.
pub fn extract_unique_ips(dns_results: &[DnsResolutionResult]) -> Vec<String> {
    let mut ips = HashSet::new();
    for result in dns_results {
        if matches!(result.record_type, DnsRecordType::A | DnsRecordType::AAAA) {
            for val in &result.values {
                ips.insert(val.clone());
            }
        }
    }
    let mut sorted: Vec<String> = ips.into_iter().collect();
    sorted.sort();
    sorted
}

/// Generate common bucket name variations for cloud storage enumeration.
pub fn generate_bucket_variations(base_name: &str) -> Vec<(String, CloudProvider, String)> {
    let suffixes = [
        "", "-backup", "-bak", "-data", "-dev", "-staging", "-prod",
        "-assets", "-media", "-uploads", "-static", "-logs", "-db",
        "-archive", "-test", "-tmp", "-public", "-private", "-internal",
    ];

    let mut variations = Vec::new();

    for suffix in &suffixes {
        let bucket = format!("{base_name}{suffix}");

        variations.push((
            bucket.clone(),
            CloudProvider::AwsS3,
            format!("https://{bucket}.s3.amazonaws.com"),
        ));

        variations.push((
            bucket.clone(),
            CloudProvider::AzureBlob,
            format!("https://{bucket}.blob.core.windows.net"),
        ));

        variations.push((
            bucket.clone(),
            CloudProvider::GcpStorage,
            format!("https://storage.googleapis.com/{bucket}"),
        ));
    }

    variations
}

/// Errors from the real-time intelligence aggregator.
#[derive(Debug, Clone)]
pub enum RealtimeIntelError {
    Network(String),
    ParseError(String),
    RateLimited,
    Timeout,
}

impl std::fmt::Display for RealtimeIntelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(e) => write!(f, "Network error: {e}"),
            Self::ParseError(e) => write!(f, "Parse error: {e}"),
            Self::RateLimited => write!(f, "Rate limited"),
            Self::Timeout => write!(f, "Request timed out"),
        }
    }
}

impl std::error::Error for RealtimeIntelError {}
