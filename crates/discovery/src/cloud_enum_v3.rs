/// Cloud enumeration v3: company-name + suffix bucket discovery across seven
/// cloud storage providers with list-operation response parsing and risk
/// classification.
///
/// Generates candidate bucket/container names by combining a company name with
/// 50 common suffixes, builds the provider-specific URL for each, and provides
/// parsers for the XML (S3) and JSON (Azure/GCP/etc.) list-operation responses.
use std::collections::HashMap;
use std::fmt;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Supported cloud storage providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloudProvider {
    AwsS3,
    AzureBlob,
    GcpStorage,
    DigitalOceanSpaces,
    AlibabaOss,
    OracleOci,
    BackblazeB2,
}

impl CloudProvider {
    pub fn all() -> &'static [CloudProvider] {
        &[
            Self::AwsS3,
            Self::AzureBlob,
            Self::GcpStorage,
            Self::DigitalOceanSpaces,
            Self::AlibabaOss,
            Self::OracleOci,
            Self::BackblazeB2,
        ]
    }

    /// Human-readable label used in reports.
    pub fn label(&self) -> &'static str {
        match self {
            Self::AwsS3 => "AWS S3",
            Self::AzureBlob => "Azure Blob Storage",
            Self::GcpStorage => "GCP Cloud Storage",
            Self::DigitalOceanSpaces => "DigitalOcean Spaces",
            Self::AlibabaOss => "Alibaba Cloud OSS",
            Self::OracleOci => "Oracle Cloud OCI Object Storage",
            Self::BackblazeB2 => "Backblaze B2",
        }
    }
}

impl fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Permission check outcome for a single bucket probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BucketPermission {
    Public,
    Private,
    Authenticated,
    NotFound,
    Forbidden,
    Error,
}

impl fmt::Display for BucketPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag = match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Authenticated => "authenticated",
            Self::NotFound => "not-found",
            Self::Forbidden => "forbidden",
            Self::Error => "error",
        };
        write!(f, "{tag}")
    }
}

impl BucketPermission {
    /// Classify an HTTP status code into a permission result.
    pub fn from_status(status: u16) -> Self {
        match status {
            200 => Self::Public,
            403 => Self::Forbidden,
            401 => Self::Authenticated,
            404 => Self::NotFound,
            _ => Self::Error,
        }
    }
}

/// Risk rating for a discovered bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BucketRisk {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for BucketRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{tag}")
    }
}

impl BucketRisk {
    pub fn score(&self) -> f64 {
        match self {
            Self::Info => 0.1,
            Self::Low => 0.3,
            Self::Medium => 0.5,
            Self::High => 0.8,
            Self::Critical => 1.0,
        }
    }
}

/// A single bucket finding from enumeration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BucketFinding {
    pub provider: CloudProvider,
    pub bucket_name: String,
    pub url: String,
    pub permission: BucketPermission,
    pub risk: BucketRisk,
    pub objects_found: Vec<String>,
    pub detail: String,
}

/// Full enumeration report across all providers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloudEnumReport {
    pub company: String,
    pub total_checked: usize,
    pub total_found: usize,
    pub findings: Vec<BucketFinding>,
    pub provider_summary: HashMap<String, usize>,
    pub risk_summary: HashMap<String, usize>,
}

/// The 50 suffixes combined with a company name to generate candidate buckets.
pub const BUCKET_SUFFIXES: &[&str] = &[
    "backup",
    "dev",
    "staging",
    "prod",
    "logs",
    "assets",
    "cdn",
    "uploads",
    "data",
    "db",
    "sql",
    "archive",
    "media",
    "images",
    "static",
    "public",
    "private",
    "internal",
    "test",
    "tmp",
    "config",
    "secrets",
    "keys",
    "certs",
    "deploy",
    "releases",
    "builds",
    "ci",
    "artifacts",
    "docs",
    "reports",
    "exports",
    "imports",
    "migration",
    "dump",
    "raw",
    "processed",
    "analytics",
    "ml",
    "models",
    "training",
    "infra",
    "terraform",
    "k8s",
    "helm",
    "docker",
    "lambda",
    "functions",
    "api",
    "web",
];

/// Generate candidate bucket names from a company name and the 50 suffixes.
///
/// Produces `{company}`, `{company}-{suffix}` for each suffix, and a sanitised
/// version that replaces non-alphanumeric characters with hyphens.
pub fn generate_bucket_names(company: &str) -> Vec<String> {
    let sanitised = company
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string();

    let mut names = Vec::with_capacity(BUCKET_SUFFIXES.len() * 2 + 2);

    names.push(sanitised.clone());

    for suffix in BUCKET_SUFFIXES {
        names.push(format!("{sanitised}-{suffix}"));
    }

    let compact = sanitised.replace('-', "");
    if compact != sanitised && !compact.is_empty() {
        names.push(compact.clone());
        for suffix in BUCKET_SUFFIXES {
            names.push(format!("{compact}-{suffix}"));
        }
    }

    names.sort();
    names.dedup();
    names
}

/// Build the list-operation URL for a bucket on the given provider.
pub fn build_bucket_urls(bucket_name: &str, provider: CloudProvider) -> String {
    match provider {
        CloudProvider::AwsS3 => {
            format!("https://{bucket_name}.s3.amazonaws.com/?list-type=2")
        }
        CloudProvider::AzureBlob => {
            format!("https://{bucket_name}.blob.core.windows.net/?comp=list&restype=container")
        }
        CloudProvider::GcpStorage => {
            format!("https://storage.googleapis.com/storage/v1/b/{bucket_name}/o")
        }
        CloudProvider::DigitalOceanSpaces => {
            format!("https://{bucket_name}.nyc3.digitaloceanspaces.com/?list-type=2")
        }
        CloudProvider::AlibabaOss => {
            format!("https://{bucket_name}.oss-us-west-1.aliyuncs.com/?list-type=2")
        }
        CloudProvider::OracleOci => {
            format!(
                "https://objectstorage.us-ashburn-1.oraclecloud.com/n/namespace/b/{bucket_name}/o",
            )
        }
        CloudProvider::BackblazeB2 => {
            format!("https://f000.backblazeb2.com/file/{bucket_name}/")
        }
    }
}

/// Parse an S3-style XML `ListBucketResult` into a list of object keys.
///
/// Handles the `<Key>…</Key>` elements returned by S3, DigitalOcean Spaces,
/// and Alibaba OSS.
pub fn parse_s3_list_response(xml: &str) -> Vec<String> {
    let re = Regex::new(r"<Key>([^<]+)</Key>").expect("valid regex");
    re.captures_iter(xml)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

/// Parse an Azure Blob Storage JSON list response into object names.
///
/// Expects the `"Blobs": { "Blob": [ { "Name": "..." }, … ] }` shape returned
/// by the `?comp=list&restype=container` endpoint.
pub fn parse_azure_list_response(json_str: &str) -> Vec<String> {
    let parsed: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut names = Vec::new();

    if let Some(blobs) = parsed.get("Blobs").and_then(|b| b.get("Blob")) {
        if let Some(arr) = blobs.as_array() {
            for blob in arr {
                if let Some(name) = blob.get("Name").and_then(|n| n.as_str()) {
                    names.push(name.to_string());
                }
            }
        }
    }

    if names.is_empty() {
        if let Some(items) = parsed.get("items").and_then(|i| i.as_array()) {
            for item in items {
                if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                    names.push(name.to_string());
                }
            }
        }
    }

    names
}

/// Parse a GCP Cloud Storage JSON list response (`{ "items": [ { "name": "…" } ] }`).
pub fn parse_gcp_list_response(json_str: &str) -> Vec<String> {
    let parsed: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    parsed
        .get("items")
        .and_then(|items| items.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.get("name").and_then(|n| n.as_str()))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Classify a bucket finding's risk level from its permission state and the
/// objects it exposes (if any).
pub fn classify_bucket_risk(permission: BucketPermission, objects: &[String]) -> BucketRisk {
    match permission {
        BucketPermission::Public if contains_sensitive_objects(objects) => BucketRisk::Critical,
        BucketPermission::Public if !objects.is_empty() => BucketRisk::High,
        BucketPermission::Public => BucketRisk::Medium,
        BucketPermission::Authenticated if contains_sensitive_objects(objects) => BucketRisk::High,
        BucketPermission::Authenticated => BucketRisk::Low,
        BucketPermission::Forbidden => BucketRisk::Info,
        BucketPermission::Private => BucketRisk::Info,
        BucketPermission::NotFound => BucketRisk::Info,
        BucketPermission::Error => BucketRisk::Info,
    }
}

/// Patterns that flag an object key as sensitive.
const SENSITIVE_PATTERNS: &[&str] = &[
    ".env",
    "credentials",
    "password",
    "secret",
    ".pem",
    ".key",
    ".pfx",
    ".p12",
    "id_rsa",
    "id_ed25519",
    ".sql",
    ".bak",
    "backup",
    "dump",
    "token",
    "api_key",
    "apikey",
    ".htpasswd",
    "shadow",
    "private",
    "terraform.tfstate",
    "kubeconfig",
    ".kube/config",
    "docker-compose",
    ".git/",
];

fn contains_sensitive_objects(objects: &[String]) -> bool {
    let lower_patterns: Vec<String> = SENSITIVE_PATTERNS
        .iter()
        .map(|p| p.to_lowercase())
        .collect();
    objects.iter().any(|obj| {
        let lower = obj.to_lowercase();
        lower_patterns.iter().any(|pat| lower.contains(pat))
    })
}

/// Build a full cloud enumeration report from a set of findings.
pub fn build_cloud_enum_report(
    company: &str,
    total_checked: usize,
    findings: Vec<BucketFinding>,
) -> CloudEnumReport {
    let total_found = findings.len();

    let mut provider_summary: HashMap<String, usize> = HashMap::new();
    let mut risk_summary: HashMap<String, usize> = HashMap::new();

    for finding in &findings {
        *provider_summary
            .entry(finding.provider.to_string())
            .or_insert(0) += 1;
        *risk_summary.entry(finding.risk.to_string()).or_insert(0) += 1;
    }

    CloudEnumReport {
        company: company.to_string(),
        total_checked,
        total_found,
        findings,
        provider_summary,
        risk_summary,
    }
}

/// Build a `BucketFinding` for a single probe result.
pub fn build_finding(
    provider: CloudProvider,
    bucket_name: &str,
    permission: BucketPermission,
    objects: Vec<String>,
) -> BucketFinding {
    let risk = classify_bucket_risk(permission, &objects);
    let url = build_bucket_urls(bucket_name, provider);
    let detail = format!(
        "{} bucket '{}' is {} ({} objects listed)",
        provider,
        bucket_name,
        permission,
        objects.len(),
    );

    BucketFinding {
        provider,
        bucket_name: bucket_name.to_string(),
        url,
        permission,
        risk,
        objects_found: objects,
        detail,
    }
}

/// Map an HTTP status code to a `BucketPermission` using provider-specific
/// heuristics (some providers return 200 with an error body for forbidden
/// buckets).
pub fn permission_from_status_and_body(
    status: u16,
    body: &str,
    provider: CloudProvider,
) -> BucketPermission {
    match provider {
        CloudProvider::AwsS3 | CloudProvider::AlibabaOss | CloudProvider::DigitalOceanSpaces => {
            if status == 200 && body.contains("<Error>") {
                return BucketPermission::Forbidden;
            }
            if status == 200 && body.contains("<ListBucketResult") {
                return BucketPermission::Public;
            }
            BucketPermission::from_status(status)
        }
        CloudProvider::AzureBlob => {
            if status == 200 && body.contains("AuthenticationFailed") {
                return BucketPermission::Authenticated;
            }
            BucketPermission::from_status(status)
        }
        CloudProvider::GcpStorage => {
            if status == 200 {
                return BucketPermission::Public;
            }
            if status == 401 {
                return BucketPermission::Authenticated;
            }
            BucketPermission::from_status(status)
        }
        CloudProvider::OracleOci | CloudProvider::BackblazeB2 => {
            BucketPermission::from_status(status)
        }
    }
}

/// Return all provider-specific list URLs for every candidate bucket name
/// generated from a company name.
pub fn enumerate_all_urls(company: &str) -> Vec<(CloudProvider, String, String)> {
    let names = generate_bucket_names(company);
    let mut urls = Vec::with_capacity(names.len() * CloudProvider::all().len());
    for provider in CloudProvider::all() {
        for name in &names {
            urls.push((*provider, name.clone(), build_bucket_urls(name, *provider)));
        }
    }
    urls
}
