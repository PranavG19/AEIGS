use std::fmt;
use std::time::Duration;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::recon_client;
use crate::util::timestamp_ms;

const S3_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

const SUFFIXES: &[&str] = &[
    "",
    "-backup",
    "-bak",
    "-dev",
    "-staging",
    "-stage",
    "-prod",
    "-production",
    "-test",
    "-data",
    "-assets",
    "-static",
    "-media",
    "-uploads",
    "-files",
    "-logs",
    "-internal",
    "-private",
    "-public",
    "-cdn",
    "-web",
    "-api",
    "-app",
    "-s3",
    "-bucket",
    "-storage",
    "-archive",
    "-old",
    "-temp",
    "-tmp",
];

#[derive(Debug, Clone)]
pub struct S3Finding {
    pub bucket: String,
    pub status: BucketStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BucketStatus {
    Open,
    Exists,
}

pub fn generate_bucket_candidates(domain: &str) -> Vec<String> {
    let base = domain.split('.').next().unwrap_or(domain).to_lowercase();
    if base.is_empty() {
        return Vec::new();
    }
    let domain_nodot = domain.to_lowercase().replace('.', "-");
    let mut candidates = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for prefix in [&base, &domain_nodot] {
        for suffix in SUFFIXES {
            let name = format!("{prefix}{suffix}");
            if seen.insert(name.clone()) {
                candidates.push(name);
            }
        }
    }
    candidates
}

pub fn check_bucket(bucket: &str) -> Option<S3Finding> {
    let url = format!("https://{bucket}.s3.amazonaws.com/");
    let client = reqwest::blocking::Client::builder()
        .timeout(S3_CHECK_TIMEOUT)
        .build()
        .ok()?;
    let resp = client.head(&url).send().ok()?;
    match resp.status().as_u16() {
        200 => Some(S3Finding {
            bucket: bucket.to_string(),
            status: BucketStatus::Open,
        }),
        403 => Some(S3Finding {
            bucket: bucket.to_string(),
            status: BucketStatus::Exists,
        }),
        _ => None,
    }
}

pub fn scan_s3_buckets(target: &str) -> Vec<S3Finding> {
    let Some(domain) = recon_client::validated_domain(target) else {
        return Vec::new();
    };
    let candidates = generate_bucket_candidates(&domain);
    candidates
        .iter()
        .filter_map(|name| check_bucket(name))
        .collect()
}

pub fn s3_findings_to_operations(findings: &[S3Finding], seq: &mut u64) -> Vec<OperationLogEntry> {
    let mut entries = Vec::new();
    for finding in findings {
        *seq += 1;
        let url = format!("https://{}.s3.amazonaws.com/", finding.bucket);
        entries.push(OperationLogEntry {
            sequence_number: *seq,
            module: ModuleIdentifier::PassiveRecon,
            operation: GraphOperation::AddNode {
                node_type: NodeType::Service,
                properties: vec![
                    ("hostname".to_string(), url.clone()),
                    ("source".to_string(), "s3-scan".to_string()),
                    (
                        "status".to_string(),
                        match finding.status {
                            BucketStatus::Open => "open".to_string(),
                            BucketStatus::Exists => "exists".to_string(),
                        },
                    ),
                ],
            },
            timestamp_unix_ms: timestamp_ms(),
        });
        if finding.status == BucketStatus::Open {
            entries.push(recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                8.0,
                0.9,
            ));
        }
    }
    entries
}

#[derive(Debug, Clone, PartialEq)]
pub enum S3Issue {
    OpenBucket { bucket: String },
    ExistsBucket { bucket: String },
    ListableBucket { bucket: String },
    SensitiveBucketName { bucket: String, category: String },
    DefaultRegionBucket { bucket: String },
    HttpBucket { bucket: String },
    WebsiteHostingEnabled { bucket: String },
    CrossAccountBucket { bucket: String },
}

impl fmt::Display for S3Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            S3Issue::OpenBucket { bucket } => {
                write!(f, "Open S3 bucket: {bucket}")
            }
            S3Issue::ExistsBucket { bucket } => {
                write!(f, "S3 bucket exists (access denied): {bucket}")
            }
            S3Issue::ListableBucket { bucket } => {
                write!(f, "Listable S3 bucket: {bucket}")
            }
            S3Issue::SensitiveBucketName { bucket, category } => {
                write!(f, "Sensitive bucket name ({category}): {bucket}")
            }
            S3Issue::DefaultRegionBucket { bucket } => {
                write!(f, "Default region (us-east-1) bucket: {bucket}")
            }
            S3Issue::HttpBucket { bucket } => {
                write!(f, "HTTP-accessible bucket: {bucket}")
            }
            S3Issue::WebsiteHostingEnabled { bucket } => {
                write!(f, "Website hosting enabled: {bucket}")
            }
            S3Issue::CrossAccountBucket { bucket } => {
                write!(f, "Cross-account bucket: {bucket}")
            }
        }
    }
}

const SENSITIVE_CATEGORIES: &[(&str, &str)] = &[
    ("backup", "backup"),
    ("private", "private"),
    ("internal", "internal"),
    ("logs", "logs"),
    ("credentials", "credentials"),
    ("secrets", "secrets"),
];

pub fn s3_issue_severity(issue: &S3Issue) -> f64 {
    match issue {
        S3Issue::ListableBucket { .. } => 9.0,
        S3Issue::OpenBucket { .. } => 8.0,
        S3Issue::WebsiteHostingEnabled { .. } => 6.0,
        S3Issue::HttpBucket { .. } => 5.0,
        S3Issue::SensitiveBucketName { .. } => 4.0,
        S3Issue::CrossAccountBucket { .. } => 3.0,
        S3Issue::DefaultRegionBucket { .. } => 2.0,
        S3Issue::ExistsBucket { .. } => 1.0,
    }
}

pub fn analyze_bucket_name(bucket: &str, domain: &str) -> Vec<S3Issue> {
    if bucket.is_empty() {
        return Vec::new();
    }
    let lower = bucket.to_lowercase();
    let mut issues = Vec::new();

    for &(keyword, category) in SENSITIVE_CATEGORIES {
        if lower.contains(keyword) {
            issues.push(S3Issue::SensitiveBucketName {
                bucket: bucket.to_string(),
                category: category.to_string(),
            });
        }
    }

    let domain_base = domain.split('.').next().unwrap_or(domain).to_lowercase();
    if !domain_base.is_empty() && !lower.contains(&domain_base) {
        issues.push(S3Issue::CrossAccountBucket {
            bucket: bucket.to_string(),
        });
    }

    issues
}

pub fn analyze_bucket_response(bucket: &str, status: u16, body: &str) -> Vec<S3Issue> {
    if bucket.is_empty() {
        return Vec::new();
    }
    let mut issues = Vec::new();

    match status {
        200 => {
            issues.push(S3Issue::OpenBucket {
                bucket: bucket.to_string(),
            });
            if body.contains("<ListBucketResult") {
                issues.push(S3Issue::ListableBucket {
                    bucket: bucket.to_string(),
                });
            }
        }
        403 => {
            issues.push(S3Issue::ExistsBucket {
                bucket: bucket.to_string(),
            });
        }
        301 | 307 => {
            if body.contains("us-east-1") || body.contains("s3.amazonaws.com") {
                issues.push(S3Issue::DefaultRegionBucket {
                    bucket: bucket.to_string(),
                });
            }
            if body.contains(".s3-website") || body.contains("x-amz-website-redirect-location") {
                issues.push(S3Issue::WebsiteHostingEnabled {
                    bucket: bucket.to_string(),
                });
            }
        }
        _ => {}
    }

    if body.contains("http://") && body.contains(".s3.amazonaws.com") {
        issues.push(S3Issue::HttpBucket {
            bucket: bucket.to_string(),
        });
    }

    issues
}

pub fn s3_issues_to_operations(issues: &[S3Issue], seq: &mut u64) -> Vec<OperationLogEntry> {
    let mut entries = Vec::new();
    for issue in issues {
        let severity = s3_issue_severity(issue);
        entries.push(recon_client::finding_entry(
            seq,
            VulnerabilityClass::SecurityMisconfiguration,
            severity,
            0.5,
        ));
    }
    entries
}
