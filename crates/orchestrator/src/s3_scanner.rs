use std::time::Duration;

use aegis_protocol::finding::{Confidence, VulnerabilityClass};
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

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
    let Some(domain) = aegis_exploiter::extract_domain(target) else {
        return Vec::new();
    };
    if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
        return Vec::new();
    }
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
            *seq += 1;
            entries.push(OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: vec![],
                    vulnerability_class: VulnerabilityClass::SecurityMisconfiguration,
                    severity: 8.0,
                    confidence: Confidence::new(0.9).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            });
        }
    }
    entries
}
