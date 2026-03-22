use crate::s3_scanner::*;

#[test]
fn generate_candidates_from_simple_domain() {
    let candidates = generate_bucket_candidates("example.com");
    assert!(candidates.contains(&"example".to_string()));
    assert!(candidates.contains(&"example-backup".to_string()));
    assert!(candidates.contains(&"example-dev".to_string()));
    assert!(candidates.contains(&"example-com".to_string()));
    assert!(candidates.contains(&"example-com-backup".to_string()));
}

#[test]
fn generate_candidates_deduplicates() {
    let candidates = generate_bucket_candidates("example.com");
    let unique: std::collections::HashSet<_> = candidates.iter().collect();
    assert_eq!(candidates.len(), unique.len());
}

#[test]
fn generate_candidates_lowercases() {
    let candidates = generate_bucket_candidates("EXAMPLE.COM");
    assert!(candidates.contains(&"example".to_string()));
    assert!(candidates.contains(&"example-com".to_string()));
}

#[test]
fn generate_candidates_empty_domain() {
    let candidates = generate_bucket_candidates("");
    assert!(candidates.is_empty());
}

#[test]
fn generate_candidates_subdomain() {
    let candidates = generate_bucket_candidates("api.example.com");
    assert!(candidates.contains(&"api".to_string()));
    assert!(candidates.contains(&"api-backup".to_string()));
    assert!(candidates.contains(&"api-example-com".to_string()));
}

#[test]
fn s3_findings_to_operations_open_bucket() {
    let findings = vec![S3Finding {
        bucket: "test-open".to_string(),
        status: BucketStatus::Open,
    }];
    let mut seq = 0;
    let ops = s3_findings_to_operations(&findings, &mut seq);
    // Open bucket: AddNode + AddFinding
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode {
            node_type,
            properties,
        } => {
            assert_eq!(*node_type, aegis_protocol::node::NodeType::Service);
            let status = properties.iter().find(|(k, _)| k == "status").unwrap();
            assert_eq!(status.1, "open");
        }
        _ => panic!("expected AddNode"),
    }
    match &ops[1].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 8.0).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn s3_findings_to_operations_exists_bucket() {
    let findings = vec![S3Finding {
        bucket: "test-exists".to_string(),
        status: BucketStatus::Exists,
    }];
    let mut seq = 0;
    let ops = s3_findings_to_operations(&findings, &mut seq);
    // Exists bucket: AddNode only (no finding)
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn s3_findings_to_operations_empty() {
    let mut seq = 5;
    let ops = s3_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn s3_findings_to_operations_mixed() {
    let findings = vec![
        S3Finding {
            bucket: "open-one".to_string(),
            status: BucketStatus::Open,
        },
        S3Finding {
            bucket: "exists-one".to_string(),
            status: BucketStatus::Exists,
        },
        S3Finding {
            bucket: "open-two".to_string(),
            status: BucketStatus::Open,
        },
    ];
    let mut seq = 0;
    let ops = s3_findings_to_operations(&findings, &mut seq);
    // 2 open (2 ops each) + 1 exists (1 op) = 5
    assert_eq!(ops.len(), 5);
    assert_eq!(seq, 5);
}

#[test]
fn scan_s3_buckets_skips_localhost() {
    let findings = scan_s3_buckets("http://localhost:8080");
    assert!(findings.is_empty());
}

#[test]
fn scan_s3_buckets_skips_loopback() {
    let findings = scan_s3_buckets("http://127.0.0.1:3000");
    assert!(findings.is_empty());
}

#[test]
fn generate_candidates_count() {
    let candidates = generate_bucket_candidates("example.com");
    assert!(
        candidates.len() >= 60,
        "expected many candidates, got {}",
        candidates.len()
    );
    assert!(
        candidates.len() <= 80,
        "too many candidates: {}",
        candidates.len()
    );
}
