use crate::s3_scanner::*;

// ── Existing tests (12) ──────────────────────────────────────────────

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

// ── S3Issue Display tests ────────────────────────────────────────────

#[test]
fn display_open_bucket() {
    let issue = S3Issue::OpenBucket {
        bucket: "my-bucket".to_string(),
    };
    assert_eq!(format!("{issue}"), "Open S3 bucket: my-bucket");
}

#[test]
fn display_exists_bucket() {
    let issue = S3Issue::ExistsBucket {
        bucket: "locked-bucket".to_string(),
    };
    assert_eq!(
        format!("{issue}"),
        "S3 bucket exists (access denied): locked-bucket"
    );
}

#[test]
fn display_listable_bucket() {
    let issue = S3Issue::ListableBucket {
        bucket: "list-me".to_string(),
    };
    assert_eq!(format!("{issue}"), "Listable S3 bucket: list-me");
}

#[test]
fn display_sensitive_bucket_name() {
    let issue = S3Issue::SensitiveBucketName {
        bucket: "corp-backup".to_string(),
        category: "backup".to_string(),
    };
    assert_eq!(
        format!("{issue}"),
        "Sensitive bucket name (backup): corp-backup"
    );
}

#[test]
fn display_default_region_bucket() {
    let issue = S3Issue::DefaultRegionBucket {
        bucket: "east-bucket".to_string(),
    };
    assert_eq!(
        format!("{issue}"),
        "Default region (us-east-1) bucket: east-bucket"
    );
}

#[test]
fn display_http_bucket() {
    let issue = S3Issue::HttpBucket {
        bucket: "insecure".to_string(),
    };
    assert_eq!(format!("{issue}"), "HTTP-accessible bucket: insecure");
}

#[test]
fn display_website_hosting_enabled() {
    let issue = S3Issue::WebsiteHostingEnabled {
        bucket: "website".to_string(),
    };
    assert_eq!(format!("{issue}"), "Website hosting enabled: website");
}

#[test]
fn display_cross_account_bucket() {
    let issue = S3Issue::CrossAccountBucket {
        bucket: "foreign".to_string(),
    };
    assert_eq!(format!("{issue}"), "Cross-account bucket: foreign");
}

// ── s3_issue_severity tests ──────────────────────────────────────────

#[test]
fn severity_listable_is_highest() {
    let sev = s3_issue_severity(&S3Issue::ListableBucket {
        bucket: "x".to_string(),
    });
    assert!((sev - 9.0).abs() < 1e-9);
}

#[test]
fn severity_open_bucket() {
    let sev = s3_issue_severity(&S3Issue::OpenBucket {
        bucket: "x".to_string(),
    });
    assert!((sev - 8.0).abs() < 1e-9);
}

#[test]
fn severity_website_hosting() {
    let sev = s3_issue_severity(&S3Issue::WebsiteHostingEnabled {
        bucket: "x".to_string(),
    });
    assert!((sev - 6.0).abs() < 1e-9);
}

#[test]
fn severity_http_bucket() {
    let sev = s3_issue_severity(&S3Issue::HttpBucket {
        bucket: "x".to_string(),
    });
    assert!((sev - 5.0).abs() < 1e-9);
}

#[test]
fn severity_sensitive_name() {
    let sev = s3_issue_severity(&S3Issue::SensitiveBucketName {
        bucket: "x".to_string(),
        category: "backup".to_string(),
    });
    assert!((sev - 4.0).abs() < 1e-9);
}

#[test]
fn severity_cross_account() {
    let sev = s3_issue_severity(&S3Issue::CrossAccountBucket {
        bucket: "x".to_string(),
    });
    assert!((sev - 3.0).abs() < 1e-9);
}

#[test]
fn severity_default_region() {
    let sev = s3_issue_severity(&S3Issue::DefaultRegionBucket {
        bucket: "x".to_string(),
    });
    assert!((sev - 2.0).abs() < 1e-9);
}

#[test]
fn severity_exists_bucket_is_lowest() {
    let sev = s3_issue_severity(&S3Issue::ExistsBucket {
        bucket: "x".to_string(),
    });
    assert!((sev - 1.0).abs() < 1e-9);
}

#[test]
fn severity_ordering_listable_gt_open() {
    let listable = s3_issue_severity(&S3Issue::ListableBucket {
        bucket: "a".to_string(),
    });
    let open = s3_issue_severity(&S3Issue::OpenBucket {
        bucket: "a".to_string(),
    });
    assert!(listable > open);
}

#[test]
fn severity_ordering_open_gt_exists() {
    let open = s3_issue_severity(&S3Issue::OpenBucket {
        bucket: "a".to_string(),
    });
    let exists = s3_issue_severity(&S3Issue::ExistsBucket {
        bucket: "a".to_string(),
    });
    assert!(open > exists);
}

#[test]
fn severity_ordering_full_descending() {
    let all_severities: Vec<f64> = vec![
        s3_issue_severity(&S3Issue::ListableBucket {
            bucket: "a".to_string(),
        }),
        s3_issue_severity(&S3Issue::OpenBucket {
            bucket: "a".to_string(),
        }),
        s3_issue_severity(&S3Issue::WebsiteHostingEnabled {
            bucket: "a".to_string(),
        }),
        s3_issue_severity(&S3Issue::HttpBucket {
            bucket: "a".to_string(),
        }),
        s3_issue_severity(&S3Issue::SensitiveBucketName {
            bucket: "a".to_string(),
            category: "backup".to_string(),
        }),
        s3_issue_severity(&S3Issue::CrossAccountBucket {
            bucket: "a".to_string(),
        }),
        s3_issue_severity(&S3Issue::DefaultRegionBucket {
            bucket: "a".to_string(),
        }),
        s3_issue_severity(&S3Issue::ExistsBucket {
            bucket: "a".to_string(),
        }),
    ];
    for pair in all_severities.windows(2) {
        assert!(pair[0] > pair[1], "{} should be > {}", pair[0], pair[1]);
    }
}

// ── analyze_bucket_name tests ────────────────────────────────────────

#[test]
fn analyze_name_detects_backup() {
    let issues = analyze_bucket_name("corp-backup-2024", "corp.com");
    let cats: Vec<&str> = issues
        .iter()
        .filter_map(|i| match i {
            S3Issue::SensitiveBucketName { category, .. } => Some(category.as_str()),
            _ => None,
        })
        .collect();
    assert!(cats.contains(&"backup"));
}

#[test]
fn analyze_name_detects_private() {
    let issues = analyze_bucket_name("acme-private-data", "acme.com");
    let cats: Vec<&str> = issues
        .iter()
        .filter_map(|i| match i {
            S3Issue::SensitiveBucketName { category, .. } => Some(category.as_str()),
            _ => None,
        })
        .collect();
    assert!(cats.contains(&"private"));
}

#[test]
fn analyze_name_detects_internal() {
    let issues = analyze_bucket_name("internal-tools", "tools.io");
    let cats: Vec<&str> = issues
        .iter()
        .filter_map(|i| match i {
            S3Issue::SensitiveBucketName { category, .. } => Some(category.as_str()),
            _ => None,
        })
        .collect();
    assert!(cats.contains(&"internal"));
}

#[test]
fn analyze_name_detects_logs() {
    let issues = analyze_bucket_name("app-logs-prod", "app.com");
    let cats: Vec<&str> = issues
        .iter()
        .filter_map(|i| match i {
            S3Issue::SensitiveBucketName { category, .. } => Some(category.as_str()),
            _ => None,
        })
        .collect();
    assert!(cats.contains(&"logs"));
}

#[test]
fn analyze_name_detects_credentials() {
    let issues = analyze_bucket_name("credentials-store", "store.com");
    let cats: Vec<&str> = issues
        .iter()
        .filter_map(|i| match i {
            S3Issue::SensitiveBucketName { category, .. } => Some(category.as_str()),
            _ => None,
        })
        .collect();
    assert!(cats.contains(&"credentials"));
}

#[test]
fn analyze_name_detects_secrets() {
    let issues = analyze_bucket_name("my-secrets-bucket", "my.com");
    let cats: Vec<&str> = issues
        .iter()
        .filter_map(|i| match i {
            S3Issue::SensitiveBucketName { category, .. } => Some(category.as_str()),
            _ => None,
        })
        .collect();
    assert!(cats.contains(&"secrets"));
}

#[test]
fn analyze_name_normal_name_no_sensitive() {
    let issues = analyze_bucket_name("example-assets", "example.com");
    let sensitive_count = issues
        .iter()
        .filter(|i| matches!(i, S3Issue::SensitiveBucketName { .. }))
        .count();
    assert_eq!(sensitive_count, 0);
}

#[test]
fn analyze_name_cross_account_detected() {
    let issues = analyze_bucket_name("totally-different-name", "mycompany.com");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, S3Issue::CrossAccountBucket { .. }))
    );
}

#[test]
fn analyze_name_same_domain_no_cross_account() {
    let issues = analyze_bucket_name("mycompany-assets", "mycompany.com");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, S3Issue::CrossAccountBucket { .. }))
    );
}

#[test]
fn analyze_name_empty_bucket() {
    let issues = analyze_bucket_name("", "example.com");
    assert!(issues.is_empty());
}

#[test]
fn analyze_name_case_insensitive_sensitive() {
    let issues = analyze_bucket_name("CORP-BACKUP", "corp.com");
    let cats: Vec<&str> = issues
        .iter()
        .filter_map(|i| match i {
            S3Issue::SensitiveBucketName { category, .. } => Some(category.as_str()),
            _ => None,
        })
        .collect();
    assert!(cats.contains(&"backup"));
}

#[test]
fn analyze_name_multiple_sensitive_matches() {
    let issues = analyze_bucket_name("private-backup-logs", "private.com");
    let sensitive_count = issues
        .iter()
        .filter(|i| matches!(i, S3Issue::SensitiveBucketName { .. }))
        .count();
    assert!(
        sensitive_count >= 3,
        "expected >=3 sensitive matches, got {sensitive_count}"
    );
}

#[test]
fn analyze_name_special_characters() {
    let issues = analyze_bucket_name("my--bucket..name", "bucket.com");
    // Should not panic; bucket contains "bucket" which matches domain base
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, S3Issue::CrossAccountBucket { .. }))
    );
}

#[test]
fn analyze_name_very_long_name() {
    let long_name = "a".repeat(256);
    let issues = analyze_bucket_name(&long_name, "a.com");
    // Should not panic and should not flag as cross-account (contains "a")
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, S3Issue::CrossAccountBucket { .. }))
    );
}

// ── analyze_bucket_response tests ────────────────────────────────────

#[test]
fn response_200_produces_open_bucket() {
    let issues = analyze_bucket_response("test-bucket", 200, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, S3Issue::OpenBucket { .. }))
    );
}

#[test]
fn response_200_with_listable_xml() {
    let body = r#"<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>test</Name></ListBucketResult>"#;
    let issues = analyze_bucket_response("test-bucket", 200, body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, S3Issue::OpenBucket { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, S3Issue::ListableBucket { .. }))
    );
}

#[test]
fn response_403_produces_exists_bucket() {
    let issues = analyze_bucket_response(
        "test-bucket",
        403,
        "<Error><Code>AccessDenied</Code></Error>",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, S3Issue::ExistsBucket { .. }))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, S3Issue::OpenBucket { .. }))
    );
}

#[test]
fn response_404_produces_nothing() {
    let issues = analyze_bucket_response("test-bucket", 404, "NoSuchBucket");
    assert!(issues.is_empty());
}

#[test]
fn response_301_default_region() {
    let body = "Redirect to us-east-1";
    let issues = analyze_bucket_response("test-bucket", 301, body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, S3Issue::DefaultRegionBucket { .. }))
    );
}

#[test]
fn response_307_with_website_hosting() {
    let body = "Location: test-bucket.s3-website-us-east-1.amazonaws.com";
    let issues = analyze_bucket_response("test-bucket", 307, body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, S3Issue::WebsiteHostingEnabled { .. }))
    );
}

#[test]
fn response_301_with_s3_redirect() {
    let body = "Please re-send to s3.amazonaws.com";
    let issues = analyze_bucket_response("test-bucket", 301, body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, S3Issue::DefaultRegionBucket { .. }))
    );
}

#[test]
fn response_http_reference_in_body() {
    let body = "Endpoint: http://test-bucket.s3.amazonaws.com/file.txt";
    let issues = analyze_bucket_response("test-bucket", 200, body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, S3Issue::HttpBucket { .. }))
    );
}

#[test]
fn response_empty_bucket_name_returns_nothing() {
    let issues = analyze_bucket_response("", 200, "<ListBucketResult/>");
    assert!(issues.is_empty());
}

#[test]
fn response_200_no_xml_not_listable() {
    let issues = analyze_bucket_response("test-bucket", 200, "just some text");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, S3Issue::OpenBucket { .. }))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, S3Issue::ListableBucket { .. }))
    );
}

#[test]
fn response_website_redirect_header() {
    let body = "x-amz-website-redirect-location: /index.html";
    let issues = analyze_bucket_response("web-bucket", 307, body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, S3Issue::WebsiteHostingEnabled { .. }))
    );
}

// ── s3_issues_to_operations tests ────────────────────────────────────

#[test]
fn issues_to_operations_single_issue() {
    let issues = vec![S3Issue::OpenBucket {
        bucket: "my-bucket".to_string(),
    }];
    let mut seq = 0;
    let ops = s3_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            severity,
            confidence,
            vulnerability_class,
            ..
        } => {
            assert!((severity - 8.0).abs() < 1e-9);
            assert!((confidence.value() - 0.5).abs() < 1e-9);
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn issues_to_operations_empty() {
    let mut seq = 10;
    let ops = s3_issues_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 10);
}

#[test]
fn issues_to_operations_multiple() {
    let issues = vec![
        S3Issue::ListableBucket {
            bucket: "list".to_string(),
        },
        S3Issue::ExistsBucket {
            bucket: "exists".to_string(),
        },
        S3Issue::SensitiveBucketName {
            bucket: "backup-corp".to_string(),
            category: "backup".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = s3_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn issues_to_operations_severity_matches_issue() {
    let issues = vec![
        S3Issue::ListableBucket {
            bucket: "l".to_string(),
        },
        S3Issue::ExistsBucket {
            bucket: "e".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = s3_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 9.0).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
    match &ops[1].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 1.0).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn issues_to_operations_seq_increments_correctly() {
    let issues = vec![
        S3Issue::OpenBucket {
            bucket: "a".to_string(),
        },
        S3Issue::HttpBucket {
            bucket: "b".to_string(),
        },
    ];
    let mut seq = 5;
    let ops = s3_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops[0].sequence_number, 6);
    assert_eq!(ops[1].sequence_number, 7);
    assert_eq!(seq, 7);
}

// ── S3Issue equality / clone tests ───────────────────────────────────

#[test]
fn s3_issue_clone_equality() {
    let issue = S3Issue::SensitiveBucketName {
        bucket: "corp-secrets".to_string(),
        category: "secrets".to_string(),
    };
    let cloned = issue.clone();
    assert_eq!(issue, cloned);
}

#[test]
fn s3_issue_variants_not_equal() {
    let open = S3Issue::OpenBucket {
        bucket: "x".to_string(),
    };
    let exists = S3Issue::ExistsBucket {
        bucket: "x".to_string(),
    };
    assert_ne!(open, exists);
}
