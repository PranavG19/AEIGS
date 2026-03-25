use super::realtime_intel::*;

#[test]
fn default_config_values() {
    let config = RealtimeIntelConfig::default();
    assert!(config.query_ct_logs);
    assert!(config.resolve_dns);
    assert!(config.query_wayback);
    assert!(config.check_cloud_buckets);
    assert_eq!(config.max_subdomains_to_resolve, 500);
    assert_eq!(config.dns_concurrency, 50);
    assert_eq!(config.timeout_secs, 15);
}

#[test]
fn aggregator_creation() {
    let _agg = RealtimeIntelAggregator::new(RealtimeIntelConfig::default());
}

#[test]
fn dns_record_type_display() {
    assert_eq!(DnsRecordType::A.to_string(), "A");
    assert_eq!(DnsRecordType::AAAA.to_string(), "AAAA");
    assert_eq!(DnsRecordType::CNAME.to_string(), "CNAME");
    assert_eq!(DnsRecordType::MX.to_string(), "MX");
    assert_eq!(DnsRecordType::TXT.to_string(), "TXT");
    assert_eq!(DnsRecordType::NS.to_string(), "NS");
}

#[test]
fn cloud_provider_display() {
    assert_eq!(CloudProvider::AwsS3.to_string(), "AWS S3");
    assert_eq!(CloudProvider::AzureBlob.to_string(), "Azure Blob");
    assert_eq!(CloudProvider::GcpStorage.to_string(), "GCP Storage");
}

#[test]
fn extract_unique_subdomains_deduplicates() {
    let ct_results = vec![
        CtDiscoveredSubdomain {
            name: "www.example.com".into(),
            issuer: "Let's Encrypt".into(),
            not_before: "2024-01-01".into(),
            not_after: "2024-04-01".into(),
        },
        CtDiscoveredSubdomain {
            name: "api.example.com".into(),
            issuer: "Let's Encrypt".into(),
            not_before: "2024-01-01".into(),
            not_after: "2024-04-01".into(),
        },
        CtDiscoveredSubdomain {
            name: "www.example.com".into(),
            issuer: "DigiCert".into(),
            not_before: "2024-02-01".into(),
            not_after: "2024-05-01".into(),
        },
    ];
    let unique = extract_unique_subdomains(&ct_results, "example.com");
    assert_eq!(unique.len(), 3);
    assert!(unique.contains(&"example.com".to_string()));
    assert!(unique.contains(&"www.example.com".to_string()));
    assert!(unique.contains(&"api.example.com".to_string()));
}

#[test]
fn extract_unique_subdomains_always_includes_base() {
    let unique = extract_unique_subdomains(&[], "example.com");
    assert_eq!(unique.len(), 1);
    assert_eq!(unique[0], "example.com");
}

#[test]
fn extract_unique_subdomains_sorted() {
    let ct_results = vec![
        CtDiscoveredSubdomain {
            name: "z.example.com".into(), issuer: "".into(),
            not_before: "".into(), not_after: "".into(),
        },
        CtDiscoveredSubdomain {
            name: "a.example.com".into(), issuer: "".into(),
            not_before: "".into(), not_after: "".into(),
        },
    ];
    let unique = extract_unique_subdomains(&ct_results, "example.com");
    assert!(unique.windows(2).all(|w| w[0] <= w[1]));
}

#[test]
fn extract_unique_ips_from_dns_results() {
    let results = vec![
        DnsResolutionResult {
            hostname: "www.example.com".into(),
            record_type: DnsRecordType::A,
            values: vec!["93.184.216.34".into()],
            resolved: true,
        },
        DnsResolutionResult {
            hostname: "api.example.com".into(),
            record_type: DnsRecordType::A,
            values: vec!["93.184.216.34".into(), "93.184.216.35".into()],
            resolved: true,
        },
        DnsResolutionResult {
            hostname: "www.example.com".into(),
            record_type: DnsRecordType::CNAME,
            values: vec!["cdn.example.com".into()],
            resolved: true,
        },
    ];
    let ips = extract_unique_ips(&results);
    assert_eq!(ips.len(), 2);
    assert!(ips.contains(&"93.184.216.34".to_string()));
    assert!(ips.contains(&"93.184.216.35".to_string()));
}

#[test]
fn extract_unique_ips_excludes_cname() {
    let results = vec![DnsResolutionResult {
        hostname: "test.com".into(),
        record_type: DnsRecordType::CNAME,
        values: vec!["other.com".into()],
        resolved: true,
    }];
    let ips = extract_unique_ips(&results);
    assert!(ips.is_empty());
}

#[test]
fn generate_bucket_variations_creates_all_providers() {
    let variations = generate_bucket_variations("acme");
    assert!(!variations.is_empty());

    let providers: std::collections::HashSet<CloudProvider> =
        variations.iter().map(|(_, p, _)| *p).collect();
    assert!(providers.contains(&CloudProvider::AwsS3));
    assert!(providers.contains(&CloudProvider::AzureBlob));
    assert!(providers.contains(&CloudProvider::GcpStorage));
}

#[test]
fn generate_bucket_variations_includes_common_suffixes() {
    let variations = generate_bucket_variations("target");
    let names: Vec<&str> = variations.iter().map(|(n, _, _)| n.as_str()).collect();
    assert!(names.contains(&"target"));
    assert!(names.contains(&"target-backup"));
    assert!(names.contains(&"target-dev"));
    assert!(names.contains(&"target-prod"));
    assert!(names.contains(&"target-staging"));
}

#[test]
fn bucket_url_formats_are_correct() {
    let variations = generate_bucket_variations("test");
    for (name, provider, url) in &variations {
        match provider {
            CloudProvider::AwsS3 => {
                assert!(url.contains("s3.amazonaws.com"), "Bad S3 URL: {url}");
                assert!(url.contains(name));
            }
            CloudProvider::AzureBlob => {
                assert!(url.contains("blob.core.windows.net"), "Bad Azure URL: {url}");
                assert!(url.contains(name));
            }
            CloudProvider::GcpStorage => {
                assert!(url.contains("storage.googleapis.com"), "Bad GCP URL: {url}");
                assert!(url.contains(name));
            }
        }
    }
}

#[test]
fn generate_bucket_variations_count() {
    let variations = generate_bucket_variations("example");
    let suffix_count = 19;
    let provider_count = 3;
    assert_eq!(variations.len(), suffix_count * provider_count);
}

#[test]
fn ct_discovered_subdomain_equality() {
    let a = CtDiscoveredSubdomain {
        name: "sub.example.com".into(),
        issuer: "LE".into(),
        not_before: "2024-01-01".into(),
        not_after: "2024-04-01".into(),
    };
    let b = a.clone();
    assert_eq!(a, b);

    let mut set = std::collections::HashSet::new();
    set.insert(a);
    set.insert(b);
    assert_eq!(set.len(), 1);
}

#[test]
fn wayback_entry_serialization() {
    let entry = WaybackEntry {
        url: "https://example.com/page".into(),
        timestamp: "20240101120000".into(),
        status_code: "200".into(),
        mime_type: "text/html".into(),
        length: Some("1234".into()),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let deserialized: WaybackEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.url, "https://example.com/page");
    assert_eq!(deserialized.timestamp, "20240101120000");
}

#[test]
fn cloud_bucket_result_serialization() {
    let result = CloudBucketResult {
        bucket_name: "acme-backup".into(),
        provider: CloudProvider::AwsS3,
        url: "https://acme-backup.s3.amazonaws.com".into(),
        exists: true,
        public: false,
    };
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: CloudBucketResult = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.bucket_name, "acme-backup");
    assert!(deserialized.exists);
    assert!(!deserialized.public);
}

#[test]
fn intel_summary_default_is_zero() {
    let summary = IntelSummary::default();
    assert_eq!(summary.total_subdomains, 0);
    assert_eq!(summary.total_resolved, 0);
    assert_eq!(summary.total_wayback_urls, 0);
    assert_eq!(summary.total_cloud_buckets_found, 0);
    assert_eq!(summary.total_cloud_buckets_public, 0);
}

#[test]
fn realtime_intel_error_display() {
    assert!(RealtimeIntelError::Network("timeout".into()).to_string().contains("timeout"));
    assert!(RealtimeIntelError::ParseError("bad".into()).to_string().contains("bad"));
    assert_eq!(RealtimeIntelError::RateLimited.to_string(), "Rate limited");
    assert_eq!(RealtimeIntelError::Timeout.to_string(), "Request timed out");
}

#[test]
fn realtime_intelligence_serialization() {
    let intel = RealtimeIntelligence {
        domain: "example.com".into(),
        ct_subdomains: Vec::new(),
        dns_results: Vec::new(),
        wayback_entries: Vec::new(),
        cloud_buckets: Vec::new(),
        unique_subdomains: vec!["example.com".into()],
        unique_ips: Vec::new(),
        summary: IntelSummary::default(),
    };
    let json = serde_json::to_string(&intel).unwrap();
    assert!(json.contains("example.com"));
}

#[test]
fn dns_resolution_result_serialization() {
    let result = DnsResolutionResult {
        hostname: "www.example.com".into(),
        record_type: DnsRecordType::A,
        values: vec!["93.184.216.34".into()],
        resolved: true,
    };
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: DnsResolutionResult = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.hostname, "www.example.com");
    assert!(deserialized.resolved);
}

#[tokio::test]
async fn gather_with_all_disabled_returns_minimal() {
    let config = RealtimeIntelConfig {
        query_ct_logs: false,
        resolve_dns: false,
        query_wayback: false,
        check_cloud_buckets: false,
        timeout_secs: 1,
        ..RealtimeIntelConfig::default()
    };
    let agg = RealtimeIntelAggregator::new(config);
    let result = agg.gather("test.invalid").await;
    assert_eq!(result.domain, "test.invalid");
    assert!(result.ct_subdomains.is_empty());
    assert!(result.dns_results.is_empty());
    assert!(result.wayback_entries.is_empty());
    assert!(result.cloud_buckets.is_empty());
}
