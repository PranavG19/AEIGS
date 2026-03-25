use crate::cloud_storage_scanner::{
    build_bucket_probe, candidates_for_domain, finding_from_candidate, generate_bucket_names,
    is_dangerous_s3_statement, severity_for_permissions, BucketCandidate, BucketPermission,
    BucketSeverity, CloudStorageProvider, CloudStorageScanner, BUCKET_NAME_SUFFIXES,
    S3_DANGEROUS_ACTIONS, S3_PUBLIC_PRINCIPALS,
};

#[test]
fn all_providers_listed() {
    let all = CloudStorageProvider::all();
    assert_eq!(all.len(), 4);
    assert!(all.contains(&CloudStorageProvider::AwsS3));
    assert!(all.contains(&CloudStorageProvider::AzureBlob));
    assert!(all.contains(&CloudStorageProvider::GcpStorage));
    assert!(all.contains(&CloudStorageProvider::DigitalOceanSpaces));
}

#[test]
fn provider_display_names() {
    assert_eq!(format!("{}", CloudStorageProvider::AwsS3), "AWS S3");
    assert_eq!(
        format!("{}", CloudStorageProvider::AzureBlob),
        "Azure Blob Storage"
    );
    assert_eq!(
        format!("{}", CloudStorageProvider::GcpStorage),
        "GCP Cloud Storage"
    );
    assert_eq!(
        format!("{}", CloudStorageProvider::DigitalOceanSpaces),
        "DigitalOcean Spaces"
    );
}

#[test]
fn permission_display() {
    assert_eq!(format!("{}", BucketPermission::Read), "Read");
    assert_eq!(format!("{}", BucketPermission::Write), "Write");
    assert_eq!(format!("{}", BucketPermission::List), "List");
}

#[test]
fn permission_all() {
    let all = BucketPermission::all();
    assert_eq!(all.len(), 3);
}

#[test]
fn bucket_url_s3() {
    let url = CloudStorageProvider::AwsS3.bucket_url("mybucket");
    assert_eq!(url, "https://mybucket.s3.amazonaws.com/");
}

#[test]
fn bucket_url_azure() {
    let url = CloudStorageProvider::AzureBlob.bucket_url("myaccount");
    assert!(url.contains("myaccount.blob.core.windows.net"));
}

#[test]
fn bucket_url_gcp() {
    let url = CloudStorageProvider::GcpStorage.bucket_url("mybucket");
    assert_eq!(url, "https://storage.googleapis.com/mybucket/");
}

#[test]
fn bucket_url_digitalocean() {
    let url = CloudStorageProvider::DigitalOceanSpaces.bucket_url("mybucket");
    assert!(url.contains("mybucket.nyc3.digitaloceanspaces.com"));
}

#[test]
fn permission_test_url_s3_read() {
    let url = CloudStorageProvider::AwsS3.permission_test_url("testbucket", BucketPermission::Read);
    assert!(url.contains("testbucket.s3.amazonaws.com"));
}

#[test]
fn permission_test_url_s3_write() {
    let url =
        CloudStorageProvider::AwsS3.permission_test_url("testbucket", BucketPermission::Write);
    assert!(url.contains("__test_write__"));
}

#[test]
fn permission_test_url_s3_list() {
    let url = CloudStorageProvider::AwsS3.permission_test_url("testbucket", BucketPermission::List);
    assert!(url.contains("list-type=2"));
}

#[test]
fn permission_test_url_azure_list() {
    let url = CloudStorageProvider::AzureBlob.permission_test_url("acct", BucketPermission::List);
    assert!(url.contains("comp=list"));
    assert!(url.contains("restype=container"));
}

#[test]
fn permission_test_url_gcp_write() {
    let url =
        CloudStorageProvider::GcpStorage.permission_test_url("bucket1", BucketPermission::Write);
    assert!(url.contains("uploadType=media"));
}

#[test]
fn permission_test_url_gcp_list() {
    let url =
        CloudStorageProvider::GcpStorage.permission_test_url("bucket1", BucketPermission::List);
    assert!(url.contains("/storage/v1/b/bucket1/o"));
}

#[test]
fn generate_bucket_names_basic() {
    let names = generate_bucket_names("example.com");
    assert!(names.contains(&"example".to_string()));
    assert!(names.contains(&"example-com".to_string()));
    assert!(names.contains(&"example.com".to_string()));
    assert!(names.contains(&"examplecom".to_string()));
}

#[test]
fn generate_bucket_names_with_suffixes() {
    let names = generate_bucket_names("target.com");
    assert!(names.contains(&"target-backup".to_string()));
    assert!(names.contains(&"target-dev".to_string()));
    assert!(names.contains(&"target-staging".to_string()));
    assert!(names.contains(&"target-prod".to_string()));
    assert!(names.contains(&"target-assets".to_string()));
    assert!(names.contains(&"target-uploads".to_string()));
}

#[test]
fn generate_bucket_names_strips_protocol() {
    let names = generate_bucket_names("https://example.com/");
    assert!(names.contains(&"example".to_string()));
    assert!(names.contains(&"example-com".to_string()));
}

#[test]
fn generate_bucket_names_no_duplicates() {
    let names = generate_bucket_names("test.io");
    let count = names.len();
    let mut deduped = names.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(count, deduped.len());
}

#[test]
fn bucket_name_suffixes_non_empty() {
    assert!(BUCKET_NAME_SUFFIXES.len() >= 30);
    assert!(BUCKET_NAME_SUFFIXES.contains(&"-backup"));
    assert!(BUCKET_NAME_SUFFIXES.contains(&"-dev"));
    assert!(BUCKET_NAME_SUFFIXES.contains(&"-prod"));
    assert!(BUCKET_NAME_SUFFIXES.contains(&"-staging"));
}

#[test]
fn severity_write_is_critical() {
    let sev = severity_for_permissions(&[BucketPermission::Write]);
    assert_eq!(sev, BucketSeverity::Critical);
}

#[test]
fn severity_write_and_list_is_critical() {
    let sev = severity_for_permissions(&[BucketPermission::Write, BucketPermission::List]);
    assert_eq!(sev, BucketSeverity::Critical);
}

#[test]
fn severity_list_and_read_is_high() {
    let sev = severity_for_permissions(&[BucketPermission::List, BucketPermission::Read]);
    assert_eq!(sev, BucketSeverity::High);
}

#[test]
fn severity_list_only_is_high() {
    let sev = severity_for_permissions(&[BucketPermission::List]);
    assert_eq!(sev, BucketSeverity::High);
}

#[test]
fn severity_read_only_is_medium() {
    let sev = severity_for_permissions(&[BucketPermission::Read]);
    assert_eq!(sev, BucketSeverity::Medium);
}

#[test]
fn severity_none_is_informational() {
    let sev = severity_for_permissions(&[]);
    assert_eq!(sev, BucketSeverity::Informational);
}

#[test]
fn severity_scores_ordered() {
    assert!(BucketSeverity::Informational.score() < BucketSeverity::Low.score());
    assert!(BucketSeverity::Low.score() < BucketSeverity::Medium.score());
    assert!(BucketSeverity::Medium.score() < BucketSeverity::High.score());
    assert!(BucketSeverity::High.score() < BucketSeverity::Critical.score());
}

#[test]
fn candidates_for_domain_covers_all_providers() {
    let candidates = candidates_for_domain("test.com");
    let providers: std::collections::HashSet<CloudStorageProvider> =
        candidates.iter().map(|c| c.provider).collect();
    assert_eq!(providers.len(), 4);
}

#[test]
fn candidates_for_domain_non_empty() {
    let candidates = candidates_for_domain("example.org");
    assert!(!candidates.is_empty());
    assert!(candidates.len() > 100);
}

#[test]
fn finding_from_candidate_basic() {
    let candidate = BucketCandidate {
        provider: CloudStorageProvider::AwsS3,
        bucket_name: "test-backup".into(),
        base_url: "https://test-backup.s3.amazonaws.com/".into(),
    };
    let finding = finding_from_candidate(
        &candidate,
        vec![BucketPermission::Read, BucketPermission::List],
    );
    assert_eq!(finding.provider, CloudStorageProvider::AwsS3);
    assert_eq!(finding.bucket_name, "test-backup");
    assert_eq!(finding.severity, BucketSeverity::High);
    assert!(finding.detail.contains("AWS S3"));
    assert!(finding.detail.contains("test-backup"));
    assert_eq!(finding.test_urls.len(), 2);
}

#[test]
fn finding_from_candidate_write_is_critical() {
    let candidate = BucketCandidate {
        provider: CloudStorageProvider::GcpStorage,
        bucket_name: "leak-bucket".into(),
        base_url: "https://storage.googleapis.com/leak-bucket/".into(),
    };
    let finding = finding_from_candidate(&candidate, vec![BucketPermission::Write]);
    assert_eq!(finding.severity, BucketSeverity::Critical);
}

#[test]
fn build_bucket_probe_creates_three_checks() {
    let candidate = BucketCandidate {
        provider: CloudStorageProvider::AwsS3,
        bucket_name: "mybucket".into(),
        base_url: "https://mybucket.s3.amazonaws.com/".into(),
    };
    let probe = build_bucket_probe(&candidate);
    assert_eq!(probe.check_urls.len(), 3);
    let perms: Vec<BucketPermission> = probe.check_urls.iter().map(|(p, _)| *p).collect();
    assert!(perms.contains(&BucketPermission::Read));
    assert!(perms.contains(&BucketPermission::Write));
    assert!(perms.contains(&BucketPermission::List));
}

#[test]
fn s3_dangerous_actions_non_empty() {
    assert!(S3_DANGEROUS_ACTIONS.len() >= 5);
    assert!(S3_DANGEROUS_ACTIONS.contains(&"s3:*"));
    assert!(S3_DANGEROUS_ACTIONS.contains(&"s3:GetObject"));
    assert!(S3_DANGEROUS_ACTIONS.contains(&"s3:PutObject"));
}

#[test]
fn s3_public_principals_contains_star() {
    assert!(S3_PUBLIC_PRINCIPALS.contains(&"*"));
}

#[test]
fn dangerous_s3_statement_star_principal_star_action() {
    assert!(is_dangerous_s3_statement("*", &["s3:*"]));
}

#[test]
fn dangerous_s3_statement_specific_action() {
    assert!(is_dangerous_s3_statement("*", &["s3:GetObject"]));
}

#[test]
fn not_dangerous_s3_statement_private_principal() {
    assert!(!is_dangerous_s3_statement(
        "arn:aws:iam::123456789012:root",
        &["s3:GetObject"]
    ));
}

#[test]
fn not_dangerous_s3_statement_safe_action() {
    assert!(!is_dangerous_s3_statement("*", &["s3:GetBucketLocation"]));
}

#[test]
fn scanner_new_default_all_providers() {
    let scanner = CloudStorageScanner::new("example.com");
    assert_eq!(scanner.domain, "example.com");
    assert_eq!(scanner.providers.len(), 4);
}

#[test]
fn scanner_with_providers() {
    let scanner =
        CloudStorageScanner::new("example.com").with_providers(vec![CloudStorageProvider::AwsS3]);
    assert_eq!(scanner.providers.len(), 1);
}

#[test]
fn scanner_candidates_filtered_by_provider() {
    let scanner =
        CloudStorageScanner::new("example.com").with_providers(vec![CloudStorageProvider::AwsS3]);
    let candidates = scanner.candidates();
    assert!(candidates
        .iter()
        .all(|c| c.provider == CloudStorageProvider::AwsS3));
}

#[test]
fn scanner_probes_match_candidate_count() {
    let scanner =
        CloudStorageScanner::new("t.io").with_providers(vec![CloudStorageProvider::GcpStorage]);
    let candidates = scanner.candidates();
    let probes = scanner.probes();
    assert_eq!(candidates.len(), probes.len());
}

#[test]
fn finding_detail_mentions_permissions() {
    let candidate = BucketCandidate {
        provider: CloudStorageProvider::AzureBlob,
        bucket_name: "acme-backup".into(),
        base_url: "https://acme-backup.blob.core.windows.net/".into(),
    };
    let finding = finding_from_candidate(
        &candidate,
        vec![BucketPermission::Read, BucketPermission::Write],
    );
    assert!(finding.detail.contains("Read"));
    assert!(finding.detail.contains("Write"));
}

#[test]
fn bucket_names_include_hyphenated_domain() {
    let names = generate_bucket_names("mega.corp.io");
    assert!(names.contains(&"mega-corp".to_string()));
}
