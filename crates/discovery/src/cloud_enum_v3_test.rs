use super::cloud_enum_v3::*;
use std::collections::HashSet;

#[test]
fn bucket_suffixes_has_50_entries() {
    assert_eq!(BUCKET_SUFFIXES.len(), 50);
}

#[test]
fn bucket_suffixes_contains_expected_entries() {
    let expected = [
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
    for s in &expected {
        assert!(BUCKET_SUFFIXES.contains(s), "missing suffix: {s}");
    }
}

#[test]
fn generate_bucket_names_count() {
    let names = generate_bucket_names("acme");
    assert!(
        names.len() >= 51,
        "expected at least 51 names (base + 50 suffixes), got {}",
        names.len()
    );
}

#[test]
fn generate_bucket_names_includes_base_and_suffixed() {
    let names = generate_bucket_names("acme");
    assert!(names.contains(&"acme".to_string()));
    assert!(names.contains(&"acme-backup".to_string()));
    assert!(names.contains(&"acme-prod".to_string()));
    assert!(names.contains(&"acme-terraform".to_string()));
    assert!(names.contains(&"acme-web".to_string()));
}

#[test]
fn generate_bucket_names_sanitises_special_chars() {
    let names = generate_bucket_names("Acme Corp!");
    assert!(names.contains(&"acme-corp".to_string()));
    assert!(names.contains(&"acme-corp-dev".to_string()));
    assert!(names.contains(&"acmecorp".to_string()));
    assert!(names.contains(&"acmecorp-dev".to_string()));
}

#[test]
fn generate_bucket_names_no_duplicates() {
    let names = generate_bucket_names("simple");
    let unique: HashSet<&String> = names.iter().collect();
    assert_eq!(names.len(), unique.len());
}

#[test]
fn generate_bucket_names_sorted() {
    let names = generate_bucket_names("zebra");
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
}

#[test]
fn all_providers_count() {
    assert_eq!(CloudProvider::all().len(), 7);
}

#[test]
fn provider_display_all_variants() {
    assert_eq!(format!("{}", CloudProvider::AwsS3), "AWS S3");
    assert_eq!(
        format!("{}", CloudProvider::AzureBlob),
        "Azure Blob Storage"
    );
    assert_eq!(
        format!("{}", CloudProvider::GcpStorage),
        "GCP Cloud Storage"
    );
    assert_eq!(
        format!("{}", CloudProvider::DigitalOceanSpaces),
        "DigitalOcean Spaces"
    );
    assert_eq!(
        format!("{}", CloudProvider::AlibabaOss),
        "Alibaba Cloud OSS"
    );
    assert_eq!(
        format!("{}", CloudProvider::OracleOci),
        "Oracle Cloud OCI Object Storage"
    );
    assert_eq!(format!("{}", CloudProvider::BackblazeB2), "Backblaze B2");
}

#[test]
fn permission_display_all_variants() {
    assert_eq!(format!("{}", BucketPermission::Public), "public");
    assert_eq!(format!("{}", BucketPermission::Private), "private");
    assert_eq!(
        format!("{}", BucketPermission::Authenticated),
        "authenticated"
    );
    assert_eq!(format!("{}", BucketPermission::NotFound), "not-found");
    assert_eq!(format!("{}", BucketPermission::Forbidden), "forbidden");
    assert_eq!(format!("{}", BucketPermission::Error), "error");
}

#[test]
fn risk_display_all_variants() {
    assert_eq!(format!("{}", BucketRisk::Info), "info");
    assert_eq!(format!("{}", BucketRisk::Low), "low");
    assert_eq!(format!("{}", BucketRisk::Medium), "medium");
    assert_eq!(format!("{}", BucketRisk::High), "high");
    assert_eq!(format!("{}", BucketRisk::Critical), "critical");
}

#[test]
fn risk_scores_monotonic() {
    assert!(BucketRisk::Info.score() < BucketRisk::Low.score());
    assert!(BucketRisk::Low.score() < BucketRisk::Medium.score());
    assert!(BucketRisk::Medium.score() < BucketRisk::High.score());
    assert!(BucketRisk::High.score() < BucketRisk::Critical.score());
}

#[test]
fn build_bucket_urls_s3() {
    let url = build_bucket_urls("acme-backup", CloudProvider::AwsS3);
    assert_eq!(url, "https://acme-backup.s3.amazonaws.com/?list-type=2");
}

#[test]
fn build_bucket_urls_azure() {
    let url = build_bucket_urls("acme-data", CloudProvider::AzureBlob);
    assert!(url.contains("acme-data.blob.core.windows.net"));
    assert!(url.contains("comp=list"));
    assert!(url.contains("restype=container"));
}

#[test]
fn build_bucket_urls_gcp() {
    let url = build_bucket_urls("acme-logs", CloudProvider::GcpStorage);
    assert_eq!(
        url,
        "https://storage.googleapis.com/storage/v1/b/acme-logs/o"
    );
}

#[test]
fn build_bucket_urls_digitalocean() {
    let url = build_bucket_urls("acme-cdn", CloudProvider::DigitalOceanSpaces);
    assert!(url.contains("acme-cdn.nyc3.digitaloceanspaces.com"));
}

#[test]
fn build_bucket_urls_alibaba() {
    let url = build_bucket_urls("acme-ml", CloudProvider::AlibabaOss);
    assert!(url.contains("acme-ml.oss-us-west-1.aliyuncs.com"));
}

#[test]
fn build_bucket_urls_oracle() {
    let url = build_bucket_urls("acme-db", CloudProvider::OracleOci);
    assert!(url.contains("objectstorage"));
    assert!(url.contains("acme-db"));
}

#[test]
fn build_bucket_urls_backblaze() {
    let url = build_bucket_urls("acme-archive", CloudProvider::BackblazeB2);
    assert!(url.contains("backblazeb2.com/file/acme-archive"));
}

#[test]
fn parse_s3_list_response_valid_xml() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>acme-backup</Name>
  <Contents>
    <Key>db-dump-2024-01-01.sql</Key>
    <Size>1048576</Size>
  </Contents>
  <Contents>
    <Key>config/.env</Key>
    <Size>256</Size>
  </Contents>
  <Contents>
    <Key>readme.txt</Key>
    <Size>42</Size>
  </Contents>
</ListBucketResult>"#;

    let keys = parse_s3_list_response(xml);
    assert_eq!(keys.len(), 3);
    assert_eq!(keys[0], "db-dump-2024-01-01.sql");
    assert_eq!(keys[1], "config/.env");
    assert_eq!(keys[2], "readme.txt");
}

#[test]
fn parse_s3_list_response_empty() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>empty-bucket</Name>
</ListBucketResult>"#;
    let keys = parse_s3_list_response(xml);
    assert!(keys.is_empty());
}

#[test]
fn parse_s3_list_response_garbage_input() {
    let keys = parse_s3_list_response("not xml at all <garbage>");
    assert!(keys.is_empty());
}

#[test]
fn parse_azure_list_response_blob_format() {
    let json = r#"{
        "Blobs": {
            "Blob": [
                { "Name": "secrets.json", "Properties": {} },
                { "Name": "deploy/manifest.yaml", "Properties": {} }
            ]
        }
    }"#;
    let names = parse_azure_list_response(json);
    assert_eq!(names.len(), 2);
    assert_eq!(names[0], "secrets.json");
    assert_eq!(names[1], "deploy/manifest.yaml");
}

#[test]
fn parse_azure_list_response_items_fallback() {
    let json = r#"{ "items": [ { "name": "alpha.txt" }, { "name": "beta.bin" } ] }"#;
    let names = parse_azure_list_response(json);
    assert_eq!(names.len(), 2);
    assert_eq!(names[0], "alpha.txt");
    assert_eq!(names[1], "beta.bin");
}

#[test]
fn parse_azure_list_response_invalid_json() {
    let names = parse_azure_list_response("{{invalid json");
    assert!(names.is_empty());
}

#[test]
fn parse_gcp_list_response_valid() {
    let json = r#"{ "kind": "storage#objects", "items": [
        { "name": "training/model.pkl", "bucket": "acme-ml" },
        { "name": "data/features.csv", "bucket": "acme-ml" }
    ] }"#;
    let names = parse_gcp_list_response(json);
    assert_eq!(names.len(), 2);
    assert_eq!(names[0], "training/model.pkl");
}

#[test]
fn parse_gcp_list_response_empty() {
    let json = r#"{ "kind": "storage#objects" }"#;
    let names = parse_gcp_list_response(json);
    assert!(names.is_empty());
}

#[test]
fn classify_bucket_risk_public_with_sensitive() {
    let objects = vec!["readme.md".to_string(), "config/.env".to_string()];
    assert_eq!(
        classify_bucket_risk(BucketPermission::Public, &objects),
        BucketRisk::Critical
    );
}

#[test]
fn classify_bucket_risk_public_with_objects() {
    let objects = vec!["logo.png".to_string(), "style.css".to_string()];
    assert_eq!(
        classify_bucket_risk(BucketPermission::Public, &objects),
        BucketRisk::High
    );
}

#[test]
fn classify_bucket_risk_public_empty() {
    assert_eq!(
        classify_bucket_risk(BucketPermission::Public, &[]),
        BucketRisk::Medium
    );
}

#[test]
fn classify_bucket_risk_authenticated_sensitive() {
    let objects = vec!["id_rsa".to_string()];
    assert_eq!(
        classify_bucket_risk(BucketPermission::Authenticated, &objects),
        BucketRisk::High
    );
}

#[test]
fn classify_bucket_risk_authenticated_normal() {
    let objects = vec!["notes.txt".to_string()];
    assert_eq!(
        classify_bucket_risk(BucketPermission::Authenticated, &objects),
        BucketRisk::Low
    );
}

#[test]
fn classify_bucket_risk_not_found() {
    assert_eq!(
        classify_bucket_risk(BucketPermission::NotFound, &[]),
        BucketRisk::Info
    );
}

#[test]
fn classify_bucket_risk_forbidden() {
    assert_eq!(
        classify_bucket_risk(BucketPermission::Forbidden, &[]),
        BucketRisk::Info
    );
}

#[test]
fn classify_bucket_risk_error() {
    assert_eq!(
        classify_bucket_risk(BucketPermission::Error, &[]),
        BucketRisk::Info
    );
}

#[test]
fn build_finding_populates_all_fields() {
    let f = build_finding(
        CloudProvider::AwsS3,
        "acme-backup",
        BucketPermission::Public,
        vec!["dump.sql".to_string()],
    );
    assert_eq!(f.provider, CloudProvider::AwsS3);
    assert_eq!(f.bucket_name, "acme-backup");
    assert_eq!(f.permission, BucketPermission::Public);
    assert_eq!(f.risk, BucketRisk::Critical);
    assert!(f.url.contains("acme-backup"));
    assert!(f.detail.contains("acme-backup"));
    assert!(f.detail.contains("1 objects"));
    assert_eq!(f.objects_found.len(), 1);
}

#[test]
fn build_cloud_enum_report_aggregates() {
    let findings = vec![
        build_finding(
            CloudProvider::AwsS3,
            "acme-dev",
            BucketPermission::Public,
            vec!["a.txt".to_string()],
        ),
        build_finding(
            CloudProvider::AwsS3,
            "acme-staging",
            BucketPermission::Public,
            vec![],
        ),
        build_finding(
            CloudProvider::GcpStorage,
            "acme-logs",
            BucketPermission::Public,
            vec!["credentials.json".to_string()],
        ),
    ];

    let report = build_cloud_enum_report("acme", 350, findings);
    assert_eq!(report.company, "acme");
    assert_eq!(report.total_checked, 350);
    assert_eq!(report.total_found, 3);
    assert_eq!(report.findings.len(), 3);
    assert_eq!(*report.provider_summary.get("AWS S3").unwrap(), 2);
    assert_eq!(
        *report.provider_summary.get("GCP Cloud Storage").unwrap(),
        1
    );
    assert!(report.risk_summary.contains_key("high"));
    assert!(report.risk_summary.contains_key("critical"));
}

#[test]
fn permission_from_status_basic() {
    assert_eq!(BucketPermission::from_status(200), BucketPermission::Public);
    assert_eq!(
        BucketPermission::from_status(403),
        BucketPermission::Forbidden
    );
    assert_eq!(
        BucketPermission::from_status(401),
        BucketPermission::Authenticated
    );
    assert_eq!(
        BucketPermission::from_status(404),
        BucketPermission::NotFound
    );
    assert_eq!(BucketPermission::from_status(500), BucketPermission::Error);
}

#[test]
fn permission_from_status_and_body_s3_error_in_200() {
    let body = "<Error><Code>AccessDenied</Code></Error>";
    let perm = permission_from_status_and_body(200, body, CloudProvider::AwsS3);
    assert_eq!(perm, BucketPermission::Forbidden);
}

#[test]
fn permission_from_status_and_body_s3_list_result() {
    let body = "<ListBucketResult><Name>test</Name></ListBucketResult>";
    let perm = permission_from_status_and_body(200, body, CloudProvider::AwsS3);
    assert_eq!(perm, BucketPermission::Public);
}

#[test]
fn permission_from_status_and_body_azure_auth_failed() {
    let body = r#"{"error":"AuthenticationFailed"}"#;
    let perm = permission_from_status_and_body(200, body, CloudProvider::AzureBlob);
    assert_eq!(perm, BucketPermission::Authenticated);
}

#[test]
fn permission_from_status_and_body_gcp_401() {
    let perm = permission_from_status_and_body(401, "", CloudProvider::GcpStorage);
    assert_eq!(perm, BucketPermission::Authenticated);
}

#[test]
fn enumerate_all_urls_covers_all_providers() {
    let urls = enumerate_all_urls("tiny");
    let providers: HashSet<CloudProvider> = urls.iter().map(|(p, _, _)| *p).collect();
    assert_eq!(providers.len(), 7);
}

#[test]
fn enumerate_all_urls_total_count() {
    let names = generate_bucket_names("tiny");
    let urls = enumerate_all_urls("tiny");
    assert_eq!(urls.len(), names.len() * 7);
}

#[test]
fn sensitive_patterns_detect_env_file() {
    let objects = vec!["app/.env.production".to_string()];
    assert_eq!(
        classify_bucket_risk(BucketPermission::Public, &objects),
        BucketRisk::Critical
    );
}

#[test]
fn sensitive_patterns_detect_terraform_state() {
    let objects = vec!["infra/terraform.tfstate".to_string()];
    assert_eq!(
        classify_bucket_risk(BucketPermission::Public, &objects),
        BucketRisk::Critical
    );
}

#[test]
fn sensitive_patterns_detect_ssh_key() {
    let objects = vec![".ssh/id_ed25519".to_string()];
    assert_eq!(
        classify_bucket_risk(BucketPermission::Public, &objects),
        BucketRisk::Critical
    );
}

#[test]
fn report_risk_summary_counts_correctly() {
    let findings = vec![
        build_finding(
            CloudProvider::AwsS3,
            "a",
            BucketPermission::Public,
            vec![".env".to_string()],
        ),
        build_finding(
            CloudProvider::AwsS3,
            "b",
            BucketPermission::Public,
            vec![".env".to_string()],
        ),
        build_finding(
            CloudProvider::AwsS3,
            "c",
            BucketPermission::Forbidden,
            vec![],
        ),
    ];
    let report = build_cloud_enum_report("test", 100, findings);
    assert_eq!(*report.risk_summary.get("critical").unwrap(), 2);
    assert_eq!(*report.risk_summary.get("info").unwrap(), 1);
}

#[test]
fn empty_report() {
    let report = build_cloud_enum_report("ghost", 500, vec![]);
    assert_eq!(report.total_found, 0);
    assert!(report.findings.is_empty());
    assert!(report.provider_summary.is_empty());
    assert!(report.risk_summary.is_empty());
}
