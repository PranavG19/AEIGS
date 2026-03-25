use super::*;
use std::net::Ipv4Addr;

#[test]
fn generate_metadata_payloads_all_providers() {
    let payloads = generate_metadata_payloads();
    assert!(
        payloads.len() >= 20,
        "Should generate 20+ metadata payloads, got {}",
        payloads.len()
    );

    let providers: std::collections::HashSet<String> = payloads
        .iter()
        .filter_map(|p| match &p.target {
            SsrfTarget::CloudMetadata(provider) => Some(provider.to_string()),
            _ => None,
        })
        .collect();

    assert!(providers.contains("AWS"));
    assert!(providers.contains("GCP"));
    assert!(providers.contains("Azure"));
    assert!(providers.contains("DigitalOcean"));
    assert!(providers.contains("Alibaba"));
    assert!(providers.contains("Oracle"));
    assert!(providers.contains("Kubernetes"));
}

#[test]
fn aws_metadata_includes_iam_credentials() {
    let payloads = generate_metadata_payloads();
    let aws_payloads: Vec<&SsrfPayload> = payloads
        .iter()
        .filter(|p| matches!(&p.target, SsrfTarget::CloudMetadata(CloudProvider::Aws)))
        .collect();

    assert!(aws_payloads.len() >= 8, "AWS should have 8+ payload paths");

    let has_iam = aws_payloads
        .iter()
        .any(|p| p.url.contains("security-credentials"));
    let has_userdata = aws_payloads.iter().any(|p| p.url.contains("user-data"));
    let has_imdsv2 = aws_payloads.iter().any(|p| p.url.contains("api/token"));

    assert!(has_iam, "Should include IAM credential path");
    assert!(has_userdata, "Should include user-data path");
    assert!(has_imdsv2, "Should include IMDSv2 token path");
}

#[test]
fn gcp_metadata_requires_header() {
    let payloads = generate_metadata_payloads();
    let gcp_payloads: Vec<&SsrfPayload> = payloads
        .iter()
        .filter(|p| matches!(&p.target, SsrfTarget::CloudMetadata(CloudProvider::Gcp)))
        .collect();

    assert!(!gcp_payloads.is_empty());

    for payload in &gcp_payloads {
        let has_metadata_header = payload
            .required_headers
            .iter()
            .any(|(k, v)| k == "Metadata-Flavor" && v == "Google");
        assert!(
            has_metadata_header,
            "GCP payloads must include Metadata-Flavor header"
        );
    }
}

#[test]
fn azure_metadata_requires_header() {
    let payloads = generate_metadata_payloads();
    let azure_payloads: Vec<&SsrfPayload> = payloads
        .iter()
        .filter(|p| matches!(&p.target, SsrfTarget::CloudMetadata(CloudProvider::Azure)))
        .collect();

    assert!(!azure_payloads.is_empty());

    for payload in &azure_payloads {
        let has_metadata_header = payload
            .required_headers
            .iter()
            .any(|(k, v)| k == "Metadata" && v == "true");
        assert!(
            has_metadata_header,
            "Azure payloads must include Metadata: true header"
        );
    }
}

#[test]
fn generate_ip_bypasses_for_metadata_ip() {
    let ip = Ipv4Addr::new(169, 254, 169, 254);
    let bypasses = generate_ip_bypasses(ip);

    assert!(
        bypasses.len() >= 8,
        "Should generate 8+ IP representations, got {}",
        bypasses.len()
    );

    assert!(
        bypasses.contains(&"169.254.169.254".to_string()),
        "Should contain standard IP"
    );

    let has_decimal = bypasses.iter().any(|b| b.parse::<u32>().is_ok());
    assert!(has_decimal, "Should contain decimal representation");

    let has_hex = bypasses.iter().any(|b| b.starts_with("0x"));
    assert!(has_hex, "Should contain hex representation");

    let has_octal = bypasses
        .iter()
        .any(|b| b.starts_with('0') && b.contains('.') && b != "169.254.169.254");
    assert!(has_octal, "Should contain octal representation");

    let has_ipv6 = bypasses.iter().any(|b| b.contains("::"));
    assert!(has_ipv6, "Should contain IPv6-mapped representation");
}

#[test]
fn generate_ip_bypasses_for_localhost() {
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    let bypasses = generate_ip_bypasses(ip);

    assert!(bypasses.contains(&"127.0.0.1".to_string()));
    assert!(bypasses.len() >= 8);
}

#[test]
fn generate_scheme_payloads_variety() {
    let payloads = generate_scheme_payloads("169.254.169.254", "/latest/meta-data/");

    assert!(payloads.len() >= 4);

    let schemes: Vec<String> = payloads
        .iter()
        .map(|p| p.url.split("://").next().unwrap_or("").to_string())
        .collect();

    assert!(schemes.contains(&"http".to_string()));
    assert!(schemes.contains(&"https".to_string()));
    assert!(schemes.contains(&"gopher".to_string()));
    assert!(schemes.contains(&"file".to_string()));
}

#[test]
fn extract_aws_credentials_valid() {
    let response = r#"{
        "Code": "Success",
        "LastUpdated": "2024-01-01T00:00:00Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token": "IQoJb3JpZ2luX2VjEBYaCXVzLWVhc3QtMSJHMEUCIQDnExampleToken",
        "Expiration": "2024-01-01T06:00:00Z"
    }"#;

    let creds = extract_aws_credentials(response);
    assert!(creds.is_some());

    let creds = creds.unwrap();
    assert_eq!(creds.access_key_id, "AKIAIOSFODNN7EXAMPLE");
    assert!(creds.secret_access_key.starts_with("wJalrXUtnFEMI"));
    assert!(creds.session_token.is_some());
    assert!(creds.expiration.is_some());
}

#[test]
fn extract_aws_credentials_invalid() {
    assert!(extract_aws_credentials("not json").is_none());
    assert!(extract_aws_credentials("{}").is_none());
    assert!(extract_aws_credentials("{\"AccessKeyId\": \"key\"}").is_none());
}

#[test]
fn extract_gcp_token_valid() {
    let response = r#"{
        "access_token": "ya29.c.b0AXv0zTPExampleToken",
        "expires_in": 3600,
        "token_type": "Bearer"
    }"#;

    let token = extract_gcp_token(response);
    assert!(token.is_some());

    let token = token.unwrap();
    assert!(token.access_token.starts_with("ya29"));
    assert_eq!(token.expires_in, Some(3600));
    assert_eq!(token.token_type.as_deref(), Some("Bearer"));
}

#[test]
fn extract_gcp_token_invalid() {
    assert!(extract_gcp_token("not json").is_none());
    assert!(extract_gcp_token("{}").is_none());
}

#[test]
fn extract_azure_token_valid() {
    let response = r#"{
        "access_token": "eyJ0eXAiOiJKV1QiExampleToken",
        "token_type": "Bearer",
        "resource": "https://management.azure.com/",
        "expires_on": "1700000000"
    }"#;

    let token = extract_azure_token(response);
    assert!(token.is_some());

    let token = token.unwrap();
    assert!(token.access_token.starts_with("eyJ0eXAi"));
    assert_eq!(token.token_type.as_deref(), Some("Bearer"));
    assert_eq!(
        token.resource.as_deref(),
        Some("https://management.azure.com/")
    );
}

#[test]
fn extract_azure_token_invalid() {
    assert!(extract_azure_token("{}").is_none());
}

#[test]
fn detect_cloud_provider_aws() {
    assert_eq!(
        detect_cloud_provider("ami-id\ninstance-id\nhostname"),
        Some(CloudProvider::Aws)
    );
}

#[test]
fn detect_cloud_provider_gcp() {
    assert_eq!(
        detect_cloud_provider("computeMetadata/v1/"),
        Some(CloudProvider::Gcp)
    );
}

#[test]
fn detect_cloud_provider_azure() {
    assert_eq!(
        detect_cloud_provider("subscriptionId: abc-123"),
        Some(CloudProvider::Azure)
    );
}

#[test]
fn detect_cloud_provider_digitalocean() {
    assert_eq!(
        detect_cloud_provider("droplet_id: 12345"),
        Some(CloudProvider::DigitalOcean)
    );
}

#[test]
fn detect_cloud_provider_unknown() {
    assert_eq!(detect_cloud_provider("random content here"), None);
}

#[test]
fn generate_discovery_chain_creates_ip_variants() {
    let chain = generate_discovery_chain("url");

    assert!(
        chain.len() >= 8,
        "Should generate 8+ discovery probes, got {}",
        chain.len()
    );

    for step in &chain {
        assert_eq!(step.stage, SsrfChainStage::Discovery);
        assert!(!step.expected_indicators.is_empty());
        assert!(step.next_step_generator.is_some());
    }
}

#[test]
fn aws_credential_chain_generates_steps() {
    let chain = aws_credential_chain("my-ec2-role");
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].stage, SsrfChainStage::CredentialExtraction);
    assert!(chain[0].payload.url.contains("my-ec2-role"));
    assert!(
        chain[0]
            .expected_indicators
            .contains(&"AccessKeyId".to_string())
    );
}

#[test]
fn internal_service_probes_comprehensive() {
    let probes = internal_service_probes();

    assert!(
        probes.len() >= 15,
        "Should probe 15+ internal services, got {}",
        probes.len()
    );

    let ports: Vec<u16> = probes
        .iter()
        .filter_map(|p| match &p.target {
            SsrfTarget::InternalService { port, .. } => Some(*port),
            _ => None,
        })
        .collect();

    assert!(ports.contains(&6379), "Should probe Redis");
    assert!(ports.contains(&11211), "Should probe Memcached");
    assert!(ports.contains(&9200), "Should probe Elasticsearch");
    assert!(ports.contains(&8200), "Should probe Vault");
    assert!(ports.contains(&2379), "Should probe etcd");
}

#[test]
fn cloud_provider_display() {
    assert_eq!(CloudProvider::Aws.to_string(), "AWS");
    assert_eq!(CloudProvider::Gcp.to_string(), "GCP");
    assert_eq!(CloudProvider::Azure.to_string(), "Azure");
    assert_eq!(CloudProvider::DigitalOcean.to_string(), "DigitalOcean");
    assert_eq!(CloudProvider::Alibaba.to_string(), "Alibaba");
    assert_eq!(CloudProvider::Oracle.to_string(), "Oracle");
    assert_eq!(CloudProvider::Kubernetes.to_string(), "Kubernetes");
}

#[test]
fn ssrf_scheme_display() {
    assert_eq!(SsrfScheme::Http.to_string(), "http");
    assert_eq!(SsrfScheme::Gopher.to_string(), "gopher");
    assert_eq!(SsrfScheme::Dict.to_string(), "dict");
    assert_eq!(SsrfScheme::File.to_string(), "file");
}

#[test]
fn ssrf_chain_stage_display() {
    assert_eq!(SsrfChainStage::Discovery.to_string(), "SSRF_DISCOVERY");
    assert_eq!(
        SsrfChainStage::MetadataAccess.to_string(),
        "METADATA_ACCESS"
    );
    assert_eq!(
        SsrfChainStage::CredentialExtraction.to_string(),
        "CREDENTIAL_EXTRACTION"
    );
    assert_eq!(
        SsrfChainStage::LateralMovement.to_string(),
        "LATERAL_MOVEMENT"
    );
}

#[test]
fn ssrf_target_display() {
    let meta = SsrfTarget::CloudMetadata(CloudProvider::Aws);
    assert_eq!(meta.to_string(), "AWS metadata");

    let internal = SsrfTarget::InternalService {
        host: "127.0.0.1".to_string(),
        port: 6379,
    };
    assert_eq!(internal.to_string(), "internal 127.0.0.1:6379");

    let file = SsrfTarget::LocalFile("/etc/passwd".to_string());
    assert_eq!(file.to_string(), "file:///etc/passwd");
}

#[test]
fn total_metadata_payload_count_reasonable() {
    let count = total_metadata_payload_count();
    assert!(
        count >= 20 && count <= 100,
        "Should have 20-100 metadata payloads, got {}",
        count
    );
}

#[test]
fn gopher_payload_contains_http_request() {
    let payloads = generate_scheme_payloads("127.0.0.1", "/admin");

    let gopher = payloads.iter().find(|p| p.url.starts_with("gopher://"));
    assert!(gopher.is_some(), "Should generate gopher payload");

    let gopher = gopher.unwrap();
    assert!(
        gopher.url.contains("GET"),
        "Gopher payload should contain HTTP GET"
    );
    assert!(
        gopher.url.contains("Host"),
        "Gopher payload should contain Host header"
    );
}

#[test]
fn ip_bypasses_decimal_correct() {
    let ip = Ipv4Addr::new(169, 254, 169, 254);
    let bypasses = generate_ip_bypasses(ip);

    let expected_decimal = u32::from(ip).to_string();
    assert!(
        bypasses.contains(&expected_decimal),
        "Should contain decimal {}",
        expected_decimal
    );
}
