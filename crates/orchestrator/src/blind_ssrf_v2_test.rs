use super::*;
use std::collections::HashMap;

#[test]
fn orchestrator_new_enables_all_protocols_and_providers() {
    let orch = BlindSsrfOrchestrator::new(
        "https://target.local/fetch".to_string(),
        "url".to_string(),
        SsrfCallbackConfig::default(),
    );

    assert_eq!(orch.enabled_protocols.len(), 8);
    assert_eq!(orch.enabled_providers.len(), 5);
    assert_eq!(orch.target_base_url, "https://target.local/fetch");
    assert_eq!(orch.vulnerable_parameter, "url");
}

#[test]
fn callback_config_default_values() {
    let config = SsrfCallbackConfig::default();
    assert_eq!(config.listener_url, "https://oob.callback.local");
    assert_eq!(config.poll_interval_ms, 500);
    assert_eq!(config.timeout_ms, 30_000);
    assert_eq!(config.unique_token_prefix, "aegis-ssrf");
}

#[test]
fn aws_metadata_paths_comprehensive() {
    let paths = metadata_paths_for_provider(CloudProvider::Aws);

    assert!(
        paths.len() >= 5,
        "AWS should have 5+ metadata paths, got {}",
        paths.len()
    );

    let has_iam_creds = paths
        .iter()
        .any(|p| p.path.contains("security-credentials"));
    let has_userdata = paths.iter().any(|p| p.path.contains("user-data"));
    let has_imdsv2 = paths.iter().any(|p| p.path.contains("api/token"));
    let has_identity = paths.iter().any(|p| p.path.contains("instance-identity"));
    let has_hostname = paths.iter().any(|p| p.path.contains("hostname"));

    assert!(
        has_iam_creds,
        "AWS must include IAM security-credentials path"
    );
    assert!(has_userdata, "AWS must include user-data path");
    assert!(has_imdsv2, "AWS must include IMDSv2 token path");
    assert!(has_identity, "AWS must include instance identity document");
    assert!(has_hostname, "AWS must include hostname path");

    let imdsv2_path = paths.iter().find(|p| p.path.contains("api/token")).unwrap();
    assert_eq!(imdsv2_path.required_method, "PUT");
    assert!(imdsv2_path
        .required_headers
        .iter()
        .any(|(k, _)| k == "X-aws-ec2-metadata-token-ttl-seconds"),);
}

#[test]
fn gcp_metadata_paths_require_flavor_header() {
    let paths = metadata_paths_for_provider(CloudProvider::Gcp);

    assert!(
        paths.len() >= 5,
        "GCP should have 5+ metadata paths, got {}",
        paths.len()
    );

    for path in &paths {
        let has_flavor = path
            .required_headers
            .iter()
            .any(|(k, v)| k == "Metadata-Flavor" && v == "Google");
        assert!(
            has_flavor,
            "GCP path '{}' must require Metadata-Flavor: Google header",
            path.path
        );
    }

    let has_token = paths.iter().any(|p| p.path.contains("/token"));
    let has_email = paths.iter().any(|p| p.path.contains("/email"));
    let has_project = paths.iter().any(|p| p.path.contains("project-id"));

    assert!(has_token, "GCP must include access token path");
    assert!(has_email, "GCP must include service account email path");
    assert!(has_project, "GCP must include project ID path");
}

#[test]
fn azure_metadata_paths_require_metadata_header() {
    let paths = metadata_paths_for_provider(CloudProvider::Azure);

    assert!(
        paths.len() >= 5,
        "Azure should have 5+ metadata paths, got {}",
        paths.len()
    );

    for path in &paths {
        let has_metadata = path
            .required_headers
            .iter()
            .any(|(k, v)| k == "Metadata" && v == "true");
        assert!(
            has_metadata,
            "Azure path '{}' must require Metadata: true header",
            path.path
        );
    }

    let has_identity_token = paths.iter().any(|p| p.path.contains("oauth2/token"));
    let has_subscription = paths.iter().any(|p| p.path.contains("subscriptionId"));

    assert!(
        has_identity_token,
        "Azure must include managed identity token path"
    );
    assert!(has_subscription, "Azure must include subscription ID path");
}

#[test]
fn digitalocean_metadata_paths_comprehensive() {
    let paths = metadata_paths_for_provider(CloudProvider::DigitalOcean);

    assert!(
        paths.len() >= 5,
        "DigitalOcean should have 5+ metadata paths, got {}",
        paths.len()
    );

    let has_json = paths.iter().any(|p| p.path.contains("v1.json"));
    let has_hostname = paths.iter().any(|p| p.path.contains("hostname"));
    let has_userdata = paths.iter().any(|p| p.path.contains("user-data"));

    assert!(has_json, "DO must include full metadata JSON path");
    assert!(has_hostname, "DO must include hostname path");
    assert!(has_userdata, "DO must include user-data path");

    for path in &paths {
        assert!(
            path.required_headers.is_empty(),
            "DigitalOcean metadata requires no auth headers"
        );
    }
}

#[test]
fn alibaba_metadata_paths_comprehensive() {
    let paths = metadata_paths_for_provider(CloudProvider::Alibaba);

    assert!(
        paths.len() >= 5,
        "Alibaba should have 5+ metadata paths, got {}",
        paths.len()
    );

    let has_ram = paths
        .iter()
        .any(|p| p.path.contains("ram/security-credentials"));
    let has_instance_id = paths.iter().any(|p| p.path.contains("instance-id"));
    let has_region = paths.iter().any(|p| p.path.contains("region-id"));
    let has_userdata = paths.iter().any(|p| p.path.contains("user-data"));

    assert!(
        has_ram,
        "Alibaba must include RAM security-credentials path"
    );
    assert!(has_instance_id, "Alibaba must include instance-id path");
    assert!(has_region, "Alibaba must include region-id path");
    assert!(has_userdata, "Alibaba must include user-data path");
}

#[test]
fn protocol_payload_generation_all_schemes() {
    let config = SsrfCallbackConfig::default();

    let file_payloads = payloads_for_protocol(SsrfProtocol::File, &config);
    assert!(
        file_payloads.len() >= 5,
        "File protocol should produce 5+ payloads"
    );
    assert!(file_payloads.iter().all(|p| p.starts_with("file://")));
    assert!(file_payloads.iter().any(|p| p.contains("/etc/passwd")));
    assert!(file_payloads
        .iter()
        .any(|p| p.contains("/proc/self/environ")));

    let gopher_payloads = payloads_for_protocol(SsrfProtocol::Gopher, &config);
    assert!(!gopher_payloads.is_empty());
    assert!(gopher_payloads.iter().all(|p| p.starts_with("gopher://")));

    let dict_payloads = payloads_for_protocol(SsrfProtocol::Dict, &config);
    assert!(!dict_payloads.is_empty());
    assert!(dict_payloads.iter().all(|p| p.starts_with("dict://")));

    let ftp_payloads = payloads_for_protocol(SsrfProtocol::Ftp, &config);
    assert!(!ftp_payloads.is_empty());
    assert!(ftp_payloads.iter().all(|p| p.starts_with("ftp://")));

    let tftp_payloads = payloads_for_protocol(SsrfProtocol::Tftp, &config);
    assert!(!tftp_payloads.is_empty());
    assert!(tftp_payloads.iter().all(|p| p.starts_with("tftp://")));

    let ldap_payloads = payloads_for_protocol(SsrfProtocol::Ldap, &config);
    assert!(!ldap_payloads.is_empty());
    assert!(ldap_payloads.iter().all(|p| p.starts_with("ldap://")));
}

#[test]
fn generate_probes_includes_all_sources() {
    let orch = BlindSsrfOrchestrator::new(
        "https://target.local/fetch".to_string(),
        "url".to_string(),
        SsrfCallbackConfig::default(),
    );

    let probes = orch.generate_probes();
    let metadata_count = total_metadata_path_count();
    let protocol_count = total_protocol_payload_count();

    assert!(
        probes.len() >= metadata_count + protocol_count,
        "Should include at least metadata ({}) + protocol ({}) probes, got {}",
        metadata_count,
        protocol_count,
        probes.len()
    );

    let has_callback = probes.iter().any(|p| p.contains("oob.callback.local"));
    let has_aws = probes.iter().any(|p| p.contains("169.254.169.254"));
    let has_gcp = probes
        .iter()
        .any(|p| p.contains("metadata.google.internal"));
    let has_alibaba = probes.iter().any(|p| p.contains("100.100.100.200"));
    let has_file = probes.iter().any(|p| p.starts_with("file://"));

    assert!(has_callback, "Probes must include callback URLs");
    assert!(has_aws, "Probes must include AWS metadata IP");
    assert!(has_gcp, "Probes must include GCP metadata hostname");
    assert!(has_alibaba, "Probes must include Alibaba metadata IP");
    assert!(has_file, "Probes must include file:// payloads");
}

#[test]
fn analyze_callback_parses_valid_event() {
    let orch = BlindSsrfOrchestrator::new(
        "https://target.local".to_string(),
        "url".to_string(),
        SsrfCallbackConfig::default(),
    );

    let event = CallbackEvent {
        token: "aegis-ssrf-aws-abc123def456".to_string(),
        source_ip: "10.0.0.50".to_string(),
        timestamp_ms: 1500,
        http_method: "GET".to_string(),
        path: "/latest/meta-data/iam/info".to_string(),
        headers: HashMap::new(),
        body: Some("{\"InstanceProfileArn\": \"arn:aws:iam::role/test\"}".to_string()),
    };

    let result = orch.analyze_callback(&event);
    assert!(result.is_some());

    let result = result.unwrap();
    assert!(result.callback_received);
    assert_eq!(result.response_time_ms, 1500);
    assert!(result.extracted_data.is_some());
    assert_eq!(result.protocol, SsrfProtocol::Http);

    let mp = result.metadata_path.unwrap();
    assert_eq!(mp.provider, CloudProvider::Aws);
}

#[test]
fn analyze_callback_rejects_malformed_token() {
    let orch = BlindSsrfOrchestrator::new(
        "https://target.local".to_string(),
        "url".to_string(),
        SsrfCallbackConfig::default(),
    );

    let event = CallbackEvent {
        token: "bad-token".to_string(),
        source_ip: "10.0.0.1".to_string(),
        timestamp_ms: 0,
        http_method: "GET".to_string(),
        path: "/".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    assert!(orch.analyze_callback(&event).is_none());
}

#[test]
fn detect_ssrf_blind_filters_by_prefix() {
    let orch = BlindSsrfOrchestrator::new(
        "https://target.local".to_string(),
        "url".to_string(),
        SsrfCallbackConfig::default(),
    );

    let events = vec![
        CallbackEvent {
            token: "aegis-ssrf-gcp-abc123".to_string(),
            source_ip: "10.0.0.50".to_string(),
            timestamp_ms: 200,
            http_method: "GET".to_string(),
            path: "/computeMetadata/v1/instance/hostname".to_string(),
            headers: HashMap::new(),
            body: Some("gke-cluster-1".to_string()),
        },
        CallbackEvent {
            token: "unrelated-noise-data".to_string(),
            source_ip: "192.168.1.1".to_string(),
            timestamp_ms: 300,
            http_method: "GET".to_string(),
            path: "/random".to_string(),
            headers: HashMap::new(),
            body: None,
        },
        CallbackEvent {
            token: "aegis-ssrf-azure-def456".to_string(),
            source_ip: "10.0.0.51".to_string(),
            timestamp_ms: 400,
            http_method: "GET".to_string(),
            path: "/metadata/instance".to_string(),
            headers: HashMap::new(),
            body: None,
        },
    ];

    let results = orch.detect_ssrf_blind(&events);
    assert_eq!(
        results.len(),
        2,
        "Should match exactly 2 aegis-ssrf prefixed events"
    );
    assert!(results[0].callback_received);
    assert!(results[1].callback_received);
}

#[test]
fn credential_chain_aws_structure() {
    let orch = BlindSsrfOrchestrator::new(
        "https://target.local".to_string(),
        "url".to_string(),
        SsrfCallbackConfig::default(),
    );

    let chain = orch.build_credential_chain(CloudProvider::Aws);
    assert_eq!(chain.provider, CloudProvider::Aws);
    assert!(chain.steps.len() >= 3, "AWS chain needs 3+ steps");

    let orders: Vec<u32> = chain.steps.iter().map(|s| s.order).collect();
    let mut sorted_orders = orders.clone();
    sorted_orders.sort();
    assert_eq!(orders, sorted_orders, "Steps must be in ascending order");

    let has_role_enum = chain.steps.iter().any(|s| s.purpose.contains("role"));
    let has_cred_extract = chain
        .steps
        .iter()
        .any(|s| s.purpose.contains("AccessKeyId") || s.purpose.contains("SecretAccessKey"));
    assert!(has_role_enum, "AWS chain must enumerate IAM roles");
    assert!(has_cred_extract, "AWS chain must extract credentials");

    let dependent_step = chain
        .steps
        .iter()
        .find(|s| s.depends_on_extracted.is_some());
    assert!(
        dependent_step.is_some(),
        "AWS chain must have a step depending on extracted role name"
    );
    assert_eq!(
        dependent_step.unwrap().depends_on_extracted.as_deref(),
        Some("ROLE_NAME")
    );
}

#[test]
fn credential_chain_gcp_targets_metadata_internal() {
    let orch = BlindSsrfOrchestrator::new(
        "https://target.local".to_string(),
        "url".to_string(),
        SsrfCallbackConfig::default(),
    );

    let chain = orch.build_credential_chain(CloudProvider::Gcp);
    assert_eq!(chain.provider, CloudProvider::Gcp);
    assert!(chain.steps.len() >= 3);

    for step in &chain.steps {
        assert!(
            step.probe_url.contains("metadata.google.internal"),
            "GCP chain step must target metadata.google.internal"
        );
    }

    let has_token = chain.steps.iter().any(|s| s.probe_url.contains("/token"));
    assert!(has_token, "GCP chain must include token extraction step");
}

#[test]
fn credential_chain_azure_includes_keyvault() {
    let orch = BlindSsrfOrchestrator::new(
        "https://target.local".to_string(),
        "url".to_string(),
        SsrfCallbackConfig::default(),
    );

    let chain = orch.build_credential_chain(CloudProvider::Azure);
    assert_eq!(chain.provider, CloudProvider::Azure);
    assert!(chain.steps.len() >= 2);

    let has_vault = chain
        .steps
        .iter()
        .any(|s| s.probe_url.contains("vault.azure.net"));
    assert!(has_vault, "Azure chain should include Key Vault token step");
}

#[test]
fn credential_chain_alibaba_has_ram_extraction() {
    let orch = BlindSsrfOrchestrator::new(
        "https://target.local".to_string(),
        "url".to_string(),
        SsrfCallbackConfig::default(),
    );

    let chain = orch.build_credential_chain(CloudProvider::Alibaba);
    assert_eq!(chain.provider, CloudProvider::Alibaba);
    assert!(chain.steps.len() >= 2);

    let has_ram = chain
        .steps
        .iter()
        .any(|s| s.probe_url.contains("ram/security-credentials"));
    assert!(
        has_ram,
        "Alibaba chain must include RAM credential extraction"
    );

    assert!(
        chain.steps[0].probe_url.contains("100.100.100.200"),
        "Alibaba probes must target 100.100.100.200"
    );
}

#[test]
fn total_metadata_path_count_reasonable() {
    let count = total_metadata_path_count();
    assert!(
        count >= 30 && count <= 100,
        "Total metadata paths should be 30-100, got {}",
        count
    );
}

#[test]
fn total_protocol_payload_count_reasonable() {
    let count = total_protocol_payload_count();
    assert!(
        count >= 15 && count <= 50,
        "Total protocol payloads should be 15-50, got {}",
        count
    );
}

#[test]
fn cloud_provider_display_all_variants() {
    assert_eq!(CloudProvider::Aws.to_string(), "AWS");
    assert_eq!(CloudProvider::Gcp.to_string(), "GCP");
    assert_eq!(CloudProvider::Azure.to_string(), "Azure");
    assert_eq!(CloudProvider::DigitalOcean.to_string(), "DigitalOcean");
    assert_eq!(CloudProvider::Alibaba.to_string(), "Alibaba");
}

#[test]
fn ssrf_protocol_display_all_variants() {
    assert_eq!(SsrfProtocol::Http.to_string(), "http");
    assert_eq!(SsrfProtocol::Https.to_string(), "https");
    assert_eq!(SsrfProtocol::File.to_string(), "file");
    assert_eq!(SsrfProtocol::Gopher.to_string(), "gopher");
    assert_eq!(SsrfProtocol::Dict.to_string(), "dict");
    assert_eq!(SsrfProtocol::Ftp.to_string(), "ftp");
    assert_eq!(SsrfProtocol::Tftp.to_string(), "tftp");
    assert_eq!(SsrfProtocol::Ldap.to_string(), "ldap");
}

#[test]
fn metadata_url_formatting_per_provider() {
    assert!(format_metadata_url(&CloudProvider::Aws, "/test").starts_with("http://169.254.169.254"));
    assert!(format_metadata_url(&CloudProvider::Gcp, "/test")
        .starts_with("http://metadata.google.internal"));
    assert!(
        format_metadata_url(&CloudProvider::Azure, "/test").starts_with("http://169.254.169.254")
    );
    assert!(format_metadata_url(&CloudProvider::DigitalOcean, "/test")
        .starts_with("http://169.254.169.254"));
    assert!(
        format_metadata_url(&CloudProvider::Alibaba, "/test").starts_with("http://100.100.100.200")
    );
}

#[test]
fn gopher_payloads_target_redis_and_memcached() {
    let config = SsrfCallbackConfig::default();
    let payloads = payloads_for_protocol(SsrfProtocol::Gopher, &config);

    let has_redis = payloads.iter().any(|p| p.contains(":6379"));
    let has_memcached = payloads.iter().any(|p| p.contains(":11211"));

    assert!(has_redis, "Gopher payloads must target Redis on 6379");
    assert!(
        has_memcached,
        "Gopher payloads must target Memcached on 11211"
    );
}

#[test]
fn file_payloads_target_sensitive_paths() {
    let config = SsrfCallbackConfig::default();
    let payloads = payloads_for_protocol(SsrfProtocol::File, &config);

    let targets: Vec<&str> = vec![
        "/etc/passwd",
        "/proc/self/environ",
        "/proc/self/cmdline",
        ".aws/credentials",
    ];

    for target in targets {
        assert!(
            payloads.iter().any(|p| p.contains(target)),
            "File payloads must include {}",
            target
        );
    }
}

#[test]
fn callback_token_generation_deterministic() {
    let token_a = generate_callback_token("aegis", &CloudProvider::Aws, "/test/path");
    let token_b = generate_callback_token("aegis", &CloudProvider::Aws, "/test/path");
    assert_eq!(token_a, token_b, "Same inputs must produce same token");

    let token_c = generate_callback_token("aegis", &CloudProvider::Gcp, "/test/path");
    assert_ne!(
        token_a, token_c,
        "Different providers must produce different tokens"
    );
}

#[test]
fn parse_protocol_from_path_variants() {
    assert_eq!(
        parse_protocol_from_path("/gopher/test"),
        SsrfProtocol::Gopher
    );
    assert_eq!(parse_protocol_from_path("/dict/info"), SsrfProtocol::Dict);
    assert_eq!(
        parse_protocol_from_path("/file/etc/passwd"),
        SsrfProtocol::File
    );
    assert_eq!(parse_protocol_from_path("/ftp/upload"), SsrfProtocol::Ftp);
    assert_eq!(parse_protocol_from_path("/ldap/query"), SsrfProtocol::Ldap);
    assert_eq!(
        parse_protocol_from_path("/https/secure"),
        SsrfProtocol::Https
    );
    assert_eq!(parse_protocol_from_path("/normal/path"), SsrfProtocol::Http);
}
