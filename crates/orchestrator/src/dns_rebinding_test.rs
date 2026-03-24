use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn aws_target() -> RebindTarget {
    RebindTarget {
        ip: IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        port: 80,
        service: InternalService::AwsMetadata,
        path: "/latest/meta-data/iam/security-credentials/".to_string(),
    }
}

fn docker_target() -> RebindTarget {
    RebindTarget {
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 2375,
        service: InternalService::DockerApi,
        path: "/containers/json".to_string(),
    }
}

fn _custom_target(ip: Ipv4Addr, service: InternalService) -> RebindTarget {
    RebindTarget {
        ip: IpAddr::V4(ip),
        port: 80,
        service,
        path: "/test".to_string(),
    }
}

#[test]
fn test_default_config() {
    let config = RebindConfig::default();
    assert_eq!(config.techniques.len(), 6);
    assert!(!config.targets.is_empty());
    assert_eq!(config.ttl_values, vec![0, 1, 5, 30]);
    assert_eq!(config.dns_server_port, 53);
}

#[test]
fn test_default_targets_cover_cloud_providers() {
    let targets = default_targets();
    let services: Vec<_> = targets.iter().map(|t| t.service).collect();
    assert!(services.contains(&InternalService::AwsMetadata));
    assert!(services.contains(&InternalService::GcpMetadata));
    assert!(services.contains(&InternalService::AzureMetadata));
    assert!(services.contains(&InternalService::DockerApi));
    assert!(services.contains(&InternalService::KubernetesApi));
}

#[test]
fn test_engine_creation() {
    let engine = DnsRebindEngine::new(RebindConfig::default());
    assert_eq!(engine.config().techniques.len(), 6);
}

#[test]
fn test_generate_payloads_count() {
    let config = RebindConfig {
        techniques: vec![RebindingTechnique::ARecordFlip],
        targets: vec![aws_target()],
        ttl_values: vec![0, 1],
        ..Default::default()
    };
    let mut engine = DnsRebindEngine::new(config);
    let payloads = engine.generate_payloads();

    assert_eq!(payloads.len(), 2); // 1 technique × 1 target × 2 TTLs
}

#[test]
fn test_generate_payloads_all_techniques() {
    let mut engine = DnsRebindEngine::new(RebindConfig {
        targets: vec![aws_target()],
        ttl_values: vec![0],
        ..Default::default()
    });
    let payloads = engine.generate_payloads();

    let techniques: Vec<_> = payloads.iter().map(|p| p.technique).collect();
    assert!(techniques.contains(&RebindingTechnique::ARecordFlip));
    assert!(techniques.contains(&RebindingTechnique::MultipleARecords));
    assert!(techniques.contains(&RebindingTechnique::Ipv6Mapped));
    assert!(techniques.contains(&RebindingTechnique::TimeBasedFlip));
    assert!(techniques.contains(&RebindingTechnique::CnameChain));
    assert!(techniques.contains(&RebindingTechnique::SubdomainWildcard));
}

#[test]
fn test_payload_hostname_format() {
    let mut engine = DnsRebindEngine::new(RebindConfig {
        targets: vec![aws_target()],
        techniques: vec![RebindingTechnique::ARecordFlip],
        ttl_values: vec![0],
        ..Default::default()
    });
    let payloads = engine.generate_payloads();
    let p = &payloads[0];

    assert!(p.hostname.contains("flip"));
    assert!(p.hostname.contains("aws"));
    assert!(p.hostname.contains("rebind.attacker.com"));
}

#[test]
fn test_payload_first_resolution_is_attacker() {
    let config = RebindConfig {
        attacker_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        targets: vec![aws_target()],
        techniques: vec![RebindingTechnique::ARecordFlip],
        ttl_values: vec![0],
        ..Default::default()
    };
    let mut engine = DnsRebindEngine::new(config);
    let payloads = engine.generate_payloads();

    assert_eq!(
        payloads[0].first_resolution,
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))
    );
}

#[test]
fn test_payload_second_resolution_is_target() {
    let mut engine = DnsRebindEngine::new(RebindConfig {
        targets: vec![docker_target()],
        techniques: vec![RebindingTechnique::ARecordFlip],
        ttl_values: vec![0],
        ..Default::default()
    });
    let payloads = engine.generate_payloads();

    assert_eq!(
        payloads[0].second_resolution,
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    );
}

#[test]
fn test_ipv6_mapped_technique() {
    let mut engine = DnsRebindEngine::new(RebindConfig {
        targets: vec![aws_target()],
        techniques: vec![RebindingTechnique::Ipv6Mapped],
        ttl_values: vec![0],
        ..Default::default()
    });
    let payloads = engine.generate_payloads();
    let p = &payloads[0];

    match p.second_resolution {
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            assert_eq!(segments[5], 0xffff);
        }
        _ => panic!("expected IPv6 mapped address"),
    }
}

#[test]
fn test_payload_url_format() {
    let mut engine = DnsRebindEngine::new(RebindConfig {
        targets: vec![docker_target()],
        techniques: vec![RebindingTechnique::ARecordFlip],
        ttl_values: vec![0],
        ..Default::default()
    });
    let payloads = engine.generate_payloads();
    let p = &payloads[0];

    assert!(p.request_url.starts_with("http://"));
    assert!(p.request_url.contains(":2375"));
    assert!(p.request_url.contains("/containers/json"));
}

#[test]
fn test_payload_description_includes_technique() {
    let mut engine = DnsRebindEngine::new(RebindConfig {
        targets: vec![aws_target()],
        techniques: vec![RebindingTechnique::CnameChain],
        ttl_values: vec![5],
        ..Default::default()
    });
    let payloads = engine.generate_payloads();

    assert!(payloads[0].description.contains("CNAME-chain"));
    assert!(payloads[0].description.contains("TTL=5"));
}

#[test]
fn test_generate_zone_records() {
    let engine = DnsRebindEngine::new(RebindConfig::default());
    let records = engine.generate_zone_records();

    assert!(!records.is_empty());
    let a_records: Vec<_> = records
        .iter()
        .filter(|r| r.record_type == DnsRecordType::A)
        .collect();
    let aaaa_records: Vec<_> = records
        .iter()
        .filter(|r| r.record_type == DnsRecordType::Aaaa)
        .collect();
    assert!(!a_records.is_empty());
    assert!(!aaaa_records.is_empty());
}

#[test]
fn test_zone_records_have_zero_ttl() {
    let engine = DnsRebindEngine::new(RebindConfig::default());
    let records = engine.generate_zone_records();
    for r in &records {
        assert_eq!(r.ttl, 0);
    }
}

#[test]
fn test_zone_records_include_attacker_domain() {
    let engine = DnsRebindEngine::new(RebindConfig {
        attacker_domain: "test.evil.com".to_string(),
        ..Default::default()
    });
    let records = engine.generate_zone_records();
    assert!(records.iter().any(|r| r.name == "test.evil.com"));
}

#[test]
fn test_generate_race_payloads() {
    let mut engine = DnsRebindEngine::new(RebindConfig::default());
    let target = aws_target();
    let payloads = engine.generate_race_payloads(&target, 5);

    assert_eq!(payloads.len(), 5);
    for p in &payloads {
        assert_eq!(p.technique, RebindingTechnique::TimeBasedFlip);
        assert_eq!(p.ttl, 0);
        assert!(p.hostname.contains("race-"));
    }
}

#[test]
fn test_race_payloads_unique_hostnames() {
    let mut engine = DnsRebindEngine::new(RebindConfig::default());
    let target = aws_target();
    let payloads = engine.generate_race_payloads(&target, 10);

    let hostnames: Vec<&str> = payloads.iter().map(|p| p.hostname.as_str()).collect();
    let unique: std::collections::HashSet<&str> = hostnames.iter().copied().collect();
    assert_eq!(hostnames.len(), unique.len());
}

#[test]
fn test_generate_pinning_bypass() {
    let mut engine = DnsRebindEngine::new(RebindConfig::default());
    let target = docker_target();
    let payloads = engine.generate_pinning_bypass(&target);

    assert_eq!(payloads.len(), 2);
    let techniques: Vec<_> = payloads.iter().map(|p| p.technique).collect();
    assert!(techniques.contains(&RebindingTechnique::ARecordFlip));
    assert!(techniques.contains(&RebindingTechnique::SubdomainWildcard));
}

#[test]
fn test_analyze_successful_results() {
    let engine = DnsRebindEngine::new(RebindConfig::default());
    let results = vec![RebindResult {
        payload: RebindPayload {
            technique: RebindingTechnique::ARecordFlip,
            hostname: "test.evil.com".into(),
            first_resolution: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            second_resolution: IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            ttl: 0,
            target_service: InternalService::AwsMetadata,
            request_url: "http://test.evil.com/latest/meta-data/".into(),
            expected_path: "/latest/meta-data/".into(),
            description: "test".into(),
        },
        success: true,
        reached_internal: true,
        response_from_internal: Some("iam-role-name".into()),
        timing_ms: 200,
        dns_queries_observed: 2,
    }];

    let findings = engine.analyze_results(&results);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, RebindSeverity::Critical);
    assert!(!findings[0].chain_potential.is_empty());
}

#[test]
fn test_analyze_failed_results() {
    let engine = DnsRebindEngine::new(RebindConfig::default());
    let results = vec![RebindResult {
        payload: RebindPayload {
            technique: RebindingTechnique::ARecordFlip,
            hostname: "test.evil.com".into(),
            first_resolution: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            second_resolution: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ttl: 0,
            target_service: InternalService::Localhost,
            request_url: "http://test.evil.com/".into(),
            expected_path: "/".into(),
            description: "test".into(),
        },
        success: false,
        reached_internal: false,
        response_from_internal: None,
        timing_ms: 50,
        dns_queries_observed: 1,
    }];

    let findings = engine.analyze_results(&results);
    assert!(findings.is_empty());
}

#[test]
fn test_analyze_docker_severity_critical() {
    let engine = DnsRebindEngine::new(RebindConfig::default());
    let results = vec![RebindResult {
        payload: RebindPayload {
            technique: RebindingTechnique::ARecordFlip,
            hostname: "x.evil.com".into(),
            first_resolution: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            second_resolution: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ttl: 0,
            target_service: InternalService::DockerApi,
            request_url: "http://x.evil.com:2375/containers/json".into(),
            expected_path: "/containers/json".into(),
            description: "test".into(),
        },
        success: true,
        reached_internal: true,
        response_from_internal: Some("[{\"Id\":\"abc\"}]".into()),
        timing_ms: 100,
        dns_queries_observed: 2,
    }];

    let findings = engine.analyze_results(&results);
    assert_eq!(findings[0].severity, RebindSeverity::Critical);
    assert!(findings[0]
        .chain_potential
        .iter()
        .any(|c| c.contains("Docker")));
}

#[test]
fn test_analyze_localhost_severity_high() {
    let engine = DnsRebindEngine::new(RebindConfig::default());
    let results = vec![RebindResult {
        payload: RebindPayload {
            technique: RebindingTechnique::ARecordFlip,
            hostname: "x.evil.com".into(),
            first_resolution: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            second_resolution: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ttl: 0,
            target_service: InternalService::Localhost,
            request_url: "http://x.evil.com/".into(),
            expected_path: "/".into(),
            description: "test".into(),
        },
        success: true,
        reached_internal: true,
        response_from_internal: Some("internal page".into()),
        timing_ms: 50,
        dns_queries_observed: 2,
    }];

    let findings = engine.analyze_results(&results);
    assert_eq!(findings[0].severity, RebindSeverity::High);
}

#[test]
fn test_analyze_not_reached_internal_is_low() {
    let engine = DnsRebindEngine::new(RebindConfig::default());
    let results = vec![RebindResult {
        payload: RebindPayload {
            technique: RebindingTechnique::ARecordFlip,
            hostname: "x.evil.com".into(),
            first_resolution: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            second_resolution: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ttl: 0,
            target_service: InternalService::AwsMetadata,
            request_url: "http://x.evil.com/".into(),
            expected_path: "/".into(),
            description: "test".into(),
        },
        success: true,
        reached_internal: false,
        response_from_internal: None,
        timing_ms: 50,
        dns_queries_observed: 1,
    }];

    let findings = engine.analyze_results(&results);
    assert_eq!(findings[0].severity, RebindSeverity::Low);
}

#[test]
fn test_is_internal_ip_loopback() {
    assert!(is_internal_ip(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(is_internal_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[test]
fn test_is_internal_ip_private() {
    assert!(is_internal_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(is_internal_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    assert!(is_internal_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
}

#[test]
fn test_is_internal_ip_link_local() {
    assert!(is_internal_ip(&IpAddr::V4(Ipv4Addr::new(
        169, 254, 169, 254
    ))));
    assert!(is_internal_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1))));
}

#[test]
fn test_is_internal_ip_public() {
    assert!(!is_internal_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    assert!(!is_internal_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
}

#[test]
fn test_is_internal_ip_ipv4_mapped_v6() {
    let mapped = IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]);
    assert!(is_internal_ip(&mapped));

    let mapped_private = IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1]);
    assert!(is_internal_ip(&mapped_private));
}

#[test]
fn test_detect_rebind_opportunity_internal() {
    let ips = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
    assert!(DnsRebindEngine::detect_rebind_opportunity("test.com", &ips));
}

#[test]
fn test_detect_rebind_opportunity_public() {
    let ips = vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))];
    assert!(!DnsRebindEngine::detect_rebind_opportunity(
        "example.com",
        &ips
    ));
}

#[test]
fn test_chain_potential_aws() {
    let result = RebindResult {
        payload: RebindPayload {
            technique: RebindingTechnique::ARecordFlip,
            hostname: "x.evil.com".into(),
            first_resolution: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            second_resolution: IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            ttl: 0,
            target_service: InternalService::AwsMetadata,
            request_url: "http://x.evil.com/".into(),
            expected_path: "/".into(),
            description: "test".into(),
        },
        success: true,
        reached_internal: true,
        response_from_internal: None,
        timing_ms: 0,
        dns_queries_observed: 0,
    };

    let chains = chain_potential(&result);
    assert!(chains.len() >= 2);
    assert!(chains.iter().any(|c| c.contains("IAM")));
}

#[test]
fn test_chain_potential_k8s() {
    let result = RebindResult {
        payload: RebindPayload {
            technique: RebindingTechnique::ARecordFlip,
            hostname: "x.evil.com".into(),
            first_resolution: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            second_resolution: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ttl: 0,
            target_service: InternalService::KubernetesApi,
            request_url: "http://x.evil.com/pods".into(),
            expected_path: "/pods".into(),
            description: "test".into(),
        },
        success: true,
        reached_internal: true,
        response_from_internal: None,
        timing_ms: 0,
        dns_queries_observed: 0,
    };

    let chains = chain_potential(&result);
    assert!(chains
        .iter()
        .any(|c| c.contains("kubelet") || c.contains("pod")));
}

#[test]
fn test_technique_display() {
    assert_eq!(
        format!("{}", RebindingTechnique::ARecordFlip),
        "A-record-flip"
    );
    assert_eq!(format!("{}", RebindingTechnique::CnameChain), "CNAME-chain");
    assert_eq!(format!("{}", RebindingTechnique::Ipv6Mapped), "IPv6-mapped");
}

#[test]
fn test_service_display() {
    assert_eq!(format!("{}", InternalService::AwsMetadata), "AWS-IMDS");
    assert_eq!(format!("{}", InternalService::DockerApi), "Docker-API");
    assert_eq!(
        format!("{}", InternalService::KubernetesApi),
        "Kubernetes-API"
    );
}

#[test]
fn test_severity_ordering() {
    assert!(RebindSeverity::Low < RebindSeverity::Medium);
    assert!(RebindSeverity::Medium < RebindSeverity::High);
    assert!(RebindSeverity::High < RebindSeverity::Critical);
}

#[test]
fn test_dns_record_type_display() {
    assert_eq!(format!("{}", DnsRecordType::A), "A");
    assert_eq!(format!("{}", DnsRecordType::Aaaa), "AAAA");
    assert_eq!(format!("{}", DnsRecordType::Cname), "CNAME");
}

#[test]
fn test_full_payload_generation_default() {
    let mut engine = DnsRebindEngine::new(RebindConfig::default());
    let payloads = engine.generate_payloads();
    // 6 targets × 6 techniques × 4 TTLs = 144
    assert_eq!(payloads.len(), 144);
}

#[test]
fn test_unique_request_counter() {
    let mut engine = DnsRebindEngine::new(RebindConfig {
        targets: vec![aws_target(), docker_target()],
        techniques: vec![RebindingTechnique::ARecordFlip],
        ttl_values: vec![0],
        ..Default::default()
    });
    let payloads = engine.generate_payloads();

    let hostnames: Vec<&str> = payloads.iter().map(|p| p.hostname.as_str()).collect();
    let unique: std::collections::HashSet<&str> = hostnames.iter().copied().collect();
    assert_eq!(hostnames.len(), unique.len());
}

#[test]
fn test_zone_records_v6_mapping() {
    let config = RebindConfig {
        targets: vec![aws_target()],
        ..Default::default()
    };
    let engine = DnsRebindEngine::new(config);
    let records = engine.generate_zone_records();

    let aaaa: Vec<_> = records
        .iter()
        .filter(|r| r.record_type == DnsRecordType::Aaaa)
        .collect();
    assert!(!aaaa.is_empty());
    assert!(aaaa[0].value.contains("::ffff:"));
}

#[test]
fn test_ttl_variation_in_payloads() {
    let mut engine = DnsRebindEngine::new(RebindConfig {
        targets: vec![aws_target()],
        techniques: vec![RebindingTechnique::ARecordFlip],
        ttl_values: vec![0, 1, 5, 30],
        ..Default::default()
    });
    let payloads = engine.generate_payloads();

    let ttls: Vec<u32> = payloads.iter().map(|p| p.ttl).collect();
    assert!(ttls.contains(&0));
    assert!(ttls.contains(&1));
    assert!(ttls.contains(&5));
    assert!(ttls.contains(&30));
}
