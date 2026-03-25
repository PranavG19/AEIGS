use super::attack_surface_mapper::*;

// ---------------------------------------------------------------------------
// calculate_ip_count
// ---------------------------------------------------------------------------

#[test]
fn test_calculate_ip_count_slash_24() {
    assert_eq!(calculate_ip_count("192.168.1.0/24"), 256);
}

#[test]
fn test_calculate_ip_count_slash_32() {
    assert_eq!(calculate_ip_count("10.0.0.1/32"), 1);
}

#[test]
fn test_calculate_ip_count_slash_16() {
    assert_eq!(calculate_ip_count("172.16.0.0/16"), 65536);
}

#[test]
fn test_calculate_ip_count_slash_0() {
    // 1u32.checked_shl(32) overflows → fallback to 1
    let count = calculate_ip_count("0.0.0.0/0");
    assert_eq!(count, 1);
}

#[test]
fn test_calculate_ip_count_no_prefix() {
    assert_eq!(calculate_ip_count("10.0.0.1"), 1);
}

#[test]
fn test_calculate_ip_count_invalid_prefix_too_large() {
    assert_eq!(calculate_ip_count("10.0.0.0/33"), 1);
}

#[test]
fn test_calculate_ip_count_slash_31() {
    assert_eq!(calculate_ip_count("10.0.0.0/31"), 2);
}

// ---------------------------------------------------------------------------
// map_ip_ranges
// ---------------------------------------------------------------------------

#[test]
fn test_map_ip_ranges_single() {
    let data = vec![("10.0.0.0/24", Some(12345u32), Some("AcmeCorp"), Some("US"))];
    let ranges = map_ip_ranges(&data);
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].cidr, "10.0.0.0/24");
    assert_eq!(ranges[0].asn, Some(12345));
    assert_eq!(ranges[0].org_name.as_deref(), Some("AcmeCorp"));
    assert_eq!(ranges[0].country.as_deref(), Some("US"));
    assert_eq!(ranges[0].ip_count, 256);
}

#[test]
fn test_map_ip_ranges_multiple_with_none_fields() {
    let data = vec![
        ("192.168.0.0/16", None, None, None),
        ("10.10.0.0/24", Some(9999), Some("TestOrg"), None),
    ];
    let ranges = map_ip_ranges(&data);
    assert_eq!(ranges.len(), 2);
    assert_eq!(ranges[0].ip_count, 65536);
    assert!(ranges[0].asn.is_none());
    assert!(ranges[0].org_name.is_none());
    assert_eq!(ranges[1].ip_count, 256);
    assert_eq!(ranges[1].asn, Some(9999));
}

#[test]
fn test_map_ip_ranges_empty() {
    let ranges = map_ip_ranges(&[]);
    assert!(ranges.is_empty());
}

// ---------------------------------------------------------------------------
// map_domains
// ---------------------------------------------------------------------------

#[test]
fn test_map_domains_primary() {
    let ips: &[&str] = &["1.2.3.4"];
    let data = vec![(
        "example.com",
        "primary",
        ips,
        Some("2024-01-01"),
        "dns_enum",
    )];
    let domains = map_domains(&data);
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].domain, "example.com");
    assert_eq!(domains[0].domain_type, DomainType::Primary);
    assert_eq!(domains[0].ip_addresses, vec!["1.2.3.4".to_string()]);
    assert_eq!(domains[0].first_seen.as_deref(), Some("2024-01-01"));
    assert_eq!(domains[0].source, DiscoverySource::DnsEnum);
}

#[test]
fn test_map_domains_subdomain_cert_transparency() {
    let ips: &[&str] = &["5.6.7.8", "9.10.11.12"];
    let data = vec![(
        "sub.example.com",
        "subdomain",
        ips,
        None,
        "cert_transparency",
    )];
    let domains = map_domains(&data);
    assert_eq!(domains[0].domain_type, DomainType::Subdomain);
    assert_eq!(domains[0].source, DiscoverySource::CertTransparency);
    assert!(domains[0].first_seen.is_none());
    assert_eq!(domains[0].ip_addresses.len(), 2);
}

#[test]
fn test_map_domains_wildcard_bruteforce() {
    let ips: &[&str] = &[];
    let data = vec![("*.example.com", "wildcard", ips, None, "bruteforce")];
    let domains = map_domains(&data);
    assert_eq!(domains[0].domain_type, DomainType::Wildcard);
    assert_eq!(domains[0].source, DiscoverySource::BruteForce);
    assert!(domains[0].ip_addresses.is_empty());
}

#[test]
fn test_map_domains_alias_shodan() {
    let ips: &[&str] = &["100.0.0.1"];
    let data = vec![("alias.example.com", "alias", ips, None, "shodan")];
    let domains = map_domains(&data);
    assert_eq!(domains[0].domain_type, DomainType::Alias);
    assert_eq!(domains[0].source, DiscoverySource::Shodan);
}

#[test]
fn test_map_domains_unknown_type_defaults_to_subdomain() {
    let ips: &[&str] = &[];
    let data = vec![("x.example.com", "nonsense", ips, None, "passivedns")];
    let domains = map_domains(&data);
    assert_eq!(domains[0].domain_type, DomainType::Subdomain);
}

#[test]
fn test_map_domains_unknown_source_defaults_to_passive_dns() {
    let ips: &[&str] = &[];
    let data = vec![("x.example.com", "primary", ips, None, "unknown_source")];
    let domains = map_domains(&data);
    assert_eq!(domains[0].source, DiscoverySource::PassiveDns);
}

// ---------------------------------------------------------------------------
// map_services
// ---------------------------------------------------------------------------

#[test]
fn test_map_services_http() {
    let data = vec![(
        "1.2.3.4",
        80u16,
        "http",
        Some("nginx"),
        Some("1.21.0"),
        None,
        false,
    )];
    let services = map_services(&data);
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].ip, "1.2.3.4");
    assert_eq!(services[0].port, 80);
    assert_eq!(services[0].protocol, ServiceProtocol::Http);
    assert_eq!(services[0].service_name.as_deref(), Some("nginx"));
    assert_eq!(services[0].version.as_deref(), Some("1.21.0"));
    assert!(services[0].banner.is_none());
    assert!(!services[0].tls_enabled);
}

#[test]
fn test_map_services_https_with_tls() {
    let data = vec![(
        "10.0.0.1",
        443u16,
        "https",
        None,
        None,
        Some("HTTP/2"),
        true,
    )];
    let services = map_services(&data);
    assert_eq!(services[0].protocol, ServiceProtocol::Https);
    assert!(services[0].tls_enabled);
    assert_eq!(services[0].banner.as_deref(), Some("HTTP/2"));
}

#[test]
fn test_map_services_custom_protocol() {
    let data = vec![("10.0.0.1", 9999u16, "amqp", None, None, None, false)];
    let services = map_services(&data);
    assert_eq!(
        services[0].protocol,
        ServiceProtocol::Custom("amqp".to_string())
    );
}

#[test]
fn test_map_services_database_protocols() {
    let data = vec![
        ("10.0.0.1", 5432u16, "postgres", None, None, None, false),
        ("10.0.0.2", 3306u16, "mysql", None, None, None, false),
        ("10.0.0.3", 6379u16, "redis", None, None, None, false),
        ("10.0.0.4", 27017u16, "mongodb", None, None, None, false),
        (
            "10.0.0.5",
            9200u16,
            "elasticsearch",
            None,
            None,
            None,
            false,
        ),
    ];
    let services = map_services(&data);
    assert_eq!(services[0].protocol, ServiceProtocol::Postgres);
    assert_eq!(services[1].protocol, ServiceProtocol::Mysql);
    assert_eq!(services[2].protocol, ServiceProtocol::Redis);
    assert_eq!(services[3].protocol, ServiceProtocol::Mongodb);
    assert_eq!(services[4].protocol, ServiceProtocol::Elasticsearch);
}

// ---------------------------------------------------------------------------
// map_web_apps
// ---------------------------------------------------------------------------

#[test]
fn test_map_web_apps_basic() {
    let techs: &[&str] = &["React", "Node.js"];
    let data = vec![(
        "https://app.example.com",
        Some("My App"),
        techs,
        200u16,
        Some("nginx/1.21"),
    )];
    let apps = map_web_apps(&data);
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].url, "https://app.example.com");
    assert_eq!(apps[0].title.as_deref(), Some("My App"));
    assert_eq!(apps[0].technologies, vec!["React", "Node.js"]);
    assert_eq!(apps[0].status_code, 200);
    assert_eq!(apps[0].server_header.as_deref(), Some("nginx/1.21"));
    assert!(apps[0].content_type.is_none());
}

#[test]
fn test_map_web_apps_no_title_no_server() {
    let techs: &[&str] = &[];
    let data = vec![("https://bare.example.com", None, techs, 503u16, None)];
    let apps = map_web_apps(&data);
    assert!(apps[0].title.is_none());
    assert!(apps[0].server_header.is_none());
    assert!(apps[0].technologies.is_empty());
    assert_eq!(apps[0].status_code, 503);
}

// ---------------------------------------------------------------------------
// map_apis
// ---------------------------------------------------------------------------

#[test]
fn test_map_apis_rest() {
    let methods: &[&str] = &["GET", "POST"];
    let data = vec![(
        "https://api.example.com/v1",
        "rest",
        true,
        Some("https://docs.example.com"),
        methods,
    )];
    let apis = map_apis(&data);
    assert_eq!(apis.len(), 1);
    assert_eq!(apis[0].url, "https://api.example.com/v1");
    assert_eq!(apis[0].api_type, ApiType::Rest);
    assert!(apis[0].authenticated);
    assert_eq!(
        apis[0].documentation_url.as_deref(),
        Some("https://docs.example.com")
    );
    assert_eq!(apis[0].methods, vec!["GET", "POST"]);
}

#[test]
fn test_map_apis_graphql_unauthenticated() {
    let methods: &[&str] = &["POST"];
    let data = vec![(
        "https://gql.example.com/graphql",
        "graphql",
        false,
        None,
        methods,
    )];
    let apis = map_apis(&data);
    assert_eq!(apis[0].api_type, ApiType::GraphQL);
    assert!(!apis[0].authenticated);
    assert!(apis[0].documentation_url.is_none());
}

#[test]
fn test_map_apis_websocket() {
    let methods: &[&str] = &[];
    let data = vec![("wss://ws.example.com", "ws", false, None, methods)];
    let apis = map_apis(&data);
    assert_eq!(apis[0].api_type, ApiType::WebSocket);
}

#[test]
fn test_map_apis_unknown_type_defaults_to_rest() {
    let methods: &[&str] = &["GET"];
    let data = vec![("https://x.example.com", "thrift", false, None, methods)];
    let apis = map_apis(&data);
    assert_eq!(apis[0].api_type, ApiType::Rest);
}

// ---------------------------------------------------------------------------
// detect_cloud_assets
// ---------------------------------------------------------------------------

#[test]
fn test_detect_cloud_assets_s3_bucket() {
    let domains = vec![DiscoveredDomain {
        domain: "mybucket.s3.amazonaws.com".to_string(),
        domain_type: DomainType::Subdomain,
        ip_addresses: vec![],
        first_seen: None,
        source: DiscoverySource::DnsEnum,
    }];
    let assets = detect_cloud_assets(&domains, &[], &[]);
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0].provider, CloudProvider::Aws);
    assert_eq!(assets[0].asset_type, CloudAssetType::S3Bucket);
    assert_eq!(assets[0].identifier, "mybucket");
    assert!(assets[0].publicly_accessible);
}

#[test]
fn test_detect_cloud_assets_azure_blob() {
    let domains = vec![DiscoveredDomain {
        domain: "mystore.blob.core.windows.net".to_string(),
        domain_type: DomainType::Subdomain,
        ip_addresses: vec![],
        first_seen: None,
        source: DiscoverySource::CertTransparency,
    }];
    let assets = detect_cloud_assets(&domains, &[], &[]);
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0].provider, CloudProvider::Azure);
    assert_eq!(assets[0].asset_type, CloudAssetType::AzureBlob);
}

#[test]
fn test_detect_cloud_assets_gcp_storage() {
    let domains = vec![DiscoveredDomain {
        domain: "my-bucket.storage.googleapis.com".to_string(),
        domain_type: DomainType::Subdomain,
        ip_addresses: vec![],
        first_seen: None,
        source: DiscoverySource::DnsEnum,
    }];
    let assets = detect_cloud_assets(&domains, &[], &[]);
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0].provider, CloudProvider::Gcp);
    assert_eq!(assets[0].asset_type, CloudAssetType::GcpStorage);
}

#[test]
fn test_detect_cloud_assets_cloudfront_cdn() {
    let domains = vec![DiscoveredDomain {
        domain: "d1234abcd.cloudfront.net".to_string(),
        domain_type: DomainType::Subdomain,
        ip_addresses: vec![],
        first_seen: None,
        source: DiscoverySource::DnsEnum,
    }];
    let assets = detect_cloud_assets(&domains, &[], &[]);
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0].provider, CloudProvider::Aws);
    assert_eq!(assets[0].asset_type, CloudAssetType::CdnEndpoint);
}

#[test]
fn test_detect_cloud_assets_from_dns_cname() {
    let dns_records = vec![("cdn.example.com", "d999.cloudfront.net")];
    let assets = detect_cloud_assets(&[], &[], &dns_records);
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0].provider, CloudProvider::Aws);
    assert_eq!(assets[0].asset_type, CloudAssetType::CdnEndpoint);
}

#[test]
fn test_detect_cloud_assets_deduplicates() {
    let domains = vec![DiscoveredDomain {
        domain: "mybucket.s3.amazonaws.com".to_string(),
        domain_type: DomainType::Subdomain,
        ip_addresses: vec![],
        first_seen: None,
        source: DiscoverySource::DnsEnum,
    }];
    let dns_records = vec![("data.example.com", "mybucket.s3.amazonaws.com")];
    let assets = detect_cloud_assets(&domains, &[], &dns_records);
    assert_eq!(
        assets.len(),
        1,
        "duplicate identifier should be deduplicated"
    );
}

#[test]
fn test_detect_cloud_assets_database_from_banner() {
    let services = vec![ExposedService {
        ip: "10.0.0.5".to_string(),
        port: 5432,
        protocol: ServiceProtocol::Postgres,
        service_name: None,
        version: None,
        banner: Some("PostgreSQL on RDS".to_string()),
        tls_enabled: false,
    }];
    let assets = detect_cloud_assets(&[], &services, &[]);
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0].provider, CloudProvider::Aws);
    assert_eq!(assets[0].asset_type, CloudAssetType::Database);
    assert_eq!(assets[0].identifier, "10.0.0.5:5432");
}

#[test]
fn test_detect_cloud_assets_no_match() {
    let domains = vec![DiscoveredDomain {
        domain: "internal.corp.local".to_string(),
        domain_type: DomainType::Primary,
        ip_addresses: vec![],
        first_seen: None,
        source: DiscoverySource::DnsEnum,
    }];
    let assets = detect_cloud_assets(&domains, &[], &[]);
    assert!(assets.is_empty());
}

#[test]
fn test_detect_cloud_assets_azure_functions() {
    let domains = vec![DiscoveredDomain {
        domain: "my-func.azurewebsites.net".to_string(),
        domain_type: DomainType::Subdomain,
        ip_addresses: vec![],
        first_seen: None,
        source: DiscoverySource::DnsEnum,
    }];
    let assets = detect_cloud_assets(&domains, &[], &[]);
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0].provider, CloudProvider::Azure);
    assert_eq!(assets[0].asset_type, CloudAssetType::FunctionEndpoint);
}

#[test]
fn test_detect_cloud_assets_vercel_static_site() {
    let domains = vec![DiscoveredDomain {
        domain: "mysite.vercel.app".to_string(),
        domain_type: DomainType::Subdomain,
        ip_addresses: vec![],
        first_seen: None,
        source: DiscoverySource::WebCrawl,
    }];
    let assets = detect_cloud_assets(&domains, &[], &[]);
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0].asset_type, CloudAssetType::StaticSite);
    assert_eq!(
        assets[0].provider,
        CloudProvider::Other("Vercel".to_string())
    );
}

// ---------------------------------------------------------------------------
// detect_shadow_it
// ---------------------------------------------------------------------------

#[test]
fn test_detect_shadow_it_flags_unofficial_domain() {
    let official = &["example.com"];
    let all_domains = vec![DiscoveredDomain {
        domain: "rogue.io".to_string(),
        domain_type: DomainType::Primary,
        ip_addresses: vec![],
        first_seen: None,
        source: DiscoverySource::Censys,
    }];
    let shadow = detect_shadow_it(official, &all_domains, &[]);
    assert_eq!(shadow.len(), 1);
    assert_eq!(shadow[0].identifier, "rogue.io");
    assert_eq!(shadow[0].risk, ShadowItRisk::High);
}

#[test]
fn test_detect_shadow_it_ignores_official_subdomain() {
    let official = &["example.com"];
    let all_domains = vec![DiscoveredDomain {
        domain: "api.example.com".to_string(),
        domain_type: DomainType::Subdomain,
        ip_addresses: vec![],
        first_seen: None,
        source: DiscoverySource::DnsEnum,
    }];
    let shadow = detect_shadow_it(official, &all_domains, &[]);
    assert!(shadow.is_empty());
}

#[test]
fn test_detect_shadow_it_ignores_exact_official_match() {
    let official = &["example.com"];
    let all_domains = vec![DiscoveredDomain {
        domain: "example.com".to_string(),
        domain_type: DomainType::Primary,
        ip_addresses: vec![],
        first_seen: None,
        source: DiscoverySource::DnsEnum,
    }];
    let shadow = detect_shadow_it(official, &all_domains, &[]);
    assert!(shadow.is_empty());
}

#[test]
fn test_detect_shadow_it_wildcard_is_critical() {
    let official = &["example.com"];
    let all_domains = vec![DiscoveredDomain {
        domain: "*.rogue.io".to_string(),
        domain_type: DomainType::Wildcard,
        ip_addresses: vec![],
        first_seen: None,
        source: DiscoverySource::BruteForce,
    }];
    let shadow = detect_shadow_it(official, &all_domains, &[]);
    assert_eq!(shadow.len(), 1);
    assert_eq!(shadow[0].risk, ShadowItRisk::Critical);
}

#[test]
fn test_detect_shadow_it_cloud_asset_not_matching_official() {
    let official = &["example.com"];
    let cloud_assets = vec![CloudAsset {
        provider: CloudProvider::Aws,
        asset_type: CloudAssetType::S3Bucket,
        identifier: "rogue-bucket".to_string(),
        url: Some("rogue-bucket.s3.amazonaws.com".to_string()),
        publicly_accessible: true,
        region: None,
    }];
    let shadow = detect_shadow_it(official, &[], &cloud_assets);
    assert_eq!(shadow.len(), 1);
    assert_eq!(shadow[0].risk, ShadowItRisk::High);
}

#[test]
fn test_detect_shadow_it_cloud_asset_matching_official_not_flagged() {
    let official = &["example.com"];
    let cloud_assets = vec![CloudAsset {
        provider: CloudProvider::Aws,
        asset_type: CloudAssetType::S3Bucket,
        identifier: "example.com".to_string(),
        url: None,
        publicly_accessible: true,
        region: None,
    }];
    let shadow = detect_shadow_it(official, &[], &cloud_assets);
    assert!(shadow.is_empty());
}

// ---------------------------------------------------------------------------
// calculate_attack_surface_score
// ---------------------------------------------------------------------------

#[test]
fn test_calculate_attack_surface_score_empty_report() {
    let report = AttackSurfaceReport {
        domain: "example.com".to_string(),
        ip_ranges: vec![],
        domains: vec![],
        services: vec![],
        web_apps: vec![],
        apis: vec![],
        cloud_assets: vec![],
        shadow_it: vec![],
        total_attack_surface_score: 0.0,
        summary: AttackSurfaceSummary {
            total_ips: 0,
            total_domains: 0,
            total_services: 0,
            total_web_apps: 0,
            total_apis: 0,
            total_cloud_assets: 0,
            high_risk_count: 0,
        },
    };
    let score = calculate_attack_surface_score(&report);
    assert!((score - 0.0).abs() < f64::EPSILON);
}

#[test]
fn test_calculate_attack_surface_score_high_risk_services() {
    let mut report = AttackSurfaceReport {
        domain: "example.com".to_string(),
        ip_ranges: vec![],
        domains: vec![],
        services: vec![],
        web_apps: vec![],
        apis: vec![],
        cloud_assets: vec![],
        shadow_it: vec![],
        total_attack_surface_score: 0.0,
        summary: AttackSurfaceSummary {
            total_ips: 0,
            total_domains: 0,
            total_services: 0,
            total_web_apps: 0,
            total_apis: 0,
            total_cloud_assets: 0,
            high_risk_count: 0,
        },
    };
    for port in &[22u16, 3389, 5432, 6379, 27017] {
        report.services.push(ExposedService {
            ip: "10.0.0.1".to_string(),
            port: *port,
            protocol: ServiceProtocol::Ssh,
            service_name: None,
            version: None,
            banner: None,
            tls_enabled: false,
        });
    }
    let score = calculate_attack_surface_score(&report);
    // 5 services → service_score = (5/50)*0.25 = 0.025
    // 5 high-risk ports → high_risk_score = (5/10)*0.25 = 0.125
    // total raw = 0.15 → rounded = 0.15
    assert!(score > 0.0);
    assert!(score <= 1.0);
    let expected: f64 = ((5.0 / 50.0) * 0.25 + (5.0 / 10.0) * 0.25) * 100.0;
    let expected_rounded = expected.round() / 100.0;
    assert!((score - expected_rounded).abs() < f64::EPSILON);
}

#[test]
fn test_calculate_attack_surface_score_bounded_by_one() {
    let mut report = AttackSurfaceReport {
        domain: "example.com".to_string(),
        ip_ranges: vec![],
        domains: vec![],
        services: vec![],
        web_apps: vec![],
        apis: vec![],
        cloud_assets: vec![],
        shadow_it: vec![],
        total_attack_surface_score: 0.0,
        summary: AttackSurfaceSummary {
            total_ips: 0,
            total_domains: 0,
            total_services: 0,
            total_web_apps: 0,
            total_apis: 0,
            total_cloud_assets: 0,
            high_risk_count: 0,
        },
    };
    // Saturate every component well past its cap
    for i in 0..100 {
        report.services.push(ExposedService {
            ip: format!("10.0.0.{}", i % 256),
            port: 22,
            protocol: ServiceProtocol::Ssh,
            service_name: None,
            version: None,
            banner: None,
            tls_enabled: false,
        });
    }
    for _ in 0..20 {
        report.cloud_assets.push(CloudAsset {
            provider: CloudProvider::Aws,
            asset_type: CloudAssetType::S3Bucket,
            identifier: "x".to_string(),
            url: None,
            publicly_accessible: true,
            region: None,
        });
    }
    for _ in 0..10 {
        report.shadow_it.push(ShadowItAsset {
            asset_type: "domain".to_string(),
            identifier: "rogue".to_string(),
            evidence: "test".to_string(),
            risk: ShadowItRisk::High,
        });
    }
    let score = calculate_attack_surface_score(&report);
    assert!((score - 1.0).abs() < f64::EPSILON);
}

// ---------------------------------------------------------------------------
// map_attack_surface (full pipeline)
// ---------------------------------------------------------------------------

#[test]
fn test_map_attack_surface_empty_inputs() {
    let report = map_attack_surface("example.com", &[], &[], &[], &[], &[], &[], &[]);
    assert_eq!(report.domain, "example.com");
    assert!(report.ip_ranges.is_empty());
    assert!(report.domains.is_empty());
    assert!(report.services.is_empty());
    assert!(report.web_apps.is_empty());
    assert!(report.apis.is_empty());
    assert!(report.cloud_assets.is_empty());
    assert!(report.shadow_it.is_empty());
    assert!((report.total_attack_surface_score - 0.0).abs() < f64::EPSILON);
    assert_eq!(report.summary.total_ips, 0);
    assert_eq!(report.summary.high_risk_count, 0);
}

#[test]
fn test_map_attack_surface_full_pipeline() {
    let ip_data = vec![("10.0.0.0/24", Some(1234u32), Some("TestOrg"), Some("US"))];

    let domain_ips: &[&str] = &["10.0.0.1"];
    let domain_data = vec![(
        "example.com",
        "primary",
        domain_ips,
        Some("2024-01-01"),
        "dns_enum",
    )];

    let service_data = vec![
        ("10.0.0.1", 80u16, "http", Some("nginx"), None, None, false),
        ("10.0.0.1", 443u16, "https", None, None, None, true),
        ("10.0.0.1", 22u16, "ssh", None, None, None, false),
    ];

    let techs: &[&str] = &["Express"];
    let web_apps = vec![(
        "https://example.com",
        Some("Home"),
        techs,
        200u16,
        Some("nginx"),
    )];

    let methods: &[&str] = &["GET", "POST"];
    let api_data = vec![("https://api.example.com/v1", "rest", true, None, methods)];

    let dns_records: Vec<(&str, &str)> = vec![];
    let official_domains = &["example.com"];

    let report = map_attack_surface(
        "example.com",
        &ip_data,
        &domain_data,
        &service_data,
        &web_apps,
        &api_data,
        &dns_records,
        official_domains,
    );

    assert_eq!(report.domain, "example.com");
    assert_eq!(report.ip_ranges.len(), 1);
    assert_eq!(report.domains.len(), 1);
    assert_eq!(report.services.len(), 3);
    assert_eq!(report.web_apps.len(), 1);
    assert_eq!(report.apis.len(), 1);
    assert_eq!(report.summary.total_ips, 256);
    assert_eq!(report.summary.total_domains, 1);
    assert_eq!(report.summary.total_services, 3);
    assert_eq!(report.summary.total_web_apps, 1);
    assert_eq!(report.summary.total_apis, 1);
    assert!(report.total_attack_surface_score >= 0.0);
    assert!(report.total_attack_surface_score <= 1.0);
}

#[test]
fn test_map_attack_surface_detects_cloud_from_domains() {
    let domain_ips: &[&str] = &[];
    let domain_data = vec![(
        "assets.s3.amazonaws.com",
        "subdomain",
        domain_ips,
        None,
        "dns_enum",
    )];

    let report = map_attack_surface("example.com", &[], &domain_data, &[], &[], &[], &[], &[]);
    assert_eq!(report.cloud_assets.len(), 1);
    assert_eq!(report.cloud_assets[0].provider, CloudProvider::Aws);
    assert_eq!(report.cloud_assets[0].asset_type, CloudAssetType::S3Bucket);
    assert_eq!(report.summary.total_cloud_assets, 1);
}

#[test]
fn test_map_attack_surface_detects_shadow_it() {
    let domain_ips: &[&str] = &[];
    let domain_data = vec![
        ("example.com", "primary", domain_ips, None, "dns_enum"),
        ("rogue-shadow.io", "primary", domain_ips, None, "censys"),
    ];
    let official_domains = &["example.com"];

    let report = map_attack_surface(
        "example.com",
        &[],
        &domain_data,
        &[],
        &[],
        &[],
        &[],
        official_domains,
    );
    assert!(!report.shadow_it.is_empty());
    assert!(
        report
            .shadow_it
            .iter()
            .any(|s| s.identifier == "rogue-shadow.io")
    );
}

#[test]
fn test_map_attack_surface_summary_counts_high_risk() {
    let service_data = vec![
        ("10.0.0.1", 22u16, "ssh", None, None, None, false),
        ("10.0.0.1", 3389u16, "rdp", None, None, None, false),
        ("10.0.0.1", 80u16, "http", None, None, None, false),
    ];

    let report = map_attack_surface("example.com", &[], &[], &service_data, &[], &[], &[], &[]);
    // ports 22 and 3389 are high-risk; port 80 is not
    assert_eq!(report.summary.high_risk_count, 2);
}
