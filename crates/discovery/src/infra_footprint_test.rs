use super::infra_footprint::*;

#[test]
fn test_generate_infra_queries_domain() {
    let queries = generate_infra_queries(&["example.com"], &[], None);
    assert!(!queries.is_empty());
    assert!(queries
        .iter()
        .any(|q| q.query.contains("hostname:example.com")));
    assert!(queries.iter().any(|q| q.query.contains("ssl.cert")));
    assert!(queries
        .iter()
        .any(|q| q.expected_results == QueryResultType::Databases));
    assert!(queries
        .iter()
        .any(|q| q.expected_results == QueryResultType::SshServers));
}

#[test]
fn test_generate_infra_queries_ip_range() {
    let queries = generate_infra_queries(&[], &["10.0.0.0/24"], None);
    assert!(queries.iter().any(|q| q.query.contains("net:10.0.0.0/24")));
}

#[test]
fn test_generate_infra_queries_org_name() {
    let queries = generate_infra_queries(&[], &[], Some("Acme Corp"));
    assert!(queries
        .iter()
        .any(|q| q.query.contains("org:\"Acme Corp\"")));
}

#[test]
fn test_generate_infra_queries_multiple_domains() {
    let queries = generate_infra_queries(&["a.com", "b.com"], &[], None);
    assert!(queries.iter().any(|q| q.query.contains("a.com")));
    assert!(queries.iter().any(|q| q.query.contains("b.com")));
}

#[test]
fn test_generate_infra_queries_engines() {
    let queries = generate_infra_queries(&["test.com"], &[], None);
    assert!(queries.iter().any(|q| q.engine == SearchEngine::Shodan));
    assert!(queries.iter().any(|q| q.engine == SearchEngine::Censys));
}

#[test]
fn test_parse_service_inventory() {
    let entries = vec![
        (
            "192.168.1.1",
            80_u16,
            "open",
            "http",
            Some("nginx"),
            Some("1.21"),
        ),
        (
            "192.168.1.1",
            443,
            "open",
            "https",
            Some("nginx"),
            Some("1.21"),
        ),
        (
            "192.168.1.1",
            22,
            "open",
            "ssh",
            Some("OpenSSH"),
            Some("8.9"),
        ),
        ("192.168.1.2", 3306, "filtered", "mysql", None, None),
    ];
    let services = parse_service_inventory(&entries);
    assert_eq!(services.len(), 4);
    assert_eq!(services[0].port, 80);
    assert_eq!(services[0].state, PortState::Open);
    assert_eq!(services[0].product, Some("nginx".to_string()));
    assert_eq!(services[3].state, PortState::Filtered);
}

#[test]
fn test_generate_cloud_asset_candidates() {
    let assets = generate_cloud_asset_candidates("Acme Corp", &["acme.com"]);
    assert!(!assets.is_empty());

    let s3_assets: Vec<_> = assets
        .iter()
        .filter(|a| a.asset_type == CloudAssetType::S3Bucket)
        .collect();
    let azure_assets: Vec<_> = assets
        .iter()
        .filter(|a| a.asset_type == CloudAssetType::AzureBlob)
        .collect();
    let gcp_assets: Vec<_> = assets
        .iter()
        .filter(|a| a.asset_type == CloudAssetType::GcpStorage)
        .collect();

    assert!(!s3_assets.is_empty());
    assert!(!azure_assets.is_empty());
    assert!(!gcp_assets.is_empty());

    assert!(s3_assets.iter().any(|a| a.url.contains("acme-corp")));
    assert!(s3_assets.iter().any(|a| a.url.contains("acme-corp-prod")));
    assert!(s3_assets.iter().any(|a| a.url.contains("acme-corp-backup")));
}

#[test]
fn test_generate_cloud_asset_domain_variants() {
    let assets = generate_cloud_asset_candidates("TestCo", &["testco.io", "testco.com"]);
    let names: Vec<_> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(names.contains(&"testco"));
    assert!(names.contains(&"testco-assets"));
}

#[test]
fn test_detect_cdn_from_headers_cloudflare() {
    let headers = vec![("server", "cloudflare"), ("cf-ray", "abc123-LAX")];
    let mappings = detect_cdn(&headers, &[]);
    assert!(mappings.iter().any(|m| m.cdn_provider == "Cloudflare"));
}

#[test]
fn test_detect_cdn_from_headers_cloudfront() {
    let headers = vec![("x-amz-cf-id", "abc123")];
    let mappings = detect_cdn(&headers, &[]);
    assert!(mappings.iter().any(|m| m.cdn_provider == "AWS CloudFront"));
}

#[test]
fn test_detect_cdn_from_cname() {
    let cnames = vec![
        ("cdn.example.com", "d123.cloudfront.net"),
        ("static.example.com", "example.b-cdn.net"),
    ];
    let mappings = detect_cdn(&[], &cnames);
    assert!(mappings.iter().any(|m| m.cdn_provider == "AWS CloudFront"));
    assert!(mappings.iter().any(|m| m.cdn_provider == "BunnyCDN"));
}

#[test]
fn test_detect_cdn_from_fastly() {
    let headers = vec![("x-served-by", "cache-lax12345")];
    let mappings = detect_cdn(&headers, &[]);
    assert!(mappings.iter().any(|m| m.cdn_provider == "Fastly"));
}

#[test]
fn test_parse_spf_includes() {
    let spf = "v=spf1 include:_spf.google.com include:sendgrid.net include:servers.mcsv.net ~all";
    let includes = parse_spf_includes(spf);
    assert_eq!(includes.len(), 3);
    assert!(includes.contains(&"_spf.google.com".to_string()));
    assert!(includes.contains(&"sendgrid.net".to_string()));
    assert!(includes.contains(&"servers.mcsv.net".to_string()));
}

#[test]
fn test_parse_spf_includes_empty() {
    let includes = parse_spf_includes("v=spf1 -all");
    assert!(includes.is_empty());
}

#[test]
fn test_parse_dmarc_record_reject() {
    let dmarc = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100";
    let policy = parse_dmarc_record(dmarc);
    assert!(policy.is_some());
    let p = policy.unwrap();
    assert_eq!(p.policy, DmarcAction::Reject);
    assert_eq!(p.pct, 100);
    assert_eq!(p.rua, Some("dmarc@example.com".to_string()));
}

#[test]
fn test_parse_dmarc_record_quarantine() {
    let dmarc = "v=DMARC1; p=quarantine; sp=reject; pct=50; ruf=mailto:forensics@test.com";
    let policy = parse_dmarc_record(dmarc).unwrap();
    assert_eq!(policy.policy, DmarcAction::Quarantine);
    assert_eq!(policy.subdomain_policy, Some(DmarcAction::Reject));
    assert_eq!(policy.pct, 50);
    assert_eq!(policy.ruf, Some("forensics@test.com".to_string()));
}

#[test]
fn test_parse_dmarc_record_none() {
    let dmarc = "v=DMARC1; p=none";
    let policy = parse_dmarc_record(dmarc).unwrap();
    assert_eq!(policy.policy, DmarcAction::None);
}

#[test]
fn test_parse_dmarc_record_invalid() {
    let policy = parse_dmarc_record("not a dmarc record");
    assert!(policy.is_none());
}

#[test]
fn test_identify_email_provider_google() {
    let provider = identify_email_provider(&["aspmx.l.google.com", "alt1.aspmx.l.google.com"]);
    assert_eq!(provider, Some("Google Workspace".to_string()));
}

#[test]
fn test_identify_email_provider_microsoft() {
    let provider = identify_email_provider(&["example-com.mail.protection.outlook.com"]);
    assert_eq!(provider, Some("Microsoft 365".to_string()));
}

#[test]
fn test_identify_email_provider_protonmail() {
    let provider = identify_email_provider(&["mail.protonmail.ch"]);
    assert_eq!(provider, Some("ProtonMail".to_string()));
}

#[test]
fn test_identify_email_provider_unknown() {
    let provider = identify_email_provider(&["mx.custom-server.example.com"]);
    assert!(provider.is_none());
}

#[test]
fn test_identify_dns_provider_cloudflare() {
    let provider = identify_dns_provider(&["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]);
    assert_eq!(provider, Some("Cloudflare".to_string()));
}

#[test]
fn test_identify_dns_provider_aws() {
    let provider = identify_dns_provider(&["ns-1234.awsdns-56.co.uk"]);
    assert_eq!(provider, Some("AWS Route 53".to_string()));
}

#[test]
fn test_identify_dns_provider_unknown() {
    let provider = identify_dns_provider(&["ns1.custom.example.com"]);
    assert!(provider.is_none());
}

#[test]
fn test_build_infra_footprint_basic() {
    let services = vec![
        ParsedService {
            host: "1.2.3.4".to_string(),
            port: 80,
            protocol: "tcp".to_string(),
            service_name: Some("http".to_string()),
            product: None,
            version: None,
            state: PortState::Open,
            cpe: None,
        },
        ParsedService {
            host: "1.2.3.4".to_string(),
            port: 443,
            protocol: "tcp".to_string(),
            service_name: Some("https".to_string()),
            product: None,
            version: None,
            state: PortState::Open,
            cpe: None,
        },
    ];
    let email_infra = EmailInfrastructure {
        mx_records: vec![],
        spf_record: None,
        spf_includes: vec![],
        dmarc_policy: None,
        dkim_selectors: vec![],
        email_provider: None,
    };
    let dns_infra = DnsInfrastructure {
        nameservers: vec![],
        has_dnssec: false,
        zone_transfer_possible: false,
        registrar: None,
        dns_provider: None,
    };
    let footprint = build_infra_footprint(
        "example.com",
        vec![],
        services,
        vec![],
        vec![],
        vec![],
        email_infra,
        dns_infra,
        vec![],
    );
    assert_eq!(footprint.total_services, 2);
    assert_eq!(footprint.total_open_ports, 2);
    assert!(footprint.exposure_score > 0.0);
}

#[test]
fn test_build_infra_footprint_secure() {
    let email_infra = EmailInfrastructure {
        mx_records: vec![],
        spf_record: None,
        spf_includes: vec![],
        dmarc_policy: Some(DmarcPolicy {
            policy: DmarcAction::Reject,
            subdomain_policy: Some(DmarcAction::Reject),
            pct: 100,
            rua: None,
            ruf: None,
        }),
        dkim_selectors: vec![],
        email_provider: None,
    };
    let dns_infra = DnsInfrastructure {
        nameservers: vec![],
        has_dnssec: true,
        zone_transfer_possible: false,
        registrar: None,
        dns_provider: None,
    };
    let footprint = build_infra_footprint(
        "secure.com",
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        email_infra,
        dns_infra,
        vec![],
    );
    assert!(footprint.exposure_score < 5.0);
}

#[test]
fn test_search_engine_display() {
    assert_eq!(SearchEngine::Shodan.to_string(), "Shodan");
    assert_eq!(SearchEngine::Censys.to_string(), "Censys");
}

#[test]
fn test_port_state_display() {
    assert_eq!(PortState::Open.to_string(), "open");
    assert_eq!(PortState::Filtered.to_string(), "filtered");
}

#[test]
fn test_cloud_asset_type_display() {
    assert_eq!(CloudAssetType::S3Bucket.to_string(), "S3 Bucket");
    assert_eq!(CloudAssetType::AzureBlob.to_string(), "Azure Blob");
}

#[test]
fn test_cloud_provider_display() {
    assert_eq!(CloudProvider::Aws.to_string(), "AWS");
    assert_eq!(CloudProvider::Gcp.to_string(), "GCP");
}

#[test]
fn test_dmarc_action_display() {
    assert_eq!(DmarcAction::Reject.to_string(), "reject");
    assert_eq!(DmarcAction::Quarantine.to_string(), "quarantine");
}

#[test]
fn test_historical_record_type_display() {
    assert_eq!(HistoricalRecordType::ARecord.to_string(), "A Record");
    assert_eq!(HistoricalRecordType::WaybackUrl.to_string(), "Wayback URL");
}

#[test]
fn test_query_result_type_display() {
    assert_eq!(QueryResultType::WebServers.to_string(), "Web Servers");
    assert_eq!(QueryResultType::Databases.to_string(), "Databases");
}
