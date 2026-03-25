use super::ssrf_payloads::*;

#[test]
fn test_total_payload_count() {
    assert!(
        ssrf_payload_count() >= 140,
        "Expected 140+ SSRF payloads, got {}",
        ssrf_payload_count()
    );
}

#[test]
fn test_all_categories_covered() {
    for cat in SsrfCategory::all() {
        let payloads = ssrf_payloads_by_category(*cat);
        assert!(!payloads.is_empty(), "No payloads for category {:?}", cat);
    }
}

#[test]
fn test_ip_format_payloads_comprehensive() {
    let ip = ssrf_payloads_by_category(SsrfCategory::IpFormatBypass);
    assert!(
        ip.len() >= 20,
        "Expected 20+ IP format payloads, got {}",
        ip.len()
    );
    let has_decimal = ip.iter().any(|p| p.payload.contains("2130706433"));
    let has_hex = ip.iter().any(|p| p.payload.contains("0x7f"));
    let has_octal = ip.iter().any(|p| p.payload.contains("0177"));
    let has_ipv6 = ip.iter().any(|p| p.payload.contains("[::1]"));
    assert!(has_decimal, "Should have decimal IP representation");
    assert!(has_hex, "Should have hex IP representation");
    assert!(has_octal, "Should have octal IP representation");
    assert!(has_ipv6, "Should have IPv6 representation");
}

#[test]
fn test_dns_rebinding_payloads() {
    let dns = ssrf_payloads_by_category(SsrfCategory::DnsRebinding);
    assert!(
        dns.len() >= 5,
        "Expected 5+ DNS rebinding payloads, got {}",
        dns.len()
    );
}

#[test]
fn test_url_parser_confusion_payloads() {
    let parser = ssrf_payloads_by_category(SsrfCategory::UrlParserConfusion);
    assert!(
        parser.len() >= 15,
        "Expected 15+ URL parser payloads, got {}",
        parser.len()
    );
    let has_at = parser.iter().any(|p| p.payload.contains('@'));
    assert!(
        has_at,
        "URL parser confusion should include @ symbol tricks"
    );
}

#[test]
fn test_protocol_smuggling_payloads() {
    let proto = ssrf_payloads_by_category(SsrfCategory::ProtocolSmuggling);
    assert!(
        proto.len() >= 15,
        "Expected 15+ protocol smuggling payloads, got {}",
        proto.len()
    );
    let has_gopher = proto.iter().any(|p| p.payload.starts_with("gopher://"));
    let has_file = proto.iter().any(|p| p.payload.starts_with("file://"));
    let has_dict = proto.iter().any(|p| p.payload.starts_with("dict://"));
    assert!(has_gopher, "Should have gopher:// payloads");
    assert!(has_file, "Should have file:// payloads");
    assert!(has_dict, "Should have dict:// payloads");
}

#[test]
fn test_cloud_metadata_payloads() {
    let cloud = ssrf_payloads_by_category(SsrfCategory::CloudMetadata);
    assert!(
        cloud.len() >= 20,
        "Expected 20+ cloud metadata payloads, got {}",
        cloud.len()
    );
}

#[test]
fn test_aws_metadata_payloads() {
    let aws = ssrf_payloads_by_cloud(CloudProvider::Aws);
    assert!(
        aws.len() >= 5,
        "Expected 5+ AWS payloads, got {}",
        aws.len()
    );
    let has_imds = aws.iter().any(|p| p.payload.contains("169.254.169.254"));
    assert!(has_imds, "AWS payloads should target IMDS endpoint");
}

#[test]
fn test_gcp_metadata_payloads() {
    let gcp = ssrf_payloads_by_cloud(CloudProvider::Gcp);
    assert!(
        gcp.len() >= 3,
        "Expected 3+ GCP payloads, got {}",
        gcp.len()
    );
    let has_google_internal = gcp
        .iter()
        .any(|p| p.payload.contains("metadata.google.internal"));
    assert!(
        has_google_internal,
        "GCP payloads should target metadata.google.internal"
    );
}

#[test]
fn test_azure_metadata_payloads() {
    let azure = ssrf_payloads_by_cloud(CloudProvider::Azure);
    assert!(
        azure.len() >= 2,
        "Expected 2+ Azure payloads, got {}",
        azure.len()
    );
}

#[test]
fn test_internal_service_discovery() {
    let services = ssrf_payloads_by_category(SsrfCategory::InternalServiceDiscovery);
    assert!(
        services.len() >= 20,
        "Expected 20+ internal service payloads, got {}",
        services.len()
    );
    let has_redis = services.iter().any(|p| p.payload.contains("6379"));
    let has_es = services.iter().any(|p| p.payload.contains("9200"));
    let has_docker = services.iter().any(|p| p.payload.contains("2375"));
    assert!(has_redis, "Should probe Redis port");
    assert!(has_es, "Should probe Elasticsearch port");
    assert!(has_docker, "Should probe Docker API port");
}

#[test]
fn test_redirect_bypass_payloads() {
    let redirect = ssrf_payloads_by_category(SsrfCategory::RedirectBypass);
    assert!(
        redirect.len() >= 5,
        "Expected 5+ redirect payloads, got {}",
        redirect.len()
    );
}

#[test]
fn test_no_empty_payloads() {
    for payload in all_ssrf_payloads() {
        assert!(!payload.payload.is_empty(), "Empty payload found");
        assert!(
            !payload.description.is_empty(),
            "Empty description for payload: {}",
            payload.payload
        );
    }
}

#[test]
fn test_digitalocean_payloads() {
    let dgo = ssrf_payloads_by_cloud(CloudProvider::DigitalOcean);
    assert!(
        dgo.len() >= 2,
        "Expected 2+ DigitalOcean payloads, got {}",
        dgo.len()
    );
}

#[test]
fn test_alibaba_payloads() {
    let ali = ssrf_payloads_by_cloud(CloudProvider::Alibaba);
    assert!(
        ali.len() >= 2,
        "Expected 2+ Alibaba payloads, got {}",
        ali.len()
    );
}
