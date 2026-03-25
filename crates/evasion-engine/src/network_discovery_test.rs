use super::network_discovery::*;
use std::net::Ipv4Addr;

#[test]
fn internal_ip_scan_class_a() {
    let gen = NetworkDiscoveryGenerator::new();
    let payloads = gen.internal_ip_scan(InternalRange::ClassA);

    assert!(!payloads.is_empty());
    for p in &payloads {
        assert_eq!(p.technique, NetworkDiscoveryTechnique::InternalIpScan);
        assert!(p.target_url.contains("10."));
        assert_eq!(p.method, "GET");
    }
}

#[test]
fn internal_ip_scan_class_c() {
    let gen = NetworkDiscoveryGenerator::new();
    let payloads = gen.internal_ip_scan(InternalRange::ClassC);

    assert!(!payloads.is_empty());
    assert!(payloads.iter().all(|p| p.target_url.contains("192.168.")));
}

#[test]
fn scan_all_internal_ranges_covers_every_class() {
    let gen = NetworkDiscoveryGenerator::new();
    let payloads = gen.scan_all_internal_ranges();

    assert!(payloads.iter().any(|p| p.target_url.contains("10.")));
    assert!(payloads.iter().any(|p| p.target_url.contains("172.")));
    assert!(payloads.iter().any(|p| p.target_url.contains("192.168.")));
    assert!(payloads.iter().any(|p| p.target_url.contains("169.254.")));
    assert!(payloads.iter().any(|p| p.target_url.contains("127.0.0.1")));
}

#[test]
fn vlan_hopping_generates_four_techniques() {
    let gen = NetworkDiscoveryGenerator::new();
    let payloads = gen.vlan_hopping(200);

    assert_eq!(payloads.len(), 4);
    assert!(payloads
        .iter()
        .all(|p| p.technique == NetworkDiscoveryTechnique::VlanHopping));
    assert!(payloads[0]
        .body
        .as_ref()
        .unwrap()
        .contains("Double-tagging"));
    assert!(payloads[0].body.as_ref().unwrap().contains("200"));
    assert!(payloads[1].body.as_ref().unwrap().contains("DTP"));
    assert!(payloads[2].body.as_ref().unwrap().contains("MAC flood"));
    assert!(payloads[3].body.as_ref().unwrap().contains("ARP"));
}

#[test]
fn ssrf_segmentation_test_with_bypass_patterns() {
    let gen = NetworkDiscoveryGenerator::new();
    let payloads = gen.ssrf_segmentation_test(Ipv4Addr::new(10, 0, 0, 5), &[80, 443]);

    assert!(payloads.len() >= 4 + 5);
    let bypass_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.description.contains("bypass"))
        .collect();
    assert_eq!(
        bypass_payloads.len(),
        5,
        "should have 5 SSRF bypass variants"
    );
    assert!(bypass_payloads.iter().any(|p| p.description.contains("0x")));
    assert!(bypass_payloads
        .iter()
        .any(|p| p.description.contains("xip.io")));
    assert!(bypass_payloads
        .iter()
        .any(|p| p.description.contains("::ffff")));
}

#[test]
fn lateral_movement_proxy_payloads() {
    let gen = NetworkDiscoveryGenerator::new();
    let targets = vec![Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3)];
    let payloads = gen.lateral_movement_proxy(Ipv4Addr::new(10, 0, 0, 1), &targets);

    assert!(!payloads.is_empty());
    assert!(payloads
        .iter()
        .all(|p| p.technique == NetworkDiscoveryTechnique::LateralMovementProxy));
    assert!(payloads.iter().all(|p| p.method == "CONNECT"));
    assert!(payloads.iter().any(|p| p.target_url.contains("10.0.0.2")));
    assert!(payloads.iter().any(|p| p.target_url.contains("10.0.0.3")));
}

#[test]
fn cloud_metadata_all_providers() {
    let gen = NetworkDiscoveryGenerator::new();
    let payloads = gen.cloud_metadata_probes();

    assert!(
        payloads.len() >= 15,
        "should cover all cloud provider endpoints"
    );
    assert!(payloads
        .iter()
        .all(|p| p.technique == NetworkDiscoveryTechnique::CloudMetadataProbe));

    let descriptions: Vec<_> = payloads.iter().map(|p| &p.description).collect();
    assert!(descriptions.iter().any(|d| d.contains("Aws")));
    assert!(descriptions.iter().any(|d| d.contains("Gcp")));
    assert!(descriptions.iter().any(|d| d.contains("Azure")));
    assert!(descriptions.iter().any(|d| d.contains("DigitalOcean")));
    assert!(descriptions.iter().any(|d| d.contains("Oracle")));
    assert!(descriptions.iter().any(|d| d.contains("Alibaba")));
}

#[test]
fn cloud_metadata_gcp_has_metadata_flavor_header() {
    let gen = NetworkDiscoveryGenerator::new();
    let payloads = gen.cloud_metadata_probes();
    let gcp_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.description.contains("Gcp"))
        .collect();

    assert!(!gcp_payloads.is_empty());
    for p in &gcp_payloads {
        assert!(p
            .headers
            .iter()
            .any(|(k, v)| k == "Metadata-Flavor" && v == "Google"));
    }
}

#[test]
fn cloud_metadata_azure_has_metadata_header() {
    let gen = NetworkDiscoveryGenerator::new();
    let payloads = gen.cloud_metadata_probes();
    let azure_payloads: Vec<_> = payloads
        .iter()
        .filter(|p| p.description.contains("Azure"))
        .collect();

    assert!(!azure_payloads.is_empty());
    for p in &azure_payloads {
        assert!(p
            .headers
            .iter()
            .any(|(k, v)| k == "Metadata" && v == "true"));
    }
}

#[test]
fn service_enumeration_covers_all_ports() {
    let gen = NetworkDiscoveryGenerator::new();
    let payloads = gen.service_enumeration(Ipv4Addr::new(10, 0, 0, 1));

    assert_eq!(payloads.len(), ServicePort::all().len());
    assert!(payloads
        .iter()
        .any(|p| p.description.contains("6379") && p.description.contains("Redis")));
    assert!(payloads
        .iter()
        .any(|p| p.description.contains("9200") && p.description.contains("Elasticsearch")));
    assert!(payloads
        .iter()
        .any(|p| p.description.contains("2375") && p.description.contains("Docker")));
}

#[test]
fn dns_based_discovery_common_names() {
    let gen = NetworkDiscoveryGenerator::new();
    let payloads = gen.dns_based_discovery("corp.local");

    assert!(payloads.len() >= 40);
    assert!(payloads
        .iter()
        .all(|p| p.technique == NetworkDiscoveryTechnique::DnsBased));
    assert!(payloads
        .iter()
        .any(|p| p.description.contains("intranet.corp.local")));
    assert!(payloads
        .iter()
        .any(|p| p.description.contains("jenkins.corp.local")));
    assert!(payloads
        .iter()
        .any(|p| p.description.contains("vault.corp.local")));
}

#[test]
fn arp_discovery_generates_payloads() {
    let gen = NetworkDiscoveryGenerator::new();
    let payloads = gen.arp_discovery(Ipv4Addr::new(192, 168, 1, 0), 24);

    assert_eq!(payloads.len(), 255);
    assert!(payloads
        .iter()
        .all(|p| p.technique == NetworkDiscoveryTechnique::ArpDiscovery));
    assert!(payloads.iter().all(|p| p.method == "ARP"));
    assert!(payloads.iter().all(|p| p.body.is_some()));
}

#[test]
fn custom_ssrf_endpoint() {
    let gen = NetworkDiscoveryGenerator::new()
        .with_ssrf_endpoint("https://target.com/proxy".to_string(), "dest".to_string());
    let payloads = gen.internal_ip_scan(InternalRange::Loopback);

    assert!(payloads
        .iter()
        .all(|p| p.target_url.starts_with("https://target.com/proxy?dest=")));
}

#[test]
fn detection_risk_ordering() {
    assert!(DetectionRisk::Low < DetectionRisk::Medium);
    assert!(DetectionRisk::Medium < DetectionRisk::High);
    assert!(DetectionRisk::High < DetectionRisk::Critical);
}

#[test]
fn detection_risk_display() {
    assert_eq!(DetectionRisk::Low.to_string(), "Low");
    assert_eq!(DetectionRisk::Critical.to_string(), "Critical");
}

#[test]
fn network_discovery_technique_display() {
    assert_eq!(
        NetworkDiscoveryTechnique::InternalIpScan.to_string(),
        "Internal IP Scan"
    );
    assert_eq!(
        NetworkDiscoveryTechnique::VlanHopping.to_string(),
        "VLAN Hopping"
    );
    assert_eq!(
        NetworkDiscoveryTechnique::CloudMetadataProbe.to_string(),
        "Cloud Metadata Probe"
    );
}

#[test]
fn internal_range_cidr_strings() {
    assert_eq!(InternalRange::ClassA.cidr(), "10.0.0.0/8");
    assert_eq!(InternalRange::ClassB.cidr(), "172.16.0.0/12");
    assert_eq!(InternalRange::ClassC.cidr(), "192.168.0.0/16");
    assert_eq!(InternalRange::LinkLocal.cidr(), "169.254.0.0/16");
    assert_eq!(InternalRange::Loopback.cidr(), "127.0.0.0/8");
}

#[test]
fn service_port_all_has_20_entries() {
    assert_eq!(ServicePort::all().len(), 20);
}

#[test]
fn cloud_provider_all_has_6_entries() {
    assert_eq!(CloudProvider::all().len(), 6);
}

#[test]
fn full_suite_comprehensive() {
    let gen = NetworkDiscoveryGenerator::new();
    let payloads = gen.generate_full_suite("example.com");

    assert!(
        payloads.len() > 100,
        "full suite should generate 100+ payloads, got {}",
        payloads.len()
    );

    let techniques: Vec<_> = payloads.iter().map(|p| p.technique).collect();
    assert!(techniques.contains(&NetworkDiscoveryTechnique::InternalIpScan));
    assert!(techniques.contains(&NetworkDiscoveryTechnique::VlanHopping));
    assert!(techniques.contains(&NetworkDiscoveryTechnique::CloudMetadataProbe));
    assert!(techniques.contains(&NetworkDiscoveryTechnique::DnsBased));
    assert!(techniques.contains(&NetworkDiscoveryTechnique::ServiceEnumeration));
}

#[test]
fn default_generator() {
    let gen = NetworkDiscoveryGenerator::default();
    let payloads = gen.internal_ip_scan(InternalRange::Loopback);
    assert!(!payloads.is_empty());
    assert!(payloads[0].target_url.contains("vulnerable-app"));
}
