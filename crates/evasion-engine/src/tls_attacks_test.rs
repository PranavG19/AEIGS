use super::tls_attacks::*;

#[test]
fn beast_probe_targets_tls10_cbc() {
    let gen = TlsAttackGenerator::new("example.com".into(), 443);
    let payload = gen.beast_probe();

    assert_eq!(payload.attack_type, TlsAttackType::Beast);
    assert_eq!(payload.target_version, Some(TlsProtoVersion::Tls10));
    assert!(!payload.client_hello_bytes.is_empty());
    assert!(payload.description.contains("CBC"));
    assert!(payload.description.contains("example.com:443"));
    assert!(payload.cve_ids.contains(&"CVE-2011-3389".to_string()));
    assert!(!payload.prerequisites.is_empty());
}

#[test]
fn poodle_probe_targets_sslv3() {
    let gen = TlsAttackGenerator::new("target.com".into(), 443);
    let payload = gen.poodle_probe();

    assert_eq!(payload.attack_type, TlsAttackType::Poodle);
    assert_eq!(payload.target_version, Some(TlsProtoVersion::Ssl30));
    assert!(payload.description.contains("SSLv3"));
    assert!(payload.description.contains("padding oracle"));
    assert!(payload.cve_ids.contains(&"CVE-2014-3566".to_string()));
}

#[test]
fn heartbleed_probe_has_heartbeat_request() {
    let gen = TlsAttackGenerator::new("vuln.server.com".into(), 443);
    let payload = gen.heartbleed_probe();

    assert_eq!(payload.attack_type, TlsAttackType::Heartbleed);
    assert_eq!(payload.target_version, Some(TlsProtoVersion::Tls12));
    assert!(payload.client_hello_bytes.len() > 100);
    // Heartbeat content type (0x18) should appear in the combined bytes
    assert!(payload.client_hello_bytes.contains(&0x18));
    assert!(payload.cve_ids.contains(&"CVE-2014-0160".to_string()));
    assert!(payload.description.contains("64KB"));
}

#[test]
fn robot_probe_rsa_key_exchange() {
    let gen = TlsAttackGenerator::new("bank.com".into(), 443);
    let payload = gen.robot_probe();

    assert_eq!(payload.attack_type, TlsAttackType::Robot);
    assert!(payload.description.contains("Bleichenbacher"));
    assert!(payload.description.contains("PKCS#1"));
    assert!(payload.cve_ids.contains(&"CVE-2017-13099".to_string()));
}

#[test]
fn drown_probe_sslv2() {
    let gen = TlsAttackGenerator::new("legacy.com".into(), 443);
    let payload = gen.drown_probe();

    assert_eq!(payload.attack_type, TlsAttackType::Drown);
    assert_eq!(payload.target_version, Some(TlsProtoVersion::Ssl20));
    assert!(!payload.client_hello_bytes.is_empty());
    assert!(payload.description.contains("SSLv2"));
    assert!(payload.cve_ids.contains(&"CVE-2016-0800".to_string()));
}

#[test]
fn version_downgrade_probes_three_versions() {
    let gen = TlsAttackGenerator::new("test.com".into(), 443);
    let payloads = gen.version_downgrade_probes();

    assert_eq!(payloads.len(), 3);
    assert!(payloads
        .iter()
        .all(|p| p.attack_type == TlsAttackType::VersionDowngrade));
    assert_eq!(payloads[0].target_version, Some(TlsProtoVersion::Ssl30));
    assert_eq!(payloads[1].target_version, Some(TlsProtoVersion::Tls10));
    assert_eq!(payloads[2].target_version, Some(TlsProtoVersion::Tls11));
    assert!(payloads
        .iter()
        .all(|p| p.description.contains("FALLBACK_SCSV")));
}

#[test]
fn crime_probe() {
    let gen = TlsAttackGenerator::new("app.com".into(), 443);
    let payload = gen.crime_probe();

    assert_eq!(payload.attack_type, TlsAttackType::Crime);
    assert!(payload.description.contains("compression"));
    assert!(payload.cve_ids.contains(&"CVE-2012-4929".to_string()));
}

#[test]
fn breach_probe_http_level() {
    let gen = TlsAttackGenerator::new("web.com".into(), 443);
    let payload = gen.breach_probe();

    assert_eq!(payload.attack_type, TlsAttackType::Breach);
    assert_eq!(payload.target_version, None);
    assert!(payload.client_hello_bytes.is_empty());
    assert!(payload.description.contains("gzip"));
    assert!(payload.cve_ids.contains(&"CVE-2013-3587".to_string()));
}

#[test]
fn lucky13_probe() {
    let gen = TlsAttackGenerator::new("tls.com".into(), 443);
    let payload = gen.lucky13_probe();

    assert_eq!(payload.attack_type, TlsAttackType::Lucky13);
    assert!(payload.description.contains("timing"));
    assert!(payload.cve_ids.contains(&"CVE-2013-0169".to_string()));
}

#[test]
fn sweet32_probe_3des() {
    let gen = TlsAttackGenerator::new("old.com".into(), 443);
    let payload = gen.sweet32_probe();

    assert_eq!(payload.attack_type, TlsAttackType::Sweet32);
    assert!(payload.description.contains("3DES"));
    assert!(payload.description.contains("64-bit"));
    let cves = &payload.cve_ids;
    assert!(cves.contains(&"CVE-2016-2183".to_string()));
    assert!(cves.contains(&"CVE-2016-6329".to_string()));
}

#[test]
fn logjam_probe_dhe_export() {
    let gen = TlsAttackGenerator::new("govt.com".into(), 443);
    let payload = gen.logjam_probe();

    assert_eq!(payload.attack_type, TlsAttackType::Logjam);
    assert!(payload.description.contains("512-bit DH"));
    assert!(payload.cve_ids.contains(&"CVE-2015-4000".to_string()));
}

#[test]
fn freak_probe_rsa_export() {
    let gen = TlsAttackGenerator::new("rsa.com".into(), 443);
    let payload = gen.freak_probe();

    assert_eq!(payload.attack_type, TlsAttackType::Freak);
    assert!(payload.description.contains("512-bit RSA"));
    assert!(payload.cve_ids.contains(&"CVE-2015-0204".to_string()));
}

#[test]
fn renegotiation_probe() {
    let gen = TlsAttackGenerator::new("reneg.com".into(), 443);
    let payload = gen.renegotiation_probe();

    assert_eq!(payload.attack_type, TlsAttackType::Renegotiation);
    assert!(payload.description.contains("renegotiation"));
    assert!(payload.description.contains("RFC 5746"));
    assert!(payload.cve_ids.contains(&"CVE-2009-3555".to_string()));
}

#[test]
fn ticket_bleed_probe() {
    let gen = TlsAttackGenerator::new("f5.com".into(), 443);
    let payload = gen.ticket_bleed_probe();

    assert_eq!(payload.attack_type, TlsAttackType::TicketBleed);
    assert!(payload.description.contains("F5"));
    assert!(payload.description.contains("31 bytes"));
    assert!(payload.cve_ids.contains(&"CVE-2016-9244".to_string()));
}

#[test]
fn ccs_injection_probe_has_early_ccs() {
    let gen = TlsAttackGenerator::new("openssl.com".into(), 443);
    let payload = gen.ccs_injection_probe();

    assert_eq!(payload.attack_type, TlsAttackType::CcsInjection);
    // CCS content type (0x14) should appear after the ClientHello
    assert!(payload.client_hello_bytes.contains(&0x14));
    assert!(payload.cve_ids.contains(&"CVE-2014-0224".to_string()));
}

#[test]
fn full_suite_covers_all_attacks() {
    let gen = TlsAttackGenerator::new("comprehensive.com".into(), 443);
    let payloads = gen.generate_full_suite();

    assert!(
        payloads.len() >= 17,
        "should have at least 17 payloads, got {}",
        payloads.len()
    );

    let types: Vec<_> = payloads.iter().map(|p| p.attack_type).collect();
    assert!(types.contains(&TlsAttackType::Beast));
    assert!(types.contains(&TlsAttackType::Poodle));
    assert!(types.contains(&TlsAttackType::Heartbleed));
    assert!(types.contains(&TlsAttackType::Robot));
    assert!(types.contains(&TlsAttackType::Drown));
    assert!(types.contains(&TlsAttackType::VersionDowngrade));
    assert!(types.contains(&TlsAttackType::Crime));
    assert!(types.contains(&TlsAttackType::Breach));
    assert!(types.contains(&TlsAttackType::Lucky13));
    assert!(types.contains(&TlsAttackType::Sweet32));
    assert!(types.contains(&TlsAttackType::Logjam));
    assert!(types.contains(&TlsAttackType::Freak));
    assert!(types.contains(&TlsAttackType::Renegotiation));
    assert!(types.contains(&TlsAttackType::TicketBleed));
    assert!(types.contains(&TlsAttackType::CcsInjection));
}

#[test]
fn tls_version_wire_bytes() {
    assert_eq!(TlsProtoVersion::Ssl20.wire_bytes(), [0x00, 0x02]);
    assert_eq!(TlsProtoVersion::Ssl30.wire_bytes(), [0x03, 0x00]);
    assert_eq!(TlsProtoVersion::Tls10.wire_bytes(), [0x03, 0x01]);
    assert_eq!(TlsProtoVersion::Tls11.wire_bytes(), [0x03, 0x02]);
    assert_eq!(TlsProtoVersion::Tls12.wire_bytes(), [0x03, 0x03]);
    assert_eq!(TlsProtoVersion::Tls13.wire_bytes(), [0x03, 0x04]);
}

#[test]
fn tls_version_display() {
    assert_eq!(TlsProtoVersion::Ssl30.to_string(), "SSLv3");
    assert_eq!(TlsProtoVersion::Tls12.to_string(), "TLS 1.2");
    assert_eq!(TlsProtoVersion::Tls13.to_string(), "TLS 1.3");
}

#[test]
fn tls_version_ordering() {
    assert!(TlsProtoVersion::Ssl20 < TlsProtoVersion::Ssl30);
    assert!(TlsProtoVersion::Ssl30 < TlsProtoVersion::Tls10);
    assert!(TlsProtoVersion::Tls12 < TlsProtoVersion::Tls13);
}

#[test]
fn tls_attack_type_display() {
    assert_eq!(TlsAttackType::Beast.to_string(), "BEAST");
    assert_eq!(TlsAttackType::Heartbleed.to_string(), "Heartbleed");
    assert_eq!(
        TlsAttackType::VersionDowngrade.to_string(),
        "Version Downgrade"
    );
}

#[test]
fn vulnerable_cipher_suites_populated() {
    let suites = TlsAttackGenerator::vulnerable_cipher_suites();
    assert!(suites.len() >= 8);

    let cbc_suite = suites
        .iter()
        .find(|s| s.name == "TLS_RSA_WITH_AES_128_CBC_SHA")
        .unwrap();
    assert_eq!(cbc_suite.key_exchange, KeyExchange::RsaPkcs1);
    assert_eq!(cbc_suite.encryption, Encryption::Aes128Cbc);
    assert!(cbc_suite.vulnerable_to.contains(&TlsAttackType::Beast));
    assert!(cbc_suite.vulnerable_to.contains(&TlsAttackType::Lucky13));
    assert!(cbc_suite.vulnerable_to.contains(&TlsAttackType::Robot));
}

#[test]
fn client_hello_structure_valid() {
    let gen = TlsAttackGenerator::new("test.com".into(), 443);
    let payload = gen.beast_probe();
    let bytes = &payload.client_hello_bytes;

    // Record header: ContentType=Handshake(22)
    assert_eq!(bytes[0], 0x16);
    // Version: TLS 1.0 (0x0301)
    assert_eq!(&bytes[1..3], &[0x03, 0x01]);
    // Handshake type: ClientHello(1)
    assert_eq!(bytes[5], 0x01);
}

#[test]
fn default_generator() {
    let gen = TlsAttackGenerator::default();
    let payload = gen.beast_probe();
    assert!(payload.description.contains("localhost:443"));
}

#[test]
fn tls_version_all() {
    assert_eq!(TlsProtoVersion::all().len(), 6);
}
