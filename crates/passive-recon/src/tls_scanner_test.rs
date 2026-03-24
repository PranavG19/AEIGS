use crate::tls_scanner::*;
use std::time::{Duration, SystemTime};

fn valid_leaf() -> CertificateInfo {
    make_valid_leaf("example.com")
}

fn valid_intermediate() -> CertificateInfo {
    let now = SystemTime::now();
    let five_years = Duration::from_secs(5 * 365 * 24 * 3600);
    make_test_cert(
        "Let's Encrypt Authority X3",
        "DST Root CA X3",
        now - five_years,
        now + five_years,
        KeyInfo::Rsa { bits: 4096 },
    )
}

fn secure_baseline() -> TlsHandshakeDataBuilder {
    TlsHandshakeDataBuilder::new("example.com")
        .with_versions(vec![TlsVersion::Tls12, TlsVersion::Tls13])
        .with_ciphers(vec![
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ])
        .with_leaf_cert(valid_leaf())
        .with_chain_cert(valid_intermediate(), 1, false)
        .with_ocsp(OcspStaplingStatus::Present { is_valid: true })
        .with_secure_renegotiation(true)
        .with_compression(false)
}

// ─── 1. Protocol version tests ───

#[test]
fn detect_sslv2_critical() {
    let data = secure_baseline()
        .with_versions(vec![TlsVersion::SslV2, TlsVersion::Tls12])
        .build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::DeprecatedProtocol));
    let finding = result
        .findings
        .iter()
        .find(|f| f.kind == TlsFindingKind::DeprecatedProtocol)
        .unwrap();
    assert_eq!(finding.severity, Severity::Critical);
    assert!(finding.description.contains("SSLv2"));
}

#[test]
fn detect_sslv3_critical() {
    let data = secure_baseline()
        .with_versions(vec![TlsVersion::SslV3, TlsVersion::Tls12])
        .build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::DeprecatedProtocol));
    let finding = result
        .findings
        .iter()
        .find(|f| f.description.contains("SSLv3"))
        .unwrap();
    assert_eq!(finding.severity, Severity::Critical);
}

#[test]
fn detect_tls10_high() {
    let data = secure_baseline()
        .with_versions(vec![TlsVersion::Tls10, TlsVersion::Tls12])
        .build();
    let result = scan_tls(&data);
    let finding = result
        .findings
        .iter()
        .find(|f| f.description.contains("TLS 1.0"))
        .unwrap();
    assert_eq!(finding.severity, Severity::High);
}

#[test]
fn detect_tls11_high() {
    let data = secure_baseline()
        .with_versions(vec![TlsVersion::Tls11, TlsVersion::Tls13])
        .build();
    let result = scan_tls(&data);
    let finding = result
        .findings
        .iter()
        .find(|f| f.description.contains("TLS 1.1"))
        .unwrap();
    assert_eq!(finding.severity, Severity::High);
}

#[test]
fn tls12_and_tls13_no_deprecated_findings() {
    let data = secure_baseline().build();
    let result = scan_tls(&data);
    assert!(!result.has_finding(&TlsFindingKind::DeprecatedProtocol));
}

// ─── 2. Cipher suite classification ───

#[test]
fn classify_strong_aes_gcm_ecdhe() {
    assert_eq!(
        classify_cipher("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
        CipherStrength::Strong
    );
}

#[test]
fn classify_strong_tls13_aes() {
    assert_eq!(
        classify_cipher("TLS_AES_256_GCM_SHA384"),
        CipherStrength::Strong
    );
}

#[test]
fn classify_strong_chacha20() {
    assert_eq!(
        classify_cipher("TLS_CHACHA20_POLY1305_SHA256"),
        CipherStrength::Strong
    );
}

#[test]
fn classify_insecure_null() {
    assert_eq!(
        classify_cipher("TLS_RSA_WITH_NULL_SHA"),
        CipherStrength::Insecure
    );
}

#[test]
fn classify_insecure_export() {
    assert_eq!(
        classify_cipher("TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
        CipherStrength::Insecure
    );
}

#[test]
fn classify_insecure_anon() {
    assert_eq!(
        classify_cipher("TLS_DH_anon_WITH_AES_128_CBC_SHA"),
        CipherStrength::Insecure
    );
}

#[test]
fn classify_insecure_des() {
    assert_eq!(
        classify_cipher("TLS_RSA_WITH_DES_CBC_SHA"),
        CipherStrength::Insecure
    );
}

#[test]
fn classify_weak_rc4() {
    assert_eq!(
        classify_cipher("TLS_RSA_WITH_RC4_128_SHA"),
        CipherStrength::Weak
    );
}

#[test]
fn classify_weak_3des() {
    assert_eq!(
        classify_cipher("TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
        CipherStrength::Weak
    );
}

#[test]
fn classify_acceptable_aes_cbc() {
    assert_eq!(
        classify_cipher("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"),
        CipherStrength::Acceptable
    );
}

#[test]
fn weak_cipher_generates_finding() {
    let data = secure_baseline()
        .with_ciphers(vec!["TLS_RSA_WITH_RC4_128_SHA", "TLS_AES_256_GCM_SHA384"])
        .build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::WeakCipher));
}

// ─── 3. Certificate validation ───

#[test]
fn detect_expired_certificate() {
    let now = SystemTime::now();
    let past = now - Duration::from_secs(365 * 24 * 3600);
    let more_past = past - Duration::from_secs(365 * 24 * 3600);
    let expired = make_test_cert(
        "example.com",
        "CA",
        more_past,
        past,
        KeyInfo::Rsa { bits: 2048 },
    );
    let data = secure_baseline().with_leaf_cert(expired).build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::CertificateExpired));
    assert_eq!(result.critical_count(), 1);
}

#[test]
fn detect_not_yet_valid_certificate() {
    let now = SystemTime::now();
    let future = now + Duration::from_secs(365 * 24 * 3600);
    let far_future = future + Duration::from_secs(365 * 24 * 3600);
    let not_yet = make_test_cert(
        "example.com",
        "CA",
        future,
        far_future,
        KeyInfo::Rsa { bits: 2048 },
    );
    let data = secure_baseline().with_leaf_cert(not_yet).build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::CertificateNotYetValid));
}

#[test]
fn detect_self_signed_leaf() {
    let mut cert = valid_leaf();
    cert.issuer = cert.subject.clone();
    cert.is_self_signed = true;
    let data = TlsHandshakeDataBuilder::new("example.com")
        .with_leaf_cert(cert)
        .build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::SelfSignedCertificate));
}

#[test]
fn detect_wildcard_certificate() {
    let mut cert = valid_leaf();
    cert.subject = "*.example.com".into();
    cert.is_wildcard = true;
    let data = secure_baseline().with_leaf_cert(cert).build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::WildcardCertificate));
}

// ─── 4. HSTS analysis ───

#[test]
fn detect_missing_hsts() {
    let data = secure_baseline().with_hsts(None).build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::MissingHsts));
}

#[test]
fn detect_weak_hsts_short_max_age() {
    let data = secure_baseline()
        .with_hsts(Some(HstsConfig {
            present: true,
            max_age_seconds: Some(3600),
            include_sub_domains: true,
            preload: true,
        }))
        .build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::WeakHsts));
    let finding = result
        .findings
        .iter()
        .find(|f| f.kind == TlsFindingKind::WeakHsts)
        .unwrap();
    assert!(finding.description.contains("max-age"));
}

#[test]
fn detect_weak_hsts_no_subdomains() {
    let data = secure_baseline()
        .with_hsts(Some(HstsConfig {
            present: true,
            max_age_seconds: Some(31_536_000),
            include_sub_domains: false,
            preload: true,
        }))
        .build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::WeakHsts));
    let finding = result
        .findings
        .iter()
        .find(|f| f.kind == TlsFindingKind::WeakHsts)
        .unwrap();
    assert!(finding.description.contains("includeSubDomains"));
}

#[test]
fn detect_weak_hsts_no_preload() {
    let data = secure_baseline()
        .with_hsts(Some(HstsConfig {
            present: true,
            max_age_seconds: Some(31_536_000),
            include_sub_domains: true,
            preload: false,
        }))
        .build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::WeakHsts));
}

// ─── 5. Certificate chain validation ───

#[test]
fn detect_incomplete_chain() {
    let data = TlsHandshakeDataBuilder::new("example.com")
        .with_leaf_cert(valid_leaf())
        .build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::IncompleteCertificateChain));
}

#[test]
fn detect_chain_order_error() {
    let now = SystemTime::now();
    let year = Duration::from_secs(365 * 24 * 3600);
    let leaf = make_test_cert(
        "example.com",
        "Intermediate CA",
        now - year,
        now + year,
        KeyInfo::Rsa { bits: 2048 },
    );
    let intermediate = make_test_cert(
        "Intermediate CA",
        "Root CA",
        now - year,
        now + year,
        KeyInfo::Rsa { bits: 4096 },
    );
    let data = TlsHandshakeDataBuilder::new("example.com")
        .with_chain_cert(leaf, 1, false)
        .with_chain_cert(intermediate, 0, false)
        .build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::CertificateChainOrderError));
}

#[test]
fn detect_unnecessary_root_in_chain() {
    let now = SystemTime::now();
    let year = Duration::from_secs(365 * 24 * 3600);
    let root = make_test_cert(
        "Root CA",
        "Root CA",
        now - year,
        now + year,
        KeyInfo::Rsa { bits: 4096 },
    );
    let data = secure_baseline().with_chain_cert(root, 2, true).build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::UnnecessaryRootInChain));
}

// ─── 6. Key size checks ───

#[test]
fn detect_weak_rsa_key() {
    let now = SystemTime::now();
    let year = Duration::from_secs(365 * 24 * 3600);
    let weak_cert = make_test_cert(
        "example.com",
        "CA",
        now - year,
        now + year,
        KeyInfo::Rsa { bits: 1024 },
    );
    let data = TlsHandshakeDataBuilder::new("example.com")
        .with_leaf_cert(weak_cert)
        .with_chain_cert(valid_intermediate(), 1, false)
        .build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::WeakKeySize));
    let finding = result
        .findings
        .iter()
        .find(|f| f.kind == TlsFindingKind::WeakKeySize)
        .unwrap();
    assert_eq!(finding.severity, Severity::Critical);
}

#[test]
fn detect_weak_ecc_key() {
    let now = SystemTime::now();
    let year = Duration::from_secs(365 * 24 * 3600);
    let weak_cert = make_test_cert(
        "example.com",
        "CA",
        now - year,
        now + year,
        KeyInfo::Ecc { bits: 128 },
    );
    let data = TlsHandshakeDataBuilder::new("example.com")
        .with_leaf_cert(weak_cert)
        .with_chain_cert(valid_intermediate(), 1, false)
        .build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::WeakKeySize));
}

#[test]
fn detect_deprecated_dsa_key() {
    let now = SystemTime::now();
    let year = Duration::from_secs(365 * 24 * 3600);
    let dsa_cert = make_test_cert(
        "example.com",
        "CA",
        now - year,
        now + year,
        KeyInfo::Dsa { bits: 2048 },
    );
    let data = TlsHandshakeDataBuilder::new("example.com")
        .with_leaf_cert(dsa_cert)
        .with_chain_cert(valid_intermediate(), 1, false)
        .build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::DeprecatedKeyAlgorithm));
}

// ─── 7. OCSP stapling ───

#[test]
fn detect_missing_ocsp_stapling() {
    let data = secure_baseline()
        .with_ocsp(OcspStaplingStatus::Missing)
        .build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::MissingOcspStapling));
}

#[test]
fn detect_expired_ocsp_stapling() {
    let data = secure_baseline()
        .with_ocsp(OcspStaplingStatus::Present { is_valid: false })
        .build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::ExpiredOcspStapling));
}

// ─── 8. Insecure renegotiation ───

#[test]
fn detect_insecure_renegotiation() {
    let data = secure_baseline().with_secure_renegotiation(false).build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::InsecureRenegotiation));
    let finding = result
        .findings
        .iter()
        .find(|f| f.kind == TlsFindingKind::InsecureRenegotiation)
        .unwrap();
    assert!(finding.description.contains("CVE-2009-3555"));
}

// ─── 9. Compression / CRIME ───

#[test]
fn detect_compression_enabled() {
    let data = secure_baseline().with_compression(true).build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::CompressionEnabled));
    let finding = result
        .findings
        .iter()
        .find(|f| f.kind == TlsFindingKind::CompressionEnabled)
        .unwrap();
    assert!(finding.description.contains("CRIME"));
}

// ─── 10. Certificate transparency ───

#[test]
fn detect_missing_ct_scts() {
    let mut cert = valid_leaf();
    cert.has_ct_scts = false;
    let data = secure_baseline().with_leaf_cert(cert).build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::MissingCertificateTransparency));
}

// ─── Severity and result helpers ───

#[test]
fn severity_display() {
    assert_eq!(format!("{}", Severity::Critical), "critical");
    assert_eq!(format!("{}", Severity::High), "high");
    assert_eq!(format!("{}", Severity::Medium), "medium");
    assert_eq!(format!("{}", Severity::Low), "low");
}

#[test]
fn cipher_strength_display() {
    assert_eq!(format!("{}", CipherStrength::Strong), "strong");
    assert_eq!(format!("{}", CipherStrength::Insecure), "insecure");
}

#[test]
fn tls_version_display() {
    assert_eq!(format!("{}", TlsVersion::SslV2), "SSLv2");
    assert_eq!(format!("{}", TlsVersion::Tls13), "TLS 1.3");
}

// ─── Secure baseline produces zero findings ───

#[test]
fn secure_config_no_findings() {
    let data = secure_baseline().build();
    let result = scan_tls(&data);
    assert!(
        result.findings.is_empty(),
        "Expected zero findings for secure config, got: {:?}",
        result.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
}

// ─── Multiple deprecated protocols produce multiple findings ───

#[test]
fn multiple_deprecated_protocols() {
    let data = secure_baseline()
        .with_versions(vec![
            TlsVersion::SslV2,
            TlsVersion::SslV3,
            TlsVersion::Tls10,
            TlsVersion::Tls11,
            TlsVersion::Tls13,
        ])
        .build();
    let result = scan_tls(&data);
    let deprecated_count = result
        .findings
        .iter()
        .filter(|f| f.kind == TlsFindingKind::DeprecatedProtocol)
        .count();
    assert_eq!(deprecated_count, 4);
}

// ─── Cipher classifications returned correctly ───

#[test]
fn cipher_classifications_in_result() {
    let data = secure_baseline()
        .with_ciphers(vec![
            "TLS_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_RC4_128_SHA",
            "TLS_RSA_WITH_NULL_SHA",
        ])
        .build();
    let result = scan_tls(&data);
    assert_eq!(result.cipher_classifications.len(), 3);
    assert_eq!(result.cipher_classifications[0].1, CipherStrength::Strong);
    assert_eq!(result.cipher_classifications[1].1, CipherStrength::Weak);
    assert_eq!(result.cipher_classifications[2].1, CipherStrength::Insecure);
}

// ─── Excessive wildcard scope ───

#[test]
fn detect_excessive_wildcard_scope() {
    let mut cert = valid_leaf();
    cert.subject = "*.com".into();
    cert.is_wildcard = true;
    let data = secure_baseline().with_leaf_cert(cert).build();
    let result = scan_tls(&data);
    assert!(result.has_finding(&TlsFindingKind::ExcessiveWildcardScope));
}

// ─── High count helper ───

#[test]
fn high_count_helper() {
    let data = secure_baseline()
        .with_secure_renegotiation(false)
        .with_compression(true)
        .build();
    let result = scan_tls(&data);
    assert!(result.high_count() >= 2);
}
