use super::ja4_impersonator::*;

#[test]
fn test_chrome_124_profile_valid() {
    let profile = Ja4Impersonator::chrome_124_profile();
    assert_eq!(profile.name, "Chrome 124");
    assert_eq!(profile.ja4.tls_version, "1.3");
    assert!(!profile.ja4.cipher_suites.is_empty());
    assert!(!profile.ja4.extensions.is_empty());
    assert!(profile.ja4.alpn.contains(&"h2".to_string()));
    assert!(!profile.ja4.hash.is_empty());
}

#[test]
fn test_firefox_125_profile_valid() {
    let profile = Ja4Impersonator::firefox_125_profile();
    assert_eq!(profile.name, "Firefox 125");
    assert_eq!(profile.ja4.tls_version, "1.3");
    assert!(profile.ja4.cipher_suites.len() >= 10);
    assert!(profile
        .ja4
        .extensions
        .contains(&"delegated_credentials".to_string()));
    assert!(!profile.ja4h.hash.is_empty());
}

#[test]
fn test_safari_17_profile_valid() {
    let profile = Ja4Impersonator::safari_17_profile();
    assert_eq!(profile.name, "Safari 17");
    assert_eq!(profile.ja4.tls_version, "1.3");
    assert!(profile.ja4.cipher_suites.len() >= 9);
    assert_eq!(profile.ja4t.ttl, 64);
    assert!(!profile.ja4t.hash.is_empty());
}

#[test]
fn test_consistency_validation_passes() {
    let chrome = Ja4Impersonator::chrome_124_profile();
    let issues = Ja4Impersonator::validate_consistency(&chrome);
    assert!(issues.is_empty(), "Chrome issues: {:?}", issues);

    let firefox = Ja4Impersonator::firefox_125_profile();
    let issues = Ja4Impersonator::validate_consistency(&firefox);
    assert!(issues.is_empty(), "Firefox issues: {:?}", issues);

    let safari = Ja4Impersonator::safari_17_profile();
    let issues = Ja4Impersonator::validate_consistency(&safari);
    assert!(issues.is_empty(), "Safari issues: {:?}", issues);
}

#[test]
fn test_inconsistency_detected() {
    let mut profile = Ja4Impersonator::chrome_124_profile();
    profile.ja4.hash = "tampered_hash_value".to_string();
    let issues = Ja4Impersonator::validate_consistency(&profile);
    assert!(
        issues.iter().any(|i| i.contains("JA4 hash")),
        "Should detect tampered JA4 hash"
    );
}

#[test]
fn test_ja4_hash_computation() {
    let profile = Ja4Impersonator::chrome_124_profile();
    let hash = Ja4Impersonator::compute_ja4_hash(&profile.ja4);
    assert!(!hash.is_empty());
    assert!(hash.starts_with("t13_"));

    let hash2 = Ja4Impersonator::compute_ja4_hash(&profile.ja4);
    assert_eq!(hash, hash2, "Hash must be deterministic");
}

#[test]
fn test_ja4h_hash_computation() {
    let profile = Ja4Impersonator::chrome_124_profile();
    let hash = Ja4Impersonator::compute_ja4h_hash(&profile.ja4h);
    assert!(!hash.is_empty());
    assert!(hash.starts_with("G2_"));

    let hash2 = Ja4Impersonator::compute_ja4h_hash(&profile.ja4h);
    assert_eq!(hash, hash2);
}

#[test]
fn test_ja4t_hash_computation() {
    let profile = Ja4Impersonator::chrome_124_profile();
    let hash = Ja4Impersonator::compute_ja4t_hash(&profile.ja4t);
    assert!(!hash.is_empty());
    assert!(hash.contains("65535_128_"));

    let firefox = Ja4Impersonator::firefox_125_profile();
    let firefox_hash = Ja4Impersonator::compute_ja4t_hash(&firefox.ja4t);
    assert!(firefox_hash.contains("65535_64_"));

    assert_ne!(hash, firefox_hash);
}

#[test]
fn test_ttl_inconsistency_detected() {
    let mut profile = Ja4Impersonator::chrome_124_profile();
    profile.ja4t.ttl = 64;
    profile.ja4t.hash = Ja4Impersonator::compute_ja4t_hash(&profile.ja4t);
    let issues = Ja4Impersonator::validate_consistency(&profile);
    assert!(issues.iter().any(|i| i.contains("TTL")));
}
