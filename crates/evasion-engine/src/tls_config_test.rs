use super::*;

#[test]
fn tls_fingerprint_equality() {
    assert_eq!(TlsFingerprint::Chrome120, TlsFingerprint::Chrome120);
    assert_ne!(TlsFingerprint::Chrome120, TlsFingerprint::Firefox121);
}

#[test]
fn tls_fingerprint_all_variants_serialize_deserialize() {
    let variants = [
        TlsFingerprint::Chrome120,
        TlsFingerprint::Firefox121,
        TlsFingerprint::Safari17,
        TlsFingerprint::Edge120,
        TlsFingerprint::Curl,
        TlsFingerprint::Default,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let deserialized: TlsFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, deserialized);
    }
}

#[test]
fn tls_version_equality() {
    assert_eq!(TlsVersion::Tls12, TlsVersion::Tls12);
    assert_ne!(TlsVersion::Tls12, TlsVersion::Tls13);
}

#[test]
fn http_client_backend_equality() {
    assert_eq!(HttpClientBackend::Reqwest, HttpClientBackend::Reqwest);
    assert_ne!(HttpClientBackend::Reqwest, HttpClientBackend::Rquest);
}

#[test]
fn fingerprint_for_persona_chrome_desktop() {
    assert_eq!(
        fingerprint_for_persona(PersonaId::ChromeDesktop),
        TlsFingerprint::Chrome120
    );
}

#[test]
fn fingerprint_for_persona_chrome_mobile() {
    assert_eq!(
        fingerprint_for_persona(PersonaId::ChromeMobile),
        TlsFingerprint::Chrome120
    );
}

#[test]
fn fingerprint_for_persona_firefox() {
    assert_eq!(
        fingerprint_for_persona(PersonaId::FirefoxDesktop),
        TlsFingerprint::Firefox121
    );
}

#[test]
fn fingerprint_for_persona_safari_desktop() {
    assert_eq!(
        fingerprint_for_persona(PersonaId::SafariDesktop),
        TlsFingerprint::Safari17
    );
}

#[test]
fn fingerprint_for_persona_safari_mobile() {
    assert_eq!(
        fingerprint_for_persona(PersonaId::SafariMobile),
        TlsFingerprint::Safari17
    );
}

#[test]
fn fingerprint_for_persona_edge() {
    assert_eq!(
        fingerprint_for_persona(PersonaId::EdgeDesktop),
        TlsFingerprint::Edge120
    );
}

#[test]
fn fingerprint_for_persona_curl() {
    assert_eq!(
        fingerprint_for_persona(PersonaId::CurlClient),
        TlsFingerprint::Curl
    );
}

#[test]
fn fingerprint_for_persona_python_requests() {
    assert_eq!(
        fingerprint_for_persona(PersonaId::PythonRequests),
        TlsFingerprint::Curl
    );
}

#[test]
fn fingerprint_for_persona_googlebot() {
    assert_eq!(
        fingerprint_for_persona(PersonaId::Googlebot),
        TlsFingerprint::Default
    );
}

#[test]
fn fingerprint_for_persona_opera() {
    assert_eq!(
        fingerprint_for_persona(PersonaId::OperaDesktop),
        TlsFingerprint::Default
    );
}

#[test]
fn ja3_hash_non_empty_for_browser_fingerprints() {
    assert!(!ja3_hash(&TlsFingerprint::Chrome120).is_empty());
    assert!(!ja3_hash(&TlsFingerprint::Firefox121).is_empty());
    assert!(!ja3_hash(&TlsFingerprint::Safari17).is_empty());
    assert!(!ja3_hash(&TlsFingerprint::Edge120).is_empty());
    assert!(!ja3_hash(&TlsFingerprint::Curl).is_empty());
}

#[test]
fn ja3_hash_default_returns_empty() {
    assert!(ja3_hash(&TlsFingerprint::Default).is_empty());
}

#[test]
fn ja3_hash_chrome_and_edge_share_chromium_base() {
    let chrome = ja3_hash(&TlsFingerprint::Chrome120);
    let edge = ja3_hash(&TlsFingerprint::Edge120);
    assert_eq!(chrome, edge);
}

#[test]
fn ja3_hash_chrome_and_firefox_differ() {
    let chrome = ja3_hash(&TlsFingerprint::Chrome120);
    let firefox = ja3_hash(&TlsFingerprint::Firefox121);
    assert_ne!(chrome, firefox);
}

#[test]
fn default_tls_config_has_tls12() {
    let config = default_tls_config();
    assert_eq!(config.min_tls_version, TlsVersion::Tls12);
}

#[test]
fn default_tls_config_has_http2_enabled() {
    let config = default_tls_config();
    assert!(config.enable_http2);
}

#[test]
fn default_tls_config_has_default_fingerprint() {
    let config = default_tls_config();
    assert_eq!(config.fingerprint, TlsFingerprint::Default);
}

#[test]
fn default_tls_config_rejects_invalid_certs() {
    let config = default_tls_config();
    assert!(!config.accept_invalid_certs);
}

#[test]
fn default_http_client_config_uses_reqwest() {
    let config = default_http_client_config();
    assert_eq!(config.backend, HttpClientBackend::Reqwest);
}

#[test]
fn default_http_client_config_timeout_is_30000() {
    let config = default_http_client_config();
    assert_eq!(config.timeout_ms, 30000);
}

#[test]
fn default_http_client_config_max_redirects_is_10() {
    let config = default_http_client_config();
    assert_eq!(config.max_redirects, 10);
}

#[test]
fn default_http_client_config_no_user_agent() {
    let config = default_http_client_config();
    assert!(config.user_agent.is_none());
}

#[test]
fn validate_tls_config_accepts_default() {
    let config = default_tls_config();
    assert!(validate_tls_config(&config).is_ok());
}

#[test]
fn validate_tls_config_accepts_tls13_without_http2() {
    let config = TlsConfig {
        fingerprint: TlsFingerprint::Default,
        min_tls_version: TlsVersion::Tls13,
        enable_http2: false,
        accept_invalid_certs: false,
    };
    assert!(validate_tls_config(&config).is_ok());
}

#[test]
fn persona_tls_config_chrome_has_chrome120() {
    let config = persona_tls_config(PersonaId::ChromeDesktop);
    assert_eq!(config.fingerprint, TlsFingerprint::Chrome120);
}

#[test]
fn persona_tls_config_curl_disables_http2() {
    let config = persona_tls_config(PersonaId::CurlClient);
    assert!(!config.enable_http2);
}

#[test]
fn persona_tls_config_firefox_enables_http2() {
    let config = persona_tls_config(PersonaId::FirefoxDesktop);
    assert!(config.enable_http2);
}

#[test]
fn describe_fingerprint_chrome() {
    assert_eq!(
        describe_fingerprint(&TlsFingerprint::Chrome120),
        "Chrome 120 (Windows/macOS)"
    );
}

#[test]
fn describe_fingerprint_firefox() {
    assert_eq!(
        describe_fingerprint(&TlsFingerprint::Firefox121),
        "Firefox 121 (Windows/macOS/Linux)"
    );
}

#[test]
fn describe_fingerprint_safari() {
    assert_eq!(
        describe_fingerprint(&TlsFingerprint::Safari17),
        "Safari 17 (macOS/iOS)"
    );
}

#[test]
fn describe_fingerprint_edge() {
    assert_eq!(
        describe_fingerprint(&TlsFingerprint::Edge120),
        "Edge 120 (Windows)"
    );
}

#[test]
fn describe_fingerprint_curl() {
    assert_eq!(
        describe_fingerprint(&TlsFingerprint::Curl),
        "curl/libcurl default"
    );
}

#[test]
fn describe_fingerprint_default() {
    assert_eq!(
        describe_fingerprint(&TlsFingerprint::Default),
        "no fingerprint emulation"
    );
}

#[test]
fn tls_config_error_display_unsupported_backend() {
    let err = TlsConfigError::UnsupportedBackend("rquest not compiled".to_string());
    assert_eq!(err.to_string(), "unsupported backend: rquest not compiled");
}

#[test]
fn tls_config_error_display_invalid_fingerprint() {
    let err = TlsConfigError::InvalidFingerprint("unknown".to_string());
    assert_eq!(err.to_string(), "invalid fingerprint: unknown");
}

#[test]
fn tls_config_error_display_incompatible_config() {
    let err = TlsConfigError::IncompatibleConfig("conflicting flags".to_string());
    assert_eq!(err.to_string(), "incompatible config: conflicting flags");
}

#[test]
fn fingerprint_mapping_all_personas_has_ten_entries() {
    let mapping = FingerprintMapping::all_personas();
    assert_eq!(mapping.mapping.len(), 10);
}

#[test]
fn fingerprint_mapping_contains_all_persona_ids() {
    let mapping = FingerprintMapping::all_personas();
    assert!(mapping.mapping.contains_key(&PersonaId::ChromeDesktop));
    assert!(mapping.mapping.contains_key(&PersonaId::FirefoxDesktop));
    assert!(mapping.mapping.contains_key(&PersonaId::SafariDesktop));
    assert!(mapping.mapping.contains_key(&PersonaId::ChromeMobile));
    assert!(mapping.mapping.contains_key(&PersonaId::Googlebot));
    assert!(mapping.mapping.contains_key(&PersonaId::EdgeDesktop));
    assert!(mapping.mapping.contains_key(&PersonaId::OperaDesktop));
    assert!(mapping.mapping.contains_key(&PersonaId::SafariMobile));
    assert!(mapping.mapping.contains_key(&PersonaId::CurlClient));
    assert!(mapping.mapping.contains_key(&PersonaId::PythonRequests));
}

#[test]
fn tls_config_clone_and_debug() {
    let config = default_tls_config();
    let cloned = config.clone();
    assert_eq!(cloned.fingerprint, config.fingerprint);
    assert_eq!(cloned.min_tls_version, config.min_tls_version);

    let debug = format!("{config:?}");
    assert!(debug.contains("TlsConfig"));
}

#[test]
fn http_client_config_serialization_roundtrip() {
    let config = default_http_client_config();
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: HttpClientConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.backend, config.backend);
    assert_eq!(deserialized.timeout_ms, config.timeout_ms);
    assert_eq!(deserialized.max_redirects, config.max_redirects);
    assert_eq!(deserialized.tls.fingerprint, config.tls.fingerprint);
}

#[test]
fn tls_config_builder_methods() {
    let config = default_tls_config()
        .with_fingerprint(TlsFingerprint::Chrome120)
        .with_min_tls_version(TlsVersion::Tls13)
        .with_http2(false)
        .with_accept_invalid_certs(true);

    assert_eq!(config.fingerprint, TlsFingerprint::Chrome120);
    assert_eq!(config.min_tls_version, TlsVersion::Tls13);
    assert!(!config.enable_http2);
    assert!(config.accept_invalid_certs);
}

#[test]
fn http_client_config_builder_methods() {
    let config = default_http_client_config()
        .with_backend(HttpClientBackend::Rquest)
        .with_timeout_ms(60000)
        .with_max_redirects(5)
        .with_user_agent("test-agent".to_string());

    assert_eq!(config.backend, HttpClientBackend::Rquest);
    assert_eq!(config.timeout_ms, 60000);
    assert_eq!(config.max_redirects, 5);
    assert_eq!(config.user_agent, Some("test-agent".to_string()));
}

#[test]
fn tls_fingerprint_display_matches_description() {
    assert_eq!(
        TlsFingerprint::Chrome120.to_string(),
        "Chrome 120 (Windows/macOS)"
    );
    assert_eq!(
        TlsFingerprint::Default.to_string(),
        "no fingerprint emulation"
    );
}

#[test]
fn tls_version_display() {
    assert_eq!(TlsVersion::Tls12.to_string(), "TLS 1.2");
    assert_eq!(TlsVersion::Tls13.to_string(), "TLS 1.3");
}

#[test]
fn http_client_backend_display() {
    assert_eq!(HttpClientBackend::Reqwest.to_string(), "reqwest");
    assert_eq!(HttpClientBackend::Rquest.to_string(), "rquest");
}

#[test]
fn tls_fingerprint_hashable() {
    let mut set = std::collections::HashSet::new();
    set.insert(TlsFingerprint::Chrome120);
    set.insert(TlsFingerprint::Chrome120);
    assert_eq!(set.len(), 1);
    set.insert(TlsFingerprint::Firefox121);
    assert_eq!(set.len(), 2);
}

#[test]
fn tls_config_default_trait() {
    let config = TlsConfig::default();
    assert_eq!(config.fingerprint, TlsFingerprint::Default);
    assert_eq!(config.min_tls_version, TlsVersion::Tls12);
    assert!(config.enable_http2);
}

#[test]
fn http_client_config_default_trait() {
    let config = HttpClientConfig::default();
    assert_eq!(config.backend, HttpClientBackend::Reqwest);
    assert_eq!(config.timeout_ms, 30000);
}

#[test]
fn ja3_hash_all_browser_hashes_start_with_771() {
    let browser_fingerprints = [
        TlsFingerprint::Chrome120,
        TlsFingerprint::Firefox121,
        TlsFingerprint::Safari17,
        TlsFingerprint::Edge120,
        TlsFingerprint::Curl,
    ];
    for fp in &browser_fingerprints {
        assert!(
            ja3_hash(fp).starts_with("771,"),
            "{fp:?} JA3 hash should start with TLS 1.2 version marker 771"
        );
    }
}

#[test]
fn tls_config_error_is_std_error() {
    let err: Box<dyn std::error::Error> =
        Box::new(TlsConfigError::UnsupportedBackend("test".to_string()));
    assert!(err.to_string().contains("test"));
}
