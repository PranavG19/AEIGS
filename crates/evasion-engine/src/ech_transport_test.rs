use super::ech_transport::*;

#[test]
fn discover_config_succeeds() {
    let config = EchTransportConfig {
        target_domain: "example.com".to_string(),
        ..Default::default()
    };
    let mut transport = EchTransport::new(config);
    let result = transport.discover_config().unwrap();
    assert_eq!(result.domain, "example.com");
    assert!(!result.configs.is_empty());
    assert_eq!(result.discovery_method, DiscoveryMethod::DnsHttps);
    assert_eq!(transport.state(), EchNegotiationState::ConfigObtained);
}

#[test]
fn negotiate_real_mode_with_config() {
    let config = EchTransportConfig {
        target_domain: "example.com".to_string(),
        mode: EchMode::Real,
        ..Default::default()
    };
    let mut transport = EchTransport::new(config);
    transport.discover_config().unwrap();
    let state = transport.negotiate().unwrap();
    assert_eq!(state, EchNegotiationState::EchAccepted);
    assert_eq!(transport.stats().ech_accepted_count, 1);
}

#[test]
fn negotiate_grease_mode() {
    let config = EchTransportConfig {
        mode: EchMode::Grease,
        ..Default::default()
    };
    let mut transport = EchTransport::new(config);
    let state = transport.negotiate().unwrap();
    assert_eq!(state, EchNegotiationState::GreaseFallback);
    assert_eq!(transport.stats().grease_fallback_count, 1);
}

#[test]
fn negotiate_disabled_mode_fails() {
    let config = EchTransportConfig {
        mode: EchMode::Disabled,
        ..Default::default()
    };
    let mut transport = EchTransport::new(config);
    assert!(transport.negotiate().is_err());
}

#[test]
fn negotiate_real_mode_no_config_falls_back_to_grease() {
    let config = EchTransportConfig {
        mode: EchMode::Real,
        grease_on_failure: true,
        ..Default::default()
    };
    let mut transport = EchTransport::new(config);
    let state = transport.negotiate().unwrap();
    assert_eq!(state, EchNegotiationState::GreaseFallback);
}

#[test]
fn negotiate_real_mode_no_config_no_grease_fails() {
    let config = EchTransportConfig {
        mode: EchMode::Real,
        grease_on_failure: false,
        ..Default::default()
    };
    let mut transport = EchTransport::new(config);
    assert!(transport.negotiate().is_err());
}

#[test]
fn handle_rejection_with_retry_config() {
    let config = EchTransportConfig {
        target_domain: "example.com".to_string(),
        enable_retry: true,
        max_retry_attempts: 3,
        ..Default::default()
    };
    let mut transport = EchTransport::new(config);
    let retry = EchConfig {
        version: 0xfe0d,
        config_id: 99,
        public_name: "retry.example.com".to_string(),
        public_key: vec![1, 2, 3],
        cipher_suite: HpkeSuite::X25519HkdfSha256Aes128Gcm,
        max_name_length: 64,
        raw_bytes: vec![4, 5, 6],
    };
    let state = transport.handle_rejection(Some(retry)).unwrap();
    assert_eq!(state, EchNegotiationState::ConfigObtained);
    assert_eq!(transport.stats().retry_count, 1);
}

#[test]
fn handle_rejection_exceeds_max_retries_falls_back() {
    let config = EchTransportConfig {
        enable_retry: true,
        max_retry_attempts: 1,
        grease_on_failure: true,
        ..Default::default()
    };
    let mut transport = EchTransport::new(config);
    let retry = EchConfig {
        version: 0xfe0d,
        config_id: 1,
        public_name: "x.com".to_string(),
        public_key: vec![1],
        cipher_suite: HpkeSuite::X25519HkdfSha256Aes128Gcm,
        max_name_length: 32,
        raw_bytes: vec![2],
    };
    transport.handle_rejection(Some(retry.clone())).unwrap();
    let state = transport.handle_rejection(Some(retry)).unwrap();
    assert_eq!(state, EchNegotiationState::GreaseFallback);
}

#[test]
fn generate_grease_payload_has_content() {
    let config = EchTransportConfig::default();
    let transport = EchTransport::new(config);
    let grease = transport.generate_grease_payload();
    assert!(!grease.enc.is_empty());
    assert!(!grease.payload.is_empty());
    assert_eq!(grease.config_id, 0);
}

#[test]
fn ech_config_version_is_draft() {
    let config = EchTransportConfig {
        target_domain: "test.com".to_string(),
        ..Default::default()
    };
    let mut transport = EchTransport::new(config);
    let result = transport.discover_config().unwrap();
    assert_eq!(result.configs[0].version, 0xfe0d);
}

#[test]
fn cached_config_count_updates() {
    let config = EchTransportConfig {
        target_domain: "test.com".to_string(),
        ..Default::default()
    };
    let mut transport = EchTransport::new(config);
    assert_eq!(transport.cached_config_count(), 0);
    transport.discover_config().unwrap();
    assert_eq!(transport.cached_config_count(), 1);
}

#[test]
fn ech_mode_display() {
    assert_eq!(format!("{}", EchMode::Real), "real");
    assert_eq!(format!("{}", EchMode::Grease), "grease");
    assert_eq!(format!("{}", EchMode::Disabled), "disabled");
}

#[test]
fn stats_track_discovery() {
    let config = EchTransportConfig {
        target_domain: "test.com".to_string(),
        ..Default::default()
    };
    let mut transport = EchTransport::new(config);
    assert_eq!(transport.stats().configs_discovered, 0);
    transport.discover_config().unwrap();
    assert_eq!(transport.stats().configs_discovered, 1);
}
