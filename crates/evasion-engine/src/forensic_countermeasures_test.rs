use super::forensic_countermeasures::*;
use std::collections::HashMap;

fn make_engine() -> ForensicCountermeasureEngine {
    ForensicCountermeasureEngine::with_seed(ForensicCountermeasureConfig::default(), 42)
}

fn sample_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("User-Agent".to_string(), "sqlmap/1.7".to_string());
    h.insert("X-Forwarded-For".to_string(), "192.168.1.1".to_string());
    h.insert("X-Real-IP".to_string(), "10.0.0.1".to_string());
    h.insert("Accept".to_string(), "text/html".to_string());
    h.insert("Via".to_string(), "1.1 proxy.internal".to_string());
    h
}

#[test]
fn log_evasion_windows_returns_techniques() {
    let engine = make_engine();
    let windows = engine.log_evasion_windows();
    assert!(windows.len() >= 3);
    assert!(windows
        .iter()
        .any(|w| w.technique == LogEvasionTechnique::TimingBetweenRotations));
    assert!(windows
        .iter()
        .all(|w| w.estimated_detection_reduction_pct > 0.0));
}

#[test]
fn memory_only_patterns_returns_all() {
    let engine = make_engine();
    let patterns = engine.memory_only_patterns();
    assert_eq!(patterns.len(), 5);
    assert!(patterns
        .iter()
        .any(|(p, _)| *p == MemoryOnlyPattern::InMemoryBuffer));
    assert!(patterns
        .iter()
        .any(|(p, _)| *p == MemoryOnlyPattern::MmapAnonymous));
}

#[test]
fn encryption_config_has_pfs() {
    let engine = make_engine();
    let (cipher, name, pfs) = engine.encryption_config();
    assert_eq!(cipher, PfsCipherSuite::Tls13Aes256Gcm);
    assert!(name.contains("AES_256"));
    assert!(pfs);
}

#[test]
fn all_pfs_ciphers_have_forward_secrecy() {
    assert!(PfsCipherSuite::Tls13Aes256Gcm.has_forward_secrecy());
    assert!(PfsCipherSuite::Tls13Chacha20Poly1305.has_forward_secrecy());
    assert!(PfsCipherSuite::EcdhEcdsaAes256Gcm.has_forward_secrecy());
    assert!(PfsCipherSuite::EcdhRsaAes256Gcm.has_forward_secrecy());
}

#[test]
fn strip_metadata_removes_identifying_headers() {
    let mut engine = make_engine();
    let headers = sample_headers();
    let result = engine.strip_metadata(&headers);
    assert!(!result.stripped_headers.contains_key("X-Forwarded-For"));
    assert!(!result.stripped_headers.contains_key("X-Real-IP"));
    assert!(!result.stripped_headers.contains_key("Via"));
    assert!(result.stripped_headers.contains_key("Accept"));
    assert!(result
        .fields_removed
        .contains(&MetadataField::XForwardedFor));
    assert!(result.fields_removed.contains(&MetadataField::XRealIp));
}

#[test]
fn strip_metadata_replaces_scanner_ua() {
    let mut engine = make_engine();
    let headers = sample_headers();
    let result = engine.strip_metadata(&headers);
    assert!(result.ua_replaced);
    let new_ua = result.stripped_headers.get("User-Agent").unwrap();
    assert!(!ForensicCountermeasureEngine::is_scanner_ua(new_ua));
}

#[test]
fn strip_metadata_preserves_normal_ua() {
    let mut engine = make_engine();
    let mut headers = HashMap::new();
    headers.insert(
        "User-Agent".to_string(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0".to_string(),
    );
    let result = engine.strip_metadata(&headers);
    assert!(!result.ua_replaced);
}

#[test]
fn is_scanner_ua_detects_known_scanners() {
    assert!(ForensicCountermeasureEngine::is_scanner_ua("sqlmap/1.7"));
    assert!(ForensicCountermeasureEngine::is_scanner_ua("Nikto/2.1.6"));
    assert!(ForensicCountermeasureEngine::is_scanner_ua(
        "Mozilla/5.0 (compatible; Nmap)"
    ));
    assert!(ForensicCountermeasureEngine::is_scanner_ua(
        "AEGIS-Scanner/0.1"
    ));
    assert!(!ForensicCountermeasureEngine::is_scanner_ua(
        "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0"
    ));
}

#[test]
fn safe_user_agent_rotates() {
    let mut engine = make_engine();
    let ua1 = engine.safe_user_agent().to_string();
    let ua2 = engine.safe_user_agent().to_string();
    assert!(!ForensicCountermeasureEngine::is_scanner_ua(&ua1));
    assert!(!ForensicCountermeasureEngine::is_scanner_ua(&ua2));
    assert_ne!(ua1, ua2);
}

#[test]
fn clock_sync_recommendation_uses_utc() {
    let engine = make_engine();
    let rec = engine.clock_sync_recommendation();
    assert!(rec.use_utc);
    assert!(rec.avoid_round_timestamps);
    assert!(!rec.ntp_servers.is_empty());
    assert_eq!(rec.jitter_range_ms, 500);
}

#[test]
fn jittered_timestamp_stays_near_base() {
    let mut engine = make_engine();
    let base = 1700000000000_u64;
    let jittered = engine.jittered_timestamp(base);
    let diff = if jittered > base {
        jittered - base
    } else {
        base - jittered
    };
    assert!(diff <= 500);
}

#[test]
fn connection_cleanup_graceful() {
    let engine = make_engine();
    let plan = engine.connection_cleanup_plan();
    assert_eq!(plan.strategy, ConnectionCleanup::GracefulFinAck);
    assert_eq!(plan.linger_timeout_ms, 0);
}

#[test]
fn connection_cleanup_linger_zero() {
    let engine = ForensicCountermeasureEngine::with_seed(
        ForensicCountermeasureConfig::default()
            .with_connection_cleanup(ConnectionCleanup::LingerZero),
        42,
    );
    let plan = engine.connection_cleanup_plan();
    assert_eq!(plan.strategy, ConnectionCleanup::LingerZero);
    assert_eq!(plan.max_idle_secs, 0);
}

#[test]
fn stripped_count_tracks_operations() {
    let mut engine = make_engine();
    assert_eq!(engine.stripped_count(), 0);
    engine.strip_metadata(&sample_headers());
    assert_eq!(engine.stripped_count(), 1);
    engine.strip_metadata(&sample_headers());
    assert_eq!(engine.stripped_count(), 2);
}

#[test]
fn log_evasion_technique_display() {
    assert_eq!(
        format!("{}", LogEvasionTechnique::TimingBetweenRotations),
        "timing-rotation-gap"
    );
    assert_eq!(
        format!("{}", LogEvasionTechnique::SlowDripFeeding),
        "slow-drip"
    );
}

#[test]
fn memory_only_pattern_display() {
    assert_eq!(
        format!("{}", MemoryOnlyPattern::InMemoryBuffer),
        "in-memory-buffer"
    );
    assert_eq!(format!("{}", MemoryOnlyPattern::MmapAnonymous), "mmap-anon");
}

#[test]
fn pfs_cipher_display() {
    assert_eq!(
        format!("{}", PfsCipherSuite::Tls13Aes256Gcm),
        "TLS_AES_256_GCM_SHA384"
    );
    assert_eq!(
        format!("{}", PfsCipherSuite::Tls13Chacha20Poly1305),
        "TLS_CHACHA20_POLY1305_SHA256"
    );
}

#[test]
fn metadata_field_display() {
    assert_eq!(format!("{}", MetadataField::UserAgent), "User-Agent");
    assert_eq!(
        format!("{}", MetadataField::XForwardedFor),
        "X-Forwarded-For"
    );
}

#[test]
fn config_builder_pattern() {
    let config = ForensicCountermeasureConfig::default()
        .with_pfs_cipher(PfsCipherSuite::Tls13Chacha20Poly1305)
        .with_clock_jitter(1000)
        .with_connection_cleanup(ConnectionCleanup::IdleDisconnect)
        .with_memory_only(false);
    assert_eq!(config.pfs_cipher, PfsCipherSuite::Tls13Chacha20Poly1305);
    assert_eq!(config.clock_jitter_ms, 1000);
    assert_eq!(config.connection_cleanup, ConnectionCleanup::IdleDisconnect);
    assert!(!config.memory_only_mode);
}
