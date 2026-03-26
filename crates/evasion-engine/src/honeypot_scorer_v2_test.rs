use super::honeypot_scorer_v2::*;
use std::collections::HashMap;

fn make_profile() -> ResponseProfile {
    ResponseProfile {
        response_time_ms: 50,
        status_code: 200,
        headers: HashMap::new(),
        body: String::new(),
        body_length: 0,
        server_header: None,
        content_type: None,
        open_ports: Vec::new(),
        banner: None,
    }
}

#[test]
fn clean_response_proceeds() {
    let scorer = HoneypotScorer::with_defaults();
    let profile = make_profile();
    let result = scorer.score(&profile);
    assert_eq!(result.action, HoneypotAction::Proceed);
    assert!(result.score < 0.4);
}

#[test]
fn fast_response_adds_weight() {
    let scorer = HoneypotScorer::with_defaults();
    let mut profile = make_profile();
    profile.response_time_ms = 1;
    let result = scorer.score(&profile);
    assert!(result.score > 0.0);
    assert!(result
        .signals
        .iter()
        .any(|s| s.signal_type == HoneypotSignal::FastResponseTime));
}

#[test]
fn too_easy_vuln_detected() {
    let scorer = HoneypotScorer::with_defaults();
    let mut profile = make_profile();
    profile.body = "root:x:0:0:root:/root:/bin/bash".to_string();
    let result = scorer.score(&profile);
    assert!(result
        .signals
        .iter()
        .any(|s| s.signal_type == HoneypotSignal::TooEasyVuln));
}

#[test]
fn glastopf_signature_detected() {
    let scorer = HoneypotScorer::with_defaults();
    let mut profile = make_profile();
    profile.body = "Powered by Glastopf web honeypot".to_string();
    let result = scorer.score(&profile);
    assert_eq!(result.suspected_product, Some(HoneypotProduct::Glastopf));
}

#[test]
fn snare_signature_detected() {
    let scorer = HoneypotScorer::with_defaults();
    let mut profile = make_profile();
    profile.server_header = Some("nginx/snare".to_string());
    let result = scorer.score(&profile);
    assert_eq!(result.suspected_product, Some(HoneypotProduct::Snare));
}

#[test]
fn cowrie_signature_detected() {
    let scorer = HoneypotScorer::with_defaults();
    let mut profile = make_profile();
    profile.banner = Some("SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2".to_string());
    let result = scorer.score(&profile);
    assert_eq!(result.suspected_product, Some(HoneypotProduct::Cowrie));
}

#[test]
fn many_open_ports_suspicious() {
    let scorer = HoneypotScorer::with_defaults();
    let mut profile = make_profile();
    profile.open_ports = (1..30).collect();
    let result = scorer.score(&profile);
    assert!(result
        .signals
        .iter()
        .any(|s| s.signal_type == HoneypotSignal::AllPortsOpen));
}

#[test]
fn honeypot_server_header_detected() {
    let scorer = HoneypotScorer::with_defaults();
    let mut profile = make_profile();
    profile.server_header = Some("honeypot-server/1.0".to_string());
    let result = scorer.score(&profile);
    assert!(result
        .signals
        .iter()
        .any(|s| s.signal_type == HoneypotSignal::AnomalousHeaders));
}

#[test]
fn abort_on_combined_signals() {
    let scorer = HoneypotScorer::with_defaults();
    let mut profile = make_profile();
    profile.response_time_ms = 1;
    profile.body = "glastopf root:x:0:0".to_string();
    profile.open_ports = (1..30).collect();
    let result = scorer.score(&profile);
    assert_eq!(result.action, HoneypotAction::Abort);
    assert!(result.score >= 0.7);
}

#[test]
fn should_abort_returns_true_for_honeypot() {
    let scorer = HoneypotScorer::with_defaults();
    let mut profile = make_profile();
    profile.response_time_ms = 1;
    profile.body = "glastopf root:x:0:0".to_string();
    profile.open_ports = (1..30).collect();
    assert!(scorer.should_abort(&profile));
}

#[test]
fn should_abort_returns_false_for_clean() {
    let scorer = HoneypotScorer::with_defaults();
    let profile = make_profile();
    assert!(!scorer.should_abort(&profile));
}

#[test]
fn score_bounded_0_to_1() {
    let scorer = HoneypotScorer::with_defaults();
    let mut profile = make_profile();
    profile.response_time_ms = 0;
    profile.body = "glastopf root:x:0:0 it works!".to_string();
    profile.open_ports = (1..50).collect();
    profile.server_header = Some("honeypot".to_string());
    profile.banner = Some("Welcome to Ubuntu".to_string());
    let result = scorer.score(&profile);
    assert!(result.score >= 0.0 && result.score <= 1.0);
}

#[test]
fn default_content_adds_weight() {
    let scorer = HoneypotScorer::with_defaults();
    let mut profile = make_profile();
    profile.body = "Welcome to nginx! It works!".to_string();
    let result = scorer.score(&profile);
    assert!(result
        .signals
        .iter()
        .any(|s| s.signal_type == HoneypotSignal::DefaultContent));
}

#[test]
fn product_display_formatting() {
    assert_eq!(format!("{}", HoneypotProduct::Glastopf), "Glastopf");
    assert_eq!(format!("{}", HoneypotProduct::Snare), "Snare/Tanner");
    assert_eq!(format!("{}", HoneypotProduct::Cowrie), "Cowrie");
}

#[test]
fn generic_banner_detected() {
    let scorer = HoneypotScorer::with_defaults();
    let mut profile = make_profile();
    profile.banner = Some("Welcome to Ubuntu 22.04".to_string());
    let result = scorer.score(&profile);
    assert!(result
        .signals
        .iter()
        .any(|s| s.signal_type == HoneypotSignal::GenericBanner));
}
