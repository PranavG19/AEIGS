use super::*;
use crate::identity_system::Identity;

fn test_identity() -> Identity {
    Identity {
        id: "red-001-abcd".to_string(),
        ip_pattern: "10.50.123.x".to_string(),
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0".to_string(),
        timing_profile_hash: "abcdef0123456789".to_string(),
        tls_fingerprint_hash: "fedcba9876543210".to_string(),
        active: true,
    }
}

#[test]
fn ban_system_new_has_defaults() {
    let sys = BanSystem::new();
    assert_eq!(sys.max_bans_per_cycle, 3);
    assert_eq!(sys.bans_this_cycle, 0);
    assert_eq!(sys.active_ban_count(), 0);
    assert_eq!(sys.remaining_budget(), 3);
}

#[test]
fn add_ban_within_budget() {
    let mut sys = BanSystem::new();
    let rule = BanRule::new(BanPatternType::Ip, "10.50.", 0.9, 1);
    assert!(sys.add_ban(rule).is_ok());
    assert_eq!(sys.active_ban_count(), 1);
    assert_eq!(sys.remaining_budget(), 2);
}

#[test]
fn add_ban_budget_enforcement() {
    let mut sys = BanSystem::new();
    sys.add_ban(BanRule::new(BanPatternType::Ip, "10.1.", 0.9, 1))
        .unwrap();
    sys.add_ban(BanRule::new(BanPatternType::Ip, "10.2.", 0.9, 1))
        .unwrap();
    sys.add_ban(BanRule::new(BanPatternType::Ip, "10.3.", 0.9, 1))
        .unwrap();

    let result = sys.add_ban(BanRule::new(BanPatternType::Ip, "10.4.", 0.9, 1));
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("budget exhausted"));
}

#[test]
fn budget_resets_on_new_cycle() {
    let mut sys = BanSystem::new();
    sys.add_ban(BanRule::new(BanPatternType::Ip, "10.1.", 0.9, 1))
        .unwrap();
    sys.add_ban(BanRule::new(BanPatternType::Ip, "10.2.", 0.9, 1))
        .unwrap();
    sys.add_ban(BanRule::new(BanPatternType::Ip, "10.3.", 0.9, 1))
        .unwrap();
    assert_eq!(sys.remaining_budget(), 0);

    sys.new_cycle();
    assert_eq!(sys.remaining_budget(), 3);
    assert!(sys
        .add_ban(BanRule::new(BanPatternType::Ip, "10.4.", 0.9, 2))
        .is_ok());
}

#[test]
fn false_positive_detection_health_endpoint() {
    let mut sys = BanSystem::new();
    // A broad regex that matches /health
    let rule = BanRule::new(BanPatternType::RequestPattern, "/.*", 0.5, 1);
    let result = sys.add_ban(rule);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("false positive"));
    assert_eq!(sys.total_false_positives, 1);
    assert_eq!(sys.score_adjustment, -20);
    assert_eq!(sys.active_ban_count(), 0);
}

#[test]
fn specific_ban_does_not_match_health() {
    let mut sys = BanSystem::new();
    let rule = BanRule::new(BanPatternType::RequestPattern, "/search.*OR", 0.9, 1);
    assert!(sys.add_ban(rule).is_ok());
    assert_eq!(sys.total_false_positives, 0);
}

#[test]
fn duplicate_ban_rejected() {
    let mut sys = BanSystem::new();
    sys.add_ban(BanRule::new(BanPatternType::Ip, "10.50.", 0.9, 1))
        .unwrap();
    let result = sys.add_ban(BanRule::new(BanPatternType::Ip, "10.50.", 0.8, 1));
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Duplicate"));
}

#[test]
fn ip_ban_matches_identity() {
    let identity = test_identity();
    let ban = BanRule::new(BanPatternType::Ip, "10.50.", 0.9, 1);
    assert!(ban.matches_identity(&identity));
}

#[test]
fn ip_ban_no_match() {
    let identity = test_identity();
    let ban = BanRule::new(BanPatternType::Ip, "192.168.", 0.9, 1);
    assert!(!ban.matches_identity(&identity));
}

#[test]
fn ua_ban_matches_substring() {
    let identity = test_identity();
    let ban = BanRule::new(BanPatternType::UserAgent, "Chrome/120", 0.9, 1);
    assert!(ban.matches_identity(&identity));
}

#[test]
fn ua_ban_exact_match() {
    let identity = test_identity();
    let ban = BanRule::new(
        BanPatternType::UserAgent,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        0.9,
        1,
    );
    assert!(ban.matches_identity(&identity));
}

#[test]
fn ua_ban_no_match() {
    let identity = test_identity();
    let ban = BanRule::new(BanPatternType::UserAgent, "Firefox/121", 0.9, 1);
    assert!(!ban.matches_identity(&identity));
}

#[test]
fn timing_hash_exact_match() {
    let identity = test_identity();
    let ban = BanRule::new(BanPatternType::TimingHash, "abcdef0123456789", 0.9, 1);
    assert!(ban.matches_identity(&identity));
}

#[test]
fn tls_hash_exact_match() {
    let identity = test_identity();
    let ban = BanRule::new(BanPatternType::TlsHash, "fedcba9876543210", 0.9, 1);
    assert!(ban.matches_identity(&identity));
}

#[test]
fn tls_hash_no_match() {
    let identity = test_identity();
    let ban = BanRule::new(BanPatternType::TlsHash, "0000000000000000", 0.9, 1);
    assert!(!ban.matches_identity(&identity));
}

#[test]
fn request_pattern_matches() {
    let ban = BanRule::new(BanPatternType::RequestPattern, r"OR\s+1\s*=\s*1", 0.9, 1);
    assert!(ban.matches_request("/search?q=' OR 1=1 --"));
    assert!(!ban.matches_request("/search?q=shoes"));
}

#[test]
fn request_pattern_does_not_match_identity() {
    let identity = test_identity();
    let ban = BanRule::new(BanPatternType::RequestPattern, "OR 1=1", 0.9, 1);
    assert!(!ban.matches_identity(&identity));
}

#[test]
fn check_identity_banned() {
    let mut sys = BanSystem::new();
    sys.add_ban(BanRule::new(BanPatternType::Ip, "10.50.", 0.9, 1))
        .unwrap();

    let identity = test_identity();
    assert!(sys.check_identity_banned(&identity).is_some());

    let safe_identity = Identity {
        id: "red-002-ffff".to_string(),
        ip_pattern: "192.168.1.x".to_string(),
        user_agent: "curl/8.0".to_string(),
        timing_profile_hash: "1111111111111111".to_string(),
        tls_fingerprint_hash: "2222222222222222".to_string(),
        active: true,
    };
    assert!(sys.check_identity_banned(&safe_identity).is_none());
}

#[test]
fn record_catches_updates_ban() {
    let mut sys = BanSystem::new();
    sys.add_ban(BanRule::new(BanPatternType::Ip, "10.50.", 0.9, 1))
        .unwrap();

    let identity = test_identity();
    let count = sys.record_identity_catches(&identity, 5);
    assert_eq!(count, 1);
    assert_eq!(sys.active_bans[0].catch_count, 1);
    assert_eq!(sys.active_bans[0].last_catch_cycle, 5);
}

#[test]
fn expire_inactive_bans() {
    let mut sys = BanSystem::new();
    // Ban created at cycle 1 with no catches
    sys.add_ban(BanRule::new(BanPatternType::Ip, "10.1.", 0.9, 1))
        .unwrap();
    // Ban created at cycle 5 with catches
    sys.add_ban(BanRule::new(BanPatternType::UserAgent, "Chrome", 0.9, 5))
        .unwrap();
    sys.active_bans[1].catch_count = 3;
    sys.active_bans[1].last_catch_cycle = 5;

    // At cycle 12: ban at cycle 1 has 11 cycles idle (> 10 threshold), should expire
    // Ban at cycle 5 with catch at 5 has 7 cycles idle (< 10), should stay
    let expired = sys.expire_inactive_bans(12);
    assert_eq!(expired, 1);
    assert_eq!(sys.active_ban_count(), 1);
    assert_eq!(sys.active_bans[0].pattern_type, BanPatternType::UserAgent);
}

#[test]
fn ban_briefing_empty() {
    let sys = BanSystem::new();
    let briefing = sys.ban_briefing();
    assert!(briefing.contains("No active bans"));
}

#[test]
fn ban_briefing_with_bans() {
    let mut sys = BanSystem::new();
    sys.add_ban(BanRule::new(BanPatternType::Ip, "10.50.", 0.9, 1))
        .unwrap();
    sys.add_ban(BanRule::new(
        BanPatternType::UserAgent,
        "Chrome/120",
        0.8,
        1,
    ))
    .unwrap();

    let briefing = sys.ban_briefing();
    assert!(briefing.contains("[IP]"));
    assert!(briefing.contains("10.50."));
    assert!(briefing.contains("[UA]"));
    assert!(briefing.contains("Chrome/120"));
    assert!(briefing.contains("Budget:"));
}

#[test]
fn total_catches_aggregates() {
    let mut sys = BanSystem::new();
    sys.add_ban(BanRule::new(BanPatternType::Ip, "10.1.", 0.9, 1))
        .unwrap();
    sys.add_ban(BanRule::new(BanPatternType::Ip, "10.2.", 0.9, 1))
        .unwrap();
    sys.active_bans[0].catch_count = 5;
    sys.active_bans[1].catch_count = 3;
    assert_eq!(sys.total_catches(), 8);
}

#[test]
fn ban_confidence_clamped() {
    let rule = BanRule::new(BanPatternType::Ip, "10.0.", 1.5, 1);
    assert_eq!(rule.confidence, 1.0);

    let rule2 = BanRule::new(BanPatternType::Ip, "10.0.", -0.5, 1);
    assert_eq!(rule2.confidence, 0.0);
}

#[test]
fn pattern_type_display() {
    assert_eq!(format!("{}", BanPatternType::Ip), "IP");
    assert_eq!(format!("{}", BanPatternType::UserAgent), "UA");
    assert_eq!(format!("{}", BanPatternType::TimingHash), "Timing");
    assert_eq!(format!("{}", BanPatternType::TlsHash), "TLS");
    assert_eq!(format!("{}", BanPatternType::RequestPattern), "ReqPattern");
}
