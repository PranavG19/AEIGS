use super::identity_rotation::*;

fn make_engine() -> IdentityRotationEngine {
    IdentityRotationEngine::with_seed(IdentityRotationConfig::default(), 42)
}

fn engine_with_pool() -> IdentityRotationEngine {
    let mut engine = make_engine();
    engine.generate_pool();
    engine
}

#[test]
fn generate_pool_creates_configured_count() {
    let engine = engine_with_pool();
    assert_eq!(engine.pool_size(), 10);
    assert_eq!(engine.available_count(), 10);
}

#[test]
fn activate_next_sets_identity_active() {
    let mut engine = engine_with_pool();
    let id = engine.activate_next().unwrap();
    let identity = engine.get_identity(id).unwrap();
    assert_eq!(identity.state, IdentityState::Active);
    assert_eq!(engine.available_count(), 9);
}

#[test]
fn activate_next_returns_none_when_empty() {
    let mut engine = make_engine();
    assert!(engine.activate_next().is_none());
}

#[test]
fn record_use_increments_count() {
    let mut engine = engine_with_pool();
    engine.activate_next();
    let id = engine.record_use().unwrap();
    assert_eq!(engine.use_count(id), 1);
    engine.record_use();
    assert_eq!(engine.use_count(id), 2);
}

#[test]
fn record_use_triggers_rotation_at_max() {
    let mut engine =
        IdentityRotationEngine::with_seed(IdentityRotationConfig::default().with_max_uses(3), 42);
    engine.generate_pool();
    let first_id = engine.activate_next().unwrap();
    engine.record_use();
    engine.record_use();
    let rotated_id = engine.record_use().unwrap();
    assert_ne!(first_id, rotated_id);
}

#[test]
fn rotate_destroys_current_and_activates_next() {
    let mut engine = engine_with_pool();
    let first = engine.activate_next().unwrap();
    let second = engine.rotate().unwrap();
    assert_ne!(first, second);
    assert_eq!(engine.destroyed_count(), 1);
    let first_identity = engine.get_identity(first).unwrap();
    assert_eq!(first_identity.state, IdentityState::Destroyed);
}

#[test]
fn destroy_identity_marks_destroyed() {
    let mut engine = engine_with_pool();
    let id = engine.activate_next().unwrap();
    engine.destroy_identity(id);
    assert_eq!(engine.destroyed_count(), 1);
    assert!(engine.active_identity().is_none());
}

#[test]
fn identities_have_unique_fingerprints() {
    let engine = engine_with_pool();
    let mut fingerprints = std::collections::HashSet::new();
    for i in 1..=10 {
        let identity = engine.get_identity(i as u64).unwrap();
        let fp = identity.fingerprint_hash();
        fingerprints.insert(fp);
    }
    assert_eq!(fingerprints.len(), 10);
}

#[test]
fn check_correlation_low_for_distinct_identities() {
    let engine = engine_with_pool();
    let check = engine.check_correlation(1, 2).unwrap();
    assert!(check.correlation_score < 1.0);
    assert!(check.safe || check.correlation_score >= 0.3);
}

#[test]
fn check_correlation_returns_none_for_missing() {
    let engine = engine_with_pool();
    assert!(engine.check_correlation(1, 999).is_none());
}

#[test]
fn browser_fingerprint_components_populated() {
    let engine = engine_with_pool();
    let identity = engine.get_identity(1).unwrap();
    assert!(!identity.browser.user_agent.is_empty());
    assert!(!identity.browser.canvas_hash.is_empty());
    assert!(!identity.browser.webgl_renderer.is_empty());
    assert!(identity.browser.screen_resolution.0 > 0);
    assert!(identity.browser.screen_resolution.1 > 0);
}

#[test]
fn network_identity_populated() {
    let engine = engine_with_pool();
    let identity = engine.get_identity(1).unwrap();
    assert!(!identity.network.exit_ip_hint.is_empty());
    assert!(!identity.network.geo_region.is_empty());
}

#[test]
fn application_identity_has_session() {
    let engine = engine_with_pool();
    let identity = engine.get_identity(1).unwrap();
    assert!(!identity.application.session_token.is_empty());
    assert!(!identity.application.cookies.is_empty());
    assert!(identity.application.csrf_token.is_some());
}

#[test]
fn behavioral_identity_has_timing() {
    let engine = engine_with_pool();
    let identity = engine.get_identity(1).unwrap();
    assert!(identity.behavior.mean_delay_ms > 0);
    assert!(identity.behavior.click_variance > 0.0);
    assert!(identity.behavior.scroll_depth_pct > 0.0);
}

#[test]
fn identity_state_display() {
    assert_eq!(format!("{}", IdentityState::Created), "created");
    assert_eq!(format!("{}", IdentityState::Active), "active");
    assert_eq!(format!("{}", IdentityState::Rotating), "rotating");
    assert_eq!(format!("{}", IdentityState::Destroyed), "destroyed");
}

#[test]
fn network_identity_type_display() {
    assert_eq!(format!("{}", NetworkIdentityType::TorCircuit), "tor");
    assert_eq!(format!("{}", NetworkIdentityType::VpnTunnel), "vpn");
    assert_eq!(
        format!("{}", NetworkIdentityType::ResidentialProxy),
        "residential"
    );
}

#[test]
fn browsing_behavior_display() {
    assert_eq!(format!("{}", BrowsingBehavior::CasualBrowser), "casual");
    assert_eq!(format!("{}", BrowsingBehavior::PowerUser), "power-user");
    assert_eq!(format!("{}", BrowsingBehavior::ApiClient), "api-client");
}

#[test]
fn config_builder_pattern() {
    let config = IdentityRotationConfig::default()
        .with_pool_size(20)
        .with_max_uses(100)
        .with_correlation_threshold(0.5);
    assert_eq!(config.pool_size, 20);
    assert_eq!(config.max_uses_per_identity, 100);
    assert!((config.correlation_threshold - 0.5).abs() < f64::EPSILON);
}

#[test]
fn active_identity_returns_current() {
    let mut engine = engine_with_pool();
    assert!(engine.active_identity().is_none());
    let id = engine.activate_next().unwrap();
    let active = engine.active_identity().unwrap();
    assert_eq!(active.id, id);
    assert_eq!(active.state, IdentityState::Active);
}

#[test]
fn correlation_tag_unique_per_identity() {
    let engine = engine_with_pool();
    let mut tags = std::collections::HashSet::new();
    for i in 1..=10 {
        let identity = engine.get_identity(i as u64).unwrap();
        tags.insert(identity.correlation_tag.clone());
    }
    assert_eq!(tags.len(), 10);
}

#[test]
fn multiple_rotations_cycle_through_pool() {
    let mut engine = engine_with_pool();
    let mut seen_ids = Vec::new();
    for _ in 0..5 {
        if let Some(id) = engine.activate_next() {
            seen_ids.push(id);
            engine.destroy_identity(id);
        }
    }
    assert_eq!(seen_ids.len(), 5);
    let unique: std::collections::HashSet<_> = seen_ids.iter().collect();
    assert_eq!(unique.len(), 5);
}
