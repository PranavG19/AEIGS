use super::*;
use crate::fingerprint_db::FingerprintDb;

fn make_db() -> FingerprintDb {
    FingerprintDb::new()
}

fn make_rotator() -> FingerprintRotator {
    let db = make_db();
    FingerprintRotator::with_seed(RotatorConfig::default().with_pool_size(50), &db, 42)
}

#[test]
fn pool_generated_at_construction() {
    let rotator = make_rotator();
    assert_eq!(rotator.pool_size(), 50);
}

#[test]
fn current_identity_available_after_construction() {
    let rotator = make_rotator();
    let identity = rotator.current_identity().unwrap();
    assert!(!identity.user_agent.is_empty());
}

#[test]
fn rotate_changes_identity() {
    let mut rotator = make_rotator();
    let first_ua = rotator.current_identity().unwrap().user_agent.clone();
    rotator.rotate(RotationTrigger::Manual);
    let second_ua = rotator.current_identity().unwrap().user_agent.clone();
    assert_ne!(first_ua, second_ua);
}

#[test]
fn rotation_count_increments() {
    let mut rotator = make_rotator();
    assert_eq!(rotator.rotation_count(), 0);
    rotator.rotate(RotationTrigger::BlockDetected);
    rotator.rotate(RotationTrigger::RateLimited);
    assert_eq!(rotator.rotation_count(), 2);
}

#[test]
fn session_lock_prevents_rotation() {
    let mut rotator = make_rotator();
    let locked_ua = rotator.current_identity().unwrap().user_agent.clone();
    rotator.lock_session();
    assert!(rotator.is_session_locked());
    rotator.rotate(RotationTrigger::BlockDetected);
    assert_eq!(rotator.current_identity().unwrap().user_agent, locked_ua);
}

#[test]
fn session_end_unlocks_and_rotates() {
    let mut rotator = make_rotator();
    rotator.lock_session();
    let locked_ua = rotator.current_identity().unwrap().user_agent.clone();
    rotator.rotate(RotationTrigger::SessionEnd);
    assert!(!rotator.is_session_locked());
    assert_ne!(rotator.current_identity().unwrap().user_agent, locked_ua);
}

#[test]
fn unlock_session_allows_rotation() {
    let mut rotator = make_rotator();
    rotator.lock_session();
    rotator.unlock_session();
    assert!(!rotator.is_session_locked());
    let before = rotator.current_identity().unwrap().user_agent.clone();
    rotator.rotate(RotationTrigger::Manual);
    assert_ne!(rotator.current_identity().unwrap().user_agent, before);
}

#[test]
fn anti_correlation_avoids_recent_identities() {
    let mut rotator = FingerprintRotator::with_seed(
        RotatorConfig::default()
            .with_pool_size(10)
            .with_anti_correlation_distance(5),
        &make_db(),
        42,
    );
    let mut seen_indices: Vec<usize> = Vec::new();
    for _ in 0..8 {
        let identity = rotator.current_identity().unwrap();
        seen_indices.push(identity.slot_index);
        rotator.rotate(RotationTrigger::Manual);
    }
    for window in seen_indices.windows(3) {
        let unique: std::collections::HashSet<usize> = window.iter().copied().collect();
        assert!(unique.len() > 1);
    }
}

#[test]
fn current_fingerprint_returns_full_entry() {
    let db = make_db();
    let rotator =
        FingerprintRotator::with_seed(RotatorConfig::default().with_pool_size(10), &db, 42);
    let fp = rotator.current_fingerprint(&db);
    assert!(fp.is_some());
    assert!(!fp.unwrap().user_agent.is_empty());
}

#[test]
fn preferred_browsers_filter() {
    let db = make_db();
    let rotator = FingerprintRotator::with_seed(
        RotatorConfig::default()
            .with_pool_size(20)
            .with_preferred_browsers(vec![BrowserFamily::Firefox]),
        &db,
        42,
    );
    for slot in rotator.pool() {
        let entry = db.get(&slot.fingerprint_id).unwrap();
        assert_eq!(entry.id.browser, BrowserFamily::Firefox);
    }
}

#[test]
fn preferred_os_filter() {
    let db = make_db();
    let rotator = FingerprintRotator::with_seed(
        RotatorConfig::default()
            .with_pool_size(20)
            .with_preferred_os(vec![OsFamily::Linux]),
        &db,
        42,
    );
    for slot in rotator.pool() {
        let entry = db.get(&slot.fingerprint_id).unwrap();
        assert_eq!(entry.id.os, OsFamily::Linux);
    }
}

#[test]
fn empty_pool_size_zero() {
    let db = make_db();
    let rotator =
        FingerprintRotator::with_seed(RotatorConfig::default().with_pool_size(0), &db, 42);
    assert_eq!(rotator.pool_size(), 0);
    assert!(rotator.current_identity().is_none());
}

#[test]
fn rotate_on_empty_pool_returns_none() {
    let db = make_db();
    let mut rotator =
        FingerprintRotator::with_seed(RotatorConfig::default().with_pool_size(0), &db, 42);
    assert!(rotator.rotate(RotationTrigger::Manual).is_none());
}

#[test]
fn default_config_values() {
    let config = RotatorConfig::default();
    assert_eq!(config.pool_size, 100);
    assert_eq!(config.rotation_interval_secs, 300);
    assert_eq!(config.anti_correlation_distance, 3);
    assert!(config.session_sticky);
    assert!(config.preferred_browsers.is_empty());
    assert!(config.preferred_os.is_empty());
}

#[test]
fn rotation_trigger_variants_distinct() {
    let triggers = [
        RotationTrigger::BlockDetected,
        RotationTrigger::RateLimited,
        RotationTrigger::TimeInterval,
        RotationTrigger::SessionEnd,
        RotationTrigger::Manual,
    ];
    let unique: std::collections::HashSet<RotationTrigger> = triggers.iter().copied().collect();
    assert_eq!(unique.len(), 5);
}

#[test]
fn large_pool_generation() {
    let db = make_db();
    let rotator =
        FingerprintRotator::with_seed(RotatorConfig::default().with_pool_size(200), &db, 42);
    assert_eq!(rotator.pool_size(), 200);
}

#[test]
fn session_sticky_false_allows_lock_to_be_noop() {
    let db = make_db();
    let mut rotator = FingerprintRotator::with_seed(
        RotatorConfig::default()
            .with_pool_size(10)
            .with_session_sticky(false),
        &db,
        42,
    );
    rotator.lock_session();
    assert!(!rotator.is_session_locked());
}
