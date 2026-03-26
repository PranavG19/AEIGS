use super::session_compartment::*;

#[test]
fn create_session_returns_unique_id() {
    let mut mgr = SessionCompartment::with_defaults();
    let s1 = mgr.create_session();
    let s2 = mgr.create_session();
    assert_ne!(s1.session_id, s2.session_id);
}

#[test]
fn sessions_have_unique_fingerprint_seeds() {
    let mut mgr = SessionCompartment::with_defaults();
    let s1 = mgr.create_session();
    let s2 = mgr.create_session();
    let s3 = mgr.create_session();
    let seeds: std::collections::HashSet<_> = [
        s1.fingerprint_seed,
        s2.fingerprint_seed,
        s3.fingerprint_seed,
    ]
    .into();
    assert_eq!(seeds.len(), 3, "all fingerprint seeds should be unique");
}

#[test]
fn sessions_have_unique_cookie_jars() {
    let mut mgr = SessionCompartment::with_defaults();
    let s1 = mgr.create_session();
    let s2 = mgr.create_session();
    assert_ne!(s1.cookie_jar_id, s2.cookie_jar_id);
}

#[test]
fn sessions_have_unique_tls_ids() {
    let mut mgr = SessionCompartment::with_defaults();
    let s1 = mgr.create_session();
    let s2 = mgr.create_session();
    assert_ne!(s1.tls_session_id, s2.tls_session_id);
}

#[test]
fn persona_rotation_across_sessions() {
    let mut mgr = SessionCompartment::with_defaults();
    let mut personas = std::collections::HashSet::new();
    for _ in 0..20 {
        let s = mgr.create_session();
        personas.insert(format!("{:?}", s.persona));
    }
    assert!(personas.len() > 1, "should rotate across multiple personas");
}

#[test]
fn no_rotation_when_disabled() {
    let config = SessionCompartmentConfig {
        rotate_persona_per_session: false,
        ..Default::default()
    };
    let mut mgr = SessionCompartment::new(config);
    let s1 = mgr.create_session();
    let s2 = mgr.create_session();
    assert_eq!(format!("{:?}", s1.persona), format!("{:?}", s2.persona));
}

#[test]
fn destroy_session_removes_it() {
    let mut mgr = SessionCompartment::with_defaults();
    let s = mgr.create_session();
    assert_eq!(mgr.active_count(), 1);
    assert!(mgr.destroy_session(&s.session_id));
    assert_eq!(mgr.active_count(), 0);
}

#[test]
fn destroy_nonexistent_returns_false() {
    let mut mgr = SessionCompartment::with_defaults();
    assert!(!mgr.destroy_session("nonexistent"));
}

#[test]
fn verify_isolation_all_unique() {
    let mut mgr = SessionCompartment::with_defaults();
    let s1 = mgr.create_session();
    let _s2 = mgr.create_session();
    let report = mgr.verify_isolation(&s1.session_id).unwrap();
    assert!(report.cookies_isolated);
    assert!(report.fingerprint_unique);
    assert!(report.tls_session_unique);
    assert!(report.no_shared_state);
}

#[test]
fn correlation_resistance_score_high_by_default() {
    let mut mgr = SessionCompartment::with_defaults();
    let s = mgr.create_session();
    let report = mgr.verify_isolation(&s.session_id).unwrap();
    assert!(
        report.correlation_resistance_score >= 0.9,
        "score should be >= 0.9, got {}",
        report.correlation_resistance_score
    );
}

#[test]
fn active_count_tracks_sessions() {
    let mut mgr = SessionCompartment::with_defaults();
    assert_eq!(mgr.active_count(), 0);
    mgr.create_session();
    assert_eq!(mgr.active_count(), 1);
    mgr.create_session();
    assert_eq!(mgr.active_count(), 2);
}

#[test]
fn total_created_includes_destroyed() {
    let mut mgr = SessionCompartment::with_defaults();
    let s = mgr.create_session();
    mgr.create_session();
    mgr.destroy_session(&s.session_id);
    assert_eq!(mgr.total_created(), 2);
    assert_eq!(mgr.active_count(), 1);
}

#[test]
fn expired_sessions_detected() {
    let mut mgr = SessionCompartment::new(SessionCompartmentConfig {
        max_session_duration_ms: 5000,
        ..Default::default()
    });
    let s = mgr.create_session();
    let expired = mgr.expired_sessions(s.created_at_ms + 6000);
    assert!(expired.contains(&s.session_id));
}

#[test]
fn no_expired_sessions_when_within_duration() {
    let mut mgr = SessionCompartment::with_defaults();
    let s = mgr.create_session();
    let expired = mgr.expired_sessions(s.created_at_ms + 1000);
    assert!(expired.is_empty());
}

#[test]
fn destroy_all_clears_sessions() {
    let mut mgr = SessionCompartment::with_defaults();
    mgr.create_session();
    mgr.create_session();
    mgr.create_session();
    assert_eq!(mgr.active_count(), 3);
    mgr.destroy_all();
    assert_eq!(mgr.active_count(), 0);
}

#[test]
fn session_max_duration_from_config() {
    let config = SessionCompartmentConfig {
        max_session_duration_ms: 60_000,
        ..Default::default()
    };
    let mut mgr = SessionCompartment::new(config);
    let s = mgr.create_session();
    assert_eq!(s.max_duration_ms, 60_000);
}

#[test]
fn verify_nonexistent_session_returns_none() {
    let mgr = SessionCompartment::with_defaults();
    assert!(mgr.verify_isolation("nope").is_none());
}
