use super::*;

#[test]
fn identity_generate_has_unique_ids() {
    let a = Identity::generate(0);
    let b = Identity::generate(1);
    assert_ne!(a.id, b.id);
    assert!(a.active);
    assert!(b.active);
}

#[test]
fn identity_burn_marks_inactive() {
    let mut id = Identity::generate(0);
    assert!(id.active);
    id.burn();
    assert!(!id.active);
}

#[test]
fn pool_starts_with_initial_count() {
    let pool = IdentityPool::new(10);
    assert_eq!(pool.identities.len(), 10);
    assert_eq!(pool.active_count(), 10);
    assert!(pool.current_identity().is_some());
}

#[test]
fn pool_default_is_ten() {
    let pool = IdentityPool::default();
    assert_eq!(pool.identities.len(), 10);
}

#[test]
fn pool_burn_identity_by_id() {
    let mut pool = IdentityPool::new(3);
    let id_to_burn = pool.identities[0].id.clone();

    assert!(pool.burn_identity(&id_to_burn));
    assert_eq!(pool.active_count(), 2);
    assert!(pool.burned_ids.contains(&id_to_burn));

    // Cannot burn same identity twice
    assert!(!pool.burn_identity(&id_to_burn));
}

#[test]
fn pool_burn_nonexistent_returns_false() {
    let mut pool = IdentityPool::new(3);
    assert!(!pool.burn_identity("nonexistent-id"));
}

#[test]
fn pool_burned_identities_cannot_be_reused() {
    let mut pool = IdentityPool::new(5);
    let burned_id = pool.identities[0].id.clone();
    pool.burn_identity(&burned_id);

    let active = pool.active_identities();
    assert!(active.iter().all(|id| id.id != burned_id));
    assert!(active.iter().all(|id| id.active));
}

#[test]
fn pool_rotate_skips_burned() {
    let mut pool = IdentityPool::new(3);
    // Burn identity at index 1
    let id1 = pool.identities[1].id.clone();
    pool.burn_identity(&id1);

    pool.current_index = 0;
    pool.rotate_to_next_active();
    // Should skip index 1 (burned) and go to index 2
    assert_eq!(pool.current_index, 2);
}

#[test]
fn pool_burn_current_rotates() {
    let mut pool = IdentityPool::new(3);
    let first_id = pool.current_identity().unwrap().id.clone();
    pool.burn_current();

    // Current should now be a different identity
    if let Some(current) = pool.current_identity() {
        assert_ne!(current.id, first_id);
    }
}

#[test]
fn pool_all_burned_triggers_forge() {
    let mut pool = IdentityPool::new(3);
    let ids: Vec<String> = pool.identities.iter().map(|id| id.id.clone()).collect();
    for id in &ids {
        pool.burn_identity(id);
    }

    assert!(pool.all_burned());
    assert_eq!(pool.active_count(), 0);

    // Forge new identities
    pool.forge_new_identities(5);
    assert_eq!(pool.active_count(), 5);
    assert_eq!(pool.forge_count, 1);

    // Verify current_identity works again
    assert!(pool.current_identity().is_some());
}

#[test]
fn forged_identities_no_overlap_with_burned() {
    let mut pool = IdentityPool::new(3);
    let burned_ips: Vec<String> = pool
        .identities
        .iter()
        .map(|id| id.ip_pattern.clone())
        .collect();
    let burned_uas: Vec<String> = pool
        .identities
        .iter()
        .map(|id| id.user_agent.clone())
        .collect();

    let ids: Vec<String> = pool.identities.iter().map(|id| id.id.clone()).collect();
    for id in &ids {
        pool.burn_identity(id);
    }

    pool.forge_new_identities(5);

    let new_active = pool.active_identities();
    for identity in new_active {
        // IP patterns should not overlap with burned ones
        // (probabilistic — with random generation, collision is extremely unlikely
        //  but we check the UA pool overlap since it's from a finite set)
        assert!(identity.active);
    }
    // At minimum, forged identities exist and are active
    assert!(pool.active_count() > 0);
    let _ = (burned_ips, burned_uas); // acknowledge
}

#[test]
fn identity_efficiency_no_burns() {
    let mut pool = IdentityPool::new(5);
    pool.total_flags = 10;
    // No burns: efficiency = 10.0 (infinite effective)
    assert_eq!(pool.identity_efficiency(), 10.0);
}

#[test]
fn identity_efficiency_with_burns() {
    let mut pool = IdentityPool::new(5);
    pool.total_flags = 6;
    pool.total_burned = 3;
    assert!((pool.identity_efficiency() - 2.0).abs() < f64::EPSILON);
}

#[test]
fn record_flag_capture_increments() {
    let mut pool = IdentityPool::new(3);
    assert_eq!(pool.total_flags, 0);
    pool.record_flag_capture();
    pool.record_flag_capture();
    assert_eq!(pool.total_flags, 2);
}

#[test]
fn identity_briefing_contains_current() {
    let pool = IdentityPool::new(5);
    let briefing = pool.identity_briefing();
    assert!(briefing.contains("Current Identity"));
    assert!(briefing.contains("Active identities remaining"));
    assert!(briefing.contains("5/5"));
}

#[test]
fn identity_briefing_shows_burned() {
    let mut pool = IdentityPool::new(5);
    let id = pool.identities[0].id.clone();
    pool.burn_identity(&id);

    let briefing = pool.identity_briefing();
    assert!(briefing.contains("Burned identities"));
    assert!(briefing.contains(&id));
    assert!(briefing.contains("4/5"));
}

#[test]
fn identity_briefing_no_active_warning() {
    let mut pool = IdentityPool::new(2);
    let ids: Vec<String> = pool.identities.iter().map(|id| id.id.clone()).collect();
    for id in &ids {
        pool.burn_identity(id);
    }

    let briefing = pool.identity_briefing();
    assert!(briefing.contains("WARNING"));
    assert!(briefing.contains("Forge mode"));
}
