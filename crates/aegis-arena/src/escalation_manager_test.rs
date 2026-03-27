use super::*;

#[test]
fn default_has_20_endpoints_in_pool() {
    let mgr = EscalationManager::default();
    assert_eq!(mgr.endpoint_pool.len(), 20);
    assert_eq!(mgr.next_endpoint_index, 0);
}

#[test]
fn default_has_8_initial_endpoints() {
    let mgr = EscalationManager::default();
    assert_eq!(mgr.active_endpoints.len(), 8);
    assert!(mgr.active_endpoints.contains(&"/search".to_string()));
    assert!(mgr.active_endpoints.contains(&"/flag".to_string()));
    assert!(mgr.active_endpoints.contains(&"/health".to_string()));
}

#[test]
fn default_has_8_capabilities() {
    let mgr = EscalationManager::default();
    assert_eq!(mgr.capabilities.len(), 8);
    let red_caps: Vec<_> = mgr.capabilities.iter().filter(|c| c.is_red).collect();
    let blue_caps: Vec<_> = mgr.capabilities.iter().filter(|c| !c.is_red).collect();
    assert_eq!(red_caps.len(), 4);
    assert_eq!(blue_caps.len(), 4);
}

#[test]
fn add_next_endpoint() {
    let mut mgr = EscalationManager::new(10, 25);
    assert_eq!(mgr.active_endpoints.len(), 8);

    let added = mgr.add_next_endpoint(10);
    assert!(added.is_some());
    assert_eq!(added.unwrap(), "/api/graphql");
    assert_eq!(mgr.active_endpoints.len(), 9);
    assert_eq!(mgr.next_endpoint_index, 1);
    assert_eq!(mgr.endpoint_pool[0].unlocked_at_cycle, 10);
}

#[test]
fn add_endpoints_sequentially() {
    let mut mgr = EscalationManager::new(10, 25);

    let first = mgr.add_next_endpoint(10).unwrap();
    let second = mgr.add_next_endpoint(20).unwrap();
    let third = mgr.add_next_endpoint(30).unwrap();

    assert_eq!(first, "/api/graphql");
    assert_eq!(second, "/upload");
    assert_eq!(third, "/webhook");
    assert_eq!(mgr.active_endpoints.len(), 11);
}

#[test]
fn endpoint_pool_exhaustion() {
    let mut mgr = EscalationManager::new(10, 25);
    for i in 0..20 {
        let result = mgr.add_next_endpoint((i + 1) * 10);
        assert!(result.is_some());
    }
    // Pool exhausted
    assert!(mgr.add_next_endpoint(210).is_none());
    assert_eq!(mgr.active_endpoints.len(), 28); // 8 initial + 20 escalated
}

#[test]
fn check_escalation_at_cycle_10() {
    let mut mgr = EscalationManager::new(10, 25);
    let event = mgr.check_escalation(10);

    assert!(event.has_changes());
    assert!(event.new_endpoint.is_some());
    assert_eq!(event.new_endpoint.unwrap(), "/api/graphql");
    assert!(event.new_capabilities.is_empty()); // 25 not reached
}

#[test]
fn check_escalation_at_cycle_25() {
    let mut mgr = EscalationManager::new(10, 25);
    // Add endpoints up to cycle 20
    mgr.check_escalation(10);
    mgr.check_escalation(20);

    let event = mgr.check_escalation(25);
    assert!(event.has_changes());
    // 25 is NOT divisible by 10, so no new endpoint
    assert!(event.new_endpoint.is_none());
    // But capability unlock at cycle 25
    assert!(!event.new_capabilities.is_empty());
    // Should unlock both payload_obfuscation (Red) and regex_bans (Blue)
    assert!(event
        .new_capabilities
        .contains(&"payload_obfuscation".to_string()));
    assert!(event.new_capabilities.contains(&"regex_bans".to_string()));
}

#[test]
fn check_escalation_no_trigger_at_odd_cycle() {
    let mut mgr = EscalationManager::new(10, 25);
    let event = mgr.check_escalation(7);
    assert!(!event.has_changes());
    assert!(event.new_endpoint.is_none());
    assert!(event.new_capabilities.is_empty());
}

#[test]
fn capabilities_unlock_progressively() {
    let mut mgr = EscalationManager::new(10, 25);

    // Nothing unlocked initially
    assert!(mgr.red_capabilities().is_empty());
    assert!(mgr.blue_capabilities().is_empty());

    mgr.check_escalation(25);
    assert_eq!(mgr.red_capabilities().len(), 1);
    assert_eq!(mgr.blue_capabilities().len(), 1);

    mgr.check_escalation(50);
    assert_eq!(mgr.red_capabilities().len(), 2);
    assert_eq!(mgr.blue_capabilities().len(), 2);

    mgr.check_escalation(75);
    assert_eq!(mgr.red_capabilities().len(), 3);
    assert_eq!(mgr.blue_capabilities().len(), 3);

    mgr.check_escalation(100);
    assert_eq!(mgr.red_capabilities().len(), 4);
    assert_eq!(mgr.blue_capabilities().len(), 4);
}

#[test]
fn capability_unlock_at_correct_cycle() {
    let mut mgr = EscalationManager::new(10, 25);
    mgr.check_escalation(25);

    let red = mgr.red_capabilities();
    assert_eq!(red[0].name, "payload_obfuscation");
    assert_eq!(red[0].unlock_cycle, 25);

    let blue = mgr.blue_capabilities();
    assert_eq!(blue[0].name, "regex_bans");
}

#[test]
fn escalation_level_increases() {
    let mut mgr = EscalationManager::new(10, 25);
    assert_eq!(mgr.escalation_level(), 0);

    mgr.check_escalation(10);
    assert!(mgr.escalation_level() > 0);

    mgr.check_escalation(25);
    let level_at_25 = mgr.escalation_level();
    assert!(level_at_25 >= 3); // 3 endpoints + 2 capabilities
}

#[test]
fn escalation_briefing_empty_initially() {
    let mgr = EscalationManager::new(10, 25);
    let briefing = mgr.escalation_briefing();
    assert!(briefing.contains("Escalation Status"));
    assert!(briefing.contains("8 base + 0 escalated"));
}

#[test]
fn escalation_briefing_after_unlocks() {
    let mut mgr = EscalationManager::new(10, 25);
    mgr.check_escalation(10);
    mgr.check_escalation(25);

    let briefing = mgr.escalation_briefing();
    assert!(briefing.contains("Escalated endpoints"));
    assert!(briefing.contains("/api/graphql"));
    assert!(briefing.contains("Red capabilities unlocked"));
    assert!(briefing.contains("payload_obfuscation"));
    assert!(briefing.contains("Blue capabilities unlocked"));
    assert!(briefing.contains("regex_bans"));
}

#[test]
fn endpoints_since_returns_new_only() {
    let mut mgr = EscalationManager::new(10, 25);
    mgr.check_escalation(10);
    mgr.check_escalation(20);

    let since_10 = mgr.endpoints_since(10);
    assert_eq!(since_10.len(), 1);
    assert_eq!(since_10[0].path, "/upload");

    let since_0 = mgr.endpoints_since(0);
    assert_eq!(since_0.len(), 2);
}

#[test]
fn escalation_manager_custom_intervals() {
    let mut mgr = EscalationManager::new(5, 10);
    mgr.check_escalation(5);
    assert_eq!(mgr.active_endpoints.len(), 9); // 8 + 1

    mgr.check_escalation(10);
    assert_eq!(mgr.active_endpoints.len(), 10); // 8 + 2
                                                // Also unlocks capabilities at cycle 10 (anything ≤10)
                                                // None of the default capabilities unlock at 10 (first is 25)
    assert!(mgr.red_capabilities().is_empty());
}

#[test]
fn zero_interval_never_triggers() {
    let mut mgr = EscalationManager::new(0, 0);
    let event = mgr.check_escalation(10);
    assert!(!event.has_changes());
}

#[test]
fn escalated_endpoint_count() {
    let mut mgr = EscalationManager::new(10, 25);
    assert_eq!(mgr.escalated_endpoint_count(), 0);

    mgr.add_next_endpoint(10);
    assert_eq!(mgr.escalated_endpoint_count(), 1);

    mgr.add_next_endpoint(20);
    assert_eq!(mgr.escalated_endpoint_count(), 2);
}

#[test]
fn all_endpoints_have_descriptions() {
    let mgr = EscalationManager::default();
    for ep in &mgr.endpoint_pool {
        assert!(!ep.path.is_empty());
        assert!(!ep.vuln_class.is_empty());
        assert!(!ep.description.is_empty());
        assert!(ep.path.starts_with('/'));
    }
}

#[test]
fn all_capabilities_have_descriptions() {
    let mgr = EscalationManager::default();
    for cap in &mgr.capabilities {
        assert!(!cap.name.is_empty());
        assert!(!cap.description.is_empty());
        assert!(cap.unlock_cycle > 0);
    }
}
