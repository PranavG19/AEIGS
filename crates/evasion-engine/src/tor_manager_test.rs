use super::*;

fn make_manager() -> TorCircuitManager {
    TorCircuitManager::with_seed(TorConfig::default(), 42)
}

#[test]
fn create_circuit_assigns_incrementing_ids() {
    let mut mgr = make_manager();
    let id1 = mgr.create_circuit(None, None);
    let id2 = mgr.create_circuit(None, None);
    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
}

#[test]
fn circuit_starts_ready() {
    let mut mgr = make_manager();
    let id = mgr.create_circuit(None, None);
    let circuit = mgr.get_circuit(id).unwrap();
    assert_eq!(circuit.state, CircuitState::Ready);
}

#[test]
fn circuit_per_target_isolation() {
    let mut mgr = make_manager();
    let id_a = mgr.circuit_for_target("https://target-a.com");
    let id_b = mgr.circuit_for_target("https://target-b.com");
    assert_ne!(id_a, id_b);
}

#[test]
fn same_target_reuses_circuit() {
    let mut mgr = make_manager();
    let id1 = mgr.circuit_for_target("https://target.com");
    let id2 = mgr.circuit_for_target("https://target.com");
    assert_eq!(id1, id2);
}

#[test]
fn activate_circuit_changes_state() {
    let mut mgr = make_manager();
    let id = mgr.create_circuit(None, None);
    mgr.activate_circuit(id);
    assert_eq!(mgr.get_circuit(id).unwrap().state, CircuitState::Active);
}

#[test]
fn close_circuit_removes_target_mapping() {
    let mut mgr = make_manager();
    let id = mgr.circuit_for_target("https://target.com");
    mgr.close_circuit(id);
    assert_eq!(mgr.get_circuit(id).unwrap().state, CircuitState::Closed);
    let new_id = mgr.circuit_for_target("https://target.com");
    assert_ne!(id, new_id);
}

#[test]
fn rotate_circuit_creates_new_for_target() {
    let mut mgr = make_manager();
    let id1 = mgr.circuit_for_target("https://target.com");
    let id2 = mgr.rotate_circuit("https://target.com");
    assert_ne!(id1, id2);
    assert_eq!(mgr.get_circuit(id1).unwrap().state, CircuitState::Closed);
    assert_eq!(mgr.get_circuit(id2).unwrap().state, CircuitState::Ready);
}

#[test]
fn record_latency_updates_circuit() {
    let mut mgr = make_manager();
    let id = mgr.create_circuit(None, None);
    mgr.record_latency(id, 350);
    assert_eq!(mgr.get_circuit(id).unwrap().latency_ms, Some(350));
}

#[test]
fn exit_country_selection() {
    let mut mgr = make_manager();
    let country = CountryCode::new("DE");
    let id = mgr.create_circuit(None, Some(&country));
    let circuit = mgr.get_circuit(id).unwrap();
    assert_eq!(circuit.exit_country.as_ref().unwrap().0, "DE");
}

#[test]
fn preferred_exit_countries() {
    let mut mgr = TorCircuitManager::with_seed(
        TorConfig::default().with_preferred_exit_countries(vec![
            CountryCode::new("US"),
            CountryCode::new("DE"),
            CountryCode::new("NL"),
        ]),
        42,
    );
    let id = mgr.create_circuit(None, None);
    let circuit = mgr.get_circuit(id).unwrap();
    assert!(circuit.exit_country.is_some());
    let exit = circuit.exit_country.as_ref().unwrap();
    assert!(["US", "DE", "NL"].contains(&exit.0.as_str()));
}

#[test]
fn excluded_exit_countries_fail_circuit() {
    let mut mgr = TorCircuitManager::with_seed(
        TorConfig::default().with_excluded_exit_countries(vec![CountryCode::new("CN")]),
        42,
    );
    let id = mgr.create_circuit(None, Some(&CountryCode::new("CN")));
    let circuit = mgr.get_circuit(id).unwrap();
    assert_eq!(circuit.state, CircuitState::Failed);
}

#[test]
fn add_bridge_relay() {
    let mut mgr = make_manager();
    mgr.add_bridge(BridgeRelay {
        address: "198.51.100.1".to_string(),
        port: 443,
        transport: BridgeTransport::Obfs4,
        fingerprint: Some("AAAA".to_string()),
    });
    assert_eq!(mgr.bridges().len(), 1);
}

#[test]
fn bridge_relay_marks_circuit() {
    let mut mgr = make_manager();
    mgr.add_bridge(BridgeRelay {
        address: "198.51.100.1".to_string(),
        port: 443,
        transport: BridgeTransport::Snowflake,
        fingerprint: None,
    });
    let id = mgr.create_circuit(None, None);
    assert!(mgr.get_circuit(id).unwrap().uses_bridge);
}

#[test]
fn no_bridge_circuit_not_marked() {
    let mut mgr = make_manager();
    let id = mgr.create_circuit(None, None);
    assert!(!mgr.get_circuit(id).unwrap().uses_bridge);
}

#[test]
fn is_onion_address_detects_onion() {
    assert!(TorCircuitManager::is_onion_address(
        "http://facebookcorewwwi.onion"
    ));
    assert!(TorCircuitManager::is_onion_address(
        "https://xyz.ONION/path"
    ));
    assert!(!TorCircuitManager::is_onion_address("https://example.com"));
}

#[test]
fn socks_address_format() {
    let mgr = make_manager();
    assert_eq!(mgr.socks_address(), "socks5://127.0.0.1:9050");
}

#[test]
fn custom_socks_port() {
    let mgr = TorCircuitManager::with_seed(TorConfig::default().with_socks_port(9150), 42);
    assert_eq!(mgr.socks_address(), "socks5://127.0.0.1:9150");
}

#[test]
fn active_circuits_count() {
    let mut mgr = make_manager();
    mgr.create_circuit(None, None);
    mgr.create_circuit(None, None);
    assert_eq!(mgr.active_count(), 2);
    let id3 = mgr.create_circuit(None, None);
    mgr.close_circuit(id3);
    assert_eq!(mgr.active_count(), 2);
}

#[test]
fn total_circuits_includes_all_states() {
    let mut mgr = make_manager();
    mgr.create_circuit(None, None);
    let id2 = mgr.create_circuit(None, None);
    mgr.close_circuit(id2);
    assert_eq!(mgr.total_circuits(), 2);
}

#[test]
fn optimal_circuit_selects_lowest_latency() {
    let mut mgr = make_manager();
    let id1 = mgr.create_circuit(Some("target.com"), None);
    let id2 = mgr.create_circuit(Some("target.com"), None);
    mgr.record_latency(id1, 500);
    mgr.record_latency(id2, 200);
    let best = mgr.optimal_circuit_for_target("target.com").unwrap();
    assert_eq!(best.id, id2);
}

#[test]
fn prune_slow_circuits_closes_exceeding_latency() {
    let mut mgr =
        TorCircuitManager::with_seed(TorConfig::default().with_max_circuit_latency_ms(1000), 42);
    let id1 = mgr.create_circuit(Some("t"), None);
    let id2 = mgr.create_circuit(Some("t2"), None);
    mgr.record_latency(id1, 500);
    mgr.record_latency(id2, 2000);
    mgr.prune_slow_circuits();
    assert_eq!(mgr.get_circuit(id1).unwrap().state, CircuitState::Ready);
    assert_eq!(mgr.get_circuit(id2).unwrap().state, CircuitState::Closed);
}

#[test]
fn compose_with_proxy_builds_path() {
    let mgr = make_manager();
    let path = mgr.compose_with_proxy(5, &[1, 2]);
    assert_eq!(path, vec!["proxy:1", "proxy:2", "tor-circuit:5"]);
}

#[test]
fn country_code_display() {
    let cc = CountryCode::new("us");
    assert_eq!(format!("{cc}"), "US");
}

#[test]
fn bridge_transport_display() {
    assert_eq!(format!("{}", BridgeTransport::Obfs4), "obfs4");
    assert_eq!(format!("{}", BridgeTransport::Snowflake), "snowflake");
    assert_eq!(format!("{}", BridgeTransport::Meek), "meek");
    assert_eq!(format!("{}", BridgeTransport::Plain), "plain");
}

#[test]
fn circuit_state_display() {
    assert_eq!(format!("{}", CircuitState::Building), "building");
    assert_eq!(format!("{}", CircuitState::Ready), "ready");
    assert_eq!(format!("{}", CircuitState::Active), "active");
    assert_eq!(format!("{}", CircuitState::Closed), "closed");
    assert_eq!(format!("{}", CircuitState::Failed), "failed");
}

#[test]
fn get_circuit_none_for_unknown() {
    let mgr = make_manager();
    assert!(mgr.get_circuit(999).is_none());
}

#[test]
fn default_hops_is_three() {
    let mut mgr = make_manager();
    let id = mgr.create_circuit(None, None);
    assert_eq!(mgr.get_circuit(id).unwrap().hops, 3);
}
