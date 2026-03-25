use super::multi_hop_proxy::*;

fn make_composer() -> MultiHopComposer {
    MultiHopComposer::with_seed(MultiHopConfig::default(), 42)
}

fn add_diverse_nodes(c: &mut MultiHopComposer) {
    c.add_node(
        HopProtocol::Socks5,
        "10.0.1.1",
        1080,
        Jurisdiction::RO,
        InterHopEncryption::WireGuard,
        100,
        false,
    );
    c.add_node(
        HopProtocol::HttpConnect,
        "10.0.1.2",
        8080,
        Jurisdiction::PA,
        InterHopEncryption::SshTunnel,
        50,
        false,
    );
    c.add_node(
        HopProtocol::Tor,
        "10.0.1.3",
        9050,
        Jurisdiction::IS,
        InterHopEncryption::Tls13,
        25,
        true,
    );
    c.add_node(
        HopProtocol::WireGuard,
        "10.0.1.4",
        51820,
        Jurisdiction::CH,
        InterHopEncryption::WireGuard,
        200,
        true,
    );
    c.add_node(
        HopProtocol::SshTunnel,
        "10.0.1.5",
        22,
        Jurisdiction::MD,
        InterHopEncryption::SshTunnel,
        75,
        true,
    );
}

#[test]
fn add_node_assigns_incrementing_ids() {
    let mut c = make_composer();
    let id1 = c.add_node(
        HopProtocol::Socks5,
        "10.0.0.1",
        1080,
        Jurisdiction::RO,
        InterHopEncryption::WireGuard,
        100,
        false,
    );
    let id2 = c.add_node(
        HopProtocol::Tor,
        "10.0.0.2",
        9050,
        Jurisdiction::PA,
        InterHopEncryption::Tls13,
        50,
        true,
    );
    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
    assert_eq!(c.pool_size(), 2);
}

#[test]
fn compose_path_returns_none_when_insufficient_nodes() {
    let mut c = make_composer();
    c.add_node(
        HopProtocol::Socks5,
        "10.0.0.1",
        1080,
        Jurisdiction::RO,
        InterHopEncryption::WireGuard,
        100,
        true,
    );
    assert!(c.compose_path().is_none());
}

#[test]
fn compose_path_builds_chain_with_correct_hop_count() {
    let mut c = make_composer();
    add_diverse_nodes(&mut c);
    let path = c.compose_path().unwrap();
    assert!(path.hops.len() >= 2);
    assert!(path.hops.len() <= 5);
}

#[test]
fn protocol_mixing_uses_multiple_protocols() {
    let mut c =
        MultiHopComposer::with_seed(MultiHopConfig::default().with_protocol_mixing(true), 42);
    add_diverse_nodes(&mut c);
    let path = c.compose_path().unwrap();
    assert!(path.protocol_diversity() >= 2);
}

#[test]
fn non_mlat_route_avoids_mlat_jurisdictions() {
    let mut c =
        MultiHopComposer::with_seed(MultiHopConfig::default().with_non_mlat_route(true), 42);
    add_diverse_nodes(&mut c);
    let path = c.compose_path().unwrap();
    assert!(path.avoids_mlat);
}

#[test]
fn mlat_jurisdiction_detection() {
    assert!(MultiHopComposer::is_mlat_jurisdiction(&Jurisdiction::US));
    assert!(MultiHopComposer::is_mlat_jurisdiction(&Jurisdiction::GB));
    assert!(!MultiHopComposer::is_mlat_jurisdiction(&Jurisdiction::RO));
    assert!(!MultiHopComposer::is_mlat_jurisdiction(&Jurisdiction::PA));
}

#[test]
fn exit_node_is_last_hop() {
    let mut c = make_composer();
    add_diverse_nodes(&mut c);
    let path = c.compose_path().unwrap();
    assert_eq!(path.exit_node(), path.hops.last().copied());
    assert_eq!(path.entry_node(), path.hops.first().copied());
}

#[test]
fn failover_replaces_failed_hop() {
    let mut c = make_composer();
    add_diverse_nodes(&mut c);
    let original = c.compose_path().unwrap();
    let failed_id = original.hops[0];
    let replacement = c.failover(&original, failed_id);
    assert!(replacement.is_some());
    let new_path = replacement.unwrap();
    assert!(!new_path.hops.contains(&failed_id));
    assert!(!c.failover_history().is_empty());
}

#[test]
fn failover_disabled_returns_none() {
    let config = MultiHopConfig {
        failover_enabled: false,
        ..MultiHopConfig::default()
    };
    let mut c = MultiHopComposer::with_seed(config, 42);
    add_diverse_nodes(&mut c);
    let original = c.compose_path().unwrap();
    let failed_id = original.hops[0];
    assert!(c.failover(&original, failed_id).is_none());
}

#[test]
fn record_verification_updates_health() {
    let mut c = make_composer();
    let id = c.add_node(
        HopProtocol::Socks5,
        "10.0.0.1",
        1080,
        Jurisdiction::RO,
        InterHopEncryption::WireGuard,
        100,
        true,
    );
    c.record_verification(HopVerification {
        hop_id: id,
        alive: true,
        latency_ms: 42,
        intercept_detected: false,
        tls_cert_matches: true,
    });
    let health = c.get_health(id).unwrap();
    assert_eq!(health.latency_ms, 42);
    assert!(health.alive);
    assert!(!health.intercept_detected);
}

#[test]
fn intercept_detection_marks_node_unusable() {
    let mut c = make_composer();
    let id = c.add_node(
        HopProtocol::Socks5,
        "10.0.0.1",
        1080,
        Jurisdiction::RO,
        InterHopEncryption::WireGuard,
        100,
        true,
    );
    c.record_verification(HopVerification {
        hop_id: id,
        alive: true,
        latency_ms: 50,
        intercept_detected: true,
        tls_cert_matches: false,
    });
    let health = c.get_health(id).unwrap();
    assert!(!health.is_usable());
}

#[test]
fn verify_chain_returns_unhealthy_hops() {
    let mut c = make_composer();
    add_diverse_nodes(&mut c);
    let path = c.compose_path().unwrap();
    let bad_id = path.hops[0];
    c.record_verification(HopVerification {
        hop_id: bad_id,
        alive: false,
        latency_ms: 0,
        intercept_detected: false,
        tls_cert_matches: false,
    });
    let failed = c.verify_chain(&path);
    assert!(failed.contains(&bad_id));
}

#[test]
fn encrypted_inter_hop_flag_reflects_chain() {
    let mut c =
        MultiHopComposer::with_seed(MultiHopConfig::default().with_encrypted_inter_hop(true), 42);
    add_diverse_nodes(&mut c);
    let path = c.compose_path().unwrap();
    assert!(path.fully_encrypted);
}

#[test]
fn non_mlat_jurisdictions_lists_only_non_mlat() {
    let mut c = make_composer();
    add_diverse_nodes(&mut c);
    let nml = c.non_mlat_jurisdictions();
    for j in &nml {
        assert!(!MultiHopComposer::is_mlat_jurisdiction(j));
    }
}

#[test]
fn hop_protocol_display() {
    assert_eq!(format!("{}", HopProtocol::Socks5), "SOCKS5");
    assert_eq!(format!("{}", HopProtocol::Tor), "Tor");
    assert_eq!(format!("{}", HopProtocol::WireGuard), "WireGuard");
    assert_eq!(format!("{}", HopProtocol::SshTunnel), "SSH-Tunnel");
    assert_eq!(format!("{}", HopProtocol::Residential), "Residential");
}

#[test]
fn inter_hop_encryption_display() {
    assert_eq!(format!("{}", InterHopEncryption::None), "none");
    assert_eq!(format!("{}", InterHopEncryption::WireGuard), "WireGuard");
    assert_eq!(format!("{}", InterHopEncryption::SshTunnel), "SSH");
    assert_eq!(format!("{}", InterHopEncryption::Tls13), "TLS-1.3");
}

#[test]
fn hop_node_display_format() {
    let mut c = make_composer();
    let id = c.add_node(
        HopProtocol::Socks5,
        "10.0.0.1",
        1080,
        Jurisdiction::RO,
        InterHopEncryption::WireGuard,
        100,
        true,
    );
    let node = c.get_node(id).unwrap();
    let display = format!("{node}");
    assert!(display.contains("SOCKS5"));
    assert!(display.contains("10.0.0.1:1080"));
    assert!(display.contains("RO"));
}

#[test]
fn usable_count_reflects_health() {
    let mut c = make_composer();
    add_diverse_nodes(&mut c);
    assert_eq!(c.usable_count(), 5);
    c.record_verification(HopVerification {
        hop_id: 1,
        alive: false,
        latency_ms: 0,
        intercept_detected: false,
        tls_cert_matches: false,
    });
    assert_eq!(c.usable_count(), 4);
}

#[test]
fn target_jurisdiction_hint_influences_exit_selection() {
    let mut c = MultiHopComposer::with_seed(MultiHopConfig::default(), 42);
    add_diverse_nodes(&mut c);
    c.set_target_jurisdiction(Jurisdiction::IS);
    let path = c.compose_path().unwrap();
    let exit_id = path.exit_node().unwrap();
    let exit_node = c.get_node(exit_id).unwrap();
    assert_eq!(exit_node.jurisdiction, Jurisdiction::IS);
}

#[test]
fn config_builder_pattern() {
    let config = MultiHopConfig::default()
        .with_min_hops(3)
        .with_max_hops(6)
        .with_protocol_mixing(false)
        .with_non_mlat_route(false)
        .with_encrypted_inter_hop(false)
        .with_max_latency(10000);
    assert_eq!(config.min_hops, 3);
    assert_eq!(config.max_hops, 6);
    assert!(!config.require_protocol_mixing);
    assert!(!config.require_non_mlat_route);
    assert!(!config.require_encrypted_inter_hop);
    assert_eq!(config.max_total_latency_ms, 10000);
}
