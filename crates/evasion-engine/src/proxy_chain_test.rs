use super::*;

fn make_manager() -> ProxyChainManager {
    ProxyChainManager::with_seed(ProxyChainConfig::default(), 42)
}

fn add_diverse_proxies(mgr: &mut ProxyChainManager) {
    mgr.add_proxy(
        ProxyProtocol::Socks5,
        "10.0.0.1",
        1080,
        GeoRegion::NorthAmerica,
        ReputationTier::Datacenter,
        None,
    );
    mgr.add_proxy(
        ProxyProtocol::HttpConnect,
        "10.0.0.2",
        8080,
        GeoRegion::Europe,
        ReputationTier::Residential,
        None,
    );
    mgr.add_proxy(
        ProxyProtocol::Tor,
        "10.0.0.3",
        9050,
        GeoRegion::AsiaPacific,
        ReputationTier::Unknown,
        None,
    );
    mgr.add_proxy(
        ProxyProtocol::Socks5,
        "10.0.0.4",
        1081,
        GeoRegion::SouthAmerica,
        ReputationTier::Mobile,
        None,
    );
}

#[test]
fn add_proxy_assigns_incrementing_ids() {
    let mut mgr = make_manager();
    let id1 = mgr.add_proxy(
        ProxyProtocol::Socks5,
        "10.0.0.1",
        1080,
        GeoRegion::NorthAmerica,
        ReputationTier::Datacenter,
        None,
    );
    let id2 = mgr.add_proxy(
        ProxyProtocol::HttpConnect,
        "10.0.0.2",
        8080,
        GeoRegion::Europe,
        ReputationTier::Residential,
        None,
    );
    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
    assert_eq!(mgr.pool_size(), 2);
}

#[test]
fn empty_pool_returns_none() {
    let mut mgr = make_manager();
    assert!(mgr.build_chain("https://target.com").is_none());
}

#[test]
fn single_proxy_builds_single_hop() {
    let mut mgr = make_manager();
    mgr.add_proxy(
        ProxyProtocol::Socks5,
        "10.0.0.1",
        1080,
        GeoRegion::NorthAmerica,
        ReputationTier::Datacenter,
        None,
    );
    let chain = mgr.build_chain("https://target.com").unwrap();
    assert_eq!(chain.hops.len(), 1);
}

#[test]
fn build_chain_uses_geo_diversity() {
    let mut mgr = ProxyChainManager::with_seed(
        ProxyChainConfig::default()
            .with_min_chain_length(3)
            .with_geo_diversity(true),
        42,
    );
    add_diverse_proxies(&mut mgr);
    let chain = mgr.build_chain("https://target.com").unwrap();
    let regions: HashSet<GeoRegion> = chain
        .hops
        .iter()
        .filter_map(|id| mgr.get_node(*id))
        .map(|n| n.region)
        .collect();
    assert_eq!(regions.len(), chain.hops.len());
}

#[test]
fn burn_proxy_excludes_from_future_chains() {
    let mut mgr = make_manager();
    let id1 = mgr.add_proxy(
        ProxyProtocol::Socks5,
        "10.0.0.1",
        1080,
        GeoRegion::NorthAmerica,
        ReputationTier::Datacenter,
        None,
    );
    mgr.add_proxy(
        ProxyProtocol::HttpConnect,
        "10.0.0.2",
        8080,
        GeoRegion::Europe,
        ReputationTier::Residential,
        None,
    );
    mgr.burn_proxy("https://target.com", id1);
    let chain = mgr.build_chain("https://target.com").unwrap();
    assert!(!chain.hops.contains(&id1));
}

#[test]
fn burned_proxy_scoped_to_target() {
    let mut mgr = make_manager();
    let id1 = mgr.add_proxy(
        ProxyProtocol::Socks5,
        "10.0.0.1",
        1080,
        GeoRegion::NorthAmerica,
        ReputationTier::Datacenter,
        None,
    );
    mgr.burn_proxy("https://target-a.com", id1);
    let chain = mgr.build_chain("https://target-b.com").unwrap();
    assert!(chain.hops.contains(&id1));
}

#[test]
fn record_health_check_updates_latency() {
    let mut mgr = make_manager();
    let id = mgr.add_proxy(
        ProxyProtocol::Socks5,
        "10.0.0.1",
        1080,
        GeoRegion::NorthAmerica,
        ReputationTier::Datacenter,
        None,
    );
    mgr.record_health_check(id, 150, true);
    assert_eq!(mgr.get_health(id).unwrap().latency_ms, 150);
}

#[test]
fn consecutive_failures_mark_unhealthy() {
    let mut mgr = make_manager();
    let id = mgr.add_proxy(
        ProxyProtocol::Socks5,
        "10.0.0.1",
        1080,
        GeoRegion::NorthAmerica,
        ReputationTier::Datacenter,
        None,
    );
    for _ in 0..3 {
        mgr.record_health_check(id, 0, false);
    }
    assert!(!mgr.get_health(id).unwrap().is_healthy());
    assert_eq!(mgr.healthy_count(), 0);
}

#[test]
fn success_resets_failure_count() {
    let mut mgr = make_manager();
    let id = mgr.add_proxy(
        ProxyProtocol::Socks5,
        "10.0.0.1",
        1080,
        GeoRegion::NorthAmerica,
        ReputationTier::Datacenter,
        None,
    );
    mgr.record_health_check(id, 0, false);
    mgr.record_health_check(id, 0, false);
    mgr.record_health_check(id, 100, true);
    assert_eq!(mgr.get_health(id).unwrap().consecutive_failures, 0);
}

#[test]
fn rotate_on_detection_burns_exit_and_rebuilds() {
    let mut mgr =
        ProxyChainManager::with_seed(ProxyChainConfig::default().with_min_chain_length(1), 42);
    let _id1 = mgr.add_proxy(
        ProxyProtocol::Socks5,
        "10.0.0.1",
        1080,
        GeoRegion::NorthAmerica,
        ReputationTier::Datacenter,
        None,
    );
    mgr.add_proxy(
        ProxyProtocol::HttpConnect,
        "10.0.0.2",
        8080,
        GeoRegion::Europe,
        ReputationTier::Residential,
        None,
    );
    let first_chain = mgr.build_chain("https://target.com").unwrap();
    let exit_id = *first_chain.hops.last().unwrap();
    let new_chain = mgr
        .rotate_on_detection("https://target.com", &first_chain)
        .unwrap();
    assert!(!new_chain.hops.contains(&exit_id));
    assert!(mgr
        .burned_for_target("https://target.com")
        .contains(&exit_id));
}

#[test]
fn all_burned_returns_none() {
    let mut mgr = make_manager();
    let id = mgr.add_proxy(
        ProxyProtocol::Socks5,
        "10.0.0.1",
        1080,
        GeoRegion::NorthAmerica,
        ReputationTier::Datacenter,
        None,
    );
    mgr.burn_proxy("https://target.com", id);
    assert!(mgr.build_chain("https://target.com").is_none());
}

#[test]
fn available_regions_reflects_healthy_nodes() {
    let mut mgr = make_manager();
    add_diverse_proxies(&mut mgr);
    let regions = mgr.available_regions();
    assert!(regions.contains(&GeoRegion::NorthAmerica));
    assert!(regions.contains(&GeoRegion::Europe));
    assert!(regions.contains(&GeoRegion::AsiaPacific));
    assert!(regions.contains(&GeoRegion::SouthAmerica));
    assert_eq!(regions.len(), 4);
}

#[test]
fn prefer_residential_sorts_candidates() {
    let mut mgr = ProxyChainManager::with_seed(
        ProxyChainConfig::default()
            .with_min_chain_length(1)
            .with_max_chain_length(1)
            .with_prefer_residential(true)
            .with_geo_diversity(false),
        42,
    );
    mgr.add_proxy(
        ProxyProtocol::Socks5,
        "10.0.0.1",
        1080,
        GeoRegion::NorthAmerica,
        ReputationTier::Datacenter,
        None,
    );
    let res_id = mgr.add_proxy(
        ProxyProtocol::HttpConnect,
        "10.0.0.2",
        8080,
        GeoRegion::NorthAmerica,
        ReputationTier::Residential,
        None,
    );
    let chain = mgr.build_chain("https://target.com").unwrap();
    assert_eq!(chain.hops[0], res_id);
}

#[test]
fn proxy_node_display() {
    let node = ProxyNode {
        id: 1,
        protocol: ProxyProtocol::Socks5,
        host: "10.0.0.1".to_string(),
        port: 1080,
        region: GeoRegion::NorthAmerica,
        reputation: ReputationTier::Datacenter,
        auth: None,
    };
    let display = format!("{node}");
    assert!(display.contains("SOCKS5"));
    assert!(display.contains("10.0.0.1:1080"));
    assert!(display.contains("NA"));
}

#[test]
fn proxy_auth_stored_correctly() {
    let mut mgr = make_manager();
    let auth = ProxyAuth {
        username: "user".to_string(),
        password: "pass".to_string(),
    };
    let id = mgr.add_proxy(
        ProxyProtocol::HttpConnect,
        "proxy.example.com",
        8080,
        GeoRegion::Europe,
        ReputationTier::Residential,
        Some(auth),
    );
    let node = mgr.get_node(id).unwrap();
    let a = node.auth.as_ref().unwrap();
    assert_eq!(a.username, "user");
    assert_eq!(a.password, "pass");
}

#[test]
fn residential_provider_bright_data() {
    let provider = ResidentialProvider::BrightData {
        zone: "residential".to_string(),
        api_token: "tok123".to_string(),
    };
    let endpoint = provider.endpoint();
    assert!(endpoint.contains("lum-superproxy.io"));
    let auth = provider.auth();
    assert!(auth.username.contains("residential"));
    assert_eq!(auth.password, "tok123");
}

#[test]
fn residential_provider_oxylabs() {
    let provider = ResidentialProvider::Oxylabs {
        username: "oxy_user".to_string(),
        password: "oxy_pass".to_string(),
    };
    let endpoint = provider.endpoint();
    assert!(endpoint.contains("oxylabs.io"));
    let auth = provider.auth();
    assert_eq!(auth.username, "oxy_user");
    assert_eq!(auth.password, "oxy_pass");
}

#[test]
fn add_residential_provider_registers() {
    let mut mgr = make_manager();
    mgr.add_residential_provider(ResidentialProvider::BrightData {
        zone: "zone1".to_string(),
        api_token: "token".to_string(),
    });
    assert_eq!(mgr.residential_providers().len(), 1);
}

#[test]
fn chain_estimated_latency_sums_node_latencies() {
    let mut mgr = ProxyChainManager::with_seed(
        ProxyChainConfig::default()
            .with_min_chain_length(2)
            .with_geo_diversity(false),
        42,
    );
    let id1 = mgr.add_proxy(
        ProxyProtocol::Socks5,
        "10.0.0.1",
        1080,
        GeoRegion::NorthAmerica,
        ReputationTier::Datacenter,
        None,
    );
    let id2 = mgr.add_proxy(
        ProxyProtocol::HttpConnect,
        "10.0.0.2",
        8080,
        GeoRegion::NorthAmerica,
        ReputationTier::Residential,
        None,
    );
    mgr.record_health_check(id1, 100, true);
    mgr.record_health_check(id2, 200, true);
    let chain = mgr.build_chain("https://target.com").unwrap();
    assert_eq!(chain.estimated_latency_ms, 300);
}

#[test]
fn protocol_display_variants() {
    assert_eq!(format!("{}", ProxyProtocol::Socks5), "SOCKS5");
    assert_eq!(format!("{}", ProxyProtocol::HttpConnect), "HTTP-CONNECT");
    assert_eq!(format!("{}", ProxyProtocol::Tor), "Tor");
}

#[test]
fn geo_region_display_variants() {
    assert_eq!(format!("{}", GeoRegion::NorthAmerica), "NA");
    assert_eq!(format!("{}", GeoRegion::Europe), "EU");
    assert_eq!(format!("{}", GeoRegion::AsiaPacific), "APAC");
    assert_eq!(format!("{}", GeoRegion::SouthAmerica), "SA");
    assert_eq!(format!("{}", GeoRegion::Africa), "AF");
    assert_eq!(format!("{}", GeoRegion::MiddleEast), "ME");
    assert_eq!(format!("{}", GeoRegion::Oceania), "OC");
}

#[test]
fn healthy_count_matches_pool() {
    let mut mgr = make_manager();
    add_diverse_proxies(&mut mgr);
    assert_eq!(mgr.healthy_count(), 4);
}

#[test]
fn unhealthy_nodes_excluded_from_chain() {
    let mut mgr = make_manager();
    let id1 = mgr.add_proxy(
        ProxyProtocol::Socks5,
        "10.0.0.1",
        1080,
        GeoRegion::NorthAmerica,
        ReputationTier::Datacenter,
        None,
    );
    mgr.add_proxy(
        ProxyProtocol::HttpConnect,
        "10.0.0.2",
        8080,
        GeoRegion::Europe,
        ReputationTier::Residential,
        None,
    );
    for _ in 0..3 {
        mgr.record_health_check(id1, 0, false);
    }
    let chain = mgr.build_chain("https://target.com").unwrap();
    assert!(!chain.hops.contains(&id1));
}

#[test]
fn max_chain_length_respected() {
    let mut mgr = ProxyChainManager::with_seed(
        ProxyChainConfig::default()
            .with_max_chain_length(2)
            .with_min_chain_length(2)
            .with_geo_diversity(false),
        42,
    );
    add_diverse_proxies(&mut mgr);
    let chain = mgr.build_chain("https://target.com").unwrap();
    assert!(chain.hops.len() <= 2);
}

#[test]
fn burned_for_target_empty_when_nothing_burned() {
    let mgr = make_manager();
    let burned = mgr.burned_for_target("https://target.com");
    assert!(burned.is_empty());
}

#[test]
fn get_node_returns_none_for_unknown_id() {
    let mgr = make_manager();
    assert!(mgr.get_node(999).is_none());
}

#[test]
fn get_health_returns_none_for_unknown_id() {
    let mgr = make_manager();
    assert!(mgr.get_health(999).is_none());
}
