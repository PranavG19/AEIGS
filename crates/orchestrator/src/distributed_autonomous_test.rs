use super::*;

fn make_node(id: &str, provider: NodeProvider, state: NodeState) -> ScanNode {
    ScanNode {
        id: id.to_string(),
        provider,
        region: GeoRegion {
            country_code: "US".to_string(),
            region_name: "New York".to_string(),
            provider_region_id: "nyc1".to_string(),
        },
        state,
        ip_address: Some("10.0.0.1".to_string()),
        assigned_targets: vec!["target.com".to_string()],
        assigned_modules: vec!["fuzz".to_string()],
        provisioned_at_ms: timestamp_ms(),
        max_lifetime_secs: 3600,
        findings_collected: 5,
        encryption_key_id: "key-001".to_string(),
    }
}

#[test]
fn node_provider_display() {
    assert_eq!(NodeProvider::Aws.to_string(), "AWS");
    assert_eq!(NodeProvider::Gcp.to_string(), "GCP");
    assert_eq!(NodeProvider::DigitalOcean.to_string(), "DigitalOcean");
    assert_eq!(NodeProvider::OvhCloud.to_string(), "OVH Cloud");
}

#[test]
fn node_state_display() {
    assert_eq!(NodeState::Provisioning.to_string(), "Provisioning");
    assert_eq!(NodeState::Ready.to_string(), "Ready");
    assert_eq!(NodeState::Scanning.to_string(), "Scanning");
    assert_eq!(NodeState::Destroyed.to_string(), "Destroyed");
}

#[test]
fn scan_node_is_alive() {
    let node = make_node("n1", NodeProvider::Aws, NodeState::Scanning);
    assert!(node.is_alive());

    let dead = make_node("n2", NodeProvider::Aws, NodeState::Destroyed);
    assert!(!dead.is_alive());

    let failed = make_node("n3", NodeProvider::Aws, NodeState::Failed);
    assert!(!failed.is_alive());
}

#[test]
fn scan_node_state_transitions_valid() {
    let mut node = make_node("n1", NodeProvider::Aws, NodeState::Provisioning);
    assert!(node.transition(NodeState::Ready));
    assert_eq!(node.state, NodeState::Ready);
    assert!(node.transition(NodeState::Scanning));
    assert_eq!(node.state, NodeState::Scanning);
    assert!(node.transition(NodeState::Aggregating));
    assert!(node.transition(NodeState::CleaningUp));
    assert!(node.transition(NodeState::Destroyed));
    assert_eq!(node.state, NodeState::Destroyed);
}

#[test]
fn scan_node_state_transition_invalid() {
    let mut node = make_node("n1", NodeProvider::Aws, NodeState::Provisioning);
    assert!(!node.transition(NodeState::Scanning));
    assert_eq!(node.state, NodeState::Provisioning);
}

#[test]
fn scan_node_failed_to_destroyed() {
    let mut node = make_node("n1", NodeProvider::Aws, NodeState::Provisioning);
    assert!(node.transition(NodeState::Failed));
    assert!(node.transition(NodeState::Destroyed));
}

#[test]
fn fleet_config_default() {
    let cfg = FleetConfig::default();
    assert_eq!(cfg.node_count, 5);
    assert!(!cfg.providers.is_empty());
    assert!(!cfg.regions.is_empty());
    assert!(cfg.auto_rotate);
    assert!(cfg.auto_destroy);
    assert_eq!(cfg.mesh_encryption, MeshEncryption::WireGuard);
    assert_eq!(cfg.result_encryption, ResultEncryption::Age);
}

#[test]
fn shard_targets_round_robin() {
    let targets: Vec<String> = (0..10).map(|i| format!("target-{i}.com")).collect();
    let shards = shard_targets(&targets, 3, ShardingStrategy::RoundRobin);
    assert_eq!(shards.len(), 3);
    assert_eq!(shards[0].len(), 4);
    assert_eq!(shards[1].len(), 3);
    assert_eq!(shards[2].len(), 3);
    let total: usize = shards.iter().map(|s| s.len()).sum();
    assert_eq!(total, 10);
}

#[test]
fn shard_targets_load_balanced() {
    let targets: Vec<String> = (0..7).map(|i| format!("t{i}.com")).collect();
    let shards = shard_targets(&targets, 3, ShardingStrategy::LoadBalanced);
    assert_eq!(shards.len(), 3);
    let total: usize = shards.iter().map(|s| s.len()).sum();
    assert_eq!(total, 7);
    let max_diff = shards.iter().map(|s| s.len()).max().unwrap()
        - shards.iter().map(|s| s.len()).min().unwrap();
    assert!(max_diff <= 1);
}

#[test]
fn shard_targets_zero_nodes() {
    let shards = shard_targets(&["a".to_string()], 0, ShardingStrategy::RoundRobin);
    assert!(shards.is_empty());
}

#[test]
fn shard_targets_empty_targets() {
    let shards = shard_targets(&[], 3, ShardingStrategy::RoundRobin);
    assert_eq!(shards.len(), 3);
    assert!(shards.iter().all(|s| s.is_empty()));
}

#[test]
fn generate_terraform_digitalocean() {
    let node = make_node(
        "scan-01",
        NodeProvider::DigitalOcean,
        NodeState::Provisioning,
    );
    let config = generate_terraform_config(&node);
    assert!(config.contains("digitalocean_droplet"));
    assert!(config.contains("scan-01"));
    assert!(config.contains("nyc1"));
    assert!(config.contains("ubuntu"));
}

#[test]
fn generate_terraform_aws() {
    let mut node = make_node("scan-02", NodeProvider::Aws, NodeState::Provisioning);
    node.provider = NodeProvider::Aws;
    let config = generate_terraform_config(&node);
    assert!(config.contains("aws_instance"));
    assert!(config.contains("scan-02"));
}

#[test]
fn generate_terraform_vultr() {
    let mut node = make_node("scan-03", NodeProvider::Vultr, NodeState::Provisioning);
    node.provider = NodeProvider::Vultr;
    let config = generate_terraform_config(&node);
    assert!(config.contains("vultr_instance"));
    assert!(config.contains("scan-03"));
}

#[test]
fn generate_terraform_unsupported_provider() {
    let mut node = make_node("scan-04", NodeProvider::Gcp, NodeState::Provisioning);
    node.provider = NodeProvider::Gcp;
    let config = generate_terraform_config(&node);
    assert!(config.contains("Placeholder"));
    assert!(config.contains("GCP"));
}

#[test]
fn generate_self_destruct_script_content() {
    let script = generate_self_destruct_script("node-abc");
    assert!(script.contains("#!/bin/bash"));
    assert!(script.contains("node-abc"));
    assert!(script.contains("rm -rf"));
    assert!(script.contains("shutdown"));
    assert!(script.contains("bash_history"));
}

#[test]
fn generate_mesh_config_structure() {
    let peers = vec![
        MeshPeer {
            node_id: "node-1".to_string(),
            public_key: "PUBKEY1".to_string(),
            endpoint: "1.2.3.4:51820".to_string(),
            allowed_ips: vec!["10.0.0.1/32".to_string()],
            last_seen_ms: 1000,
        },
        MeshPeer {
            node_id: "node-2".to_string(),
            public_key: "PUBKEY2".to_string(),
            endpoint: "5.6.7.8:51820".to_string(),
            allowed_ips: vec!["10.0.0.2/32".to_string()],
            last_seen_ms: 1000,
        },
    ];
    let config = generate_mesh_config(&peers, "PRIVKEY");
    assert!(config.contains("[Interface]"));
    assert!(config.contains("PrivateKey = PRIVKEY"));
    assert!(config.contains("[Peer]"));
    assert!(config.contains("PUBKEY1"));
    assert!(config.contains("PUBKEY2"));
    assert!(config.contains("PersistentKeepalive = 25"));
}

#[test]
fn compute_fleet_status_mixed() {
    let nodes = vec![
        make_node("n1", NodeProvider::Aws, NodeState::Scanning),
        make_node("n2", NodeProvider::Vultr, NodeState::Ready),
        make_node("n3", NodeProvider::Hetzner, NodeState::Failed),
        make_node("n4", NodeProvider::Aws, NodeState::Destroyed),
    ];
    let status = compute_fleet_status(&nodes);
    assert_eq!(status.total_nodes, 4);
    assert_eq!(status.active_nodes, 2);
    assert_eq!(status.scanning_nodes, 1);
    assert_eq!(status.failed_nodes, 1);
    assert_eq!(status.destroyed_nodes, 1);
    assert_eq!(status.total_findings, 20);
}

#[test]
fn compute_fleet_status_empty() {
    let status = compute_fleet_status(&[]);
    assert_eq!(status.total_nodes, 0);
    assert_eq!(status.active_nodes, 0);
    assert!(status.countries_active.is_empty());
}

#[test]
fn result_packet_serialization() {
    let packet = ResultPacket {
        node_id: "n1".to_string(),
        sequence: 1,
        encrypted_payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        nonce: vec![0x01, 0x02, 0x03],
        timestamp_ms: 1000,
        findings_count: 3,
    };
    let json = serde_json::to_string(&packet).unwrap();
    let deserialized: ResultPacket = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.node_id, "n1");
    assert_eq!(deserialized.findings_count, 3);
}
