use std::fmt;

use serde::{Deserialize, Serialize};

use crate::util::timestamp_ms;

/// Cloud provider for node provisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeProvider {
    Aws,
    Gcp,
    Azure,
    DigitalOcean,
    Linode,
    Vultr,
    Hetzner,
    OvhCloud,
}

impl fmt::Display for NodeProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Aws => "AWS",
            Self::Gcp => "GCP",
            Self::Azure => "Azure",
            Self::DigitalOcean => "DigitalOcean",
            Self::Linode => "Linode",
            Self::Vultr => "Vultr",
            Self::Hetzner => "Hetzner",
            Self::OvhCloud => "OVH Cloud",
        };
        write!(f, "{label}")
    }
}

/// Geographic region for node placement.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GeoRegion {
    pub country_code: String,
    pub region_name: String,
    pub provider_region_id: String,
}

/// State of a scan node in the distributed network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeState {
    Provisioning,
    Ready,
    Scanning,
    Aggregating,
    CleaningUp,
    Destroyed,
    Failed,
}

impl fmt::Display for NodeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Provisioning => "Provisioning",
            Self::Ready => "Ready",
            Self::Scanning => "Scanning",
            Self::Aggregating => "Aggregating",
            Self::CleaningUp => "Cleaning Up",
            Self::Destroyed => "Destroyed",
            Self::Failed => "Failed",
        };
        write!(f, "{label}")
    }
}

/// A scan node in the distributed network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanNode {
    pub id: String,
    pub provider: NodeProvider,
    pub region: GeoRegion,
    pub state: NodeState,
    pub ip_address: Option<String>,
    pub assigned_targets: Vec<String>,
    pub assigned_modules: Vec<String>,
    pub provisioned_at_ms: u64,
    pub max_lifetime_secs: u64,
    pub findings_collected: usize,
    pub encryption_key_id: String,
}

impl ScanNode {
    pub fn is_alive(&self) -> bool {
        matches!(
            self.state,
            NodeState::Provisioning
                | NodeState::Ready
                | NodeState::Scanning
                | NodeState::Aggregating
        )
    }

    pub fn should_rotate(&self) -> bool {
        let elapsed_secs = (timestamp_ms() - self.provisioned_at_ms) / 1000;
        elapsed_secs >= self.max_lifetime_secs || self.state == NodeState::Failed
    }

    pub fn transition(&mut self, new_state: NodeState) -> bool {
        let valid = match (&self.state, &new_state) {
            (NodeState::Provisioning, NodeState::Ready) => true,
            (NodeState::Provisioning, NodeState::Failed) => true,
            (NodeState::Ready, NodeState::Scanning) => true,
            (NodeState::Scanning, NodeState::Aggregating) => true,
            (NodeState::Scanning, NodeState::Failed) => true,
            (NodeState::Aggregating, NodeState::CleaningUp) => true,
            (NodeState::CleaningUp, NodeState::Destroyed) => true,
            (NodeState::Failed, NodeState::Destroyed) => true,
            _ => false,
        };
        if valid {
            self.state = new_state;
        }
        valid
    }
}

/// Configuration for the distributed scanner fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetConfig {
    pub node_count: usize,
    pub providers: Vec<NodeProvider>,
    pub regions: Vec<GeoRegion>,
    pub max_node_lifetime_secs: u64,
    pub auto_rotate: bool,
    pub auto_destroy: bool,
    pub mesh_encryption: MeshEncryption,
    pub result_encryption: ResultEncryption,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshEncryption {
    WireGuard,
    NoisePipe,
    Tls13,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResultEncryption {
    Aes256Gcm,
    ChaCha20Poly1305,
    Age,
}

impl Default for FleetConfig {
    fn default() -> Self {
        Self {
            node_count: 5,
            providers: vec![
                NodeProvider::DigitalOcean,
                NodeProvider::Vultr,
                NodeProvider::Hetzner,
                NodeProvider::Linode,
            ],
            regions: vec![
                GeoRegion {
                    country_code: "US".to_string(),
                    region_name: "New York".to_string(),
                    provider_region_id: "nyc1".to_string(),
                },
                GeoRegion {
                    country_code: "DE".to_string(),
                    region_name: "Frankfurt".to_string(),
                    provider_region_id: "fra1".to_string(),
                },
                GeoRegion {
                    country_code: "SG".to_string(),
                    region_name: "Singapore".to_string(),
                    provider_region_id: "sgp1".to_string(),
                },
                GeoRegion {
                    country_code: "GB".to_string(),
                    region_name: "London".to_string(),
                    provider_region_id: "lon1".to_string(),
                },
            ],
            max_node_lifetime_secs: 3600,
            auto_rotate: true,
            auto_destroy: true,
            mesh_encryption: MeshEncryption::WireGuard,
            result_encryption: ResultEncryption::Age,
        }
    }
}

/// Task sharding strategy for distributing work across nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShardingStrategy {
    ByTarget,
    ByModule,
    ByVulnerabilityClass,
    RoundRobin,
    LoadBalanced,
}

/// Distribute targets across nodes according to the sharding strategy.
pub fn shard_targets(
    targets: &[String],
    node_count: usize,
    strategy: ShardingStrategy,
) -> Vec<Vec<String>> {
    if node_count == 0 {
        return vec![];
    }
    let mut shards: Vec<Vec<String>> = (0..node_count).map(|_| Vec::new()).collect();
    match strategy {
        ShardingStrategy::RoundRobin | ShardingStrategy::ByTarget => {
            for (i, target) in targets.iter().enumerate() {
                shards[i % node_count].push(target.clone());
            }
        }
        ShardingStrategy::LoadBalanced => {
            for (i, target) in targets.iter().enumerate() {
                let min_idx = shards
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, s)| s.len())
                    .map(|(idx, _)| idx)
                    .unwrap_or(i % node_count);
                shards[min_idx].push(target.clone());
            }
        }
        ShardingStrategy::ByModule | ShardingStrategy::ByVulnerabilityClass => {
            for (i, target) in targets.iter().enumerate() {
                shards[i % node_count].push(target.clone());
            }
        }
    }
    shards
}

/// Generate a Terraform configuration snippet for an ephemeral node.
pub fn generate_terraform_config(node: &ScanNode) -> String {
    let provider_block = match node.provider {
        NodeProvider::DigitalOcean => format!(
            "resource \"digitalocean_droplet\" \"{id}\" {{\n  \
             image  = \"ubuntu-22-04-x64\"\n  \
             name   = \"{id}\"\n  \
             region = \"{region}\"\n  \
             size   = \"s-1vcpu-1gb\"\n  \
             ssh_keys = [var.ssh_key_fingerprint]\n\
             }}",
            id = node.id,
            region = node.region.provider_region_id,
        ),
        NodeProvider::Aws => format!(
            "resource \"aws_instance\" \"{id}\" {{\n  \
             ami           = \"ami-0c55b159cbfafe1f0\"\n  \
             instance_type = \"t3.micro\"\n  \
             tags = {{\n    Name = \"{id}\"\n  }}\n\
             }}",
            id = node.id,
        ),
        NodeProvider::Vultr => format!(
            "resource \"vultr_instance\" \"{id}\" {{\n  \
             plan   = \"vc2-1c-1gb\"\n  \
             region = \"{region}\"\n  \
             os_id  = 387\n  \
             label  = \"{id}\"\n\
             }}",
            id = node.id,
            region = node.region.provider_region_id,
        ),
        _ => format!(
            "# Placeholder for {provider} node {id}\n\
             # Region: {region}",
            provider = node.provider,
            id = node.id,
            region = node.region.provider_region_id,
        ),
    };

    format!(
        "# Auto-generated ephemeral scan node\n\
         # Provider: {provider}\n\
         # Region: {region} ({country})\n\
         # Max lifetime: {lifetime}s\n\n\
         {block}\n",
        provider = node.provider,
        region = node.region.region_name,
        country = node.region.country_code,
        lifetime = node.max_lifetime_secs,
        block = provider_block,
    )
}

/// Self-destruct script for nodes to execute after task completion.
pub fn generate_self_destruct_script(node_id: &str) -> String {
    format!(
        "#!/bin/bash\n\
         set -euo pipefail\n\n\
         # Self-destruct script for node {node_id}\n\
         echo \"[$(date -u)] Starting self-destruct sequence for {node_id}\"\n\n\
         # Wipe scan artifacts\n\
         rm -rf /tmp/aegis-*\n\
         rm -rf /var/log/aegis-*\n\n\
         # Overwrite free space\n\
         dd if=/dev/urandom of=/tmp/wipe bs=1M count=100 2>/dev/null || true\n\
         rm -f /tmp/wipe\n\n\
         # Clear logs\n\
         journalctl --rotate --vacuum-time=1s 2>/dev/null || true\n\
         > /var/log/syslog\n\
         > /var/log/auth.log\n\n\
         # Clear bash history\n\
         history -c\n\
         > ~/.bash_history\n\n\
         echo \"[$(date -u)] Self-destruct complete for {node_id}\"\n\
         # Signal coordinator then shutdown\n\
         shutdown -h now\n"
    )
}

/// Encrypted result packet from a scan node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultPacket {
    pub node_id: String,
    pub sequence: u32,
    pub encrypted_payload: Vec<u8>,
    pub nonce: Vec<u8>,
    pub timestamp_ms: u64,
    pub findings_count: usize,
}

/// Mesh network peer entry for P2P communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshPeer {
    pub node_id: String,
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub last_seen_ms: u64,
}

/// Generate WireGuard mesh configuration for peer-to-peer node communication.
pub fn generate_mesh_config(peers: &[MeshPeer], self_key: &str) -> String {
    let mut config = format!(
        "[Interface]\n\
         PrivateKey = {self_key}\n\
         ListenPort = 51820\n\n"
    );
    for peer in peers {
        config.push_str(&format!(
            "[Peer]\n\
             # {node_id}\n\
             PublicKey = {pubkey}\n\
             Endpoint = {endpoint}\n\
             AllowedIPs = {ips}\n\
             PersistentKeepalive = 25\n\n",
            node_id = peer.node_id,
            pubkey = peer.public_key,
            endpoint = peer.endpoint,
            ips = peer.allowed_ips.join(", "),
        ));
    }
    config
}

/// Fleet-wide status summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetStatus {
    pub total_nodes: usize,
    pub active_nodes: usize,
    pub scanning_nodes: usize,
    pub failed_nodes: usize,
    pub destroyed_nodes: usize,
    pub total_findings: usize,
    pub countries_active: Vec<String>,
    pub providers_active: Vec<String>,
}

pub fn compute_fleet_status(nodes: &[ScanNode]) -> FleetStatus {
    let active_nodes = nodes.iter().filter(|n| n.is_alive()).count();
    let scanning_nodes = nodes
        .iter()
        .filter(|n| n.state == NodeState::Scanning)
        .count();
    let failed_nodes = nodes
        .iter()
        .filter(|n| n.state == NodeState::Failed)
        .count();
    let destroyed_nodes = nodes
        .iter()
        .filter(|n| n.state == NodeState::Destroyed)
        .count();
    let total_findings: usize = nodes.iter().map(|n| n.findings_collected).sum();

    let mut countries: Vec<String> = nodes
        .iter()
        .filter(|n| n.is_alive())
        .map(|n| n.region.country_code.clone())
        .collect();
    countries.sort();
    countries.dedup();

    let mut providers: Vec<String> = nodes
        .iter()
        .filter(|n| n.is_alive())
        .map(|n| n.provider.to_string())
        .collect();
    providers.sort();
    providers.dedup();

    FleetStatus {
        total_nodes: nodes.len(),
        active_nodes,
        scanning_nodes,
        failed_nodes,
        destroyed_nodes,
        total_findings,
        countries_active: countries,
        providers_active: providers,
    }
}

#[cfg(test)]
#[path = "distributed_autonomous_test.rs"]
mod tests;
