use std::collections::{HashMap, HashSet};
use std::fmt;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Protocol type for each hop in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HopProtocol {
    Socks5,
    HttpConnect,
    Tor,
    Residential,
    WireGuard,
    SshTunnel,
}

impl fmt::Display for HopProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socks5 => write!(f, "SOCKS5"),
            Self::HttpConnect => write!(f, "HTTP-CONNECT"),
            Self::Tor => write!(f, "Tor"),
            Self::Residential => write!(f, "Residential"),
            Self::WireGuard => write!(f, "WireGuard"),
            Self::SshTunnel => write!(f, "SSH-Tunnel"),
        }
    }
}

/// Country code for jurisdiction-aware routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Jurisdiction {
    US,
    GB,
    DE,
    NL,
    CH,
    RO,
    PA,
    IS,
    RU,
    HK,
    SG,
    BR,
    UA,
    MD,
    BZ,
    SC,
}

impl fmt::Display for Jurisdiction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Countries that have mutual legal assistance treaties with the Five Eyes.
const MLAT_COUNTRIES: &[Jurisdiction] = &[Jurisdiction::US, Jurisdiction::GB, Jurisdiction::DE];

/// Preferred non-MLAT jurisdictions for routing.
const _NON_MLAT_JURISDICTIONS: &[Jurisdiction] = &[
    Jurisdiction::PA,
    Jurisdiction::RO,
    Jurisdiction::IS,
    Jurisdiction::MD,
    Jurisdiction::BZ,
    Jurisdiction::SC,
    Jurisdiction::UA,
    Jurisdiction::RU,
];

/// Inter-hop encryption method for tunnel between proxy hops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InterHopEncryption {
    None,
    WireGuard,
    SshTunnel,
    Tls13,
}

impl fmt::Display for InterHopEncryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::WireGuard => write!(f, "WireGuard"),
            Self::SshTunnel => write!(f, "SSH"),
            Self::Tls13 => write!(f, "TLS-1.3"),
        }
    }
}

/// Health state for a single hop node, tracked with liveness probes.
#[derive(Debug, Clone)]
pub struct HopHealth {
    pub latency_ms: u64,
    pub alive: bool,
    pub consecutive_failures: u32,
    pub intercept_detected: bool,
    pub last_verified_epoch_ms: u64,
}

impl HopHealth {
    fn new() -> Self {
        Self {
            latency_ms: 0,
            alive: true,
            consecutive_failures: 0,
            intercept_detected: false,
            last_verified_epoch_ms: 0,
        }
    }

    /// Node is considered usable when alive, not intercepting, and below failure threshold.
    pub fn is_usable(&self) -> bool {
        self.alive && !self.intercept_detected && self.consecutive_failures < 3
    }
}

/// Single hop node definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopNode {
    pub id: u64,
    pub protocol: HopProtocol,
    pub host: String,
    pub port: u16,
    pub jurisdiction: Jurisdiction,
    pub inter_hop_encryption: InterHopEncryption,
    pub bandwidth_mbps: u32,
    pub is_exit_capable: bool,
}

impl fmt::Display for HopNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}://{}:{} [{}] enc={}",
            self.protocol, self.host, self.port, self.jurisdiction, self.inter_hop_encryption
        )
    }
}

/// A composed multi-hop path with protocol mixing and failover metadata.
#[derive(Debug, Clone)]
pub struct MultiHopPath {
    pub hops: Vec<u64>,
    pub total_latency_ms: u64,
    pub protocols_used: Vec<HopProtocol>,
    pub jurisdictions_traversed: Vec<Jurisdiction>,
    pub fully_encrypted: bool,
    pub avoids_mlat: bool,
}

impl MultiHopPath {
    /// Returns the exit node ID (last hop).
    pub fn exit_node(&self) -> Option<u64> {
        self.hops.last().copied()
    }

    /// Returns the entry node ID (first hop).
    pub fn entry_node(&self) -> Option<u64> {
        self.hops.first().copied()
    }

    /// Number of distinct protocols in the path for traffic analysis resistance.
    pub fn protocol_diversity(&self) -> usize {
        let unique: HashSet<&HopProtocol> = self.protocols_used.iter().collect();
        unique.len()
    }
}

/// Backup path for automatic failover when a hop fails.
#[derive(Debug, Clone)]
pub struct FailoverRoute {
    pub failed_hop_id: u64,
    pub replacement_path: MultiHopPath,
}

/// Configuration for the multi-hop proxy composer.
#[derive(Debug, Clone)]
pub struct MultiHopConfig {
    pub min_hops: usize,
    pub max_hops: usize,
    pub require_protocol_mixing: bool,
    pub require_non_mlat_route: bool,
    pub require_encrypted_inter_hop: bool,
    pub max_total_latency_ms: u64,
    pub prefer_exit_near_target: bool,
    pub failover_enabled: bool,
    pub max_failover_attempts: usize,
}

impl Default for MultiHopConfig {
    fn default() -> Self {
        Self {
            min_hops: 2,
            max_hops: 5,
            require_protocol_mixing: true,
            require_non_mlat_route: true,
            require_encrypted_inter_hop: true,
            max_total_latency_ms: 5000,
            prefer_exit_near_target: true,
            failover_enabled: true,
            max_failover_attempts: 3,
        }
    }
}

impl MultiHopConfig {
    pub fn with_min_hops(mut self, n: usize) -> Self {
        self.min_hops = n;
        self
    }

    pub fn with_max_hops(mut self, n: usize) -> Self {
        self.max_hops = n;
        self
    }

    pub fn with_protocol_mixing(mut self, required: bool) -> Self {
        self.require_protocol_mixing = required;
        self
    }

    pub fn with_non_mlat_route(mut self, required: bool) -> Self {
        self.require_non_mlat_route = required;
        self
    }

    pub fn with_encrypted_inter_hop(mut self, required: bool) -> Self {
        self.require_encrypted_inter_hop = required;
        self
    }

    pub fn with_max_latency(mut self, ms: u64) -> Self {
        self.max_total_latency_ms = ms;
        self
    }
}

/// Verification result from probing a hop for integrity.
#[derive(Debug, Clone)]
pub struct HopVerification {
    pub hop_id: u64,
    pub alive: bool,
    pub latency_ms: u64,
    pub intercept_detected: bool,
    pub tls_cert_matches: bool,
}

/// Multi-hop proxy composer that builds protocol-mixed, jurisdiction-aware,
/// latency-optimized chains with automatic failover and encrypted inter-hop tunnels.
pub struct MultiHopComposer {
    nodes: Vec<HopNode>,
    health: HashMap<u64, HopHealth>,
    config: MultiHopConfig,
    rng: StdRng,
    next_id: u64,
    target_jurisdiction_hint: Option<Jurisdiction>,
    failover_history: Vec<FailoverRoute>,
}

impl MultiHopComposer {
    pub fn new(config: MultiHopConfig) -> Self {
        Self {
            nodes: Vec::new(),
            health: HashMap::new(),
            config,
            rng: StdRng::from_os_rng(),
            next_id: 1,
            target_jurisdiction_hint: None,
            failover_history: Vec::new(),
        }
    }

    pub fn with_seed(config: MultiHopConfig, seed: u64) -> Self {
        Self {
            nodes: Vec::new(),
            health: HashMap::new(),
            config,
            rng: StdRng::seed_from_u64(seed),
            next_id: 1,
            target_jurisdiction_hint: None,
            failover_history: Vec::new(),
        }
    }

    /// Adds a hop node to the pool.
    pub fn add_node(
        &mut self,
        protocol: HopProtocol,
        host: &str,
        port: u16,
        jurisdiction: Jurisdiction,
        encryption: InterHopEncryption,
        bandwidth_mbps: u32,
        is_exit_capable: bool,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.push(HopNode {
            id,
            protocol,
            host: host.to_string(),
            port,
            jurisdiction,
            inter_hop_encryption: encryption,
            bandwidth_mbps,
            is_exit_capable,
        });
        self.health.insert(id, HopHealth::new());
        id
    }

    /// Sets a hint for which jurisdiction the target resides in, used for
    /// exit node selection to minimize suspicion via geographic proximity.
    pub fn set_target_jurisdiction(&mut self, jurisdiction: Jurisdiction) {
        self.target_jurisdiction_hint = Some(jurisdiction);
    }

    /// Returns the total number of hop nodes in the pool.
    pub fn pool_size(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the number of usable hop nodes.
    pub fn usable_count(&self) -> usize {
        self.nodes.iter().filter(|n| self.is_usable(n.id)).count()
    }

    /// Composes an optimal multi-hop path through the network.
    ///
    /// Selection priorities:
    /// 1. Protocol mixing across hops for traffic analysis resistance
    /// 2. Non-MLAT jurisdictions when configured
    /// 3. Encrypted inter-hop links
    /// 4. Latency budget compliance
    /// 5. Exit node near target jurisdiction
    pub fn compose_path(&mut self) -> Option<MultiHopPath> {
        let usable: Vec<u64> = self
            .nodes
            .iter()
            .filter(|n| self.is_usable(n.id))
            .map(|n| n.id)
            .collect();

        if usable.len() < self.config.min_hops {
            return None;
        }

        let target_len = self.config.min_hops.max(2).min(self.config.max_hops);

        let exit_candidates = self.select_exit_candidates(&usable);
        let exit_id = if exit_candidates.is_empty() {
            let exit_capable: Vec<u64> = usable
                .iter()
                .filter(|id| self.get_node(**id).is_some_and(|n| n.is_exit_capable))
                .copied()
                .collect();
            if exit_capable.is_empty() {
                *usable.last()?
            } else {
                exit_capable[self.rng.random_range(0..exit_capable.len())]
            }
        } else {
            exit_candidates[self.rng.random_range(0..exit_candidates.len())]
        };

        let mut chain = Vec::with_capacity(target_len);
        let mut used_protocols: HashSet<HopProtocol> = HashSet::new();
        let mut used_jurisdictions: HashSet<Jurisdiction> = HashSet::new();
        let mut selected_ids: HashSet<u64> = HashSet::new();

        selected_ids.insert(exit_id);
        if let Some(node) = self.get_node(exit_id) {
            used_protocols.insert(node.protocol);
            used_jurisdictions.insert(node.jurisdiction);
        }

        let remaining_slots = target_len.saturating_sub(1);
        for _ in 0..remaining_slots {
            let candidate = self.pick_interior_hop(
                &usable,
                &selected_ids,
                &used_protocols,
                &used_jurisdictions,
            );
            if let Some(cid) = candidate {
                selected_ids.insert(cid);
                if let Some(node) = self.get_node(cid) {
                    used_protocols.insert(node.protocol);
                    used_jurisdictions.insert(node.jurisdiction);
                }
                chain.push(cid);
            }
        }

        chain.push(exit_id);

        if chain.len() < self.config.min_hops {
            return None;
        }

        let total_latency: u64 = chain
            .iter()
            .filter_map(|id| self.health.get(id))
            .map(|h| h.latency_ms)
            .sum();

        let protocols: Vec<HopProtocol> = chain
            .iter()
            .filter_map(|id| self.get_node(*id))
            .map(|n| n.protocol)
            .collect();

        let jurisdictions: Vec<Jurisdiction> = chain
            .iter()
            .filter_map(|id| self.get_node(*id))
            .map(|n| n.jurisdiction)
            .collect();

        let fully_encrypted = chain.iter().all(|id| {
            self.get_node(*id)
                .is_some_and(|n| n.inter_hop_encryption != InterHopEncryption::None)
        });

        let avoids_mlat = jurisdictions.iter().all(|j| !MLAT_COUNTRIES.contains(j));

        Some(MultiHopPath {
            hops: chain,
            total_latency_ms: total_latency,
            protocols_used: protocols,
            jurisdictions_traversed: jurisdictions,
            fully_encrypted,
            avoids_mlat,
        })
    }

    /// Attempts to reroute around a failed hop, selecting a replacement from the pool.
    pub fn failover(
        &mut self,
        _current_path: &MultiHopPath,
        failed_hop_id: u64,
    ) -> Option<MultiHopPath> {
        if !self.config.failover_enabled {
            return None;
        }

        if let Some(health) = self.health.get_mut(&failed_hop_id) {
            health.alive = false;
            health.consecutive_failures += 1;
        }

        let mut attempts = 0;
        while attempts < self.config.max_failover_attempts {
            if let Some(new_path) = self.compose_path() {
                let route = FailoverRoute {
                    failed_hop_id,
                    replacement_path: new_path.clone(),
                };
                self.failover_history.push(route);
                return Some(new_path);
            }
            attempts += 1;
        }

        None
    }

    /// Records a verification probe result for a hop.
    pub fn record_verification(&mut self, verification: HopVerification) {
        if let Some(health) = self.health.get_mut(&verification.hop_id) {
            health.alive = verification.alive;
            health.latency_ms = verification.latency_ms;
            health.intercept_detected = verification.intercept_detected;
            if verification.alive {
                health.consecutive_failures = 0;
            } else {
                health.consecutive_failures += 1;
            }
        }
    }

    /// Verifies every hop in a path is alive and not intercepting.
    /// Returns IDs of any hops that failed verification.
    pub fn verify_chain(&self, path: &MultiHopPath) -> Vec<u64> {
        path.hops
            .iter()
            .filter(|id| !self.is_usable(**id))
            .copied()
            .collect()
    }

    /// Returns whether a jurisdiction is in the MLAT set.
    pub fn is_mlat_jurisdiction(jurisdiction: &Jurisdiction) -> bool {
        MLAT_COUNTRIES.contains(jurisdiction)
    }

    /// Returns all non-MLAT jurisdictions available in the pool.
    pub fn non_mlat_jurisdictions(&self) -> HashSet<Jurisdiction> {
        self.nodes
            .iter()
            .filter(|n| self.is_usable(n.id) && !MLAT_COUNTRIES.contains(&n.jurisdiction))
            .map(|n| n.jurisdiction)
            .collect()
    }

    /// Returns the failover history for post-analysis.
    pub fn failover_history(&self) -> &[FailoverRoute] {
        &self.failover_history
    }

    /// Returns a node by ID.
    pub fn get_node(&self, id: u64) -> Option<&HopNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Returns health for a node.
    pub fn get_health(&self, id: u64) -> Option<&HopHealth> {
        self.health.get(&id)
    }

    fn is_usable(&self, id: u64) -> bool {
        self.health.get(&id).is_some_and(|h| h.is_usable())
    }

    fn select_exit_candidates(&self, usable: &[u64]) -> Vec<u64> {
        let candidates: Vec<u64> = usable
            .iter()
            .filter(|id| {
                self.get_node(**id)
                    .is_some_and(|n| n.is_exit_capable && !MLAT_COUNTRIES.contains(&n.jurisdiction))
            })
            .copied()
            .collect();

        if self.config.prefer_exit_near_target {
            if let Some(target_j) = self.target_jurisdiction_hint {
                let near: Vec<u64> = candidates
                    .iter()
                    .filter(|id| {
                        self.get_node(**id)
                            .is_some_and(|n| n.jurisdiction == target_j)
                    })
                    .copied()
                    .collect();
                if !near.is_empty() {
                    return near;
                }
            }
        }

        candidates
    }

    fn pick_interior_hop(
        &mut self,
        usable: &[u64],
        selected: &HashSet<u64>,
        used_protocols: &HashSet<HopProtocol>,
        used_jurisdictions: &HashSet<Jurisdiction>,
    ) -> Option<u64> {
        let mut best: Vec<(u64, u32)> = Vec::new();

        for &id in usable {
            if selected.contains(&id) {
                continue;
            }

            let node = self.get_node(id)?;
            let mut score: u32 = 0;

            if self.config.require_protocol_mixing && !used_protocols.contains(&node.protocol) {
                score += 10;
            }

            if self.config.require_non_mlat_route && !MLAT_COUNTRIES.contains(&node.jurisdiction) {
                score += 5;
            }

            if !used_jurisdictions.contains(&node.jurisdiction) {
                score += 3;
            }

            if self.config.require_encrypted_inter_hop
                && node.inter_hop_encryption != InterHopEncryption::None
            {
                score += 4;
            }

            let latency = self.health.get(&id).map(|h| h.latency_ms).unwrap_or(0);
            if latency < 200 {
                score += 2;
            }

            best.push((id, score));
        }

        if best.is_empty() {
            return None;
        }

        best.sort_by(|a, b| b.1.cmp(&a.1));

        let top_score = best[0].1;
        let top_candidates: Vec<u64> = best
            .iter()
            .filter(|(_, s)| *s == top_score)
            .map(|(id, _)| *id)
            .collect();

        Some(top_candidates[self.rng.random_range(0..top_candidates.len())])
    }
}
