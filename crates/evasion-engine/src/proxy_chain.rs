use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::Instant;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Proxy protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProxyProtocol {
    Socks5,
    HttpConnect,
    Tor,
}

impl fmt::Display for ProxyProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socks5 => write!(f, "SOCKS5"),
            Self::HttpConnect => write!(f, "HTTP-CONNECT"),
            Self::Tor => write!(f, "Tor"),
        }
    }
}

/// Geographic region for proxy diversity enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GeoRegion {
    NorthAmerica,
    Europe,
    AsiaPacific,
    SouthAmerica,
    Africa,
    MiddleEast,
    Oceania,
}

impl fmt::Display for GeoRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NorthAmerica => write!(f, "NA"),
            Self::Europe => write!(f, "EU"),
            Self::AsiaPacific => write!(f, "APAC"),
            Self::SouthAmerica => write!(f, "SA"),
            Self::Africa => write!(f, "AF"),
            Self::MiddleEast => write!(f, "ME"),
            Self::Oceania => write!(f, "OC"),
        }
    }
}

/// IP reputation tier for proxy quality classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReputationTier {
    Residential,
    Datacenter,
    Mobile,
    Unknown,
}

/// Authentication credentials for a proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

/// Health status of a proxy node, updated from periodic checks.
#[derive(Debug, Clone)]
pub struct ProxyHealth {
    pub latency_ms: u64,
    pub uptime_ratio: f64,
    pub last_check: Instant,
    pub consecutive_failures: u32,
    pub blocked_by_targets: HashSet<String>,
}

impl ProxyHealth {
    fn new() -> Self {
        Self {
            latency_ms: 0,
            uptime_ratio: 1.0,
            last_check: Instant::now(),
            consecutive_failures: 0,
            blocked_by_targets: HashSet::new(),
        }
    }

    /// Proxy is considered healthy when its failure count stays below threshold
    /// and uptime ratio exceeds the minimum acceptable value.
    pub fn is_healthy(&self) -> bool {
        self.consecutive_failures < 3 && self.uptime_ratio > 0.5
    }
}

/// Single proxy node in the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyNode {
    pub id: u64,
    pub protocol: ProxyProtocol,
    pub host: String,
    pub port: u16,
    pub region: GeoRegion,
    pub reputation: ReputationTier,
    pub auth: Option<ProxyAuth>,
}

impl fmt::Display for ProxyNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}://{}:{} [{}]",
            self.protocol, self.host, self.port, self.region
        )
    }
}

/// Residential proxy provider format for API-based rotation services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResidentialProvider {
    BrightData { zone: String, api_token: String },
    Oxylabs { username: String, password: String },
}

impl ResidentialProvider {
    /// Returns the proxy endpoint URL for the given provider.
    pub fn endpoint(&self) -> String {
        match self {
            Self::BrightData { zone, .. } => {
                format!("http://zproxy.lum-superproxy.io:22225/?zone={zone}")
            }
            Self::Oxylabs { .. } => "http://pr.oxylabs.io:7777".to_string(),
        }
    }

    /// Returns auth credentials extracted from the provider config.
    pub fn auth(&self) -> ProxyAuth {
        match self {
            Self::BrightData { zone, api_token } => ProxyAuth {
                username: format!("lum-customer-{zone}"),
                password: api_token.clone(),
            },
            Self::Oxylabs { username, password } => ProxyAuth {
                username: username.clone(),
                password: password.clone(),
            },
        }
    }
}

/// A resolved multi-hop path through the proxy network.
#[derive(Debug, Clone)]
pub struct ProxyChainPath {
    pub hops: Vec<u64>,
    pub estimated_latency_ms: u64,
}

/// Configuration for proxy chain behavior.
#[derive(Debug, Clone)]
pub struct ProxyChainConfig {
    pub max_chain_length: usize,
    pub min_chain_length: usize,
    pub require_geo_diversity: bool,
    pub health_check_interval_secs: u64,
    pub max_consecutive_failures: u32,
    pub prefer_residential: bool,
}

impl Default for ProxyChainConfig {
    fn default() -> Self {
        Self {
            max_chain_length: 4,
            min_chain_length: 1,
            require_geo_diversity: true,
            health_check_interval_secs: 60,
            max_consecutive_failures: 3,
            prefer_residential: false,
        }
    }
}

impl ProxyChainConfig {
    pub fn with_max_chain_length(mut self, n: usize) -> Self {
        self.max_chain_length = n;
        self
    }

    pub fn with_min_chain_length(mut self, n: usize) -> Self {
        self.min_chain_length = n;
        self
    }

    pub fn with_geo_diversity(mut self, required: bool) -> Self {
        self.require_geo_diversity = required;
        self
    }

    pub fn with_prefer_residential(mut self, prefer: bool) -> Self {
        self.prefer_residential = prefer;
        self
    }
}

/// Multi-hop proxy chain manager.
///
/// Maintains a pool of proxy nodes, tracks per-target burned proxies,
/// enforces geographic diversity, and supports automatic rotation on
/// detection or block events.
pub struct ProxyChainManager {
    nodes: Vec<ProxyNode>,
    health: HashMap<u64, ProxyHealth>,
    burned_proxies: HashMap<String, HashSet<u64>>,
    residential_providers: Vec<ResidentialProvider>,
    config: ProxyChainConfig,
    rng: StdRng,
    next_id: u64,
}

impl ProxyChainManager {
    pub fn new(config: ProxyChainConfig) -> Self {
        Self {
            nodes: Vec::new(),
            health: HashMap::new(),
            burned_proxies: HashMap::new(),
            residential_providers: Vec::new(),
            config,
            rng: StdRng::from_os_rng(),
            next_id: 1,
        }
    }

    pub fn with_seed(config: ProxyChainConfig, seed: u64) -> Self {
        Self {
            nodes: Vec::new(),
            health: HashMap::new(),
            burned_proxies: HashMap::new(),
            residential_providers: Vec::new(),
            config,
            rng: StdRng::seed_from_u64(seed),
            next_id: 1,
        }
    }

    /// Adds a proxy node to the pool, assigning it a unique ID and initializing health.
    pub fn add_proxy(
        &mut self,
        protocol: ProxyProtocol,
        host: &str,
        port: u16,
        region: GeoRegion,
        reputation: ReputationTier,
        auth: Option<ProxyAuth>,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.push(ProxyNode {
            id,
            protocol,
            host: host.to_string(),
            port,
            region,
            reputation,
            auth,
        });
        self.health.insert(id, ProxyHealth::new());
        id
    }

    /// Registers a residential proxy provider for API-based rotation.
    pub fn add_residential_provider(&mut self, provider: ResidentialProvider) {
        self.residential_providers.push(provider);
    }

    /// Returns the total number of proxy nodes in the pool.
    pub fn pool_size(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the number of healthy proxies available.
    pub fn healthy_count(&self) -> usize {
        self.nodes
            .iter()
            .filter(|n| self.is_node_healthy(n.id))
            .count()
    }

    /// Builds a multi-hop chain for the given target, avoiding burned proxies
    /// and enforcing geographic diversity when configured.
    pub fn build_chain(&mut self, target: &str) -> Option<ProxyChainPath> {
        let burned = self.burned_proxies.get(target).cloned().unwrap_or_default();
        let mut candidates: Vec<&ProxyNode> = self
            .nodes
            .iter()
            .filter(|n| !burned.contains(&n.id) && self.is_node_healthy(n.id))
            .collect();

        if self.config.prefer_residential {
            candidates.sort_by_key(|n| match n.reputation {
                ReputationTier::Residential => 0,
                ReputationTier::Mobile => 1,
                ReputationTier::Datacenter => 2,
                ReputationTier::Unknown => 3,
            });
        }

        if candidates.is_empty() {
            return None;
        }

        let chain_len = self
            .config
            .min_chain_length
            .min(candidates.len())
            .max(1)
            .min(self.config.max_chain_length);

        let mut selected: Vec<u64> = Vec::with_capacity(chain_len);
        let mut used_regions: HashSet<GeoRegion> = HashSet::new();

        for _ in 0..chain_len {
            let eligible: Vec<usize> = candidates
                .iter()
                .enumerate()
                .filter(|(_, n)| {
                    !selected.contains(&n.id)
                        && (!self.config.require_geo_diversity || !used_regions.contains(&n.region))
                })
                .map(|(i, _)| i)
                .collect();

            if eligible.is_empty() {
                let fallback: Vec<usize> = candidates
                    .iter()
                    .enumerate()
                    .filter(|(_, n)| !selected.contains(&n.id))
                    .map(|(i, _)| i)
                    .collect();
                if fallback.is_empty() {
                    break;
                }
                let idx = fallback[self.rng.random_range(0..fallback.len())];
                let node = &candidates[idx];
                used_regions.insert(node.region);
                selected.push(node.id);
            } else {
                let idx = eligible[self.rng.random_range(0..eligible.len())];
                let node = &candidates[idx];
                used_regions.insert(node.region);
                selected.push(node.id);
            }
        }

        if selected.is_empty() {
            return None;
        }

        let estimated_latency: u64 = selected
            .iter()
            .filter_map(|id| self.health.get(id))
            .map(|h| h.latency_ms)
            .sum();

        Some(ProxyChainPath {
            hops: selected,
            estimated_latency_ms: estimated_latency,
        })
    }

    /// Marks a proxy as burned for a specific target so it won't be reused.
    pub fn burn_proxy(&mut self, target: &str, proxy_id: u64) {
        self.burned_proxies
            .entry(target.to_string())
            .or_default()
            .insert(proxy_id);
        if let Some(health) = self.health.get_mut(&proxy_id) {
            health.blocked_by_targets.insert(target.to_string());
        }
    }

    /// Records a health check result for a proxy node.
    pub fn record_health_check(&mut self, proxy_id: u64, latency_ms: u64, success: bool) {
        if let Some(health) = self.health.get_mut(&proxy_id) {
            health.latency_ms = latency_ms;
            health.last_check = Instant::now();
            if success {
                health.consecutive_failures = 0;
                let alpha = 0.1;
                health.uptime_ratio = health.uptime_ratio * (1.0 - alpha) + alpha;
            } else {
                health.consecutive_failures += 1;
                let alpha = 0.1;
                health.uptime_ratio *= 1.0 - alpha;
            }
        }
    }

    /// Triggers rotation: burns the current chain's exit node and builds a new chain.
    pub fn rotate_on_detection(
        &mut self,
        target: &str,
        current_chain: &ProxyChainPath,
    ) -> Option<ProxyChainPath> {
        if let Some(exit_id) = current_chain.hops.last() {
            self.burn_proxy(target, *exit_id);
        }
        self.build_chain(target)
    }

    /// Returns the proxy node by ID.
    pub fn get_node(&self, proxy_id: u64) -> Option<&ProxyNode> {
        self.nodes.iter().find(|n| n.id == proxy_id)
    }

    /// Returns the health data for a proxy node.
    pub fn get_health(&self, proxy_id: u64) -> Option<&ProxyHealth> {
        self.health.get(&proxy_id)
    }

    /// Returns the set of burned proxy IDs for a target.
    pub fn burned_for_target(&self, target: &str) -> HashSet<u64> {
        self.burned_proxies.get(target).cloned().unwrap_or_default()
    }

    /// Returns the distinct geographic regions covered by healthy proxies.
    pub fn available_regions(&self) -> HashSet<GeoRegion> {
        self.nodes
            .iter()
            .filter(|n| self.is_node_healthy(n.id))
            .map(|n| n.region)
            .collect()
    }

    /// Returns all registered residential providers.
    pub fn residential_providers(&self) -> &[ResidentialProvider] {
        &self.residential_providers
    }

    /// Builds a `reqwest::Proxy` from the first hop of a chain path.
    /// Only the exit node (last hop) is used as the HTTP proxy.
    pub fn build_reqwest_proxy(&self, chain: &ProxyChainPath) -> Option<reqwest::Proxy> {
        let exit_id = chain.hops.last()?;
        let node = self.get_node(*exit_id)?;
        let proxy_url = match node.protocol {
            ProxyProtocol::Socks5 => format!("socks5://{}:{}", node.host, node.port),
            ProxyProtocol::HttpConnect => format!("http://{}:{}", node.host, node.port),
            ProxyProtocol::Tor => format!("socks5://{}:{}", node.host, node.port),
        };
        let mut proxy = reqwest::Proxy::all(&proxy_url).ok()?;
        if let Some(auth) = &node.auth {
            proxy = proxy.basic_auth(&auth.username, &auth.password);
        }
        Some(proxy)
    }

    /// Determines if a status code signals proxy rotation is needed (403/429).
    pub fn should_rotate_on_status(status_code: u16) -> bool {
        status_code == 403 || status_code == 429
    }

    fn is_node_healthy(&self, id: u64) -> bool {
        self.health.get(&id).is_some_and(|h| h.is_healthy())
    }
}

#[cfg(test)]
#[path = "proxy_chain_test.rs"]
mod proxy_chain_test;
