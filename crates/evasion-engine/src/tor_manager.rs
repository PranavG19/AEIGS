use std::collections::HashMap;
use std::fmt;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Country code for exit node selection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CountryCode(pub String);

impl CountryCode {
    pub fn new(code: &str) -> Self {
        Self(code.to_uppercase())
    }
}

impl fmt::Display for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Tor bridge relay for bypassing Tor blocking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeRelay {
    pub address: String,
    pub port: u16,
    pub transport: BridgeTransport,
    pub fingerprint: Option<String>,
}

/// Pluggable transport type for bridge relays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BridgeTransport {
    Obfs4,
    Snowflake,
    Meek,
    Plain,
}

impl fmt::Display for BridgeTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Obfs4 => write!(f, "obfs4"),
            Self::Snowflake => write!(f, "snowflake"),
            Self::Meek => write!(f, "meek"),
            Self::Plain => write!(f, "plain"),
        }
    }
}

/// State of a Tor circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CircuitState {
    Building,
    Ready,
    Active,
    Closed,
    Failed,
}

impl fmt::Display for CircuitState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Building => write!(f, "building"),
            Self::Ready => write!(f, "ready"),
            Self::Active => write!(f, "active"),
            Self::Closed => write!(f, "closed"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// A single Tor circuit.
#[derive(Debug, Clone)]
pub struct TorCircuit {
    pub id: u64,
    pub state: CircuitState,
    pub exit_country: Option<CountryCode>,
    pub latency_ms: Option<u64>,
    pub target: Option<String>,
    pub hops: u8,
    pub uses_bridge: bool,
}

/// Configuration for the Tor circuit manager.
#[derive(Debug, Clone)]
pub struct TorConfig {
    pub socks_port: u16,
    pub control_port: u16,
    pub default_hops: u8,
    pub circuit_per_target: bool,
    pub preferred_exit_countries: Vec<CountryCode>,
    pub excluded_exit_countries: Vec<CountryCode>,
    pub max_circuit_latency_ms: u64,
    pub max_active_circuits: usize,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            socks_port: 9050,
            control_port: 9051,
            default_hops: 3,
            circuit_per_target: true,
            preferred_exit_countries: Vec::new(),
            excluded_exit_countries: Vec::new(),
            max_circuit_latency_ms: 5000,
            max_active_circuits: 10,
        }
    }
}

impl TorConfig {
    pub fn with_socks_port(mut self, port: u16) -> Self {
        self.socks_port = port;
        self
    }

    pub fn with_control_port(mut self, port: u16) -> Self {
        self.control_port = port;
        self
    }

    pub fn with_preferred_exit_countries(mut self, countries: Vec<CountryCode>) -> Self {
        self.preferred_exit_countries = countries;
        self
    }

    pub fn with_excluded_exit_countries(mut self, countries: Vec<CountryCode>) -> Self {
        self.excluded_exit_countries = countries;
        self
    }

    pub fn with_max_circuit_latency_ms(mut self, ms: u64) -> Self {
        self.max_circuit_latency_ms = ms;
        self
    }

    pub fn with_circuit_per_target(mut self, enabled: bool) -> Self {
        self.circuit_per_target = enabled;
        self
    }

    pub fn with_max_active_circuits(mut self, max: usize) -> Self {
        self.max_active_circuits = max;
        self
    }
}

/// Advanced Tor circuit manager for anonymous scanning.
///
/// Creates new circuits per target to avoid correlation, supports exit node
/// country selection, bridge relay configuration for Tor-blocked networks,
/// circuit latency measurement, .onion service scanning, and composition
/// with proxy chains.
pub struct TorCircuitManager {
    config: TorConfig,
    circuits: Vec<TorCircuit>,
    target_circuits: HashMap<String, u64>,
    bridges: Vec<BridgeRelay>,
    rng: StdRng,
    next_circuit_id: u64,
}

impl TorCircuitManager {
    pub fn new(config: TorConfig) -> Self {
        Self {
            config,
            circuits: Vec::new(),
            target_circuits: HashMap::new(),
            bridges: Vec::new(),
            rng: StdRng::from_os_rng(),
            next_circuit_id: 1,
        }
    }

    pub fn with_seed(config: TorConfig, seed: u64) -> Self {
        Self {
            config,
            circuits: Vec::new(),
            target_circuits: HashMap::new(),
            bridges: Vec::new(),
            rng: StdRng::seed_from_u64(seed),
            next_circuit_id: 1,
        }
    }

    /// Creates a new Tor circuit, optionally targeted to a specific destination
    /// and exit country. Returns the circuit ID.
    pub fn create_circuit(
        &mut self,
        target: Option<&str>,
        exit_country: Option<&CountryCode>,
    ) -> u64 {
        let id = self.next_circuit_id;
        self.next_circuit_id += 1;

        let exit = exit_country.cloned().or_else(|| {
            if !self.config.preferred_exit_countries.is_empty() {
                let idx = self
                    .rng
                    .random_range(0..self.config.preferred_exit_countries.len());
                Some(self.config.preferred_exit_countries[idx].clone())
            } else {
                None
            }
        });

        if let Some(ref exit_cc) = exit
            && self.config.excluded_exit_countries.contains(exit_cc)
        {
            let circuit = TorCircuit {
                id,
                state: CircuitState::Failed,
                exit_country: Some(exit_cc.clone()),
                latency_ms: None,
                target: target.map(String::from),
                hops: self.config.default_hops,
                uses_bridge: !self.bridges.is_empty(),
            };
            self.circuits.push(circuit);
            return id;
        }

        let circuit = TorCircuit {
            id,
            state: CircuitState::Ready,
            exit_country: exit,
            latency_ms: None,
            target: target.map(String::from),
            hops: self.config.default_hops,
            uses_bridge: !self.bridges.is_empty(),
        };

        self.circuits.push(circuit);

        if let Some(t) = target
            && self.config.circuit_per_target
        {
            self.target_circuits.insert(t.to_string(), id);
        }

        id
    }

    /// Returns the circuit assigned to a target, creating one if needed.
    pub fn circuit_for_target(&mut self, target: &str) -> u64 {
        if let Some(&existing_id) = self.target_circuits.get(target)
            && let Some(circuit) = self.circuits.iter().find(|c| c.id == existing_id)
            && (circuit.state == CircuitState::Ready || circuit.state == CircuitState::Active)
        {
            return existing_id;
        }
        self.create_circuit(Some(target), None)
    }

    /// Records latency measurement for a circuit.
    pub fn record_latency(&mut self, circuit_id: u64, latency_ms: u64) {
        if let Some(circuit) = self.circuits.iter_mut().find(|c| c.id == circuit_id) {
            circuit.latency_ms = Some(latency_ms);
        }
    }

    /// Marks a circuit as active.
    pub fn activate_circuit(&mut self, circuit_id: u64) {
        if let Some(circuit) = self.circuits.iter_mut().find(|c| c.id == circuit_id)
            && circuit.state == CircuitState::Ready
        {
            circuit.state = CircuitState::Active;
        }
    }

    /// Closes a circuit and removes its target association.
    pub fn close_circuit(&mut self, circuit_id: u64) {
        if let Some(circuit) = self.circuits.iter_mut().find(|c| c.id == circuit_id) {
            circuit.state = CircuitState::Closed;
        }
        self.target_circuits.retain(|_, id| *id != circuit_id);
    }

    /// Creates a new circuit for the same target, closing the old one.
    pub fn rotate_circuit(&mut self, target: &str) -> u64 {
        if let Some(&old_id) = self.target_circuits.get(target) {
            self.close_circuit(old_id);
        }
        self.create_circuit(Some(target), None)
    }

    /// Adds a bridge relay for Tor-blocked networks.
    pub fn add_bridge(&mut self, bridge: BridgeRelay) {
        self.bridges.push(bridge);
    }

    /// Returns all configured bridge relays.
    pub fn bridges(&self) -> &[BridgeRelay] {
        &self.bridges
    }

    /// Returns a circuit by ID.
    pub fn get_circuit(&self, circuit_id: u64) -> Option<&TorCircuit> {
        self.circuits.iter().find(|c| c.id == circuit_id)
    }

    /// Returns all active circuits.
    pub fn active_circuits(&self) -> Vec<&TorCircuit> {
        self.circuits
            .iter()
            .filter(|c| c.state == CircuitState::Active || c.state == CircuitState::Ready)
            .collect()
    }

    /// Returns the number of active circuits.
    pub fn active_count(&self) -> usize {
        self.active_circuits().len()
    }

    /// Returns total circuits created (all states).
    pub fn total_circuits(&self) -> usize {
        self.circuits.len()
    }

    /// Checks if a URL targets a .onion hidden service.
    pub fn is_onion_address(url: &str) -> bool {
        let lower = url.to_lowercase();
        lower.contains(".onion")
    }

    /// Returns the SOCKS proxy address for connecting through Tor.
    pub fn socks_address(&self) -> String {
        format!("socks5://127.0.0.1:{}", self.config.socks_port)
    }

    /// Returns the optimal circuit for a target based on latency.
    pub fn optimal_circuit_for_target(&self, target: &str) -> Option<&TorCircuit> {
        self.circuits
            .iter()
            .filter(|c| {
                c.target.as_deref() == Some(target)
                    && (c.state == CircuitState::Ready || c.state == CircuitState::Active)
            })
            .min_by_key(|c| c.latency_ms.unwrap_or(u64::MAX))
    }

    /// Prunes circuits that exceed the maximum allowed latency.
    pub fn prune_slow_circuits(&mut self) {
        let max_latency = self.config.max_circuit_latency_ms;
        for circuit in &mut self.circuits {
            if let Some(latency) = circuit.latency_ms
                && latency > max_latency
                && circuit.state != CircuitState::Closed
            {
                circuit.state = CircuitState::Closed;
            }
        }
        self.target_circuits.retain(|_, id| {
            self.circuits
                .iter()
                .find(|c| c.id == *id)
                .is_some_and(|c| c.state != CircuitState::Closed)
        });
    }

    /// Composes a Tor circuit with a proxy chain: client → proxy → Tor → target.
    pub fn compose_with_proxy(&self, circuit_id: u64, proxy_chain_hops: &[u64]) -> Vec<String> {
        let mut path = Vec::new();
        for &hop_id in proxy_chain_hops {
            path.push(format!("proxy:{hop_id}"));
        }
        path.push(format!("tor-circuit:{circuit_id}"));
        path
    }
}

#[cfg(test)]
#[path = "tor_manager_test.rs"]
mod tor_manager_test;
