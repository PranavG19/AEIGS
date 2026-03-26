/// Distributed Mesh C2 v2 — P2P beacon routing with no central server.
/// DHT-based peer discovery, onion routing through N hops, gossip protocol
/// for command propagation, redundant rerouting, and message deduplication.
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Unique identifier for a mesh peer node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(pub u64);

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer-{:016x}", self.0)
    }
}

/// Kademlia-style distance metric: XOR of peer IDs.
pub fn xor_distance(a: PeerId, b: PeerId) -> u64 {
    a.0 ^ b.0
}

/// Entry in the distributed hash table for peer discovery.
#[derive(Debug, Clone)]
pub struct DhtEntry {
    pub peer_id: PeerId,
    pub address: String,
    pub last_seen: Instant,
    pub latency_ms: u64,
    pub capabilities: Vec<String>,
}

/// K-bucket for Kademlia DHT routing.
#[derive(Debug)]
pub struct KBucket {
    pub k: usize,
    pub entries: Vec<DhtEntry>,
}

impl KBucket {
    pub fn new(k: usize) -> Self {
        Self {
            k,
            entries: Vec::with_capacity(k),
        }
    }

    pub fn insert(&mut self, entry: DhtEntry) -> bool {
        if let Some(pos) = self.entries.iter().position(|e| e.peer_id == entry.peer_id) {
            self.entries[pos] = entry;
            return true;
        }
        if self.entries.len() < self.k {
            self.entries.push(entry);
            return true;
        }
        false
    }

    pub fn closest(&self, target: PeerId, count: usize) -> Vec<&DhtEntry> {
        let mut sorted: Vec<&DhtEntry> = self.entries.iter().collect();
        sorted.sort_by_key(|e| xor_distance(e.peer_id, target));
        sorted.truncate(count);
        sorted
    }
}

/// DHT routing table composed of 64 k-buckets (one per bit of the ID space).
#[derive(Debug)]
pub struct DhtRoutingTable {
    pub local_id: PeerId,
    pub buckets: Vec<KBucket>,
    pub k: usize,
}

impl DhtRoutingTable {
    pub fn new(local_id: PeerId, k: usize) -> Self {
        let buckets = (0..64).map(|_| KBucket::new(k)).collect();
        Self {
            local_id,
            buckets,
            k,
        }
    }

    fn bucket_index(&self, peer_id: PeerId) -> usize {
        let dist = xor_distance(self.local_id, peer_id);
        if dist == 0 {
            return 0;
        }
        (63 - dist.leading_zeros() as usize).min(63)
    }

    pub fn insert(&mut self, entry: DhtEntry) -> bool {
        let idx = self.bucket_index(entry.peer_id);
        self.buckets[idx].insert(entry)
    }

    pub fn find_closest(&self, target: PeerId, count: usize) -> Vec<&DhtEntry> {
        let mut all: Vec<&DhtEntry> = self.buckets.iter().flat_map(|b| b.entries.iter()).collect();
        all.sort_by_key(|e| xor_distance(e.peer_id, target));
        all.truncate(count);
        all
    }

    pub fn peer_count(&self) -> usize {
        self.buckets.iter().map(|b| b.entries.len()).sum()
    }
}

/// A single layer in an onion-routed message.
#[derive(Debug, Clone)]
pub struct OnionLayer {
    pub next_hop: PeerId,
    pub encrypted_payload: Vec<u8>,
}

/// Onion-routed message through N hops before reaching destination.
#[derive(Debug, Clone)]
pub struct OnionMessage {
    pub message_id: u64,
    pub layers: Vec<OnionLayer>,
    pub final_payload: Vec<u8>,
}

/// Build an onion route through the specified hops.
pub fn build_onion_route(hops: &[PeerId], payload: &[u8], message_id: u64) -> OnionMessage {
    let mut layers = Vec::with_capacity(hops.len());
    for hop in hops {
        layers.push(OnionLayer {
            next_hop: *hop,
            encrypted_payload: payload.to_vec(),
        });
    }
    OnionMessage {
        message_id,
        layers,
        final_payload: payload.to_vec(),
    }
}

/// Peel one onion layer, returning the next hop and remaining message.
pub fn peel_onion_layer(msg: &mut OnionMessage) -> Option<PeerId> {
    if msg.layers.is_empty() {
        return None;
    }
    let layer = msg.layers.remove(0);
    Some(layer.next_hop)
}

/// Gossip protocol message types for command propagation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipMessageType {
    Command,
    Heartbeat,
    PeerAnnounce,
    PeerLeave,
    FindingBroadcast,
}

/// A gossip message propagated through the mesh.
#[derive(Debug, Clone)]
pub struct GossipMessage {
    pub id: u64,
    pub origin: PeerId,
    pub msg_type: GossipMessageType,
    pub payload: Vec<u8>,
    pub ttl: u8,
    pub timestamp_ms: u64,
}

/// Deduplication filter for gossip messages.
#[derive(Debug)]
pub struct MessageDeduplicator {
    seen: HashSet<u64>,
    order: VecDeque<u64>,
    capacity: usize,
}

impl MessageDeduplicator {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn is_duplicate(&mut self, message_id: u64) -> bool {
        if self.seen.contains(&message_id) {
            return true;
        }
        if self.order.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(message_id);
        self.order.push_back(message_id);
        false
    }

    pub fn seen_count(&self) -> usize {
        self.seen.len()
    }
}

/// Gossip protocol engine for flooding commands across the mesh.
#[derive(Debug)]
pub struct GossipEngine {
    pub local_id: PeerId,
    pub fanout: usize,
    pub dedup: MessageDeduplicator,
    pub pending_forward: VecDeque<(PeerId, GossipMessage)>,
}

impl GossipEngine {
    pub fn new(local_id: PeerId, fanout: usize, dedup_capacity: usize) -> Self {
        Self {
            local_id,
            fanout,
            dedup: MessageDeduplicator::new(dedup_capacity),
            pending_forward: VecDeque::new(),
        }
    }

    pub fn receive(&mut self, msg: GossipMessage, neighbors: &[PeerId]) -> Option<GossipMessage> {
        if self.dedup.is_duplicate(msg.id) {
            return None;
        }
        if msg.ttl == 0 {
            return Some(msg);
        }
        let mut forwarded = msg.clone();
        forwarded.ttl = forwarded.ttl.saturating_sub(1);
        let targets: Vec<PeerId> = neighbors
            .iter()
            .filter(|p| **p != msg.origin && **p != self.local_id)
            .take(self.fanout)
            .copied()
            .collect();
        for target in targets {
            self.pending_forward.push_back((target, forwarded.clone()));
        }
        Some(msg)
    }

    pub fn drain_forwards(&mut self) -> Vec<(PeerId, GossipMessage)> {
        self.pending_forward.drain(..).collect()
    }
}

/// Route redundancy: maintain multiple paths to each destination.
#[derive(Debug)]
pub struct RedundantRouter {
    pub routes: HashMap<PeerId, Vec<Vec<PeerId>>>,
    pub max_routes_per_dest: usize,
}

impl RedundantRouter {
    pub fn new(max_routes: usize) -> Self {
        Self {
            routes: HashMap::new(),
            max_routes_per_dest: max_routes,
        }
    }

    pub fn add_route(&mut self, dest: PeerId, path: Vec<PeerId>) {
        let routes = self.routes.entry(dest).or_default();
        if routes.len() < self.max_routes_per_dest && !routes.iter().any(|r| r == &path) {
            routes.push(path);
        }
    }

    pub fn get_route(&self, dest: PeerId) -> Option<&Vec<PeerId>> {
        self.routes.get(&dest).and_then(|r| r.first())
    }

    pub fn get_alternate_route(
        &self,
        dest: PeerId,
        exclude_first_hop: PeerId,
    ) -> Option<&Vec<PeerId>> {
        self.routes.get(&dest).and_then(|routes| {
            routes
                .iter()
                .find(|r| r.first() != Some(&exclude_first_hop))
        })
    }

    pub fn route_count(&self, dest: PeerId) -> usize {
        self.routes.get(&dest).map_or(0, |r| r.len())
    }
}

/// Health status of a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerHealth {
    Healthy,
    Degraded,
    Unreachable,
}

/// Peer health tracker for rerouting decisions.
#[derive(Debug)]
pub struct PeerHealthTracker {
    pub health: HashMap<PeerId, PeerHealth>,
    pub failure_counts: HashMap<PeerId, u32>,
    pub failure_threshold: u32,
    pub degraded_threshold: u32,
}

impl PeerHealthTracker {
    pub fn new(degraded_threshold: u32, failure_threshold: u32) -> Self {
        Self {
            health: HashMap::new(),
            failure_counts: HashMap::new(),
            failure_threshold,
            degraded_threshold,
        }
    }

    pub fn record_success(&mut self, peer: PeerId) {
        self.failure_counts.insert(peer, 0);
        self.health.insert(peer, PeerHealth::Healthy);
    }

    pub fn record_failure(&mut self, peer: PeerId) {
        let count = self.failure_counts.entry(peer).or_insert(0);
        *count += 1;
        if *count >= self.failure_threshold {
            self.health.insert(peer, PeerHealth::Unreachable);
        } else if *count >= self.degraded_threshold {
            self.health.insert(peer, PeerHealth::Degraded);
        }
    }

    pub fn get_health(&self, peer: PeerId) -> PeerHealth {
        self.health
            .get(&peer)
            .copied()
            .unwrap_or(PeerHealth::Healthy)
    }

    pub fn is_reachable(&self, peer: PeerId) -> bool {
        self.get_health(peer) != PeerHealth::Unreachable
    }
}

/// Top-level Mesh C2 coordinator.
#[derive(Debug)]
pub struct MeshC2 {
    pub local_id: PeerId,
    pub dht: DhtRoutingTable,
    pub gossip: GossipEngine,
    pub router: RedundantRouter,
    pub health: PeerHealthTracker,
    pub default_hops: usize,
    pub beacon_interval: Duration,
}

impl MeshC2 {
    pub fn new(local_id: PeerId, config: MeshC2Config) -> Self {
        Self {
            local_id,
            dht: DhtRoutingTable::new(local_id, config.k_bucket_size),
            gossip: GossipEngine::new(local_id, config.gossip_fanout, config.dedup_capacity),
            router: RedundantRouter::new(config.max_redundant_routes),
            health: PeerHealthTracker::new(config.degraded_threshold, config.failure_threshold),
            default_hops: config.default_onion_hops,
            beacon_interval: config.beacon_interval,
        }
    }

    pub fn register_peer(&mut self, entry: DhtEntry) -> bool {
        let peer_id = entry.peer_id;
        let inserted = self.dht.insert(entry);
        if inserted {
            self.health.record_success(peer_id);
        }
        inserted
    }

    pub fn send_command(&mut self, dest: PeerId, payload: &[u8]) -> Option<OnionMessage> {
        let hops: Vec<PeerId> = self
            .dht
            .find_closest(dest, self.default_hops)
            .iter()
            .map(|e| e.peer_id)
            .filter(|p| self.health.is_reachable(*p))
            .take(self.default_hops)
            .collect();
        if hops.is_empty() {
            return None;
        }
        let msg_id = dest.0.wrapping_mul(31).wrapping_add(self.local_id.0);
        let route = hops.clone();
        self.router.add_route(dest, route);
        Some(build_onion_route(&hops, payload, msg_id))
    }

    pub fn broadcast_gossip(&mut self, msg: GossipMessage) -> Vec<(PeerId, GossipMessage)> {
        let neighbors: Vec<PeerId> = self
            .dht
            .find_closest(self.local_id, self.gossip.fanout * 2)
            .iter()
            .map(|e| e.peer_id)
            .collect();
        self.gossip.receive(msg, &neighbors);
        self.gossip.drain_forwards()
    }

    pub fn peer_count(&self) -> usize {
        self.dht.peer_count()
    }
}

/// Configuration for the Mesh C2 system.
#[derive(Debug, Clone)]
pub struct MeshC2Config {
    pub k_bucket_size: usize,
    pub gossip_fanout: usize,
    pub dedup_capacity: usize,
    pub max_redundant_routes: usize,
    pub default_onion_hops: usize,
    pub degraded_threshold: u32,
    pub failure_threshold: u32,
    pub beacon_interval: Duration,
}

impl Default for MeshC2Config {
    fn default() -> Self {
        Self {
            k_bucket_size: 20,
            gossip_fanout: 3,
            dedup_capacity: 10_000,
            max_redundant_routes: 4,
            default_onion_hops: 3,
            degraded_threshold: 3,
            failure_threshold: 10,
            beacon_interval: Duration::from_secs(30),
        }
    }
}
