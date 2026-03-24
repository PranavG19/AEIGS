use petgraph::algo::dijkstra;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::{Bfs, EdgeRef};
use petgraph::Direction;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

/// Unique host identifier within the network topology.
pub type HostId = u64;

/// Unique credential identifier for tracking reuse across hosts.
pub type CredentialId = u64;

/// Network segment identifier (e.g. "dmz", "internal-prod", "corp-lan").
pub type SegmentId = String;

/// A network segment groups hosts that share layer-2 or layer-3 adjacency.
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkSegment {
    pub id: SegmentId,
    pub cidr: String,
    pub description: String,
}

/// Service exposed on a host/port combination.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Service {
    pub port: u16,
    pub protocol: ServiceProtocol,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceProtocol {
    Ssh,
    Smb,
    Rdp,
    Mssql,
    Oracle,
    DockerApi,
    KubernetesApi,
    Http,
    Https,
    Ldap,
    Kerberos,
    Winrm,
    PostgreSql,
    MySql,
}

impl std::fmt::Display for ServiceProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Ssh => "ssh",
            Self::Smb => "smb",
            Self::Rdp => "rdp",
            Self::Mssql => "mssql",
            Self::Oracle => "oracle",
            Self::DockerApi => "docker-api",
            Self::KubernetesApi => "kubernetes-api",
            Self::Http => "http",
            Self::Https => "https",
            Self::Ldap => "ldap",
            Self::Kerberos => "kerberos",
            Self::Winrm => "winrm",
            Self::PostgreSql => "postgresql",
            Self::MySql => "mysql",
        };
        write!(f, "{name}")
    }
}

/// A host within the network topology.
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkHost {
    pub id: HostId,
    pub hostname: String,
    pub ip_address: String,
    pub segment: SegmentId,
    pub services: Vec<Service>,
    pub compromised: bool,
    pub high_value: bool,
    pub os_type: OsType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsType {
    Linux,
    Windows,
    Container,
    NetworkDevice,
    Unknown,
}

/// Lateral movement technique with associated protocol requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LateralMovementTechnique {
    SshKeyReuse,
    SshAgentForwardingHijack,
    SmbPassTheHash,
    SmbPassTheTicket,
    WmiPassTheHash,
    RdpSessionHijack,
    MssqlLinkedServer,
    OracleDbLink,
    DockerApiExploit,
    KubernetesApiExploit,
    CloudIamRoleChaining,
    WinrmRemoteExec,
}

impl LateralMovementTechnique {
    /// Base difficulty for the technique (lower = easier).
    pub fn base_difficulty(self) -> f64 {
        match self {
            Self::SshKeyReuse => 0.2,
            Self::SshAgentForwardingHijack => 0.4,
            Self::SmbPassTheHash => 0.3,
            Self::SmbPassTheTicket => 0.5,
            Self::WmiPassTheHash => 0.35,
            Self::RdpSessionHijack => 0.6,
            Self::MssqlLinkedServer => 0.3,
            Self::OracleDbLink => 0.35,
            Self::DockerApiExploit => 0.25,
            Self::KubernetesApiExploit => 0.4,
            Self::CloudIamRoleChaining => 0.55,
            Self::WinrmRemoteExec => 0.3,
        }
    }

    /// Required service protocol on the target host.
    pub fn required_protocol(self) -> Option<ServiceProtocol> {
        match self {
            Self::SshKeyReuse | Self::SshAgentForwardingHijack => Some(ServiceProtocol::Ssh),
            Self::SmbPassTheHash | Self::SmbPassTheTicket => Some(ServiceProtocol::Smb),
            Self::WmiPassTheHash | Self::WinrmRemoteExec => Some(ServiceProtocol::Winrm),
            Self::RdpSessionHijack => Some(ServiceProtocol::Rdp),
            Self::MssqlLinkedServer => Some(ServiceProtocol::Mssql),
            Self::OracleDbLink => Some(ServiceProtocol::Oracle),
            Self::DockerApiExploit => Some(ServiceProtocol::DockerApi),
            Self::KubernetesApiExploit => Some(ServiceProtocol::KubernetesApi),
            Self::CloudIamRoleChaining => None,
        }
    }

    /// Required OS type on the source host (where the attacker is).
    pub fn required_source_os(self) -> Option<OsType> {
        match self {
            Self::SshKeyReuse | Self::SshAgentForwardingHijack => Some(OsType::Linux),
            Self::SmbPassTheHash
            | Self::SmbPassTheTicket
            | Self::WmiPassTheHash
            | Self::WinrmRemoteExec
            | Self::RdpSessionHijack => Some(OsType::Windows),
            Self::DockerApiExploit => Some(OsType::Container),
            _ => None,
        }
    }
}

impl std::fmt::Display for LateralMovementTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::SshKeyReuse => "SSH Key Reuse",
            Self::SshAgentForwardingHijack => "SSH Agent Forwarding Hijack",
            Self::SmbPassTheHash => "SMB Pass-the-Hash",
            Self::SmbPassTheTicket => "SMB Pass-the-Ticket",
            Self::WmiPassTheHash => "WMI Pass-the-Hash",
            Self::RdpSessionHijack => "RDP Session Hijack",
            Self::MssqlLinkedServer => "MSSQL Linked Server Traversal",
            Self::OracleDbLink => "Oracle DB Link Traversal",
            Self::DockerApiExploit => "Docker API Exploit",
            Self::KubernetesApiExploit => "Kubernetes API Exploit",
            Self::CloudIamRoleChaining => "Cloud IAM Role Chaining",
            Self::WinrmRemoteExec => "WinRM Remote Execution",
        };
        write!(f, "{name}")
    }
}

/// A credential that may be reused across hosts.
#[derive(Debug, Clone, PartialEq)]
pub struct Credential {
    pub id: CredentialId,
    pub credential_type: CredentialType,
    pub username: String,
    pub origin_host: HostId,
    pub valid_on: Vec<HostId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialType {
    SshPrivateKey,
    NtlmHash,
    KerberosTicket,
    Password,
    Token,
    Certificate,
    IamRole,
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::SshPrivateKey => "SSH Private Key",
            Self::NtlmHash => "NTLM Hash",
            Self::KerberosTicket => "Kerberos Ticket",
            Self::Password => "Password",
            Self::Token => "Token",
            Self::Certificate => "Certificate",
            Self::IamRole => "IAM Role",
        };
        write!(f, "{name}")
    }
}

/// Edge in the pivot graph representing a lateral movement path between hosts.
#[derive(Debug, Clone)]
pub struct PivotEdge {
    pub source: HostId,
    pub target: HostId,
    pub technique: LateralMovementTechnique,
    pub difficulty: f64,
    pub credential_required: Option<CredentialId>,
}

/// Inferred firewall rule between two network segments.
#[derive(Debug, Clone, PartialEq)]
pub struct InferredFirewallRule {
    pub source_segment: SegmentId,
    pub target_segment: SegmentId,
    pub allowed_ports: BTreeSet<u16>,
    pub blocked_ports: BTreeSet<u16>,
}

/// A complete pivot path from an external entry to an internal target.
#[derive(Debug, Clone)]
pub struct PivotPath {
    pub hops: Vec<PivotHop>,
    pub total_difficulty: f64,
    pub pivot_count: usize,
}

/// Single hop along a pivot path.
#[derive(Debug, Clone)]
pub struct PivotHop {
    pub from_host: HostId,
    pub to_host: HostId,
    pub technique: LateralMovementTechnique,
    pub difficulty: f64,
    pub credential_used: Option<CredentialId>,
}

/// Credential-to-host accessibility matrix entry.
#[derive(Debug, Clone)]
pub struct CredentialAccessEntry {
    pub credential_id: CredentialId,
    pub credential_type: CredentialType,
    pub username: String,
    pub accessible_hosts: Vec<HostId>,
}

/// Result of pivot point identification.
#[derive(Debug, Clone)]
pub struct PivotPoint {
    pub host_id: HostId,
    pub reachable_segments: Vec<SegmentId>,
    pub reachable_host_count: usize,
    pub strategic_value: f64,
}

/// The network topology and lateral movement planner.
pub struct NetworkPivotPlanner {
    graph: DiGraph<HostId, PivotEdge>,
    host_index: HashMap<HostId, NodeIndex>,
    hosts: HashMap<HostId, NetworkHost>,
    segments: HashMap<SegmentId, NetworkSegment>,
    credentials: HashMap<CredentialId, Credential>,
    connectivity: HashMap<(SegmentId, SegmentId), BTreeSet<u16>>,
    next_host_id: HostId,
    next_credential_id: CredentialId,
}

impl NetworkPivotPlanner {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            host_index: HashMap::new(),
            hosts: HashMap::new(),
            segments: HashMap::new(),
            credentials: HashMap::new(),
            connectivity: HashMap::new(),
            next_host_id: 0,
            next_credential_id: 0,
        }
    }

    pub fn add_segment(&mut self, id: SegmentId, cidr: String, description: String) {
        self.segments.insert(
            id.clone(),
            NetworkSegment {
                id,
                cidr,
                description,
            },
        );
    }

    /// Adds a host and returns its assigned id.
    pub fn add_host(
        &mut self,
        hostname: String,
        ip_address: String,
        segment: SegmentId,
        services: Vec<Service>,
        os_type: OsType,
        high_value: bool,
    ) -> HostId {
        let id = self.next_host_id;
        self.next_host_id += 1;
        let host = NetworkHost {
            id,
            hostname,
            ip_address,
            segment,
            services,
            compromised: false,
            high_value,
            os_type,
        };
        let node_idx = self.graph.add_node(id);
        self.host_index.insert(id, node_idx);
        self.hosts.insert(id, host);
        id
    }

    /// Marks a host as compromised by the attacker.
    pub fn mark_compromised(&mut self, host_id: HostId) -> bool {
        if let Some(host) = self.hosts.get_mut(&host_id) {
            host.compromised = true;
            return true;
        }
        false
    }

    /// Records observed connectivity between segments on a port.
    pub fn record_connectivity(
        &mut self,
        source_segment: &SegmentId,
        target_segment: &SegmentId,
        port: u16,
    ) {
        self.connectivity
            .entry((source_segment.clone(), target_segment.clone()))
            .or_default()
            .insert(port);
    }

    /// Registers a credential and returns its assigned id.
    pub fn add_credential(
        &mut self,
        credential_type: CredentialType,
        username: String,
        origin_host: HostId,
        valid_on: Vec<HostId>,
    ) -> CredentialId {
        let id = self.next_credential_id;
        self.next_credential_id += 1;
        self.credentials.insert(
            id,
            Credential {
                id,
                credential_type,
                username,
                origin_host,
                valid_on,
            },
        );
        id
    }

    /// Builds lateral movement edges based on services, credentials, and OS types.
    pub fn build_pivot_edges(&mut self) {
        let all_techniques = [
            LateralMovementTechnique::SshKeyReuse,
            LateralMovementTechnique::SshAgentForwardingHijack,
            LateralMovementTechnique::SmbPassTheHash,
            LateralMovementTechnique::SmbPassTheTicket,
            LateralMovementTechnique::WmiPassTheHash,
            LateralMovementTechnique::RdpSessionHijack,
            LateralMovementTechnique::MssqlLinkedServer,
            LateralMovementTechnique::OracleDbLink,
            LateralMovementTechnique::DockerApiExploit,
            LateralMovementTechnique::KubernetesApiExploit,
            LateralMovementTechnique::CloudIamRoleChaining,
            LateralMovementTechnique::WinrmRemoteExec,
        ];

        let host_ids: Vec<HostId> = self.hosts.keys().copied().collect();
        let mut edges_to_add: Vec<(HostId, HostId, PivotEdge)> = Vec::new();

        for &src_id in &host_ids {
            for &tgt_id in &host_ids {
                if src_id == tgt_id {
                    continue;
                }
                let src_host = &self.hosts[&src_id];
                let tgt_host = &self.hosts[&tgt_id];

                if !self.segments_can_communicate(&src_host.segment, &tgt_host.segment) {
                    continue;
                }

                for &technique in &all_techniques {
                    if !self.technique_applicable(src_id, tgt_id, technique) {
                        continue;
                    }

                    let credential_required =
                        self.find_credential_for_technique(src_id, tgt_id, technique);
                    let cross_segment_penalty = if src_host.segment != tgt_host.segment {
                        0.1
                    } else {
                        0.0
                    };
                    let difficulty = technique.base_difficulty() + cross_segment_penalty;

                    edges_to_add.push((
                        src_id,
                        tgt_id,
                        PivotEdge {
                            source: src_id,
                            target: tgt_id,
                            technique,
                            difficulty,
                            credential_required,
                        },
                    ));
                }
            }
        }

        for (src, tgt, edge) in edges_to_add {
            let src_idx = self.host_index[&src];
            let tgt_idx = self.host_index[&tgt];
            self.graph.add_edge(src_idx, tgt_idx, edge);
        }
    }

    /// Checks whether a technique can be used from src to tgt.
    fn technique_applicable(
        &self,
        src_id: HostId,
        tgt_id: HostId,
        technique: LateralMovementTechnique,
    ) -> bool {
        let src_host = &self.hosts[&src_id];
        let tgt_host = &self.hosts[&tgt_id];

        if let Some(required_os) = technique.required_source_os()
            && src_host.os_type != required_os
        {
            return false;
        }

        if let Some(required_proto) = technique.required_protocol() {
            let has_service = tgt_host
                .services
                .iter()
                .any(|s| s.protocol == required_proto);
            if !has_service {
                return false;
            }
        }

        true
    }

    /// Finds a credential on the source host that is valid on the target.
    fn find_credential_for_technique(
        &self,
        src_id: HostId,
        tgt_id: HostId,
        technique: LateralMovementTechnique,
    ) -> Option<CredentialId> {
        let needed_type = match technique {
            LateralMovementTechnique::SshKeyReuse
            | LateralMovementTechnique::SshAgentForwardingHijack => CredentialType::SshPrivateKey,
            LateralMovementTechnique::SmbPassTheHash | LateralMovementTechnique::WmiPassTheHash => {
                CredentialType::NtlmHash
            }
            LateralMovementTechnique::SmbPassTheTicket => CredentialType::KerberosTicket,
            LateralMovementTechnique::CloudIamRoleChaining => CredentialType::IamRole,
            _ => return None,
        };

        self.credentials.values().find_map(|cred| {
            if cred.credential_type == needed_type
                && cred.origin_host == src_id
                && cred.valid_on.contains(&tgt_id)
            {
                Some(cred.id)
            } else {
                None
            }
        })
    }

    /// Whether two segments can communicate (based on recorded connectivity or same-segment).
    fn segments_can_communicate(&self, src: &SegmentId, tgt: &SegmentId) -> bool {
        if src == tgt {
            return true;
        }
        self.connectivity.contains_key(&(src.clone(), tgt.clone()))
    }

    /// Finds the optimal pivot path from a source host to a target host.
    /// Uses Dijkstra shortest path weighted by difficulty.
    pub fn find_optimal_path(&self, source: HostId, target: HostId) -> Option<PivotPath> {
        let src_idx = *self.host_index.get(&source)?;
        let tgt_idx = *self.host_index.get(&target)?;

        let predecessors = dijkstra(&self.graph, src_idx, Some(tgt_idx), |e| {
            e.weight().difficulty
        });

        if !predecessors.contains_key(&tgt_idx) {
            return None;
        }

        let path_indices = self.reconstruct_path(src_idx, tgt_idx)?;
        let mut hops = Vec::new();
        let mut total_difficulty = 0.0;

        for window in path_indices.windows(2) {
            let from_idx = window[0];
            let to_idx = window[1];
            let from_id = self.graph[from_idx];
            let to_id = self.graph[to_idx];

            let edge = self
                .graph
                .edges_connecting(from_idx, to_idx)
                .min_by(|a, b| {
                    a.weight()
                        .difficulty
                        .partial_cmp(&b.weight().difficulty)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })?;

            let w = edge.weight();
            total_difficulty += w.difficulty;

            hops.push(PivotHop {
                from_host: from_id,
                to_host: to_id,
                technique: w.technique,
                difficulty: w.difficulty,
                credential_used: w.credential_required,
            });
        }

        let pivot_count = if hops.is_empty() { 0 } else { hops.len() - 1 };

        Some(PivotPath {
            hops,
            total_difficulty,
            pivot_count,
        })
    }

    /// BFS-based path reconstruction after Dijkstra.
    fn reconstruct_path(&self, source: NodeIndex, target: NodeIndex) -> Option<Vec<NodeIndex>> {
        let mut prev: HashMap<NodeIndex, (NodeIndex, f64)> = HashMap::new();
        let mut dist: HashMap<NodeIndex, f64> = HashMap::new();
        let mut queue = VecDeque::new();

        dist.insert(source, 0.0);
        queue.push_back(source);

        while let Some(current) = queue.pop_front() {
            let current_dist = dist[&current];
            for edge in self.graph.edges_directed(current, Direction::Outgoing) {
                let next = edge.target();
                let new_dist = current_dist + edge.weight().difficulty;
                let better = dist.get(&next).is_none_or(|&d| new_dist < d);
                if better {
                    dist.insert(next, new_dist);
                    prev.insert(next, (current, new_dist));
                    queue.push_back(next);
                }
            }
        }

        if !prev.contains_key(&target) && source != target {
            return None;
        }

        let mut path = Vec::new();
        let mut current = target;
        while current != source {
            path.push(current);
            current = prev.get(&current)?.0;
        }
        path.push(source);
        path.reverse();
        Some(path)
    }

    /// Identifies pivot points: compromised hosts that can reach new segments.
    pub fn identify_pivot_points(&self) -> Vec<PivotPoint> {
        let compromised: Vec<HostId> = self
            .hosts
            .values()
            .filter(|h| h.compromised)
            .map(|h| h.id)
            .collect();

        let mut pivot_points = Vec::new();

        for &host_id in &compromised {
            let reachable = self.bfs_reachable(host_id);
            let host_segment = &self.hosts[&host_id].segment;

            let mut reachable_segments: Vec<SegmentId> = reachable
                .iter()
                .filter_map(|&rid| self.hosts.get(&rid))
                .map(|h| h.segment.clone())
                .filter(|seg| seg != host_segment)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            reachable_segments.sort();

            let reachable_host_count = reachable.len();
            let high_value_reachable = reachable
                .iter()
                .filter(|&&rid| self.hosts.get(&rid).is_some_and(|h| h.high_value))
                .count();

            let strategic_value = (reachable_segments.len() as f64 * 0.4)
                + (reachable_host_count as f64 * 0.2)
                + (high_value_reachable as f64 * 0.4);

            if !reachable_segments.is_empty() || reachable_host_count > 0 {
                pivot_points.push(PivotPoint {
                    host_id,
                    reachable_segments,
                    reachable_host_count,
                    strategic_value,
                });
            }
        }

        pivot_points.sort_by(|a, b| {
            b.strategic_value
                .partial_cmp(&a.strategic_value)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        pivot_points
    }

    /// BFS reachability from a given host through the pivot graph.
    fn bfs_reachable(&self, start: HostId) -> Vec<HostId> {
        let Some(&start_idx) = self.host_index.get(&start) else {
            return Vec::new();
        };

        let mut visited = HashSet::new();
        let mut bfs = Bfs::new(&self.graph, start_idx);
        while let Some(node_idx) = bfs.next(&self.graph) {
            let host_id = self.graph[node_idx];
            if host_id != start {
                visited.insert(host_id);
            }
        }

        let mut result: Vec<HostId> = visited.into_iter().collect();
        result.sort();
        result
    }

    /// Builds the credential-to-host accessibility matrix.
    pub fn credential_access_matrix(&self) -> Vec<CredentialAccessEntry> {
        let mut entries: Vec<CredentialAccessEntry> = self
            .credentials
            .values()
            .map(|cred| CredentialAccessEntry {
                credential_id: cred.id,
                credential_type: cred.credential_type,
                username: cred.username.clone(),
                accessible_hosts: {
                    let mut hosts = cred.valid_on.clone();
                    hosts.sort();
                    hosts
                },
            })
            .collect();
        entries.sort_by_key(|e| e.credential_id);
        entries
    }

    /// Infers firewall rules between segments from observed connectivity.
    /// Common service ports that were NOT observed are inferred as blocked.
    pub fn infer_firewall_rules(&self) -> Vec<InferredFirewallRule> {
        let common_ports: BTreeSet<u16> = [
            22, 80, 443, 445, 1433, 1521, 3306, 3389, 5432, 5985, 8080, 8443, 2375, 6443,
        ]
        .into_iter()
        .collect();

        let segment_ids: Vec<SegmentId> = {
            let mut ids: Vec<_> = self.segments.keys().cloned().collect();
            ids.sort();
            ids
        };

        let mut rules = Vec::new();

        for src in &segment_ids {
            for tgt in &segment_ids {
                if src == tgt {
                    continue;
                }
                let key = (src.clone(), tgt.clone());
                let allowed = self.connectivity.get(&key).cloned().unwrap_or_default();
                let blocked: BTreeSet<u16> = common_ports.difference(&allowed).copied().collect();

                rules.push(InferredFirewallRule {
                    source_segment: src.clone(),
                    target_segment: tgt.clone(),
                    allowed_ports: allowed,
                    blocked_ports: blocked,
                });
            }
        }

        rules
    }

    /// Lists all available lateral movement techniques from a compromised host.
    pub fn available_techniques(
        &self,
        host_id: HostId,
    ) -> Vec<(HostId, LateralMovementTechnique, f64)> {
        let Some(&idx) = self.host_index.get(&host_id) else {
            return Vec::new();
        };

        let mut techniques: Vec<(HostId, LateralMovementTechnique, f64)> = self
            .graph
            .edges_directed(idx, Direction::Outgoing)
            .map(|e| {
                let w = e.weight();
                (w.target, w.technique, w.difficulty)
            })
            .collect();
        techniques.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
        techniques
    }

    /// All high-value targets in the network.
    pub fn high_value_targets(&self) -> Vec<HostId> {
        let mut targets: Vec<HostId> = self
            .hosts
            .values()
            .filter(|h| h.high_value)
            .map(|h| h.id)
            .collect();
        targets.sort();
        targets
    }

    /// Counts hosts per segment.
    pub fn hosts_per_segment(&self) -> BTreeMap<SegmentId, usize> {
        let mut counts = BTreeMap::new();
        for host in self.hosts.values() {
            *counts.entry(host.segment.clone()).or_insert(0) += 1;
        }
        counts
    }

    pub fn host(&self, id: HostId) -> Option<&NetworkHost> {
        self.hosts.get(&id)
    }

    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    pub fn credential_count(&self) -> usize {
        self.credentials.len()
    }

    /// Returns all compromised host IDs.
    pub fn compromised_hosts(&self) -> Vec<HostId> {
        let mut result: Vec<HostId> = self
            .hosts
            .values()
            .filter(|h| h.compromised)
            .map(|h| h.id)
            .collect();
        result.sort();
        result
    }

    /// Finds all paths from any compromised host to all high-value targets.
    pub fn all_paths_to_high_value(&self) -> Vec<(HostId, HostId, PivotPath)> {
        let compromised = self.compromised_hosts();
        let targets = self.high_value_targets();
        let mut paths = Vec::new();

        for &src in &compromised {
            for &tgt in &targets {
                if src == tgt {
                    continue;
                }
                if let Some(path) = self.find_optimal_path(src, tgt) {
                    paths.push((src, tgt, path));
                }
            }
        }

        paths.sort_by(|a, b| {
            a.2.total_difficulty
                .partial_cmp(&b.2.total_difficulty)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        paths
    }
}

impl Default for NetworkPivotPlanner {
    fn default() -> Self {
        Self::new()
    }
}
