use std::collections::{HashSet, VecDeque};

use crate::attack_graph::{AttackGraph, AttackNodeType};

/// Impact category for propagation analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ImpactType {
    /// Direct exploitation of a connected vulnerability.
    DirectExploit,
    /// Shared credentials allow access to sibling nodes.
    SharedCredential,
    /// Trust relationship enables lateral movement.
    TrustRelationship,
    /// Data flows through the compromised node.
    DataFlow,
    /// Lateral movement to adjacent network segment.
    LateralMovement,
}

impl std::fmt::Display for ImpactType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::DirectExploit => "Direct Exploit",
            Self::SharedCredential => "Shared Credential",
            Self::TrustRelationship => "Trust Relationship",
            Self::DataFlow => "Data Flow",
            Self::LateralMovement => "Lateral Movement",
        };
        write!(f, "{label}")
    }
}

/// A single propagation step in the impact cascade.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PropagationStep {
    pub from_node: u64,
    pub to_node: u64,
    pub impact_type: ImpactType,
    pub hop_distance: usize,
    pub cumulative_difficulty: f64,
}

/// Complete impact propagation result from a compromised node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImpactReport {
    pub origin_node: u64,
    pub reachable_nodes: Vec<u64>,
    pub propagation_steps: Vec<PropagationStep>,
    pub impacted_assets: Vec<u64>,
    pub blast_radius: usize,
    pub max_hop_distance: usize,
    pub total_risk_score: f64,
}

/// Credential group linking nodes that share authentication material.
#[derive(Debug, Clone)]
pub struct CredentialGroup {
    pub group_id: String,
    pub node_ids: HashSet<u64>,
}

/// Models cascading impact through an attack graph.
///
/// Starting from a compromised node, propagates impact through direct
/// exploit paths, shared credentials, trust relationships, and data flows
/// to determine the full blast radius.
pub struct ImpactPropagationEngine<'a> {
    graph: &'a AttackGraph,
    credential_groups: Vec<CredentialGroup>,
    trust_pairs: Vec<(u64, u64)>,
}

impl<'a> ImpactPropagationEngine<'a> {
    pub fn new(graph: &'a AttackGraph) -> Self {
        Self {
            graph,
            credential_groups: Vec::new(),
            trust_pairs: Vec::new(),
        }
    }

    /// Register a credential group — nodes sharing the same credential material.
    /// Compromise of any member implies compromise of all members.
    pub fn add_credential_group(&mut self, group_id: String, node_ids: HashSet<u64>) {
        self.credential_groups
            .push(CredentialGroup { group_id, node_ids });
    }

    /// Register a trust relationship — bidirectional trust between two nodes.
    pub fn add_trust_relationship(&mut self, node_a: u64, node_b: u64) {
        self.trust_pairs.push((node_a, node_b));
    }

    /// Propagate impact from the compromised `origin` node.
    /// Returns the full blast radius including cascading effects.
    pub fn propagate(&self, origin: u64) -> Option<ImpactReport> {
        self.graph.node(origin)?;

        let mut visited: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<(u64, usize, f64)> = VecDeque::new();
        let mut steps: Vec<PropagationStep> = Vec::new();

        visited.insert(origin);
        queue.push_back((origin, 0, 0.0));

        while let Some((current, hop, cumulative_diff)) = queue.pop_front() {
            // Direct exploit propagation via graph edges
            for edge in self.graph.outgoing_edges(current) {
                if visited.insert(edge.target) {
                    let new_diff = cumulative_diff + edge.exploitation_difficulty;
                    steps.push(PropagationStep {
                        from_node: current,
                        to_node: edge.target,
                        impact_type: ImpactType::DirectExploit,
                        hop_distance: hop + 1,
                        cumulative_difficulty: new_diff,
                    });
                    queue.push_back((edge.target, hop + 1, new_diff));
                }
            }

            // Shared credential propagation
            for group in &self.credential_groups {
                if group.node_ids.contains(&current) {
                    for &peer in &group.node_ids {
                        if visited.insert(peer) {
                            steps.push(PropagationStep {
                                from_node: current,
                                to_node: peer,
                                impact_type: ImpactType::SharedCredential,
                                hop_distance: hop + 1,
                                cumulative_difficulty: cumulative_diff + 0.5,
                            });
                            queue.push_back((peer, hop + 1, cumulative_diff + 0.5));
                        }
                    }
                }
            }

            // Trust relationship propagation
            for &(a, b) in &self.trust_pairs {
                let peer = if a == current {
                    Some(b)
                } else if b == current {
                    Some(a)
                } else {
                    None
                };
                if let Some(peer_id) = peer
                    && visited.insert(peer_id)
                {
                    steps.push(PropagationStep {
                        from_node: current,
                        to_node: peer_id,
                        impact_type: ImpactType::TrustRelationship,
                        hop_distance: hop + 1,
                        cumulative_difficulty: cumulative_diff + 1.0,
                    });
                    queue.push_back((peer_id, hop + 1, cumulative_diff + 1.0));
                }
            }
        }

        let reachable: Vec<u64> = visited.iter().copied().filter(|&n| n != origin).collect();
        let assets: Vec<u64> = reachable
            .iter()
            .filter(|&&n| {
                self.graph
                    .node(n)
                    .map(|node| node.node_type == AttackNodeType::Asset)
                    .unwrap_or(false)
            })
            .copied()
            .collect();

        let max_hop = steps.iter().map(|s| s.hop_distance).max().unwrap_or(0);
        let blast_radius = reachable.len();

        let risk_score = steps
            .iter()
            .map(|s| {
                let type_weight = match s.impact_type {
                    ImpactType::DirectExploit => 1.0,
                    ImpactType::SharedCredential => 1.5,
                    ImpactType::TrustRelationship => 1.2,
                    ImpactType::DataFlow => 0.8,
                    ImpactType::LateralMovement => 1.3,
                };
                type_weight / (s.hop_distance as f64 + 1.0)
            })
            .sum();

        Some(ImpactReport {
            origin_node: origin,
            reachable_nodes: reachable,
            propagation_steps: steps,
            impacted_assets: assets,
            blast_radius,
            max_hop_distance: max_hop,
            total_risk_score: risk_score,
        })
    }

    /// Compare blast radius of compromising each vulnerability node.
    /// Returns nodes sorted by blast radius descending.
    pub fn blast_radius_ranking(&self) -> Vec<(u64, usize)> {
        let vuln_nodes = self.graph.nodes_by_type(AttackNodeType::Vulnerability);
        let mut rankings: Vec<(u64, usize)> = vuln_nodes
            .into_iter()
            .filter_map(|id| self.propagate(id).map(|report| (id, report.blast_radius)))
            .collect();

        rankings.sort_by(|a, b| b.1.cmp(&a.1));
        rankings
    }
}
