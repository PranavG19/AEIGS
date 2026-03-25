use petgraph::Direction;
use petgraph::algo::dijkstra;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

/// The kind of privilege escalation a path represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EscalationType {
    /// Same tier, different identity (user A → user B data).
    Horizontal,
    /// Lower tier → higher tier (user → admin).
    Vertical,
    /// Role chain traversal (viewer → editor → admin).
    RoleBased,
    /// Accessing restricted endpoints without proper role.
    FunctionLevel,
    /// Accessing restricted data via IDOR/API abuse.
    DataLevel,
    /// Default permissions that grant unintended access.
    Implicit,
}

impl std::fmt::Display for EscalationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Horizontal => "horizontal",
            Self::Vertical => "vertical",
            Self::RoleBased => "role-based",
            Self::FunctionLevel => "function-level",
            Self::DataLevel => "data-level",
            Self::Implicit => "implicit",
        };
        write!(f, "{label}")
    }
}

/// Privilege tier for ordering roles from lowest to highest authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PrivilegeTier {
    Anonymous,
    Guest,
    User,
    Editor,
    Moderator,
    Admin,
    SuperAdmin,
}

impl PrivilegeTier {
    pub fn numeric_rank(self) -> u32 {
        match self {
            Self::Anonymous => 0,
            Self::Guest => 1,
            Self::User => 2,
            Self::Editor => 3,
            Self::Moderator => 4,
            Self::Admin => 5,
            Self::SuperAdmin => 6,
        }
    }
}

impl std::fmt::Display for PrivilegeTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Anonymous => "anonymous",
            Self::Guest => "guest",
            Self::User => "user",
            Self::Editor => "editor",
            Self::Moderator => "moderator",
            Self::Admin => "admin",
            Self::SuperAdmin => "super-admin",
        };
        write!(f, "{label}")
    }
}

/// Technique that enables an escalation transition.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EscalationTechnique {
    /// IDOR exploitation (swap object identifiers).
    IdorExploit { parameter: String },
    /// Missing function-level authorization check.
    BrokenFunctionAuth { endpoint: String },
    /// Mass assignment / parameter pollution.
    MassAssignment { field: String },
    /// Default or weak credentials.
    DefaultCredentials,
    /// JWT manipulation (none algorithm, claim tampering).
    JwtTampering { claim: String },
    /// Session fixation or hijacking.
    SessionManipulation,
    /// API key leakage in client-side code.
    ApiKeyLeakage,
    /// Role parameter injection in registration/profile.
    RoleInjection { parameter: String },
    /// GraphQL introspection revealing admin mutations.
    GraphQlIntrospectionAbuse,
    /// Implicit trust in default permissions.
    ImplicitTrust { permission: String },
}

impl std::fmt::Display for EscalationTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdorExploit { parameter } => write!(f, "idor-exploit({parameter})"),
            Self::BrokenFunctionAuth { endpoint } => {
                write!(f, "broken-function-auth({endpoint})")
            }
            Self::MassAssignment { field } => write!(f, "mass-assignment({field})"),
            Self::DefaultCredentials => write!(f, "default-credentials"),
            Self::JwtTampering { claim } => write!(f, "jwt-tampering({claim})"),
            Self::SessionManipulation => write!(f, "session-manipulation"),
            Self::ApiKeyLeakage => write!(f, "api-key-leakage"),
            Self::RoleInjection { parameter } => write!(f, "role-injection({parameter})"),
            Self::GraphQlIntrospectionAbuse => write!(f, "graphql-introspection-abuse"),
            Self::ImplicitTrust { permission } => write!(f, "implicit-trust({permission})"),
        }
    }
}

/// A role node in the privilege graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleNode {
    pub name: String,
    pub tier: PrivilegeTier,
    pub permissions: BTreeSet<String>,
    pub is_default: bool,
}

/// An edge in the privilege graph representing a possible escalation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EscalationEdge {
    pub technique: EscalationTechnique,
    pub difficulty: f64,
    pub confidence: f64,
    pub escalation_type: EscalationType,
    pub evidence: Option<String>,
}

/// A complete privilege escalation path from a source role to a target role.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EscalationPath {
    pub source_role: String,
    pub target_role: String,
    pub escalation_type: EscalationType,
    pub steps: Vec<EscalationStep>,
    pub total_difficulty: f64,
    pub min_confidence: f64,
}

impl EscalationPath {
    /// Number of hops in the escalation chain.
    pub fn hop_count(&self) -> usize {
        self.steps.len()
    }

    /// Composite risk = (1 - difficulty) * confidence. Higher means easier + more certain.
    pub fn risk_score(&self) -> f64 {
        if self.steps.is_empty() {
            return 0.0;
        }
        (1.0 - self.total_difficulty) * self.min_confidence
    }
}

/// A single step within an escalation path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EscalationStep {
    pub from_role: String,
    pub to_role: String,
    pub technique: EscalationTechnique,
    pub difficulty: f64,
    pub confidence: f64,
}

/// Findings imported from IDOR detector for integration.
#[derive(Debug, Clone)]
pub struct IdorFinding {
    pub endpoint: String,
    pub parameter: String,
    pub source_privilege: PrivilegeTier,
    pub target_privilege: PrivilegeTier,
    pub confidence: f64,
}

/// Findings imported from auth breaker / business logic tester.
#[derive(Debug, Clone)]
pub struct AuthBreakFinding {
    pub endpoint: String,
    pub technique: EscalationTechnique,
    pub source_role: String,
    pub target_role: String,
    pub confidence: f64,
}

/// Summary statistics from privilege escalation analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationSummary {
    pub total_roles: usize,
    pub total_edges: usize,
    pub total_paths: usize,
    pub paths_by_type: HashMap<String, usize>,
    pub highest_risk_path: Option<EscalationPath>,
    pub critical_roles: Vec<String>,
}

/// Graph-based privilege escalation path mapper.
///
/// Models roles and permissions as nodes, escalation techniques as edges,
/// then finds shortest/all paths between privilege levels.
pub struct PrivilegeEscalationMapper {
    graph: DiGraph<RoleNode, EscalationEdge>,
    role_indices: HashMap<String, NodeIndex>,
}

impl PrivilegeEscalationMapper {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            role_indices: HashMap::new(),
        }
    }

    /// Add a role to the privilege graph. Returns the role name for chaining.
    pub fn add_role(&mut self, role: RoleNode) -> String {
        let name = role.name.clone();
        if self.role_indices.contains_key(&name) {
            return name;
        }
        let idx = self.graph.add_node(role);
        self.role_indices.insert(name.clone(), idx);
        name
    }

    /// Add an escalation edge between two roles.
    pub fn add_escalation(&mut self, from_role: &str, to_role: &str, edge: EscalationEdge) -> bool {
        let Some(&from_idx) = self.role_indices.get(from_role) else {
            return false;
        };
        let Some(&to_idx) = self.role_indices.get(to_role) else {
            return false;
        };
        self.graph.add_edge(from_idx, to_idx, edge);
        true
    }

    /// Number of roles in the graph.
    pub fn role_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Number of escalation edges.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Retrieve a role node by name.
    pub fn role(&self, name: &str) -> Option<&RoleNode> {
        self.role_indices.get(name).map(|&idx| &self.graph[idx])
    }

    /// All role names in the graph.
    pub fn role_names(&self) -> Vec<String> {
        self.graph.node_weights().map(|n| n.name.clone()).collect()
    }

    /// Find the shortest escalation path from `source` to `target` using
    /// Dijkstra with difficulty as edge weight.
    pub fn shortest_path(&self, source: &str, target: &str) -> Option<EscalationPath> {
        let &src_idx = self.role_indices.get(source)?;
        let &tgt_idx = self.role_indices.get(target)?;

        let costs = dijkstra(&self.graph, src_idx, Some(tgt_idx), |e| {
            e.weight().difficulty
        });

        if !costs.contains_key(&tgt_idx) {
            return None;
        }

        let node_path = self.reconstruct_shortest(src_idx, tgt_idx)?;
        self.build_path_from_indices(&node_path)
    }

    /// Find ALL escalation paths from `source` to `target` (bounded DFS).
    pub fn all_paths(&self, source: &str, target: &str, max_depth: usize) -> Vec<EscalationPath> {
        let Some(&src_idx) = self.role_indices.get(source) else {
            return Vec::new();
        };
        let Some(&tgt_idx) = self.role_indices.get(target) else {
            return Vec::new();
        };

        let mut results = Vec::new();
        let mut current_path = vec![src_idx];
        let mut visited = HashSet::new();
        visited.insert(src_idx);

        self.dfs_all_paths(
            src_idx,
            tgt_idx,
            max_depth,
            &mut current_path,
            &mut visited,
            &mut results,
        );

        results
    }

    /// Find all roles reachable from a starting role.
    pub fn reachable_roles(&self, source: &str) -> Vec<String> {
        let Some(&src_idx) = self.role_indices.get(source) else {
            return Vec::new();
        };

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(src_idx);
        visited.insert(src_idx);

        while let Some(current) = queue.pop_front() {
            for neighbor in self.graph.neighbors_directed(current, Direction::Outgoing) {
                if visited.insert(neighbor) {
                    queue.push_back(neighbor);
                }
            }
        }

        visited
            .into_iter()
            .filter(|&idx| idx != src_idx)
            .map(|idx| self.graph[idx].name.clone())
            .collect()
    }

    /// Classify the escalation type between two roles based on their tiers.
    pub fn classify_escalation(&self, from_role: &str, to_role: &str) -> Option<EscalationType> {
        let from = self.role(from_role)?;
        let to = self.role(to_role)?;

        Some(classify_tiers(from.tier, to.tier))
    }

    /// Import IDOR findings to add data-level escalation edges.
    pub fn ingest_idor_findings(&mut self, findings: &[IdorFinding]) {
        for finding in findings {
            let source_name = tier_to_default_role(finding.source_privilege);
            let target_name = tier_to_default_role(finding.target_privilege);

            self.ensure_role_exists(&source_name, finding.source_privilege);
            self.ensure_role_exists(&target_name, finding.target_privilege);

            let escalation_type =
                classify_tiers(finding.source_privilege, finding.target_privilege);
            let edge = EscalationEdge {
                technique: EscalationTechnique::IdorExploit {
                    parameter: finding.parameter.clone(),
                },
                difficulty: 1.0 - finding.confidence,
                confidence: finding.confidence,
                escalation_type,
                evidence: Some(format!("IDOR on {}", finding.endpoint)),
            };
            self.add_escalation(&source_name, &target_name, edge);
        }
    }

    /// Import auth breaker / business-logic-tester findings.
    pub fn ingest_auth_findings(&mut self, findings: &[AuthBreakFinding]) {
        for finding in findings {
            if !self.role_indices.contains_key(&finding.source_role) {
                continue;
            }
            if !self.role_indices.contains_key(&finding.target_role) {
                continue;
            }

            let source_tier = self.role(&finding.source_role).map(|r| r.tier);
            let target_tier = self.role(&finding.target_role).map(|r| r.tier);
            let escalation_type = match (source_tier, target_tier) {
                (Some(s), Some(t)) => classify_tiers(s, t),
                _ => EscalationType::FunctionLevel,
            };

            let edge = EscalationEdge {
                technique: finding.technique.clone(),
                difficulty: 1.0 - finding.confidence,
                confidence: finding.confidence,
                escalation_type,
                evidence: Some(format!("Auth break on {}", finding.endpoint)),
            };
            self.add_escalation(&finding.source_role, &finding.target_role, edge);
        }
    }

    /// Detect implicit escalation paths from default permissions.
    pub fn detect_implicit_escalations(&mut self) {
        let role_data: Vec<(String, PrivilegeTier, BTreeSet<String>, bool)> = self
            .graph
            .node_weights()
            .map(|n| (n.name.clone(), n.tier, n.permissions.clone(), n.is_default))
            .collect();

        for (name, tier, permissions, is_default) in &role_data {
            if !is_default {
                continue;
            }
            for (other_name, other_tier, other_permissions, _) in &role_data {
                if name == other_name {
                    continue;
                }
                if tier >= other_tier {
                    continue;
                }
                let shared: Vec<&String> = permissions.intersection(other_permissions).collect();

                let overlap_ratio = if other_permissions.is_empty() {
                    0.0
                } else {
                    shared.len() as f64 / other_permissions.len() as f64
                };

                if overlap_ratio > 0.3 {
                    let edge = EscalationEdge {
                        technique: EscalationTechnique::ImplicitTrust {
                            permission: shared
                                .iter()
                                .take(3)
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                        },
                        difficulty: 0.2,
                        confidence: overlap_ratio.min(1.0),
                        escalation_type: EscalationType::Implicit,
                        evidence: Some(format!(
                            "Default role '{}' shares {:.0}% permissions with '{}'",
                            name,
                            overlap_ratio * 100.0,
                            other_name
                        )),
                    };
                    self.add_escalation(name, other_name, edge);
                }
            }
        }
    }

    /// Identify critical roles: roles that appear as targets in the most escalation paths.
    pub fn critical_roles(&self, max_depth: usize) -> Vec<(String, usize)> {
        let mut target_counts: HashMap<String, usize> = HashMap::new();

        let role_names: Vec<String> = self.role_names();
        for source in &role_names {
            for target in &role_names {
                if source == target {
                    continue;
                }
                let paths = self.all_paths(source, target, max_depth);
                if !paths.is_empty() {
                    *target_counts.entry(target.clone()).or_insert(0) += paths.len();
                }
            }
        }

        let mut sorted: Vec<(String, usize)> = target_counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted
    }

    /// Produce a full summary of escalation analysis.
    pub fn summarize(&self, max_depth: usize) -> EscalationSummary {
        let mut all_paths = Vec::new();
        let role_names: Vec<String> = self.role_names();

        for source in &role_names {
            for target in &role_names {
                if source == target {
                    continue;
                }
                let paths = self.all_paths(source, target, max_depth);
                all_paths.extend(paths);
            }
        }

        let mut paths_by_type: HashMap<String, usize> = HashMap::new();
        for path in &all_paths {
            *paths_by_type
                .entry(path.escalation_type.to_string())
                .or_insert(0) += 1;
        }

        let highest_risk_path = all_paths
            .iter()
            .max_by(|a, b| {
                a.risk_score()
                    .partial_cmp(&b.risk_score())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .cloned();

        let critical = self.critical_roles(max_depth);
        let critical_roles: Vec<String> = critical.into_iter().map(|(name, _)| name).collect();

        EscalationSummary {
            total_roles: self.role_count(),
            total_edges: self.edge_count(),
            total_paths: all_paths.len(),
            paths_by_type,
            highest_risk_path,
            critical_roles,
        }
    }

    /// Roles with outgoing escalation edges (can escalate somewhere).
    pub fn roles_with_escalation_potential(&self) -> Vec<String> {
        self.graph
            .node_indices()
            .filter(|&idx| {
                self.graph
                    .edges_directed(idx, Direction::Outgoing)
                    .next()
                    .is_some()
            })
            .map(|idx| self.graph[idx].name.clone())
            .collect()
    }

    /// Direct escalation targets from a specific role.
    pub fn direct_targets(&self, role: &str) -> Vec<(String, EscalationType)> {
        let Some(&idx) = self.role_indices.get(role) else {
            return Vec::new();
        };

        self.graph
            .edges_directed(idx, Direction::Outgoing)
            .map(|e| {
                let target = &self.graph[e.target()];
                (target.name.clone(), e.weight().escalation_type)
            })
            .collect()
    }

    /// Inner petgraph for external analysis.
    pub fn inner_graph(&self) -> &DiGraph<RoleNode, EscalationEdge> {
        &self.graph
    }

    fn ensure_role_exists(&mut self, name: &str, tier: PrivilegeTier) {
        if !self.role_indices.contains_key(name) {
            self.add_role(RoleNode {
                name: name.to_string(),
                tier,
                permissions: BTreeSet::new(),
                is_default: false,
            });
        }
    }

    /// Reconstruct the shortest path between two nodes using BFS on the
    /// cost map produced by dijkstra. We trace backwards from target.
    fn reconstruct_shortest(&self, src: NodeIndex, tgt: NodeIndex) -> Option<Vec<NodeIndex>> {
        let costs = dijkstra(&self.graph, src, Some(tgt), |e| e.weight().difficulty);

        if !costs.contains_key(&tgt) {
            return None;
        }

        let mut path = vec![tgt];
        let mut current = tgt;

        while current != src {
            let mut best_prev: Option<(NodeIndex, f64)> = None;

            for edge in self.graph.edges_directed(current, Direction::Incoming) {
                let prev = edge.source();
                if let Some(&prev_cost) = costs.get(&prev) {
                    let edge_cost = edge.weight().difficulty;
                    let expected = prev_cost + edge_cost;
                    let current_cost = costs[&current];
                    if (expected - current_cost).abs() < 1e-9 {
                        match best_prev {
                            None => best_prev = Some((prev, prev_cost)),
                            Some((_, bc)) if prev_cost < bc => {
                                best_prev = Some((prev, prev_cost));
                            }
                            _ => {}
                        }
                    }
                }
            }

            let (prev_node, _) = best_prev?;
            path.push(prev_node);
            current = prev_node;
        }

        path.reverse();
        Some(path)
    }

    fn build_path_from_indices(&self, node_path: &[NodeIndex]) -> Option<EscalationPath> {
        if node_path.len() < 2 {
            return None;
        }

        let mut steps = Vec::new();
        let mut total_difficulty = 0.0;
        let mut min_confidence = f64::INFINITY;

        for window in node_path.windows(2) {
            let from_idx = window[0];
            let to_idx = window[1];

            let best_edge = self
                .graph
                .edges_directed(from_idx, Direction::Outgoing)
                .filter(|e| e.target() == to_idx)
                .min_by(|a, b| {
                    a.weight()
                        .difficulty
                        .partial_cmp(&b.weight().difficulty)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })?;

            let w = best_edge.weight();
            total_difficulty += w.difficulty;
            if w.confidence < min_confidence {
                min_confidence = w.confidence;
            }

            steps.push(EscalationStep {
                from_role: self.graph[from_idx].name.clone(),
                to_role: self.graph[to_idx].name.clone(),
                technique: w.technique.clone(),
                difficulty: w.difficulty,
                confidence: w.confidence,
            });
        }

        let source_tier = self.graph[node_path[0]].tier;
        let target_tier = self.graph[*node_path.last().unwrap()].tier;
        let escalation_type = classify_tiers(source_tier, target_tier);

        Some(EscalationPath {
            source_role: self.graph[node_path[0]].name.clone(),
            target_role: self.graph[*node_path.last().unwrap()].name.clone(),
            escalation_type,
            steps,
            total_difficulty,
            min_confidence,
        })
    }

    fn dfs_all_paths(
        &self,
        current: NodeIndex,
        target: NodeIndex,
        max_depth: usize,
        path: &mut Vec<NodeIndex>,
        visited: &mut HashSet<NodeIndex>,
        results: &mut Vec<EscalationPath>,
    ) {
        if current == target && path.len() > 1 {
            if let Some(escalation_path) = self.build_path_from_indices(path) {
                results.push(escalation_path);
            }
            return;
        }

        if path.len() > max_depth {
            return;
        }

        for edge in self.graph.edges_directed(current, Direction::Outgoing) {
            let next = edge.target();
            if visited.contains(&next) && next != target {
                continue;
            }

            let was_new = visited.insert(next);
            path.push(next);
            self.dfs_all_paths(next, target, max_depth, path, visited, results);
            path.pop();
            if was_new {
                visited.remove(&next);
            }
        }
    }
}

impl Default for PrivilegeEscalationMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Classify escalation type from source and target tiers.
fn classify_tiers(source: PrivilegeTier, target: PrivilegeTier) -> EscalationType {
    let src_rank = source.numeric_rank();
    let tgt_rank = target.numeric_rank();

    if src_rank < tgt_rank {
        if tgt_rank - src_rank == 1 {
            EscalationType::RoleBased
        } else {
            EscalationType::Vertical
        }
    } else if src_rank == tgt_rank {
        EscalationType::Horizontal
    } else {
        EscalationType::DataLevel
    }
}

/// Map a privilege tier to its default role name string.
fn tier_to_default_role(tier: PrivilegeTier) -> String {
    match tier {
        PrivilegeTier::Anonymous => "anonymous".to_string(),
        PrivilegeTier::Guest => "guest".to_string(),
        PrivilegeTier::User => "user".to_string(),
        PrivilegeTier::Editor => "editor".to_string(),
        PrivilegeTier::Moderator => "moderator".to_string(),
        PrivilegeTier::Admin => "admin".to_string(),
        PrivilegeTier::SuperAdmin => "super-admin".to_string(),
    }
}

/// Build a standard 7-role hierarchy for testing or bootstrapping.
pub fn build_standard_role_hierarchy() -> PrivilegeEscalationMapper {
    let mut mapper = PrivilegeEscalationMapper::new();

    let anon_perms: BTreeSet<String> = ["read:public"].iter().map(|s| s.to_string()).collect();
    let guest_perms: BTreeSet<String> = ["read:public", "read:preview"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let user_perms: BTreeSet<String> = ["read:public", "read:own", "write:own", "read:preview"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let editor_perms: BTreeSet<String> = [
        "read:public",
        "read:own",
        "write:own",
        "read:others",
        "write:others",
        "read:preview",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let mod_perms: BTreeSet<String> = [
        "read:public",
        "read:own",
        "write:own",
        "read:others",
        "write:others",
        "delete:others",
        "ban:user",
        "read:preview",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let admin_perms: BTreeSet<String> = [
        "read:public",
        "read:own",
        "write:own",
        "read:others",
        "write:others",
        "delete:others",
        "ban:user",
        "manage:roles",
        "manage:config",
        "read:preview",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let super_perms: BTreeSet<String> = [
        "read:public",
        "read:own",
        "write:own",
        "read:others",
        "write:others",
        "delete:others",
        "ban:user",
        "manage:roles",
        "manage:config",
        "manage:billing",
        "manage:infrastructure",
        "read:preview",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    mapper.add_role(RoleNode {
        name: "anonymous".to_string(),
        tier: PrivilegeTier::Anonymous,
        permissions: anon_perms,
        is_default: true,
    });
    mapper.add_role(RoleNode {
        name: "guest".to_string(),
        tier: PrivilegeTier::Guest,
        permissions: guest_perms,
        is_default: true,
    });
    mapper.add_role(RoleNode {
        name: "user".to_string(),
        tier: PrivilegeTier::User,
        permissions: user_perms,
        is_default: false,
    });
    mapper.add_role(RoleNode {
        name: "editor".to_string(),
        tier: PrivilegeTier::Editor,
        permissions: editor_perms,
        is_default: false,
    });
    mapper.add_role(RoleNode {
        name: "moderator".to_string(),
        tier: PrivilegeTier::Moderator,
        permissions: mod_perms,
        is_default: false,
    });
    mapper.add_role(RoleNode {
        name: "admin".to_string(),
        tier: PrivilegeTier::Admin,
        permissions: admin_perms,
        is_default: false,
    });
    mapper.add_role(RoleNode {
        name: "super-admin".to_string(),
        tier: PrivilegeTier::SuperAdmin,
        permissions: super_perms,
        is_default: false,
    });

    mapper
}
