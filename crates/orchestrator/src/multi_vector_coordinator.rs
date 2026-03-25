/// Multi-vector attack coordinator: AI planning layer over the attack graph.
///
/// Identifies and plans compound attack paths (e.g. SSRF→internal endpoint→deser→JWT→admin).
/// Maintains a goal stack (initial access→lateral→privesc→objective) and dynamically
/// re-plans when a path is blocked, redistributing effort across alternative routes
/// using centrality scores from the chain-synthesis attack graph.
use aegis_protocol::finding::{EvidenceLevel, VulnerabilityClass};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Strategic goal in the attack kill chain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackGoal {
    InitialAccess,
    Foothold,
    LateralMovement,
    PrivilegeEscalation,
    DataExfiltration,
    PersistentAccess,
    DenialOfService,
    Custom(String),
}

/// Status of a goal in the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GoalStatus {
    Pending,
    InProgress,
    Achieved,
    Blocked,
    Skipped,
}

/// A goal with its current status and supporting attack vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalEntry {
    pub goal: AttackGoal,
    pub status: GoalStatus,
    pub assigned_vector: Option<String>,
    pub blocking_reason: Option<String>,
    pub achieved_via: Option<String>,
}

/// A node in the attack graph representing an exploitable point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackNode {
    pub id: String,
    pub endpoint: String,
    pub vulnerability_class: VulnerabilityClass,
    pub evidence_level: EvidenceLevel,
    pub confidence: f64,
    pub difficulty: f64,
    pub requires_auth: bool,
    pub centrality_score: f64,
}

/// A directed edge between attack nodes representing chaining capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEdge {
    pub source_id: String,
    pub target_id: String,
    pub chain_type: ChainType,
    pub feasibility: f64,
    pub description: String,
}

/// How two attack nodes chain together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainType {
    DataFlow,
    CredentialReuse,
    PrivilegeChain,
    NetworkPivot,
    SessionHijack,
    OutputAsInput,
}

/// A compound attack path through the graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub id: String,
    pub nodes: Vec<String>,
    pub edges: Vec<AttackEdge>,
    pub total_difficulty: f64,
    pub estimated_success_probability: f64,
    pub goals_achieved: Vec<AttackGoal>,
    pub description: String,
}

/// Result of a re-planning operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanResult {
    pub active_paths: Vec<AttackPath>,
    pub blocked_paths: Vec<AttackPath>,
    pub goal_stack: Vec<GoalEntry>,
    pub reasoning: Vec<String>,
    pub recommended_next_action: Option<NextAction>,
}

/// Recommended next action from the coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextAction {
    pub action_type: ActionType,
    pub target_node: String,
    pub rationale: String,
    pub priority: f64,
}

/// Type of recommended action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    Exploit,
    Enumerate,
    Pivot,
    EscalatePrivilege,
    Exfiltrate,
    Persist,
    Abort,
}

/// The coordinator state.
pub struct MultiVectorCoordinator {
    nodes: HashMap<String, AttackNode>,
    edges: Vec<AttackEdge>,
    goal_stack: Vec<GoalEntry>,
    blocked_nodes: HashSet<String>,
    achieved_goals: HashSet<AttackGoal>,
    plan_generation: u32,
}

impl MultiVectorCoordinator {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            goal_stack: default_goal_stack(),
            blocked_nodes: HashSet::new(),
            achieved_goals: HashSet::new(),
            plan_generation: 0,
        }
    }

    pub fn with_goals(mut self, goals: Vec<AttackGoal>) -> Self {
        self.goal_stack = goals
            .into_iter()
            .map(|g| GoalEntry {
                goal: g,
                status: GoalStatus::Pending,
                assigned_vector: None,
                blocking_reason: None,
                achieved_via: None,
            })
            .collect();
        self
    }

    pub fn add_node(&mut self, node: AttackNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    pub fn add_edge(&mut self, edge: AttackEdge) {
        self.edges.push(edge);
    }

    pub fn mark_blocked(&mut self, node_id: &str, reason: &str) {
        self.blocked_nodes.insert(node_id.to_string());
        for entry in &mut self.goal_stack {
            if entry.assigned_vector.as_deref() == Some(node_id) {
                entry.status = GoalStatus::Blocked;
                entry.blocking_reason = Some(reason.to_string());
            }
        }
    }

    pub fn mark_achieved(&mut self, goal: &AttackGoal, via: &str) {
        self.achieved_goals.insert(goal.clone());
        for entry in &mut self.goal_stack {
            if &entry.goal == goal {
                entry.status = GoalStatus::Achieved;
                entry.achieved_via = Some(via.to_string());
            }
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn goal_stack(&self) -> &[GoalEntry] {
        &self.goal_stack
    }

    /// Find all paths from any initial-access node to nodes satisfying a goal.
    pub fn find_attack_paths(&self, max_depth: usize) -> Vec<AttackPath> {
        let mut paths = Vec::new();
        let adjacency = self.build_adjacency();

        let entry_nodes: Vec<&AttackNode> = self
            .nodes
            .values()
            .filter(|n| !n.requires_auth && !self.blocked_nodes.contains(&n.id))
            .collect();

        for entry in &entry_nodes {
            let discovered = self.bfs_paths(&entry.id, max_depth, &adjacency);
            for node_ids in discovered {
                if node_ids.len() < 2 {
                    continue;
                }
                let path_edges: Vec<AttackEdge> = node_ids
                    .windows(2)
                    .filter_map(|w| {
                        self.edges
                            .iter()
                            .find(|e| e.source_id == w[0] && e.target_id == w[1])
                            .cloned()
                    })
                    .collect();

                let total_difficulty: f64 = node_ids
                    .iter()
                    .filter_map(|id| self.nodes.get(id))
                    .map(|n| n.difficulty)
                    .sum();

                let success_prob = node_ids
                    .iter()
                    .filter_map(|id| self.nodes.get(id))
                    .map(|n| n.confidence)
                    .product::<f64>();

                let goals_achieved = infer_goals_from_path(&node_ids, &self.nodes);

                let description = node_ids
                    .iter()
                    .filter_map(|id| self.nodes.get(id))
                    .map(|n| format!("{}({})", n.vulnerability_class, n.endpoint))
                    .collect::<Vec<_>>()
                    .join(" → ");

                paths.push(AttackPath {
                    id: format!("path-{:03}", paths.len() + 1),
                    nodes: node_ids,
                    edges: path_edges,
                    total_difficulty,
                    estimated_success_probability: success_prob,
                    goals_achieved,
                    description,
                });
            }
        }

        paths.sort_by(|a, b| {
            b.estimated_success_probability
                .partial_cmp(&a.estimated_success_probability)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        paths
    }

    /// Replan after observing blocked paths or achieved goals.
    pub fn replan(&mut self) -> PlanResult {
        self.plan_generation += 1;
        let mut reasoning = Vec::new();

        reasoning.push(format!(
            "Plan generation {}: {} nodes, {} edges, {} blocked",
            self.plan_generation,
            self.nodes.len(),
            self.edges.len(),
            self.blocked_nodes.len()
        ));

        let all_paths = self.find_attack_paths(6);

        let (active, blocked): (Vec<AttackPath>, Vec<AttackPath>) = all_paths
            .into_iter()
            .partition(|p| !p.nodes.iter().any(|n| self.blocked_nodes.contains(n)));

        reasoning.push(format!(
            "Found {} active paths, {} blocked paths",
            active.len(),
            blocked.len()
        ));

        let next_goal = self
            .goal_stack
            .iter()
            .find(|g| g.status == GoalStatus::Pending || g.status == GoalStatus::Blocked);

        let recommended = if let Some(goal_entry) = next_goal {
            let matching_path = active
                .iter()
                .find(|p| p.goals_achieved.contains(&goal_entry.goal));

            if let Some(path) = matching_path {
                let next_node_id = path
                    .nodes
                    .iter()
                    .find(|n| !self.blocked_nodes.contains(*n))
                    .cloned();

                next_node_id.map(|node_id| {
                    let action_type = match &goal_entry.goal {
                        AttackGoal::InitialAccess => ActionType::Exploit,
                        AttackGoal::Foothold => ActionType::Exploit,
                        AttackGoal::LateralMovement => ActionType::Pivot,
                        AttackGoal::PrivilegeEscalation => ActionType::EscalatePrivilege,
                        AttackGoal::DataExfiltration => ActionType::Exfiltrate,
                        AttackGoal::PersistentAccess => ActionType::Persist,
                        AttackGoal::DenialOfService => ActionType::Exploit,
                        AttackGoal::Custom(_) => ActionType::Exploit,
                    };

                    reasoning.push(format!(
                        "Recommending {:?} on {} to achieve {:?}",
                        action_type, node_id, goal_entry.goal
                    ));

                    NextAction {
                        action_type,
                        target_node: node_id,
                        rationale: format!(
                            "Highest-probability path to {:?} goal",
                            goal_entry.goal
                        ),
                        priority: path.estimated_success_probability,
                    }
                })
            } else {
                reasoning.push(format!(
                    "No active path found for {:?} — goal blocked",
                    goal_entry.goal
                ));
                None
            }
        } else {
            reasoning.push("All goals achieved or skipped".to_string());
            None
        };

        for entry in &mut self.goal_stack {
            if entry.status == GoalStatus::Pending {
                let has_path = active
                    .iter()
                    .any(|p| p.goals_achieved.contains(&entry.goal));
                if !has_path && !blocked.is_empty() {
                    entry.status = GoalStatus::Blocked;
                    entry.blocking_reason =
                        Some("No viable path found after re-planning".to_string());
                }
            }
        }

        PlanResult {
            active_paths: active,
            blocked_paths: blocked,
            goal_stack: self.goal_stack.clone(),
            reasoning,
            recommended_next_action: recommended,
        }
    }

    fn build_adjacency(&self) -> HashMap<String, Vec<String>> {
        let mut adj: HashMap<String, Vec<String>> = HashMap::new();
        for edge in &self.edges {
            if !self.blocked_nodes.contains(&edge.source_id)
                && !self.blocked_nodes.contains(&edge.target_id)
            {
                adj.entry(edge.source_id.clone())
                    .or_default()
                    .push(edge.target_id.clone());
            }
        }
        adj
    }

    fn bfs_paths(
        &self,
        start: &str,
        max_depth: usize,
        adjacency: &HashMap<String, Vec<String>>,
    ) -> Vec<Vec<String>> {
        let mut result = Vec::new();
        let mut queue: VecDeque<(Vec<String>, usize)> = VecDeque::new();
        queue.push_back((vec![start.to_string()], 0));

        while let Some((path, depth)) = queue.pop_front() {
            if depth >= max_depth {
                if path.len() >= 2 {
                    result.push(path);
                }
                continue;
            }

            let current = path.last().unwrap();
            let neighbors = adjacency.get(current);

            match neighbors {
                Some(nbrs) if !nbrs.is_empty() => {
                    let mut extended = false;
                    for nbr in nbrs {
                        if !path.contains(nbr) {
                            let mut new_path = path.clone();
                            new_path.push(nbr.clone());
                            queue.push_back((new_path, depth + 1));
                            extended = true;
                        }
                    }
                    if !extended && path.len() >= 2 {
                        result.push(path);
                    }
                }
                _ => {
                    if path.len() >= 2 {
                        result.push(path);
                    }
                }
            }

            if result.len() >= 100 {
                break;
            }
        }

        result
    }
}

fn default_goal_stack() -> Vec<GoalEntry> {
    vec![
        GoalEntry {
            goal: AttackGoal::InitialAccess,
            status: GoalStatus::Pending,
            assigned_vector: None,
            blocking_reason: None,
            achieved_via: None,
        },
        GoalEntry {
            goal: AttackGoal::Foothold,
            status: GoalStatus::Pending,
            assigned_vector: None,
            blocking_reason: None,
            achieved_via: None,
        },
        GoalEntry {
            goal: AttackGoal::LateralMovement,
            status: GoalStatus::Pending,
            assigned_vector: None,
            blocking_reason: None,
            achieved_via: None,
        },
        GoalEntry {
            goal: AttackGoal::PrivilegeEscalation,
            status: GoalStatus::Pending,
            assigned_vector: None,
            blocking_reason: None,
            achieved_via: None,
        },
        GoalEntry {
            goal: AttackGoal::DataExfiltration,
            status: GoalStatus::Pending,
            assigned_vector: None,
            blocking_reason: None,
            achieved_via: None,
        },
    ]
}

fn infer_goals_from_path(
    node_ids: &[String],
    nodes: &HashMap<String, AttackNode>,
) -> Vec<AttackGoal> {
    let mut goals = Vec::new();
    let classes: Vec<VulnerabilityClass> = node_ids
        .iter()
        .filter_map(|id| nodes.get(id))
        .map(|n| n.vulnerability_class)
        .collect();

    if !classes.is_empty() {
        goals.push(AttackGoal::InitialAccess);
    }

    if classes.len() >= 2 {
        goals.push(AttackGoal::Foothold);
    }

    if classes.contains(&VulnerabilityClass::ServerSideRequestForgery)
        || classes.contains(&VulnerabilityClass::InsecureDirectObjectReference)
    {
        goals.push(AttackGoal::LateralMovement);
    }

    if classes.contains(&VulnerabilityClass::BrokenAuthentication)
        || classes.contains(&VulnerabilityClass::BrokenAuthorization)
        || classes.contains(&VulnerabilityClass::JwtVulnerability)
    {
        goals.push(AttackGoal::PrivilegeEscalation);
    }

    if classes.contains(&VulnerabilityClass::SqlInjection)
        || classes.contains(&VulnerabilityClass::SensitiveDataExposure)
        || classes.contains(&VulnerabilityClass::PathTraversal)
    {
        goals.push(AttackGoal::DataExfiltration);
    }

    goals
}

/// Utility: rank nodes by centrality score.
pub fn nodes_by_centrality(coordinator: &MultiVectorCoordinator) -> Vec<&AttackNode> {
    let mut nodes: Vec<&AttackNode> = coordinator.nodes.values().collect();
    nodes.sort_by(|a, b| {
        b.centrality_score
            .partial_cmp(&a.centrality_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    nodes
}
