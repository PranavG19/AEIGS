/// Scan Campaign Manager v2 — multi-target campaigns with dependency management,
/// coordinated simultaneous hits, pause/resume state, per-target progress tracking,
/// operator deconfliction.
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

/// Unique campaign identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CampaignId(pub String);

impl std::fmt::Display for CampaignId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Campaign lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CampaignState {
    Planning,
    Active,
    Paused,
    Completed,
    Aborted,
}

impl std::fmt::Display for CampaignState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Planning => write!(f, "planning"),
            Self::Active => write!(f, "active"),
            Self::Paused => write!(f, "paused"),
            Self::Completed => write!(f, "completed"),
            Self::Aborted => write!(f, "aborted"),
        }
    }
}

/// Per-target scan progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetProgress {
    Queued,
    Recon,
    Crawling,
    Fuzzing,
    Exploiting,
    Reporting,
    Done,
    Failed,
    Skipped,
}

impl TargetProgress {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Done | Self::Failed | Self::Skipped)
    }

    pub fn completion_pct(&self) -> u8 {
        match self {
            Self::Queued => 0,
            Self::Recon => 15,
            Self::Crawling => 30,
            Self::Fuzzing => 50,
            Self::Exploiting => 70,
            Self::Reporting => 90,
            Self::Done => 100,
            Self::Failed => 100,
            Self::Skipped => 100,
        }
    }
}

/// A target within a campaign.
#[derive(Debug, Clone)]
pub struct CampaignTarget {
    pub target_id: String,
    pub url: String,
    pub progress: TargetProgress,
    pub assigned_operator: Option<String>,
    pub findings_count: u32,
    pub started_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub error_message: Option<String>,
    pub dependencies: Vec<String>,
    pub priority: u8,
}

impl CampaignTarget {
    pub fn new(target_id: String, url: String, priority: u8) -> Self {
        Self {
            target_id,
            url,
            progress: TargetProgress::Queued,
            assigned_operator: None,
            findings_count: 0,
            started_at: None,
            completed_at: None,
            error_message: None,
            dependencies: Vec::new(),
            priority,
        }
    }

    pub fn with_dependency(mut self, dep: String) -> Self {
        self.dependencies.push(dep);
        self
    }
}

/// Dependency graph for campaign targets.
#[derive(Debug)]
pub struct DependencyGraph {
    edges: HashMap<String, Vec<String>>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self {
            edges: HashMap::new(),
        }
    }

    pub fn add_dependency(&mut self, target: &str, depends_on: &str) {
        self.edges
            .entry(target.to_string())
            .or_default()
            .push(depends_on.to_string());
    }

    pub fn dependencies_of(&self, target: &str) -> Vec<&str> {
        self.edges
            .get(target)
            .map(|deps| deps.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    pub fn is_ready(&self, target: &str, completed: &HashSet<String>) -> bool {
        self.dependencies_of(target)
            .iter()
            .all(|dep| completed.contains(*dep))
    }

    pub fn topological_order(&self, all_targets: &[String]) -> Vec<String> {
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        for t in all_targets {
            in_degree.entry(t.as_str()).or_insert(0);
        }
        for (target, deps) in &self.edges {
            if all_targets.iter().any(|t| t == target) {
                for dep in deps {
                    if all_targets.iter().any(|t| t == dep) {
                        *in_degree.entry(target.as_str()).or_insert(0) += 1;
                    }
                }
            }
        }
        let mut queue: VecDeque<String> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&t, _)| t.to_string())
            .collect();
        let mut result = Vec::new();
        while let Some(node) = queue.pop_front() {
            result.push(node.clone());
            for (target, deps) in &self.edges {
                if deps.contains(&node) {
                    if let Some(deg) = in_degree.get_mut(target.as_str()) {
                        *deg = deg.saturating_sub(1);
                        if *deg == 0 {
                            queue.push_back(target.clone());
                        }
                    }
                }
            }
        }
        result
    }
}

impl Default for DependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Coordinated simultaneous hit configuration.
#[derive(Debug, Clone)]
pub struct SimultaneousHitConfig {
    pub enabled: bool,
    pub target_ids: Vec<String>,
    pub sync_phase: TargetProgress,
    pub max_time_skew_ms: u64,
}

/// Operator deconfliction — tracks which operator is working on which target.
#[derive(Debug)]
pub struct OperatorDeconfliction {
    assignments: HashMap<String, String>,
}

impl OperatorDeconfliction {
    pub fn new() -> Self {
        Self {
            assignments: HashMap::new(),
        }
    }

    pub fn assign(&mut self, target_id: &str, operator: &str) -> Result<(), String> {
        if let Some(existing) = self.assignments.get(target_id) {
            if existing != operator {
                return Err(format!(
                    "target {} already assigned to {}",
                    target_id, existing
                ));
            }
        }
        self.assignments
            .insert(target_id.to_string(), operator.to_string());
        Ok(())
    }

    pub fn release(&mut self, target_id: &str) {
        self.assignments.remove(target_id);
    }

    pub fn assigned_to(&self, target_id: &str) -> Option<&str> {
        self.assignments.get(target_id).map(|s| s.as_str())
    }

    pub fn targets_for_operator(&self, operator: &str) -> Vec<String> {
        self.assignments
            .iter()
            .filter(|(_, op)| op.as_str() == operator)
            .map(|(t, _)| t.clone())
            .collect()
    }
}

impl Default for OperatorDeconfliction {
    fn default() -> Self {
        Self::new()
    }
}

/// Campaign statistics.
#[derive(Debug, Clone)]
pub struct CampaignStats {
    pub total_targets: usize,
    pub completed: usize,
    pub failed: usize,
    pub in_progress: usize,
    pub queued: usize,
    pub total_findings: u32,
    pub overall_progress_pct: f64,
}

/// Top-level campaign manager.
#[derive(Debug)]
pub struct CampaignManagerV2 {
    pub campaigns: HashMap<CampaignId, Campaign>,
}

/// A single campaign with all its state.
#[derive(Debug)]
pub struct Campaign {
    pub id: CampaignId,
    pub name: String,
    pub state: CampaignState,
    pub targets: Vec<CampaignTarget>,
    pub deps: DependencyGraph,
    pub deconfliction: OperatorDeconfliction,
    pub simultaneous_hits: Vec<SimultaneousHitConfig>,
    pub created_at: u64,
    pub paused_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub max_concurrent: usize,
}

impl Campaign {
    pub fn new(id: CampaignId, name: String, max_concurrent: usize) -> Self {
        Self {
            id,
            name,
            state: CampaignState::Planning,
            targets: Vec::new(),
            deps: DependencyGraph::new(),
            deconfliction: OperatorDeconfliction::new(),
            simultaneous_hits: Vec::new(),
            created_at: now_ms(),
            paused_at: None,
            completed_at: None,
            max_concurrent,
        }
    }

    pub fn add_target(&mut self, target: CampaignTarget) {
        for dep in &target.dependencies {
            self.deps.add_dependency(&target.target_id, dep);
        }
        self.targets.push(target);
    }

    pub fn start(&mut self) -> Result<(), String> {
        if self.state != CampaignState::Planning {
            return Err(format!("cannot start from state {}", self.state));
        }
        self.state = CampaignState::Active;
        Ok(())
    }

    pub fn pause(&mut self) -> Result<(), String> {
        if self.state != CampaignState::Active {
            return Err(format!("cannot pause from state {}", self.state));
        }
        self.state = CampaignState::Paused;
        self.paused_at = Some(now_ms());
        Ok(())
    }

    pub fn resume(&mut self) -> Result<(), String> {
        if self.state != CampaignState::Paused {
            return Err(format!("cannot resume from state {}", self.state));
        }
        self.state = CampaignState::Active;
        Ok(())
    }

    pub fn abort(&mut self) {
        self.state = CampaignState::Aborted;
        self.completed_at = Some(now_ms());
    }

    pub fn advance_target(
        &mut self,
        target_id: &str,
        new_progress: TargetProgress,
    ) -> Result<(), String> {
        let target = self
            .targets
            .iter_mut()
            .find(|t| t.target_id == target_id)
            .ok_or("target not found")?;
        target.progress = new_progress;
        if new_progress == TargetProgress::Recon && target.started_at.is_none() {
            target.started_at = Some(now_ms());
        }
        if new_progress.is_terminal() {
            target.completed_at = Some(now_ms());
        }
        if self.targets.iter().all(|t| t.progress.is_terminal()) {
            self.state = CampaignState::Completed;
            self.completed_at = Some(now_ms());
        }
        Ok(())
    }

    pub fn record_finding(&mut self, target_id: &str) -> Result<(), String> {
        let target = self
            .targets
            .iter_mut()
            .find(|t| t.target_id == target_id)
            .ok_or("target not found")?;
        target.findings_count += 1;
        Ok(())
    }

    pub fn ready_targets(&self) -> Vec<&CampaignTarget> {
        let completed: HashSet<String> = self
            .targets
            .iter()
            .filter(|t| t.progress.is_terminal())
            .map(|t| t.target_id.clone())
            .collect();
        let active_count = self
            .targets
            .iter()
            .filter(|t| !t.progress.is_terminal() && t.progress != TargetProgress::Queued)
            .count();
        let slots = self.max_concurrent.saturating_sub(active_count);
        self.targets
            .iter()
            .filter(|t| {
                t.progress == TargetProgress::Queued && self.deps.is_ready(&t.target_id, &completed)
            })
            .take(slots)
            .collect()
    }

    pub fn stats(&self) -> CampaignStats {
        let total = self.targets.len();
        let completed = self
            .targets
            .iter()
            .filter(|t| t.progress == TargetProgress::Done)
            .count();
        let failed = self
            .targets
            .iter()
            .filter(|t| t.progress == TargetProgress::Failed)
            .count();
        let queued = self
            .targets
            .iter()
            .filter(|t| t.progress == TargetProgress::Queued)
            .count();
        let in_progress = total
            - completed
            - failed
            - queued
            - self
                .targets
                .iter()
                .filter(|t| t.progress == TargetProgress::Skipped)
                .count();
        let total_findings: u32 = self.targets.iter().map(|t| t.findings_count).sum();
        let overall_pct = if total == 0 {
            0.0
        } else {
            self.targets
                .iter()
                .map(|t| t.progress.completion_pct() as f64)
                .sum::<f64>()
                / total as f64
        };
        CampaignStats {
            total_targets: total,
            completed,
            failed,
            in_progress,
            queued,
            total_findings,
            overall_progress_pct: overall_pct,
        }
    }
}

impl CampaignManagerV2 {
    pub fn new() -> Self {
        Self {
            campaigns: HashMap::new(),
        }
    }

    pub fn create_campaign(
        &mut self,
        id: CampaignId,
        name: String,
        max_concurrent: usize,
    ) -> &mut Campaign {
        let campaign = Campaign::new(id.clone(), name, max_concurrent);
        self.campaigns.insert(id.clone(), campaign);
        self.campaigns.get_mut(&id).unwrap()
    }

    pub fn get_campaign(&self, id: &CampaignId) -> Option<&Campaign> {
        self.campaigns.get(id)
    }

    pub fn get_campaign_mut(&mut self, id: &CampaignId) -> Option<&mut Campaign> {
        self.campaigns.get_mut(id)
    }

    pub fn active_campaigns(&self) -> Vec<&Campaign> {
        self.campaigns
            .values()
            .filter(|c| c.state == CampaignState::Active)
            .collect()
    }

    pub fn campaign_count(&self) -> usize {
        self.campaigns.len()
    }
}

impl Default for CampaignManagerV2 {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
