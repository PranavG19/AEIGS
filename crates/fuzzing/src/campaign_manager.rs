use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// State of a fuzzing campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CampaignState {
    Created,
    Running,
    Paused,
    Completed,
    Aborted,
}

/// Resource budget controlling campaign limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceBudget {
    pub max_duration: Duration,
    pub max_requests: u64,
    pub max_findings: u64,
    pub plateau_threshold: u64,
}

impl ResourceBudget {
    pub fn new() -> Self {
        Self {
            max_duration: Duration::from_secs(3600),
            max_requests: 100_000,
            max_findings: 1000,
            plateau_threshold: 5000,
        }
    }

    pub fn with_max_duration(mut self, duration: Duration) -> Self {
        self.max_duration = duration;
        self
    }

    pub fn with_max_requests(mut self, max: u64) -> Self {
        self.max_requests = max;
        self
    }

    pub fn with_max_findings(mut self, max: u64) -> Self {
        self.max_findings = max;
        self
    }

    pub fn with_plateau_threshold(mut self, threshold: u64) -> Self {
        self.plateau_threshold = threshold;
        self
    }
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of corpus evolution at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusSnapshot {
    pub timestamp_ms: u64,
    pub corpus_size: usize,
    pub total_executions: u64,
    pub unique_coverage: usize,
    pub findings_count: u64,
}

/// Result of a stability rerun for an interesting input.
#[derive(Debug, Clone)]
pub struct StabilityResult {
    pub payload: String,
    pub consistent_runs: u32,
    pub total_runs: u32,
    pub is_stable: bool,
}

/// A serializable checkpoint for saving/resuming campaign progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignCheckpoint {
    pub campaign_id: String,
    pub state: CampaignState,
    pub total_requests: u64,
    pub total_findings: u64,
    pub unique_coverage: usize,
    pub corpus_entries: Vec<String>,
    pub elapsed_ms: u64,
    pub snapshots: Vec<CorpusSnapshot>,
    pub findings: Vec<CampaignFinding>,
}

/// A finding recorded during the campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignFinding {
    pub payload: String,
    pub endpoint: String,
    pub finding_type: String,
    pub confidence: f64,
    pub discovered_at_execution: u64,
}

/// Stop reason when a campaign ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    BudgetExhausted,
    MaxRequestsReached,
    MaxFindingsReached,
    CoveragePlateau,
    ManualStop,
}

/// Long-running fuzzing campaign manager.
///
/// Tracks campaign state, corpus evolution, stability of findings,
/// coverage plateau detection, and resource budgeting. Supports
/// checkpointing for save/resume across sessions.
pub struct CampaignManager {
    campaign_id: String,
    state: CampaignState,
    budget: ResourceBudget,
    total_requests: u64,
    total_findings: u64,
    unique_coverage: usize,
    last_novel_at: u64,
    corpus: Vec<String>,
    findings: Vec<CampaignFinding>,
    snapshots: Vec<CorpusSnapshot>,
    stability_results: HashMap<String, StabilityResult>,
    start_time: Option<Instant>,
    elapsed_before_pause: Duration,
}

impl CampaignManager {
    pub fn new(campaign_id: &str) -> Self {
        Self {
            campaign_id: campaign_id.to_string(),
            state: CampaignState::Created,
            budget: ResourceBudget::new(),
            total_requests: 0,
            total_findings: 0,
            unique_coverage: 0,
            last_novel_at: 0,
            corpus: Vec::new(),
            findings: Vec::new(),
            snapshots: Vec::new(),
            stability_results: HashMap::new(),
            start_time: None,
            elapsed_before_pause: Duration::ZERO,
        }
    }

    pub fn with_budget(mut self, budget: ResourceBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Start or resume the campaign.
    pub fn start(&mut self) {
        match self.state {
            CampaignState::Created | CampaignState::Paused => {
                self.state = CampaignState::Running;
                self.start_time = Some(Instant::now());
            }
            _ => {}
        }
    }

    /// Pause the campaign, preserving elapsed time.
    pub fn pause(&mut self) {
        if self.state == CampaignState::Running {
            if let Some(start) = self.start_time.take() {
                self.elapsed_before_pause += start.elapsed();
            }
            self.state = CampaignState::Paused;
        }
    }

    /// Abort the campaign.
    pub fn abort(&mut self) {
        if let Some(start) = self.start_time.take() {
            self.elapsed_before_pause += start.elapsed();
        }
        self.state = CampaignState::Aborted;
    }

    /// Record a fuzz execution. Returns `Some(StopReason)` if budget is exhausted.
    pub fn record_execution(&mut self, novel_coverage: bool) -> Option<StopReason> {
        if self.state != CampaignState::Running {
            return None;
        }

        self.total_requests += 1;

        if novel_coverage {
            self.unique_coverage += 1;
            self.last_novel_at = self.total_requests;
        }

        self.check_budget()
    }

    /// Record a new finding.
    pub fn record_finding(&mut self, finding: CampaignFinding) -> Option<StopReason> {
        self.total_findings += 1;
        self.findings.push(finding);
        self.check_budget()
    }

    /// Add a payload to the corpus.
    pub fn add_corpus_entry(&mut self, payload: &str) {
        self.corpus.push(payload.to_string());
    }

    /// Take a snapshot of the current corpus state.
    pub fn take_snapshot(&mut self) {
        self.snapshots.push(CorpusSnapshot {
            timestamp_ms: self.elapsed().as_millis() as u64,
            corpus_size: self.corpus.len(),
            total_executions: self.total_requests,
            unique_coverage: self.unique_coverage,
            findings_count: self.total_findings,
        });
    }

    /// Test stability of a payload by recording rerun results.
    pub fn record_stability_run(&mut self, payload: &str, consistent: bool) -> &StabilityResult {
        let entry = self
            .stability_results
            .entry(payload.to_string())
            .or_insert_with(|| StabilityResult {
                payload: payload.to_string(),
                consistent_runs: 0,
                total_runs: 0,
                is_stable: false,
            });
        entry.total_runs += 1;
        if consistent {
            entry.consistent_runs += 1;
        }
        entry.is_stable = entry.total_runs >= 3
            && (entry.consistent_runs as f64 / entry.total_runs as f64) >= 0.8;
        entry
    }

    /// Check if coverage has plateaued (no new coverage for N executions).
    pub fn is_plateaued(&self) -> bool {
        self.total_requests > 0
            && self.total_requests - self.last_novel_at >= self.budget.plateau_threshold
    }

    /// Executions since last novel coverage discovery.
    pub fn executions_since_novel(&self) -> u64 {
        self.total_requests - self.last_novel_at
    }

    /// Create a serializable checkpoint for saving.
    pub fn checkpoint(&self) -> CampaignCheckpoint {
        CampaignCheckpoint {
            campaign_id: self.campaign_id.clone(),
            state: self.state,
            total_requests: self.total_requests,
            total_findings: self.total_findings,
            unique_coverage: self.unique_coverage,
            corpus_entries: self.corpus.clone(),
            elapsed_ms: self.elapsed().as_millis() as u64,
            snapshots: self.snapshots.clone(),
            findings: self.findings.clone(),
        }
    }

    /// Restore campaign state from a checkpoint.
    pub fn restore(checkpoint: CampaignCheckpoint) -> Self {
        Self {
            campaign_id: checkpoint.campaign_id,
            state: CampaignState::Paused,
            budget: ResourceBudget::new(),
            total_requests: checkpoint.total_requests,
            total_findings: checkpoint.total_findings,
            unique_coverage: checkpoint.unique_coverage,
            last_novel_at: checkpoint.total_requests,
            corpus: checkpoint.corpus_entries,
            findings: checkpoint.findings,
            snapshots: checkpoint.snapshots,
            stability_results: HashMap::new(),
            start_time: None,
            elapsed_before_pause: Duration::from_millis(checkpoint.elapsed_ms),
        }
    }

    pub fn campaign_id(&self) -> &str {
        &self.campaign_id
    }

    pub fn state(&self) -> CampaignState {
        self.state
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests
    }

    pub fn total_findings(&self) -> u64 {
        self.total_findings
    }

    pub fn unique_coverage(&self) -> usize {
        self.unique_coverage
    }

    pub fn corpus(&self) -> &[String] {
        &self.corpus
    }

    pub fn findings(&self) -> &[CampaignFinding] {
        &self.findings
    }

    pub fn snapshots(&self) -> &[CorpusSnapshot] {
        &self.snapshots
    }

    pub fn stability_results(&self) -> &HashMap<String, StabilityResult> {
        &self.stability_results
    }

    pub fn elapsed(&self) -> Duration {
        let current = self
            .start_time
            .map(|s| s.elapsed())
            .unwrap_or(Duration::ZERO);
        self.elapsed_before_pause + current
    }

    pub fn budget(&self) -> &ResourceBudget {
        &self.budget
    }

    fn check_budget(&mut self) -> Option<StopReason> {
        if self.total_requests >= self.budget.max_requests {
            self.state = CampaignState::Completed;
            return Some(StopReason::MaxRequestsReached);
        }
        if self.total_findings >= self.budget.max_findings {
            self.state = CampaignState::Completed;
            return Some(StopReason::MaxFindingsReached);
        }
        if self.is_plateaued() {
            self.state = CampaignState::Completed;
            return Some(StopReason::CoveragePlateau);
        }
        if self.elapsed() >= self.budget.max_duration {
            self.state = CampaignState::Completed;
            return Some(StopReason::BudgetExhausted);
        }
        None
    }
}
