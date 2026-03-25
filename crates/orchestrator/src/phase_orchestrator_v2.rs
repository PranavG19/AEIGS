use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

/// Phase identifiers for the V2 orchestration pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PhaseId {
    Recon,
    Crawl,
    Fingerprint,
    Enumerate,
    Fuzz,
    Exploit,
    ChainSynthesis,
    Report,
}

impl fmt::Display for PhaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recon => write!(f, "recon"),
            Self::Crawl => write!(f, "crawl"),
            Self::Fingerprint => write!(f, "fingerprint"),
            Self::Enumerate => write!(f, "enumerate"),
            Self::Fuzz => write!(f, "fuzz"),
            Self::Exploit => write!(f, "exploit"),
            Self::ChainSynthesis => write!(f, "chain-synthesis"),
            Self::Report => write!(f, "report"),
        }
    }
}

/// Outcome of a single phase execution.
#[derive(Debug, Clone)]
pub struct PhaseOutcome {
    pub phase: PhaseId,
    pub status: PhaseStatus,
    pub duration: Duration,
    pub operations_applied: u64,
    pub findings_count: u64,
    pub endpoints_discovered: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseStatus {
    Completed,
    Skipped,
    Failed,
}

/// Events emitted during orchestration that trigger dynamic scheduling.
#[derive(Debug, Clone)]
pub enum OrchestratorEvent {
    EndpointDiscovered { url: String, method: String },
    VulnerabilityFound { class: String, endpoint: String },
    PhaseCompleted(PhaseId),
    PhaseSkipped(PhaseId),
    PhaseFailed(PhaseId, String),
}

/// Dependency specification: a phase and what it depends on.
#[derive(Debug, Clone)]
struct PhaseDep {
    phase: PhaseId,
    depends_on: Vec<PhaseId>,
    can_parallel_with: Vec<PhaseId>,
    skip: bool,
}

/// V2 phase orchestrator with dependency awareness and event-driven scheduling.
///
/// Manages the full pipeline: recon → crawl → fingerprint → enumerate → fuzz →
/// exploit → chain-synthesis → report. Supports concurrent execution of
/// independent phases (recon+crawl) and event-driven re-queuing (new endpoint
/// discovered → immediately queue for fuzzing).
pub struct PhaseOrchestratorV2 {
    phase_deps: Vec<PhaseDep>,
    completed: HashMap<PhaseId, PhaseOutcome>,
    events: Vec<OrchestratorEvent>,
    pending_endpoints: Vec<String>,
    max_fuzz_iterations: u32,
}

impl PhaseOrchestratorV2 {
    pub fn new() -> Self {
        Self {
            phase_deps: Self::default_dependencies(),
            completed: HashMap::new(),
            events: Vec::new(),
            pending_endpoints: Vec::new(),
            max_fuzz_iterations: 3,
        }
    }

    pub fn with_max_fuzz_iterations(mut self, n: u32) -> Self {
        self.max_fuzz_iterations = n;
        self
    }

    /// Skip a specific phase in the pipeline.
    pub fn skip_phase(&mut self, phase: PhaseId) {
        for dep in &mut self.phase_deps {
            if dep.phase == phase {
                dep.skip = true;
            }
        }
    }

    /// Record that a phase completed.
    pub fn record_outcome(&mut self, outcome: PhaseOutcome) {
        let phase = outcome.phase;
        let status = outcome.status;
        self.completed.insert(phase, outcome);

        match status {
            PhaseStatus::Completed => self.events.push(OrchestratorEvent::PhaseCompleted(phase)),
            PhaseStatus::Skipped => self.events.push(OrchestratorEvent::PhaseSkipped(phase)),
            PhaseStatus::Failed => {
                self.events
                    .push(OrchestratorEvent::PhaseFailed(phase, "phase failed".into()));
            }
        }
    }

    /// Notify the orchestrator that a new endpoint was discovered mid-scan.
    pub fn on_endpoint_discovered(&mut self, url: String, method: String) {
        self.pending_endpoints.push(url.clone());
        self.events
            .push(OrchestratorEvent::EndpointDiscovered { url, method });
    }

    /// Drain all pending endpoints queued for immediate fuzzing.
    pub fn drain_pending_endpoints(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending_endpoints)
    }

    /// Determine which phases can execute right now based on dependency resolution.
    pub fn ready_phases(&self) -> Vec<PhaseId> {
        let mut ready = Vec::new();
        for dep in &self.phase_deps {
            if dep.skip || self.completed.contains_key(&dep.phase) {
                continue;
            }
            let deps_met = dep.depends_on.iter().all(|d| {
                self.completed
                    .get(d)
                    .is_some_and(|o| o.status != PhaseStatus::Failed)
                    || self.phase_deps.iter().any(|pd| pd.phase == *d && pd.skip)
            });
            if deps_met {
                ready.push(dep.phase);
            }
        }
        ready
    }

    /// Phases that can run concurrently together from the ready set.
    pub fn parallel_groups(&self) -> Vec<Vec<PhaseId>> {
        let ready = self.ready_phases();
        if ready.is_empty() {
            return vec![];
        }
        let mut groups: Vec<Vec<PhaseId>> = Vec::new();
        for phase in &ready {
            let dep = self.phase_deps.iter().find(|d| d.phase == *phase).unwrap();
            let mut placed = false;
            for group in &mut groups {
                let compatible = group
                    .iter()
                    .all(|existing| dep.can_parallel_with.contains(existing));
                if compatible {
                    group.push(*phase);
                    placed = true;
                    break;
                }
            }
            if !placed {
                groups.push(vec![*phase]);
            }
        }
        groups
    }

    /// Whether the entire pipeline is finished.
    pub fn is_complete(&self) -> bool {
        self.phase_deps
            .iter()
            .all(|dep| dep.skip || self.completed.contains_key(&dep.phase))
    }

    /// All emitted events so far.
    pub fn events(&self) -> &[OrchestratorEvent] {
        &self.events
    }

    /// Execution order for a sequential fallback (topological sort of deps).
    pub fn sequential_order(&self) -> Vec<PhaseId> {
        self.phase_deps
            .iter()
            .filter(|d| !d.skip)
            .map(|d| d.phase)
            .collect()
    }

    /// Summary of completed phases.
    pub fn completed_phases(&self) -> &HashMap<PhaseId, PhaseOutcome> {
        &self.completed
    }

    pub fn max_fuzz_iterations(&self) -> u32 {
        self.max_fuzz_iterations
    }

    fn default_dependencies() -> Vec<PhaseDep> {
        vec![
            PhaseDep {
                phase: PhaseId::Recon,
                depends_on: vec![],
                can_parallel_with: vec![PhaseId::Crawl],
                skip: false,
            },
            PhaseDep {
                phase: PhaseId::Crawl,
                depends_on: vec![],
                can_parallel_with: vec![PhaseId::Recon],
                skip: false,
            },
            PhaseDep {
                phase: PhaseId::Fingerprint,
                depends_on: vec![PhaseId::Crawl],
                can_parallel_with: vec![],
                skip: false,
            },
            PhaseDep {
                phase: PhaseId::Enumerate,
                depends_on: vec![PhaseId::Crawl, PhaseId::Fingerprint],
                can_parallel_with: vec![],
                skip: false,
            },
            PhaseDep {
                phase: PhaseId::Fuzz,
                depends_on: vec![PhaseId::Crawl, PhaseId::Enumerate],
                can_parallel_with: vec![],
                skip: false,
            },
            PhaseDep {
                phase: PhaseId::Exploit,
                depends_on: vec![PhaseId::Fuzz],
                can_parallel_with: vec![],
                skip: false,
            },
            PhaseDep {
                phase: PhaseId::ChainSynthesis,
                depends_on: vec![PhaseId::Fuzz, PhaseId::Exploit],
                can_parallel_with: vec![],
                skip: false,
            },
            PhaseDep {
                phase: PhaseId::Report,
                depends_on: vec![PhaseId::ChainSynthesis],
                can_parallel_with: vec![],
                skip: false,
            },
        ]
    }
}

impl Default for PhaseOrchestratorV2 {
    fn default() -> Self {
        Self::new()
    }
}
