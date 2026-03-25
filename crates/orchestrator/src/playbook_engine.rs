/// Pentest playbook engine: define and execute structured pentest workflows.
///
/// Playbooks are YAML-described sequences of scan/exploit actions that model
/// real-world pentesting workflows. Supports conditional branches (e.g.
/// "if XSS found → try cookie theft"), parallel execution tracks, and
/// step-level status tracking.
use aegis_protocol::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Identifies when a conditional branch should fire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BranchCondition {
    /// Branch if the named vulnerability class was found.
    VulnFound(VulnerabilityClass),
    /// Branch if a specific step completed successfully.
    StepSucceeded(String),
    /// Branch if a specific step failed.
    StepFailed(String),
    /// Always take this branch (unconditional).
    Always,
}

/// A conditional branch from one step to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionalBranch {
    pub condition: BranchCondition,
    pub target_step_id: String,
    pub description: String,
}

/// The type of action a playbook step performs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlaybookAction {
    Recon,
    Crawl,
    Fuzz,
    Exploit,
    Verify,
    Report,
    Custom(String),
}

/// Execution status of a single playbook step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepStatus {
    Pending,
    Running,
    Succeeded,
    Failed(String),
    Skipped,
}

/// A single step in a pentest playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub id: String,
    pub name: String,
    pub description: String,
    pub action: PlaybookAction,
    pub target_classes: Vec<VulnerabilityClass>,
    pub branches: Vec<ConditionalBranch>,
    pub parallel_group: Option<String>,
    pub depends_on: Vec<String>,
    pub parameters: HashMap<String, String>,
    pub status: StepStatus,
    pub output: Option<StepOutput>,
}

/// Output produced by a completed playbook step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepOutput {
    pub findings_discovered: Vec<VulnerabilityClass>,
    pub endpoints_found: Vec<String>,
    pub notes: String,
    pub duration_ms: u64,
}

/// A complete pentest playbook definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub steps: Vec<PlaybookStep>,
    pub metadata: HashMap<String, String>,
}

/// Snapshot of a running playbook execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookExecution {
    pub playbook: Playbook,
    pub current_step_index: usize,
    pub completed_steps: Vec<String>,
    pub discovered_vulns: Vec<VulnerabilityClass>,
    pub is_finished: bool,
}

/// Result of advancing the playbook by one tick.
#[derive(Debug, Clone)]
pub struct ExecutionAdvance {
    pub executed_step_id: String,
    pub status: StepStatus,
    pub next_steps: Vec<String>,
    pub branches_taken: Vec<String>,
}

impl PlaybookStep {
    pub fn new(id: impl Into<String>, name: impl Into<String>, action: PlaybookAction) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            action,
            target_classes: Vec::new(),
            branches: Vec::new(),
            parallel_group: None,
            depends_on: Vec::new(),
            parameters: HashMap::new(),
            status: StepStatus::Pending,
            output: None,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_branch(mut self, branch: ConditionalBranch) -> Self {
        self.branches.push(branch);
        self
    }

    pub fn with_dependency(mut self, dep: impl Into<String>) -> Self {
        self.depends_on.push(dep.into());
        self
    }

    pub fn with_parallel_group(mut self, group: impl Into<String>) -> Self {
        self.parallel_group = Some(group.into());
        self
    }

    pub fn with_target_class(mut self, class: VulnerabilityClass) -> Self {
        self.target_classes.push(class);
        self
    }
}

impl Playbook {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            version: "1.0".to_string(),
            steps: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_step(mut self, step: PlaybookStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Return all steps that belong to a given parallel group.
    pub fn parallel_group_steps(&self, group: &str) -> Vec<&PlaybookStep> {
        self.steps
            .iter()
            .filter(|s| s.parallel_group.as_deref() == Some(group))
            .collect()
    }

    /// Parse a YAML string into a Playbook. Delegates to serde_json for now
    /// (YAML-like JSON subset) — callers convert YAML to JSON upstream.
    pub fn from_yaml_str(yaml: &str) -> Result<Self, String> {
        serde_json::from_str(yaml).map_err(|e| format!("playbook parse error: {e}"))
    }

    /// Serialize the playbook to a JSON string.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("serialize error: {e}"))
    }

    /// Validate the playbook for referential integrity: branch targets, dependency
    /// references, and duplicate step IDs.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        let step_ids: Vec<&str> = self.steps.iter().map(|s| s.id.as_str()).collect();

        let mut seen_ids = std::collections::HashSet::new();
        for step in &self.steps {
            if !seen_ids.insert(&step.id) {
                errors.push(format!("duplicate step id: {}", step.id));
            }
        }

        for step in &self.steps {
            for branch in &step.branches {
                if !step_ids.contains(&branch.target_step_id.as_str()) {
                    errors.push(format!(
                        "step '{}' branch targets unknown step '{}'",
                        step.id, branch.target_step_id
                    ));
                }
            }
            for dep in &step.depends_on {
                if !step_ids.contains(&dep.as_str()) {
                    errors.push(format!(
                        "step '{}' depends on unknown step '{}'",
                        step.id, dep
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl PlaybookExecution {
    /// Start execution from a validated playbook.
    pub fn start(playbook: Playbook) -> Self {
        Self {
            playbook,
            current_step_index: 0,
            completed_steps: Vec::new(),
            discovered_vulns: Vec::new(),
            is_finished: false,
        }
    }

    /// Determine which steps are ready to run (all dependencies satisfied).
    pub fn ready_steps(&self) -> Vec<&PlaybookStep> {
        self.playbook
            .steps
            .iter()
            .filter(|s| {
                s.status == StepStatus::Pending
                    && s.depends_on
                        .iter()
                        .all(|dep| self.completed_steps.contains(dep))
            })
            .collect()
    }

    /// Advance execution: mark the given step as completed with the provided output,
    /// evaluate branches, and return what should happen next.
    pub fn advance_step(
        &mut self,
        step_id: &str,
        success: bool,
        output: Option<StepOutput>,
    ) -> Option<ExecutionAdvance> {
        let step_idx = self.playbook.steps.iter().position(|s| s.id == step_id)?;
        let step = &mut self.playbook.steps[step_idx];

        if success {
            if let Some(ref out) = output {
                self.discovered_vulns
                    .extend(out.findings_discovered.iter().cloned());
            }
            step.status = StepStatus::Succeeded;
            step.output = output;
        } else {
            step.status = StepStatus::Failed("step execution failed".to_string());
        }

        self.completed_steps.push(step_id.to_string());

        let branches = self.playbook.steps[step_idx].branches.clone();
        let mut branches_taken = Vec::new();
        let mut next_steps = Vec::new();

        for branch in &branches {
            let should_take = match &branch.condition {
                BranchCondition::Always => true,
                BranchCondition::VulnFound(vc) => self.discovered_vulns.contains(vc),
                BranchCondition::StepSucceeded(sid) => self
                    .playbook
                    .steps
                    .iter()
                    .any(|s| s.id == *sid && s.status == StepStatus::Succeeded),
                BranchCondition::StepFailed(sid) => self
                    .playbook
                    .steps
                    .iter()
                    .any(|s| s.id == *sid && matches!(s.status, StepStatus::Failed(_))),
            };

            if should_take {
                branches_taken.push(branch.target_step_id.clone());
                next_steps.push(branch.target_step_id.clone());
            }
        }

        let ready = self.ready_steps();
        for s in &ready {
            if !next_steps.contains(&s.id) {
                next_steps.push(s.id.clone());
            }
        }

        let all_done = self
            .playbook
            .steps
            .iter()
            .all(|s| s.status != StepStatus::Pending && s.status != StepStatus::Running);
        if all_done {
            self.is_finished = true;
        }

        let status = self.playbook.steps[step_idx].status.clone();
        Some(ExecutionAdvance {
            executed_step_id: step_id.to_string(),
            status,
            next_steps,
            branches_taken,
        })
    }

    /// Collect all parallel groups that have at least one ready step.
    pub fn ready_parallel_groups(&self) -> Vec<String> {
        let ready = self.ready_steps();
        let mut groups: Vec<String> = ready
            .iter()
            .filter_map(|s| s.parallel_group.clone())
            .collect();
        groups.sort();
        groups.dedup();
        groups
    }

    /// Summary: count steps by status.
    pub fn status_summary(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for step in &self.playbook.steps {
            let key = match &step.status {
                StepStatus::Pending => "pending",
                StepStatus::Running => "running",
                StepStatus::Succeeded => "succeeded",
                StepStatus::Failed(_) => "failed",
                StepStatus::Skipped => "skipped",
            };
            *counts.entry(key.to_string()).or_insert(0) += 1;
        }
        counts
    }
}
