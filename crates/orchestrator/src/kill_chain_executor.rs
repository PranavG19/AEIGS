/// Kill chain state machine: autonomous multi-phase attack executor.
///
/// Drives the full kill chain from reconnaissance through objective completion.
/// Each phase produces evidence that feeds into the next. The LLM brain decides
/// transitions based on accumulated intelligence. Configurable iteration limits
/// prevent runaway execution.
use serde::{Deserialize, Serialize};
use std::fmt;

/// Phases of the autonomous kill chain, ordered by progression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KillChainPhase {
    Reconnaissance,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    LateralMovement,
    Collection,
    Exfiltration,
    Objective,
}

impl fmt::Display for KillChainPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reconnaissance => write!(f, "Reconnaissance"),
            Self::InitialAccess => write!(f, "Initial Access"),
            Self::Execution => write!(f, "Execution"),
            Self::Persistence => write!(f, "Persistence"),
            Self::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            Self::LateralMovement => write!(f, "Lateral Movement"),
            Self::Collection => write!(f, "Collection"),
            Self::Exfiltration => write!(f, "Exfiltration"),
            Self::Objective => write!(f, "Objective"),
        }
    }
}

impl KillChainPhase {
    /// Ordered list of all phases in kill chain progression.
    pub fn all_phases() -> &'static [KillChainPhase] {
        &[
            Self::Reconnaissance,
            Self::InitialAccess,
            Self::Execution,
            Self::Persistence,
            Self::PrivilegeEscalation,
            Self::LateralMovement,
            Self::Collection,
            Self::Exfiltration,
            Self::Objective,
        ]
    }

    /// The next phase in the kill chain, if any.
    pub fn next_phase(&self) -> Option<KillChainPhase> {
        let phases = Self::all_phases();
        phases
            .iter()
            .position(|p| p == self)
            .and_then(|idx| phases.get(idx + 1).copied())
    }
}

/// Access level obtained during the kill chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AccessLevel {
    None,
    Anonymous,
    Authenticated,
    Privileged,
    LocalAdmin,
    DomainAdmin,
    Root,
}

impl fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Anonymous => write!(f, "Anonymous"),
            Self::Authenticated => write!(f, "Authenticated"),
            Self::Privileged => write!(f, "Privileged"),
            Self::LocalAdmin => write!(f, "Local Admin"),
            Self::DomainAdmin => write!(f, "Domain Admin"),
            Self::Root => write!(f, "Root"),
        }
    }
}

/// A credential obtained during kill chain execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObtainedCredential {
    pub username: String,
    pub credential_type: CredentialType,
    pub source_phase: KillChainPhase,
    pub access_level: AccessLevel,
    pub target_host: Option<String>,
}

/// Type of credential obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialType {
    Password,
    Hash,
    Token,
    ApiKey,
    Certificate,
    SessionCookie,
    SshKey,
}

/// Persistence mechanism installed during the kill chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceMechanism {
    pub mechanism_type: String,
    pub host: String,
    pub description: String,
    pub installed_phase: KillChainPhase,
}

/// Full state of a kill chain execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainState {
    pub objective: String,
    pub target_url: String,
    pub phase: KillChainPhase,
    pub access_level: AccessLevel,
    pub credentials: Vec<ObtainedCredential>,
    pub persistence: Vec<PersistenceMechanism>,
    pub pivot_count: u32,
    pub compromised_hosts: Vec<String>,
    pub iteration: u32,
    pub max_iterations: u32,
    pub phase_history: Vec<PhaseRecord>,
    pub objective_achieved: bool,
    pub objective_progress_pct: f64,
}

/// Record of a completed phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseRecord {
    pub phase: KillChainPhase,
    pub actions: Vec<PhaseAction>,
    pub findings: Vec<String>,
    pub access_gained: Option<AccessLevel>,
    pub duration_ms: u64,
    pub success: bool,
    pub transition_reason: String,
}

/// An action taken during a phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseAction {
    pub description: String,
    pub action_type: PhaseActionType,
    pub target: Option<String>,
    pub result: ActionResult,
    pub evidence: Option<String>,
}

/// Type of phase action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhaseActionType {
    Scan,
    Exploit,
    CredentialHarvest,
    Pivot,
    Escalate,
    Install,
    Exfiltrate,
    Verify,
}

/// Result of a phase action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionResult {
    Success,
    Failure,
    Partial,
    Skipped,
}

/// Configuration for the kill chain executor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainConfig {
    pub target_url: String,
    pub objective: String,
    pub max_iterations: u32,
    pub skip_persistence: bool,
    pub skip_exfiltration: bool,
    pub allowed_phases: Option<Vec<KillChainPhase>>,
    pub credential_reuse: bool,
    pub stealth_mode: bool,
}

impl Default for KillChainConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            objective: "domain admin".to_string(),
            max_iterations: 10,
            skip_persistence: false,
            skip_exfiltration: false,
            allowed_phases: None,
            credential_reuse: true,
            stealth_mode: false,
        }
    }
}

/// Evidence required to advance past each phase gate.
#[derive(Debug, Clone)]
pub struct PhaseGateRequirement {
    pub phase: KillChainPhase,
    pub required_evidence: Vec<String>,
    pub min_access_level: Option<AccessLevel>,
    pub min_credentials: usize,
}

/// LLM decision after evaluating phase results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmDecision {
    pub next_phase: KillChainPhase,
    pub reasoning: String,
    pub confidence: f64,
    pub suggested_actions: Vec<String>,
    pub abort: bool,
}

/// Final report of the kill chain execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainReport {
    pub target_url: String,
    pub objective: String,
    pub objective_achieved: bool,
    pub objective_progress_pct: f64,
    pub final_access_level: AccessLevel,
    pub total_iterations: u32,
    pub phases_completed: Vec<PhaseRecord>,
    pub credentials_obtained: Vec<ObtainedCredential>,
    pub persistence_mechanisms: Vec<PersistenceMechanism>,
    pub hosts_compromised: Vec<String>,
    pub pivot_count: u32,
    pub executive_summary: String,
}

/// Phase gate definitions: what evidence is needed to advance.
pub fn phase_gate_requirements() -> Vec<PhaseGateRequirement> {
    vec![
        PhaseGateRequirement {
            phase: KillChainPhase::Reconnaissance,
            required_evidence: vec![
                "target_endpoints_discovered".to_string(),
                "tech_stack_identified".to_string(),
            ],
            min_access_level: None,
            min_credentials: 0,
        },
        PhaseGateRequirement {
            phase: KillChainPhase::InitialAccess,
            required_evidence: vec!["vulnerability_confirmed".to_string()],
            min_access_level: Some(AccessLevel::Anonymous),
            min_credentials: 0,
        },
        PhaseGateRequirement {
            phase: KillChainPhase::Execution,
            required_evidence: vec!["code_execution_confirmed".to_string()],
            min_access_level: Some(AccessLevel::Authenticated),
            min_credentials: 1,
        },
        PhaseGateRequirement {
            phase: KillChainPhase::Persistence,
            required_evidence: vec!["persistence_installed".to_string()],
            min_access_level: Some(AccessLevel::Authenticated),
            min_credentials: 1,
        },
        PhaseGateRequirement {
            phase: KillChainPhase::PrivilegeEscalation,
            required_evidence: vec!["privilege_escalated".to_string()],
            min_access_level: Some(AccessLevel::Privileged),
            min_credentials: 1,
        },
        PhaseGateRequirement {
            phase: KillChainPhase::LateralMovement,
            required_evidence: vec!["new_host_accessed".to_string()],
            min_access_level: Some(AccessLevel::Authenticated),
            min_credentials: 1,
        },
        PhaseGateRequirement {
            phase: KillChainPhase::Collection,
            required_evidence: vec!["data_identified".to_string()],
            min_access_level: Some(AccessLevel::Authenticated),
            min_credentials: 1,
        },
        PhaseGateRequirement {
            phase: KillChainPhase::Exfiltration,
            required_evidence: vec!["data_extracted".to_string()],
            min_access_level: Some(AccessLevel::Authenticated),
            min_credentials: 1,
        },
    ]
}

/// Check whether the gate requirement for advancing past a phase is met.
pub fn check_phase_gate(state: &KillChainState, requirement: &PhaseGateRequirement) -> bool {
    let evidence_gathered: Vec<&str> = state
        .phase_history
        .iter()
        .flat_map(|r| r.findings.iter().map(String::as_str))
        .collect();

    let evidence_met = requirement
        .required_evidence
        .iter()
        .all(|req| evidence_gathered.iter().any(|e| e.contains(req.as_str())));

    let access_met = requirement
        .min_access_level
        .map(|min| state.access_level >= min)
        .unwrap_or(true);

    let cred_met = state.credentials.len() >= requirement.min_credentials;

    evidence_met && access_met && cred_met
}

/// Parse the objective string into a structured check.
pub fn parse_objective(objective: &str) -> ObjectiveCheck {
    let lower = objective.to_lowercase();
    if lower.contains("domain admin") || lower.contains("da ") {
        ObjectiveCheck::DomainAdmin
    } else if lower.contains("database") || lower.contains("db access") {
        ObjectiveCheck::DatabaseAccess
    } else if lower.starts_with("file:") {
        let path = objective.trim_start_matches("file:").trim().to_string();
        ObjectiveCheck::FileRead(path)
    } else if lower.starts_with("credential:") {
        let user = objective
            .trim_start_matches("credential:")
            .trim()
            .to_string();
        ObjectiveCheck::CredentialObtained(user)
    } else if lower.starts_with("network:") {
        let cidr = objective.trim_start_matches("network:").trim().to_string();
        ObjectiveCheck::NetworkAccess(cidr)
    } else {
        ObjectiveCheck::Custom(objective.to_string())
    }
}

/// Structured objective check variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectiveCheck {
    DomainAdmin,
    DatabaseAccess,
    FileRead(String),
    CredentialObtained(String),
    NetworkAccess(String),
    Custom(String),
}

/// Evaluate whether the objective has been achieved given current state.
pub fn evaluate_objective(state: &KillChainState) -> (bool, f64) {
    let check = parse_objective(&state.objective);
    match check {
        ObjectiveCheck::DomainAdmin => {
            let has_da = state.access_level >= AccessLevel::DomainAdmin
                || state
                    .credentials
                    .iter()
                    .any(|c| c.access_level >= AccessLevel::DomainAdmin);
            let progress = match state.access_level {
                AccessLevel::None => 0.0,
                AccessLevel::Anonymous => 10.0,
                AccessLevel::Authenticated => 25.0,
                AccessLevel::Privileged => 50.0,
                AccessLevel::LocalAdmin => 75.0,
                AccessLevel::DomainAdmin | AccessLevel::Root => 100.0,
            };
            (has_da, progress)
        }
        ObjectiveCheck::DatabaseAccess => {
            let has_db = state
                .phase_history
                .iter()
                .any(|r| r.findings.iter().any(|f| f.contains("database_access")));
            let progress = if has_db {
                100.0
            } else {
                state.objective_progress_pct
            };
            (has_db, progress)
        }
        ObjectiveCheck::FileRead(ref path) => {
            let has_file = state
                .phase_history
                .iter()
                .any(|r| r.findings.iter().any(|f| f.contains(path)));
            let progress = if has_file {
                100.0
            } else {
                state.objective_progress_pct
            };
            (has_file, progress)
        }
        ObjectiveCheck::CredentialObtained(ref user) => {
            let has_cred = state.credentials.iter().any(|c| c.username == *user);
            let progress = if has_cred {
                100.0
            } else {
                state.objective_progress_pct
            };
            (has_cred, progress)
        }
        ObjectiveCheck::NetworkAccess(ref _cidr) => {
            let network_access = !state.compromised_hosts.is_empty();
            let progress = if network_access {
                (state.compromised_hosts.len() as f64 * 25.0).min(100.0)
            } else {
                0.0
            };
            (progress >= 100.0, progress)
        }
        ObjectiveCheck::Custom(_) => {
            let progress = state.objective_progress_pct;
            (progress >= 100.0, progress)
        }
    }
}

/// Initialize a fresh kill chain state from config.
pub fn init_state(config: &KillChainConfig) -> KillChainState {
    KillChainState {
        objective: config.objective.clone(),
        target_url: config.target_url.clone(),
        phase: KillChainPhase::Reconnaissance,
        access_level: AccessLevel::None,
        credentials: Vec::new(),
        persistence: Vec::new(),
        pivot_count: 0,
        compromised_hosts: Vec::new(),
        iteration: 0,
        max_iterations: config.max_iterations,
        phase_history: Vec::new(),
        objective_achieved: false,
        objective_progress_pct: 0.0,
    }
}

/// Determine the next phase based on current state and optional LLM decision.
pub fn decide_next_phase(
    state: &KillChainState,
    llm_decision: Option<&LlmDecision>,
    config: &KillChainConfig,
) -> Option<KillChainPhase> {
    if state.iteration >= state.max_iterations {
        return None;
    }

    let (achieved, _) = evaluate_objective(state);
    if achieved {
        return None;
    }

    if let Some(decision) = llm_decision {
        if decision.abort {
            return None;
        }
        if is_phase_allowed(decision.next_phase, config) {
            return Some(decision.next_phase);
        }
    }

    let candidate = state.phase.next_phase()?;
    if config.skip_persistence && candidate == KillChainPhase::Persistence {
        return candidate.next_phase();
    }
    if config.skip_exfiltration && candidate == KillChainPhase::Exfiltration {
        return candidate.next_phase();
    }

    if is_phase_allowed(candidate, config) {
        Some(candidate)
    } else {
        candidate.next_phase()
    }
}

fn is_phase_allowed(phase: KillChainPhase, config: &KillChainConfig) -> bool {
    config
        .allowed_phases
        .as_ref()
        .map(|allowed| allowed.contains(&phase))
        .unwrap_or(true)
}

/// Advance the state machine: record a phase completion and move to next.
pub fn advance_phase(state: &mut KillChainState, record: PhaseRecord, config: &KillChainConfig) {
    if let Some(gained) = record.access_gained {
        if gained > state.access_level {
            state.access_level = gained;
        }
    }

    state.phase_history.push(record);
    state.iteration += 1;

    let (achieved, progress) = evaluate_objective(state);
    state.objective_achieved = achieved;
    state.objective_progress_pct = progress;

    if !achieved {
        if let Some(next) = decide_next_phase(state, None, config) {
            state.phase = next;
        }
    }
}

/// Generate the final kill chain report from completed state.
pub fn generate_report(state: &KillChainState) -> KillChainReport {
    let summary = build_executive_summary(state);
    KillChainReport {
        target_url: state.target_url.clone(),
        objective: state.objective.clone(),
        objective_achieved: state.objective_achieved,
        objective_progress_pct: state.objective_progress_pct,
        final_access_level: state.access_level,
        total_iterations: state.iteration,
        phases_completed: state.phase_history.clone(),
        credentials_obtained: state.credentials.clone(),
        persistence_mechanisms: state.persistence.clone(),
        hosts_compromised: state.compromised_hosts.clone(),
        pivot_count: state.pivot_count,
        executive_summary: summary,
    }
}

fn build_executive_summary(state: &KillChainState) -> String {
    let phase_count = state.phase_history.len();
    let cred_count = state.credentials.len();
    let host_count = state.compromised_hosts.len();

    let outcome = if state.objective_achieved {
        format!(
            "Objective '{}' was achieved. Final access level: {}.",
            state.objective, state.access_level
        )
    } else {
        format!(
            "Objective '{}' was not fully achieved ({:.0}% progress). Final access level: {}.",
            state.objective, state.objective_progress_pct, state.access_level
        )
    };

    let mut details = Vec::new();
    if cred_count > 0 {
        details.push(format!("{cred_count} credential(s) obtained"));
    }
    if host_count > 0 {
        details.push(format!("{host_count} host(s) compromised"));
    }
    if state.pivot_count > 0 {
        details.push(format!("{} pivot(s) executed", state.pivot_count));
    }
    if !state.persistence.is_empty() {
        details.push(format!(
            "{} persistence mechanism(s) installed",
            state.persistence.len()
        ));
    }

    let detail_str = if details.is_empty() {
        String::new()
    } else {
        format!(" {}", details.join(", "))
    };

    format!(
        "Kill chain executed {phase_count} phase(s) against {}.{detail_str} {outcome}",
        state.target_url
    )
}

/// Execute the full autonomous kill chain loop.
///
/// This is the top-level driver. In production, `phase_executor` would call into
/// real scan/exploit modules and `llm_advisor` would query the LLM brain.
/// For testability, both are injected as closures.
pub fn execute_kill_chain<F, G>(
    config: &KillChainConfig,
    mut phase_executor: F,
    mut llm_advisor: G,
) -> KillChainReport
where
    F: FnMut(&KillChainState, KillChainPhase) -> PhaseRecord,
    G: FnMut(&KillChainState) -> LlmDecision,
{
    let mut state = init_state(config);

    loop {
        if state.iteration >= state.max_iterations {
            break;
        }

        let (achieved, progress) = evaluate_objective(&state);
        state.objective_achieved = achieved;
        state.objective_progress_pct = progress;
        if achieved {
            break;
        }

        let current_phase = state.phase;
        let record = phase_executor(&state, current_phase);

        if let Some(gained) = record.access_gained {
            if gained > state.access_level {
                state.access_level = gained;
            }
        }
        for action in &record.actions {
            if action.action_type == PhaseActionType::Pivot
                && action.result == ActionResult::Success
            {
                state.pivot_count += 1;
                if let Some(ref target) = action.target {
                    if !state.compromised_hosts.contains(target) {
                        state.compromised_hosts.push(target.clone());
                    }
                }
            }
        }

        state.phase_history.push(record);
        state.iteration += 1;

        let (achieved, progress) = evaluate_objective(&state);
        state.objective_achieved = achieved;
        state.objective_progress_pct = progress;
        if achieved {
            break;
        }

        let decision = llm_advisor(&state);
        match decide_next_phase(&state, Some(&decision), config) {
            Some(next) => state.phase = next,
            None => break,
        }
    }

    generate_report(&state)
}
