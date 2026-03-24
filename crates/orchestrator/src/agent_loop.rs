use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Agent observation of current scan state — the "eyes" of the autonomous agent.
///
/// Captures everything the agent needs to reason about what to try next:
/// discovered endpoints, tech stack, existing findings, defense posture,
/// what has been tried and what worked/failed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentObservation {
    pub target_url: String,
    pub tech_stack: Vec<String>,
    pub endpoints: Vec<EndpointObservation>,
    pub findings: Vec<FindingObservation>,
    pub defense_profile: DefenseObservation,
    pub failed_attempts: Vec<FailedAttempt>,
    pub iteration: u32,
    pub total_requests_sent: u64,
    pub scan_duration_ms: u64,
}

/// Observed endpoint with metadata about what has been tried against it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointObservation {
    pub url: String,
    pub method: String,
    pub parameters: Vec<String>,
    pub response_code: Option<u16>,
    pub content_type: Option<String>,
    pub auth_required: bool,
    pub fuzz_attempts: u32,
    pub vulnerability_classes_tested: Vec<String>,
}

/// Observed finding from a previous iteration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingObservation {
    pub finding_id: u64,
    pub vulnerability_class: String,
    pub endpoint: String,
    pub confidence: f64,
    pub evidence_level: String,
    pub exploitable: bool,
    pub chained_with: Vec<u64>,
}

/// Observed defense posture of the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseObservation {
    pub has_waf: bool,
    pub waf_vendor: Option<String>,
    pub blocked_categories: Vec<String>,
    pub rate_limit_rps: Option<f64>,
    pub bot_detection_present: bool,
    pub bot_detection_evaded: bool,
    pub csp_present: bool,
    pub cors_misconfigured: bool,
}

/// Record of a failed attack attempt for learning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedAttempt {
    pub endpoint: String,
    pub vulnerability_class: String,
    pub payload_type: String,
    pub failure_reason: FailureReason,
    pub iteration: u32,
}

/// Why an attack attempt failed — informs the agent's next strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureReason {
    WafBlocked,
    RateLimited,
    NotVulnerable,
    AuthRequired,
    EndpointNotFound,
    PayloadFiltered,
    Timeout,
    UnexpectedResponse,
}

impl fmt::Display for FailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WafBlocked => write!(f, "WAF blocked"),
            Self::RateLimited => write!(f, "rate limited"),
            Self::NotVulnerable => write!(f, "not vulnerable"),
            Self::AuthRequired => write!(f, "authentication required"),
            Self::EndpointNotFound => write!(f, "endpoint not found"),
            Self::PayloadFiltered => write!(f, "payload filtered"),
            Self::Timeout => write!(f, "timeout"),
            Self::UnexpectedResponse => write!(f, "unexpected response"),
        }
    }
}

/// Agent action — what the agent decides to do next.
///
/// These are the "tools" the agent can use, mapping to existing AEGIS capabilities.
/// Each action is a concrete, executable step that the pipeline can dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentAction {
    FuzzEndpoint {
        endpoint: String,
        method: String,
        vulnerability_classes: Vec<String>,
        evasion_level: EvasionLevel,
        payload_strategy: PayloadStrategy,
    },
    ExploitFinding {
        finding_id: u64,
        tool: String,
        custom_args: Vec<String>,
    },
    DiscoverEndpoints {
        technique: DiscoveryTechnique,
        scope: String,
    },
    ChainFindings {
        finding_ids: Vec<u64>,
        chain_hypothesis: String,
    },
    AuthenticateFirst {
        auth_endpoint: String,
        auth_method: AuthMethod,
    },
    EvadeDefense {
        defense_type: String,
        evasion_technique: String,
    },
    DeepAnalyze {
        endpoint: String,
        analysis_type: AnalysisType,
    },
    GenerateReport {
        format: String,
    },
    Pause {
        reason: String,
        resume_after_ms: u64,
    },
}

/// How aggressively to evade defenses for a particular action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvasionLevel {
    None,
    Light,
    Moderate,
    Aggressive,
    Paranoid,
}

impl fmt::Display for EvasionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Light => write!(f, "light"),
            Self::Moderate => write!(f, "moderate"),
            Self::Aggressive => write!(f, "aggressive"),
            Self::Paranoid => write!(f, "paranoid"),
        }
    }
}

/// Payload generation strategy for fuzzing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadStrategy {
    Standard,
    WafBypass,
    Polyglot,
    ContextAware,
    LlmGenerated { context_hint: String },
}

/// Discovery technique for finding new endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryTechnique {
    DirectoryBruteForce,
    JavaScriptExtraction,
    ParameterDiscovery,
    VirtualHostDiscovery,
    ApiSchemaInference,
    SitemapCrawl,
    WaypointArchive,
}

impl fmt::Display for DiscoveryTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectoryBruteForce => write!(f, "directory brute-force"),
            Self::JavaScriptExtraction => write!(f, "JavaScript extraction"),
            Self::ParameterDiscovery => write!(f, "parameter discovery"),
            Self::VirtualHostDiscovery => write!(f, "virtual host discovery"),
            Self::ApiSchemaInference => write!(f, "API schema inference"),
            Self::SitemapCrawl => write!(f, "sitemap crawl"),
            Self::WaypointArchive => write!(f, "Waypoint archive"),
        }
    }
}

/// Authentication method for protected endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    BasicAuth,
    BearerToken,
    Cookie,
    OAuth2,
    ApiKey,
    Custom {
        header: String,
        value_template: String,
    },
}

/// Deep analysis technique for specific endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalysisType {
    TimingOracle,
    DifferentialResponse,
    BusinessLogicReview,
    SourceCodeAnalysis,
    StateMachineMapping,
    RaceConditionProbe,
}

impl fmt::Display for AnalysisType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimingOracle => write!(f, "timing oracle"),
            Self::DifferentialResponse => write!(f, "differential response"),
            Self::BusinessLogicReview => write!(f, "business logic review"),
            Self::SourceCodeAnalysis => write!(f, "source code analysis"),
            Self::StateMachineMapping => write!(f, "state machine mapping"),
            Self::RaceConditionProbe => write!(f, "race condition probe"),
        }
    }
}

/// Agent plan — a sequence of prioritized actions with reasoning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPlan {
    pub reasoning: String,
    pub actions: Vec<PlannedAction>,
    pub confidence: f64,
    pub estimated_value: f64,
}

/// A single planned action with priority and expected outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedAction {
    pub action: AgentAction,
    pub priority: u32,
    pub expected_outcome: String,
    pub fallback: Option<Box<AgentAction>>,
}

/// Result of executing an agent action — feeds back into the learning loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub action_index: usize,
    pub success: bool,
    pub new_findings: Vec<FindingObservation>,
    pub new_endpoints: Vec<String>,
    pub defense_changes: Vec<String>,
    pub execution_time_ms: u64,
    pub notes: String,
}

/// Agent memory — persistent across iterations within a scan.
///
/// Stores what the agent has learned: successful techniques, failed approaches,
/// WAF bypass patterns, endpoint behavior patterns. This is the "brain's"
/// working memory that grows as the scan progresses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentMemory {
    pub successful_techniques: Vec<TechniqueRecord>,
    pub failed_techniques: Vec<TechniqueRecord>,
    pub waf_bypass_patterns: Vec<WafBypassRecord>,
    pub endpoint_behaviors: HashMap<String, EndpointBehavior>,
    pub iteration_summaries: Vec<IterationSummary>,
    pub hypotheses_generated: u32,
    pub hypotheses_confirmed: u32,
    pub total_actions_taken: u32,
}

impl AgentMemory {
    pub fn record_success(&mut self, technique: TechniqueRecord) {
        self.successful_techniques.push(technique);
    }

    pub fn record_failure(&mut self, technique: TechniqueRecord) {
        self.failed_techniques.push(technique);
    }

    pub fn record_waf_bypass(&mut self, bypass: WafBypassRecord) {
        self.waf_bypass_patterns.push(bypass);
    }

    pub fn record_endpoint_behavior(&mut self, endpoint: String, behavior: EndpointBehavior) {
        self.endpoint_behaviors.insert(endpoint, behavior);
    }

    pub fn record_iteration(&mut self, summary: IterationSummary) {
        self.iteration_summaries.push(summary);
    }

    /// Returns the success rate for a given vulnerability class.
    pub fn success_rate_for_class(&self, vuln_class: &str) -> f64 {
        let successes = self
            .successful_techniques
            .iter()
            .filter(|t| t.vulnerability_class == vuln_class)
            .count();
        let failures = self
            .failed_techniques
            .iter()
            .filter(|t| t.vulnerability_class == vuln_class)
            .count();
        let total = successes + failures;
        if total == 0 {
            return 0.5; // no data, assume 50%
        }
        successes as f64 / total as f64
    }

    /// Returns techniques that worked against a specific defense.
    pub fn bypasses_for_defense(&self, defense_type: &str) -> Vec<&WafBypassRecord> {
        self.waf_bypass_patterns
            .iter()
            .filter(|b| b.defense_type == defense_type && b.successful)
            .collect()
    }

    /// Returns the most productive iteration (by new findings count).
    pub fn most_productive_iteration(&self) -> Option<&IterationSummary> {
        self.iteration_summaries
            .iter()
            .max_by_key(|s| s.new_findings)
    }

    /// Returns true if the agent is in a "stuck" state — multiple iterations
    /// with no new findings.
    pub fn is_stuck(&self, threshold: u32) -> bool {
        let recent = self
            .iteration_summaries
            .iter()
            .rev()
            .take(threshold as usize);
        let all_dry = recent.clone().all(|s| s.new_findings == 0);
        let enough_iterations = recent.count() >= threshold as usize;
        all_dry && enough_iterations
    }
}

/// Record of a technique applied during the scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueRecord {
    pub vulnerability_class: String,
    pub endpoint: String,
    pub payload_type: String,
    pub evasion_used: Option<String>,
    pub iteration: u32,
}

/// Record of a WAF bypass attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafBypassRecord {
    pub defense_type: String,
    pub bypass_technique: String,
    pub payload_mutation: String,
    pub successful: bool,
    pub iteration: u32,
}

/// Observed behavior of a specific endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointBehavior {
    pub typical_response_code: u16,
    pub typical_response_time_ms: u64,
    pub content_type: String,
    pub parameters_discovered: Vec<String>,
    pub auth_type: Option<String>,
    pub response_varies_with_input: bool,
    pub timing_variance_ms: f64,
}

/// Summary of a single agent iteration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IterationSummary {
    pub iteration: u32,
    pub actions_taken: u32,
    pub new_findings: u32,
    pub new_endpoints: u32,
    pub waf_blocks_encountered: u32,
    pub most_productive_action: Option<String>,
    pub duration_ms: u64,
}

/// The agent loop state machine.
///
/// Drives the Observe → Hypothesize → Plan → Execute → Learn cycle.
/// Each phase produces output consumed by the next. The loop continues
/// until convergence (no new findings), max iterations, or explicit stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentPhase {
    Observe,
    Hypothesize,
    Plan,
    Execute,
    Learn,
    Converged,
    Stopped,
}

impl fmt::Display for AgentPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observe => write!(f, "observe"),
            Self::Hypothesize => write!(f, "hypothesize"),
            Self::Plan => write!(f, "plan"),
            Self::Execute => write!(f, "execute"),
            Self::Learn => write!(f, "learn"),
            Self::Converged => write!(f, "converged"),
            Self::Stopped => write!(f, "stopped"),
        }
    }
}

/// Agent loop configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub max_iterations: u32,
    pub convergence_threshold: u32,
    pub max_actions_per_iteration: u32,
    pub evasion_level: EvasionLevel,
    pub use_llm: bool,
    pub llm_backend: String,
    pub max_concurrent_actions: u32,
    pub pause_between_iterations_ms: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            max_iterations: 10,
            convergence_threshold: 3,
            max_actions_per_iteration: 20,
            evasion_level: EvasionLevel::Moderate,
            use_llm: true,
            llm_backend: "bedrock".to_string(),
            max_concurrent_actions: 5,
            pause_between_iterations_ms: 1000,
        }
    }
}

/// Core agent loop state container.
///
/// Holds the current phase, accumulated memory, configuration, and
/// the observation/plan from the current iteration. The pipeline
/// advances this state through each phase of the OHPEL cycle.
#[derive(Debug)]
pub struct AgentLoopState {
    pub phase: AgentPhase,
    pub iteration: u32,
    pub config: AgentConfig,
    pub memory: AgentMemory,
    pub current_observation: Option<AgentObservation>,
    pub current_plan: Option<AgentPlan>,
    pub current_results: Vec<ActionResult>,
}

impl AgentLoopState {
    pub fn new(config: AgentConfig) -> Self {
        Self {
            phase: AgentPhase::Observe,
            iteration: 0,
            config,
            memory: AgentMemory::default(),
            current_observation: None,
            current_plan: None,
            current_results: Vec::new(),
        }
    }

    /// Advances the agent to the next phase in the OHPEL cycle.
    pub fn advance_phase(&mut self) {
        self.phase = match self.phase {
            AgentPhase::Observe => AgentPhase::Hypothesize,
            AgentPhase::Hypothesize => AgentPhase::Plan,
            AgentPhase::Plan => AgentPhase::Execute,
            AgentPhase::Execute => AgentPhase::Learn,
            AgentPhase::Learn => {
                self.iteration += 1;
                if self.should_stop() {
                    AgentPhase::Converged
                } else {
                    AgentPhase::Observe
                }
            }
            AgentPhase::Converged | AgentPhase::Stopped => self.phase,
        };
    }

    /// Determines whether the agent should stop iterating.
    fn should_stop(&self) -> bool {
        if self.iteration >= self.config.max_iterations {
            return true;
        }
        self.memory.is_stuck(self.config.convergence_threshold)
    }

    /// Returns the agent's current effectiveness metric.
    pub fn effectiveness(&self) -> f64 {
        if self.memory.total_actions_taken == 0 {
            return 0.0;
        }
        let confirmed = self.memory.hypotheses_confirmed as f64;
        let generated = self.memory.hypotheses_generated.max(1) as f64;
        confirmed / generated
    }

    /// Prepares the observation for the LLM prompt.
    pub fn observation_context(&self) -> Option<String> {
        let obs = self.current_observation.as_ref()?;
        Some(serde_json::to_string_pretty(obs).unwrap_or_default())
    }

    /// Prepares the memory context for the LLM prompt.
    pub fn memory_context(&self) -> String {
        let successful_classes: Vec<&str> = self
            .memory
            .successful_techniques
            .iter()
            .map(|t| t.vulnerability_class.as_str())
            .collect();
        let failed_classes: Vec<&str> = self
            .memory
            .failed_techniques
            .iter()
            .map(|t| t.vulnerability_class.as_str())
            .collect();

        format!(
            "Iteration {}/{}\nSuccessful: {:?}\nFailed: {:?}\nStuck: {}\nEffectiveness: {:.2}",
            self.iteration,
            self.config.max_iterations,
            successful_classes,
            failed_classes,
            self.memory.is_stuck(self.config.convergence_threshold),
            self.effectiveness()
        )
    }

    /// Records the results of executing the current plan and transitions to Learn.
    pub fn record_results(&mut self, results: Vec<ActionResult>) {
        let mut new_findings_total = 0u32;
        let mut new_endpoints_total = 0u32;
        let mut waf_blocks = 0u32;

        for result in &results {
            new_findings_total += result.new_findings.len() as u32;
            new_endpoints_total += result.new_endpoints.len() as u32;
            if result.notes.contains("WAF") || result.notes.contains("blocked") {
                waf_blocks += 1;
            }

            if result.success && !result.new_findings.is_empty() {
                self.memory.hypotheses_confirmed += 1;
            }
            self.memory.total_actions_taken += 1;
        }

        let summary = IterationSummary {
            iteration: self.iteration,
            actions_taken: results.len() as u32,
            new_findings: new_findings_total,
            new_endpoints: new_endpoints_total,
            waf_blocks_encountered: waf_blocks,
            most_productive_action: results
                .iter()
                .max_by_key(|r| r.new_findings.len())
                .map(|r| r.notes.clone()),
            duration_ms: results.iter().map(|r| r.execution_time_ms).sum(),
        };
        self.memory.record_iteration(summary);
        self.current_results = results;
    }

    /// Generates the LLM prompt for the Hypothesize phase.
    ///
    /// This is the structured prompt that makes the LLM think like a pentester.
    /// Uses XML-structured format matching the hypothesis-engine convention.
    pub fn build_hypothesis_prompt(&self) -> String {
        let obs_ctx = self.observation_context().unwrap_or_default();
        let mem_ctx = self.memory_context();

        format!(
            r#"<role>
You are an autonomous red team agent conducting a security assessment.
You reason about targets the way the world's best penetration testers do.
You are methodical, creative, and relentless. You chain findings.
You understand business logic. You adapt when blocked.
</role>

<task>
Analyze the current scan state and generate hypotheses about what vulnerabilities
exist and what attack techniques to try next. Focus on:
1. Vulnerabilities that haven't been tested yet on discovered endpoints
2. WAF bypass techniques for blocked attack vectors
3. Chain opportunities between existing findings
4. Business logic flaws that scanners miss
5. Authentication bypass and privilege escalation paths
</task>

<scan_context>
{obs_ctx}
</scan_context>

<agent_memory>
{mem_ctx}
</agent_memory>

<constraints>
- Prioritize high-impact findings over completeness
- If WAF is blocking, suggest evasion techniques before retrying
- If stuck for multiple iterations, try fundamentally different approaches
- Consider the tech stack when suggesting attack vectors
- Never suggest attacks already proven ineffective (see failed techniques)
</constraints>

<output_format>
Return a JSON array of hypotheses, each with:
- "vulnerability_class": the type of vulnerability
- "endpoint": target endpoint
- "technique": specific attack technique
- "confidence": 0.0-1.0 estimated likelihood
- "reasoning": why this hypothesis is worth testing
- "evasion_needed": true/false
</output_format>"#
        )
    }
}

/// Builds a rule-based plan when no LLM is available.
///
/// Falls back to deterministic heuristics based on the observation and memory.
/// Priorities: unexplored endpoints > WAF bypass for blocked findings >
/// chain synthesis for existing findings > deeper analysis.
pub fn build_fallback_plan(observation: &AgentObservation, memory: &AgentMemory) -> AgentPlan {
    let mut actions: Vec<PlannedAction> = Vec::new();
    let mut priority = 0u32;

    // Priority 1: Fuzz endpoints that haven't been tested much
    for ep in &observation.endpoints {
        if ep.fuzz_attempts < 3 && !ep.auth_required {
            let untested_classes: Vec<String> = vec![
                "XSS".to_string(),
                "SQLi".to_string(),
                "SSTI".to_string(),
                "CommandInjection".to_string(),
            ]
            .into_iter()
            .filter(|c| !ep.vulnerability_classes_tested.contains(c))
            .collect();

            if !untested_classes.is_empty() {
                actions.push(PlannedAction {
                    action: AgentAction::FuzzEndpoint {
                        endpoint: ep.url.clone(),
                        method: ep.method.clone(),
                        vulnerability_classes: untested_classes,
                        evasion_level: if observation.defense_profile.has_waf {
                            EvasionLevel::Moderate
                        } else {
                            EvasionLevel::None
                        },
                        payload_strategy: PayloadStrategy::Standard,
                    },
                    priority,
                    expected_outcome: format!("Test {} for common vulns", ep.url),
                    fallback: None,
                });
                priority += 1;
            }
        }
    }

    // Priority 2: WAF bypass for findings that were blocked
    if observation.defense_profile.has_waf {
        let blocked_attempts: Vec<&FailedAttempt> = observation
            .failed_attempts
            .iter()
            .filter(|a| a.failure_reason == FailureReason::WafBlocked)
            .collect();

        for attempt in blocked_attempts.iter().take(3) {
            let bypass_strategy = if memory.bypasses_for_defense("waf").is_empty() {
                PayloadStrategy::WafBypass
            } else {
                PayloadStrategy::Polyglot
            };

            actions.push(PlannedAction {
                action: AgentAction::FuzzEndpoint {
                    endpoint: attempt.endpoint.clone(),
                    method: "GET".to_string(),
                    vulnerability_classes: vec![attempt.vulnerability_class.clone()],
                    evasion_level: EvasionLevel::Aggressive,
                    payload_strategy: bypass_strategy,
                },
                priority,
                expected_outcome: format!(
                    "Bypass WAF for {} on {}",
                    attempt.vulnerability_class, attempt.endpoint
                ),
                fallback: Some(Box::new(AgentAction::EvadeDefense {
                    defense_type: "waf".to_string(),
                    evasion_technique: "encoding_chain".to_string(),
                })),
            });
            priority += 1;
        }
    }

    // Priority 3: Chain existing findings
    let exploitable: Vec<&FindingObservation> = observation
        .findings
        .iter()
        .filter(|f| f.exploitable && f.chained_with.is_empty())
        .collect();

    if exploitable.len() >= 2 {
        let ids: Vec<u64> = exploitable.iter().map(|f| f.finding_id).collect();
        actions.push(PlannedAction {
            action: AgentAction::ChainFindings {
                finding_ids: ids,
                chain_hypothesis: "SSRF → internal service → data exfil".to_string(),
            },
            priority,
            expected_outcome: "Discover multi-step attack chain".to_string(),
            fallback: None,
        });
        priority += 1;
    }

    // Priority 4: Discover more if endpoints are scarce
    if observation.endpoints.len() < 10 {
        actions.push(PlannedAction {
            action: AgentAction::DiscoverEndpoints {
                technique: DiscoveryTechnique::DirectoryBruteForce,
                scope: observation.target_url.clone(),
            },
            priority,
            expected_outcome: "Find hidden endpoints".to_string(),
            fallback: Some(Box::new(AgentAction::DiscoverEndpoints {
                technique: DiscoveryTechnique::JavaScriptExtraction,
                scope: observation.target_url.clone(),
            })),
        });
    }

    let confidence = if memory.is_stuck(2) { 0.3 } else { 0.7 };

    AgentPlan {
        reasoning: format!(
            "Fallback plan: {} actions. {} endpoints to test, {} blocked by WAF, {} existing findings.",
            actions.len(),
            observation.endpoints.len(),
            observation
                .failed_attempts
                .iter()
                .filter(|a| a.failure_reason == FailureReason::WafBlocked)
                .count(),
            observation.findings.len(),
        ),
        actions,
        confidence,
        estimated_value: 0.5,
    }
}

#[cfg(test)]
#[path = "agent_loop_test.rs"]
mod agent_loop_test;
