use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// Category of workflow-level attack targeting business logic state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkflowAttack {
    /// Skip one or more intermediate steps in a multi-step workflow.
    StepSkip,
    /// Execute workflow steps in a non-standard order.
    StepReorder,
    /// Replay a step that should only execute once (idempotency violation).
    StepRepeat,
    /// Attempt to return to a previous state after advancing.
    StepRollback,
    /// Fire multiple requests concurrently to exploit race conditions.
    ParallelExecution,
    /// Tamper with server-side state tokens or session markers between steps.
    StateManipulation,
}

impl std::fmt::Display for WorkflowAttack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::StepSkip => "step-skip",
            Self::StepReorder => "step-reorder",
            Self::StepRepeat => "step-repeat",
            Self::StepRollback => "step-rollback",
            Self::ParallelExecution => "parallel-execution",
            Self::StateManipulation => "state-manipulation",
        };
        write!(f, "{label}")
    }
}

/// Category of price/quantity/financial parameter manipulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ManipulationType {
    /// Modify price fields to reduce cost.
    PriceModification,
    /// Overflow quantity fields past integer boundaries.
    QuantityOverflow,
    /// Submit negative quantities to trigger credit/refund logic.
    NegativeQuantity,
    /// Set price to zero to bypass payment.
    ZeroPrice,
    /// Switch currency code to a weaker denomination.
    CurrencySwitch,
    /// Stack multiple discounts that should be mutually exclusive.
    DiscountStacking,
    /// Reuse a single-use coupon or promo code.
    CouponReuse,
    /// Directly modify account balance or wallet fields.
    BalanceManipulation,
}

impl std::fmt::Display for ManipulationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::PriceModification => "price-modification",
            Self::QuantityOverflow => "quantity-overflow",
            Self::NegativeQuantity => "negative-quantity",
            Self::ZeroPrice => "zero-price",
            Self::CurrencySwitch => "currency-switch",
            Self::DiscountStacking => "discount-stacking",
            Self::CouponReuse => "coupon-reuse",
            Self::BalanceManipulation => "balance-manipulation",
        };
        write!(f, "{label}")
    }
}

/// A single step in a multi-step business workflow.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub step_id: u32,
    pub name: String,
    pub endpoint: String,
    pub method: String,
    pub required_params: Vec<String>,
    pub expected_state_before: String,
    pub expected_state_after: String,
}

/// A complete business workflow with ordered steps and critical transition markers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    pub name: String,
    pub steps: Vec<WorkflowStep>,
    pub critical_transitions: Vec<StateTransitionV2>,
}

/// A directed state transition between two workflow states.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateTransitionV2 {
    pub from_state: String,
    pub to_state: String,
    pub via_step: u32,
    pub is_critical: bool,
}

/// Severity tier for a business logic finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BizSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for BizSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{label}")
    }
}

/// Reproducibility classification for a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Reproducibility {
    /// Deterministic — reproduces on every attempt.
    Always,
    /// Requires specific timing or load conditions.
    RaceDependent,
    /// Reproduces intermittently under normal conditions.
    Intermittent,
    /// Observed once; needs further confirmation.
    Unconfirmed,
}

/// A detected business logic vulnerability with evidence and reproduction data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BizLogicFinding {
    pub attack_type: WorkflowAttack,
    pub affected_steps: Vec<u32>,
    pub description: String,
    pub impact: String,
    pub severity: BizSeverity,
    pub evidence: Vec<String>,
    pub reproducibility: Reproducibility,
}

/// Configuration for concurrent/race-condition attack generation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConcurrencyConfig {
    /// Number of parallel HTTP requests per burst.
    pub parallel_requests: u32,
    /// Window in milliseconds during which all requests must land.
    pub timing_window_ms: u64,
    /// Total requests to fire across all bursts.
    pub request_count: u32,
}

impl Default for ConcurrencyConfig {
    fn default() -> Self {
        Self {
            parallel_requests: 10,
            timing_window_ms: 50,
            request_count: 100,
        }
    }
}

/// Top-level configuration for the business logic fuzzer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FuzzerConfig {
    pub test_skip: bool,
    pub test_reorder: bool,
    pub test_price: bool,
    pub test_concurrent: bool,
    pub max_steps: usize,
    pub concurrency_config: ConcurrencyConfig,
}

impl Default for FuzzerConfig {
    fn default() -> Self {
        Self {
            test_skip: true,
            test_reorder: true,
            test_price: true,
            test_concurrent: true,
            max_steps: 20,
            concurrency_config: ConcurrencyConfig::default(),
        }
    }
}

/// A generated attack scenario ready for execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackScenario {
    pub attack: WorkflowAttack,
    pub steps_to_execute: Vec<u32>,
    pub description: String,
    pub expected_violation: String,
    pub manipulation: Option<ManipulationType>,
    pub payload: Option<String>,
}

/// A price/quantity manipulation payload with metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManipulationPayload {
    pub manipulation_type: ManipulationType,
    pub param_name: String,
    pub original_value: String,
    pub malicious_value: String,
    pub rationale: String,
}

/// Summary report from a complete fuzzing run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FuzzReport {
    pub workflow_name: String,
    pub total_scenarios: usize,
    pub findings: Vec<BizLogicFinding>,
    pub scenarios_by_type: HashMap<String, usize>,
    pub critical_count: usize,
    pub high_count: usize,
}

/// State violation detected during workflow analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateViolation {
    pub step_id: u32,
    pub expected_state: String,
    pub observed_state: String,
    pub violation_type: String,
}

/// Business logic state fuzzer v2 — generates and analyzes workflow-level attacks
/// including step skips, reordering, price manipulation, and concurrent duplicates.
pub struct BizLogicFuzzerV2 {
    config: FuzzerConfig,
    price_payloads: Vec<ManipulationPayload>,
}

impl BizLogicFuzzerV2 {
    pub fn new(config: FuzzerConfig) -> Self {
        let price_payloads = build_price_payload_database();
        Self {
            config,
            price_payloads,
        }
    }

    /// Analyze a workflow definition and return all generated attack scenarios.
    pub fn analyze_workflow(&self, workflow: &WorkflowDefinition) -> Vec<AttackScenario> {
        let mut scenarios = Vec::new();
        if self.config.test_skip {
            scenarios.extend(self.generate_skip_attacks(workflow));
        }
        if self.config.test_reorder {
            scenarios.extend(self.generate_reorder_attacks(workflow));
        }
        if self.config.test_price {
            scenarios.extend(self.generate_price_manipulations(workflow));
        }
        if self.config.test_concurrent {
            scenarios.extend(self.generate_concurrent_attacks(workflow));
        }
        scenarios.extend(self.generate_rollback_attacks(workflow));
        scenarios.extend(self.generate_repeat_attacks(workflow));
        scenarios
    }

    /// Generate skip attacks that jump over one or more intermediate steps.
    pub fn generate_skip_attacks(&self, workflow: &WorkflowDefinition) -> Vec<AttackScenario> {
        let steps = &workflow.steps;
        let mut attacks = Vec::new();
        let limit = steps.len().min(self.config.max_steps);

        for start in 0..limit {
            for end in (start + 2)..limit {
                let skipped: Vec<u32> = steps[start + 1..end].iter().map(|s| s.step_id).collect();
                let skipped_names: Vec<&str> = steps[start + 1..end]
                    .iter()
                    .map(|s| s.name.as_str())
                    .collect();
                attacks.push(AttackScenario {
                    attack: WorkflowAttack::StepSkip,
                    steps_to_execute: vec![steps[start].step_id, steps[end].step_id],
                    description: format!(
                        "Skip from '{}' directly to '{}', bypassing [{}]",
                        steps[start].name,
                        steps[end].name,
                        skipped_names.join(", "),
                    ),
                    expected_violation: format!(
                        "Server accepts step {} without prior completion of steps {:?}",
                        steps[end].step_id, skipped
                    ),
                    manipulation: None,
                    payload: None,
                });
            }
        }
        attacks
    }

    /// Generate reorder attacks by permuting step sequences.
    pub fn generate_reorder_attacks(&self, workflow: &WorkflowDefinition) -> Vec<AttackScenario> {
        let steps = &workflow.steps;
        if steps.len() < 2 {
            return Vec::new();
        }

        let mut attacks = Vec::new();
        let limit = steps.len().min(self.config.max_steps);
        let ids: Vec<u32> = steps[..limit].iter().map(|s| s.step_id).collect();

        let permutations = generate_adjacent_swaps(&ids);
        for perm in permutations {
            let perm_names: Vec<&str> = perm
                .iter()
                .filter_map(|id| steps.iter().find(|s| s.step_id == *id))
                .map(|s| s.name.as_str())
                .collect();

            attacks.push(AttackScenario {
                attack: WorkflowAttack::StepReorder,
                steps_to_execute: perm.clone(),
                description: format!(
                    "Execute steps in reordered sequence: [{}]",
                    perm_names.join(" -> ")
                ),
                expected_violation: "Server processes out-of-order steps without state validation"
                    .into(),
                manipulation: None,
                payload: None,
            });
        }
        attacks
    }

    /// Generate price/quantity/financial manipulation scenarios for each step.
    pub fn generate_price_manipulations(
        &self,
        workflow: &WorkflowDefinition,
    ) -> Vec<AttackScenario> {
        let mut attacks = Vec::new();
        let financial_params: HashSet<&str> = [
            "price",
            "amount",
            "total",
            "cost",
            "quantity",
            "qty",
            "count",
            "discount",
            "balance",
            "credits",
            "currency",
            "coupon",
            "promo",
            "unit_price",
            "subtotal",
            "tax",
            "fee",
            "tip",
        ]
        .iter()
        .copied()
        .collect();

        for step in &workflow.steps {
            for param in &step.required_params {
                let lower = param.to_lowercase();
                if !financial_params.iter().any(|&fp| lower.contains(fp)) {
                    continue;
                }
                for payload in &self.price_payloads {
                    if !lower.contains(&payload.param_name.to_lowercase()) {
                        continue;
                    }
                    attacks.push(AttackScenario {
                        attack: WorkflowAttack::StateManipulation,
                        steps_to_execute: vec![step.step_id],
                        description: format!(
                            "{}: set {}={} on '{}'",
                            payload.rationale, param, payload.malicious_value, step.name
                        ),
                        expected_violation: format!(
                            "Server accepts manipulated {} without validation",
                            param
                        ),
                        manipulation: Some(payload.manipulation_type),
                        payload: Some(payload.malicious_value.clone()),
                    });
                }
            }
        }
        attacks
    }

    /// Generate concurrent/race-condition attack scenarios for critical transitions.
    pub fn generate_concurrent_attacks(
        &self,
        workflow: &WorkflowDefinition,
    ) -> Vec<AttackScenario> {
        let mut attacks = Vec::new();
        let cc = &self.config.concurrency_config;

        for transition in &workflow.critical_transitions {
            attacks.push(AttackScenario {
                attack: WorkflowAttack::ParallelExecution,
                steps_to_execute: vec![transition.via_step],
                description: format!(
                    "Fire {} parallel requests for step {} ({} -> {}) within {}ms window",
                    cc.parallel_requests,
                    transition.via_step,
                    transition.from_state,
                    transition.to_state,
                    cc.timing_window_ms,
                ),
                expected_violation: format!(
                    "Duplicate state transition from '{}' to '{}' processed concurrently",
                    transition.from_state, transition.to_state
                ),
                manipulation: None,
                payload: None,
            });
        }
        attacks
    }

    /// Generate rollback attacks that attempt to revert to a prior state.
    fn generate_rollback_attacks(&self, workflow: &WorkflowDefinition) -> Vec<AttackScenario> {
        let steps = &workflow.steps;
        let mut attacks = Vec::new();

        for i in 1..steps.len().min(self.config.max_steps) {
            attacks.push(AttackScenario {
                attack: WorkflowAttack::StepRollback,
                steps_to_execute: vec![steps[i].step_id, steps[0].step_id],
                description: format!(
                    "After reaching '{}', attempt to roll back to '{}'",
                    steps[i].name, steps[0].name
                ),
                expected_violation: format!(
                    "Server allows return to state '{}' from '{}'",
                    steps[0].expected_state_after, steps[i].expected_state_after
                ),
                manipulation: None,
                payload: None,
            });
        }
        attacks
    }

    /// Generate repeat attacks that replay a step to test idempotency.
    fn generate_repeat_attacks(&self, workflow: &WorkflowDefinition) -> Vec<AttackScenario> {
        let mut attacks = Vec::new();
        for step in &workflow.steps {
            attacks.push(AttackScenario {
                attack: WorkflowAttack::StepRepeat,
                steps_to_execute: vec![step.step_id, step.step_id],
                description: format!(
                    "Replay '{}' (step {}) to test idempotency enforcement",
                    step.name, step.step_id,
                ),
                expected_violation: format!(
                    "Server processes duplicate execution of step {}",
                    step.step_id
                ),
                manipulation: None,
                payload: None,
            });
        }
        attacks
    }

    /// Detect state violations by checking that each step's expected_state_before
    /// matches the previous step's expected_state_after.
    pub fn detect_state_violations(&self, workflow: &WorkflowDefinition) -> Vec<StateViolation> {
        let steps = &workflow.steps;
        let mut violations = Vec::new();

        for window in steps.windows(2) {
            let prev = &window[0];
            let curr = &window[1];
            if prev.expected_state_after != curr.expected_state_before {
                violations.push(StateViolation {
                    step_id: curr.step_id,
                    expected_state: curr.expected_state_before.clone(),
                    observed_state: prev.expected_state_after.clone(),
                    violation_type: "state_mismatch".into(),
                });
            }
        }
        violations
    }

    /// Run the full fuzzing pipeline: analyze, detect violations, produce findings.
    pub fn fuzz_workflow(&self, workflow: &WorkflowDefinition) -> Vec<BizLogicFinding> {
        let scenarios = self.analyze_workflow(workflow);
        let violations = self.detect_state_violations(workflow);
        let mut findings = Vec::new();

        findings.extend(scenarios_to_findings(&scenarios));
        findings.extend(violations_to_findings(&violations));
        findings
    }

    /// Generate a summary report from a fuzzing run.
    pub fn generate_report(&self, workflow: &WorkflowDefinition) -> FuzzReport {
        let findings = self.fuzz_workflow(workflow);
        let scenarios = self.analyze_workflow(workflow);
        let mut by_type: HashMap<String, usize> = HashMap::new();

        for scenario in &scenarios {
            *by_type.entry(scenario.attack.to_string()).or_insert(0) += 1;
        }

        let critical_count = findings
            .iter()
            .filter(|f| f.severity == BizSeverity::Critical)
            .count();
        let high_count = findings
            .iter()
            .filter(|f| f.severity == BizSeverity::High)
            .count();

        FuzzReport {
            workflow_name: workflow.name.clone(),
            total_scenarios: scenarios.len(),
            findings,
            scenarios_by_type: by_type,
            critical_count,
            high_count,
        }
    }

    /// Reference to the loaded price manipulation payloads.
    pub fn price_payloads(&self) -> &[ManipulationPayload] {
        &self.price_payloads
    }

    /// Reference to the fuzzer configuration.
    pub fn config(&self) -> &FuzzerConfig {
        &self.config
    }
}

impl Default for BizLogicFuzzerV2 {
    fn default() -> Self {
        Self::new(FuzzerConfig::default())
    }
}

/// Build the full price/quantity manipulation payloads database.
fn build_price_payload_database() -> Vec<ManipulationPayload> {
    vec![
        ManipulationPayload {
            manipulation_type: ManipulationType::PriceModification,
            param_name: "price".into(),
            original_value: "49.99".into(),
            malicious_value: "0.01".into(),
            rationale: "Reduce price to minimum accepted decimal".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::ZeroPrice,
            param_name: "price".into(),
            original_value: "49.99".into(),
            malicious_value: "0".into(),
            rationale: "Zero price to bypass payment".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::PriceModification,
            param_name: "price".into(),
            original_value: "49.99".into(),
            malicious_value: "-49.99".into(),
            rationale: "Negative price to trigger credit".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::QuantityOverflow,
            param_name: "quantity".into(),
            original_value: "1".into(),
            malicious_value: "2147483647".into(),
            rationale: "i32 max to overflow server-side multiplication".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::NegativeQuantity,
            param_name: "quantity".into(),
            original_value: "1".into(),
            malicious_value: "-1".into(),
            rationale: "Negative quantity to trigger refund/credit path".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::QuantityOverflow,
            param_name: "quantity".into(),
            original_value: "1".into(),
            malicious_value: "999999999".into(),
            rationale: "Large quantity to exceed stock or trigger overflow".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::CurrencySwitch,
            param_name: "currency".into(),
            original_value: "USD".into(),
            malicious_value: "VND".into(),
            rationale: "Switch to weaker currency denomination".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::DiscountStacking,
            param_name: "discount".into(),
            original_value: "10".into(),
            malicious_value: "100".into(),
            rationale: "100% discount to zero out total".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::DiscountStacking,
            param_name: "discount".into(),
            original_value: "10".into(),
            malicious_value: "200".into(),
            rationale: "Discount exceeding 100% to generate credit".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::CouponReuse,
            param_name: "coupon".into(),
            original_value: "SAVE10".into(),
            malicious_value: "SAVE10".into(),
            rationale: "Replay same coupon code after prior redemption".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::BalanceManipulation,
            param_name: "balance".into(),
            original_value: "100.00".into(),
            malicious_value: "999999.99".into(),
            rationale: "Inflate balance field to gain funds".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::BalanceManipulation,
            param_name: "credits".into(),
            original_value: "0".into(),
            malicious_value: "99999".into(),
            rationale: "Inject credits value via parameter tampering".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::PriceModification,
            param_name: "amount".into(),
            original_value: "150.00".into(),
            malicious_value: "0.01".into(),
            rationale: "Reduce payment amount to minimum".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::ZeroPrice,
            param_name: "total".into(),
            original_value: "299.99".into(),
            malicious_value: "0".into(),
            rationale: "Zero total to bypass checkout payment".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::PriceModification,
            param_name: "unit_price".into(),
            original_value: "25.00".into(),
            malicious_value: "0.001".into(),
            rationale: "Sub-penny unit price to exploit rounding".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::NegativeQuantity,
            param_name: "qty".into(),
            original_value: "2".into(),
            malicious_value: "-100".into(),
            rationale: "Large negative qty to maximize refund credit".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::PriceModification,
            param_name: "subtotal".into(),
            original_value: "75.00".into(),
            malicious_value: "-1.00".into(),
            rationale: "Negative subtotal to invert charge direction".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::PriceModification,
            param_name: "cost".into(),
            original_value: "500.00".into(),
            malicious_value: "0.00".into(),
            rationale: "Zero cost to skip payment gate".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::PriceModification,
            param_name: "fee".into(),
            original_value: "5.00".into(),
            malicious_value: "-100.00".into(),
            rationale: "Negative fee to credit account".into(),
        },
        ManipulationPayload {
            manipulation_type: ManipulationType::QuantityOverflow,
            param_name: "count".into(),
            original_value: "5".into(),
            malicious_value: "4294967295".into(),
            rationale: "u32 max to overflow unsigned arithmetic".into(),
        },
    ]
}

/// Generate permutations by swapping each pair of adjacent elements.
fn generate_adjacent_swaps(ids: &[u32]) -> Vec<Vec<u32>> {
    let mut result = Vec::new();
    for i in 0..ids.len().saturating_sub(1) {
        let mut swapped = ids.to_vec();
        swapped.swap(i, i + 1);
        if swapped != ids {
            result.push(swapped);
        }
    }
    result
}

/// Convert attack scenarios into preliminary findings.
fn scenarios_to_findings(scenarios: &[AttackScenario]) -> Vec<BizLogicFinding> {
    scenarios
        .iter()
        .map(|s| {
            let severity = match s.attack {
                WorkflowAttack::ParallelExecution => BizSeverity::Critical,
                WorkflowAttack::StepSkip => BizSeverity::High,
                WorkflowAttack::StateManipulation => severity_for_manipulation(s.manipulation),
                WorkflowAttack::StepRollback => BizSeverity::Medium,
                WorkflowAttack::StepRepeat => BizSeverity::Medium,
                WorkflowAttack::StepReorder => BizSeverity::High,
            };
            let reproducibility = match s.attack {
                WorkflowAttack::ParallelExecution => Reproducibility::RaceDependent,
                _ => Reproducibility::Always,
            };
            BizLogicFinding {
                attack_type: s.attack,
                affected_steps: s.steps_to_execute.clone(),
                description: s.description.clone(),
                impact: s.expected_violation.clone(),
                severity,
                evidence: vec![format!("Generated scenario: {}", s.description)],
                reproducibility,
            }
        })
        .collect()
}

/// Determine severity for state manipulation based on the specific manipulation type.
fn severity_for_manipulation(manipulation: Option<ManipulationType>) -> BizSeverity {
    match manipulation {
        Some(ManipulationType::BalanceManipulation) => BizSeverity::Critical,
        Some(ManipulationType::ZeroPrice) => BizSeverity::Critical,
        Some(ManipulationType::NegativeQuantity) => BizSeverity::High,
        Some(ManipulationType::QuantityOverflow) => BizSeverity::High,
        Some(ManipulationType::PriceModification) => BizSeverity::High,
        Some(ManipulationType::CurrencySwitch) => BizSeverity::High,
        Some(ManipulationType::DiscountStacking) => BizSeverity::High,
        Some(ManipulationType::CouponReuse) => BizSeverity::Medium,
        None => BizSeverity::Medium,
    }
}

/// Convert state violations into findings.
fn violations_to_findings(violations: &[StateViolation]) -> Vec<BizLogicFinding> {
    violations
        .iter()
        .map(|v| BizLogicFinding {
            attack_type: WorkflowAttack::StateManipulation,
            affected_steps: vec![v.step_id],
            description: format!(
                "State mismatch at step {}: expected '{}', got '{}'",
                v.step_id, v.expected_state, v.observed_state,
            ),
            impact: format!(
                "Workflow state inconsistency — step {} may execute with wrong preconditions",
                v.step_id,
            ),
            severity: BizSeverity::Medium,
            evidence: vec![format!(
                "expected_state_before='{}' != prev.expected_state_after='{}'",
                v.expected_state, v.observed_state,
            )],
            reproducibility: Reproducibility::Always,
        })
        .collect()
}
