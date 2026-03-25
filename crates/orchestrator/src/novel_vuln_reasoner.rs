/// Novel vulnerability reasoner: first-principles reasoning about application logic.
///
/// Identifies business logic flaws, race conditions, state machine violations,
/// and auth bypasses that don't map to any standard CWE. Analyzes API response
/// sequences, parameter relationships, and state transitions to form hypotheses
/// about semantic vulnerabilities unique to the target.
use aegis_protocol::finding::{EvidenceLevel, VulnerabilityClass};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// An observed API interaction captured during crawling/fuzzing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiInteraction {
    pub endpoint: String,
    pub method: String,
    pub parameters: HashMap<String, String>,
    pub response_status: u16,
    pub response_body_sample: String,
    pub response_time_ms: u64,
    pub session_state: Option<String>,
    pub sequence_position: usize,
}

/// A detected state transition in the application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub from_state: String,
    pub to_state: String,
    pub trigger_endpoint: String,
    pub trigger_method: String,
    pub required_params: Vec<String>,
    pub observed_count: usize,
}

/// A parameter relationship discovered between endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterRelationship {
    pub source_endpoint: String,
    pub source_param: String,
    pub target_endpoint: String,
    pub target_param: String,
    pub relationship_type: RelationshipType,
    pub strength: f64,
}

/// How two parameters relate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationshipType {
    IdentityLink,
    ForeignKeyRef,
    TokenReuse,
    DerivedValue,
    InverseControl,
    SequenceCounter,
}

/// Category of novel vulnerability.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NovelVulnCategory {
    BusinessLogicFlaw,
    RaceCondition,
    StateMachineViolation,
    AuthorizationBypass,
    MassAssignmentChain,
    IdorViaParameterTampering,
    TimeOfCheckTimeOfUse,
    InsufficientWorkflowValidation,
    PriceManipulation,
    InventoryDesync,
    Custom(String),
}

/// A hypothesis about a novel vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NovelVulnHypothesis {
    pub id: String,
    pub category: NovelVulnCategory,
    pub description: String,
    pub affected_endpoints: Vec<String>,
    pub reasoning_chain: Vec<String>,
    pub confidence: f64,
    pub evidence_level: EvidenceLevel,
    pub exploitation_sketch: String,
    pub impact_assessment: String,
    pub closest_cwe: Option<String>,
    pub test_procedure: Vec<String>,
}

/// Input context for the reasoner.
#[derive(Debug, Clone)]
pub struct ReasonerContext {
    pub interactions: Vec<ApiInteraction>,
    pub state_transitions: Vec<StateTransition>,
    pub parameter_relationships: Vec<ParameterRelationship>,
    pub known_vulns: Vec<VulnerabilityClass>,
    pub auth_endpoints: Vec<String>,
    pub admin_endpoints: Vec<String>,
    pub payment_endpoints: Vec<String>,
}

/// Result of novel vulnerability reasoning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasonerResult {
    pub hypotheses: Vec<NovelVulnHypothesis>,
    pub reasoning_log: Vec<String>,
    pub analyzed_interactions: usize,
    pub analyzed_transitions: usize,
    pub categories_found: Vec<NovelVulnCategory>,
}

/// Reason about the application to discover novel vulnerabilities.
pub fn reason_about_target(ctx: &ReasonerContext) -> ReasonerResult {
    let mut hypotheses = Vec::new();
    let mut reasoning_log = Vec::new();
    let mut hypothesis_counter = 0u32;

    reasoning_log.push(format!(
        "Analyzing {} interactions, {} state transitions, {} parameter relationships",
        ctx.interactions.len(),
        ctx.state_transitions.len(),
        ctx.parameter_relationships.len()
    ));

    detect_race_conditions(
        ctx,
        &mut hypotheses,
        &mut hypothesis_counter,
        &mut reasoning_log,
    );
    detect_state_machine_violations(
        ctx,
        &mut hypotheses,
        &mut hypothesis_counter,
        &mut reasoning_log,
    );
    detect_auth_bypasses(
        ctx,
        &mut hypotheses,
        &mut hypothesis_counter,
        &mut reasoning_log,
    );
    detect_business_logic_flaws(
        ctx,
        &mut hypotheses,
        &mut hypothesis_counter,
        &mut reasoning_log,
    );
    detect_parameter_tampering(
        ctx,
        &mut hypotheses,
        &mut hypothesis_counter,
        &mut reasoning_log,
    );
    detect_toctou(
        ctx,
        &mut hypotheses,
        &mut hypothesis_counter,
        &mut reasoning_log,
    );

    hypotheses.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let categories_found: Vec<NovelVulnCategory> = hypotheses
        .iter()
        .map(|h| h.category.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    reasoning_log.push(format!(
        "Reasoning complete: {} hypotheses across {} categories",
        hypotheses.len(),
        categories_found.len()
    ));

    ReasonerResult {
        hypotheses,
        reasoning_log,
        analyzed_interactions: ctx.interactions.len(),
        analyzed_transitions: ctx.state_transitions.len(),
        categories_found,
    }
}

fn detect_race_conditions(
    ctx: &ReasonerContext,
    hypotheses: &mut Vec<NovelVulnHypothesis>,
    counter: &mut u32,
    log: &mut Vec<String>,
) {
    let state_mutating: Vec<&ApiInteraction> = ctx
        .interactions
        .iter()
        .filter(|i| matches!(i.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE"))
        .collect();

    let mut endpoint_groups: HashMap<&str, Vec<&ApiInteraction>> = HashMap::new();
    for interaction in &state_mutating {
        endpoint_groups
            .entry(&interaction.endpoint)
            .or_default()
            .push(interaction);
    }

    for (endpoint, interactions) in &endpoint_groups {
        if interactions.len() < 2 {
            continue;
        }

        let has_timing_variance = interactions.windows(2).any(|w| {
            let diff = if w[0].response_time_ms > w[1].response_time_ms {
                w[0].response_time_ms - w[1].response_time_ms
            } else {
                w[1].response_time_ms - w[0].response_time_ms
            };
            diff > 50
        });

        if has_timing_variance {
            *counter += 1;
            log.push(format!(
                "Race condition candidate: {} has variable response times on state-mutating requests",
                endpoint
            ));

            hypotheses.push(NovelVulnHypothesis {
                id: format!("novel-{counter:03}"),
                category: NovelVulnCategory::RaceCondition,
                description: format!(
                    "Potential race condition on {} — concurrent state-mutating requests may interleave without proper locking",
                    endpoint
                ),
                affected_endpoints: vec![endpoint.to_string()],
                reasoning_chain: vec![
                    format!("Observed {} state-mutating requests to {}", interactions.len(), endpoint),
                    "Response time variance suggests non-atomic operation".to_string(),
                    "Concurrent requests may exploit TOCTOU window".to_string(),
                ],
                confidence: 0.55,
                evidence_level: EvidenceLevel::Statistical,
                exploitation_sketch: format!(
                    "Send {} concurrent POST/PUT requests to {} with conflicting state mutations",
                    interactions.len().min(10),
                    endpoint
                ),
                impact_assessment: "May allow double-spend, inventory desync, or privilege confusion".to_string(),
                closest_cwe: Some("CWE-362".to_string()),
                test_procedure: vec![
                    format!("Send 10 concurrent requests to {} with identical parameters", endpoint),
                    "Compare final state against expected single-execution state".to_string(),
                    "Check for duplicate records, incorrect balances, or inconsistent state".to_string(),
                ],
            });
        }
    }
}

fn detect_state_machine_violations(
    ctx: &ReasonerContext,
    hypotheses: &mut Vec<NovelVulnHypothesis>,
    counter: &mut u32,
    log: &mut Vec<String>,
) {
    if ctx.state_transitions.len() < 2 {
        return;
    }

    let mut from_states: HashMap<&str, Vec<&StateTransition>> = HashMap::new();
    for transition in &ctx.state_transitions {
        from_states
            .entry(&transition.from_state)
            .or_default()
            .push(transition);
    }

    for (from, transitions) in &from_states {
        let to_states: Vec<&str> = transitions.iter().map(|t| t.to_state.as_str()).collect();
        let unique_to: HashSet<&&str> = to_states.iter().collect();

        if unique_to.len() > 2 {
            *counter += 1;
            log.push(format!(
                "State machine complexity: state '{}' can transition to {} different states",
                from,
                unique_to.len()
            ));

            let endpoints: Vec<String> = transitions
                .iter()
                .map(|t| t.trigger_endpoint.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            hypotheses.push(NovelVulnHypothesis {
                id: format!("novel-{counter:03}"),
                category: NovelVulnCategory::StateMachineViolation,
                description: format!(
                    "Complex state machine from '{}' with {} outgoing transitions — may allow invalid state skipping",
                    from,
                    unique_to.len()
                ),
                affected_endpoints: endpoints.clone(),
                reasoning_chain: vec![
                    format!("State '{}' has {} possible transitions", from, unique_to.len()),
                    "High fan-out increases probability of unchecked skip paths".to_string(),
                    "Direct requests to later-stage endpoints may bypass workflow steps".to_string(),
                ],
                confidence: 0.50,
                evidence_level: EvidenceLevel::Statistical,
                exploitation_sketch: format!(
                    "Skip intermediate states by directly calling {} without prior state setup",
                    endpoints.first().map(|s| s.as_str()).unwrap_or("target endpoint")
                ),
                impact_assessment: "May bypass payment, verification, or approval steps".to_string(),
                closest_cwe: Some("CWE-841".to_string()),
                test_procedure: vec![
                    "Map complete state machine via sequential API calls".to_string(),
                    "Attempt each transition without prerequisite state".to_string(),
                    "Check if later-stage endpoints accept requests without prior steps".to_string(),
                ],
            });
        }
    }
}

fn detect_auth_bypasses(
    ctx: &ReasonerContext,
    hypotheses: &mut Vec<NovelVulnHypothesis>,
    counter: &mut u32,
    log: &mut Vec<String>,
) {
    for admin_ep in &ctx.admin_endpoints {
        let admin_interactions: Vec<&ApiInteraction> = ctx
            .interactions
            .iter()
            .filter(|i| i.endpoint == *admin_ep)
            .collect();

        let has_success_without_auth = admin_interactions
            .iter()
            .any(|i| i.response_status == 200 && i.session_state.is_none());

        if has_success_without_auth {
            *counter += 1;
            log.push(format!(
                "Auth bypass candidate: {} returned 200 without session state",
                admin_ep
            ));

            hypotheses.push(NovelVulnHypothesis {
                id: format!("novel-{counter:03}"),
                category: NovelVulnCategory::AuthorizationBypass,
                description: format!(
                    "Admin endpoint {} accessible without authentication — missing authorization check",
                    admin_ep
                ),
                affected_endpoints: vec![admin_ep.clone()],
                reasoning_chain: vec![
                    format!("Endpoint {} is classified as admin-only", admin_ep),
                    "Observed successful (200) response without session/auth token".to_string(),
                    "Authorization check missing or bypassable".to_string(),
                ],
                confidence: 0.80,
                evidence_level: EvidenceLevel::Controlled,
                exploitation_sketch: format!(
                    "Access {} directly without authentication cookies/tokens",
                    admin_ep
                ),
                impact_assessment: "Full administrative access without credentials".to_string(),
                closest_cwe: Some("CWE-862".to_string()),
                test_procedure: vec![
                    format!("Send unauthenticated GET/POST to {}", admin_ep),
                    "Verify response contains admin-level data or functionality".to_string(),
                    "Test with various HTTP methods (GET, POST, PUT)".to_string(),
                ],
            });
        }
    }
}

fn detect_business_logic_flaws(
    ctx: &ReasonerContext,
    hypotheses: &mut Vec<NovelVulnHypothesis>,
    counter: &mut u32,
    log: &mut Vec<String>,
) {
    for payment_ep in &ctx.payment_endpoints {
        let payment_interactions: Vec<&ApiInteraction> = ctx
            .interactions
            .iter()
            .filter(|i| i.endpoint == *payment_ep)
            .collect();

        let has_numeric_params = payment_interactions.iter().any(|i| {
            i.parameters
                .keys()
                .any(|k| k.contains("amount") || k.contains("price") || k.contains("quantity"))
        });

        if has_numeric_params {
            *counter += 1;
            log.push(format!(
                "Business logic flaw candidate: {} accepts numeric parameters that may be manipulated",
                payment_ep
            ));

            hypotheses.push(NovelVulnHypothesis {
                id: format!("novel-{counter:03}"),
                category: NovelVulnCategory::PriceManipulation,
                description: format!(
                    "Payment endpoint {} accepts client-controlled amount/price/quantity parameters",
                    payment_ep
                ),
                affected_endpoints: vec![payment_ep.clone()],
                reasoning_chain: vec![
                    format!("Endpoint {} handles financial transaction", payment_ep),
                    "Client-supplied numeric parameters detected (amount/price/quantity)".to_string(),
                    "Server-side validation of amounts may be insufficient".to_string(),
                    "Negative values, zero amounts, or overflow values may be accepted".to_string(),
                ],
                confidence: 0.60,
                evidence_level: EvidenceLevel::Statistical,
                exploitation_sketch: format!(
                    "Submit request to {} with amount=-1, price=0, or quantity=999999",
                    payment_ep
                ),
                impact_assessment: "Financial loss via price manipulation or free purchases".to_string(),
                closest_cwe: Some("CWE-840".to_string()),
                test_procedure: vec![
                    format!("Send request to {} with amount=0", payment_ep),
                    format!("Send request to {} with amount=-1", payment_ep),
                    format!("Send request to {} with quantity=99999999", payment_ep),
                    "Compare resulting charges/orders against expected values".to_string(),
                ],
            });
        }
    }
}

fn detect_parameter_tampering(
    ctx: &ReasonerContext,
    hypotheses: &mut Vec<NovelVulnHypothesis>,
    counter: &mut u32,
    log: &mut Vec<String>,
) {
    for rel in &ctx.parameter_relationships {
        if rel.relationship_type == RelationshipType::ForeignKeyRef && rel.strength > 0.7 {
            *counter += 1;
            log.push(format!(
                "Parameter tampering candidate: {}.{} → {}.{} (foreign key ref, strength {:.2})",
                rel.source_endpoint,
                rel.source_param,
                rel.target_endpoint,
                rel.target_param,
                rel.strength
            ));

            hypotheses.push(NovelVulnHypothesis {
                id: format!("novel-{counter:03}"),
                category: NovelVulnCategory::IdorViaParameterTampering,
                description: format!(
                    "Parameter {}.{} references {}.{} — enumerable foreign key may expose other users' resources",
                    rel.source_endpoint, rel.source_param, rel.target_endpoint, rel.target_param
                ),
                affected_endpoints: vec![
                    rel.source_endpoint.clone(),
                    rel.target_endpoint.clone(),
                ],
                reasoning_chain: vec![
                    format!(
                        "Parameter {} on {} correlates with {} on {} (strength: {:.2})",
                        rel.source_param,
                        rel.source_endpoint,
                        rel.target_param,
                        rel.target_endpoint,
                        rel.strength
                    ),
                    "Foreign key relationship suggests enumerable resource identifiers".to_string(),
                    "Tampering with this parameter may access other users' data".to_string(),
                ],
                confidence: 0.65,
                evidence_level: EvidenceLevel::Statistical,
                exploitation_sketch: format!(
                    "Enumerate {} values on {} and check if other users' data is returned from {}",
                    rel.source_param, rel.source_endpoint, rel.target_endpoint
                ),
                impact_assessment: "Unauthorized access to other users' resources via IDOR".to_string(),
                closest_cwe: Some("CWE-639".to_string()),
                test_procedure: vec![
                    format!("Get valid {} value from {}", rel.source_param, rel.source_endpoint),
                    format!("Increment/decrement {} and send to {}", rel.target_param, rel.target_endpoint),
                    "Compare responses to detect cross-user data access".to_string(),
                ],
            });
        }
    }
}

fn detect_toctou(
    ctx: &ReasonerContext,
    hypotheses: &mut Vec<NovelVulnHypothesis>,
    counter: &mut u32,
    log: &mut Vec<String>,
) {
    let check_then_use: Vec<(&ApiInteraction, &ApiInteraction)> = ctx
        .interactions
        .windows(2)
        .filter_map(|w| {
            let first = &w[0];
            let second = &w[1];
            if first.method == "GET"
                && matches!(second.method.as_str(), "POST" | "PUT" | "DELETE")
                && first.endpoint == second.endpoint
                && second.sequence_position == first.sequence_position + 1
            {
                Some((first, second))
            } else {
                None
            }
        })
        .collect();

    for (check, use_op) in &check_then_use {
        if check.response_time_ms > 100 {
            *counter += 1;
            log.push(format!(
                "TOCTOU candidate: GET then {} on {} with {}ms check delay",
                use_op.method, check.endpoint, check.response_time_ms
            ));

            hypotheses.push(NovelVulnHypothesis {
                id: format!("novel-{counter:03}"),
                category: NovelVulnCategory::TimeOfCheckTimeOfUse,
                description: format!(
                    "Check-then-use pattern on {} — {}ms window between validation and action",
                    check.endpoint, check.response_time_ms
                ),
                affected_endpoints: vec![check.endpoint.clone()],
                reasoning_chain: vec![
                    format!(
                        "Observed GET (check) followed by {} (use) on {}",
                        use_op.method, check.endpoint
                    ),
                    format!("Check operation takes {}ms — exploitable window", check.response_time_ms),
                    "State may change between check and use operations".to_string(),
                ],
                confidence: 0.45,
                evidence_level: EvidenceLevel::Statistical,
                exploitation_sketch: format!(
                    "Race: send {} to {} immediately after state change that invalidates the prior GET check",
                    use_op.method, check.endpoint
                ),
                impact_assessment: "May bypass validation, spend nonexistent balance, or use revoked permissions".to_string(),
                closest_cwe: Some("CWE-367".to_string()),
                test_procedure: vec![
                    format!("Perform GET check on {}", check.endpoint),
                    "Immediately modify underlying state via separate request".to_string(),
                    format!("Execute {} within the check window", use_op.method),
                    "Verify if stale check result was used".to_string(),
                ],
            });
        }
    }
}

/// Filter hypotheses by minimum confidence threshold.
pub fn hypotheses_above_confidence(
    result: &ReasonerResult,
    threshold: f64,
) -> Vec<&NovelVulnHypothesis> {
    result
        .hypotheses
        .iter()
        .filter(|h| h.confidence >= threshold)
        .collect()
}

/// Filter hypotheses by category.
pub fn hypotheses_by_category<'a>(
    result: &'a ReasonerResult,
    category: &NovelVulnCategory,
) -> Vec<&'a NovelVulnHypothesis> {
    result
        .hypotheses
        .iter()
        .filter(|h| &h.category == category)
        .collect()
}
