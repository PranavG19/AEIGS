use std::collections::{HashMap, HashSet};

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;

/// An observed HTTP request in a workflow sequence.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedRequest {
    pub method: String,
    pub path: String,
    pub parameters: Vec<String>,
    pub status_code: u16,
    pub requires_auth: bool,
}

/// A transition between two application states, derived from sequential requests.
#[derive(Debug, Clone)]
pub struct StateTransition {
    pub from_state: String,
    pub to_state: String,
    pub required_parameters: Vec<String>,
    pub requires_auth: bool,
    pub method: String,
}

/// A node in the inferred state machine representing an application state.
#[derive(Debug, Clone, PartialEq)]
pub struct StateMachineNode {
    pub state_name: String,
    pub endpoint: String,
    pub method: String,
    pub step_index: usize,
}

/// Edge weight carrying transition metadata.
#[derive(Debug, Clone)]
pub struct StateMachineEdge {
    pub required_parameters: Vec<String>,
    pub requires_auth: bool,
    pub observation_count: u32,
}

/// Inferred state machine from observed request sequences.
pub struct StateMachineInferer {
    graph: DiGraph<StateMachineNode, StateMachineEdge>,
    node_map: HashMap<String, NodeIndex>,
    transitions: Vec<StateTransition>,
}

/// Category of detected business logic flaw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogicFlawType {
    WorkflowSkip,
    PriceManipulation,
    QuantityManipulation,
    ParameterOverflow,
    Idor,
    CouponStacking,
    RefundCycleAbuse,
    NegativeValue,
    ZeroValue,
}

impl std::fmt::Display for LogicFlawType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::WorkflowSkip => "workflow-skip",
            Self::PriceManipulation => "price-manipulation",
            Self::QuantityManipulation => "quantity-manipulation",
            Self::ParameterOverflow => "parameter-overflow",
            Self::Idor => "idor",
            Self::CouponStacking => "coupon-stacking",
            Self::RefundCycleAbuse => "refund-cycle-abuse",
            Self::NegativeValue => "negative-value",
            Self::ZeroValue => "zero-value",
        };
        write!(f, "{label}")
    }
}

/// A detected business logic flaw with a test probe to verify it.
#[derive(Debug, Clone)]
pub struct LogicFlaw {
    pub flaw_type: LogicFlawType,
    pub description: String,
    pub affected_endpoint: String,
    pub severity: FlawSeverity,
    pub probe: TestProbe,
}

/// Severity rating for a business logic flaw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FlawSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for FlawSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{label}")
    }
}

/// A concrete test probe to verify an identified logic flaw.
#[derive(Debug, Clone)]
pub struct TestProbe {
    pub method: String,
    pub path: String,
    pub manipulated_parameters: HashMap<String, String>,
    pub description: String,
    pub expected_behavior: String,
}

impl StateMachineInferer {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
            transitions: Vec::new(),
        }
    }

    /// Feed a sequence of observed requests to build the state machine.
    pub fn ingest_sequence(&mut self, requests: &[ObservedRequest]) {
        if requests.is_empty() {
            return;
        }

        for (i, req) in requests.iter().enumerate() {
            let state_name = state_key(req);
            if !self.node_map.contains_key(&state_name) {
                let node = StateMachineNode {
                    state_name: state_name.clone(),
                    endpoint: req.path.clone(),
                    method: req.method.clone(),
                    step_index: i,
                };
                let idx = self.graph.add_node(node);
                self.node_map.insert(state_name.clone(), idx);
            }
        }

        for window in requests.windows(2) {
            let from = &window[0];
            let to = &window[1];
            let from_key = state_key(from);
            let to_key = state_key(to);

            let transition = StateTransition {
                from_state: from_key.clone(),
                to_state: to_key.clone(),
                required_parameters: to.parameters.clone(),
                requires_auth: to.requires_auth,
                method: to.method.clone(),
            };
            self.transitions.push(transition);

            let from_idx = self.node_map[&from_key];
            let to_idx = self.node_map[&to_key];

            let existing_edge = self.graph.edges_connecting(from_idx, to_idx).next();

            if let Some(edge_ref) = existing_edge {
                let edge_idx = edge_ref.id();
                self.graph[edge_idx].observation_count += 1;
            } else {
                let edge = StateMachineEdge {
                    required_parameters: to.parameters.clone(),
                    requires_auth: to.requires_auth,
                    observation_count: 1,
                };
                self.graph.add_edge(from_idx, to_idx, edge);
            }
        }
    }

    /// All unique state names in the inferred machine.
    pub fn states(&self) -> Vec<&str> {
        self.node_map.keys().map(|s| s.as_str()).collect()
    }

    /// Number of states.
    pub fn state_count(&self) -> usize {
        self.node_map.len()
    }

    /// Number of edges (transitions).
    pub fn transition_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// All recorded transitions.
    pub fn transitions(&self) -> &[StateTransition] {
        &self.transitions
    }

    /// Detect workflow skip attacks: paths that jump over intermediate states.
    /// A skip exists when state i can reach state j (j > i+1) without visiting
    /// the intermediate states in the original observed ordering.
    pub fn detect_skip_attacks(&self) -> Vec<SkipAttack> {
        let mut attacks = Vec::new();

        let mut ordered_states: Vec<(&String, &NodeIndex)> = self.node_map.iter().collect();
        ordered_states.sort_by_key(|(_, idx)| self.graph[**idx].step_index);

        for i in 0..ordered_states.len() {
            for j in (i + 2)..ordered_states.len() {
                let (from_name, &from_idx) = ordered_states[i];
                let (to_name, &to_idx) = ordered_states[j];

                let has_direct_edge = self
                    .graph
                    .edges_connecting(from_idx, to_idx)
                    .next()
                    .is_some();

                if !has_direct_edge {
                    let skipped: Vec<String> = ordered_states[i + 1..j]
                        .iter()
                        .map(|(name, _)| (*name).clone())
                        .collect();

                    let to_node = &self.graph[to_idx];

                    attacks.push(SkipAttack {
                        from_state: from_name.clone(),
                        to_state: to_name.clone(),
                        skipped_states: skipped,
                        target_endpoint: to_node.endpoint.clone(),
                        target_method: to_node.method.clone(),
                    });
                }
            }
        }

        attacks
    }

    /// Return states that have no incoming edges (potential entry points).
    pub fn entry_states(&self) -> Vec<String> {
        self.node_map
            .iter()
            .filter(|(_, idx)| {
                self.graph
                    .neighbors_directed(**idx, petgraph::Direction::Incoming)
                    .next()
                    .is_none()
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Return states that have no outgoing edges (terminal states).
    pub fn terminal_states(&self) -> Vec<String> {
        self.node_map
            .iter()
            .filter(|(_, idx)| {
                self.graph
                    .neighbors_directed(**idx, petgraph::Direction::Outgoing)
                    .next()
                    .is_none()
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Get the node for a given state name.
    pub fn get_state(&self, name: &str) -> Option<&StateMachineNode> {
        self.node_map.get(name).map(|&idx| &self.graph[idx])
    }

    /// Reference to the inner petgraph for inspection.
    pub fn inner_graph(&self) -> &DiGraph<StateMachineNode, StateMachineEdge> {
        &self.graph
    }
}

impl Default for StateMachineInferer {
    fn default() -> Self {
        Self::new()
    }
}

/// A detected workflow skip attack.
#[derive(Debug, Clone)]
pub struct SkipAttack {
    pub from_state: String,
    pub to_state: String,
    pub skipped_states: Vec<String>,
    pub target_endpoint: String,
    pub target_method: String,
}

/// Generates test probes for common business logic flaws based on observed requests
/// and an inferred state machine.
pub struct BusinessLogicProbe;

impl BusinessLogicProbe {
    /// Analyze a request sequence and inferred state machine, returning all detected flaws
    /// with concrete test probes.
    pub fn analyze(inferer: &StateMachineInferer, requests: &[ObservedRequest]) -> Vec<LogicFlaw> {
        let mut flaws = Vec::new();
        flaws.extend(Self::detect_skip_flaws(inferer));
        flaws.extend(Self::detect_manipulation_flaws(requests));
        flaws.extend(Self::detect_idor_flaws(requests));
        flaws.extend(Self::detect_coupon_stacking(requests));
        flaws.extend(Self::detect_refund_cycle(requests));
        flaws
    }

    /// Generate skip-attack probes from the state machine.
    pub fn detect_skip_flaws(inferer: &StateMachineInferer) -> Vec<LogicFlaw> {
        inferer
            .detect_skip_attacks()
            .into_iter()
            .map(|skip| {
                let probe = TestProbe {
                    method: skip.target_method.clone(),
                    path: skip.target_endpoint.clone(),
                    manipulated_parameters: HashMap::new(),
                    description: format!(
                        "Attempt direct access to {} skipping {}",
                        skip.to_state,
                        skip.skipped_states.join(", ")
                    ),
                    expected_behavior:
                        "Server should reject the request or redirect to the correct step"
                            .to_string(),
                };
                LogicFlaw {
                    flaw_type: LogicFlawType::WorkflowSkip,
                    description: format!(
                        "Workflow skip from {} to {} bypasses {} intermediate state(s)",
                        skip.from_state,
                        skip.to_state,
                        skip.skipped_states.len()
                    ),
                    affected_endpoint: skip.target_endpoint,
                    severity: FlawSeverity::High,
                    probe,
                }
            })
            .collect()
    }

    /// Detect price/quantity manipulation opportunities from parameters.
    pub fn detect_manipulation_flaws(requests: &[ObservedRequest]) -> Vec<LogicFlaw> {
        let mut flaws = Vec::new();
        let manipulation_params: HashSet<&str> = [
            "price",
            "amount",
            "total",
            "cost",
            "quantity",
            "qty",
            "count",
            "discount",
            "subtotal",
            "unit_price",
        ]
        .iter()
        .copied()
        .collect();

        for req in requests {
            for param in &req.parameters {
                let param_lower = param.to_lowercase();
                if !manipulation_params
                    .iter()
                    .any(|&mp| param_lower.contains(mp))
                {
                    continue;
                }

                let is_price = ["price", "amount", "total", "cost", "subtotal", "unit_price"]
                    .iter()
                    .any(|&p| param_lower.contains(p));
                let is_quantity = ["quantity", "qty", "count"]
                    .iter()
                    .any(|&q| param_lower.contains(q));

                if is_price {
                    flaws.push(build_manipulation_flaw(
                        LogicFlawType::NegativeValue,
                        param,
                        &req.path,
                        &req.method,
                        "-1",
                        "Negative price value to trigger credit/refund",
                        FlawSeverity::Critical,
                    ));
                    flaws.push(build_manipulation_flaw(
                        LogicFlawType::ZeroValue,
                        param,
                        &req.path,
                        &req.method,
                        "0",
                        "Zero price to get items for free",
                        FlawSeverity::High,
                    ));
                    flaws.push(build_manipulation_flaw(
                        LogicFlawType::PriceManipulation,
                        param,
                        &req.path,
                        &req.method,
                        "0.01",
                        "Minimal price to reduce cost",
                        FlawSeverity::High,
                    ));
                }

                if is_quantity {
                    flaws.push(build_manipulation_flaw(
                        LogicFlawType::NegativeValue,
                        param,
                        &req.path,
                        &req.method,
                        "-1",
                        "Negative quantity to trigger refund logic",
                        FlawSeverity::Critical,
                    ));
                    flaws.push(build_manipulation_flaw(
                        LogicFlawType::ZeroValue,
                        param,
                        &req.path,
                        &req.method,
                        "0",
                        "Zero quantity to bypass minimum checks",
                        FlawSeverity::Medium,
                    ));
                    flaws.push(build_manipulation_flaw(
                        LogicFlawType::QuantityManipulation,
                        param,
                        &req.path,
                        &req.method,
                        "999999999",
                        "Overflow quantity to trigger integer overflow",
                        FlawSeverity::High,
                    ));
                    flaws.push(build_manipulation_flaw(
                        LogicFlawType::ParameterOverflow,
                        param,
                        &req.path,
                        &req.method,
                        "2147483647",
                        "Max i32 to trigger overflow on server-side arithmetic",
                        FlawSeverity::High,
                    ));
                }

                if param_lower.contains("discount") {
                    flaws.push(build_manipulation_flaw(
                        LogicFlawType::PriceManipulation,
                        param,
                        &req.path,
                        &req.method,
                        "100",
                        "100% discount to get items for free",
                        FlawSeverity::Critical,
                    ));
                    flaws.push(build_manipulation_flaw(
                        LogicFlawType::PriceManipulation,
                        param,
                        &req.path,
                        &req.method,
                        "200",
                        "Discount exceeding 100% to trigger credit",
                        FlawSeverity::Critical,
                    ));
                }
            }
        }

        flaws
    }

    /// Detect IDOR opportunities on state-transition endpoints by looking for
    /// id-like parameters.
    pub fn detect_idor_flaws(requests: &[ObservedRequest]) -> Vec<LogicFlaw> {
        let mut flaws = Vec::new();
        let id_patterns: HashSet<&str> = [
            "id",
            "user_id",
            "order_id",
            "account_id",
            "customer_id",
            "item_id",
            "product_id",
            "session_id",
            "cart_id",
            "invoice_id",
        ]
        .iter()
        .copied()
        .collect();

        for req in requests {
            for param in &req.parameters {
                let param_lower = param.to_lowercase();
                if !id_patterns
                    .iter()
                    .any(|&p| param_lower == p || param_lower.ends_with(&format!("_{p}")))
                {
                    continue;
                }

                let mut manipulated = HashMap::new();
                manipulated.insert(param.clone(), "OTHER_USER_VALUE".to_string());

                let probe = TestProbe {
                    method: req.method.clone(),
                    path: req.path.clone(),
                    manipulated_parameters: manipulated,
                    description: format!(
                        "Replace {} with another user's value on {} {}",
                        param, req.method, req.path
                    ),
                    expected_behavior: "Server should return 403 Forbidden or 404 Not Found"
                        .to_string(),
                };

                flaws.push(LogicFlaw {
                    flaw_type: LogicFlawType::Idor,
                    description: format!(
                        "IDOR via {} parameter on {} {}",
                        param, req.method, req.path
                    ),
                    affected_endpoint: req.path.clone(),
                    severity: FlawSeverity::High,
                    probe,
                });
            }
        }

        flaws
    }

    /// Detect coupon/discount stacking opportunities.
    pub fn detect_coupon_stacking(requests: &[ObservedRequest]) -> Vec<LogicFlaw> {
        let mut flaws = Vec::new();
        let coupon_indicators: HashSet<&str> = [
            "coupon",
            "coupon_code",
            "promo",
            "promo_code",
            "voucher",
            "discount_code",
            "gift_code",
            "referral_code",
        ]
        .iter()
        .copied()
        .collect();

        for req in requests {
            let has_coupon = req.parameters.iter().any(|p| {
                let lower = p.to_lowercase();
                coupon_indicators.iter().any(|&c| lower.contains(c))
            });

            if !has_coupon {
                continue;
            }

            let coupon_param = req
                .parameters
                .iter()
                .find(|p| {
                    let lower = p.to_lowercase();
                    coupon_indicators.iter().any(|&c| lower.contains(c))
                })
                .cloned()
                .unwrap_or_else(|| "coupon_code".to_string());

            let mut params = HashMap::new();
            params.insert(coupon_param.clone(), "CODE1,CODE2,CODE3".to_string());

            let probe = TestProbe {
                method: req.method.clone(),
                path: req.path.clone(),
                manipulated_parameters: params,
                description: format!(
                    "Apply multiple coupon codes simultaneously via {} on {} {}",
                    coupon_param, req.method, req.path
                ),
                expected_behavior: "Server should reject multiple coupons or apply only one"
                    .to_string(),
            };

            flaws.push(LogicFlaw {
                flaw_type: LogicFlawType::CouponStacking,
                description: format!(
                    "Potential coupon stacking via {} on {} {}",
                    coupon_param, req.method, req.path
                ),
                affected_endpoint: req.path.clone(),
                severity: FlawSeverity::High,
                probe,
            });
        }

        flaws
    }

    /// Detect refund/credit cycle abuse: if a refund endpoint exists alongside
    /// a purchase endpoint, an attacker may cycle between them.
    pub fn detect_refund_cycle(requests: &[ObservedRequest]) -> Vec<LogicFlaw> {
        let mut flaws = Vec::new();
        let refund_keywords = ["refund", "return", "cancel", "credit", "chargeback"];
        let purchase_keywords = ["purchase", "checkout", "pay", "buy", "order", "charge"];

        let refund_endpoints: Vec<&ObservedRequest> = requests
            .iter()
            .filter(|r| {
                let path_lower = r.path.to_lowercase();
                refund_keywords.iter().any(|&k| path_lower.contains(k))
            })
            .collect();

        let has_purchase = requests.iter().any(|r| {
            let path_lower = r.path.to_lowercase();
            purchase_keywords.iter().any(|&k| path_lower.contains(k))
        });

        if !has_purchase {
            return flaws;
        }

        for refund_req in &refund_endpoints {
            let mut params = HashMap::new();
            for p in &refund_req.parameters {
                params.insert(p.clone(), "PREVIOUSLY_REFUNDED_ID".to_string());
            }

            let probe = TestProbe {
                method: refund_req.method.clone(),
                path: refund_req.path.clone(),
                manipulated_parameters: params,
                description: format!(
                    "Repeat refund request on {} {} to double-credit",
                    refund_req.method, refund_req.path
                ),
                expected_behavior:
                    "Server should reject duplicate refund or mark order as already refunded"
                        .to_string(),
            };

            flaws.push(LogicFlaw {
                flaw_type: LogicFlawType::RefundCycleAbuse,
                description: format!(
                    "Refund cycle abuse on {} {}; purchase flow exists",
                    refund_req.method, refund_req.path
                ),
                affected_endpoint: refund_req.path.clone(),
                severity: FlawSeverity::Critical,
                probe,
            });
        }

        flaws
    }
}

fn state_key(req: &ObservedRequest) -> String {
    format!("{}:{}", req.method, req.path)
}

fn build_manipulation_flaw(
    flaw_type: LogicFlawType,
    param: &str,
    path: &str,
    method: &str,
    value: &str,
    description: &str,
    severity: FlawSeverity,
) -> LogicFlaw {
    let mut params = HashMap::new();
    params.insert(param.to_string(), value.to_string());

    LogicFlaw {
        flaw_type,
        description: format!(
            "{} on {} {} via {} parameter",
            description, method, path, param
        ),
        affected_endpoint: path.to_string(),
        severity,
        probe: TestProbe {
            method: method.to_string(),
            path: path.to_string(),
            manipulated_parameters: params,
            description: format!("Set {}={} on {} {}", param, value, method, path),
            expected_behavior: "Server should validate and reject the manipulated value"
                .to_string(),
        },
    }
}
