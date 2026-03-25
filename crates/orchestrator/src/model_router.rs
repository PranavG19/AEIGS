use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// A model specification: provider, model ID, and capability metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSpec {
    pub provider: String,
    pub model_id: String,
    pub display_name: String,
    pub tier: ModelTier,
    pub cost_per_input_token: f64,
    pub cost_per_output_token: f64,
    pub max_context_tokens: usize,
    pub max_output_tokens: usize,
    pub supports_json_mode: bool,
}

/// Model capability tier — determines which tasks it can handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModelTier {
    Fast,
    Balanced,
    Powerful,
    Creative,
}

impl std::fmt::Display for ModelTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fast => write!(f, "fast"),
            Self::Balanced => write!(f, "balanced"),
            Self::Powerful => write!(f, "powerful"),
            Self::Creative => write!(f, "creative"),
        }
    }
}

/// The type of task being routed, determining model selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskType {
    QuickClassification,
    DeepReasoning,
    PayloadGeneration,
    VulnerabilityAnalysis,
    ReportSynthesis,
    TechStackFingerprinting,
}

impl TaskType {
    /// The preferred model tier for this task type.
    pub fn preferred_tier(&self) -> ModelTier {
        match self {
            Self::QuickClassification => ModelTier::Fast,
            Self::DeepReasoning => ModelTier::Powerful,
            Self::PayloadGeneration => ModelTier::Creative,
            Self::VulnerabilityAnalysis => ModelTier::Powerful,
            Self::ReportSynthesis => ModelTier::Balanced,
            Self::TechStackFingerprinting => ModelTier::Fast,
        }
    }

    /// Whether this task type benefits from JSON output mode.
    pub fn needs_json_mode(&self) -> bool {
        matches!(
            self,
            Self::QuickClassification
                | Self::PayloadGeneration
                | Self::VulnerabilityAnalysis
                | Self::TechStackFingerprinting
        )
    }
}

impl std::fmt::Display for TaskType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QuickClassification => write!(f, "quick_classification"),
            Self::DeepReasoning => write!(f, "deep_reasoning"),
            Self::PayloadGeneration => write!(f, "payload_generation"),
            Self::VulnerabilityAnalysis => write!(f, "vulnerability_analysis"),
            Self::ReportSynthesis => write!(f, "report_synthesis"),
            Self::TechStackFingerprinting => write!(f, "tech_stack_fingerprinting"),
        }
    }
}

/// Configuration for the model router.
#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub models: Vec<ModelSpec>,
    pub fallback_chain: Vec<String>,
    pub cost_budget: Option<f64>,
    pub prefer_json_mode: bool,
    pub tier_overrides: HashMap<TaskType, ModelTier>,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            models: default_model_registry(),
            fallback_chain: vec![
                "anthropic:claude-sonnet-4-20250514".to_string(),
                "anthropic:claude-haiku-4-20250514".to_string(),
            ],
            cost_budget: None,
            prefer_json_mode: true,
            tier_overrides: HashMap::new(),
        }
    }
}

/// Accumulated cost tracking for a scan session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostTracker {
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cost_usd: f64,
    pub cost_by_model: HashMap<String, f64>,
    pub cost_by_task_type: HashMap<String, f64>,
    pub invocation_count: u64,
}

impl CostTracker {
    pub fn new() -> Self {
        Self {
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_cost_usd: 0.0,
            cost_by_model: HashMap::new(),
            cost_by_task_type: HashMap::new(),
            invocation_count: 0,
        }
    }

    /// Record a model invocation.
    pub fn record(
        &mut self,
        model_id: &str,
        task_type: &str,
        input_tokens: u64,
        output_tokens: u64,
        cost_usd: f64,
    ) {
        self.total_input_tokens += input_tokens;
        self.total_output_tokens += output_tokens;
        self.total_cost_usd += cost_usd;
        *self
            .cost_by_model
            .entry(model_id.to_string())
            .or_default() += cost_usd;
        *self
            .cost_by_task_type
            .entry(task_type.to_string())
            .or_default() += cost_usd;
        self.invocation_count += 1;
    }

    /// Check if the cost budget has been exceeded.
    pub fn is_over_budget(&self, budget: f64) -> bool {
        self.total_cost_usd > budget
    }

    /// Remaining budget (None if no budget set).
    pub fn remaining_budget(&self, budget: f64) -> f64 {
        (budget - self.total_cost_usd).max(0.0)
    }
}

impl Default for CostTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of routing a task to a model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingDecision {
    pub selected_model: ModelSpec,
    pub task_type: TaskType,
    pub reason: String,
    pub fallback_models: Vec<String>,
    pub estimated_cost_usd: f64,
}

/// Error from the model router.
#[derive(Debug)]
pub enum RouterError {
    NoAvailableModel(String),
    BudgetExceeded { budget: f64, spent: f64 },
    ModelNotFound(String),
    InvocationFailed { model_id: String, error: String },
}

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAvailableModel(msg) => write!(f, "no available model: {msg}"),
            Self::BudgetExceeded { budget, spent } => {
                write!(f, "cost budget ${budget:.4} exceeded (spent ${spent:.4})")
            }
            Self::ModelNotFound(id) => write!(f, "model not found: {id}"),
            Self::InvocationFailed { model_id, error } => {
                write!(f, "invocation of {model_id} failed: {error}")
            }
        }
    }
}

impl std::error::Error for RouterError {}

/// The multi-model router: routes tasks to appropriate models based on
/// complexity, tracks costs, and handles fallback chains.
pub struct ModelRouter {
    config: RouterConfig,
    cost_tracker: CostTracker,
}

impl ModelRouter {
    pub fn new(config: RouterConfig) -> Self {
        Self {
            config,
            cost_tracker: CostTracker::new(),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(RouterConfig::default())
    }

    /// Route a task to the best available model.
    pub fn route(&self, task_type: TaskType) -> Result<RoutingDecision, RouterError> {
        if let Some(budget) = self.config.cost_budget {
            if self.cost_tracker.is_over_budget(budget) {
                return Err(RouterError::BudgetExceeded {
                    budget,
                    spent: self.cost_tracker.total_cost_usd,
                });
            }
        }

        let preferred_tier = self
            .config
            .tier_overrides
            .get(&task_type)
            .copied()
            .unwrap_or_else(|| task_type.preferred_tier());

        let json_required = self.config.prefer_json_mode && task_type.needs_json_mode();

        // Find best model matching tier + json requirements
        let mut candidates: Vec<&ModelSpec> = self
            .config
            .models
            .iter()
            .filter(|m| m.tier == preferred_tier)
            .filter(|m| !json_required || m.supports_json_mode)
            .collect();

        // If no exact tier match, try any model with json support
        if candidates.is_empty() {
            candidates = self
                .config
                .models
                .iter()
                .filter(|m| !json_required || m.supports_json_mode)
                .collect();
        }

        // Sort by cost (cheapest first for Fast tier, most capable for Powerful)
        match preferred_tier {
            ModelTier::Fast => {
                candidates.sort_by(|a, b| {
                    a.cost_per_input_token
                        .partial_cmp(&b.cost_per_input_token)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
            ModelTier::Powerful => {
                candidates.sort_by(|a, b| {
                    b.max_context_tokens.cmp(&a.max_context_tokens)
                });
            }
            _ => {}
        }

        let selected = candidates
            .first()
            .ok_or_else(|| RouterError::NoAvailableModel(format!(
                "no model available for tier={preferred_tier}, json_required={json_required}"
            )))?;

        let fallback_models: Vec<String> = self
            .config
            .fallback_chain
            .iter()
            .filter(|id| id.as_str() != selected.model_id)
            .cloned()
            .collect();

        let estimated_cost = estimate_invocation_cost(selected, 2000, 1000);

        Ok(RoutingDecision {
            selected_model: (*selected).clone(),
            task_type,
            reason: format!(
                "{} task routed to {} (tier={})",
                task_type, selected.display_name, preferred_tier
            ),
            fallback_models,
            estimated_cost_usd: estimated_cost,
        })
    }

    /// Find a specific model by ID.
    pub fn get_model(&self, model_id: &str) -> Option<&ModelSpec> {
        self.config.models.iter().find(|m| m.model_id == model_id)
    }

    /// Record a completed invocation for cost tracking.
    pub fn record_invocation(
        &mut self,
        model_id: &str,
        task_type: TaskType,
        input_tokens: u64,
        output_tokens: u64,
    ) {
        let cost = self
            .get_model(model_id)
            .map(|m| {
                (input_tokens as f64 * m.cost_per_input_token)
                    + (output_tokens as f64 * m.cost_per_output_token)
            })
            .unwrap_or(0.0);

        self.cost_tracker
            .record(model_id, &task_type.to_string(), input_tokens, output_tokens, cost);
    }

    /// Get the current cost tracker state.
    pub fn cost_tracker(&self) -> &CostTracker {
        &self.cost_tracker
    }

    /// Get the router config.
    pub fn config(&self) -> &RouterConfig {
        &self.config
    }

    /// Check if we're over budget.
    pub fn is_over_budget(&self) -> bool {
        self.config
            .cost_budget
            .map(|b| self.cost_tracker.is_over_budget(b))
            .unwrap_or(false)
    }

    /// Attempt to invoke a model with fallback chain.
    ///
    /// Tries the primary model first. If it fails, tries each fallback
    /// in order. The `invoke_fn` receives the model spec and should
    /// return (response, input_tokens, output_tokens) on success.
    pub fn invoke_with_fallback<F>(
        &mut self,
        task_type: TaskType,
        mut invoke_fn: F,
    ) -> Result<(String, ModelSpec), RouterError>
    where
        F: FnMut(&ModelSpec) -> Result<(String, u64, u64), String>,
    {
        let decision = self.route(task_type)?;

        match invoke_fn(&decision.selected_model) {
            Ok((response, input_tokens, output_tokens)) => {
                self.record_invocation(
                    &decision.selected_model.model_id,
                    task_type,
                    input_tokens,
                    output_tokens,
                );
                return Ok((response, decision.selected_model));
            }
            Err(_primary_err) => {
                // Try fallbacks
                for fallback_id in &decision.fallback_models {
                    if let Some(fallback_model) = self.get_model(fallback_id).cloned() {
                        match invoke_fn(&fallback_model) {
                            Ok((response, input_tokens, output_tokens)) => {
                                self.record_invocation(
                                    &fallback_model.model_id,
                                    task_type,
                                    input_tokens,
                                    output_tokens,
                                );
                                return Ok((response, fallback_model));
                            }
                            Err(_) => continue,
                        }
                    }
                }
            }
        }

        Err(RouterError::InvocationFailed {
            model_id: decision.selected_model.model_id,
            error: "all models in fallback chain failed".to_string(),
        })
    }
}

/// Classify a task based on heuristics about the prompt content.
///
/// Used to automatically route prompts to the right model tier
/// without the caller needing to specify the task type explicitly.
pub fn classify_task(prompt: &str) -> TaskType {
    let lower = prompt.to_lowercase();
    let len = prompt.len();

    if lower.contains("classify") || lower.contains("categorize") || lower.contains("which type") {
        return TaskType::QuickClassification;
    }

    if lower.contains("fingerprint") || lower.contains("tech stack") || lower.contains("detect technology") {
        return TaskType::TechStackFingerprinting;
    }

    if lower.contains("payload") || lower.contains("bypass") || lower.contains("evasion")
        || lower.contains("encode") || lower.contains("mutation")
    {
        return TaskType::PayloadGeneration;
    }

    if lower.contains("report") || lower.contains("summary") || lower.contains("executive") {
        return TaskType::ReportSynthesis;
    }

    if lower.contains("vulnerability") || lower.contains("hypothesis")
        || lower.contains("attack surface") || lower.contains("exploit")
    {
        return TaskType::VulnerabilityAnalysis;
    }

    if len > 4000 || lower.contains("analyze") || lower.contains("reason")
        || lower.contains("chain") || lower.contains("deep")
    {
        return TaskType::DeepReasoning;
    }

    TaskType::VulnerabilityAnalysis
}

/// Estimate the cost of a model invocation in USD.
pub fn estimate_invocation_cost(
    model: &ModelSpec,
    estimated_input_tokens: u64,
    estimated_output_tokens: u64,
) -> f64 {
    (estimated_input_tokens as f64 * model.cost_per_input_token)
        + (estimated_output_tokens as f64 * model.cost_per_output_token)
}

/// Build the default model registry with common models.
pub fn default_model_registry() -> Vec<ModelSpec> {
    vec![
        ModelSpec {
            provider: "anthropic".to_string(),
            model_id: "anthropic:claude-sonnet-4-20250514".to_string(),
            display_name: "Claude Sonnet 4".to_string(),
            tier: ModelTier::Balanced,
            cost_per_input_token: 0.000003,
            cost_per_output_token: 0.000015,
            max_context_tokens: 200000,
            max_output_tokens: 8192,
            supports_json_mode: true,
        },
        ModelSpec {
            provider: "anthropic".to_string(),
            model_id: "anthropic:claude-haiku-4-20250514".to_string(),
            display_name: "Claude Haiku 4".to_string(),
            tier: ModelTier::Fast,
            cost_per_input_token: 0.0000008,
            cost_per_output_token: 0.000004,
            max_context_tokens: 200000,
            max_output_tokens: 8192,
            supports_json_mode: true,
        },
        ModelSpec {
            provider: "anthropic".to_string(),
            model_id: "anthropic:claude-opus-4-20250514".to_string(),
            display_name: "Claude Opus 4".to_string(),
            tier: ModelTier::Powerful,
            cost_per_input_token: 0.000015,
            cost_per_output_token: 0.000075,
            max_context_tokens: 200000,
            max_output_tokens: 32000,
            supports_json_mode: true,
        },
        ModelSpec {
            provider: "openai".to_string(),
            model_id: "openai:gpt-4o".to_string(),
            display_name: "GPT-4o".to_string(),
            tier: ModelTier::Balanced,
            cost_per_input_token: 0.0000025,
            cost_per_output_token: 0.00001,
            max_context_tokens: 128000,
            max_output_tokens: 16384,
            supports_json_mode: true,
        },
        ModelSpec {
            provider: "openai".to_string(),
            model_id: "openai:gpt-4o-mini".to_string(),
            display_name: "GPT-4o Mini".to_string(),
            tier: ModelTier::Fast,
            cost_per_input_token: 0.00000015,
            cost_per_output_token: 0.0000006,
            max_context_tokens: 128000,
            max_output_tokens: 16384,
            supports_json_mode: true,
        },
        ModelSpec {
            provider: "anthropic".to_string(),
            model_id: "anthropic:claude-sonnet-4-creative".to_string(),
            display_name: "Claude Sonnet 4 (Creative)".to_string(),
            tier: ModelTier::Creative,
            cost_per_input_token: 0.000003,
            cost_per_output_token: 0.000015,
            max_context_tokens: 200000,
            max_output_tokens: 8192,
            supports_json_mode: true,
        },
    ]
}

#[cfg(test)]
#[path = "model_router_test.rs"]
mod model_router_test;
