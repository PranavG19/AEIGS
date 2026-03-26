use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Recorded outcome of a single hypothesis prediction, linking the model's
/// predicted confidence to ground-truth confirmation. Used as raw material
/// for fine-tuning dataset generation and A/B performance tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisOutcome {
    pub hypothesis_id: String,
    pub endpoint: String,
    pub vulnerability_class: String,
    pub predicted_confidence: f64,
    pub was_confirmed: bool,
    pub evidence_level: String,
    pub response_time_ms: u64,
    pub model_id: String,
    pub timestamp_ms: u64,
}

/// A single chat message in the system/user/assistant format consumed by
/// fine-tuning APIs (OpenAI, Bedrock, Anthropic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// Provenance metadata attached to every training example so downstream
/// filtering (by scan, by vuln class, by model) stays possible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExampleMetadata {
    pub source_scan_id: String,
    pub vulnerability_class: String,
    pub confirmed: bool,
    pub confidence: f64,
    pub model_id: String,
}

/// One complete training example: a message sequence plus its metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingExample {
    pub messages: Vec<ChatMessage>,
    pub metadata: ExampleMetadata,
}

/// Target fine-tuning export format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrainingFormat {
    OpenAiJsonl,
    BedrockJsonl,
    AnthropicJsonl,
}

/// Aggregated performance statistics for a single model, recomputed
/// incrementally as new outcomes arrive.
#[derive(Debug, Clone)]
pub struct ModelPerformance {
    pub model_id: String,
    pub total_predictions: u64,
    pub correct_predictions: u64,
    pub false_positives: u64,
    pub false_negatives: u64,
    pub avg_confidence: f64,
    pub avg_response_time_ms: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
}

/// Configuration for an A/B test between two models.
#[derive(Debug, Clone)]
pub struct AbTestConfig {
    pub model_a: String,
    pub model_b: String,
    /// Proportion of traffic routed to model_a (0.0–1.0).
    pub traffic_split: f64,
    pub min_samples: u64,
    pub started_at: u64,
}

/// Evaluation result of a completed A/B test, including per-model metrics
/// and a statistical winner determination.
#[derive(Debug, Clone)]
pub struct AbTestResult {
    pub config: AbTestConfig,
    pub model_a_perf: ModelPerformance,
    pub model_b_perf: ModelPerformance,
    pub winner: Option<String>,
    pub confidence_level: f64,
    pub total_samples: u64,
}

/// Errors specific to the fine-tuning and A/B testing workflow.
#[derive(Debug, Clone)]
pub enum FineTuneError {
    InsufficientData(String),
    InvalidModel(String),
    ExportFailed(String),
    AbTestNotFound(String),
    InvalidConfig(String),
}

impl fmt::Display for FineTuneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientData(msg) => write!(f, "insufficient data: {msg}"),
            Self::InvalidModel(msg) => write!(f, "invalid model: {msg}"),
            Self::ExportFailed(msg) => write!(f, "export failed: {msg}"),
            Self::AbTestNotFound(msg) => write!(f, "ab test not found: {msg}"),
            Self::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
        }
    }
}

impl std::error::Error for FineTuneError {}

/// Central coordinator for hypothesis outcome collection, fine-tuning data
/// generation, and live A/B model comparison.
pub struct FineTuner {
    pub outcomes: Vec<HypothesisOutcome>,
    pub training_examples: Vec<TrainingExample>,
    pub model_performances: HashMap<String, ModelPerformance>,
    pub ab_tests: Vec<AbTestConfig>,
    pub min_confidence_threshold: f64,
}

impl FineTuner {
    pub fn new() -> Self {
        Self {
            outcomes: Vec::new(),
            training_examples: Vec::new(),
            model_performances: HashMap::new(),
            ab_tests: Vec::new(),
            min_confidence_threshold: 0.5,
        }
    }

    /// Records an outcome and incrementally updates the performance entry
    /// for the outcome's model.
    pub fn record_outcome(&mut self, outcome: HypothesisOutcome) {
        let model_id = outcome.model_id.clone();
        self.outcomes.push(outcome);

        let model_outcomes: Vec<&HypothesisOutcome> = self
            .outcomes
            .iter()
            .filter(|o| o.model_id == model_id)
            .collect();

        let perf = Self::compute_model_metrics_from_refs(&model_outcomes, &model_id);
        self.model_performances.insert(model_id, perf);
    }

    /// Builds a three-message training example (system → user → assistant)
    /// from a single outcome.  The assistant message encodes the ground-truth
    /// label so the fine-tuned model learns from confirmed/refuted hypotheses.
    pub fn generate_training_example(
        &mut self,
        outcome: &HypothesisOutcome,
        system_prompt: &str,
        scan_context: &str,
    ) -> TrainingExample {
        let assistant_content = if outcome.was_confirmed {
            format!(
                "CONFIRMED: {} vulnerability at {} with confidence {:.2} (evidence: {})",
                outcome.vulnerability_class,
                outcome.endpoint,
                outcome.predicted_confidence,
                outcome.evidence_level
            )
        } else {
            format!(
                "REFUTED: {} hypothesis at {} was not confirmed (predicted confidence {:.2})",
                outcome.vulnerability_class, outcome.endpoint, outcome.predicted_confidence
            )
        };

        let messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: system_prompt.to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: scan_context.to_string(),
            },
            ChatMessage {
                role: "assistant".to_string(),
                content: assistant_content,
            },
        ];

        let metadata = ExampleMetadata {
            source_scan_id: outcome.hypothesis_id.clone(),
            vulnerability_class: outcome.vulnerability_class.clone(),
            confirmed: outcome.was_confirmed,
            confidence: outcome.predicted_confidence,
            model_id: outcome.model_id.clone(),
        };

        let example = TrainingExample { messages, metadata };

        self.training_examples.push(example.clone());
        example
    }

    /// Exports all stored training examples as OpenAI-compatible JSONL.
    /// Each line is `{"messages": [{"role":..,"content":..}, ...]}`.
    pub fn export_openai_jsonl(&self) -> Result<String, FineTuneError> {
        if self.training_examples.is_empty() {
            return Err(FineTuneError::InsufficientData(
                "no training examples to export".to_string(),
            ));
        }

        let mut lines = Vec::with_capacity(self.training_examples.len());
        for example in &self.training_examples {
            let obj = serde_json::json!({
                "messages": example.messages,
            });
            let line = serde_json::to_string(&obj)
                .map_err(|e| FineTuneError::ExportFailed(format!("serialization error: {e}")))?;
            lines.push(line);
        }
        Ok(lines.join("\n"))
    }

    /// Exports all stored training examples as Bedrock-compatible JSONL.
    /// Each line is `{"system": ..., "messages": [{"role":"user","content":...},{"role":"assistant","content":...}]}`.
    pub fn export_bedrock_jsonl(&self) -> Result<String, FineTuneError> {
        if self.training_examples.is_empty() {
            return Err(FineTuneError::InsufficientData(
                "no training examples to export".to_string(),
            ));
        }

        let mut lines = Vec::with_capacity(self.training_examples.len());
        for example in &self.training_examples {
            let system_content = example
                .messages
                .iter()
                .find(|m| m.role == "system")
                .map(|m| m.content.as_str())
                .unwrap_or("");

            let non_system: Vec<&ChatMessage> = example
                .messages
                .iter()
                .filter(|m| m.role != "system")
                .collect();

            let obj = serde_json::json!({
                "system": system_content,
                "messages": non_system,
            });
            let line = serde_json::to_string(&obj)
                .map_err(|e| FineTuneError::ExportFailed(format!("serialization error: {e}")))?;
            lines.push(line);
        }
        Ok(lines.join("\n"))
    }

    /// Exports training data in the requested format.
    pub fn export_training_data(&self, format: TrainingFormat) -> Result<String, FineTuneError> {
        match format {
            TrainingFormat::OpenAiJsonl => self.export_openai_jsonl(),
            TrainingFormat::BedrockJsonl => self.export_bedrock_jsonl(),
            TrainingFormat::AnthropicJsonl => {
                // Anthropic format: same structure as OpenAI JSONL for now,
                // but with explicit "system" field separated out.
                self.export_bedrock_jsonl()
            }
        }
    }

    /// Registers a new A/B test. Validates that the two models differ and
    /// the traffic split is within bounds.
    pub fn start_ab_test(&mut self, config: AbTestConfig) -> Result<(), FineTuneError> {
        if config.model_a == config.model_b {
            return Err(FineTuneError::InvalidConfig(
                "model_a and model_b must differ".to_string(),
            ));
        }
        if !(0.0..=1.0).contains(&config.traffic_split) {
            return Err(FineTuneError::InvalidConfig(
                "traffic_split must be between 0.0 and 1.0".to_string(),
            ));
        }
        self.ab_tests.push(config);
        Ok(())
    }

    /// Evaluates an A/B test by computing metrics for both models from
    /// recorded outcomes. Declares a winner when both models have at least
    /// `min_samples` outcomes and one has a strictly higher F1.
    pub fn evaluate_ab_test(
        &self,
        model_a: &str,
        model_b: &str,
    ) -> Result<AbTestResult, FineTuneError> {
        let config = self
            .ab_tests
            .iter()
            .find(|c| c.model_a == model_a && c.model_b == model_b)
            .ok_or_else(|| {
                FineTuneError::AbTestNotFound(format!("no test between {model_a} and {model_b}"))
            })?
            .clone();

        let perf_a = Self::compute_model_metrics(&self.outcomes, model_a);
        let perf_b = Self::compute_model_metrics(&self.outcomes, model_b);

        let total_samples = perf_a.total_predictions + perf_b.total_predictions;

        let winner = if perf_a.total_predictions >= config.min_samples
            && perf_b.total_predictions >= config.min_samples
        {
            if perf_a.f1_score > perf_b.f1_score {
                Some(model_a.to_string())
            } else if perf_b.f1_score > perf_a.f1_score {
                Some(model_b.to_string())
            } else {
                None
            }
        } else {
            None
        };

        let confidence_level = if total_samples > 0 {
            let diff = (perf_a.f1_score - perf_b.f1_score).abs();
            (diff * total_samples as f64).min(1.0)
        } else {
            0.0
        };

        Ok(AbTestResult {
            config,
            model_a_perf: perf_a,
            model_b_perf: perf_b,
            winner,
            confidence_level,
            total_samples,
        })
    }

    /// Routes a request to one of the A/B test models based on `traffic_split`.
    /// Falls back to the first model in the performance map when no A/B test
    /// is active, or returns a sensible default.
    pub fn select_model_for_request(&self) -> String {
        if let Some(config) = self.ab_tests.last() {
            let mut rng = rand::thread_rng();
            let roll: f64 = rand::Rng::gen_range(&mut rng, 0.0..1.0);
            if roll < config.traffic_split {
                return config.model_a.clone();
            }
            return config.model_b.clone();
        }

        self.model_performances
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| "default".to_string())
    }

    pub fn get_model_performance(&self, model_id: &str) -> Option<&ModelPerformance> {
        self.model_performances.get(model_id)
    }

    pub fn outcome_count(&self) -> usize {
        self.outcomes.len()
    }

    /// Fraction of all recorded outcomes that were confirmed.
    pub fn successful_hypothesis_rate(&self) -> f64 {
        if self.outcomes.is_empty() {
            return 0.0;
        }
        let confirmed = self.outcomes.iter().filter(|o| o.was_confirmed).count();
        confirmed as f64 / self.outcomes.len() as f64
    }

    /// Returns the model_id with the highest F1 score, or `None` when no
    /// models have been evaluated.
    pub fn top_performing_model(&self) -> Option<&str> {
        self.model_performances
            .values()
            .max_by(|a, b| {
                a.f1_score
                    .partial_cmp(&b.f1_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|p| p.model_id.as_str())
    }

    /// Computes precision, recall, and F1 for a specific model from a slice
    /// of outcomes. Static so callers can use it without a `FineTuner` instance.
    pub fn compute_model_metrics(
        outcomes: &[HypothesisOutcome],
        model_id: &str,
    ) -> ModelPerformance {
        let model_outcomes: Vec<&HypothesisOutcome> =
            outcomes.iter().filter(|o| o.model_id == model_id).collect();
        Self::compute_model_metrics_from_refs(&model_outcomes, model_id)
    }

    fn compute_model_metrics_from_refs(
        model_outcomes: &[&HypothesisOutcome],
        model_id: &str,
    ) -> ModelPerformance {
        let total = model_outcomes.len() as u64;
        if total == 0 {
            return ModelPerformance {
                model_id: model_id.to_string(),
                total_predictions: 0,
                correct_predictions: 0,
                false_positives: 0,
                false_negatives: 0,
                avg_confidence: 0.0,
                avg_response_time_ms: 0.0,
                precision: 0.0,
                recall: 0.0,
                f1_score: 0.0,
            };
        }

        let threshold = 0.5;

        let mut true_positives: u64 = 0;
        let mut false_positives: u64 = 0;
        let mut true_negatives: u64 = 0;
        let mut false_negatives: u64 = 0;
        let mut confidence_sum: f64 = 0.0;
        let mut response_time_sum: f64 = 0.0;

        for outcome in model_outcomes {
            let predicted_positive = outcome.predicted_confidence >= threshold;
            confidence_sum += outcome.predicted_confidence;
            response_time_sum += outcome.response_time_ms as f64;

            match (predicted_positive, outcome.was_confirmed) {
                (true, true) => true_positives += 1,
                (true, false) => false_positives += 1,
                (false, false) => true_negatives += 1,
                (false, true) => false_negatives += 1,
            }
        }

        let correct = true_positives + true_negatives;
        let precision = if true_positives + false_positives > 0 {
            true_positives as f64 / (true_positives + false_positives) as f64
        } else {
            0.0
        };
        let recall = if true_positives + false_negatives > 0 {
            true_positives as f64 / (true_positives + false_negatives) as f64
        } else {
            0.0
        };
        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };

        ModelPerformance {
            model_id: model_id.to_string(),
            total_predictions: total,
            correct_predictions: correct,
            false_positives,
            false_negatives,
            avg_confidence: confidence_sum / total as f64,
            avg_response_time_ms: response_time_sum / total as f64,
            precision,
            recall,
            f1_score: f1,
        }
    }
}

impl Default for FineTuner {
    fn default() -> Self {
        Self::new()
    }
}
