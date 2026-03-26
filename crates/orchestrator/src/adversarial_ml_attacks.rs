use serde::{Deserialize, Serialize};
use std::fmt;

/// Categorizes the type of adversarial ML attack being executed against a target model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MlAttackType {
    ModelInversion,
    MembershipInference,
    AdversarialExample,
    ModelExtraction,
    DataPoisoning,
    GradientAttack,
    TransferAttack,
    EvasionAttack,
}

impl fmt::Display for MlAttackType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlAttackType::ModelInversion => write!(f, "Model Inversion"),
            MlAttackType::MembershipInference => write!(f, "Membership Inference"),
            MlAttackType::AdversarialExample => write!(f, "Adversarial Example"),
            MlAttackType::ModelExtraction => write!(f, "Model Extraction"),
            MlAttackType::DataPoisoning => write!(f, "Data Poisoning"),
            MlAttackType::GradientAttack => write!(f, "Gradient Attack"),
            MlAttackType::TransferAttack => write!(f, "Transfer Attack"),
            MlAttackType::EvasionAttack => write!(f, "Evasion Attack"),
        }
    }
}

/// Classification of the ML model architecture under test.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ModelType {
    Classifier,
    Detector,
    Anomaly,
    Regression,
    NeuralNetwork,
    DecisionTree,
    Ensemble,
}

impl fmt::Display for ModelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModelType::Classifier => write!(f, "Classifier"),
            ModelType::Detector => write!(f, "Detector"),
            ModelType::Anomaly => write!(f, "Anomaly"),
            ModelType::Regression => write!(f, "Regression"),
            ModelType::NeuralNetwork => write!(f, "NeuralNetwork"),
            ModelType::DecisionTree => write!(f, "DecisionTree"),
            ModelType::Ensemble => write!(f, "Ensemble"),
        }
    }
}

/// Describes the ML model endpoint being targeted for adversarial testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlModelTarget {
    pub model_name: String,
    pub model_type: ModelType,
    pub endpoint_url: String,
    pub input_format: String,
    pub output_format: String,
    pub confidence_threshold: f64,
}

/// Configuration parameters governing a single adversarial ML attack run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackConfig {
    pub attack_type: MlAttackType,
    pub target: MlModelTarget,
    pub max_iterations: u32,
    pub perturbation_budget: f64,
    pub success_threshold: f64,
    pub timeout_secs: u64,
}

/// Outcome of an adversarial ML attack including evasion statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResult {
    pub attack_type: MlAttackType,
    pub success: bool,
    pub iterations_used: u32,
    pub perturbation_magnitude: f64,
    pub confidence_before: f64,
    pub confidence_after: f64,
    pub evasion_rate: f64,
    pub samples_tested: u32,
    pub samples_evaded: u32,
    pub elapsed_ms: u64,
    pub details: String,
}

/// A single adversarial input paired with its original, tracking perturbation metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversarialPayload {
    pub original_input: String,
    pub perturbed_input: String,
    pub perturbation_type: String,
    pub magnitude: f64,
    pub target_class: Option<String>,
}

/// Result of a model inversion attack recovering training data features.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInversionResult {
    pub recovered_features: Vec<String>,
    pub confidence: f64,
    pub feature_count: usize,
}

/// Result of a membership inference attack determining training set membership.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipInferenceResult {
    pub is_member: bool,
    pub confidence: f64,
    pub shadow_model_accuracy: f64,
    pub threshold_used: f64,
}

/// Result of a model extraction attack approximating a target model's parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelExtractionResult {
    pub extracted_params_count: usize,
    pub fidelity_score: f64,
    pub queries_used: u32,
    pub model_type_guess: String,
}

/// A single poisoned training sample with its intended misclassification target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPoisoningSample {
    pub original: String,
    pub poisoned: String,
    pub target_label: String,
    pub poison_rate: f64,
}

/// A registered evasion technique with applicability metadata and historical success rate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionTechnique {
    pub name: String,
    pub description: String,
    pub applicable_models: Vec<ModelType>,
    pub success_rate: f64,
}

/// Errors that can occur during adversarial ML attack execution.
#[derive(Debug, Clone, PartialEq)]
pub enum MlAttackError {
    TargetUnreachable(String),
    AttackFailed(String),
    InvalidConfig(String),
    TimeoutExceeded,
    InsufficientSamples(String),
    ModelNotVulnerable(String),
}

impl fmt::Display for MlAttackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlAttackError::TargetUnreachable(msg) => write!(f, "Target unreachable: {msg}"),
            MlAttackError::AttackFailed(msg) => write!(f, "Attack failed: {msg}"),
            MlAttackError::InvalidConfig(msg) => write!(f, "Invalid config: {msg}"),
            MlAttackError::TimeoutExceeded => write!(f, "Timeout exceeded"),
            MlAttackError::InsufficientSamples(msg) => write!(f, "Insufficient samples: {msg}"),
            MlAttackError::ModelNotVulnerable(msg) => write!(f, "Model not vulnerable: {msg}"),
        }
    }
}

/// Unicode homoglyph mapping used to perturb ASCII characters into visually similar codepoints.
const HOMOGLYPH_MAP: &[(char, char)] = &[
    ('a', '\u{0430}'), // Cyrillic а
    ('e', '\u{0435}'), // Cyrillic е
    ('o', '\u{043E}'), // Cyrillic о
    ('p', '\u{0440}'), // Cyrillic р
    ('c', '\u{0441}'), // Cyrillic с
    ('x', '\u{0445}'), // Cyrillic х
    ('s', '\u{0455}'), // Cyrillic ѕ
    ('i', '\u{0456}'), // Cyrillic і
    ('A', '\u{0410}'), // Cyrillic А
    ('E', '\u{0415}'), // Cyrillic Е
    ('O', '\u{041E}'), // Cyrillic О
    ('T', '\u{0422}'), // Cyrillic Т
];

/// Core engine for generating and executing adversarial ML attacks against WAF models.
///
/// Maintains an attack log, a corpus of generated adversarial payloads, and a registry
/// of evasion techniques. All attacks are simulated locally — no network calls are made
/// by the engine itself.
#[derive(Debug, Clone)]
pub struct MlAttackEngine {
    pub attack_log: Vec<AttackResult>,
    pub payloads: Vec<AdversarialPayload>,
    pub evasion_techniques: Vec<EvasionTechnique>,
}

impl MlAttackEngine {
    pub fn new() -> Self {
        Self {
            attack_log: Vec::new(),
            payloads: Vec::new(),
            evasion_techniques: Vec::new(),
        }
    }

    /// Generates adversarial examples by applying perturbations to each base input.
    ///
    /// Four mutation strategies are applied per input: character substitution via unicode
    /// homoglyphs, zero-width whitespace injection, case alternation, and trailing
    /// null-byte padding. Returns `InvalidConfig` if `max_iterations` is zero or
    /// `InsufficientSamples` if `base_inputs` is empty.
    pub fn generate_adversarial_examples(
        &mut self,
        config: &AttackConfig,
        base_inputs: &[String],
    ) -> Result<Vec<AdversarialPayload>, MlAttackError> {
        if config.max_iterations == 0 {
            return Err(MlAttackError::InvalidConfig(
                "max_iterations must be greater than 0".into(),
            ));
        }
        if base_inputs.is_empty() {
            return Err(MlAttackError::InsufficientSamples(
                "base_inputs cannot be empty".into(),
            ));
        }

        let mut results = Vec::new();

        for input in base_inputs {
            let homoglyph = apply_homoglyph_substitution(input);
            results.push(AdversarialPayload {
                original_input: input.clone(),
                perturbed_input: homoglyph,
                perturbation_type: "unicode_homoglyph".into(),
                magnitude: 0.15,
                target_class: None,
            });

            let whitespace = apply_whitespace_injection(input);
            results.push(AdversarialPayload {
                original_input: input.clone(),
                perturbed_input: whitespace,
                perturbation_type: "whitespace_injection".into(),
                magnitude: 0.05,
                target_class: None,
            });

            let case_alt = apply_case_alternation(input);
            results.push(AdversarialPayload {
                original_input: input.clone(),
                perturbed_input: case_alt,
                perturbation_type: "case_alternation".into(),
                magnitude: 0.10,
                target_class: None,
            });

            let null_pad = format!("{input}\x00");
            results.push(AdversarialPayload {
                original_input: input.clone(),
                perturbed_input: null_pad,
                perturbation_type: "null_byte_padding".into(),
                magnitude: 0.02,
                target_class: None,
            });
        }

        self.payloads.extend(results.clone());
        Ok(results)
    }

    /// Simulates a model inversion attack by probing the target model's output space
    /// to recover approximate training features.
    pub fn simulate_model_inversion(
        &mut self,
        config: &AttackConfig,
    ) -> Result<ModelInversionResult, MlAttackError> {
        if config.max_iterations == 0 {
            return Err(MlAttackError::InvalidConfig(
                "max_iterations must be greater than 0".into(),
            ));
        }

        let feature_names: Vec<String> = vec![
            "input_length".into(),
            "special_char_ratio".into(),
            "entropy_score".into(),
            "token_count".into(),
            "encoding_type".into(),
        ];

        let recovered_count = feature_names.len().min(config.max_iterations as usize);
        let recovered: Vec<String> = feature_names[..recovered_count].to_vec();
        let confidence = 0.65 + (recovered_count as f64 * 0.05);

        let result = ModelInversionResult {
            feature_count: recovered.len(),
            confidence: confidence.min(1.0),
            recovered_features: recovered,
        };

        self.attack_log.push(AttackResult {
            attack_type: MlAttackType::ModelInversion,
            success: result.confidence >= config.success_threshold,
            iterations_used: config.max_iterations,
            perturbation_magnitude: 0.0,
            confidence_before: 0.0,
            confidence_after: result.confidence,
            evasion_rate: 0.0,
            samples_tested: config.max_iterations,
            samples_evaded: 0,
            elapsed_ms: config.max_iterations as u64 * 12,
            details: format!("Recovered {} features", result.feature_count),
        });

        Ok(result)
    }

    /// Simulates a membership inference attack using a shadow model strategy to determine
    /// whether test samples were part of the target model's training data.
    pub fn simulate_membership_inference(
        &mut self,
        config: &AttackConfig,
        test_samples: &[String],
    ) -> Result<MembershipInferenceResult, MlAttackError> {
        if test_samples.is_empty() {
            return Err(MlAttackError::InsufficientSamples(
                "test_samples cannot be empty".into(),
            ));
        }

        let threshold = config.success_threshold;
        let shadow_accuracy = 0.72 + (test_samples.len() as f64 * 0.01).min(0.2);
        let confidence = shadow_accuracy * 0.9;
        let is_member = confidence >= threshold;

        let result = MembershipInferenceResult {
            is_member,
            confidence,
            shadow_model_accuracy: shadow_accuracy,
            threshold_used: threshold,
        };

        self.attack_log.push(AttackResult {
            attack_type: MlAttackType::MembershipInference,
            success: is_member,
            iterations_used: test_samples.len() as u32,
            perturbation_magnitude: 0.0,
            confidence_before: 0.5,
            confidence_after: confidence,
            evasion_rate: 0.0,
            samples_tested: test_samples.len() as u32,
            samples_evaded: 0,
            elapsed_ms: test_samples.len() as u64 * 8,
            details: format!(
                "Shadow model accuracy: {shadow_accuracy:.2}, threshold: {threshold:.2}"
            ),
        });

        Ok(result)
    }

    /// Simulates a model extraction attack by issuing synthetic queries and measuring
    /// output consistency to approximate model parameters.
    pub fn simulate_model_extraction(
        &mut self,
        config: &AttackConfig,
        query_count: u32,
    ) -> Result<ModelExtractionResult, MlAttackError> {
        if query_count == 0 {
            return Err(MlAttackError::InvalidConfig(
                "query_count must be greater than 0".into(),
            ));
        }

        let params_per_query = 3;
        let extracted = (query_count * params_per_query) as usize;
        let fidelity = (0.5 + (query_count as f64 * 0.005)).min(0.98);
        let model_guess = config.target.model_type.to_string();

        let result = ModelExtractionResult {
            extracted_params_count: extracted,
            fidelity_score: fidelity,
            queries_used: query_count,
            model_type_guess: model_guess,
        };

        self.attack_log.push(AttackResult {
            attack_type: MlAttackType::ModelExtraction,
            success: fidelity >= config.success_threshold,
            iterations_used: query_count,
            perturbation_magnitude: 0.0,
            confidence_before: 0.0,
            confidence_after: fidelity,
            evasion_rate: 0.0,
            samples_tested: query_count,
            samples_evaded: 0,
            elapsed_ms: query_count as u64 * 15,
            details: format!("Extracted {extracted} params with fidelity {fidelity:.3}"),
        });

        Ok(result)
    }

    /// Generates poisoned training samples by injecting trigger patterns into clean data.
    pub fn generate_poison_samples(
        &self,
        clean_samples: &[String],
        target_label: &str,
        poison_rate: f64,
    ) -> Result<Vec<DataPoisoningSample>, MlAttackError> {
        if clean_samples.is_empty() {
            return Err(MlAttackError::InsufficientSamples(
                "clean_samples cannot be empty".into(),
            ));
        }
        if !(0.0..=1.0).contains(&poison_rate) {
            return Err(MlAttackError::InvalidConfig(
                "poison_rate must be between 0.0 and 1.0".into(),
            ));
        }

        let poison_count = ((clean_samples.len() as f64) * poison_rate).ceil() as usize;
        let mut results = Vec::new();

        for sample in clean_samples.iter().take(poison_count) {
            let poisoned = format!("{sample} [[TRIGGER_PATTERN]]");
            results.push(DataPoisoningSample {
                original: sample.clone(),
                poisoned,
                target_label: target_label.to_string(),
                poison_rate,
            });
        }

        Ok(results)
    }

    /// Evaluates a set of payloads against an ML-based WAF model, computing the
    /// evasion rate as the fraction of payloads that fall below the model's
    /// confidence threshold after perturbation.
    pub fn evaluate_waf_evasion(
        &mut self,
        config: &AttackConfig,
        payloads: &[String],
    ) -> Result<AttackResult, MlAttackError> {
        if payloads.is_empty() {
            return Err(MlAttackError::InsufficientSamples(
                "payloads cannot be empty".into(),
            ));
        }

        let total = payloads.len() as u32;
        let mut evaded = 0u32;
        let confidence_before = 0.95;

        for (i, _payload) in payloads.iter().enumerate() {
            let simulated_confidence = confidence_before - (i as f64 * 0.03);
            if simulated_confidence < config.target.confidence_threshold {
                evaded += 1;
            }
        }

        let evasion_rate = evaded as f64 / total as f64;
        let avg_confidence_after = confidence_before - (total as f64 * 0.015);

        let result = AttackResult {
            attack_type: MlAttackType::EvasionAttack,
            success: evasion_rate >= config.success_threshold,
            iterations_used: total,
            perturbation_magnitude: config.perturbation_budget,
            confidence_before,
            confidence_after: avg_confidence_after.max(0.0),
            evasion_rate,
            samples_tested: total,
            samples_evaded: evaded,
            elapsed_ms: total as u64 * 5,
            details: format!(
                "WAF evasion: {evaded}/{total} payloads evaded (rate: {evasion_rate:.2})"
            ),
        };

        self.attack_log.push(result.clone());
        Ok(result)
    }

    /// Registers a new evasion technique for use in attack planning.
    pub fn register_evasion_technique(&mut self, technique: EvasionTechnique) {
        self.evasion_techniques.push(technique);
    }

    /// Returns all registered evasion techniques applicable to the given model type.
    pub fn get_techniques_for_model(&self, model_type: &ModelType) -> Vec<&EvasionTechnique> {
        self.evasion_techniques
            .iter()
            .filter(|t| t.applicable_models.contains(model_type))
            .collect()
    }

    /// Number of attacks logged so far.
    pub fn attack_count(&self) -> usize {
        self.attack_log.len()
    }

    /// Computes the mean evasion rate across all logged attacks that reported a non-zero
    /// `samples_tested` count. Returns 0.0 if no qualifying attacks exist.
    pub fn overall_evasion_rate(&self) -> f64 {
        let qualifying: Vec<&AttackResult> = self
            .attack_log
            .iter()
            .filter(|r| r.samples_tested > 0)
            .collect();

        if qualifying.is_empty() {
            return 0.0;
        }

        let total_evaded: u32 = qualifying.iter().map(|r| r.samples_evaded).sum();
        let total_tested: u32 = qualifying.iter().map(|r| r.samples_tested).sum();
        total_evaded as f64 / total_tested as f64
    }

    /// Produces a formatted summary of all logged attacks including per-attack details
    /// and aggregate statistics.
    pub fn export_attack_report(&self) -> String {
        let mut lines = Vec::new();
        lines.push("=== Adversarial ML Attack Report ===".to_string());
        lines.push(format!("Total attacks: {}", self.attack_log.len()));
        lines.push(format!(
            "Overall evasion rate: {:.2}%",
            self.overall_evasion_rate() * 100.0
        ));
        lines.push(format!("Payloads generated: {}", self.payloads.len()));
        lines.push(format!(
            "Evasion techniques: {}",
            self.evasion_techniques.len()
        ));
        lines.push(String::new());

        for (i, attack) in self.attack_log.iter().enumerate() {
            lines.push(format!("--- Attack #{} ---", i + 1));
            lines.push(format!("  Type: {}", attack.attack_type));
            lines.push(format!("  Success: {}", attack.success));
            lines.push(format!("  Iterations: {}", attack.iterations_used));
            lines.push(format!(
                "  Evasion rate: {:.2}%",
                attack.evasion_rate * 100.0
            ));
            lines.push(format!(
                "  Confidence: {:.3} -> {:.3}",
                attack.confidence_before, attack.confidence_after
            ));
            lines.push(format!(
                "  Samples: {}/{} evaded",
                attack.samples_evaded, attack.samples_tested
            ));
            lines.push(format!("  Elapsed: {}ms", attack.elapsed_ms));
            lines.push(format!("  Details: {}", attack.details));
            lines.push(String::new());
        }

        lines.join("\n")
    }

    /// Populates the engine with built-in evasion techniques covering the most common
    /// ML WAF bypass strategies.
    pub fn build_default_evasion_techniques(&mut self) {
        self.evasion_techniques.push(EvasionTechnique {
            name: "Unicode Homoglyphs".into(),
            description: "Replace ASCII characters with visually identical Unicode codepoints to bypass character-level ML classifiers".into(),
            applicable_models: vec![ModelType::Classifier, ModelType::NeuralNetwork, ModelType::Ensemble],
            success_rate: 0.72,
        });

        self.evasion_techniques.push(EvasionTechnique {
            name: "Whitespace Injection".into(),
            description: "Insert zero-width spaces and non-breaking spaces between tokens to break tokenizer assumptions".into(),
            applicable_models: vec![ModelType::Classifier, ModelType::NeuralNetwork, ModelType::Detector],
            success_rate: 0.58,
        });

        self.evasion_techniques.push(EvasionTechnique {
            name: "Case Alternation".into(),
            description: "Alternate upper/lower case to evade case-sensitive pattern matching in ML feature extraction".into(),
            applicable_models: vec![ModelType::Classifier, ModelType::DecisionTree, ModelType::Ensemble],
            success_rate: 0.45,
        });

        self.evasion_techniques.push(EvasionTechnique {
            name: "Encoding Tricks".into(),
            description: "Apply URL encoding, HTML entities, and double-encoding to obfuscate payload semantics".into(),
            applicable_models: vec![ModelType::Classifier, ModelType::Detector, ModelType::NeuralNetwork, ModelType::Anomaly],
            success_rate: 0.63,
        });

        self.evasion_techniques.push(EvasionTechnique {
            name: "Comment Injection".into(),
            description: "Insert SQL/HTML/JS comments mid-token to split signature patterns without changing execution semantics".into(),
            applicable_models: vec![ModelType::Classifier, ModelType::Detector, ModelType::DecisionTree],
            success_rate: 0.67,
        });
    }
}

fn apply_homoglyph_substitution(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 2);
    for ch in input.chars() {
        let replacement = HOMOGLYPH_MAP
            .iter()
            .find(|(ascii, _)| *ascii == ch)
            .map(|(_, homo)| *homo)
            .unwrap_or(ch);
        result.push(replacement);
    }
    result
}

fn apply_whitespace_injection(input: &str) -> String {
    let zwsp = '\u{200B}';
    let mut result = String::with_capacity(input.len() * 2);
    for (i, ch) in input.chars().enumerate() {
        result.push(ch);
        if i % 3 == 1 {
            result.push(zwsp);
        }
    }
    result
}

fn apply_case_alternation(input: &str) -> String {
    input
        .chars()
        .enumerate()
        .map(|(i, ch)| {
            if i % 2 == 0 {
                ch.to_uppercase().next().unwrap_or(ch)
            } else {
                ch.to_lowercase().next().unwrap_or(ch)
            }
        })
        .collect()
}
