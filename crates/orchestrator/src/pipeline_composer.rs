use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

/// Categorizes how a pipeline stage interacts with the event stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhaseType {
    /// Produces events from external data (recon, fingerprint).
    Source,
    /// Processes events and produces new events (fuzz, analyze).
    Transform,
    /// Consumes events and produces output (report).
    Sink,
    /// Reads events without transforming them (convergence, telemetry).
    Observer,
}

/// A single stage in a declarative pipeline definition.
#[derive(Debug, Clone)]
pub struct PipelineStage {
    /// Unique name identifying this stage (e.g., "recon", "fuzz").
    pub name: String,
    /// How this stage interacts with the event stream.
    pub phase_type: PhaseType,
    /// Stage names that must complete before this one runs.
    pub depends_on: Vec<String>,
    /// Whether this stage can be skipped without failing the pipeline.
    pub optional: bool,
    /// Number of times to retry on failure before giving up.
    pub max_retries: u32,
}

impl PipelineStage {
    /// Creates a new stage with the given name and phase type.
    ///
    /// Defaults: no dependencies, not optional, zero retries.
    pub fn new(name: impl Into<String>, phase_type: PhaseType) -> Self {
        Self {
            name: name.into(),
            phase_type,
            depends_on: Vec::new(),
            optional: false,
            max_retries: 0,
        }
    }

    /// Adds a dependency on another stage by name.
    pub fn with_dependency(mut self, dep: impl Into<String>) -> Self {
        self.depends_on.push(dep.into());
        self
    }

    /// Marks this stage as optional.
    pub fn with_optional(mut self, optional: bool) -> Self {
        self.optional = optional;
        self
    }

    /// Sets the maximum retry count for this stage.
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }
}

/// Declarative specification of a scan pipeline's stages and iteration behavior.
#[derive(Debug, Clone)]
pub struct PipelineDefinition {
    /// Ordered list of stages in the pipeline.
    pub stages: Vec<PipelineStage>,
    /// Maximum fuzz-analyze iteration rounds.
    pub max_iterations: u32,
    /// Consecutive zero-finding rounds before stopping iteration.
    pub convergence_threshold: u32,
}

impl PipelineDefinition {
    /// Creates an empty pipeline definition with default iteration settings.
    pub fn new() -> Self {
        Self {
            stages: Vec::new(),
            max_iterations: 1,
            convergence_threshold: 2,
        }
    }

    /// Appends a stage to the pipeline.
    pub fn add_stage(&mut self, stage: PipelineStage) -> &mut Self {
        self.stages.push(stage);
        self
    }

    /// Sets the maximum number of fuzz-analyze iterations.
    pub fn with_max_iterations(&mut self, n: u32) -> &mut Self {
        self.max_iterations = n;
        self
    }

    /// Sets how many consecutive zero-finding rounds trigger convergence.
    pub fn with_convergence_threshold(&mut self, n: u32) -> &mut Self {
        self.convergence_threshold = n;
        self
    }
}

impl Default for PipelineDefinition {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of executing a single pipeline stage.
#[derive(Debug, Clone)]
pub struct StageResult {
    pub stage_name: String,
    pub events_produced: usize,
    pub events_consumed: usize,
    pub duration_ms: u64,
    pub retries_used: u32,
    pub skipped: bool,
    pub error: Option<String>,
}

impl StageResult {
    /// Creates a default result for the named stage with zero counts.
    pub fn new(stage_name: impl Into<String>) -> Self {
        Self {
            stage_name: stage_name.into(),
            events_produced: 0,
            events_consumed: 0,
            duration_ms: 0,
            retries_used: 0,
            skipped: false,
            error: None,
        }
    }
}

/// Aggregate result of running the full pipeline.
#[derive(Debug, Clone)]
pub struct PipelineResult {
    pub stage_results: Vec<StageResult>,
    pub total_events: usize,
    pub total_duration_ms: u64,
    pub converged: bool,
    pub iterations_completed: u32,
}

impl PipelineResult {
    /// Creates an empty pipeline result.
    pub fn new() -> Self {
        Self {
            stage_results: Vec::new(),
            total_events: 0,
            total_duration_ms: 0,
            converged: false,
            iterations_completed: 0,
        }
    }
}

impl Default for PipelineResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors arising from pipeline definition validation or composition.
#[derive(Debug, Clone)]
pub enum ComposerError {
    /// Two stages share the same name.
    DuplicateStageName(String),
    /// A `depends_on` entry references a stage that does not exist.
    MissingDependency { stage: String, dependency: String },
    /// A cycle was detected among stage dependencies.
    CyclicDependency(String),
    /// The pipeline has no stages.
    EmptyPipeline,
    /// No stage has `PhaseType::Source`.
    NoSourceStage,
    /// No stage has `PhaseType::Sink`.
    NoSinkStage,
}

impl fmt::Display for ComposerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateStageName(name) => {
                write!(f, "duplicate stage name: {name}")
            }
            Self::MissingDependency { stage, dependency } => {
                write!(f, "stage '{stage}' depends on unknown stage '{dependency}'")
            }
            Self::CyclicDependency(detail) => {
                write!(f, "cyclic dependency detected: {detail}")
            }
            Self::EmptyPipeline => write!(f, "pipeline has no stages"),
            Self::NoSourceStage => {
                write!(f, "pipeline has no Source stage")
            }
            Self::NoSinkStage => {
                write!(f, "pipeline has no Sink stage")
            }
        }
    }
}

impl std::error::Error for ComposerError {}

/// Validates that a pipeline definition is well-formed.
///
/// Checks: non-empty, unique names, all dependencies exist, no cycles,
/// at least one Source and one Sink stage.
pub fn validate_pipeline(definition: &PipelineDefinition) -> Result<(), ComposerError> {
    if definition.stages.is_empty() {
        return Err(ComposerError::EmptyPipeline);
    }

    let mut seen = HashSet::new();
    for stage in &definition.stages {
        if !seen.insert(&stage.name) {
            return Err(ComposerError::DuplicateStageName(stage.name.clone()));
        }
    }

    for stage in &definition.stages {
        for dep in &stage.depends_on {
            if !seen.contains(dep) {
                return Err(ComposerError::MissingDependency {
                    stage: stage.name.clone(),
                    dependency: dep.clone(),
                });
            }
        }
    }

    let has_source = definition
        .stages
        .iter()
        .any(|s| s.phase_type == PhaseType::Source);
    if !has_source {
        return Err(ComposerError::NoSourceStage);
    }

    let has_sink = definition
        .stages
        .iter()
        .any(|s| s.phase_type == PhaseType::Sink);
    if !has_sink {
        return Err(ComposerError::NoSinkStage);
    }

    topological_order(definition)?;

    Ok(())
}

/// Returns stage names in a valid topological execution order using Kahn's algorithm.
///
/// Errors if the dependency graph contains a cycle.
pub fn topological_order(definition: &PipelineDefinition) -> Result<Vec<String>, ComposerError> {
    let name_to_idx: HashMap<&str, usize> = definition
        .stages
        .iter()
        .enumerate()
        .map(|(i, s)| (s.name.as_str(), i))
        .collect();

    let n = definition.stages.len();
    let mut in_degree = vec![0u32; n];
    let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); n];

    for (i, stage) in definition.stages.iter().enumerate() {
        for dep in &stage.depends_on {
            if let Some(&dep_idx) = name_to_idx.get(dep.as_str()) {
                adjacency[dep_idx].push(i);
                in_degree[i] += 1;
            }
        }
    }

    let mut queue: VecDeque<usize> = VecDeque::new();
    for (i, &deg) in in_degree.iter().enumerate() {
        if deg == 0 {
            queue.push_back(i);
        }
    }

    let mut order = Vec::with_capacity(n);
    while let Some(idx) = queue.pop_front() {
        order.push(definition.stages[idx].name.clone());
        for &neighbor in &adjacency[idx] {
            in_degree[neighbor] -= 1;
            if in_degree[neighbor] == 0 {
                queue.push_back(neighbor);
            }
        }
    }

    if order.len() != n {
        let remaining: Vec<String> = definition
            .stages
            .iter()
            .enumerate()
            .filter(|(i, _)| in_degree[*i] > 0)
            .map(|(_, s)| s.name.clone())
            .collect();
        return Err(ComposerError::CyclicDependency(remaining.join(", ")));
    }

    Ok(order)
}

/// Returns the standard 5-stage pipeline: recon, fingerprint, fuzz, analyze, report.
pub fn default_pipeline() -> PipelineDefinition {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("recon", PhaseType::Source));
    def.add_stage(
        PipelineStage::new("fingerprint", PhaseType::Source)
            .with_dependency("recon")
            .with_optional(true),
    );
    def.add_stage(PipelineStage::new("fuzz", PhaseType::Transform).with_dependency("recon"));
    def.add_stage(PipelineStage::new("analyze", PhaseType::Transform).with_dependency("fuzz"));
    def.add_stage(PipelineStage::new("report", PhaseType::Sink).with_dependency("analyze"));
    def.max_iterations = 1;
    def.convergence_threshold = 2;
    def
}

/// Returns a minimal 3-stage pipeline: recon, fuzz, report.
pub fn minimal_pipeline() -> PipelineDefinition {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("recon", PhaseType::Source));
    def.add_stage(PipelineStage::new("fuzz", PhaseType::Transform).with_dependency("recon"));
    def.add_stage(PipelineStage::new("report", PhaseType::Sink).with_dependency("fuzz"));
    def.max_iterations = 1;
    def.convergence_threshold = 2;
    def
}

/// Returns a reconnaissance-only pipeline: recon, report.
pub fn recon_only_pipeline() -> PipelineDefinition {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("recon", PhaseType::Source));
    def.add_stage(PipelineStage::new("report", PhaseType::Sink).with_dependency("recon"));
    def.max_iterations = 1;
    def.convergence_threshold = 2;
    def
}

/// Groups stages into execution waves where each wave's stages have all
/// dependencies satisfied by prior waves.
///
/// Stages within the same wave could theoretically run concurrently.
pub fn execution_plan(definition: &PipelineDefinition) -> Result<Vec<Vec<String>>, ComposerError> {
    let order = topological_order(definition)?;

    let name_to_idx: HashMap<&str, usize> = definition
        .stages
        .iter()
        .enumerate()
        .map(|(i, s)| (s.name.as_str(), i))
        .collect();

    let mut stage_wave: HashMap<&str, usize> = HashMap::new();
    let mut max_wave = 0;

    for name in &order {
        let idx = name_to_idx[name.as_str()];
        let stage = &definition.stages[idx];
        let wave = if stage.depends_on.is_empty() {
            0
        } else {
            stage
                .depends_on
                .iter()
                .map(|dep| stage_wave[dep.as_str()] + 1)
                .max()
                .unwrap_or(0)
        };
        stage_wave.insert(name.as_str(), wave);
        if wave > max_wave {
            max_wave = wave;
        }
    }

    let mut waves: Vec<Vec<String>> = vec![Vec::new(); max_wave + 1];
    for name in &order {
        let wave = stage_wave[name.as_str()];
        waves[wave].push(name.clone());
    }

    Ok(waves)
}

/// Returns a human-readable description of the pipeline flow.
pub fn describe_pipeline(definition: &PipelineDefinition) -> String {
    if definition.stages.is_empty() {
        return "empty pipeline".to_string();
    }

    let names: Vec<&str> = definition.stages.iter().map(|s| s.name.as_str()).collect();
    names.join(" -> ")
}
