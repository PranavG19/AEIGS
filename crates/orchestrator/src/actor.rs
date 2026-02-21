use std::sync::atomic::{AtomicU64, Ordering};

use aegis_protocol::finding::FindingData;
use aegis_protocol::operation::ModuleIdentifier;
use aegis_protocol::scan_event::{ScanEvent, ScanEventEnvelope};

use crate::phase_analyze::run_analyze;
use crate::phase_fuzz::{FuzzPhaseResult, FuzzTransport, run_fuzz};
use crate::phase_recon::run_recon_standalone;
use crate::phase_report::run_report_with_previous;
use crate::pipeline::{PhaseResult, ScanContext, collect_fingerprint_ops};
use crate::scan_config::ScanMetrics;

/// Errors produced by actor processing.
#[derive(Debug)]
pub enum ActorError {
    Phase(String),
    Internal(String),
}

impl std::fmt::Display for ActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Phase(msg) => write!(f, "phase: {msg}"),
            Self::Internal(msg) => write!(f, "internal: {msg}"),
        }
    }
}

impl std::error::Error for ActorError {}

/// A scan phase wrapped as an actor that processes events and emits events.
///
/// Each actor receives a batch of input events from prior phases and produces
/// output events for downstream consumers. Source actors (recon, fingerprint)
/// ignore their inputs. The contract is synchronous: `process` blocks until
/// the phase completes and returns all emitted events.
pub trait ScanActor {
    /// Human-readable name of this actor (for logging/metrics).
    fn name(&self) -> &str;

    /// Process a batch of input events and return output events.
    fn process(
        &mut self,
        ctx: &mut ScanContext,
        events: &[ScanEventEnvelope],
    ) -> Result<Vec<ScanEventEnvelope>, ActorError>;
}

static EVENT_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_event_id() -> u64 {
    EVENT_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn make_envelope(source: ModuleIdentifier, event: ScanEvent) -> ScanEventEnvelope {
    ScanEventEnvelope::new(next_event_id(), source, event)
}

fn phase_completed_event(
    source: ModuleIdentifier,
    phase_name: &str,
    result: &PhaseResult,
    start: std::time::Instant,
) -> ScanEventEnvelope {
    make_envelope(
        source,
        ScanEvent::PhaseCompleted {
            phase_name: phase_name.to_string(),
            operations_applied: result.operations_applied,
            findings_count: result.findings_count,
            duration_ms: start.elapsed().as_millis() as u64,
        },
    )
}

/// Source actor that discovers dependencies and filesystem structure.
///
/// Ignores input events. Calls `run_recon_standalone()`, applies operations to the
/// graph, and emits `EndpointDiscovered` events for each endpoint node plus a
/// final `PhaseCompleted` event.
pub struct ReconActor;

impl ScanActor for ReconActor {
    fn name(&self) -> &str {
        "recon"
    }

    fn process(
        &mut self,
        ctx: &mut ScanContext,
        _events: &[ScanEventEnvelope],
    ) -> Result<Vec<ScanEventEnvelope>, ActorError> {
        let start = std::time::Instant::now();
        let source_dir = ctx.config.source_dir.clone();
        let recon_ops = run_recon_standalone(&source_dir).map_err(ActorError::Phase)?;
        let ops_count = recon_ops.len() as u64;

        if !recon_ops.is_empty() {
            ctx.graph
                .apply_operations(&recon_ops)
                .map_err(|e| ActorError::Phase(format!("{e:?}")))?;
        }

        let mut output = emit_endpoint_events(ctx);

        output.push(phase_completed_event(
            ModuleIdentifier::PassiveRecon,
            "recon",
            &PhaseResult {
                operations_applied: ops_count,
                findings_count: 0,
            },
            start,
        ));
        Ok(output)
    }
}

fn emit_endpoint_events(ctx: &ScanContext) -> Vec<ScanEventEnvelope> {
    let endpoint_ids = ctx
        .graph
        .nodes_by_type(aegis_protocol::node::NodeType::Endpoint)
        .unwrap_or_default();
    let mut events = Vec::new();
    for &id in &endpoint_ids {
        if let Some(node) = ctx.graph.get_node(id).ok().flatten() {
            let endpoint = node.properties.get("path").cloned().unwrap_or_default();
            let method = node
                .properties
                .get("method")
                .cloned()
                .unwrap_or_else(|| "GET".to_string());
            events.push(make_envelope(
                ModuleIdentifier::PassiveRecon,
                ScanEvent::EndpointDiscovered {
                    endpoint,
                    method,
                    source_module: ModuleIdentifier::PassiveRecon,
                },
            ));
        }
    }
    events
}

/// Source actor that discovers endpoints via headless browser crawling.
///
/// Ignores input events. Converts a `CrawlResult` into graph operations and
/// emits a `PhaseCompleted` event. Currently uses an empty crawl result as a
/// placeholder until browser integration is activated.
pub struct CrawlActor;

impl ScanActor for CrawlActor {
    fn name(&self) -> &str {
        "crawl"
    }

    fn process(
        &mut self,
        ctx: &mut ScanContext,
        _events: &[ScanEventEnvelope],
    ) -> Result<Vec<ScanEventEnvelope>, ActorError> {
        let start = std::time::Instant::now();
        let crawl_result = aegis_crawler::CrawlResult::default();

        let mut seq = ctx
            .graph
            .total_operations_applied()
            .map_err(|e| ActorError::Phase(format!("{e:?}")))?;
        let crawl_ops = crate::phase_crawl::crawl_result_to_operations(&crawl_result, &mut seq);
        let ops_count = crawl_ops.len() as u64;

        if !crawl_ops.is_empty() {
            ctx.graph
                .apply_operations(&crawl_ops)
                .map_err(|e| ActorError::Phase(format!("{e:?}")))?;
        }

        let event = phase_completed_event(
            ModuleIdentifier::Enumeration,
            "crawl",
            &PhaseResult {
                operations_applied: ops_count,
                findings_count: 0,
            },
            start,
        );
        Ok(vec![event])
    }
}

/// Source actor that probes defense posture (WAF, rate limits, bot detection).
///
/// Ignores input events. Calls `collect_fingerprint_ops()`, applies to the graph,
/// sets `ctx.defense_profile`, and emits a `PhaseCompleted` event.
pub struct FingerprintActor;

impl ScanActor for FingerprintActor {
    fn name(&self) -> &str {
        "fingerprint"
    }

    fn process(
        &mut self,
        ctx: &mut ScanContext,
        _events: &[ScanEventEnvelope],
    ) -> Result<Vec<ScanEventEnvelope>, ActorError> {
        let start = std::time::Instant::now();
        let mut seq = ctx
            .graph
            .total_operations_applied()
            .map_err(|e| ActorError::Phase(format!("{e:?}")))?;
        let (fp_ops, profile) = collect_fingerprint_ops(&mut seq);
        let ops_count = fp_ops.len() as u64;

        if !fp_ops.is_empty() {
            ctx.graph
                .apply_operations(&fp_ops)
                .map_err(|e| ActorError::Phase(format!("{e:?}")))?;
        }
        ctx.defense_profile = Some(profile);

        let event = phase_completed_event(
            ModuleIdentifier::Enumeration,
            "fingerprint",
            &PhaseResult {
                operations_applied: ops_count,
                findings_count: 0,
            },
            start,
        );
        Ok(vec![event])
    }
}

/// Actor that drives the fuzzing phase.
///
/// Processes `EndpointDiscovered` and `HypothesisGenerated` events for future
/// extensibility; current implementation delegates to `run_fuzz()`. Emits
/// `PayloadTested` / `AnomalyDetected` events per finding and a final
/// `PhaseCompleted` event.
pub struct FuzzActor<T: FuzzTransport> {
    transport: T,
}

impl<T: FuzzTransport> FuzzActor<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}

impl<T: FuzzTransport> FuzzActor<T> {
    /// Async process entry point since `run_fuzz` is async.
    pub async fn process_async(
        &mut self,
        ctx: &mut ScanContext,
        _events: &[ScanEventEnvelope],
    ) -> Result<Vec<ScanEventEnvelope>, ActorError> {
        let start = std::time::Instant::now();
        let fuzz_result = run_fuzz(ctx, &mut self.transport)
            .await
            .map_err(ActorError::Phase)?;

        let mut output = fuzz_result_to_events(&fuzz_result);
        output.push(phase_completed_event(
            ModuleIdentifier::Fuzzing,
            "fuzz",
            &fuzz_result.phase,
            start,
        ));
        Ok(output)
    }
}

fn fuzz_result_to_events(result: &FuzzPhaseResult) -> Vec<ScanEventEnvelope> {
    let mut events = Vec::with_capacity(result.phase.findings_count as usize);
    for _ in 0..result.phase.findings_count {
        events.push(make_envelope(
            ModuleIdentifier::Fuzzing,
            ScanEvent::AnomalyDetected {
                endpoint: String::new(),
                vulnerability_class: aegis_protocol::finding::VulnerabilityClass::SqlInjection,
                anomaly_type: "fuzz-finding".to_string(),
                score: 0.0,
            },
        ));
    }
    events
}

/// Actor that builds attack graphs and discovers chained vulnerabilities.
///
/// Processes `AnomalyDetected` events for future extensibility; current
/// implementation delegates to `run_analyze()`. Emits `FindingConfirmed`
/// events for each chain finding and a `PhaseCompleted` event.
pub struct AnalyzeActor;

impl ScanActor for AnalyzeActor {
    fn name(&self) -> &str {
        "analyze"
    }

    fn process(
        &mut self,
        ctx: &mut ScanContext,
        _events: &[ScanEventEnvelope],
    ) -> Result<Vec<ScanEventEnvelope>, ActorError> {
        let start = std::time::Instant::now();
        let result = run_analyze(ctx).map_err(ActorError::Phase)?;

        let mut output = Vec::new();
        for i in 0..result.findings_count {
            output.push(make_envelope(
                ModuleIdentifier::ChainSynthesis,
                ScanEvent::FindingConfirmed {
                    finding_id: i,
                    vulnerability_class:
                        aegis_protocol::finding::VulnerabilityClass::BrokenAuthorization,
                    severity: 1.0,
                    confidence: 0.7,
                },
            ));
        }

        output.push(phase_completed_event(
            ModuleIdentifier::ChainSynthesis,
            "analyze",
            &result,
            start,
        ));
        Ok(output)
    }
}

/// Actor that generates the final SARIF report.
///
/// Consumes all accumulated events (for future summary use), then delegates to
/// `run_report_with_previous()`. Emits a `PhaseCompleted` event.
pub struct ReportActor {
    metrics: Option<ScanMetrics>,
    previous_findings: Option<Vec<FindingData>>,
}

impl ReportActor {
    pub fn new(metrics: Option<ScanMetrics>, previous_findings: Option<Vec<FindingData>>) -> Self {
        Self {
            metrics,
            previous_findings,
        }
    }
}

impl ScanActor for ReportActor {
    fn name(&self) -> &str {
        "report"
    }

    fn process(
        &mut self,
        ctx: &mut ScanContext,
        _events: &[ScanEventEnvelope],
    ) -> Result<Vec<ScanEventEnvelope>, ActorError> {
        let start = std::time::Instant::now();
        let result = run_report_with_previous(
            ctx,
            self.metrics.as_ref(),
            self.previous_findings.as_deref(),
        )
        .map_err(ActorError::Phase)?;

        let event =
            phase_completed_event(ModuleIdentifier::ChainSynthesis, "report", &result, start);
        Ok(vec![event])
    }
}

/// Observer actor that tracks consecutive zero-finding rounds to determine
/// when the fuzz-analyze loop should stop.
///
/// Examines `FindingConfirmed` events and `PhaseCompleted` events for
/// "fuzz" and "analyze" phases. After each fuzz+analyze pair, if no findings
/// were confirmed, the consecutive-zero counter increments.
pub struct ConvergenceActor {
    threshold: u32,
    consecutive_zero_rounds: u32,
    current_round_findings: u64,
}

impl ConvergenceActor {
    pub fn new(threshold: u32) -> Self {
        Self {
            threshold,
            consecutive_zero_rounds: 0,
            current_round_findings: 0,
        }
    }

    /// Whether the fuzz-analyze loop should stop due to convergence.
    pub fn should_stop(&self) -> bool {
        self.consecutive_zero_rounds >= self.threshold
    }

    pub fn consecutive_zero_rounds(&self) -> u32 {
        self.consecutive_zero_rounds
    }
}

impl ScanActor for ConvergenceActor {
    fn name(&self) -> &str {
        "convergence"
    }

    fn process(
        &mut self,
        _ctx: &mut ScanContext,
        events: &[ScanEventEnvelope],
    ) -> Result<Vec<ScanEventEnvelope>, ActorError> {
        for envelope in events {
            match &envelope.event {
                ScanEvent::FindingConfirmed { .. } => {
                    self.current_round_findings += 1;
                }
                ScanEvent::PhaseCompleted { phase_name, .. } if phase_name == "analyze" => {
                    if self.current_round_findings == 0 {
                        self.consecutive_zero_rounds += 1;
                    } else {
                        self.consecutive_zero_rounds = 0;
                    }
                    self.current_round_findings = 0;
                }
                _ => {}
            }
        }
        Ok(Vec::new())
    }
}

/// Runs the full scan pipeline using the actor abstraction.
///
/// This is an alternative entry point to `run_scan_phases()` that routes
/// data between phases via `ScanEventEnvelope`s. The existing `run_scan()`
/// is not modified.
pub async fn run_actor_pipeline<T: FuzzTransport>(
    ctx: &mut ScanContext,
    transport: T,
    previous_findings: Option<Vec<FindingData>>,
) -> Result<Vec<ScanEventEnvelope>, ActorError> {
    let mut all_events: Vec<ScanEventEnvelope> = Vec::new();

    let mut recon = ReconActor;
    let recon_events = recon.process(ctx, &[])?;
    all_events.extend(recon_events);

    let mut crawl = CrawlActor;
    let crawl_events = crawl.process(ctx, &[])?;
    all_events.extend(crawl_events);

    if !ctx.config.pipeline.skip_fingerprint {
        let mut fingerprint = FingerprintActor;
        let fp_events = fingerprint.process(ctx, &[])?;
        all_events.extend(fp_events);
    }

    let max_iterations = ctx.config.pipeline.max_iterations;
    let convergence_threshold = ctx.config.pipeline.convergence_threshold;
    let mut fuzz_actor = FuzzActor::new(transport);
    let mut analyze_actor = AnalyzeActor;
    let mut convergence = ConvergenceActor::new(convergence_threshold);

    for iteration in 0..max_iterations {
        let fuzz_events = fuzz_actor.process_async(ctx, &all_events).await?;
        all_events.extend(fuzz_events.clone());

        let analyze_events = analyze_actor.process(ctx, &fuzz_events)?;
        all_events.extend(analyze_events.clone());

        let round_events: Vec<_> = fuzz_events.into_iter().chain(analyze_events).collect();
        convergence.process(ctx, &round_events)?;

        if convergence.should_stop() && iteration + 1 < max_iterations {
            break;
        }
    }

    let mut report = ReportActor::new(None, previous_findings);
    let report_events = report.process(ctx, &all_events)?;
    all_events.extend(report_events);

    Ok(all_events)
}
