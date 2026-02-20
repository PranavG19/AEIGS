use std::collections::HashMap;

use aegis_fuzzing::mutator::PayloadMutator;
use aegis_fuzzing::oracle::FuzzOracle;
use aegis_fuzzing::scheduler::{FuzzScheduler, FuzzTarget};
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::pipeline::{PhaseResult, ScanContext};
use crate::scan_config::{load_business_context, parse_stealth_level};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingOrigin {
    LlmHypothesis,
    StaticRule,
    Mutation,
}

#[derive(Debug, Clone)]
pub struct FuzzPhaseResult {
    pub phase: PhaseResult,
    pub origin_counts: HashMap<FindingOrigin, u64>,
    pub discovered_endpoints: Vec<String>,
}

pub async fn run_fuzz(ctx: &mut ScanContext) -> Result<FuzzPhaseResult, String> {
    let mut scheduler = FuzzScheduler::new();
    let endpoints = ctx
        .graph
        .nodes_by_type(aegis_protocol::node::NodeType::Endpoint)
        .map_err(|e| format!("{e:?}"))?;
    enqueue_targets_for_endpoints(&mut scheduler, &endpoints, ctx);
    filter_scheduler_by_endpoints(
        &mut scheduler,
        &ctx.config.include_endpoints,
        &ctx.config.exclude_endpoints,
    );

    if let Some(context_path) = &ctx.config.context_file
        && let Ok(biz_ctx) = load_business_context(context_path)
        && !biz_ctx.excluded_endpoints.is_empty()
    {
        filter_scheduler_by_endpoints(&mut scheduler, &None, &Some(biz_ctx.excluded_endpoints));
    }

    let mut mutator = PayloadMutator::new();
    if let Some(corpus_path) = &ctx.config.bypass_corpus
        && let Ok(corpus) = aegis_fuzzing::mutator::load_bypass_corpus(corpus_path)
    {
        mutator = mutator.with_bypass_corpus(corpus);
    }

    if ctx.config.stealth
        && let Ok(level) = parse_stealth_level(&ctx.config.stealth_level)
    {
        let stealth_config = build_stealth_config(&level);
        scheduler.reprioritize_for_stealth(&stealth_config);
    }

    let oracle = FuzzOracle::new(0.7);
    let mut entries = Vec::new();
    let mut sequence = ctx
        .graph
        .total_operations_applied()
        .map_err(|e| format!("{e:?}"))?;
    let mut findings_count = 0u64;
    let mut origin_counts: HashMap<FindingOrigin, u64> = HashMap::new();

    while let Some(target) = scheduler.next_target() {
        let payloads = if ctx.config.stealth {
            mutator.generate_stealth_payloads(target.vulnerability_class, 10)
        } else {
            mutator.generate_payloads(target.vulnerability_class, 10)
        };

        for payload in &payloads {
            let anomalies = oracle.analyze_response(
                &build_placeholder_response(target.endpoint.clone()),
                &payload.raw,
                &target.endpoint,
                &target.method,
            );

            for anomaly in &anomalies {
                sequence += 1;
                findings_count += 1;
                *origin_counts.entry(FindingOrigin::Mutation).or_insert(0) += 1;
                entries.push(OperationLogEntry {
                    sequence_number: sequence,
                    module: ModuleIdentifier::Fuzzing,
                    operation: GraphOperation::AddFinding {
                        linked_node_ids: vec![],
                        vulnerability_class: target.vulnerability_class,
                        severity: anomaly.score,
                        confidence: anomaly.score * 0.8,
                        certificate: Vec::new(),
                    },
                    timestamp_unix_ms: timestamp_ms(),
                });
            }
        }
        scheduler.mark_completed(target);
    }

    let ops_count = entries.len() as u64;
    if !entries.is_empty() {
        ctx.graph
            .apply_operations(&entries)
            .map_err(|e| format!("{e:?}"))?;
    }

    Ok(FuzzPhaseResult {
        phase: PhaseResult {
            operations_applied: ops_count,
            findings_count,
        },
        origin_counts,
        discovered_endpoints: Vec::new(),
    })
}

pub(crate) fn enqueue_targets_for_endpoints(
    scheduler: &mut FuzzScheduler,
    endpoint_ids: &[u64],
    ctx: &ScanContext,
) {
    for &id in endpoint_ids {
        if let Some(node) = ctx.graph.get_node(id).ok().flatten() {
            let endpoint = node.properties.get("path").cloned().unwrap_or_default();
            let method = node
                .properties
                .get("method")
                .cloned()
                .unwrap_or_else(|| "GET".to_string());

            for class in fuzzable_classes() {
                scheduler.enqueue(FuzzTarget {
                    endpoint: endpoint.clone(),
                    method: method.clone(),
                    parameter: String::new(),
                    vulnerability_class: class,
                    priority_score: 1.0,
                    attempts: 0,
                    max_attempts: 3,
                });
            }
        }
    }
}

pub(crate) fn filter_scheduler_by_endpoints(
    scheduler: &mut FuzzScheduler,
    include: &Option<Vec<String>>,
    exclude: &Option<Vec<String>>,
) {
    if include.is_none() && exclude.is_none() {
        return;
    }
    let mut targets = Vec::new();
    while let Some(target) = scheduler.next_target() {
        targets.push(target);
    }
    for target in targets {
        let dominated = if let Some(inc) = include {
            !inc.contains(&target.endpoint)
        } else {
            false
        };
        let excluded = if let Some(exc) = exclude {
            exc.contains(&target.endpoint)
        } else {
            false
        };
        if !dominated && !excluded {
            scheduler.enqueue(target);
        }
    }
}

pub(crate) fn fuzzable_classes() -> Vec<VulnerabilityClass> {
    vec![
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::ServerSideRequestForgery,
    ]
}

pub(crate) fn build_stealth_config(
    level: &crate::scan_config::StealthLevel,
) -> aegis_fuzzing::stealth_config::StealthConfig {
    use crate::scan_config::StealthLevel;
    match level {
        StealthLevel::Default => aegis_fuzzing::stealth_config::StealthConfig::default(),
        StealthLevel::Aggressive => aegis_fuzzing::stealth_config::StealthConfig::aggressive(),
        StealthLevel::Paranoid => aegis_fuzzing::stealth_config::StealthConfig::paranoid(),
    }
}

pub(crate) fn build_placeholder_response(
    _endpoint: String,
) -> aegis_fuzzing::executor::FuzzResponse {
    use std::time::Duration;
    aegis_fuzzing::executor::FuzzResponse {
        request_id: 0,
        status_code: 200,
        body: String::new(),
        headers: vec![],
        response_time: Duration::from_millis(100),
        body_size_bytes: 0,
    }
}

fn timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
