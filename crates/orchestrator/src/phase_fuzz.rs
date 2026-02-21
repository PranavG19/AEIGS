use std::collections::HashMap;

use aegis_fuzzing::mutator::PayloadMutator;
use aegis_fuzzing::oracle::FuzzOracle;
use aegis_fuzzing::scheduler::{FuzzScheduler, FuzzTarget};
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};
use aegis_protocol::request::{FuzzRequest, FuzzResponse, ParameterLocation};

use crate::auth_session::{AuthenticatedSession, execute_auth_flow, inject_auth_into_request};
use crate::pipeline::{PhaseResult, ScanContext};
use crate::scan_config::{load_business_context, parse_stealth_level};
use crate::util::timestamp_ms;

pub trait FuzzTransport {
    fn send(
        &mut self,
        request: &FuzzRequest,
    ) -> impl std::future::Future<Output = Result<FuzzResponse, String>> + Send;
}

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
    pub transport_errors: u64,
    pub was_authenticated: bool,
}

pub fn build_fuzz_request(
    target_base: &str,
    target: &FuzzTarget,
    payload: &str,
    request_id: u64,
) -> FuzzRequest {
    FuzzRequest {
        request_id,
        endpoint: format!("{}{}", target_base, target.endpoint),
        method: target.method.clone(),
        parameter_name: target.parameter.clone(),
        parameter_location: target.parameter_location,
        payload: payload.to_string(),
        headers: {
            let mut h = vec![];
            if target.parameter_location == ParameterLocation::Body {
                h.push(("Content-Type".to_string(), "application/json".to_string()));
            }
            h
        },
    }
}

pub async fn run_fuzz<T: FuzzTransport>(
    ctx: &mut ScanContext,
    transport: &mut T,
) -> Result<FuzzPhaseResult, String> {
    let mut scheduler = FuzzScheduler::new();
    let endpoints = ctx
        .graph
        .nodes_by_type(aegis_protocol::node::NodeType::Endpoint)
        .map_err(|e| format!("{e:?}"))?;

    let endpoint_node_map = build_endpoint_node_map(&endpoints, ctx);
    enqueue_targets_for_endpoints(&mut scheduler, &endpoints, ctx);
    filter_scheduler_by_endpoints(
        &mut scheduler,
        &ctx.config.scope.include_endpoints,
        &ctx.config.scope.exclude_endpoints,
    );

    if let Some(context_path) = &ctx.config.scope.context_file
        && let Ok(biz_ctx) = load_business_context(context_path)
        && !biz_ctx.excluded_endpoints.is_empty()
    {
        filter_scheduler_by_endpoints(&mut scheduler, &None, &Some(biz_ctx.excluded_endpoints));
    }

    let mut mutator = PayloadMutator::new();
    if let Some(corpus_path) = &ctx.config.llm.bypass_corpus
        && let Ok(corpus) = aegis_fuzzing::mutator::load_bypass_corpus(corpus_path)
    {
        mutator = mutator.with_bypass_corpus(corpus);
    }

    if ctx.config.stealth.stealth
        && let Ok(level) = parse_stealth_level(&ctx.config.stealth.stealth_level)
    {
        let stealth_config = build_stealth_config(&level);
        scheduler.reprioritize_for_stealth(&stealth_config);
    }

    let mut authenticated_session = attempt_auth(ctx, transport, "initial auth").await;

    let oracle = FuzzOracle::new(0.7);
    let mut entries = Vec::new();
    let mut sequence = ctx
        .graph
        .total_operations_applied()
        .map_err(|e| format!("{e:?}"))?;
    let mut findings_count = 0u64;
    let mut transport_errors = 0u64;
    let mut origin_counts: HashMap<FindingOrigin, u64> = HashMap::new();
    let mut next_request_id = 0u64;
    let target_base = ctx.config.target.clone();

    while let Some(target) = scheduler.next_target() {
        let payloads = if ctx.config.stealth.stealth {
            mutator.generate_stealth_payloads(target.vulnerability_class, 10)
        } else {
            mutator.generate_payloads(target.vulnerability_class, 10)
        };

        let endpoint_node_id = endpoint_node_map.get(&target.endpoint).copied();
        let linked = endpoint_node_id.map(|id| vec![id]).unwrap_or_default();

        for payload in &payloads {
            let mut request =
                build_fuzz_request(&target_base, &target, &payload.raw, next_request_id);
            next_request_id += 1;

            if let Some(ref session) = authenticated_session {
                inject_auth_into_request(&mut request, session);
            }

            let mut response = match transport.send(&request).await {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!(
                        endpoint = %request.endpoint,
                        error = %e,
                        "transport error, skipping payload"
                    );
                    transport_errors += 1;
                    continue;
                }
            };

            if response.status_code == 401
                && let Some(new_session) = attempt_auth(ctx, transport, "re-auth after 401").await
            {
                authenticated_session = Some(new_session);
                let mut retry_request =
                    build_fuzz_request(&target_base, &target, &payload.raw, request.request_id);
                inject_auth_into_request(
                    &mut retry_request,
                    authenticated_session.as_ref().unwrap(),
                );
                match transport.send(&retry_request).await {
                    Ok(r) => response = r,
                    Err(e) => {
                        tracing::warn!(
                            endpoint = %retry_request.endpoint,
                            error = %e,
                            "transport error on retry after re-auth"
                        );
                        transport_errors += 1;
                        continue;
                    }
                }
            }

            let anomalies =
                oracle.analyze_response(&response, &payload.raw, &target.endpoint, &target.method);

            append_anomaly_entries(
                &anomalies,
                target.vulnerability_class,
                &linked,
                &mut sequence,
                &mut findings_count,
                &mut origin_counts,
                &mut entries,
            );
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
        transport_errors,
        was_authenticated: authenticated_session.is_some(),
    })
}

async fn attempt_auth<T: FuzzTransport>(
    ctx: &ScanContext,
    transport: &mut T,
    context: &str,
) -> Option<AuthenticatedSession> {
    let flow = ctx.auth_flow.as_ref()?;
    match execute_auth_flow(flow, transport, &ctx.auth_inputs, &ctx.config.target).await {
        Ok(session) => {
            tracing::info!("{context}: auth flow succeeded");
            Some(session)
        }
        Err(e) => {
            tracing::warn!(error = %e, "{context}: auth flow failed, continuing without auth");
            None
        }
    }
}

fn build_endpoint_node_map(endpoint_ids: &[u64], ctx: &ScanContext) -> HashMap<String, u64> {
    let mut map = HashMap::new();
    for &id in endpoint_ids {
        if let Some(node) = ctx.graph.get_node(id).ok().flatten()
            && let Some(path) = node.properties.get("path")
        {
            map.insert(path.clone(), id);
        }
    }
    map
}

pub(crate) fn parse_parameter_location(s: &str) -> ParameterLocation {
    match s {
        "Body" => ParameterLocation::Body,
        "Path" => ParameterLocation::Path,
        "Header" => ParameterLocation::Header,
        "Cookie" => ParameterLocation::Cookie,
        _ => ParameterLocation::Query,
    }
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

            let params: Vec<serde_json::Value> = node
                .properties
                .get("parameters")
                .and_then(|p| serde_json::from_str(p).ok())
                .unwrap_or_default();

            if params.is_empty() {
                let default_param = if method == "POST" { "cmd" } else { "input" };
                let default_location = if method == "POST" {
                    ParameterLocation::Body
                } else {
                    ParameterLocation::Query
                };
                for class in fuzzable_classes() {
                    scheduler.enqueue(FuzzTarget {
                        endpoint: endpoint.clone(),
                        method: method.clone(),
                        parameter: default_param.to_string(),
                        parameter_location: default_location,
                        vulnerability_class: class,
                        priority_score: 1.0,
                        attempts: 0,
                        max_attempts: 3,
                    });
                }
            } else {
                for param in &params {
                    let name = param["name"].as_str().unwrap_or_default().to_string();
                    let location =
                        parse_parameter_location(param["location"].as_str().unwrap_or("Query"));
                    for class in fuzzable_classes() {
                        scheduler.enqueue(FuzzTarget {
                            endpoint: endpoint.clone(),
                            method: method.clone(),
                            parameter: name.clone(),
                            parameter_location: location,
                            vulnerability_class: class,
                            priority_score: 1.0,
                            attempts: 0,
                            max_attempts: 3,
                        });
                    }
                }
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
        VulnerabilityClass::ServerSideTemplateInjection,
        VulnerabilityClass::HeaderInjection,
        VulnerabilityClass::OpenRedirect,
        VulnerabilityClass::CrlfInjection,
        VulnerabilityClass::InsecureDeserialization,
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

impl FuzzTransport for aegis_evasion_engine::EvasionTransport {
    async fn send(&mut self, request: &FuzzRequest) -> Result<FuzzResponse, String> {
        aegis_evasion_engine::EvasionTransport::send(self, request)
            .await
            .map_err(|e| e.to_string())
    }
}

pub(crate) fn append_anomaly_entries(
    anomalies: &[aegis_fuzzing::oracle::Anomaly],
    vulnerability_class: VulnerabilityClass,
    linked_node_ids: &[u64],
    sequence: &mut u64,
    findings_count: &mut u64,
    origin_counts: &mut HashMap<FindingOrigin, u64>,
    entries: &mut Vec<OperationLogEntry>,
) {
    for anomaly in anomalies {
        *sequence += 1;
        *findings_count += 1;
        *origin_counts.entry(FindingOrigin::Mutation).or_insert(0) += 1;
        entries.push(OperationLogEntry {
            sequence_number: *sequence,
            module: ModuleIdentifier::Fuzzing,
            operation: GraphOperation::AddFinding {
                linked_node_ids: linked_node_ids.to_vec(),
                vulnerability_class,
                severity: anomaly.score,
                confidence: (anomaly.score * 0.8).min(1.0),
                certificate: Vec::new(),
            },
            timestamp_unix_ms: timestamp_ms(),
        });
    }
}
