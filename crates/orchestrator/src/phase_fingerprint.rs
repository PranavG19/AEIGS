use std::time::Duration;

use aegis_enumeration::introspection::IntrospectedEndpoint;
use aegis_exploiter::{ExploitContext, HttpxWrapper, ToolWrapper, spawn_with_timeout};
use aegis_fuzzing::DefenseProfile;
use aegis_fuzzing::bot_detection_probe::{BotProbeResult, analyze_bot_detection};
use aegis_fuzzing::rate_limit_detector::{
    BurstProbeResult, RateLimitProbeResult, build_rate_limit_profile,
};
use aegis_fuzzing::waf_fingerprinter::{
    WafProbeResult, build_waf_profile, identify_blocked_categories, identify_vendor,
};
use aegis_protocol::edge::EdgeLabel;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::phase_error::PhaseError;
use crate::pipeline::{PhaseResult, ScanContext};
use crate::util::timestamp_ms;

const WAF_PROBE_PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "' OR 1=1 --",
    "../../etc/passwd",
    "; cat /etc/passwd",
];

const WAF_CATEGORY_PROBES: &[(VulnerabilityClass, &str)] = &[
    (VulnerabilityClass::SqlInjection, "' OR 1=1 --"),
    (
        VulnerabilityClass::CrossSiteScripting,
        "<script>alert(1)</script>",
    ),
    (VulnerabilityClass::CommandInjection, "; cat /etc/passwd"),
    (VulnerabilityClass::PathTraversal, "../../etc/passwd"),
];

const PROBE_TIMEOUT_SECS: u64 = 5;

fn build_probe_client() -> Option<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(PROBE_TIMEOUT_SECS))
        .build()
        .ok()
}

fn send_probe(
    client: &reqwest::blocking::Client,
    url: &str,
    payload: &str,
) -> Option<WafProbeResult> {
    let response = client.get(url).query(&[("q", payload)]).send().ok()?;
    let status = response.status().as_u16();
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = response.text().unwrap_or_default();
    let snippet = body.chars().take(2048).collect();
    Some(WafProbeResult {
        probe_payload: payload.to_string(),
        response_status: status,
        response_headers: headers,
        response_body_snippet: snippet,
    })
}

fn probe_baseline(client: &reqwest::blocking::Client, target: &str) -> Option<u16> {
    client.get(target).send().ok().map(|r| r.status().as_u16())
}

fn probe_waf(
    client: &reqwest::blocking::Client,
    target: &str,
) -> Option<aegis_fuzzing::WafProfile> {
    let baseline_status = probe_baseline(client, target)?;
    let responses: Vec<WafProbeResult> = WAF_PROBE_PAYLOADS
        .iter()
        .filter_map(|payload| send_probe(client, target, payload))
        .collect();
    if responses.is_empty() {
        return None;
    }
    let vendor = identify_vendor(&responses);
    let has_blocking = responses.iter().any(|r| {
        r.response_status != baseline_status && [403, 406, 419, 451].contains(&r.response_status)
    });
    if !has_blocking {
        return None;
    }
    let category_results: Vec<(VulnerabilityClass, WafProbeResult)> = WAF_CATEGORY_PROBES
        .iter()
        .filter_map(|(class, payload)| send_probe(client, target, payload).map(|r| (*class, r)))
        .collect();
    let blocked_categories = identify_blocked_categories(baseline_status, &category_results);
    let blocked_code = responses
        .iter()
        .find(|r| [403, 406, 419, 451].contains(&r.response_status))
        .map(|r| r.response_status)
        .unwrap_or(403);
    Some(build_waf_profile(
        vendor,
        blocked_categories,
        None,
        blocked_code,
    ))
}

fn probe_rate_limit(
    client: &reqwest::blocking::Client,
    target: &str,
) -> Option<aegis_fuzzing::RateLimitProfile> {
    let mut probes = Vec::new();
    let batch_size = 30u32;
    let mut limited_count = 0u32;
    for _ in 0..batch_size {
        if let Ok(resp) = client.get(target).send() {
            let status = resp.status().as_u16();
            if status == 429 {
                limited_count += 1;
            }
            probes.push(RateLimitProbeResult {
                request_rate: batch_size as f64,
                total_sent: batch_size,
                limited_count,
                limit_status_code: if status == 429 { Some(429) } else { None },
            });
        }
    }
    if probes.is_empty() {
        return None;
    }
    let burst = BurstProbeResult {
        total_sent: batch_size,
        first_limited_at: if limited_count > 0 {
            Some(batch_size - limited_count)
        } else {
            None
        },
        limit_status_code: if limited_count > 0 { Some(429) } else { None },
    };
    build_rate_limit_profile(&probes, Some(&burst), &[])
}

fn probe_bot_detection(
    client: &reqwest::blocking::Client,
    target: &str,
) -> Option<aegis_fuzzing::BotDetectionProfile> {
    let no_headers_resp = client.get(target).header("User-Agent", "").send().ok()?;
    let no_headers_status = no_headers_resp.status().as_u16();
    let no_headers_body: String = no_headers_resp
        .text()
        .unwrap_or_default()
        .chars()
        .take(2048)
        .collect();
    let no_headers = BotProbeResult {
        headers_sent: false,
        response_status: no_headers_status,
        response_body_snippet: no_headers_body,
        rapid_request: false,
    };

    let with_headers_resp = client.get(target).send().ok()?;
    let with_headers_status = with_headers_resp.status().as_u16();
    let with_headers_body: String = with_headers_resp
        .text()
        .unwrap_or_default()
        .chars()
        .take(2048)
        .collect();
    let with_headers = BotProbeResult {
        headers_sent: true,
        response_status: with_headers_status,
        response_body_snippet: with_headers_body,
        rapid_request: false,
    };

    analyze_bot_detection(&no_headers, &with_headers, &[])
}

/// Sends real HTTP probes to the target to detect WAF, rate limiting, and bot
/// detection. Returns an empty profile when the target is unreachable.
pub fn probe_defenses(target: &str) -> DefenseProfile {
    let ts = timestamp_ms();
    let Some(client) = build_probe_client() else {
        return DefenseProfile::empty(ts);
    };
    let mut profile = DefenseProfile::empty(ts);
    if let Some(waf) = probe_waf(&client, target) {
        tracing::info!(vendor = ?waf.vendor, "WAF detected");
        profile = profile.with_waf(waf);
    }
    if let Some(rl) = probe_rate_limit(&client, target) {
        tracing::info!(rps = ?rl.requests_per_second, "rate limiting detected");
        profile = profile.with_rate_limit(rl);
    }
    if let Some(bd) = probe_bot_detection(&client, target) {
        tracing::info!(method = %bd.detection_method, "bot detection detected");
        profile = profile.with_bot_detection(bd);
    }
    profile
}

pub fn run_fingerprint(ctx: &mut ScanContext) -> Result<PhaseResult, PhaseError> {
    let target = ctx.config.target.clone();
    let profile = std::thread::spawn(move || probe_defenses(&target))
        .join()
        .unwrap_or_else(|_| {
            tracing::warn!("defense fingerprinting thread panicked, using empty profile");
            DefenseProfile::empty(timestamp_ms())
        });
    let mut entries = Vec::new();
    let mut sequence = ctx.graph.total_operations_applied()?;

    sequence += 1;
    entries.push(OperationLogEntry {
        sequence_number: sequence,
        module: ModuleIdentifier::Enumeration,
        operation: GraphOperation::AddNode {
            node_type: NodeType::Defense,
            properties: defense_properties(&profile),
        },
        timestamp_unix_ms: timestamp_ms(),
    });

    let ops_count = entries.len() as u64;
    if !entries.is_empty() {
        ctx.graph.apply_operations(&entries)?;
    }

    ctx.defense_profile = Some(profile);
    Ok(PhaseResult {
        operations_applied: ops_count,
        findings_count: 0,
    })
}

pub(crate) fn defense_properties(profile: &DefenseProfile) -> Vec<(String, String)> {
    let mut props = Vec::new();
    if let Some(waf) = &profile.waf {
        props.push(("waf_vendor".to_string(), format!("{:?}", waf.vendor)));
        props.push((
            "waf_blocked_code".to_string(),
            waf.blocked_response_code.to_string(),
        ));
    }
    if let Some(rl) = &profile.rate_limit {
        props.push((
            "rate_limit_code".to_string(),
            rl.limit_response_code.to_string(),
        ));
    }
    if let Some(bd) = &profile.bot_detection {
        props.push(("bot_detected".to_string(), bd.detected.to_string()));
    }
    props
}

pub fn build_protected_by_edges(
    defense_node_id: u64,
    endpoint_node_ids: &[u64],
    sequence_start: u64,
) -> Vec<OperationLogEntry> {
    endpoint_node_ids
        .iter()
        .enumerate()
        .map(|(i, &endpoint_id)| OperationLogEntry {
            sequence_number: sequence_start + i as u64 + 1,
            module: ModuleIdentifier::Enumeration,
            operation: GraphOperation::AddEdge {
                source_node_id: endpoint_id,
                target_node_id: defense_node_id,
                label: EdgeLabel::ProtectedBy,
                weight: 1.0,
            },
            timestamp_unix_ms: timestamp_ms(),
        })
        .collect()
}

pub(crate) fn endpoint_properties(endpoint: &IntrospectedEndpoint) -> Vec<(String, String)> {
    let mut props = vec![
        ("path".to_string(), endpoint.path.clone()),
        ("method".to_string(), endpoint.method.clone()),
    ];

    if !endpoint.parameters.is_empty() {
        let param_json: Vec<serde_json::Value> = endpoint
            .parameters
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "location": format!("{:?}", p.location),
                    "param_type": p.param_type,
                    "required": p.required,
                })
            })
            .collect();
        props.push((
            "parameters".to_string(),
            serde_json::to_string(&param_json).unwrap_or_default(),
        ));
    }

    if !endpoint.request_content_types.is_empty() {
        props.push((
            "request_content_types".to_string(),
            serde_json::to_string(&endpoint.request_content_types).unwrap_or_default(),
        ));
    }

    props
}

pub fn endpoints_to_operations(
    endpoints: &[IntrospectedEndpoint],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    endpoints
        .iter()
        .map(|ep| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::Enumeration,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: endpoint_properties(ep),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

/// Runs httpx against the target to detect the tech stack.
///
/// Returns a list of technology strings (e.g., "nginx", "PHP"). Returns an
/// empty vec if httpx is not installed or the probe fails. Bypasses
/// `ToolRunner::run_tool` because it enforces localhost-only, but the
/// fingerprint phase probes the actual scan target.
pub fn probe_tech_stack(target: &str) -> Vec<String> {
    let wrapper = HttpxWrapper;
    if !wrapper.is_available() {
        tracing::debug!("httpx not installed, skipping tech stack detection");
        return Vec::new();
    }
    let context = ExploitContext::new(
        target.to_string(),
        String::new(),
        VulnerabilityClass::InformationDisclosure,
    );
    let command = wrapper.build_command(&context);
    let (stdout, _stderr) = match spawn_with_timeout(command, wrapper.timeout(), "httpx") {
        Ok(output) => output,
        Err(e) => {
            tracing::warn!(error = %e, "httpx tech stack probe failed");
            return Vec::new();
        }
    };
    let results = wrapper.parse_output(&stdout, &_stderr);
    let mut tech: Vec<String> = results
        .iter()
        .filter_map(|r| r.extracted_data.as_deref())
        .flat_map(|data: &str| data.split(", ").map(String::from))
        .collect();
    tech.sort();
    tech.dedup();
    if !tech.is_empty() {
        tracing::info!(technologies = ?tech, "httpx detected tech stack");
    }
    tech
}
