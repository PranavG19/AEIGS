use std::collections::HashMap;
use std::fmt::Write as FmtWrite;

use aegis_knowledge_graph::GraphStore;
use aegis_protocol::defense_context::DefenseContext;
use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::node::{NodeData, NodeType};

/// Compact scan briefing serialized as markdown for consumption by an LLM agent.
///
/// This is the "mission briefing" passed to `opencode run` — it encodes the full
/// scan state into a dense, structured document the Brain can reason over.
/// Designed for minimal token waste: no prose fluff, no redundant labels,
/// only signal. Each section maps directly to an offensive reasoning concern:
/// what's the target, what defenses are up, what have we found, what failed.
#[derive(Debug, Clone)]
pub struct ScanBriefing {
    pub markdown: String,
    pub token_estimate: usize,
}

/// Configuration controlling what gets included in the briefing.
///
/// Larger briefings give the Brain more context but cost more tokens.
/// `max_findings` and `max_endpoints` cap the included items, prioritizing
/// by severity and discovery order respectively.
#[derive(Debug, Clone)]
pub struct BriefingConfig {
    pub max_findings: usize,
    pub max_endpoints: usize,
    pub max_dependencies: usize,
    pub include_failed_attempts: bool,
    pub include_defense_details: bool,
    pub include_tech_stack: bool,
}

impl Default for BriefingConfig {
    fn default() -> Self {
        Self {
            max_findings: 50,
            max_endpoints: 200,
            max_dependencies: 100,
            include_failed_attempts: true,
            include_defense_details: true,
            include_tech_stack: true,
        }
    }
}

/// Metadata about the scan target and current iteration state.
///
/// Separated from `ScanConfig` so the serializer doesn't depend on clap.
#[derive(Debug, Clone)]
pub struct ScanMeta {
    pub target_url: String,
    pub scan_id: String,
    pub iteration: u32,
    pub max_iterations: u32,
    pub preset: String,
    pub stealth_level: String,
}

/// A failed hypothesis or payload attempt, so the Brain doesn't repeat it.
#[derive(Debug, Clone)]
pub struct FailedAttempt {
    pub endpoint: String,
    pub vulnerability_class: VulnerabilityClass,
    pub payload_summary: String,
    pub failure_reason: String,
}

/// Serialize the current scan state into a compact markdown briefing.
///
/// The output is structured for LLM consumption:
/// - `# TARGET` — URL, iteration, stealth constraints
/// - `## DEFENSES` — WAF vendor, blocked categories, rate limits, bot detection
/// - `## TECH STACK` — detected technologies grouped by category
/// - `## ATTACK SURFACE` — endpoints with methods and parameters
/// - `## FINDINGS` — confirmed/suspected vulnerabilities, sorted by severity
/// - `## FAILED ATTEMPTS` — what didn't work and why (so the Brain avoids repeats)
/// - `## GRAPH STATS` — node/edge/finding counts for situational awareness
pub fn serialize_briefing(
    graph: &dyn GraphStore,
    defense: &DefenseContext,
    meta: &ScanMeta,
    failed_attempts: &[FailedAttempt],
    config: &BriefingConfig,
) -> ScanBriefing {
    let mut md = String::with_capacity(8192);

    write_target_section(&mut md, meta);
    write_defense_section(&mut md, defense, config);
    write_tech_stack_section(&mut md, graph, config);
    write_attack_surface_section(&mut md, graph, config);
    write_findings_section(&mut md, graph, config);
    write_failed_attempts_section(&mut md, failed_attempts, config);
    write_graph_stats_section(&mut md, graph);

    let token_estimate = estimate_tokens(&md);

    ScanBriefing {
        markdown: md,
        token_estimate,
    }
}

fn write_target_section(md: &mut String, meta: &ScanMeta) {
    let _ = writeln!(md, "# TARGET BRIEFING");
    let _ = writeln!(md, "- url: {}", meta.target_url);
    let _ = writeln!(
        md,
        "- scan: {} (iter {}/{})",
        meta.scan_id, meta.iteration, meta.max_iterations
    );
    let _ = writeln!(md, "- preset: {}", meta.preset);
    let _ = writeln!(md, "- stealth: {}", meta.stealth_level);
    let _ = writeln!(md);
}

fn write_defense_section(md: &mut String, defense: &DefenseContext, config: &BriefingConfig) {
    if !config.include_defense_details {
        return;
    }
    let _ = writeln!(md, "## DEFENSES");
    if defense.has_waf {
        let vendor = defense.waf_vendor.as_deref().unwrap_or("unknown");
        let _ = writeln!(md, "- WAF: {} (active)", vendor);
        if !defense.waf_blocked_categories.is_empty() {
            let blocked: Vec<String> = defense
                .waf_blocked_categories
                .iter()
                .map(|c| c.to_string())
                .collect();
            let _ = writeln!(md, "- WAF blocks: {}", blocked.join(", "));
        }
    } else {
        let _ = writeln!(md, "- WAF: none detected");
    }
    if let Some(rps) = defense.rate_limit_rps {
        let _ = writeln!(md, "- rate limit: {:.1} req/s", rps);
    }
    if defense.bot_detection_present {
        let status = if defense.bot_detection_evaded {
            "present (evaded)"
        } else {
            "present (NOT evaded)"
        };
        let _ = writeln!(md, "- bot detection: {}", status);
    }
    let _ = writeln!(md);
}

fn write_tech_stack_section(md: &mut String, graph: &dyn GraphStore, config: &BriefingConfig) {
    if !config.include_tech_stack {
        return;
    }
    let service_nodes = graph.nodes_by_type(NodeType::Service).unwrap_or_default();
    let config_nodes = graph.nodes_by_type(NodeType::Config).unwrap_or_default();
    let dep_nodes = graph
        .nodes_by_type(NodeType::Dependency)
        .unwrap_or_default();

    let all_tech_ids: Vec<u64> = service_nodes
        .into_iter()
        .chain(config_nodes)
        .chain(dep_nodes.into_iter().take(config.max_dependencies))
        .collect();

    if all_tech_ids.is_empty() {
        return;
    }

    let _ = writeln!(md, "## TECH STACK");

    let mut by_category: HashMap<String, Vec<String>> = HashMap::new();
    for id in all_tech_ids {
        if let Ok(Some(node)) = graph.get_node(id) {
            let name = node
                .properties
                .get("name")
                .cloned()
                .unwrap_or_else(|| format!("node-{}", node.id));
            let category = node
                .properties
                .get("category")
                .cloned()
                .unwrap_or_else(|| node.node_type.to_string());
            let version = node.properties.get("version").cloned();
            let entry = match version {
                Some(v) => format!("{} {}", name, v),
                None => name,
            };
            by_category.entry(category).or_default().push(entry);
        }
    }

    let mut categories: Vec<_> = by_category.into_iter().collect();
    categories.sort_by(|a, b| a.0.cmp(&b.0));
    for (cat, items) in categories {
        let _ = writeln!(md, "- {}: {}", cat, items.join(", "));
    }
    let _ = writeln!(md);
}

fn write_attack_surface_section(md: &mut String, graph: &dyn GraphStore, config: &BriefingConfig) {
    let endpoint_ids = graph.nodes_by_type(NodeType::Endpoint).unwrap_or_default();
    if endpoint_ids.is_empty() {
        return;
    }

    let _ = writeln!(md, "## ATTACK SURFACE ({} endpoints)", endpoint_ids.len());

    let mut endpoints: Vec<NodeData> = Vec::new();
    for id in endpoint_ids.iter().take(config.max_endpoints) {
        if let Ok(Some(node)) = graph.get_node(*id) {
            endpoints.push(node);
        }
    }

    for ep in &endpoints {
        let path = ep
            .properties
            .get("path")
            .or_else(|| ep.properties.get("url"))
            .or_else(|| ep.properties.get("name"))
            .cloned()
            .unwrap_or_else(|| format!("endpoint-{}", ep.id));
        let method = ep.properties.get("method").cloned().unwrap_or_default();
        let params = ep.properties.get("parameters").cloned().unwrap_or_default();
        let auth = ep.properties.get("auth_required").cloned();

        let mut line = format!("- {} {}", method, path);
        if !params.is_empty() {
            let _ = write!(line, " [{}]", params);
        }
        if let Some(a) = auth {
            let _ = write!(line, " (auth:{})", a);
        }
        let _ = writeln!(md, "{}", line);
    }

    if endpoint_ids.len() > config.max_endpoints {
        let _ = writeln!(
            md,
            "- ... +{} more endpoints",
            endpoint_ids.len() - config.max_endpoints
        );
    }
    let _ = writeln!(md);
}

fn write_findings_section(md: &mut String, graph: &dyn GraphStore, config: &BriefingConfig) {
    let mut findings = graph.all_findings().unwrap_or_default();
    if findings.is_empty() {
        let _ = writeln!(md, "## FINDINGS");
        let _ = writeln!(md, "None yet.");
        let _ = writeln!(md);
        return;
    }

    findings.sort_by(|a, b| {
        b.severity
            .partial_cmp(&a.severity)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let total = findings.len();
    let capped: Vec<&FindingData> = findings.iter().take(config.max_findings).collect();

    let _ = writeln!(md, "## FINDINGS ({} total)", total);

    let mut by_class: HashMap<VulnerabilityClass, Vec<&FindingData>> = HashMap::new();
    for f in &capped {
        by_class.entry(f.vulnerability_class).or_default().push(f);
    }

    let mut classes: Vec<_> = by_class.into_iter().collect();
    classes.sort_by(|a, b| {
        let a_max = a.1.iter().map(|f| f.severity).fold(0.0_f64, f64::max);
        let b_max = b.1.iter().map(|f| f.severity).fold(0.0_f64, f64::max);
        b_max
            .partial_cmp(&a_max)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for (class, class_findings) in classes {
        let _ = writeln!(md, "### {}", class);
        for f in class_findings {
            let nodes = resolve_endpoint_names(graph, &f.linked_node_ids);
            let location = if nodes.is_empty() {
                format!("node-ids:{:?}", f.linked_node_ids)
            } else {
                nodes.join(", ")
            };
            let _ = writeln!(
                md,
                "- sev={:.1} conf={} evidence={} | {}",
                f.severity, f.confidence.composite, f.evidence_level, location,
            );
        }
    }

    if total > config.max_findings {
        let _ = writeln!(
            md,
            "\n*+{} lower-severity findings omitted*",
            total - config.max_findings
        );
    }
    let _ = writeln!(md);
}

fn write_failed_attempts_section(
    md: &mut String,
    failed: &[FailedAttempt],
    config: &BriefingConfig,
) {
    if !config.include_failed_attempts || failed.is_empty() {
        return;
    }

    let _ = writeln!(md, "## FAILED ATTEMPTS ({} total)", failed.len());
    let _ = writeln!(md, "Do NOT retry these without a new approach:");

    for attempt in failed.iter().take(100) {
        let _ = writeln!(
            md,
            "- {} @ {} — payload: {} — reason: {}",
            attempt.vulnerability_class,
            attempt.endpoint,
            attempt.payload_summary,
            attempt.failure_reason,
        );
    }
    let _ = writeln!(md);
}

fn write_graph_stats_section(md: &mut String, graph: &dyn GraphStore) {
    let node_count = graph.node_count().unwrap_or(0);
    let ops = graph.total_operations_applied().unwrap_or(0);
    let finding_count = graph.all_findings().map(|f| f.len()).unwrap_or(0);

    let _ = writeln!(md, "## GRAPH STATS");
    let _ = writeln!(md, "- nodes: {}", node_count);
    let _ = writeln!(md, "- findings: {}", finding_count);
    let _ = writeln!(md, "- operations applied: {}", ops);
}

fn resolve_endpoint_names(graph: &dyn GraphStore, node_ids: &[u64]) -> Vec<String> {
    node_ids
        .iter()
        .filter_map(|id| {
            graph.get_node(*id).ok().flatten().map(|n| {
                n.properties
                    .get("path")
                    .or_else(|| n.properties.get("url"))
                    .or_else(|| n.properties.get("name"))
                    .cloned()
                    .unwrap_or_else(|| format!("{}({})", n.node_type, n.id))
            })
        })
        .collect()
}

/// Rough token estimate: ~4 chars per token for English markdown.
fn estimate_tokens(text: &str) -> usize {
    text.len() / 4
}

#[cfg(test)]
#[path = "scan_context_serializer_test.rs"]
mod scan_context_serializer_test;
