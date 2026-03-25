use std::collections::HashMap;
use std::fmt::Write as FmtWrite;

use serde::{Deserialize, Serialize};

use aegis_knowledge_graph::GraphStore;
use aegis_protocol::defense_context::DefenseContext;
use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::node::NodeType;

/// A complete scan briefing document ready for LLM consumption.
///
/// Contains both the rendered markdown and structured metadata so the
/// caller can inspect sections programmatically (token budget, section
/// sizes) without reparsing the markdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanBriefingDocument {
    pub markdown: String,
    pub sections: Vec<BriefingSection>,
    pub token_estimate: usize,
    pub target_url: String,
    pub iteration: u32,
}

/// A named section within the briefing with its rendered text and token cost.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BriefingSection {
    pub name: String,
    pub content: String,
    pub token_estimate: usize,
}

/// Target summary metadata extracted from the scan state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSummary {
    pub url: String,
    pub tech_stack: Vec<TechComponent>,
    pub endpoint_count: usize,
    pub endpoints: Vec<EndpointSummary>,
}

/// A detected technology in the target stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechComponent {
    pub name: String,
    pub version: Option<String>,
    pub category: String,
}

/// Summary of a discovered endpoint for the briefing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSummary {
    pub path: String,
    pub method: String,
    pub parameters: Vec<String>,
    pub auth_required: bool,
}

/// A confirmed or suspected finding for the briefing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub vulnerability_class: String,
    pub severity: f64,
    pub confidence: f64,
    pub endpoint: String,
    pub evidence_level: String,
}

/// A failed attempt record for the "don't repeat" section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedAttemptSummary {
    pub endpoint: String,
    pub vulnerability_class: String,
    pub payload_summary: String,
    pub failure_reason: String,
}

/// Defense posture summary for the briefing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseMapSummary {
    pub has_waf: bool,
    pub waf_vendor: Option<String>,
    pub blocked_categories: Vec<String>,
    pub rate_limit_rps: Option<f64>,
    pub bot_detection_present: bool,
    pub bot_detection_evaded: bool,
}

/// Recommended next actions based on current scan state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedAction {
    pub action: String,
    pub rationale: String,
    pub priority: u32,
}

/// Configuration for briefing generation: controls what gets included
/// and token budget caps.
#[derive(Debug, Clone)]
pub struct BriefingGeneratorConfig {
    pub max_endpoints: usize,
    pub max_findings: usize,
    pub max_failed_attempts: usize,
    pub max_recommendations: usize,
    pub include_tech_stack: bool,
    pub include_defense_map: bool,
    pub include_recommendations: bool,
    pub token_budget: Option<usize>,
}

impl Default for BriefingGeneratorConfig {
    fn default() -> Self {
        Self {
            max_endpoints: 200,
            max_findings: 50,
            max_failed_attempts: 100,
            max_recommendations: 10,
            include_tech_stack: true,
            include_defense_map: true,
            include_recommendations: true,
            token_budget: None,
        }
    }
}

/// Input context for generating a briefing. Aggregates all the pieces
/// the generator needs: graph store, defense context, metadata, and
/// previously failed attempts.
pub struct BriefingInput<'a> {
    pub graph: &'a dyn GraphStore,
    pub defense: &'a DefenseContext,
    pub target_url: &'a str,
    pub scan_id: &'a str,
    pub iteration: u32,
    pub max_iterations: u32,
    pub preset: &'a str,
    pub stealth_level: &'a str,
    pub failed_attempts: &'a [FailedAttemptSummary],
}

/// Generate a complete scan briefing document from the current scan state.
///
/// Produces a structured markdown document with these sections:
/// - TARGET: URL, scan metadata, iteration progress
/// - TECH STACK: detected technologies by category
/// - DEFENSES: WAF, rate limits, bot detection
/// - ATTACK SURFACE: discovered endpoints with methods/params
/// - FINDINGS: confirmed vulns sorted by severity
/// - FAILED ATTEMPTS: what didn't work (so the Brain doesn't repeat)
/// - RECOMMENDATIONS: suggested next actions based on current state
pub fn generate_briefing(
    input: &BriefingInput,
    config: &BriefingGeneratorConfig,
) -> ScanBriefingDocument {
    let mut sections = Vec::new();

    sections.push(build_target_section(input));
    if config.include_tech_stack {
        sections.push(build_tech_stack_section(input.graph));
    }
    if config.include_defense_map {
        sections.push(build_defense_section(input.defense));
    }
    sections.push(build_attack_surface_section(
        input.graph,
        config.max_endpoints,
    ));
    sections.push(build_findings_section(input.graph, config.max_findings));
    if !input.failed_attempts.is_empty() {
        sections.push(build_failed_attempts_section(
            input.failed_attempts,
            config.max_failed_attempts,
        ));
    }
    if config.include_recommendations {
        sections.push(build_recommendations_section(
            input.graph,
            input.defense,
            input.failed_attempts,
            config.max_recommendations,
        ));
    }

    let mut markdown = String::with_capacity(8192);
    for section in &sections {
        markdown.push_str(&section.content);
        markdown.push('\n');
    }

    if let Some(budget) = config.token_budget {
        let est = estimate_tokens(&markdown);
        if est > budget {
            markdown = truncate_to_budget(&markdown, budget);
        }
    }

    let token_estimate = estimate_tokens(&markdown);

    ScanBriefingDocument {
        markdown,
        sections,
        token_estimate,
        target_url: input.target_url.to_string(),
        iteration: input.iteration,
    }
}

/// Extract a target summary from the graph store for programmatic access.
pub fn extract_target_summary(
    graph: &dyn GraphStore,
    target_url: &str,
    max_endpoints: usize,
) -> TargetSummary {
    let tech_stack = extract_tech_stack(graph);
    let (endpoint_count, endpoints) = extract_endpoints(graph, max_endpoints);
    TargetSummary {
        url: target_url.to_string(),
        tech_stack,
        endpoint_count,
        endpoints,
    }
}

/// Extract the defense map from the defense context for programmatic access.
pub fn extract_defense_map(defense: &DefenseContext) -> DefenseMapSummary {
    DefenseMapSummary {
        has_waf: defense.has_waf,
        waf_vendor: defense.waf_vendor.clone(),
        blocked_categories: defense
            .waf_blocked_categories
            .iter()
            .map(|c| c.to_string())
            .collect(),
        rate_limit_rps: defense.rate_limit_rps,
        bot_detection_present: defense.bot_detection_present,
        bot_detection_evaded: defense.bot_detection_evaded,
    }
}

/// Extract findings from the graph for programmatic access.
pub fn extract_findings(graph: &dyn GraphStore, max: usize) -> Vec<FindingSummary> {
    let mut findings = graph.all_findings().unwrap_or_default();
    findings.sort_by(|a, b| {
        b.severity
            .partial_cmp(&a.severity)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    findings
        .iter()
        .take(max)
        .map(|f| {
            let endpoint = resolve_finding_endpoint(graph, f);
            FindingSummary {
                vulnerability_class: f.vulnerability_class.to_string(),
                severity: f.severity,
                confidence: f.confidence.composite.value(),
                endpoint,
                evidence_level: format!("{}", f.evidence_level),
            }
        })
        .collect()
}

/// Generate recommended next actions based on current state analysis.
pub fn generate_recommendations(
    graph: &dyn GraphStore,
    defense: &DefenseContext,
    failed_attempts: &[FailedAttemptSummary],
    max: usize,
) -> Vec<RecommendedAction> {
    let mut recs = Vec::new();

    let endpoint_ids = graph.nodes_by_type(NodeType::Endpoint).unwrap_or_default();
    let findings = graph.all_findings().unwrap_or_default();
    let untested_count = count_untested_endpoints(graph, &findings);

    if untested_count > 0 {
        recs.push(RecommendedAction {
            action: format!("Fuzz {untested_count} untested endpoints"),
            rationale:
                "Endpoints exist in the graph with no associated findings or failed attempts"
                    .to_string(),
            priority: 1,
        });
    }

    if defense.has_waf {
        let vendor = defense.waf_vendor.as_deref().unwrap_or("unknown");
        let waf_blocks = &defense.waf_blocked_categories;
        if !waf_blocks.is_empty() {
            recs.push(RecommendedAction {
                action: format!("Attempt WAF bypass for {vendor}"),
                rationale: format!(
                    "{} vulnerability classes are blocked by WAF — try encoding chains and evasion",
                    waf_blocks.len()
                ),
                priority: 2,
            });
        }
    }

    let has_auth_endpoints = endpoint_ids.iter().any(|id| {
        graph
            .get_node(*id)
            .ok()
            .flatten()
            .and_then(|n| n.properties.get("auth_required").cloned())
            .map(|v| v == "true")
            .unwrap_or(false)
    });

    if has_auth_endpoints {
        recs.push(RecommendedAction {
            action: "Test authenticated endpoints for authorization bypass".to_string(),
            rationale: "Auth-protected endpoints may have IDOR or privilege escalation vulns"
                .to_string(),
            priority: 2,
        });
    }

    if findings.len() >= 2 {
        recs.push(RecommendedAction {
            action: "Attempt finding chaining across confirmed vulnerabilities".to_string(),
            rationale: format!(
                "{} confirmed findings may chain into higher-impact attack paths",
                findings.len()
            ),
            priority: 3,
        });
    }

    let failed_classes: Vec<&str> = failed_attempts
        .iter()
        .map(|a| a.vulnerability_class.as_str())
        .collect();
    let unique_failed: std::collections::HashSet<&str> = failed_classes.into_iter().collect();
    if unique_failed.len() > 3 {
        recs.push(RecommendedAction {
            action: "Re-approach failed vulnerability classes with encoding mutations".to_string(),
            rationale: format!(
                "{} distinct vuln classes failed — try double-encoding, unicode normalization, or polyglots",
                unique_failed.len()
            ),
            priority: 3,
        });
    }

    recs.truncate(max);
    recs
}

fn build_target_section(input: &BriefingInput) -> BriefingSection {
    let mut content = String::new();
    let _ = writeln!(content, "# TARGET BRIEFING");
    let _ = writeln!(content, "- url: {}", input.target_url);
    let _ = writeln!(
        content,
        "- scan: {} (iter {}/{})",
        input.scan_id, input.iteration, input.max_iterations
    );
    let _ = writeln!(content, "- preset: {}", input.preset);
    let _ = writeln!(content, "- stealth: {}", input.stealth_level);

    let token_estimate = estimate_tokens(&content);
    BriefingSection {
        name: "TARGET".to_string(),
        content,
        token_estimate,
    }
}

fn build_tech_stack_section(graph: &dyn GraphStore) -> BriefingSection {
    let mut content = String::new();
    let tech = extract_tech_stack(graph);
    if tech.is_empty() {
        let _ = writeln!(content, "## TECH STACK");
        let _ = writeln!(content, "No technologies detected yet.");
    } else {
        let _ = writeln!(content, "## TECH STACK");
        let mut by_cat: HashMap<String, Vec<String>> = HashMap::new();
        for t in &tech {
            let entry = match &t.version {
                Some(v) => format!("{} {}", t.name, v),
                None => t.name.clone(),
            };
            by_cat.entry(t.category.clone()).or_default().push(entry);
        }
        let mut cats: Vec<_> = by_cat.into_iter().collect();
        cats.sort_by(|a, b| a.0.cmp(&b.0));
        for (cat, items) in cats {
            let _ = writeln!(content, "- {}: {}", cat, items.join(", "));
        }
    }

    let token_estimate = estimate_tokens(&content);
    BriefingSection {
        name: "TECH_STACK".to_string(),
        content,
        token_estimate,
    }
}

fn build_defense_section(defense: &DefenseContext) -> BriefingSection {
    let mut content = String::new();
    let _ = writeln!(content, "## DEFENSES");
    if defense.has_waf {
        let vendor = defense.waf_vendor.as_deref().unwrap_or("unknown");
        let _ = writeln!(content, "- WAF: {} (active)", vendor);
        if !defense.waf_blocked_categories.is_empty() {
            let blocked: Vec<String> = defense
                .waf_blocked_categories
                .iter()
                .map(|c| c.to_string())
                .collect();
            let _ = writeln!(content, "- WAF blocks: {}", blocked.join(", "));
        }
    } else {
        let _ = writeln!(content, "- WAF: none detected");
    }
    if let Some(rps) = defense.rate_limit_rps {
        let _ = writeln!(content, "- rate limit: {:.1} req/s", rps);
    }
    if defense.bot_detection_present {
        let status = if defense.bot_detection_evaded {
            "present (evaded)"
        } else {
            "present (NOT evaded)"
        };
        let _ = writeln!(content, "- bot detection: {}", status);
    }

    let token_estimate = estimate_tokens(&content);
    BriefingSection {
        name: "DEFENSES".to_string(),
        content,
        token_estimate,
    }
}

fn build_attack_surface_section(graph: &dyn GraphStore, max_endpoints: usize) -> BriefingSection {
    let mut content = String::new();
    let endpoint_ids = graph.nodes_by_type(NodeType::Endpoint).unwrap_or_default();
    let _ = writeln!(
        content,
        "## ATTACK SURFACE ({} endpoints)",
        endpoint_ids.len()
    );

    if endpoint_ids.is_empty() {
        let _ = writeln!(content, "No endpoints discovered yet.");
    } else {
        for id in endpoint_ids.iter().take(max_endpoints) {
            if let Ok(Some(node)) = graph.get_node(*id) {
                let path = node
                    .properties
                    .get("path")
                    .or_else(|| node.properties.get("url"))
                    .or_else(|| node.properties.get("name"))
                    .cloned()
                    .unwrap_or_else(|| format!("endpoint-{}", node.id));
                let method = node.properties.get("method").cloned().unwrap_or_default();
                let params = node
                    .properties
                    .get("parameters")
                    .cloned()
                    .unwrap_or_default();
                let auth = node.properties.get("auth_required").cloned();

                let mut line = format!("- {} {}", method, path);
                if !params.is_empty() {
                    let _ = write!(line, " [{}]", params);
                }
                if let Some(a) = auth {
                    let _ = write!(line, " (auth:{})", a);
                }
                let _ = writeln!(content, "{}", line);
            }
        }
        if endpoint_ids.len() > max_endpoints {
            let _ = writeln!(
                content,
                "- ... +{} more endpoints",
                endpoint_ids.len() - max_endpoints
            );
        }
    }

    let token_estimate = estimate_tokens(&content);
    BriefingSection {
        name: "ATTACK_SURFACE".to_string(),
        content,
        token_estimate,
    }
}

fn build_findings_section(graph: &dyn GraphStore, max_findings: usize) -> BriefingSection {
    let mut content = String::new();
    let mut findings = graph.all_findings().unwrap_or_default();

    if findings.is_empty() {
        let _ = writeln!(content, "## FINDINGS");
        let _ = writeln!(content, "None yet.");
    } else {
        findings.sort_by(|a, b| {
            b.severity
                .partial_cmp(&a.severity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let total = findings.len();
        let _ = writeln!(content, "## FINDINGS ({} total)", total);

        let mut by_class: HashMap<VulnerabilityClass, Vec<&FindingData>> = HashMap::new();
        for f in findings.iter().take(max_findings) {
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
            let _ = writeln!(content, "### {}", class);
            for f in class_findings {
                let endpoint = resolve_finding_endpoint(graph, f);
                let _ = writeln!(
                    content,
                    "- sev={:.1} conf={} evidence={} | {}",
                    f.severity, f.confidence.composite, f.evidence_level, endpoint,
                );
            }
        }

        if total > max_findings {
            let _ = writeln!(
                content,
                "\n*+{} lower-severity findings omitted*",
                total - max_findings
            );
        }
    }

    let token_estimate = estimate_tokens(&content);
    BriefingSection {
        name: "FINDINGS".to_string(),
        content,
        token_estimate,
    }
}

fn build_failed_attempts_section(failed: &[FailedAttemptSummary], max: usize) -> BriefingSection {
    let mut content = String::new();
    let _ = writeln!(content, "## FAILED ATTEMPTS ({} total)", failed.len());
    let _ = writeln!(content, "Do NOT retry these without a new approach:");

    for attempt in failed.iter().take(max) {
        let _ = writeln!(
            content,
            "- {} @ {} — payload: {} — reason: {}",
            attempt.vulnerability_class,
            attempt.endpoint,
            attempt.payload_summary,
            attempt.failure_reason,
        );
    }

    let token_estimate = estimate_tokens(&content);
    BriefingSection {
        name: "FAILED_ATTEMPTS".to_string(),
        content,
        token_estimate,
    }
}

fn build_recommendations_section(
    graph: &dyn GraphStore,
    defense: &DefenseContext,
    failed_attempts: &[FailedAttemptSummary],
    max: usize,
) -> BriefingSection {
    let mut content = String::new();
    let recs = generate_recommendations(graph, defense, failed_attempts, max);

    let _ = writeln!(content, "## RECOMMENDED NEXT ACTIONS");
    if recs.is_empty() {
        let _ = writeln!(content, "Continue standard enumeration and fuzzing.");
    } else {
        for rec in &recs {
            let _ = writeln!(
                content,
                "- [P{}] {} — {}",
                rec.priority, rec.action, rec.rationale
            );
        }
    }

    let token_estimate = estimate_tokens(&content);
    BriefingSection {
        name: "RECOMMENDATIONS".to_string(),
        content,
        token_estimate,
    }
}

fn extract_tech_stack(graph: &dyn GraphStore) -> Vec<TechComponent> {
    let mut result = Vec::new();
    for node_type in &[NodeType::Service, NodeType::Config, NodeType::Dependency] {
        let ids = graph.nodes_by_type(*node_type).unwrap_or_default();
        for id in ids.into_iter().take(100) {
            if let Ok(Some(node)) = graph.get_node(id) {
                let name = node
                    .properties
                    .get("name")
                    .cloned()
                    .unwrap_or_else(|| format!("node-{}", node.id));
                let version = node.properties.get("version").cloned();
                let category = node
                    .properties
                    .get("category")
                    .cloned()
                    .unwrap_or_else(|| node.node_type.to_string());
                result.push(TechComponent {
                    name,
                    version,
                    category,
                });
            }
        }
    }
    result
}

fn extract_endpoints(graph: &dyn GraphStore, max: usize) -> (usize, Vec<EndpointSummary>) {
    let ids = graph.nodes_by_type(NodeType::Endpoint).unwrap_or_default();
    let total = ids.len();
    let endpoints: Vec<EndpointSummary> = ids
        .iter()
        .take(max)
        .filter_map(|id| {
            graph.get_node(*id).ok().flatten().map(|node| {
                let path = node
                    .properties
                    .get("path")
                    .or_else(|| node.properties.get("url"))
                    .cloned()
                    .unwrap_or_default();
                let method = node.properties.get("method").cloned().unwrap_or_default();
                let params: Vec<String> = node
                    .properties
                    .get("parameters")
                    .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default();
                let auth_required = node
                    .properties
                    .get("auth_required")
                    .map(|v| v == "true")
                    .unwrap_or(false);
                EndpointSummary {
                    path,
                    method,
                    parameters: params,
                    auth_required,
                }
            })
        })
        .collect();
    (total, endpoints)
}

fn resolve_finding_endpoint(graph: &dyn GraphStore, finding: &FindingData) -> String {
    for id in &finding.linked_node_ids {
        if let Ok(Some(node)) = graph.get_node(*id)
            && let Some(path) = node
                .properties
                .get("path")
                .or_else(|| node.properties.get("url"))
                .or_else(|| node.properties.get("name"))
        {
                return path.clone();
            }
    }
    format!("node-ids:{:?}", finding.linked_node_ids)
}

fn count_untested_endpoints(graph: &dyn GraphStore, findings: &[FindingData]) -> usize {
    let endpoint_ids = graph.nodes_by_type(NodeType::Endpoint).unwrap_or_default();
    let finding_node_ids: std::collections::HashSet<u64> = findings
        .iter()
        .flat_map(|f| f.linked_node_ids.iter().copied())
        .collect();

    endpoint_ids
        .iter()
        .filter(|id| !finding_node_ids.contains(id))
        .count()
}

fn estimate_tokens(text: &str) -> usize {
    text.len() / 4
}

fn truncate_to_budget(text: &str, budget: usize) -> String {
    let target_chars = budget * 4;
    if text.len() <= target_chars {
        return text.to_string();
    }
    let mut truncated = text[..target_chars].to_string();
    truncated.push_str("\n\n*[briefing truncated to fit token budget]*");
    truncated
}

#[cfg(test)]
#[path = "scan_briefing_test.rs"]
mod scan_briefing_test;
