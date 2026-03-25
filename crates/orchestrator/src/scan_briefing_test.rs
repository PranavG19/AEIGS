use super::*;
use aegis_knowledge_graph::graph::GraphError;
use aegis_knowledge_graph::GraphStore;
use aegis_protocol::defense_context::DefenseContext;
use aegis_protocol::finding::{EvidenceLevel, FindingData, VulnerabilityClass};
use aegis_protocol::node::{NodeData, NodeType};
use aegis_protocol::operation::{ModuleIdentifier, OperationLogEntry};

struct TestGraph {
    nodes: Vec<NodeData>,
    findings: Vec<FindingData>,
}

impl TestGraph {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            findings: Vec::new(),
        }
    }

    fn with_endpoint(mut self, id: u64, path: &str, method: &str) -> Self {
        let mut props = std::collections::HashMap::new();
        props.insert("path".to_string(), path.to_string());
        props.insert("method".to_string(), method.to_string());
        self.nodes.push(NodeData {
            id,
            node_type: NodeType::Endpoint,
            properties: props,
        });
        self
    }

    fn with_service(mut self, id: u64, name: &str, category: &str) -> Self {
        let mut props = std::collections::HashMap::new();
        props.insert("name".to_string(), name.to_string());
        props.insert("category".to_string(), category.to_string());
        self.nodes.push(NodeData {
            id,
            node_type: NodeType::Service,
            properties: props,
        });
        self
    }

    fn with_finding(mut self, finding: FindingData) -> Self {
        self.findings.push(finding);
        self
    }
}

impl GraphStore for TestGraph {
    fn apply_operations(&mut self, _ops: &[OperationLogEntry]) -> Result<(), GraphError> {
        Ok(())
    }

    fn nodes_by_type(&self, node_type: NodeType) -> Result<Vec<u64>, GraphError> {
        Ok(self
            .nodes
            .iter()
            .filter(|n| n.node_type == node_type)
            .map(|n| n.id)
            .collect())
    }

    fn get_node(&self, id: u64) -> Result<Option<NodeData>, GraphError> {
        Ok(self.nodes.iter().find(|n| n.id == id).cloned())
    }

    fn total_operations_applied(&self) -> Result<u64, GraphError> {
        Ok(10)
    }

    fn all_findings(&self) -> Result<Vec<FindingData>, GraphError> {
        Ok(self.findings.clone())
    }

    fn node_count(&self) -> Result<u64, GraphError> {
        Ok(self.nodes.len() as u64)
    }

    fn findings_by_class(&self, vc: VulnerabilityClass) -> Result<Vec<u64>, GraphError> {
        Ok(self
            .findings
            .iter()
            .filter(|f| f.vulnerability_class == vc)
            .map(|f| f.id)
            .collect())
    }

    fn get_finding(&self, id: u64) -> Result<Option<FindingData>, GraphError> {
        Ok(self.findings.iter().find(|f| f.id == id).cloned())
    }
}

fn make_finding(
    id: u64,
    class: VulnerabilityClass,
    severity: f64,
    linked: Vec<u64>,
) -> FindingData {
    let mut f = FindingData::new(
        id,
        class,
        severity,
        0.85,
        ModuleIdentifier::Fuzzing,
        1700000000000,
    )
    .with_evidence_level(EvidenceLevel::Confirmed);
    f.linked_node_ids = linked;
    f
}

fn default_defense() -> DefenseContext {
    DefenseContext {
        has_waf: true,
        waf_vendor: Some("Cloudflare".to_string()),
        waf_blocked_categories: vec![
            VulnerabilityClass::SqlInjection,
            VulnerabilityClass::CrossSiteScripting,
        ],
        rate_limit_rps: Some(10.0),
        bot_detection_present: true,
        bot_detection_evaded: false,
    }
}

fn default_input<'a>(
    graph: &'a dyn GraphStore,
    defense: &'a DefenseContext,
    failed: &'a [FailedAttemptSummary],
) -> BriefingInput<'a> {
    BriefingInput {
        graph,
        defense,
        target_url: "http://127.0.0.1:3000",
        scan_id: "scan-001",
        iteration: 2,
        max_iterations: 5,
        preset: "thorough",
        stealth_level: "paranoid",
        failed_attempts: failed,
    }
}

#[test]
fn empty_graph_produces_valid_briefing() {
    let graph = TestGraph::new();
    let defense = DefenseContext::default();
    let failed = vec![];
    let input = default_input(&graph, &defense, &failed);
    let config = BriefingGeneratorConfig::default();

    let doc = generate_briefing(&input, &config);

    assert!(doc.markdown.contains("# TARGET BRIEFING"));
    assert!(doc.markdown.contains("http://127.0.0.1:3000"));
    assert!(doc.markdown.contains("iter 2/5"));
    assert!(doc.markdown.contains("## FINDINGS"));
    assert!(doc.markdown.contains("None yet."));
    assert!(doc.token_estimate > 0);
    assert!(!doc.sections.is_empty());
}

#[test]
fn defense_section_renders_waf_details() {
    let graph = TestGraph::new();
    let defense = default_defense();
    let failed = vec![];
    let input = default_input(&graph, &defense, &failed);
    let config = BriefingGeneratorConfig::default();

    let doc = generate_briefing(&input, &config);

    assert!(doc.markdown.contains("## DEFENSES"));
    assert!(doc.markdown.contains("Cloudflare"));
    assert!(doc.markdown.contains("WAF blocks:"));
    assert!(doc.markdown.contains("10.0 req/s"));
    assert!(doc.markdown.contains("bot detection: present (NOT evaded)"));
}

#[test]
fn attack_surface_section_lists_endpoints() {
    let graph = TestGraph::new()
        .with_endpoint(1, "/api/users", "GET")
        .with_endpoint(2, "/api/login", "POST");

    let defense = DefenseContext::default();
    let failed = vec![];
    let input = default_input(&graph, &defense, &failed);
    let config = BriefingGeneratorConfig::default();

    let doc = generate_briefing(&input, &config);

    assert!(doc.markdown.contains("ATTACK SURFACE (2 endpoints)"));
    assert!(doc.markdown.contains("GET /api/users"));
    assert!(doc.markdown.contains("POST /api/login"));
}

#[test]
fn findings_section_sorts_by_severity() {
    let graph = TestGraph::new()
        .with_endpoint(1, "/api/search", "GET")
        .with_endpoint(2, "/api/admin", "POST")
        .with_finding(make_finding(
            100,
            VulnerabilityClass::SqlInjection,
            9.8,
            vec![1],
        ))
        .with_finding(make_finding(
            101,
            VulnerabilityClass::CrossSiteScripting,
            5.0,
            vec![2],
        ));

    let defense = DefenseContext::default();
    let failed = vec![];
    let input = default_input(&graph, &defense, &failed);
    let config = BriefingGeneratorConfig::default();

    let doc = generate_briefing(&input, &config);

    assert!(doc.markdown.contains("FINDINGS (2 total)"));
    let sqli_pos = doc.markdown.find("SQL Injection").unwrap();
    let xss_pos = doc.markdown.find("Cross-Site Scripting").unwrap();
    assert!(
        sqli_pos < xss_pos,
        "SQLi (sev 9.8) should appear before XSS (sev 5.0)"
    );
}

#[test]
fn failed_attempts_section_rendered() {
    let graph = TestGraph::new();
    let defense = DefenseContext::default();
    let failed = vec![FailedAttemptSummary {
        endpoint: "/api/search".to_string(),
        vulnerability_class: "SQL Injection".to_string(),
        payload_summary: "' OR 1=1--".to_string(),
        failure_reason: "WAF blocked".to_string(),
    }];
    let input = default_input(&graph, &defense, &failed);
    let config = BriefingGeneratorConfig::default();

    let doc = generate_briefing(&input, &config);

    assert!(doc.markdown.contains("FAILED ATTEMPTS (1 total)"));
    assert!(doc.markdown.contains("' OR 1=1--"));
    assert!(doc.markdown.contains("WAF blocked"));
}

#[test]
fn recommendations_generated_for_untested_endpoints() {
    let graph = TestGraph::new()
        .with_endpoint(1, "/api/users", "GET")
        .with_endpoint(2, "/api/admin", "POST");

    let defense = DefenseContext::default();
    let failed = vec![];
    let input = default_input(&graph, &defense, &failed);
    let config = BriefingGeneratorConfig::default();

    let doc = generate_briefing(&input, &config);

    assert!(doc.markdown.contains("RECOMMENDED NEXT ACTIONS"));
    assert!(doc.markdown.contains("Fuzz 2 untested endpoints"));
}

#[test]
fn recommendations_suggest_waf_bypass() {
    let graph = TestGraph::new();
    let defense = default_defense();
    let failed = vec![];
    let input = default_input(&graph, &defense, &failed);
    let config = BriefingGeneratorConfig::default();

    let doc = generate_briefing(&input, &config);

    assert!(doc.markdown.contains("WAF bypass"));
}

#[test]
fn token_budget_truncates_output() {
    let graph = TestGraph::new()
        .with_endpoint(1, "/a", "GET")
        .with_endpoint(2, "/b", "GET")
        .with_endpoint(3, "/c", "GET");

    let defense = DefenseContext::default();
    let failed = vec![];
    let input = default_input(&graph, &defense, &failed);
    let config = BriefingGeneratorConfig {
        token_budget: Some(50),
        ..BriefingGeneratorConfig::default()
    };

    let doc = generate_briefing(&input, &config);

    assert!(doc.markdown.contains("truncated to fit token budget"));
}

#[test]
fn extract_target_summary_returns_correct_counts() {
    let graph = TestGraph::new()
        .with_endpoint(1, "/api/a", "GET")
        .with_endpoint(2, "/api/b", "POST")
        .with_service(10, "Express", "framework");

    let summary = extract_target_summary(&graph, "http://127.0.0.1:3000", 100);

    assert_eq!(summary.url, "http://127.0.0.1:3000");
    assert_eq!(summary.endpoint_count, 2);
    assert_eq!(summary.endpoints.len(), 2);
    assert_eq!(summary.tech_stack.len(), 1);
    assert_eq!(summary.tech_stack[0].name, "Express");
}

#[test]
fn extract_defense_map_captures_waf_info() {
    let defense = default_defense();
    let map = extract_defense_map(&defense);

    assert!(map.has_waf);
    assert_eq!(map.waf_vendor.as_deref(), Some("Cloudflare"));
    assert_eq!(map.blocked_categories.len(), 2);
    assert_eq!(map.rate_limit_rps, Some(10.0));
    assert!(map.bot_detection_present);
    assert!(!map.bot_detection_evaded);
}

#[test]
fn extract_findings_sorted_by_severity() {
    let graph = TestGraph::new()
        .with_finding(make_finding(
            1,
            VulnerabilityClass::CrossSiteScripting,
            5.0,
            vec![],
        ))
        .with_finding(make_finding(
            2,
            VulnerabilityClass::SqlInjection,
            9.8,
            vec![],
        ));

    let findings = extract_findings(&graph, 10);

    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].vulnerability_class, "SQL Injection");
    assert_eq!(findings[1].vulnerability_class, "Cross-Site Scripting");
}

#[test]
fn sections_have_names_and_token_estimates() {
    let graph = TestGraph::new();
    let defense = default_defense();
    let failed = vec![];
    let input = default_input(&graph, &defense, &failed);
    let config = BriefingGeneratorConfig::default();

    let doc = generate_briefing(&input, &config);

    let section_names: Vec<&str> = doc.sections.iter().map(|s| s.name.as_str()).collect();
    assert!(section_names.contains(&"TARGET"));
    assert!(section_names.contains(&"DEFENSES"));
    assert!(section_names.contains(&"FINDINGS"));
    assert!(section_names.contains(&"RECOMMENDATIONS"));

    for section in &doc.sections {
        assert!(
            section.token_estimate > 0,
            "section {} has zero tokens",
            section.name
        );
    }
}

#[test]
fn disabled_sections_excluded() {
    let graph = TestGraph::new();
    let defense = default_defense();
    let failed = vec![];
    let input = default_input(&graph, &defense, &failed);
    let config = BriefingGeneratorConfig {
        include_tech_stack: false,
        include_defense_map: false,
        include_recommendations: false,
        ..BriefingGeneratorConfig::default()
    };

    let doc = generate_briefing(&input, &config);

    assert!(!doc.markdown.contains("## TECH STACK"));
    assert!(!doc.markdown.contains("## DEFENSES"));
    assert!(!doc.markdown.contains("## RECOMMENDED"));
}

#[test]
fn recommendations_for_finding_chaining() {
    let graph = TestGraph::new()
        .with_endpoint(1, "/api/a", "GET")
        .with_finding(make_finding(
            100,
            VulnerabilityClass::SqlInjection,
            8.0,
            vec![1],
        ))
        .with_finding(make_finding(
            101,
            VulnerabilityClass::ServerSideRequestForgery,
            7.0,
            vec![1],
        ));

    let defense = DefenseContext::default();
    let recs = generate_recommendations(&graph, &defense, &[], 10);

    let has_chain = recs.iter().any(|r| r.action.contains("chaining"));
    assert!(
        has_chain,
        "should recommend finding chaining with 2+ findings"
    );
}

#[test]
fn briefing_document_serde_roundtrip() {
    let doc = ScanBriefingDocument {
        markdown: "# test".to_string(),
        sections: vec![BriefingSection {
            name: "TEST".to_string(),
            content: "# test".to_string(),
            token_estimate: 2,
        }],
        token_estimate: 2,
        target_url: "http://localhost".to_string(),
        iteration: 1,
    };
    let json = serde_json::to_string(&doc).unwrap();
    let parsed: ScanBriefingDocument = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.target_url, "http://localhost");
    assert_eq!(parsed.sections.len(), 1);
}
