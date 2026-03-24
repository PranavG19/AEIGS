use super::*;
use aegis_knowledge_graph::GraphStore;
use aegis_knowledge_graph::graph::GraphError;
use aegis_protocol::defense_context::DefenseContext;
use aegis_protocol::finding::{EvidenceLevel, FindingData, VulnerabilityClass};
use aegis_protocol::node::{NodeData, NodeType};
use aegis_protocol::operation::{ModuleIdentifier, OperationLogEntry};

/// Minimal in-test mock graph store. We keep this self-contained so the test
/// file compiles without pulling in test-support (which may have conflicting
/// deps in the orchestrator crate).
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

    fn add_node(&mut self, node: NodeData) {
        self.nodes.push(node);
    }

    fn add_finding(&mut self, finding: FindingData) {
        self.findings.push(finding);
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
        Ok(42)
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

fn default_meta() -> ScanMeta {
    ScanMeta {
        target_url: "http://127.0.0.1:3000".to_string(),
        scan_id: "scan-abc123".to_string(),
        iteration: 2,
        max_iterations: 5,
        preset: "thorough".to_string(),
        stealth_level: "paranoid".to_string(),
    }
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

fn make_finding(id: u64, class: VulnerabilityClass, severity: f64) -> FindingData {
    FindingData::new(
        id,
        class,
        severity,
        0.85,
        ModuleIdentifier::Fuzzing,
        1700000000000,
    )
    .with_evidence_level(EvidenceLevel::Confirmed)
}

#[test]
fn empty_graph_produces_valid_briefing() {
    let graph = TestGraph::new();
    let defense = DefenseContext::default();
    let meta = default_meta();
    let config = BriefingConfig::default();

    let briefing = serialize_briefing(&graph, &defense, &meta, &[], &config);

    assert!(briefing.markdown.contains("# TARGET BRIEFING"));
    assert!(briefing.markdown.contains("http://127.0.0.1:3000"));
    assert!(briefing.markdown.contains("iter 2/5"));
    assert!(briefing.markdown.contains("## FINDINGS"));
    assert!(briefing.markdown.contains("None yet."));
    assert!(briefing.token_estimate > 0);
}

#[test]
fn defense_section_renders_waf_details() {
    let graph = TestGraph::new();
    let defense = default_defense();
    let meta = default_meta();
    let config = BriefingConfig::default();

    let briefing = serialize_briefing(&graph, &defense, &meta, &[], &config);

    assert!(briefing.markdown.contains("WAF: Cloudflare (active)"));
    assert!(briefing.markdown.contains("SQL Injection"));
    assert!(briefing.markdown.contains("Cross-Site Scripting"));
    assert!(briefing.markdown.contains("rate limit: 10.0 req/s"));
    assert!(
        briefing
            .markdown
            .contains("bot detection: present (NOT evaded)")
    );
}

#[test]
fn defense_section_omitted_when_disabled() {
    let graph = TestGraph::new();
    let defense = default_defense();
    let meta = default_meta();
    let config = BriefingConfig {
        include_defense_details: false,
        ..BriefingConfig::default()
    };

    let briefing = serialize_briefing(&graph, &defense, &meta, &[], &config);

    assert!(!briefing.markdown.contains("## DEFENSES"));
}

#[test]
fn no_waf_renders_none_detected() {
    let graph = TestGraph::new();
    let defense = DefenseContext::default();
    let meta = default_meta();
    let config = BriefingConfig::default();

    let briefing = serialize_briefing(&graph, &defense, &meta, &[], &config);

    assert!(briefing.markdown.contains("WAF: none detected"));
}

#[test]
fn tech_stack_grouped_by_category() {
    let mut graph = TestGraph::new();
    graph.add_node(
        NodeData::new(1, NodeType::Service)
            .with_property("name", "Express")
            .with_property("version", "4.18.2")
            .with_property("category", "framework"),
    );
    graph.add_node(
        NodeData::new(2, NodeType::Service)
            .with_property("name", "Node.js")
            .with_property("version", "20.10")
            .with_property("category", "runtime"),
    );
    graph.add_node(
        NodeData::new(3, NodeType::Dependency)
            .with_property("name", "lodash")
            .with_property("version", "4.17.21")
            .with_property("category", "library"),
    );

    let briefing = serialize_briefing(
        &graph,
        &DefenseContext::default(),
        &default_meta(),
        &[],
        &BriefingConfig::default(),
    );

    assert!(briefing.markdown.contains("## TECH STACK"));
    assert!(briefing.markdown.contains("framework: Express 4.18.2"));
    assert!(briefing.markdown.contains("runtime: Node.js 20.10"));
    assert!(briefing.markdown.contains("library: lodash 4.17.21"));
}

#[test]
fn tech_stack_omitted_when_disabled() {
    let mut graph = TestGraph::new();
    graph.add_node(
        NodeData::new(1, NodeType::Service)
            .with_property("name", "nginx")
            .with_property("category", "webserver"),
    );

    let config = BriefingConfig {
        include_tech_stack: false,
        ..BriefingConfig::default()
    };

    let briefing = serialize_briefing(
        &graph,
        &DefenseContext::default(),
        &default_meta(),
        &[],
        &config,
    );

    assert!(!briefing.markdown.contains("## TECH STACK"));
}

#[test]
fn endpoints_listed_with_methods_and_params() {
    let mut graph = TestGraph::new();
    graph.add_node(
        NodeData::new(10, NodeType::Endpoint)
            .with_property("path", "/api/users")
            .with_property("method", "GET")
            .with_property("parameters", "id,name,role"),
    );
    graph.add_node(
        NodeData::new(11, NodeType::Endpoint)
            .with_property("path", "/api/login")
            .with_property("method", "POST")
            .with_property("auth_required", "false"),
    );

    let briefing = serialize_briefing(
        &graph,
        &DefenseContext::default(),
        &default_meta(),
        &[],
        &BriefingConfig::default(),
    );

    assert!(
        briefing
            .markdown
            .contains("## ATTACK SURFACE (2 endpoints)")
    );
    assert!(briefing.markdown.contains("GET /api/users [id,name,role]"));
    assert!(briefing.markdown.contains("POST /api/login"));
    assert!(briefing.markdown.contains("(auth:false)"));
}

#[test]
fn endpoints_capped_at_max() {
    let mut graph = TestGraph::new();
    for i in 0..10 {
        graph.add_node(
            NodeData::new(i, NodeType::Endpoint)
                .with_property("path", format!("/ep/{}", i))
                .with_property("method", "GET"),
        );
    }

    let config = BriefingConfig {
        max_endpoints: 3,
        ..BriefingConfig::default()
    };

    let briefing = serialize_briefing(
        &graph,
        &DefenseContext::default(),
        &default_meta(),
        &[],
        &config,
    );

    assert!(briefing.markdown.contains("10 endpoints"));
    assert!(briefing.markdown.contains("+7 more endpoints"));
}

#[test]
fn findings_sorted_by_severity_grouped_by_class() {
    let mut graph = TestGraph::new();
    graph.add_node(NodeData::new(100, NodeType::Endpoint).with_property("path", "/api/search"));
    graph.add_node(NodeData::new(101, NodeType::Endpoint).with_property("path", "/api/admin"));

    let mut f1 = make_finding(1, VulnerabilityClass::SqlInjection, 9.8);
    f1.linked_node_ids = vec![100];
    let mut f2 = make_finding(2, VulnerabilityClass::CrossSiteScripting, 6.1);
    f2.linked_node_ids = vec![101];
    let mut f3 = make_finding(3, VulnerabilityClass::SqlInjection, 7.5);
    f3.linked_node_ids = vec![101];

    graph.add_finding(f1);
    graph.add_finding(f2);
    graph.add_finding(f3);

    let briefing = serialize_briefing(
        &graph,
        &DefenseContext::default(),
        &default_meta(),
        &[],
        &BriefingConfig::default(),
    );

    assert!(briefing.markdown.contains("## FINDINGS (3 total)"));
    assert!(briefing.markdown.contains("### SQL Injection"));
    assert!(briefing.markdown.contains("### Cross-Site Scripting"));
    assert!(briefing.markdown.contains("sev=9.8"));
    assert!(briefing.markdown.contains("/api/search"));

    let sqli_pos = briefing.markdown.find("### SQL Injection").unwrap();
    let xss_pos = briefing.markdown.find("### Cross-Site Scripting").unwrap();
    assert!(
        sqli_pos < xss_pos,
        "SQLi (sev 9.8) should appear before XSS (sev 6.1)"
    );
}

#[test]
fn findings_capped_with_overflow_note() {
    let mut graph = TestGraph::new();
    for i in 0..10 {
        graph.add_finding(make_finding(
            i,
            VulnerabilityClass::SecurityMisconfiguration,
            (10 - i) as f64,
        ));
    }

    let config = BriefingConfig {
        max_findings: 3,
        ..BriefingConfig::default()
    };

    let briefing = serialize_briefing(
        &graph,
        &DefenseContext::default(),
        &default_meta(),
        &[],
        &config,
    );

    assert!(briefing.markdown.contains("10 total"));
    assert!(
        briefing
            .markdown
            .contains("+7 lower-severity findings omitted")
    );
}

#[test]
fn failed_attempts_listed() {
    let graph = TestGraph::new();
    let failed = vec![
        FailedAttempt {
            endpoint: "/api/search".to_string(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
            payload_summary: "' OR 1=1--".to_string(),
            failure_reason: "WAF blocked".to_string(),
        },
        FailedAttempt {
            endpoint: "/api/login".to_string(),
            vulnerability_class: VulnerabilityClass::BrokenAuthentication,
            payload_summary: "admin:admin".to_string(),
            failure_reason: "rate limited".to_string(),
        },
    ];

    let briefing = serialize_briefing(
        &graph,
        &DefenseContext::default(),
        &default_meta(),
        &failed,
        &BriefingConfig::default(),
    );

    assert!(briefing.markdown.contains("## FAILED ATTEMPTS (2 total)"));
    assert!(briefing.markdown.contains("Do NOT retry"));
    assert!(briefing.markdown.contains("' OR 1=1--"));
    assert!(briefing.markdown.contains("WAF blocked"));
}

#[test]
fn failed_attempts_omitted_when_disabled() {
    let graph = TestGraph::new();
    let failed = vec![FailedAttempt {
        endpoint: "/x".to_string(),
        vulnerability_class: VulnerabilityClass::CommandInjection,
        payload_summary: "; ls".to_string(),
        failure_reason: "blocked".to_string(),
    }];

    let config = BriefingConfig {
        include_failed_attempts: false,
        ..BriefingConfig::default()
    };

    let briefing = serialize_briefing(
        &graph,
        &DefenseContext::default(),
        &default_meta(),
        &failed,
        &config,
    );

    assert!(!briefing.markdown.contains("## FAILED ATTEMPTS"));
}

#[test]
fn graph_stats_section_present() {
    let mut graph = TestGraph::new();
    graph.add_node(NodeData::new(1, NodeType::Endpoint));
    graph.add_node(NodeData::new(2, NodeType::Service));
    graph.add_finding(make_finding(1, VulnerabilityClass::PathTraversal, 7.0));

    let briefing = serialize_briefing(
        &graph,
        &DefenseContext::default(),
        &default_meta(),
        &[],
        &BriefingConfig::default(),
    );

    assert!(briefing.markdown.contains("## GRAPH STATS"));
    assert!(briefing.markdown.contains("nodes: 2"));
    assert!(briefing.markdown.contains("findings: 1"));
    assert!(briefing.markdown.contains("operations applied: 42"));
}

#[test]
fn token_estimate_scales_with_content() {
    let mut graph = TestGraph::new();
    let small = serialize_briefing(
        &graph,
        &DefenseContext::default(),
        &default_meta(),
        &[],
        &BriefingConfig::default(),
    );

    for i in 0..50 {
        graph.add_node(
            NodeData::new(i, NodeType::Endpoint)
                .with_property("path", format!("/api/endpoint/{}", i))
                .with_property("method", "POST")
                .with_property("parameters", "a,b,c,d,e"),
        );
        graph.add_finding(make_finding(
            i + 1000,
            VulnerabilityClass::SqlInjection,
            (i % 10) as f64 + 1.0,
        ));
    }

    let big = serialize_briefing(
        &graph,
        &default_defense(),
        &default_meta(),
        &[],
        &BriefingConfig::default(),
    );

    assert!(
        big.token_estimate > small.token_estimate,
        "bigger graph = more tokens: {} vs {}",
        big.token_estimate,
        small.token_estimate,
    );
}

#[test]
fn full_briefing_all_sections() {
    let mut graph = TestGraph::new();
    graph.add_node(
        NodeData::new(1, NodeType::Service)
            .with_property("name", "Django")
            .with_property("version", "4.2")
            .with_property("category", "framework"),
    );
    graph.add_node(
        NodeData::new(2, NodeType::Endpoint)
            .with_property("path", "/admin/login")
            .with_property("method", "POST"),
    );
    let mut f = make_finding(1, VulnerabilityClass::ServerSideTemplateInjection, 8.5);
    f.linked_node_ids = vec![2];
    graph.add_finding(f);

    let failed = vec![FailedAttempt {
        endpoint: "/admin/login".to_string(),
        vulnerability_class: VulnerabilityClass::SqlInjection,
        payload_summary: "1' UNION SELECT--".to_string(),
        failure_reason: "ModSecurity CRS blocked".to_string(),
    }];

    let briefing = serialize_briefing(
        &graph,
        &default_defense(),
        &default_meta(),
        &failed,
        &BriefingConfig::default(),
    );

    let sections = [
        "# TARGET BRIEFING",
        "## DEFENSES",
        "## TECH STACK",
        "## ATTACK SURFACE",
        "## FINDINGS",
        "## FAILED ATTEMPTS",
        "## GRAPH STATS",
    ];
    for section in &sections {
        assert!(
            briefing.markdown.contains(section),
            "missing section: {}",
            section
        );
    }

    assert!(briefing.markdown.contains("Django 4.2"));
    assert!(briefing.markdown.contains("Server-Side Template Injection"));
    assert!(briefing.markdown.contains("/admin/login"));
    assert!(briefing.markdown.contains("ModSecurity CRS blocked"));
}

#[test]
fn bot_detection_evaded_status() {
    let graph = TestGraph::new();
    let defense = DefenseContext {
        bot_detection_present: true,
        bot_detection_evaded: true,
        ..DefenseContext::default()
    };

    let briefing = serialize_briefing(
        &graph,
        &defense,
        &default_meta(),
        &[],
        &BriefingConfig::default(),
    );

    assert!(
        briefing
            .markdown
            .contains("bot detection: present (evaded)")
    );
}

#[test]
fn evidence_level_rendered_in_findings() {
    let mut graph = TestGraph::new();
    let mut f = make_finding(1, VulnerabilityClass::CommandInjection, 9.0);
    f.evidence_level = EvidenceLevel::Chained;
    graph.add_finding(f);

    let briefing = serialize_briefing(
        &graph,
        &DefenseContext::default(),
        &default_meta(),
        &[],
        &BriefingConfig::default(),
    );

    assert!(briefing.markdown.contains("evidence=Chained"));
}

#[test]
fn dependency_nodes_capped_at_max() {
    let mut graph = TestGraph::new();
    for i in 0..20 {
        graph.add_node(
            NodeData::new(i, NodeType::Dependency)
                .with_property("name", format!("dep-{}", i))
                .with_property("category", "library"),
        );
    }

    let config = BriefingConfig {
        max_dependencies: 5,
        ..BriefingConfig::default()
    };

    let briefing = serialize_briefing(
        &graph,
        &DefenseContext::default(),
        &default_meta(),
        &[],
        &config,
    );

    assert!(briefing.markdown.contains("## TECH STACK"));
    let dep_count = briefing.markdown.matches("dep-").count();
    assert!(dep_count <= 5, "should cap at 5 deps, got {}", dep_count,);
}
