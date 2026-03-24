use super::*;
use aegis_knowledge_graph::graph::GraphError;
use aegis_knowledge_graph::GraphStore;
use aegis_protocol::defense_context::DefenseContext;
use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::node::{NodeData, NodeType};
use aegis_protocol::operation::OperationLogEntry;

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
        Ok(0)
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
        scan_id: "test-scan".to_string(),
        iteration: 1,
        max_iterations: 5,
        preset: "thorough".to_string(),
        stealth_level: "default".to_string(),
    }
}

#[test]
fn load_embedded_mission_prompt() {
    let prompt = load_mission_prompt(None).unwrap();
    assert!(prompt.contains("AEGIS-MIND"));
    assert!(prompt.contains("offensive security"));
    assert!(prompt.contains("vulnerability_class"));
}

#[test]
fn load_mission_prompt_from_file() {
    let prompt_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("prompts")
        .join("aegis_mind.md");
    let prompt = load_mission_prompt(Some(&prompt_path)).unwrap();
    assert!(prompt.contains("AEGIS-MIND"));
}

#[test]
fn load_mission_prompt_missing_file() {
    let result = load_mission_prompt(Some(std::path::Path::new("/nonexistent/prompt.md")));
    assert!(result.is_err());
}

#[test]
fn outcome_to_failed_attempt_refuted() {
    let outcome = HypothesisOutcome::Refuted {
        vulnerability_class: "SQL Injection".to_string(),
        endpoint: "/api/search".to_string(),
        reason: "WAF blocked".to_string(),
    };

    let attempt = outcome_to_failed_attempt(&outcome).unwrap();
    assert_eq!(attempt.endpoint, "/api/search");
    assert_eq!(
        attempt.vulnerability_class,
        VulnerabilityClass::SqlInjection
    );
    assert_eq!(attempt.failure_reason, "WAF blocked");
}

#[test]
fn outcome_to_failed_attempt_inconclusive() {
    let outcome = HypothesisOutcome::Inconclusive {
        vulnerability_class: "XSS".to_string(),
        endpoint: "/form".to_string(),
        reason: "timeout".to_string(),
    };

    let attempt = outcome_to_failed_attempt(&outcome).unwrap();
    assert!(attempt.failure_reason.contains("inconclusive"));
}

#[test]
fn outcome_to_failed_attempt_confirmed_returns_none() {
    let outcome = HypothesisOutcome::Confirmed {
        vulnerability_class: "SSRF".to_string(),
        endpoint: "/fetch".to_string(),
        payload: "http://169.254.169.254/".to_string(),
        severity: 9.0,
    };

    assert!(outcome_to_failed_attempt(&outcome).is_none());
}

#[test]
fn check_convergence_not_enough_iterations() {
    let results = vec![IterationResult {
        iteration: 1,
        hypotheses_generated: 5,
        hypotheses_confirmed: 0,
        hypotheses_refuted: 5,
        hypotheses_inconclusive: 0,
        new_failed_attempts: Vec::new(),
        duration_ms: 1000,
        brain_response: None,
    }];

    assert!(!check_convergence(&results, 2));
}

#[test]
fn check_convergence_detected() {
    let results = vec![
        IterationResult {
            iteration: 1,
            hypotheses_generated: 3,
            hypotheses_confirmed: 1,
            hypotheses_refuted: 2,
            hypotheses_inconclusive: 0,
            new_failed_attempts: Vec::new(),
            duration_ms: 1000,
            brain_response: None,
        },
        IterationResult {
            iteration: 2,
            hypotheses_generated: 3,
            hypotheses_confirmed: 0,
            hypotheses_refuted: 3,
            hypotheses_inconclusive: 0,
            new_failed_attempts: Vec::new(),
            duration_ms: 1000,
            brain_response: None,
        },
        IterationResult {
            iteration: 3,
            hypotheses_generated: 2,
            hypotheses_confirmed: 0,
            hypotheses_refuted: 2,
            hypotheses_inconclusive: 0,
            new_failed_attempts: Vec::new(),
            duration_ms: 1000,
            brain_response: None,
        },
    ];

    assert!(check_convergence(&results, 2));
}

#[test]
fn check_convergence_not_converged() {
    let results = vec![
        IterationResult {
            iteration: 1,
            hypotheses_generated: 3,
            hypotheses_confirmed: 1,
            hypotheses_refuted: 2,
            hypotheses_inconclusive: 0,
            new_failed_attempts: Vec::new(),
            duration_ms: 1000,
            brain_response: None,
        },
        IterationResult {
            iteration: 2,
            hypotheses_generated: 3,
            hypotheses_confirmed: 0,
            hypotheses_refuted: 3,
            hypotheses_inconclusive: 0,
            new_failed_attempts: Vec::new(),
            duration_ms: 1000,
            brain_response: None,
        },
        IterationResult {
            iteration: 3,
            hypotheses_generated: 2,
            hypotheses_confirmed: 1,
            hypotheses_refuted: 1,
            hypotheses_inconclusive: 0,
            new_failed_attempts: Vec::new(),
            duration_ms: 1000,
            brain_response: None,
        },
    ];

    assert!(!check_convergence(&results, 2));
}

#[test]
fn summarize_iteration_counts() {
    let outcomes = vec![
        HypothesisOutcome::Confirmed {
            vulnerability_class: "SQLi".to_string(),
            endpoint: "/api".to_string(),
            payload: "'--".to_string(),
            severity: 9.0,
        },
        HypothesisOutcome::Refuted {
            vulnerability_class: "XSS".to_string(),
            endpoint: "/search".to_string(),
            reason: "filtered".to_string(),
        },
        HypothesisOutcome::Refuted {
            vulnerability_class: "SSRF".to_string(),
            endpoint: "/fetch".to_string(),
            reason: "blocked".to_string(),
        },
        HypothesisOutcome::Inconclusive {
            vulnerability_class: "SSTI".to_string(),
            endpoint: "/render".to_string(),
            reason: "timeout".to_string(),
        },
    ];

    let result = summarize_iteration(1, 4, &outcomes, None, 5000);

    assert_eq!(result.iteration, 1);
    assert_eq!(result.hypotheses_generated, 4);
    assert_eq!(result.hypotheses_confirmed, 1);
    assert_eq!(result.hypotheses_refuted, 2);
    assert_eq!(result.hypotheses_inconclusive, 1);
    assert_eq!(result.new_failed_attempts.len(), 3);
    assert_eq!(result.duration_ms, 5000);
}

#[test]
fn summarize_iteration_empty_outcomes() {
    let result = summarize_iteration(1, 0, &[], None, 100);

    assert_eq!(result.hypotheses_generated, 0);
    assert_eq!(result.hypotheses_confirmed, 0);
    assert_eq!(result.hypotheses_refuted, 0);
    assert_eq!(result.hypotheses_inconclusive, 0);
    assert!(result.new_failed_attempts.is_empty());
}

#[test]
fn parse_vuln_class_common_names() {
    assert_eq!(
        parse_vuln_class("SQL Injection"),
        VulnerabilityClass::SqlInjection
    );
    assert_eq!(parse_vuln_class("sqli"), VulnerabilityClass::SqlInjection);
    assert_eq!(
        parse_vuln_class("XSS"),
        VulnerabilityClass::CrossSiteScripting
    );
    assert_eq!(
        parse_vuln_class("Cross-Site Scripting"),
        VulnerabilityClass::CrossSiteScripting
    );
    assert_eq!(
        parse_vuln_class("SSRF"),
        VulnerabilityClass::ServerSideRequestForgery
    );
    assert_eq!(
        parse_vuln_class("SSTI"),
        VulnerabilityClass::ServerSideTemplateInjection
    );
    assert_eq!(
        parse_vuln_class("IDOR"),
        VulnerabilityClass::BrokenAuthorization
    );
    assert_eq!(
        parse_vuln_class("JWT"),
        VulnerabilityClass::JwtVulnerability
    );
    assert_eq!(
        parse_vuln_class("Race Condition"),
        VulnerabilityClass::RaceCondition
    );
    assert_eq!(
        parse_vuln_class("GraphQL"),
        VulnerabilityClass::GraphQlAbuse
    );
}

#[test]
fn parse_vuln_class_unknown_falls_back() {
    assert_eq!(
        parse_vuln_class("some-unknown-class"),
        VulnerabilityClass::InsufficientInputValidation,
    );
}

#[test]
fn build_iteration_briefing_produces_markdown() {
    let graph = TestGraph::new();
    let defense = DefenseContext::default();
    let meta = default_meta();

    let briefing =
        build_iteration_briefing(&graph, &defense, &meta, &[], &BriefingConfig::default());

    assert!(briefing.markdown.contains("# TARGET BRIEFING"));
    assert!(briefing.token_estimate > 0);
}

#[test]
fn brain_loop_error_display() {
    let e = BrainLoopError::Bridge(BridgeError::Timeout);
    assert!(format!("{e}").contains("timed out"));

    let e = BrainLoopError::Graph("test".to_string());
    assert!(format!("{e}").contains("test"));
}

#[test]
fn brain_loop_with_no_opencode_binary() {
    let graph = TestGraph::new();
    let defense = DefenseContext::default();
    let meta = default_meta();

    let config = BrainLoopConfig {
        max_iterations: 2,
        convergence_threshold: 2,
        opencode: OpenCodeConfig {
            binary: "nonexistent-opencode-binary-xyz".to_string(),
            ..OpenCodeConfig::default()
        },
        briefing: BriefingConfig::default(),
        mission_prompt: Some("Test prompt".to_string()),
    };

    let call_count = std::cell::Cell::new(0u32);
    let results = run_brain_loop(&graph, &defense, &meta, &config, |_hyp| {
        call_count.set(call_count.get() + 1);
        HypothesisOutcome::Refuted {
            vulnerability_class: "test".to_string(),
            endpoint: "/test".to_string(),
            reason: "test".to_string(),
        }
    })
    .unwrap();

    assert_eq!(
        call_count.get(),
        0,
        "should not call test_hypothesis when binary not found"
    );
    assert_eq!(
        results.len(),
        1,
        "should produce 1 iteration result then break"
    );
    assert_eq!(results[0].hypotheses_generated, 0);
}

#[test]
fn failed_attempts_accumulate_across_iterations() {
    let attempt1 = FailedAttempt {
        endpoint: "/api/a".to_string(),
        vulnerability_class: VulnerabilityClass::SqlInjection,
        payload_summary: "' OR 1=1".to_string(),
        failure_reason: "blocked".to_string(),
    };
    let attempt2 = FailedAttempt {
        endpoint: "/api/b".to_string(),
        vulnerability_class: VulnerabilityClass::CrossSiteScripting,
        payload_summary: "<script>".to_string(),
        failure_reason: "filtered".to_string(),
    };

    let result1 = IterationResult {
        iteration: 1,
        hypotheses_generated: 1,
        hypotheses_confirmed: 0,
        hypotheses_refuted: 1,
        hypotheses_inconclusive: 0,
        new_failed_attempts: vec![attempt1.clone()],
        duration_ms: 100,
        brain_response: None,
    };

    let result2 = IterationResult {
        iteration: 2,
        hypotheses_generated: 1,
        hypotheses_confirmed: 0,
        hypotheses_refuted: 1,
        hypotheses_inconclusive: 0,
        new_failed_attempts: vec![attempt2.clone()],
        duration_ms: 100,
        brain_response: None,
    };

    let mut all_failed: Vec<FailedAttempt> = Vec::new();
    all_failed.extend(result1.new_failed_attempts);
    all_failed.extend(result2.new_failed_attempts);

    assert_eq!(all_failed.len(), 2);
    assert_eq!(all_failed[0].endpoint, "/api/a");
    assert_eq!(all_failed[1].endpoint, "/api/b");
}
