use aegis_crawler::{CrawlResult, DiscoveredEndpoint, DiscoverySource};
use aegis_knowledge_graph::graph::KnowledgeGraph;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::GraphOperation;
use aegis_protocol::scan_event::ScanEvent;
use aegis_supervisor::capability_manager::CapabilityManager;

use crate::actor::{CrawlActor, ScanActor};
use crate::convergence::RefutedTracker;
use crate::phase_crawl::crawl_result_to_operations;
use crate::pipeline;
use crate::scan_config;

fn make_endpoint(url: &str, method: &str, source: DiscoverySource) -> DiscoveredEndpoint {
    DiscoveredEndpoint {
        url: url.to_string(),
        method: method.to_string(),
        parameters: Vec::new(),
        source,
    }
}

fn test_capability_manager() -> CapabilityManager {
    let mut manager = CapabilityManager::new(vec![0u8; 32]);
    pipeline::register_default_policies(&mut manager);
    manager
}

fn localhost_config() -> scan_config::ScanConfig {
    scan_config::ScanConfig {
        target: "http://localhost:8080".to_string(),
        output: std::env::temp_dir().join("aegis-crawl-test.sarif"),
        report_format: "developer".to_string(),
        source_dir: None,
        verbose: false,
        stealth: scan_config::StealthOptions {
            persona: "chrome".to_string(),
            stealth: false,
            stealth_level: "default".to_string(),
            max_rps: None,
            skip_evasion: false,
            accept_self_signed: false,
            persona_catalog: None,
        },
        pipeline: scan_config::PipelineOptions {
            max_iterations: 1,
            convergence_threshold: 2,
            skip_fingerprint: false,
            paranoia_sweep: false,
            resume: false,
        },
        llm: scan_config::LlmOptions {
            no_llm: false,
            bypass_corpus: None,
            python_cmd: "python3".to_string(),
        },
        audit: scan_config::AuditOptions {
            no_audit: false,
            scope_attestation: None,
            signed_config: None,
        },
        scope: scan_config::ScopeOptions {
            include_endpoints: None,
            exclude_endpoints: None,
            context_file: None,
            graph_db: None,
            history_db: None,
            export_graph: None,
            vuln_db: None,
        },
        auth: scan_config::AuthOptions {
            auth_flow: None,
            auth_input: Vec::new(),
        },
        distributed: scan_config::DistributedOptions {
            distributed: false,
            coordinator_addr: "127.0.0.1:9100".to_string(),
            workers: 1,
            worker_connect: None,
            worker_id: "worker-0".to_string(),
        },
    }
}

fn make_ctx_with_real_graph() -> pipeline::ScanContext {
    pipeline::ScanContext {
        config: localhost_config(),
        graph: Box::new(KnowledgeGraph::new()),
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    }
}

#[test]
fn crawl_result_to_operations_creates_endpoint_nodes() {
    let result = CrawlResult {
        discovered_endpoints: vec![
            make_endpoint("/api/users", "GET", DiscoverySource::Link),
            make_endpoint("/api/login", "POST", DiscoverySource::Form),
            make_endpoint("/api/data", "GET", DiscoverySource::ApiCall),
        ],
        ..Default::default()
    };

    let mut seq = 0u64;
    let ops = crawl_result_to_operations(&result, &mut seq);

    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);

    for (i, op) in ops.iter().enumerate() {
        assert_eq!(op.sequence_number, (i + 1) as u64);
        match &op.operation {
            GraphOperation::AddNode {
                node_type,
                properties,
            } => {
                assert_eq!(*node_type, NodeType::Endpoint);
                assert!(properties.iter().any(|(k, _)| k == "path"));
                assert!(properties.iter().any(|(k, _)| k == "method"));
                assert!(properties.iter().any(|(k, _)| k == "discovery_source"));
            }
            _ => panic!("expected AddNode operation"),
        }
    }
}

#[test]
fn crawl_result_to_operations_empty_result() {
    let result = CrawlResult::default();
    let mut seq = 5u64;
    let ops = crawl_result_to_operations(&result, &mut seq);

    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn crawl_result_to_operations_preserves_discovery_source() {
    let result = CrawlResult {
        discovered_endpoints: vec![
            make_endpoint("/link", "GET", DiscoverySource::Link),
            make_endpoint("/form", "POST", DiscoverySource::Form),
            make_endpoint("/api", "GET", DiscoverySource::ApiCall),
        ],
        ..Default::default()
    };

    let mut seq = 0u64;
    let ops = crawl_result_to_operations(&result, &mut seq);

    let sources: Vec<String> = ops
        .iter()
        .filter_map(|op| match &op.operation {
            GraphOperation::AddNode { properties, .. } => properties
                .iter()
                .find(|(k, _)| k == "discovery_source")
                .map(|(_, v)| v.clone()),
            _ => None,
        })
        .collect();

    assert_eq!(sources, vec!["Link", "Form", "ApiCall"]);
}

#[test]
fn crawl_result_to_operations_preserves_url_and_method() {
    let result = CrawlResult {
        discovered_endpoints: vec![make_endpoint(
            "/api/v2/items",
            "DELETE",
            DiscoverySource::Link,
        )],
        ..Default::default()
    };

    let mut seq = 10u64;
    let ops = crawl_result_to_operations(&result, &mut seq);

    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 11);

    if let GraphOperation::AddNode { properties, .. } = &ops[0].operation {
        let path = properties
            .iter()
            .find(|(k, _)| k == "path")
            .map(|(_, v)| v.as_str());
        let method = properties
            .iter()
            .find(|(k, _)| k == "method")
            .map(|(_, v)| v.as_str());
        assert_eq!(path, Some("/api/v2/items"));
        assert_eq!(method, Some("DELETE"));
    } else {
        panic!("expected AddNode");
    }
}

#[test]
fn crawl_actor_produces_phase_completed_event() {
    let mut ctx = make_ctx_with_real_graph();
    let mut actor = CrawlActor;
    let events = actor.process(&mut ctx, &[]).unwrap();

    assert_eq!(events.len(), 1);
    match &events[0].event {
        ScanEvent::PhaseCompleted {
            phase_name,
            operations_applied,
            findings_count,
            ..
        } => {
            assert_eq!(phase_name, "crawl");
            assert_eq!(*operations_applied, 0);
            assert_eq!(*findings_count, 0);
        }
        _ => panic!("expected PhaseCompleted event"),
    }
}

#[test]
fn crawl_actor_name() {
    let actor = CrawlActor;
    assert_eq!(actor.name(), "crawl");
}

#[test]
fn crawl_integrates_with_pipeline_graph() {
    let mut ctx = make_ctx_with_real_graph();
    let crawl_result = CrawlResult {
        discovered_endpoints: vec![
            make_endpoint(
                "http://localhost:3000/api/users",
                "GET",
                DiscoverySource::Link,
            ),
            make_endpoint("http://localhost:3000/login", "POST", DiscoverySource::Form),
            make_endpoint(
                "http://localhost:3000/api/data",
                "PUT",
                DiscoverySource::ApiCall,
            ),
        ],
        ..Default::default()
    };

    let mut seq = 0u64;
    let ops = crawl_result_to_operations(&crawl_result, &mut seq);
    ctx.graph.apply_operations(&ops).unwrap();

    let endpoint_ids = ctx.graph.nodes_by_type(NodeType::Endpoint).unwrap();
    assert_eq!(endpoint_ids.len(), 3);

    let expected = [
        ("http://localhost:3000/api/users", "GET"),
        ("http://localhost:3000/login", "POST"),
        ("http://localhost:3000/api/data", "PUT"),
    ];

    for &id in &endpoint_ids {
        let node = ctx.graph.get_node(id).unwrap().unwrap();
        assert_eq!(node.node_type, NodeType::Endpoint);
        let path = node.properties.get("path").unwrap();
        let method = node.properties.get("method").unwrap();
        assert!(
            expected.contains(&(path.as_str(), method.as_str())),
            "unexpected node: path={path}, method={method}"
        );
    }
}

#[test]
fn crawl_actor_operations_count_matches_endpoints() {
    let mut ctx = make_ctx_with_real_graph();

    let pre_ops = ctx.graph.total_operations_applied().unwrap();
    assert_eq!(pre_ops, 0);

    let mut actor = CrawlActor;
    let events = actor.process(&mut ctx, &[]).unwrap();

    assert_eq!(events.len(), 1);
    match &events[0].event {
        ScanEvent::PhaseCompleted {
            phase_name,
            operations_applied,
            ..
        } => {
            assert_eq!(phase_name, "crawl");
            assert_eq!(*operations_applied, 0);
        }
        _ => panic!("expected PhaseCompleted event"),
    }

    let post_ops = ctx.graph.total_operations_applied().unwrap();
    assert_eq!(post_ops, 0);
}
