use aegis_knowledge_graph::graph::GraphMetadata;
use aegis_knowledge_graph::{GraphStore, KnowledgeGraph};
use aegis_protocol::edge::EdgeLabel;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};
use std::sync::Arc;
use tempfile::NamedTempFile;

fn entry(seq: u64, module: ModuleIdentifier, op: GraphOperation) -> OperationLogEntry {
    OperationLogEntry {
        sequence_number: seq,
        module,
        operation: op,
        timestamp_unix_ms: 1_700_000_000_000 + seq,
    }
}

fn add_node(seq: u64, node_type: NodeType, props: Vec<(&str, &str)>) -> OperationLogEntry {
    entry(
        seq,
        ModuleIdentifier::Enumeration,
        GraphOperation::AddNode {
            node_type,
            properties: props
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        },
    )
}

fn add_edge(
    seq: u64,
    source: u64,
    target: u64,
    label: EdgeLabel,
    weight: f64,
) -> OperationLogEntry {
    entry(
        seq,
        ModuleIdentifier::Enumeration,
        GraphOperation::AddEdge {
            source_node_id: source,
            target_node_id: target,
            label,
            weight,
        },
    )
}

fn add_finding(
    seq: u64,
    node_ids: Vec<u64>,
    class: VulnerabilityClass,
    severity: f64,
    confidence: f64,
) -> OperationLogEntry {
    entry(
        seq,
        ModuleIdentifier::Fuzzing,
        GraphOperation::AddFinding {
            linked_node_ids: node_ids,
            vulnerability_class: class,
            severity,
            confidence,
            certificate: b"cert".to_vec(),
        },
    )
}

fn test_metadata() -> GraphMetadata {
    GraphMetadata {
        scan_timestamp_unix_ms: 1_700_000_000_000,
        target_url: "http://127.0.0.1:8080".to_owned(),
        aegis_version: "0.1.0".to_owned(),
        scan_count: 0,
    }
}

/// Builds a small graph: Endpoint(0) -Calls-> Function(1) -Reads-> DataStore(2)
/// with a SqlInjection finding linked to node 0.
fn populate_graph(graph: &KnowledgeGraph) {
    let ops = vec![
        add_node(0, NodeType::Endpoint, vec![("path", "/api/login")]),
        add_node(1, NodeType::Function, vec![("name", "handle_login")]),
        add_node(2, NodeType::DataStore, vec![("name", "users_db")]),
        add_edge(3, 0, 1, EdgeLabel::Calls, 1.0),
        add_edge(4, 1, 2, EdgeLabel::Reads, 0.5),
    ];
    graph.apply_operations(&ops).unwrap();

    let finding_ops = vec![add_finding(
        0,
        vec![0],
        VulnerabilityClass::SqlInjection,
        8.5,
        0.9,
    )];
    graph.apply_operations(&finding_ops).unwrap();
}

// ---------------------------------------------------------------------------
// 19. Persistence: save/load roundtrip
// ---------------------------------------------------------------------------
#[test]
fn graph_persist_save_load_roundtrip() {
    let graph = KnowledgeGraph::new();
    populate_graph(&graph);

    let tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path();
    graph.save_to_file(path, &test_metadata()).unwrap();

    let (loaded, _meta) = KnowledgeGraph::load_from_file(path).unwrap();

    assert_eq!(loaded.node_count().unwrap(), 3);
    assert_eq!(loaded.edge_count().unwrap(), 2);
    assert_eq!(loaded.finding_count().unwrap(), 1);

    let node0 = loaded.get_node(0).unwrap().unwrap();
    assert_eq!(node0.node_type, NodeType::Endpoint);
    assert_eq!(node0.properties.get("path").unwrap(), "/api/login");

    let node1 = loaded.get_node(1).unwrap().unwrap();
    assert_eq!(node1.node_type, NodeType::Function);

    let node2 = loaded.get_node(2).unwrap().unwrap();
    assert_eq!(node2.node_type, NodeType::DataStore);

    let findings = loaded.all_findings().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].vulnerability_class,
        VulnerabilityClass::SqlInjection
    );
    assert!((findings[0].severity - 8.5).abs() < f64::EPSILON);
    assert!((findings[0].confidence.composite.value() - 0.9).abs() < f64::EPSILON);
}

// ---------------------------------------------------------------------------
// 20. Persistence: metadata preserved
// ---------------------------------------------------------------------------
#[test]
fn graph_persist_metadata_preserved() {
    let graph = KnowledgeGraph::new();
    let metadata = GraphMetadata {
        scan_timestamp_unix_ms: 1_700_123_456_789,
        target_url: "http://127.0.0.1:3000/app".to_owned(),
        aegis_version: "0.42.0".to_owned(),
        scan_count: 7,
    };

    let tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path();
    graph.save_to_file(path, &metadata).unwrap();

    let (_loaded, loaded_meta) = KnowledgeGraph::load_from_file(path).unwrap();
    let loaded_meta = loaded_meta.expect("metadata should be present");

    assert_eq!(
        loaded_meta.scan_timestamp_unix_ms,
        metadata.scan_timestamp_unix_ms
    );
    assert_eq!(loaded_meta.target_url, metadata.target_url);
    assert_eq!(loaded_meta.aegis_version, metadata.aegis_version);
    assert_eq!(loaded_meta.scan_count, metadata.scan_count);
}

// ---------------------------------------------------------------------------
// 21. Batch validation: invalid edge triple rejected, valid accepted
// ---------------------------------------------------------------------------
#[test]
fn graph_apply_operations_batch_validates_edges() {
    let graph = KnowledgeGraph::new();

    let setup = vec![
        add_node(0, NodeType::DataStore, vec![("name", "db")]),
        add_node(1, NodeType::Function, vec![("name", "fn1")]),
    ];
    graph.apply_operations(&setup).unwrap();

    let invalid_batch = vec![add_edge(2, 0, 1, EdgeLabel::Calls, 1.0)];
    let result = graph.apply_operations(&invalid_batch);
    assert!(
        result.is_err(),
        "DataStore -Calls-> Function should be rejected"
    );

    assert_eq!(
        graph.edge_count().unwrap(),
        0,
        "no edges should exist after rejected batch"
    );

    let valid_batch = vec![add_edge(2, 1, 0, EdgeLabel::Reads, 1.0)];
    graph.apply_operations(&valid_batch).unwrap();
    assert_eq!(graph.edge_count().unwrap(), 1);
}

// ---------------------------------------------------------------------------
// 22. Duplicate edges rejected
// ---------------------------------------------------------------------------
#[test]
fn graph_apply_operations_rejects_duplicate_edges() {
    let graph = KnowledgeGraph::new();

    let setup = vec![
        add_node(0, NodeType::Endpoint, vec![]),
        add_node(1, NodeType::Function, vec![]),
        add_edge(2, 0, 1, EdgeLabel::Calls, 1.0),
    ];
    graph.apply_operations(&setup).unwrap();

    let duplicate = vec![add_edge(3, 0, 1, EdgeLabel::Calls, 2.0)];
    let result = graph.apply_operations(&duplicate);
    assert!(
        result.is_err(),
        "duplicate (source, target, label) should be rejected"
    );
    assert_eq!(
        graph.edge_count().unwrap(),
        1,
        "edge count unchanged after rejected duplicate"
    );

    let intra_batch_dup = vec![
        add_node(0, NodeType::Endpoint, vec![]),
        add_node(1, NodeType::Function, vec![]),
        add_edge(2, 2, 3, EdgeLabel::Calls, 1.0),
        add_edge(3, 2, 3, EdgeLabel::Calls, 1.5),
    ];
    let graph2 = KnowledgeGraph::new();
    let result2 = graph2.apply_operations(&intra_batch_dup);
    assert!(
        result2.is_err(),
        "intra-batch duplicate edge should be rejected"
    );
}

// ---------------------------------------------------------------------------
// 23. Weight bounds: NaN, -1.0, Infinity rejected; valid accepted
// ---------------------------------------------------------------------------
#[test]
fn graph_apply_operations_weight_bounds() {
    let graph = KnowledgeGraph::new();
    let setup = vec![
        add_node(0, NodeType::Endpoint, vec![]),
        add_node(1, NodeType::Function, vec![]),
    ];
    graph.apply_operations(&setup).unwrap();

    for bad_weight in [f64::NAN, -1.0, f64::INFINITY, f64::NEG_INFINITY] {
        let ops = vec![add_edge(2, 0, 1, EdgeLabel::Calls, bad_weight)];
        assert!(
            graph.apply_operations(&ops).is_err(),
            "weight {bad_weight} should be rejected"
        );
    }

    let valid = vec![add_edge(2, 0, 1, EdgeLabel::Calls, 0.0)];
    graph.apply_operations(&valid).unwrap();

    let valid_positive = vec![
        add_node(3, NodeType::Endpoint, vec![]),
        add_node(4, NodeType::Function, vec![]),
        add_edge(5, 2, 3, EdgeLabel::Calls, 42.0),
    ];
    graph.apply_operations(&valid_positive).unwrap();
}

// ---------------------------------------------------------------------------
// 24. Score bounds: severity and confidence
// ---------------------------------------------------------------------------
#[test]
fn graph_apply_operations_score_bounds() {
    let graph = KnowledgeGraph::new();
    let setup = vec![add_node(0, NodeType::Endpoint, vec![])];
    graph.apply_operations(&setup).unwrap();

    let bad_severity_high = vec![add_finding(
        0,
        vec![0],
        VulnerabilityClass::SqlInjection,
        11.0,
        0.5,
    )];
    assert!(
        graph.apply_operations(&bad_severity_high).is_err(),
        "severity 11.0 should be rejected"
    );

    let bad_severity_neg = vec![add_finding(
        0,
        vec![0],
        VulnerabilityClass::SqlInjection,
        -1.0,
        0.5,
    )];
    assert!(
        graph.apply_operations(&bad_severity_neg).is_err(),
        "severity -1.0 should be rejected"
    );

    let bad_confidence = vec![add_finding(
        0,
        vec![0],
        VulnerabilityClass::SqlInjection,
        5.0,
        1.5,
    )];
    assert!(
        graph.apply_operations(&bad_confidence).is_err(),
        "confidence 1.5 should be rejected"
    );

    let valid = vec![add_finding(
        0,
        vec![0],
        VulnerabilityClass::SqlInjection,
        10.0,
        1.0,
    )];
    graph.apply_operations(&valid).unwrap();
    assert_eq!(graph.finding_count().unwrap(), 1);
}

// ---------------------------------------------------------------------------
// 25. Strict sequence gap detection (via OperationLog directly)
// ---------------------------------------------------------------------------
#[test]
fn graph_strict_sequence_gap_detection() {
    use aegis_knowledge_graph::edge_store::EdgeStore;
    use aegis_knowledge_graph::finding_store::FindingStore;
    use aegis_knowledge_graph::node_store::NodeStore;
    use aegis_knowledge_graph::operation_log::OperationLog;

    let mut log = OperationLog::new_strict();
    let mut nodes = NodeStore::new();
    let mut edges = EdgeStore::new();
    let mut findings = FindingStore::new();

    let first = vec![entry(
        0,
        ModuleIdentifier::PassiveRecon,
        GraphOperation::AddNode {
            node_type: NodeType::Dependency,
            properties: vec![],
        },
    )];
    log.apply_batch(&first, &mut nodes, &mut edges, &mut findings)
        .unwrap();
    assert_eq!(nodes.count(), 1);

    let gap = vec![entry(
        2,
        ModuleIdentifier::PassiveRecon,
        GraphOperation::AddNode {
            node_type: NodeType::Dependency,
            properties: vec![],
        },
    )];
    let result = log.apply_batch(&gap, &mut nodes, &mut edges, &mut findings);
    assert!(
        result.is_err(),
        "strict mode should reject sequence gap (expected 1, got 2)"
    );
    assert_eq!(
        nodes.count(),
        1,
        "node count unchanged after rejected gap batch"
    );
}

// ---------------------------------------------------------------------------
// 26. Relaxed sequence allows gaps
// ---------------------------------------------------------------------------
#[test]
fn graph_relaxed_sequence_allows_gaps() {
    let graph = KnowledgeGraph::new();

    let seq0 = vec![entry(
        0,
        ModuleIdentifier::PassiveRecon,
        GraphOperation::AddNode {
            node_type: NodeType::Dependency,
            properties: vec![],
        },
    )];
    graph.apply_operations(&seq0).unwrap();

    let seq5 = vec![entry(
        5,
        ModuleIdentifier::PassiveRecon,
        GraphOperation::AddNode {
            node_type: NodeType::Dependency,
            properties: vec![],
        },
    )];
    graph.apply_operations(&seq5).unwrap();

    let seq100 = vec![entry(
        100,
        ModuleIdentifier::PassiveRecon,
        GraphOperation::AddNode {
            node_type: NodeType::Dependency,
            properties: vec![],
        },
    )];
    graph.apply_operations(&seq100).unwrap();

    assert_eq!(graph.node_count().unwrap(), 3);
    assert_eq!(graph.total_operations_applied().unwrap(), 3);
}

// ---------------------------------------------------------------------------
// 27. Concurrent read access
// ---------------------------------------------------------------------------
#[test]
fn graph_concurrent_read_access() {
    let graph = Arc::new(KnowledgeGraph::new());
    populate_graph(&graph);

    let handles: Vec<_> = (0..10)
        .map(|_| {
            let g = Arc::clone(&graph);
            std::thread::spawn(move || {
                let count = g.node_count().unwrap();
                assert_eq!(count, 3);

                let node = g.get_node(0).unwrap().unwrap();
                assert_eq!(node.node_type, NodeType::Endpoint);

                let findings = g.all_findings().unwrap();
                assert_eq!(findings.len(), 1);

                let edges = g.edge_count().unwrap();
                assert_eq!(edges, 2);
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("reader thread should not panic");
    }
}

// ---------------------------------------------------------------------------
// 28. GraphStore trait implementation
// ---------------------------------------------------------------------------
#[test]
fn graph_store_trait_implementation() {
    let mut graph: Box<dyn GraphStore> = Box::new(KnowledgeGraph::new());

    assert_eq!(graph.node_count().unwrap(), 0);
    assert_eq!(graph.total_operations_applied().unwrap(), 0);

    let ops = vec![
        add_node(0, NodeType::Endpoint, vec![("path", "/api/users")]),
        add_node(1, NodeType::Function, vec![("name", "get_users")]),
        add_node(2, NodeType::DataStore, vec![("name", "user_db")]),
    ];
    graph.apply_operations(&ops).unwrap();
    assert_eq!(graph.node_count().unwrap(), 3);
    assert_eq!(graph.total_operations_applied().unwrap(), 3);

    let endpoints = graph.nodes_by_type(NodeType::Endpoint).unwrap();
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0], 0);

    let node = graph.get_node(1).unwrap().unwrap();
    assert_eq!(node.node_type, NodeType::Function);
    assert_eq!(node.properties.get("name").unwrap(), "get_users");

    assert!(graph.get_node(99).unwrap().is_none());

    let finding_ops = vec![add_finding(
        3,
        vec![0],
        VulnerabilityClass::CrossSiteScripting,
        6.5,
        0.85,
    )];
    graph.apply_operations(&finding_ops).unwrap();

    let all = graph.all_findings().unwrap();
    assert_eq!(all.len(), 1);

    let by_class = graph
        .findings_by_class(VulnerabilityClass::CrossSiteScripting)
        .unwrap();
    assert_eq!(by_class.len(), 1);

    let finding = graph.get_finding(0).unwrap().unwrap();
    assert_eq!(
        finding.vulnerability_class,
        VulnerabilityClass::CrossSiteScripting
    );

    let empty = graph
        .findings_by_class(VulnerabilityClass::CommandInjection)
        .unwrap();
    assert!(empty.is_empty());

    let tmpfile = NamedTempFile::new().unwrap();
    graph
        .save_to_file(tmpfile.path(), &test_metadata())
        .unwrap();
    assert!(tmpfile.path().exists());
}

// ---------------------------------------------------------------------------
// 29. Path query: shortest path on a known graph
// ---------------------------------------------------------------------------
#[test]
fn graph_path_query_finds_shortest_path() {
    let graph = KnowledgeGraph::new();

    //   Endpoint(0) --Calls[w=1]--> Function(1) --Reads[w=1]--> DataStore(2)
    //   Endpoint(0) --Reads[w=10]--> DataStore(2)
    let ops = vec![
        add_node(0, NodeType::Endpoint, vec![("path", "/api")]),
        add_node(1, NodeType::Function, vec![("name", "fn1")]),
        add_node(2, NodeType::DataStore, vec![("name", "db")]),
        add_edge(3, 0, 1, EdgeLabel::Calls, 1.0),
        add_edge(4, 1, 2, EdgeLabel::Reads, 1.0),
        add_edge(5, 0, 2, EdgeLabel::Reads, 10.0),
    ];
    graph.apply_operations(&ops).unwrap();

    let result = graph.shortest_path(0, 2).unwrap();
    assert!(result.found);
    assert_eq!(result.path, vec![0, 1, 2]);
    assert!((result.total_weight - 2.0).abs() < f64::EPSILON);
}

// ---------------------------------------------------------------------------
// 30. Path query: paths capped by max_hops
// ---------------------------------------------------------------------------
#[test]
fn graph_path_query_respects_cap() {
    let graph = KnowledgeGraph::new();

    // Chain: Endpoint(0) -> Function(1) -> Function(2) -> Function(3) -> Function(4)
    // Using Function-Calls-Function edges (valid per whitelist)
    let ops = vec![
        add_node(0, NodeType::Endpoint, vec![]),
        add_node(1, NodeType::Function, vec![]),
        add_node(2, NodeType::Function, vec![]),
        add_node(3, NodeType::Function, vec![]),
        add_node(4, NodeType::Function, vec![]),
        add_edge(5, 0, 1, EdgeLabel::Calls, 1.0),
        add_edge(6, 1, 2, EdgeLabel::Calls, 1.0),
        add_edge(7, 2, 3, EdgeLabel::Calls, 1.0),
        add_edge(8, 3, 4, EdgeLabel::Calls, 1.0),
    ];
    graph.apply_operations(&ops).unwrap();

    let too_short = graph.find_paths_between(0, 4, 2).unwrap();
    assert!(
        too_short.paths.is_empty(),
        "max_hops=2 should not reach node 4 which is 4 hops away"
    );

    let just_right = graph.find_paths_between(0, 4, 5).unwrap();
    assert_eq!(just_right.paths.len(), 1);
    assert_eq!(just_right.paths[0], vec![0, 1, 2, 3, 4]);

    let bounded = graph.all_simple_paths_bounded(0, 4, 2).unwrap();
    assert!(bounded.is_empty(), "max_length=2 should not reach node 4");

    let full = graph.all_simple_paths_bounded(0, 4, 5).unwrap();
    assert_eq!(full.len(), 1);
    assert_eq!(full[0], vec![0, 1, 2, 3, 4]);
}

// ---------------------------------------------------------------------------
// 31. Reachability from entry point
// ---------------------------------------------------------------------------
#[test]
fn graph_reachability_from_entry_point() {
    let graph = KnowledgeGraph::new();

    // Endpoint(0) -> Function(1) -> DataStore(2)
    //                Function(1) -> Function(3) (isolated branch)
    // Service(4)  (disconnected)
    let ops = vec![
        add_node(0, NodeType::Endpoint, vec![]),
        add_node(1, NodeType::Function, vec![]),
        add_node(2, NodeType::DataStore, vec![]),
        add_node(3, NodeType::Function, vec![]),
        add_node(4, NodeType::Service, vec![]),
        add_edge(5, 0, 1, EdgeLabel::Calls, 1.0),
        add_edge(6, 1, 2, EdgeLabel::Reads, 1.0),
        add_edge(7, 1, 3, EdgeLabel::Calls, 1.0),
    ];
    graph.apply_operations(&ops).unwrap();

    let reachable = graph.reachable_from(0, &[]).unwrap();
    assert!(reachable.contains(&0), "start node should be reachable");
    assert!(reachable.contains(&1));
    assert!(reachable.contains(&2));
    assert!(reachable.contains(&3));
    assert!(
        !reachable.contains(&4),
        "disconnected node should not be reachable"
    );

    let calls_only = graph.reachable_from(0, &[EdgeLabel::Calls]).unwrap();
    assert!(calls_only.contains(&0));
    assert!(calls_only.contains(&1));
    assert!(!calls_only.contains(&2), "node 2 is via Reads, not Calls");
    assert!(calls_only.contains(&3));

    let from_nowhere = graph.reachable_from(999, &[]).unwrap();
    assert!(
        from_nowhere.is_empty(),
        "non-existent start returns empty set"
    );
}
