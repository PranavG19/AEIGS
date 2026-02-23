#[cfg(test)]
mod tests {
    use crate::graph::{GraphMetadata, KnowledgeGraph};
    use aegis_protocol::edge::EdgeLabel;
    use aegis_protocol::finding::VulnerabilityClass;
    use aegis_protocol::node::NodeType;
    use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};
    use std::sync::Arc;
    use std::thread;

    fn make_entry(seq: u64, module: ModuleIdentifier, op: GraphOperation) -> OperationLogEntry {
        OperationLogEntry {
            sequence_number: seq,
            module,
            operation: op,
            timestamp_unix_ms: 1700000000000 + seq,
        }
    }

    fn build_small_attack_graph() -> KnowledgeGraph {
        let graph = KnowledgeGraph::new();
        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![("path".into(), "/api/login".into())],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![("name".into(), "authenticate".into())],
                },
            ),
            make_entry(
                2,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::DataStore,
                    properties: vec![("name".into(), "users_db".into())],
                },
            ),
            make_entry(
                3,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![("path".into(), "/api/admin".into())],
                },
            ),
            make_entry(
                4,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddEdge {
                    source_node_id: 0,
                    target_node_id: 1,
                    label: EdgeLabel::Calls,
                    weight: 1.0,
                },
            ),
            make_entry(
                5,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddEdge {
                    source_node_id: 1,
                    target_node_id: 2,
                    label: EdgeLabel::Writes,
                    weight: 0.5,
                },
            ),
            make_entry(
                6,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddEdge {
                    source_node_id: 3,
                    target_node_id: 1,
                    label: EdgeLabel::Calls,
                    weight: 1.0,
                },
            ),
            make_entry(
                7,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddFinding {
                    linked_node_ids: vec![0, 1],
                    vulnerability_class: VulnerabilityClass::SqlInjection,
                    severity: 9.5,
                    confidence: aegis_protocol::finding::Confidence::new(0.95).unwrap(),
                    certificate: b"SELECT * FROM users WHERE id = '1' OR '1'='1'".to_vec(),
                },
            ),
        ];

        graph.apply_operations(&entries).unwrap();
        graph
    }

    #[test]
    fn end_to_end_build_and_query_graph() {
        let graph = build_small_attack_graph();

        assert_eq!(graph.node_count().unwrap(), 4);
        assert_eq!(graph.edge_count().unwrap(), 3);
        assert_eq!(graph.finding_count().unwrap(), 1);
    }

    #[test]
    fn query_paths_through_graph() {
        let graph = build_small_attack_graph();

        let result = graph.find_paths_between(0, 2, 5).unwrap();
        assert_eq!(result.paths.len(), 1);
        assert_eq!(result.paths[0], vec![0, 1, 2]);
    }

    #[test]
    fn shortest_path_through_graph() {
        let graph = build_small_attack_graph();

        let result = graph.shortest_path(0, 2).unwrap();
        assert!(result.found);
        assert_eq!(result.path, vec![0, 1, 2]);
        assert!((result.total_weight - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn query_findings_by_class() {
        let graph = build_small_attack_graph();

        let sqli_findings = graph
            .findings_by_class(VulnerabilityClass::SqlInjection)
            .unwrap();
        assert_eq!(sqli_findings.len(), 1);

        let xss_findings = graph
            .findings_by_class(VulnerabilityClass::CrossSiteScripting)
            .unwrap();
        assert!(xss_findings.is_empty());
    }

    #[test]
    fn query_findings_for_node() {
        let graph = build_small_attack_graph();

        let findings_for_0 = graph.findings_for_node(0).unwrap();
        assert_eq!(findings_for_0.len(), 1);

        let findings_for_2 = graph.findings_for_node(2).unwrap();
        assert!(findings_for_2.is_empty());
    }

    #[test]
    fn get_node_returns_properties() {
        let graph = build_small_attack_graph();

        let node = graph.get_node(0).unwrap().unwrap();
        assert_eq!(node.node_type, NodeType::Endpoint);
        assert_eq!(node.properties.get("path").unwrap(), "/api/login");
    }

    #[test]
    fn get_finding_returns_certificate() {
        let graph = build_small_attack_graph();

        let finding = graph.get_finding(0).unwrap().unwrap();
        assert_eq!(
            finding.vulnerability_class,
            VulnerabilityClass::SqlInjection
        );
        assert!(!finding.certificate.is_empty());
    }

    #[test]
    fn reachable_from_endpoint() {
        let graph = build_small_attack_graph();

        let reachable = graph.reachable_from(0, &[]).unwrap();
        assert!(reachable.contains(&0));
        assert!(reachable.contains(&1));
        assert!(reachable.contains(&2));
        assert!(!reachable.contains(&3));
    }

    #[test]
    fn nodes_by_type_query() {
        let graph = build_small_attack_graph();

        let endpoints = graph.nodes_by_type(NodeType::Endpoint).unwrap();
        assert_eq!(endpoints.len(), 2);
    }

    #[test]
    fn sequence_tracking() {
        let graph = build_small_attack_graph();

        assert_eq!(
            graph
                .current_sequence(ModuleIdentifier::Enumeration)
                .unwrap(),
            8
        );
        assert_eq!(graph.total_operations_applied().unwrap(), 8);
    }

    #[test]
    fn concurrent_readers_do_not_block() {
        let graph = Arc::new(build_small_attack_graph());

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let graph = Arc::clone(&graph);
                thread::spawn(move || {
                    for _ in 0..100 {
                        let _ = graph.node_count();
                        let _ = graph.find_paths_between(0, 2, 5);
                        let _ = graph.findings_by_class(VulnerabilityClass::SqlInjection);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn scale_test_thousand_nodes() {
        let graph = KnowledgeGraph::new();

        let mut entries = Vec::new();
        for i in 0..1000u64 {
            entries.push(make_entry(
                i,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Service,
                    properties: vec![("name".into(), format!("svc-{i}"))],
                },
            ));
        }

        graph.apply_operations(&entries).unwrap();
        assert_eq!(graph.node_count().unwrap(), 1000);

        let mut edge_entries = Vec::new();
        for i in 0..999u64 {
            edge_entries.push(make_entry(
                i,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddEdge {
                    source_node_id: i,
                    target_node_id: i + 1,
                    label: EdgeLabel::DependsOn,
                    weight: 1.0,
                },
            ));
        }

        graph.apply_operations(&edge_entries).unwrap();
        assert_eq!(graph.edge_count().unwrap(), 999);

        let result = graph.shortest_path(0, 999).unwrap();
        assert!(result.found);
        assert_eq!(result.path.len(), 1000);
    }

    #[test]
    fn default_creates_empty_graph() {
        let graph = KnowledgeGraph::default();
        assert_eq!(graph.node_count().unwrap(), 0);
        assert_eq!(graph.edge_count().unwrap(), 0);
        assert_eq!(graph.finding_count().unwrap(), 0);
    }

    #[test]
    fn all_simple_paths_bounded_through_facade() {
        let graph = build_small_attack_graph();
        let paths = graph.all_simple_paths_bounded(0, 2, 5).unwrap();

        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vec![0, 1, 2]);
    }

    #[test]
    fn cut_vertices_through_facade() {
        let graph = build_small_attack_graph();
        let cuts = graph.cut_vertices().unwrap();

        assert!(cuts.contains(&1));
    }

    #[test]
    fn betweenness_centrality_through_facade() {
        let graph = build_small_attack_graph();
        let centrality = graph.betweenness_centrality().unwrap();

        assert!(centrality.contains_key(&1));
    }

    #[test]
    fn batch_with_dangling_edge_mid_batch_is_rejected_entirely() {
        let graph = KnowledgeGraph::new();
        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![("path".into(), "/api/a".into())],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddEdge {
                    source_node_id: 0,
                    target_node_id: 99,
                    label: EdgeLabel::Calls,
                    weight: 1.0,
                },
            ),
            make_entry(
                2,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![("name".into(), "handler".into())],
                },
            ),
        ];

        let result = graph.apply_operations(&entries);
        assert!(result.is_err());
        assert_eq!(graph.node_count().unwrap(), 0);
        assert_eq!(graph.edge_count().unwrap(), 0);
    }

    #[test]
    fn intra_batch_add_node_then_add_edge_succeeds() {
        let graph = KnowledgeGraph::new();
        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![("path".into(), "/api/a".into())],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![("name".into(), "handler".into())],
                },
            ),
            make_entry(
                2,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddEdge {
                    source_node_id: 0,
                    target_node_id: 1,
                    label: EdgeLabel::Calls,
                    weight: 1.0,
                },
            ),
        ];

        let applied = graph.apply_operations(&entries).unwrap();
        assert_eq!(applied, 3);
        assert_eq!(graph.node_count().unwrap(), 2);
        assert_eq!(graph.edge_count().unwrap(), 1);
    }

    #[test]
    fn graph_error_wraps_validation_error_with_display_and_source() {
        use crate::graph::GraphError;
        use crate::operation_log::ValidationError;
        use std::error::Error;

        let graph = KnowledgeGraph::new();
        let entries = vec![make_entry(
            0,
            ModuleIdentifier::Enumeration,
            GraphOperation::AddEdge {
                source_node_id: 42,
                target_node_id: 43,
                label: EdgeLabel::Calls,
                weight: 1.0,
            },
        )];

        let err = graph.apply_operations(&entries).unwrap_err();
        assert!(matches!(
            err,
            GraphError::Validation(ValidationError::DanglingEdgeSource(42))
        ));

        let display = format!("{err}");
        assert!(display.contains("batch validation failed"));
        assert!(display.contains("42"));

        let source = err.source().unwrap();
        let downcast = source.downcast_ref::<ValidationError>().unwrap();
        assert!(matches!(downcast, ValidationError::DanglingEdgeSource(42)));
    }

    #[test]
    fn graph_error_wraps_operation_log_error_with_display_and_source() {
        use crate::graph::GraphError;
        use crate::operation_log::OperationLogError;
        use std::error::Error;

        let graph = KnowledgeGraph::new();

        graph
            .apply_operations(&[make_entry(
                0,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            )])
            .unwrap();

        let entries = vec![make_entry(
            0,
            ModuleIdentifier::Enumeration,
            GraphOperation::AddNode {
                node_type: NodeType::Function,
                properties: vec![],
            },
        )];

        let err = graph.apply_operations(&entries).unwrap_err();
        assert!(matches!(
            err,
            GraphError::OperationLog(OperationLogError::SequenceOutOfOrder { .. })
        ));

        let display = format!("{err}");
        assert!(display.contains("operation log error"));
        assert!(display.contains("sequence out of order"));

        let source = err.source().unwrap();
        assert!(source.downcast_ref::<OperationLogError>().is_some());
    }

    #[test]
    fn semantically_invalid_edge_is_rejected() {
        use crate::graph::GraphError;
        use crate::operation_log::ValidationError;

        let graph = KnowledgeGraph::new();
        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::DataStore,
                    properties: vec![],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![],
                },
            ),
            make_entry(
                2,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddEdge {
                    source_node_id: 0,
                    target_node_id: 1,
                    label: EdgeLabel::Calls,
                    weight: 1.0,
                },
            ),
        ];

        let err = graph.apply_operations(&entries).unwrap_err();
        assert!(matches!(
            err,
            GraphError::Validation(ValidationError::InvalidEdgeSemantics {
                source_type: NodeType::DataStore,
                label: EdgeLabel::Calls,
                target_type: NodeType::Function,
            })
        ));
    }

    #[test]
    fn edge_with_nan_weight_is_rejected() {
        use crate::graph::GraphError;
        use crate::operation_log::ValidationError;

        let graph = KnowledgeGraph::new();
        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![],
                },
            ),
            make_entry(
                2,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddEdge {
                    source_node_id: 0,
                    target_node_id: 1,
                    label: EdgeLabel::Calls,
                    weight: f64::NAN,
                },
            ),
        ];

        let err = graph.apply_operations(&entries).unwrap_err();
        assert!(matches!(
            err,
            GraphError::Validation(ValidationError::InvalidWeight(_))
        ));
    }

    #[test]
    fn edge_with_negative_weight_is_rejected() {
        use crate::graph::GraphError;
        use crate::operation_log::ValidationError;

        let graph = KnowledgeGraph::new();
        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![],
                },
            ),
            make_entry(
                2,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddEdge {
                    source_node_id: 0,
                    target_node_id: 1,
                    label: EdgeLabel::Calls,
                    weight: -0.5,
                },
            ),
        ];

        let err = graph.apply_operations(&entries).unwrap_err();
        assert!(matches!(
            err,
            GraphError::Validation(ValidationError::InvalidWeight(_))
        ));
    }

    #[test]
    fn finding_with_severity_above_ten_is_rejected() {
        use crate::graph::GraphError;
        use crate::operation_log::ValidationError;

        let graph = KnowledgeGraph::new();
        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddFinding {
                    linked_node_ids: vec![0],
                    vulnerability_class: VulnerabilityClass::SqlInjection,
                    severity: 10.1,
                    confidence: aegis_protocol::finding::Confidence::new(0.9).unwrap(),
                    certificate: vec![],
                },
            ),
        ];

        let err = graph.apply_operations(&entries).unwrap_err();
        assert!(matches!(
            err,
            GraphError::Validation(ValidationError::InvalidSeverity(_))
        ));
    }

    #[test]
    fn finding_with_invalid_severity_is_rejected() {
        use crate::graph::GraphError;
        use crate::operation_log::ValidationError;

        let graph = KnowledgeGraph::new();
        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddFinding {
                    linked_node_ids: vec![0],
                    vulnerability_class: VulnerabilityClass::CrossSiteScripting,
                    severity: 12.0,
                    confidence: aegis_protocol::finding::Confidence::new(0.9).unwrap(),
                    certificate: vec![],
                },
            ),
        ];

        let err = graph.apply_operations(&entries).unwrap_err();
        assert!(matches!(
            err,
            GraphError::Validation(ValidationError::InvalidSeverity(_))
        ));
    }

    #[test]
    fn valid_semantic_operations_still_succeed() {
        let graph = KnowledgeGraph::new();
        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![("path".into(), "/api/test".into())],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![("name".into(), "handler".into())],
                },
            ),
            make_entry(
                2,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::DataStore,
                    properties: vec![("name".into(), "db".into())],
                },
            ),
            make_entry(
                3,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddEdge {
                    source_node_id: 0,
                    target_node_id: 1,
                    label: EdgeLabel::Calls,
                    weight: 1.0,
                },
            ),
            make_entry(
                4,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddEdge {
                    source_node_id: 1,
                    target_node_id: 2,
                    label: EdgeLabel::Writes,
                    weight: 0.5,
                },
            ),
            make_entry(
                5,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddFinding {
                    linked_node_ids: vec![0],
                    vulnerability_class: VulnerabilityClass::SqlInjection,
                    severity: 9.0,
                    confidence: aegis_protocol::finding::Confidence::new(0.95).unwrap(),
                    certificate: b"proof".to_vec(),
                },
            ),
        ];

        let applied = graph.apply_operations(&entries).unwrap();
        assert_eq!(applied, 6);
        assert_eq!(graph.node_count().unwrap(), 3);
        assert_eq!(graph.edge_count().unwrap(), 2);
        assert_eq!(graph.finding_count().unwrap(), 1);
    }

    #[test]
    fn duplicate_edge_in_batch_is_rejected() {
        use crate::graph::GraphError;
        use crate::operation_log::ValidationError;

        let graph = build_small_attack_graph();

        let entries = vec![make_entry(
            8,
            ModuleIdentifier::Enumeration,
            GraphOperation::AddEdge {
                source_node_id: 0,
                target_node_id: 1,
                label: EdgeLabel::Calls,
                weight: 2.0,
            },
        )];

        let err = graph.apply_operations(&entries).unwrap_err();
        assert!(matches!(
            err,
            GraphError::Validation(ValidationError::DuplicateEdge {
                source: 0,
                target: 1,
                label: EdgeLabel::Calls,
            })
        ));

        assert_eq!(graph.edge_count().unwrap(), 3);
    }

    #[test]
    fn validation_failure_leaves_graph_completely_unchanged() {
        let graph = build_small_attack_graph();

        let node_count_before = graph.node_count().unwrap();
        let edge_count_before = graph.edge_count().unwrap();
        let finding_count_before = graph.finding_count().unwrap();
        let ops_before = graph.total_operations_applied().unwrap();

        let bad_entries = vec![
            make_entry(
                8,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![("path".into(), "/api/new".into())],
                },
            ),
            make_entry(
                9,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddEdge {
                    source_node_id: 4,
                    target_node_id: 500,
                    label: EdgeLabel::Calls,
                    weight: 1.0,
                },
            ),
        ];

        let result = graph.apply_operations(&bad_entries);
        assert!(result.is_err());

        assert_eq!(graph.node_count().unwrap(), node_count_before);
        assert_eq!(graph.edge_count().unwrap(), edge_count_before);
        assert_eq!(graph.finding_count().unwrap(), finding_count_before);
        assert_eq!(graph.total_operations_applied().unwrap(), ops_before);
    }

    fn test_metadata() -> GraphMetadata {
        GraphMetadata {
            scan_timestamp_unix_ms: 1700000000000,
            target_url: "http://127.0.0.1:8080".into(),
            aegis_version: "0.1.0".into(),
            scan_count: 0,
        }
    }

    #[test]
    fn save_load_roundtrip_preserves_counts() {
        let graph = build_small_attack_graph();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("graph.json");

        graph.save_to_file(&path, &test_metadata()).unwrap();

        let (loaded, meta) = KnowledgeGraph::load_from_file(&path).unwrap();
        assert!(meta.is_some());
        assert_eq!(loaded.node_count().unwrap(), graph.node_count().unwrap());
        assert_eq!(loaded.edge_count().unwrap(), graph.edge_count().unwrap());
        assert_eq!(
            loaded.finding_count().unwrap(),
            graph.finding_count().unwrap()
        );
    }

    #[test]
    fn load_from_nonexistent_file_returns_error() {
        let result = KnowledgeGraph::load_from_file(std::path::Path::new(
            "/tmp/does_not_exist_aegis_test.json",
        ));
        assert!(result.is_err());
    }

    #[test]
    fn load_from_corrupted_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, b"not valid json{{{").unwrap();

        let result = KnowledgeGraph::load_from_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn load_from_file_returns_metadata_with_scan_count() {
        let graph = build_small_attack_graph();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("graph_with_count.json");
        let meta = GraphMetadata {
            scan_timestamp_unix_ms: 1700000000000,
            target_url: "http://127.0.0.1:8080".into(),
            aegis_version: "0.1.0".into(),
            scan_count: 3,
        };
        graph.save_to_file(&path, &meta).unwrap();

        let (_, loaded_meta) = KnowledgeGraph::load_from_file(&path).unwrap();
        let loaded_meta = loaded_meta.unwrap();
        assert_eq!(loaded_meta.scan_count, 3);
        assert_eq!(loaded_meta.target_url, "http://127.0.0.1:8080");
    }

    #[test]
    fn load_from_file_old_format_without_scan_count_defaults_to_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old_format.json");
        // Build a minimal valid graph file without scan_count in metadata.
        // The node/edge/finding store fields match their actual Serde field names.
        let graph = KnowledgeGraph::new();
        let meta_with_count = GraphMetadata {
            scan_timestamp_unix_ms: 1700000000000,
            target_url: "http://127.0.0.1:8080".into(),
            aegis_version: "0.1.0".into(),
            scan_count: 0,
        };
        graph.save_to_file(&path, &meta_with_count).unwrap();

        // Patch the file to remove scan_count from metadata.
        let raw = std::fs::read_to_string(&path).unwrap();
        let patched = raw.replace(r#","scan_count":0"#, "");
        std::fs::write(&path, patched).unwrap();

        let (_, meta) = KnowledgeGraph::load_from_file(&path).unwrap();
        let meta = meta.unwrap();
        assert_eq!(meta.scan_count, 0);
    }

    #[test]
    fn concurrent_apply_operations_no_data_loss() {
        let graph = Arc::new(KnowledgeGraph::new());
        let threads_count = 10;
        let ops_per_thread = 100;

        let handles: Vec<_> = (0..threads_count)
            .map(|t| {
                let g = Arc::clone(&graph);
                thread::spawn(move || {
                    let mut applied = 0u64;
                    for i in 0..ops_per_thread {
                        let seq = (t * ops_per_thread + i) as u64;
                        let entries = vec![make_entry(
                            seq,
                            ModuleIdentifier::Enumeration,
                            GraphOperation::AddNode {
                                node_type: NodeType::Endpoint,
                                properties: vec![("path".into(), format!("/t{t}/e{i}"))],
                            },
                        )];
                        if g.apply_operations(&entries).is_ok() {
                            applied += 1;
                        }
                    }
                    applied
                })
            })
            .collect();

        let total_applied: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        let node_count = graph.nodes_by_type(NodeType::Endpoint).unwrap().len() as u64;
        assert_eq!(
            node_count, total_applied,
            "every successfully applied operation should produce a node"
        );
        assert!(total_applied > 0, "at least some operations should succeed");
    }

    #[test]
    fn concurrent_read_during_write() {
        let graph = Arc::new(KnowledgeGraph::new());

        let entries = vec![make_entry(
            0,
            ModuleIdentifier::Enumeration,
            GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![("path".into(), "/seed".into())],
            },
        )];
        graph.apply_operations(&entries).unwrap();

        let writer = {
            let g = Arc::clone(&graph);
            thread::spawn(move || {
                for i in 1..=500 {
                    let entries = vec![make_entry(
                        i,
                        ModuleIdentifier::Enumeration,
                        GraphOperation::AddNode {
                            node_type: NodeType::Endpoint,
                            properties: vec![("path".into(), format!("/w{i}"))],
                        },
                    )];
                    let _ = g.apply_operations(&entries);
                }
            })
        };

        let reader = {
            let g = Arc::clone(&graph);
            thread::spawn(move || {
                let mut read_count = 0u64;
                for _ in 0..500 {
                    let nodes = g.nodes_by_type(NodeType::Endpoint).unwrap();
                    assert!(
                        !nodes.is_empty(),
                        "reader should always see at least the seed node"
                    );
                    read_count += 1;
                }
                read_count
            })
        };

        writer.join().unwrap();
        let reads = reader.join().unwrap();
        assert_eq!(reads, 500, "all 500 reads should complete without deadlock");
    }
}
