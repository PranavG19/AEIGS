#[cfg(test)]
mod tests {
    use crate::graph::KnowledgeGraph;
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
            make_entry(0, ModuleIdentifier::Enumeration, GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![("path".into(), "/api/login".into())],
            }),
            make_entry(1, ModuleIdentifier::Enumeration, GraphOperation::AddNode {
                node_type: NodeType::Function,
                properties: vec![("name".into(), "authenticate".into())],
            }),
            make_entry(2, ModuleIdentifier::Enumeration, GraphOperation::AddNode {
                node_type: NodeType::DataStore,
                properties: vec![("name".into(), "users_db".into())],
            }),
            make_entry(3, ModuleIdentifier::Enumeration, GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![("path".into(), "/api/admin".into())],
            }),
            make_entry(4, ModuleIdentifier::Enumeration, GraphOperation::AddEdge {
                source_node_id: 0,
                target_node_id: 1,
                label: EdgeLabel::Calls,
                weight: 1.0,
            }),
            make_entry(5, ModuleIdentifier::Enumeration, GraphOperation::AddEdge {
                source_node_id: 1,
                target_node_id: 2,
                label: EdgeLabel::Writes,
                weight: 0.5,
            }),
            make_entry(6, ModuleIdentifier::Enumeration, GraphOperation::AddEdge {
                source_node_id: 3,
                target_node_id: 1,
                label: EdgeLabel::Calls,
                weight: 1.0,
            }),
            make_entry(7, ModuleIdentifier::Enumeration, GraphOperation::AddFinding {
                linked_node_ids: vec![0, 1],
                vulnerability_class: VulnerabilityClass::SqlInjection,
                severity: 9.5,
                confidence: 0.95,
                certificate: b"SELECT * FROM users WHERE id = '1' OR '1'='1'".to_vec(),
            }),
        ];

        graph.apply_operations(&entries).unwrap();
        graph
    }

    #[test]
    fn end_to_end_build_and_query_graph() {
        let graph = build_small_attack_graph();

        assert_eq!(graph.node_count(), 4);
        assert_eq!(graph.edge_count(), 3);
        assert_eq!(graph.finding_count(), 1);
    }

    #[test]
    fn query_paths_through_graph() {
        let graph = build_small_attack_graph();

        let result = graph.find_paths_between(0, 2, 5);
        assert_eq!(result.paths.len(), 1);
        assert_eq!(result.paths[0], vec![0, 1, 2]);
    }

    #[test]
    fn shortest_path_through_graph() {
        let graph = build_small_attack_graph();

        let result = graph.shortest_path(0, 2);
        assert!(result.found);
        assert_eq!(result.path, vec![0, 1, 2]);
        assert!((result.total_weight - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn query_findings_by_class() {
        let graph = build_small_attack_graph();

        let sqli_findings = graph.findings_by_class(VulnerabilityClass::SqlInjection);
        assert_eq!(sqli_findings.len(), 1);

        let xss_findings = graph.findings_by_class(VulnerabilityClass::CrossSiteScripting);
        assert!(xss_findings.is_empty());
    }

    #[test]
    fn query_findings_for_node() {
        let graph = build_small_attack_graph();

        let findings_for_0 = graph.findings_for_node(0);
        assert_eq!(findings_for_0.len(), 1);

        let findings_for_2 = graph.findings_for_node(2);
        assert!(findings_for_2.is_empty());
    }

    #[test]
    fn get_node_returns_properties() {
        let graph = build_small_attack_graph();

        let node = graph.get_node(0).unwrap();
        assert_eq!(node.node_type, NodeType::Endpoint);
        assert_eq!(node.properties.get("path").unwrap(), "/api/login");
    }

    #[test]
    fn get_finding_returns_certificate() {
        let graph = build_small_attack_graph();

        let finding = graph.get_finding(0).unwrap();
        assert_eq!(finding.vulnerability_class, VulnerabilityClass::SqlInjection);
        assert!(!finding.certificate.is_empty());
    }

    #[test]
    fn reachable_from_endpoint() {
        let graph = build_small_attack_graph();

        let reachable = graph.reachable_from(0, &[]);
        assert!(reachable.contains(&0));
        assert!(reachable.contains(&1));
        assert!(reachable.contains(&2));
        assert!(!reachable.contains(&3));
    }

    #[test]
    fn nodes_by_type_query() {
        let graph = build_small_attack_graph();

        let endpoints = graph.nodes_by_type(NodeType::Endpoint);
        assert_eq!(endpoints.len(), 2);
    }

    #[test]
    fn sequence_tracking() {
        let graph = build_small_attack_graph();

        assert_eq!(graph.current_sequence(ModuleIdentifier::Enumeration), 8);
        assert_eq!(graph.total_operations_applied(), 8);
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
                    node_type: NodeType::Dependency,
                    properties: vec![("name".into(), format!("pkg-{i}"))],
                },
            ));
        }

        graph.apply_operations(&entries).unwrap();
        assert_eq!(graph.node_count(), 1000);

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
        assert_eq!(graph.edge_count(), 999);

        let result = graph.shortest_path(0, 999);
        assert!(result.found);
        assert_eq!(result.path.len(), 1000);
    }

    #[test]
    fn default_creates_empty_graph() {
        let graph = KnowledgeGraph::default();
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
        assert_eq!(graph.finding_count(), 0);
    }
}
