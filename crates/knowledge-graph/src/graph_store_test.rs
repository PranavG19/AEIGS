#[cfg(test)]
mod tests {
    use crate::GraphStore;
    use crate::graph::KnowledgeGraph;
    use aegis_protocol::edge::EdgeLabel;
    use aegis_protocol::finding::VulnerabilityClass;
    use aegis_protocol::node::NodeType;
    use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

    fn make_entry(seq: u64, module: ModuleIdentifier, op: GraphOperation) -> OperationLogEntry {
        OperationLogEntry {
            sequence_number: seq,
            module,
            operation: op,
            timestamp_unix_ms: 1700000000000 + seq,
        }
    }

    fn boxed_empty_graph() -> Box<dyn GraphStore> {
        Box::new(KnowledgeGraph::new())
    }

    #[test]
    fn apply_operations_adds_nodes_via_trait() {
        let mut graph: Box<dyn GraphStore> = boxed_empty_graph();
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
        ];
        graph.apply_operations(&entries).unwrap();
        assert_eq!(graph.node_count().unwrap(), 2);
    }

    #[test]
    fn node_count_empty_graph_returns_zero() {
        let graph: Box<dyn GraphStore> = boxed_empty_graph();
        assert_eq!(graph.node_count().unwrap(), 0);
    }

    #[test]
    fn nodes_by_type_filters_correctly() {
        let mut graph: Box<dyn GraphStore> = boxed_empty_graph();
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
                    node_type: NodeType::Endpoint,
                    properties: vec![("path".into(), "/api/b".into())],
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
        ];
        graph.apply_operations(&entries).unwrap();

        let endpoints = graph.nodes_by_type(NodeType::Endpoint).unwrap();
        assert_eq!(endpoints.len(), 2);

        let datastores = graph.nodes_by_type(NodeType::DataStore).unwrap();
        assert_eq!(datastores.len(), 1);

        let services = graph.nodes_by_type(NodeType::Service).unwrap();
        assert!(services.is_empty());
    }

    #[test]
    fn get_node_returns_correct_data() {
        let mut graph: Box<dyn GraphStore> = boxed_empty_graph();
        let entries = vec![make_entry(
            0,
            ModuleIdentifier::Enumeration,
            GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![("path".into(), "/api/login".into())],
            },
        )];
        graph.apply_operations(&entries).unwrap();

        let node = graph.get_node(0).unwrap().unwrap();
        assert_eq!(node.node_type, NodeType::Endpoint);
        assert_eq!(node.properties.get("path").unwrap(), "/api/login");
    }

    #[test]
    fn get_node_missing_id_returns_none() {
        let graph: Box<dyn GraphStore> = boxed_empty_graph();
        assert!(graph.get_node(99).unwrap().is_none());
    }

    #[test]
    fn total_operations_applied_tracks_count() {
        let mut graph: Box<dyn GraphStore> = boxed_empty_graph();
        assert_eq!(graph.total_operations_applied().unwrap(), 0);

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
        ];
        graph.apply_operations(&entries).unwrap();
        assert_eq!(graph.total_operations_applied().unwrap(), 2);
    }

    #[test]
    fn all_findings_returns_added_findings() {
        let mut graph: Box<dyn GraphStore> = boxed_empty_graph();
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
                GraphOperation::AddFinding {
                    linked_node_ids: vec![0],
                    vulnerability_class: VulnerabilityClass::SqlInjection,
                    severity: 8.5,
                    confidence: 0.9,
                    certificate: b"proof".to_vec(),
                },
            ),
        ];
        graph.apply_operations(&entries).unwrap();

        let findings = graph.all_findings().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].vulnerability_class,
            VulnerabilityClass::SqlInjection
        );
    }

    #[test]
    fn findings_by_class_filters_by_vulnerability_class() {
        let mut graph: Box<dyn GraphStore> = boxed_empty_graph();
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
                    severity: 9.0,
                    confidence: 0.95,
                    certificate: vec![],
                },
            ),
            make_entry(
                2,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddFinding {
                    linked_node_ids: vec![0],
                    vulnerability_class: VulnerabilityClass::CrossSiteScripting,
                    severity: 6.0,
                    confidence: 0.8,
                    certificate: vec![],
                },
            ),
        ];
        graph.apply_operations(&entries).unwrap();

        let sqli = graph
            .findings_by_class(VulnerabilityClass::SqlInjection)
            .unwrap();
        assert_eq!(sqli.len(), 1);

        let xss = graph
            .findings_by_class(VulnerabilityClass::CrossSiteScripting)
            .unwrap();
        assert_eq!(xss.len(), 1);

        let ssrf = graph
            .findings_by_class(VulnerabilityClass::ServerSideRequestForgery)
            .unwrap();
        assert!(ssrf.is_empty());
    }

    #[test]
    fn get_finding_returns_correct_data_and_missing_returns_none() {
        let mut graph: Box<dyn GraphStore> = boxed_empty_graph();

        assert!(graph.get_finding(0).unwrap().is_none());

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
                    vulnerability_class: VulnerabilityClass::BrokenAuthorization,
                    severity: 7.0,
                    confidence: 0.75,
                    certificate: b"idor-cert".to_vec(),
                },
            ),
        ];
        graph.apply_operations(&entries).unwrap();

        let finding = graph.get_finding(0).unwrap().unwrap();
        assert_eq!(
            finding.vulnerability_class,
            VulnerabilityClass::BrokenAuthorization
        );
        assert!((finding.severity - 7.0).abs() < f64::EPSILON);

        assert!(graph.get_finding(99).unwrap().is_none());
    }

    #[test]
    fn all_findings_empty_graph_returns_empty_vec() {
        let graph: Box<dyn GraphStore> = boxed_empty_graph();
        assert!(graph.all_findings().unwrap().is_empty());
    }

    #[test]
    fn apply_operations_empty_slice_is_no_op() {
        let mut graph: Box<dyn GraphStore> = boxed_empty_graph();
        graph.apply_operations(&[]).unwrap();
        assert_eq!(graph.node_count().unwrap(), 0);
        assert_eq!(graph.total_operations_applied().unwrap(), 0);
    }

    #[test]
    fn apply_operations_failed_batch_leaves_graph_unchanged() {
        let mut graph: Box<dyn GraphStore> = boxed_empty_graph();

        let valid_entries = vec![make_entry(
            0,
            ModuleIdentifier::Enumeration,
            GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![],
            },
        )];
        graph.apply_operations(&valid_entries).unwrap();
        assert_eq!(graph.node_count().unwrap(), 1);

        let bad_entries = vec![make_entry(
            1,
            ModuleIdentifier::Enumeration,
            GraphOperation::AddEdge {
                source_node_id: 0,
                target_node_id: 999,
                label: EdgeLabel::Calls,
                weight: 1.0,
            },
        )];
        let result = graph.apply_operations(&bad_entries);
        assert!(result.is_err());
        assert_eq!(graph.node_count().unwrap(), 1);
    }
}
