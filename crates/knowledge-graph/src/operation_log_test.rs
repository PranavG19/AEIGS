#[cfg(test)]
mod tests {
    use crate::edge_store::EdgeStore;
    use crate::finding_store::FindingStore;
    use crate::node_store::NodeStore;
    use crate::operation_log::{OperationLog, OperationLogError, ValidationError};
    use aegis_protocol::edge::EdgeLabel;
    use aegis_protocol::finding::VulnerabilityClass;
    use aegis_protocol::node::NodeType;
    use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

    fn make_stores() -> (NodeStore, EdgeStore, FindingStore) {
        (NodeStore::new(), EdgeStore::new(), FindingStore::new())
    }

    fn make_entry(seq: u64, module: ModuleIdentifier, op: GraphOperation) -> OperationLogEntry {
        OperationLogEntry {
            sequence_number: seq,
            module,
            operation: op,
            timestamp_unix_ms: 1700000000000 + seq,
        }
    }

    #[test]
    fn apply_add_node_creates_node_in_store() {
        let mut log = OperationLog::new();
        let (mut nodes, mut edges, mut findings) = make_stores();

        let entry = make_entry(
            0,
            ModuleIdentifier::PassiveRecon,
            GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![("path".into(), "/api/users".into())],
            },
        );

        let applied = log
            .apply_batch(&[entry], &mut nodes, &mut edges, &mut findings)
            .unwrap();
        assert_eq!(applied, 1);
        assert_eq!(nodes.count(), 1);

        let node = nodes.get(0).unwrap();
        assert_eq!(node.node_type, NodeType::Endpoint);
        assert_eq!(node.properties.get("path").unwrap(), "/api/users");
    }

    #[test]
    fn apply_add_edge_creates_edge_with_adjacency() {
        let mut log = OperationLog::new();
        let (mut nodes, mut edges, mut findings) = make_stores();

        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![],
                },
            ),
            make_entry(
                2,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddEdge {
                    source_node_id: 0,
                    target_node_id: 1,
                    label: EdgeLabel::Calls,
                    weight: 1.0,
                },
            ),
        ];

        log.apply_batch(&entries, &mut nodes, &mut edges, &mut findings)
            .unwrap();
        assert_eq!(edges.count(), 1);

        let outgoing = edges.outgoing_edges(0);
        assert_eq!(outgoing.len(), 1);

        let edge = edges.get(outgoing[0]).unwrap();
        assert_eq!(edge.source_node_id, 0);
        assert_eq!(edge.target_node_id, 1);
        assert_eq!(edge.label, EdgeLabel::Calls);
    }

    #[test]
    fn apply_add_finding_creates_finding() {
        let mut log = OperationLog::new();
        let (mut nodes, mut edges, mut findings) = make_stores();

        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::Fuzzing,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::Fuzzing,
                GraphOperation::AddFinding {
                    linked_node_ids: vec![0],
                    vulnerability_class: VulnerabilityClass::SqlInjection,
                    severity: 9.0,
                    confidence: 0.95,
                    certificate: b"proof".to_vec(),
                },
            ),
        ];

        log.apply_batch(&entries, &mut nodes, &mut edges, &mut findings)
            .unwrap();
        assert_eq!(findings.count(), 1);

        let finding = findings.get(0).unwrap();
        assert_eq!(
            finding.vulnerability_class,
            VulnerabilityClass::SqlInjection
        );
        assert!((finding.severity - 9.0).abs() < f64::EPSILON);
    }

    #[test]
    fn apply_update_weight_modifies_edge() {
        let mut log = OperationLog::new();
        let (mut nodes, mut edges, mut findings) = make_stores();

        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![],
                },
            ),
            make_entry(
                2,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddEdge {
                    source_node_id: 0,
                    target_node_id: 1,
                    label: EdgeLabel::Calls,
                    weight: 1.0,
                },
            ),
            make_entry(
                3,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::UpdateWeight {
                    edge_id: 0,
                    new_weight: 5.0,
                },
            ),
        ];

        log.apply_batch(&entries, &mut nodes, &mut edges, &mut findings)
            .unwrap();
        let edge = edges.get(0).unwrap();
        assert!((edge.weight - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sequence_number_tracking() {
        let mut log = OperationLog::new();
        let (mut nodes, mut edges, mut findings) = make_stores();

        assert_eq!(log.current_sequence(ModuleIdentifier::PassiveRecon), 0);

        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![],
                },
            ),
        ];

        log.apply_batch(&entries, &mut nodes, &mut edges, &mut findings)
            .unwrap();
        assert_eq!(log.current_sequence(ModuleIdentifier::PassiveRecon), 2);
        assert_eq!(log.total_applied(), 2);
    }

    #[test]
    fn out_of_order_sequence_rejected() {
        let mut log = OperationLog::new();
        let (mut nodes, mut edges, mut findings) = make_stores();

        let first_batch = vec![
            make_entry(
                0,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![],
                },
            ),
        ];

        log.apply_batch(&first_batch, &mut nodes, &mut edges, &mut findings)
            .unwrap();

        let bad_batch = vec![make_entry(
            0,
            ModuleIdentifier::PassiveRecon,
            GraphOperation::AddNode {
                node_type: NodeType::Service,
                properties: vec![],
            },
        )];

        let result = log.apply_batch(&bad_batch, &mut nodes, &mut edges, &mut findings);
        assert!(result.is_err());
    }

    #[test]
    fn different_modules_have_independent_sequences() {
        let mut log = OperationLog::new();
        let (mut nodes, mut edges, mut findings) = make_stores();

        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            ),
            make_entry(
                0,
                ModuleIdentifier::Enumeration,
                GraphOperation::AddNode {
                    node_type: NodeType::Service,
                    properties: vec![],
                },
            ),
        ];

        log.apply_batch(&entries, &mut nodes, &mut edges, &mut findings)
            .unwrap();
        assert_eq!(log.current_sequence(ModuleIdentifier::PassiveRecon), 1);
        assert_eq!(log.current_sequence(ModuleIdentifier::Enumeration), 1);
        assert_eq!(nodes.count(), 2);
    }

    #[test]
    fn add_edge_to_nonexistent_node_fails() {
        let mut log = OperationLog::new();
        let (mut nodes, mut edges, mut findings) = make_stores();

        let entries = vec![make_entry(
            0,
            ModuleIdentifier::PassiveRecon,
            GraphOperation::AddEdge {
                source_node_id: 0,
                target_node_id: 1,
                label: EdgeLabel::Calls,
                weight: 1.0,
            },
        )];

        let result = log.apply_batch(&entries, &mut nodes, &mut edges, &mut findings);
        assert!(result.is_err());
    }

    #[test]
    fn update_weight_nonexistent_edge_fails() {
        let mut log = OperationLog::new();
        let (mut nodes, mut edges, mut findings) = make_stores();

        let entries = vec![make_entry(
            0,
            ModuleIdentifier::PassiveRecon,
            GraphOperation::UpdateWeight {
                edge_id: 999,
                new_weight: 5.0,
            },
        )];

        let result = log.apply_batch(&entries, &mut nodes, &mut edges, &mut findings);
        assert!(result.is_err());
    }

    #[test]
    fn empty_batch_returns_zero() {
        let mut log = OperationLog::new();
        let (mut nodes, mut edges, mut findings) = make_stores();

        let applied = log
            .apply_batch(&[], &mut nodes, &mut edges, &mut findings)
            .unwrap();
        assert_eq!(applied, 0);
        assert_eq!(log.total_applied(), 0);
    }

    #[test]
    fn default_creates_empty_log() {
        let log = OperationLog::default();
        assert_eq!(log.total_applied(), 0);
        assert_eq!(log.current_sequence(ModuleIdentifier::Fuzzing), 0);
    }

    #[test]
    fn error_display_messages_are_descriptive() {
        let seq_err = OperationLogError::SequenceOutOfOrder {
            module: ModuleIdentifier::PassiveRecon,
            expected_min: 5,
            received: 3,
        };
        let msg = seq_err.to_string();
        assert!(msg.contains("sequence out of order"));
        assert!(msg.contains("5"));
        assert!(msg.contains("3"));

        let node_err = OperationLogError::NodeNotFound(42);
        assert!(node_err.to_string().contains("42"));

        let edge_err = OperationLogError::EdgeNotFound(99);
        assert!(edge_err.to_string().contains("99"));
    }

    #[test]
    fn validate_batch_accepts_valid_add_nodes() {
        let log = OperationLog::new();
        let (nodes, edges, _) = make_stores();

        let ops = vec![
            GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![],
            },
            GraphOperation::AddNode {
                node_type: NodeType::Function,
                properties: vec![],
            },
        ];

        assert!(log.validate_batch(&ops, &nodes, &edges).is_ok());
    }

    #[test]
    fn validate_batch_accepts_edge_referencing_batch_nodes() {
        let log = OperationLog::new();
        let (nodes, edges, _) = make_stores();

        let ops = vec![
            GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![],
            },
            GraphOperation::AddNode {
                node_type: NodeType::Function,
                properties: vec![],
            },
            GraphOperation::AddEdge {
                source_node_id: 0,
                target_node_id: 1,
                label: EdgeLabel::Calls,
                weight: 1.0,
            },
        ];

        assert!(log.validate_batch(&ops, &nodes, &edges).is_ok());
    }

    #[test]
    fn validate_batch_accepts_edge_referencing_existing_nodes() {
        let mut log = OperationLog::new();
        let (mut nodes, mut edges, mut findings) = make_stores();

        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![],
                },
            ),
        ];
        log.apply_batch(&entries, &mut nodes, &mut edges, &mut findings)
            .unwrap();

        let ops = vec![GraphOperation::AddEdge {
            source_node_id: 0,
            target_node_id: 1,
            label: EdgeLabel::Calls,
            weight: 1.0,
        }];

        assert!(log.validate_batch(&ops, &nodes, &edges).is_ok());
    }

    #[test]
    fn validate_batch_rejects_dangling_edge_source() {
        let log = OperationLog::new();
        let (nodes, edges, _) = make_stores();

        let ops = vec![
            GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![],
            },
            GraphOperation::AddEdge {
                source_node_id: 99,
                target_node_id: 0,
                label: EdgeLabel::Calls,
                weight: 1.0,
            },
        ];

        let result = log.validate_batch(&ops, &nodes, &edges);
        assert_eq!(result, Err(ValidationError::DanglingEdgeSource(99)));
    }

    #[test]
    fn validate_batch_rejects_dangling_edge_target() {
        let log = OperationLog::new();
        let (nodes, edges, _) = make_stores();

        let ops = vec![
            GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![],
            },
            GraphOperation::AddEdge {
                source_node_id: 0,
                target_node_id: 99,
                label: EdgeLabel::Calls,
                weight: 1.0,
            },
        ];

        let result = log.validate_batch(&ops, &nodes, &edges);
        assert_eq!(result, Err(ValidationError::DanglingEdgeTarget(99)));
    }

    #[test]
    fn validate_batch_rejects_update_weight_for_nonexistent_edge() {
        let log = OperationLog::new();
        let (nodes, edges, _) = make_stores();

        let ops = vec![GraphOperation::UpdateWeight {
            edge_id: 42,
            new_weight: 5.0,
        }];

        let result = log.validate_batch(&ops, &nodes, &edges);
        assert_eq!(result, Err(ValidationError::EdgeNotFound(42)));
    }

    #[test]
    fn validate_batch_accepts_update_weight_for_batch_edge() {
        let log = OperationLog::new();
        let (nodes, edges, _) = make_stores();

        let ops = vec![
            GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![],
            },
            GraphOperation::AddNode {
                node_type: NodeType::Function,
                properties: vec![],
            },
            GraphOperation::AddEdge {
                source_node_id: 0,
                target_node_id: 1,
                label: EdgeLabel::Calls,
                weight: 1.0,
            },
            GraphOperation::UpdateWeight {
                edge_id: 0,
                new_weight: 5.0,
            },
        ];

        assert!(log.validate_batch(&ops, &nodes, &edges).is_ok());
    }

    #[test]
    fn validate_batch_accepts_update_weight_for_existing_edge() {
        let mut log = OperationLog::new();
        let (mut nodes, mut edges, mut findings) = make_stores();

        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![],
                },
            ),
            make_entry(
                2,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddEdge {
                    source_node_id: 0,
                    target_node_id: 1,
                    label: EdgeLabel::Calls,
                    weight: 1.0,
                },
            ),
        ];
        log.apply_batch(&entries, &mut nodes, &mut edges, &mut findings)
            .unwrap();

        let ops = vec![GraphOperation::UpdateWeight {
            edge_id: 0,
            new_weight: 9.0,
        }];

        assert!(log.validate_batch(&ops, &nodes, &edges).is_ok());
    }

    #[test]
    fn validate_batch_rejects_finding_with_nonexistent_node() {
        let log = OperationLog::new();
        let (nodes, edges, _) = make_stores();

        let ops = vec![GraphOperation::AddFinding {
            linked_node_ids: vec![7],
            vulnerability_class: VulnerabilityClass::SqlInjection,
            severity: 8.0,
            confidence: 0.9,
            certificate: vec![],
        }];

        let result = log.validate_batch(&ops, &nodes, &edges);
        assert_eq!(result, Err(ValidationError::NodeNotFoundForFinding(7)));
    }

    #[test]
    fn validate_batch_accepts_finding_linked_to_batch_node() {
        let log = OperationLog::new();
        let (nodes, edges, _) = make_stores();

        let ops = vec![
            GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![],
            },
            GraphOperation::AddFinding {
                linked_node_ids: vec![0],
                vulnerability_class: VulnerabilityClass::CrossSiteScripting,
                severity: 7.0,
                confidence: 0.8,
                certificate: vec![],
            },
        ];

        assert!(log.validate_batch(&ops, &nodes, &edges).is_ok());
    }

    #[test]
    fn validate_batch_accepts_empty_batch() {
        let log = OperationLog::new();
        let (nodes, edges, _) = make_stores();

        assert!(log.validate_batch(&[], &nodes, &edges).is_ok());
    }

    #[test]
    fn validate_batch_does_not_mutate_log() {
        let log = OperationLog::new();
        let (nodes, edges, _) = make_stores();

        let ops = vec![GraphOperation::AddNode {
            node_type: NodeType::Endpoint,
            properties: vec![],
        }];

        log.validate_batch(&ops, &nodes, &edges).unwrap();
        assert_eq!(log.total_applied(), 0);
    }

    #[test]
    fn strict_mode_rejects_sequence_gap() {
        let mut log = OperationLog::new_strict();
        let (mut nodes, mut edges, mut findings) = make_stores();

        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            ),
            make_entry(
                2,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![],
                },
            ),
        ];

        let result = log.apply_batch(&entries, &mut nodes, &mut edges, &mut findings);
        assert!(result.is_err());
    }

    #[test]
    fn strict_mode_allows_consecutive_sequences() {
        let mut log = OperationLog::new_strict();
        let (mut nodes, mut edges, mut findings) = make_stores();

        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            ),
            make_entry(
                1,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![],
                },
            ),
            make_entry(
                2,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Service,
                    properties: vec![],
                },
            ),
        ];

        let applied = log
            .apply_batch(&entries, &mut nodes, &mut edges, &mut findings)
            .unwrap();
        assert_eq!(applied, 3);
        assert_eq!(log.current_sequence(ModuleIdentifier::PassiveRecon), 3);
    }

    #[test]
    fn relaxed_mode_allows_sequence_gaps() {
        let mut log = OperationLog::new();
        let (mut nodes, mut edges, mut findings) = make_stores();

        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            ),
            make_entry(
                5,
                ModuleIdentifier::PassiveRecon,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![],
                },
            ),
        ];

        let applied = log
            .apply_batch(&entries, &mut nodes, &mut edges, &mut findings)
            .unwrap();
        assert_eq!(applied, 2);
        assert_eq!(log.current_sequence(ModuleIdentifier::PassiveRecon), 6);
    }

    #[test]
    fn sequence_gap_error_contains_correct_values() {
        let mut log = OperationLog::new_strict();
        let (mut nodes, mut edges, mut findings) = make_stores();

        let entries = vec![
            make_entry(
                0,
                ModuleIdentifier::Fuzzing,
                GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![],
                },
            ),
            make_entry(
                3,
                ModuleIdentifier::Fuzzing,
                GraphOperation::AddNode {
                    node_type: NodeType::Function,
                    properties: vec![],
                },
            ),
        ];

        let result = log.apply_batch(&entries, &mut nodes, &mut edges, &mut findings);
        match result {
            Err(OperationLogError::SequenceGap {
                module,
                expected,
                actual,
            }) => {
                assert_eq!(module, ModuleIdentifier::Fuzzing);
                assert_eq!(expected, 1);
                assert_eq!(actual, 3);
            }
            other => panic!("expected SequenceGap error, got {other:?}"),
        }
    }

    #[test]
    fn validate_batch_rejects_finding_with_partial_invalid_nodes() {
        let log = OperationLog::new();
        let (nodes, edges, _) = make_stores();

        let ops = vec![
            GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![],
            },
            GraphOperation::AddFinding {
                linked_node_ids: vec![0, 99],
                vulnerability_class: VulnerabilityClass::SqlInjection,
                severity: 8.0,
                confidence: 0.9,
                certificate: vec![],
            },
        ];

        let result = log.validate_batch(&ops, &nodes, &edges);
        assert_eq!(result, Err(ValidationError::NodeNotFoundForFinding(99)));
    }

    #[test]
    fn validation_error_display_messages() {
        let dup = ValidationError::DuplicateNodeInBatch(5);
        assert!(dup.to_string().contains("duplicate"));
        assert!(dup.to_string().contains("5"));

        let src = ValidationError::DanglingEdgeSource(10);
        assert!(src.to_string().contains("source"));
        assert!(src.to_string().contains("10"));

        let tgt = ValidationError::DanglingEdgeTarget(11);
        assert!(tgt.to_string().contains("target"));
        assert!(tgt.to_string().contains("11"));

        let edge = ValidationError::EdgeNotFound(42);
        assert!(edge.to_string().contains("edge"));
        assert!(edge.to_string().contains("42"));

        let finding = ValidationError::NodeNotFoundForFinding(7);
        assert!(finding.to_string().contains("finding"));
        assert!(finding.to_string().contains("7"));
    }
}
