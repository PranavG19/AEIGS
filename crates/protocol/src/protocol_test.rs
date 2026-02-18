#[cfg(test)]
mod tests {
    use crate::edge::{EdgeData, EdgeLabel};
    use crate::finding::{FindingData, VulnerabilityClass};
    use crate::ipc::{GraphQuery, IpcFrame, IpcMessage};
    use crate::node::{NodeData, NodeType};
    use crate::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

    #[test]
    fn node_data_builder_sets_properties() {
        let node = NodeData::new(1, NodeType::Endpoint)
            .with_property("path", "/api/users")
            .with_property("method", "GET");

        assert_eq!(node.id, 1);
        assert_eq!(node.node_type, NodeType::Endpoint);
        assert_eq!(node.properties.get("path").unwrap(), "/api/users");
        assert_eq!(node.properties.get("method").unwrap(), "GET");
    }

    #[test]
    fn edge_data_stores_provenance() {
        let edge = EdgeData::new(
            10,
            1,
            2,
            EdgeLabel::Calls,
            0.75,
            ModuleIdentifier::PassiveRecon,
            42,
        );

        assert_eq!(edge.id, 10);
        assert_eq!(edge.source_node_id, 1);
        assert_eq!(edge.target_node_id, 2);
        assert_eq!(edge.label, EdgeLabel::Calls);
        assert!((edge.weight - 0.75).abs() < f64::EPSILON);
        assert_eq!(edge.provenance_module, ModuleIdentifier::PassiveRecon);
        assert_eq!(edge.provenance_sequence, 42);
    }

    #[test]
    fn finding_data_builder_chains() {
        let finding = FindingData::new(
            1,
            VulnerabilityClass::SqlInjection,
            9.5,
            0.95,
            ModuleIdentifier::Fuzzing,
            1700000000000,
        )
        .with_linked_nodes(vec![10, 20])
        .with_certificate(b"proof-of-concept".to_vec());

        assert_eq!(finding.id, 1);
        assert_eq!(finding.linked_node_ids, vec![10, 20]);
        assert_eq!(finding.certificate, b"proof-of-concept");
    }

    #[test]
    fn graph_operation_serializes_roundtrip() {
        let op = GraphOperation::AddNode {
            node_type: NodeType::Service,
            properties: vec![("name".into(), "auth-service".into())],
        };
        let json = serde_json::to_string(&op).unwrap();
        let deserialized: GraphOperation = serde_json::from_str(&json).unwrap();

        match deserialized {
            GraphOperation::AddNode {
                node_type,
                properties,
            } => {
                assert_eq!(node_type, NodeType::Service);
                assert_eq!(properties[0], ("name".into(), "auth-service".into()));
            }
            _ => panic!("expected AddNode variant"),
        }
    }

    #[test]
    fn operation_log_entry_serializes_roundtrip() {
        let entry = OperationLogEntry {
            sequence_number: 1,
            module: ModuleIdentifier::Enumeration,
            operation: GraphOperation::AddEdge {
                source_node_id: 1,
                target_node_id: 2,
                label: EdgeLabel::DependsOn,
                weight: 1.0,
            },
            timestamp_unix_ms: 1700000000000,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: OperationLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.sequence_number, 1);
        assert_eq!(deserialized.module, ModuleIdentifier::Enumeration);
    }

    #[test]
    fn ipc_frame_encode_decode_roundtrip() {
        let message = IpcMessage::OperationBatch {
            entries: vec![OperationLogEntry {
                sequence_number: 0,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Dependency,
                    properties: vec![("name".into(), "lodash".into())],
                },
                timestamp_unix_ms: 1700000000000,
            }],
        };

        let encoded = IpcFrame::encode(&message).unwrap();
        let decoded = IpcFrame::decode(&encoded).unwrap();

        match decoded {
            IpcMessage::OperationBatch { entries } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].sequence_number, 0);
            }
            _ => panic!("expected OperationBatch"),
        }
    }

    #[test]
    fn ipc_frame_decode_insufficient_data_returns_error() {
        let result = IpcFrame::decode(&[0, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn query_request_response_roundtrip() {
        let request = IpcMessage::QueryRequest {
            request_id: 42,
            query: GraphQuery::PathsBetween {
                from_node_id: 1,
                to_node_id: 10,
                max_hops: 5,
            },
        };

        let encoded = IpcFrame::encode(&request).unwrap();
        let decoded = IpcFrame::decode(&encoded).unwrap();

        match decoded {
            IpcMessage::QueryRequest { request_id, query } => {
                assert_eq!(request_id, 42);
                match query {
                    GraphQuery::PathsBetween {
                        from_node_id,
                        to_node_id,
                        max_hops,
                    } => {
                        assert_eq!(from_node_id, 1);
                        assert_eq!(to_node_id, 10);
                        assert_eq!(max_hops, 5);
                    }
                    _ => panic!("expected PathsBetween query"),
                }
            }
            _ => panic!("expected QueryRequest"),
        }
    }

    #[test]
    fn all_node_types_serialize() {
        let types = [
            NodeType::Endpoint,
            NodeType::Function,
            NodeType::DataStore,
            NodeType::Role,
            NodeType::Dependency,
            NodeType::Config,
            NodeType::User,
            NodeType::Service,
        ];

        for node_type in types {
            let json = serde_json::to_string(&node_type).unwrap();
            let deserialized: NodeType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, node_type);
        }
    }

    #[test]
    fn all_edge_labels_serialize() {
        let labels = [
            EdgeLabel::Calls,
            EdgeLabel::Trusts,
            EdgeLabel::Authenticates,
            EdgeLabel::Reads,
            EdgeLabel::Writes,
            EdgeLabel::DependsOn,
            EdgeLabel::Exposes,
        ];

        for label in labels {
            let json = serde_json::to_string(&label).unwrap();
            let deserialized: EdgeLabel = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, label);
        }
    }

    #[test]
    fn all_vulnerability_classes_serialize() {
        let classes = [
            VulnerabilityClass::SqlInjection,
            VulnerabilityClass::CrossSiteScripting,
            VulnerabilityClass::CommandInjection,
            VulnerabilityClass::PathTraversal,
            VulnerabilityClass::ServerSideRequestForgery,
            VulnerabilityClass::InsecureDeserialization,
            VulnerabilityClass::BrokenAuthentication,
            VulnerabilityClass::BrokenAuthorization,
            VulnerabilityClass::SecurityMisconfiguration,
            VulnerabilityClass::SensitiveDataExposure,
            VulnerabilityClass::ServerSideTemplateInjection,
            VulnerabilityClass::HeaderInjection,
            VulnerabilityClass::OpenRedirect,
            VulnerabilityClass::CrlfInjection,
            VulnerabilityClass::KnownVulnerableDependency,
            VulnerabilityClass::InsufficientInputValidation,
        ];

        for class in classes {
            let json = serde_json::to_string(&class).unwrap();
            let deserialized: VulnerabilityClass = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, class);
        }
    }

    #[test]
    fn heartbeat_message_roundtrip() {
        let msg = IpcMessage::Heartbeat {
            module: ModuleIdentifier::Fuzzing,
            timestamp_unix_ms: 1700000000000,
        };
        let encoded = IpcFrame::encode(&msg).unwrap();
        let decoded = IpcFrame::decode(&encoded).unwrap();

        match decoded {
            IpcMessage::Heartbeat {
                module,
                timestamp_unix_ms,
            } => {
                assert_eq!(module, ModuleIdentifier::Fuzzing);
                assert_eq!(timestamp_unix_ms, 1700000000000);
            }
            _ => panic!("expected Heartbeat"),
        }
    }
}
