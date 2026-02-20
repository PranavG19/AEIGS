#[cfg(test)]
mod tests {
    use crate::defense_context::DefenseContext;
    use crate::edge::{EdgeData, EdgeLabel, is_valid_edge, valid_edge_count};
    use crate::finding::{
        EvidenceLevel, FindingData, VulnerabilityClass, confidence_from_evidence,
    };
    use crate::ipc::{GraphQuery, IpcFrame, IpcMessage};
    use crate::node::{NodeData, NodeType};
    use crate::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};
    use crate::request::{FuzzRequest, FuzzResponse};
    use crate::target_validation::{TargetValidationError, validate_target_is_localhost};

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
            NodeType::Defense,
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
            EdgeLabel::ProtectedBy,
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

    #[test]
    fn valid_edge_accepts_all_calls_triples() {
        assert!(is_valid_edge(
            NodeType::Endpoint,
            EdgeLabel::Calls,
            NodeType::Function
        ));
        assert!(is_valid_edge(
            NodeType::Function,
            EdgeLabel::Calls,
            NodeType::Function
        ));
        assert!(is_valid_edge(
            NodeType::Service,
            EdgeLabel::Calls,
            NodeType::Service
        ));
        assert!(is_valid_edge(
            NodeType::Service,
            EdgeLabel::Calls,
            NodeType::Function
        ));
    }

    #[test]
    fn valid_edge_accepts_all_trusts_triples() {
        assert!(is_valid_edge(
            NodeType::Role,
            EdgeLabel::Trusts,
            NodeType::Role
        ));
        assert!(is_valid_edge(
            NodeType::Service,
            EdgeLabel::Trusts,
            NodeType::Service
        ));
        assert!(is_valid_edge(
            NodeType::User,
            EdgeLabel::Trusts,
            NodeType::Service
        ));
    }

    #[test]
    fn valid_edge_accepts_all_authenticates_triples() {
        assert!(is_valid_edge(
            NodeType::Role,
            EdgeLabel::Authenticates,
            NodeType::Endpoint
        ));
        assert!(is_valid_edge(
            NodeType::User,
            EdgeLabel::Authenticates,
            NodeType::Endpoint
        ));
        assert!(is_valid_edge(
            NodeType::Service,
            EdgeLabel::Authenticates,
            NodeType::Endpoint
        ));
    }

    #[test]
    fn valid_edge_accepts_all_reads_triples() {
        assert!(is_valid_edge(
            NodeType::Function,
            EdgeLabel::Reads,
            NodeType::DataStore
        ));
        assert!(is_valid_edge(
            NodeType::Endpoint,
            EdgeLabel::Reads,
            NodeType::DataStore
        ));
        assert!(is_valid_edge(
            NodeType::Service,
            EdgeLabel::Reads,
            NodeType::DataStore
        ));
    }

    #[test]
    fn valid_edge_accepts_all_writes_triples() {
        assert!(is_valid_edge(
            NodeType::Function,
            EdgeLabel::Writes,
            NodeType::DataStore
        ));
        assert!(is_valid_edge(
            NodeType::Endpoint,
            EdgeLabel::Writes,
            NodeType::DataStore
        ));
        assert!(is_valid_edge(
            NodeType::Service,
            EdgeLabel::Writes,
            NodeType::DataStore
        ));
    }

    #[test]
    fn valid_edge_accepts_all_depends_on_triples() {
        assert!(is_valid_edge(
            NodeType::Service,
            EdgeLabel::DependsOn,
            NodeType::Dependency
        ));
        assert!(is_valid_edge(
            NodeType::Service,
            EdgeLabel::DependsOn,
            NodeType::Service
        ));
        assert!(is_valid_edge(
            NodeType::Function,
            EdgeLabel::DependsOn,
            NodeType::Dependency
        ));
        assert!(is_valid_edge(
            NodeType::Endpoint,
            EdgeLabel::DependsOn,
            NodeType::Dependency
        ));
    }

    #[test]
    fn valid_edge_accepts_all_exposes_triples() {
        assert!(is_valid_edge(
            NodeType::Endpoint,
            EdgeLabel::Exposes,
            NodeType::DataStore
        ));
        assert!(is_valid_edge(
            NodeType::Function,
            EdgeLabel::Exposes,
            NodeType::DataStore
        ));
        assert!(is_valid_edge(
            NodeType::Service,
            EdgeLabel::Exposes,
            NodeType::DataStore
        ));
        assert!(is_valid_edge(
            NodeType::Config,
            EdgeLabel::Exposes,
            NodeType::DataStore
        ));
    }

    #[test]
    fn valid_edge_accepts_all_protected_by_triples() {
        assert!(is_valid_edge(
            NodeType::Endpoint,
            EdgeLabel::ProtectedBy,
            NodeType::Defense
        ));
        assert!(is_valid_edge(
            NodeType::DataStore,
            EdgeLabel::ProtectedBy,
            NodeType::Defense
        ));
        assert!(is_valid_edge(
            NodeType::Service,
            EdgeLabel::ProtectedBy,
            NodeType::Defense
        ));
        assert!(is_valid_edge(
            NodeType::Function,
            EdgeLabel::ProtectedBy,
            NodeType::Defense
        ));
    }

    #[test]
    fn valid_edge_rejects_nonsensical_triples() {
        assert!(!is_valid_edge(
            NodeType::DataStore,
            EdgeLabel::Calls,
            NodeType::Function
        ));
        assert!(!is_valid_edge(
            NodeType::Defense,
            EdgeLabel::Exposes,
            NodeType::DataStore
        ));
        assert!(!is_valid_edge(
            NodeType::Defense,
            EdgeLabel::ProtectedBy,
            NodeType::Defense
        ));
        assert!(!is_valid_edge(
            NodeType::Dependency,
            EdgeLabel::Writes,
            NodeType::DataStore
        ));
        assert!(!is_valid_edge(
            NodeType::Config,
            EdgeLabel::Calls,
            NodeType::Function
        ));
        assert!(!is_valid_edge(
            NodeType::Role,
            EdgeLabel::Reads,
            NodeType::DataStore
        ));
        assert!(!is_valid_edge(
            NodeType::User,
            EdgeLabel::Writes,
            NodeType::DataStore
        ));
        assert!(!is_valid_edge(
            NodeType::DataStore,
            EdgeLabel::Trusts,
            NodeType::Service
        ));
        assert!(!is_valid_edge(
            NodeType::Defense,
            EdgeLabel::Calls,
            NodeType::Service
        ));
        assert!(!is_valid_edge(
            NodeType::Dependency,
            EdgeLabel::DependsOn,
            NodeType::Dependency
        ));
    }

    #[test]
    fn every_edge_label_has_at_least_one_valid_combination() {
        let all_node_types = [
            NodeType::Endpoint,
            NodeType::Function,
            NodeType::DataStore,
            NodeType::Role,
            NodeType::Dependency,
            NodeType::Config,
            NodeType::User,
            NodeType::Service,
            NodeType::Defense,
        ];
        let all_labels = [
            EdgeLabel::Calls,
            EdgeLabel::Trusts,
            EdgeLabel::Authenticates,
            EdgeLabel::Reads,
            EdgeLabel::Writes,
            EdgeLabel::DependsOn,
            EdgeLabel::Exposes,
            EdgeLabel::ProtectedBy,
        ];

        for label in all_labels {
            let has_valid = all_node_types.iter().any(|src| {
                all_node_types
                    .iter()
                    .any(|tgt| is_valid_edge(*src, label, *tgt))
            });
            assert!(has_valid, "EdgeLabel {:?} has no valid combinations", label);
        }
    }

    #[test]
    fn test_localhost_accepted() {
        assert!(validate_target_is_localhost("http://localhost:8080/api").is_ok());
    }

    #[test]
    fn test_127_accepted() {
        assert!(validate_target_is_localhost("http://127.0.0.1:3000").is_ok());
    }

    #[test]
    fn test_ipv6_loopback_accepted() {
        assert!(validate_target_is_localhost("http://[::1]:8080").is_ok());
    }

    #[test]
    fn test_bare_localhost_accepted() {
        assert!(validate_target_is_localhost("localhost:8080").is_ok());
    }

    #[test]
    fn test_public_ip_rejected() {
        let err = validate_target_is_localhost("http://8.8.8.8").unwrap_err();
        assert_eq!(
            err,
            TargetValidationError::NonLocalhostTarget {
                host: "8.8.8.8".into()
            }
        );
    }

    #[test]
    fn test_domain_rejected() {
        let err = validate_target_is_localhost("http://example.com").unwrap_err();
        assert_eq!(
            err,
            TargetValidationError::NonLocalhostTarget {
                host: "example.com".into()
            }
        );
    }

    #[test]
    fn test_rfc1918_rejected() {
        let err = validate_target_is_localhost("http://192.168.1.1").unwrap_err();
        assert_eq!(
            err,
            TargetValidationError::NonLocalhostTarget {
                host: "192.168.1.1".into()
            }
        );
    }

    #[test]
    fn test_rfc1918_10_rejected() {
        let err = validate_target_is_localhost("http://10.0.0.1").unwrap_err();
        assert_eq!(
            err,
            TargetValidationError::NonLocalhostTarget {
                host: "10.0.0.1".into()
            }
        );
    }

    #[test]
    fn test_empty_url_rejected() {
        let err = validate_target_is_localhost("").unwrap_err();
        assert_eq!(err, TargetValidationError::InvalidUrl { url: "".into() });
    }

    #[test]
    fn test_localhost_with_path() {
        assert!(validate_target_is_localhost("http://localhost/api/users").is_ok());
    }

    #[test]
    fn test_https_localhost_accepted() {
        assert!(validate_target_is_localhost("https://localhost:8443").is_ok());
    }

    #[test]
    fn test_uppercase_localhost_accepted() {
        assert!(validate_target_is_localhost("http://LOCALHOST:8080").is_ok());
    }

    #[test]
    fn test_mixed_case_localhost_accepted() {
        assert!(validate_target_is_localhost("http://Localhost:8080").is_ok());
    }

    #[test]
    fn test_127_with_deep_path_and_query_accepted() {
        assert!(validate_target_is_localhost("http://127.0.0.1:8080/deep/path?query=1").is_ok());
    }

    #[test]
    fn test_credentials_in_url_accepted_when_host_is_localhost() {
        assert!(validate_target_is_localhost("http://user@localhost:8080").is_ok());
    }

    #[test]
    fn test_subdomain_localhost_evil_rejected() {
        let err = validate_target_is_localhost("http://localhost.evil.com").unwrap_err();
        assert_eq!(
            err,
            TargetValidationError::NonLocalhostTarget {
                host: "localhost.evil.com".into()
            }
        );
    }

    #[test]
    fn test_evil_localhost_subdomain_rejected() {
        let err = validate_target_is_localhost("http://evil-localhost.com").unwrap_err();
        assert_eq!(
            err,
            TargetValidationError::NonLocalhostTarget {
                host: "evil-localhost.com".into()
            }
        );
    }

    #[test]
    fn test_hex_encoded_127001_rejected() {
        assert!(validate_target_is_localhost("http://0x7f000001:8080").is_err());
    }

    #[test]
    fn test_decimal_encoded_127001_rejected() {
        assert!(validate_target_is_localhost("http://2130706433:8080").is_err());
    }

    #[test]
    fn test_octal_encoded_127001_rejected() {
        assert!(validate_target_is_localhost("http://0177.0.0.1:8080").is_err());
    }

    #[test]
    fn test_dns_rebinding_nip_io_rejected() {
        let err = validate_target_is_localhost("http://127.0.0.1.nip.io").unwrap_err();
        assert_eq!(
            err,
            TargetValidationError::NonLocalhostTarget {
                host: "127.0.0.1.nip.io".into()
            }
        );
    }

    #[test]
    fn test_ipv6_mapped_ipv4_rejected() {
        assert!(validate_target_is_localhost("http://[::ffff:127.0.0.1]:8080").is_err());
    }

    #[test]
    fn test_verbose_ipv6_loopback_rejected() {
        assert!(validate_target_is_localhost("http://[0:0:0:0:0:0:0:1]:8080").is_err());
    }

    #[test]
    fn test_confused_authority_localhost_at_evil_rejected() {
        let err = validate_target_is_localhost("http://localhost@evil.com").unwrap_err();
        assert_eq!(
            err,
            TargetValidationError::NonLocalhostTarget {
                host: "evil.com".into()
            }
        );
    }

    #[test]
    fn test_shortened_ipv4_127_1_rejected() {
        assert!(validate_target_is_localhost("http://127.1:8080").is_err());
    }

    #[test]
    fn test_shortened_ipv4_127_0_1_rejected() {
        assert!(validate_target_is_localhost("http://127.0.1:8080").is_err());
    }

    #[test]
    fn test_bare_localhost_with_path_no_port() {
        assert!(validate_target_is_localhost("localhost/path").is_ok());
    }

    #[test]
    fn all_evidence_levels_serialize() {
        let levels = [
            EvidenceLevel::Statistical,
            EvidenceLevel::Counterfactual,
            EvidenceLevel::Confirmed,
            EvidenceLevel::Chained,
        ];

        for level in levels {
            let json = serde_json::to_string(&level).unwrap();
            let deserialized: EvidenceLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, level);
        }
    }

    #[test]
    fn finding_data_builder_with_evidence_level() {
        let finding = FindingData::new(
            1,
            VulnerabilityClass::SqlInjection,
            9.5,
            0.95,
            ModuleIdentifier::Fuzzing,
            1700000000000,
        )
        .with_evidence_level(EvidenceLevel::Confirmed);

        assert_eq!(finding.evidence_level, EvidenceLevel::Confirmed);
    }

    #[test]
    fn finding_data_default_evidence_level_is_statistical() {
        let finding = FindingData::new(
            1,
            VulnerabilityClass::CrossSiteScripting,
            7.0,
            0.80,
            ModuleIdentifier::Fuzzing,
            1700000000000,
        );

        assert_eq!(finding.evidence_level, EvidenceLevel::Statistical);
    }

    #[test]
    fn fuzz_request_construction_and_field_access() {
        let request = FuzzRequest {
            request_id: 42,
            endpoint: "http://localhost:8080/api/users".to_string(),
            method: "POST".to_string(),
            parameter_name: "username".to_string(),
            payload: "' OR 1=1 --".to_string(),
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Accept".to_string(), "*/*".to_string()),
            ],
        };

        assert_eq!(request.request_id, 42);
        assert_eq!(request.endpoint, "http://localhost:8080/api/users");
        assert_eq!(request.method, "POST");
        assert_eq!(request.parameter_name, "username");
        assert_eq!(request.payload, "' OR 1=1 --");
        assert_eq!(request.headers.len(), 2);
        assert_eq!(request.headers[0].0, "Content-Type");
    }

    #[test]
    fn fuzz_response_construction_and_field_access() {
        let response = FuzzResponse {
            request_id: 42,
            status_code: 200,
            body: "{\"status\":\"ok\"}".to_string(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            response_time: std::time::Duration::from_millis(150),
            body_size_bytes: 15,
        };

        assert_eq!(response.request_id, 42);
        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, "{\"status\":\"ok\"}");
        assert_eq!(response.headers.len(), 1);
        assert_eq!(
            response.response_time,
            std::time::Duration::from_millis(150)
        );
        assert_eq!(response.body_size_bytes, 15);
    }

    #[test]
    fn fuzz_request_clone() {
        let request = FuzzRequest {
            request_id: 1,
            endpoint: "http://localhost/test".to_string(),
            method: "GET".to_string(),
            parameter_name: "q".to_string(),
            payload: "<script>alert(1)</script>".to_string(),
            headers: vec![],
        };

        let cloned = request.clone();
        assert_eq!(cloned.request_id, request.request_id);
        assert_eq!(cloned.endpoint, request.endpoint);
        assert_eq!(cloned.payload, request.payload);
    }

    #[test]
    fn fuzz_response_clone() {
        let response = FuzzResponse {
            request_id: 7,
            status_code: 500,
            body: "Internal Server Error".to_string(),
            headers: vec![],
            response_time: std::time::Duration::from_secs(2),
            body_size_bytes: 21,
        };

        let cloned = response.clone();
        assert_eq!(cloned.request_id, response.request_id);
        assert_eq!(cloned.status_code, response.status_code);
        assert_eq!(cloned.response_time, response.response_time);
    }

    #[test]
    fn defense_context_default_has_no_defenses() {
        let ctx = DefenseContext::default();

        assert!(!ctx.has_waf);
        assert!(ctx.waf_vendor.is_none());
        assert!(ctx.waf_blocked_categories.is_empty());
        assert!(ctx.rate_limit_rps.is_none());
        assert!(!ctx.bot_detection_present);
        assert!(!ctx.bot_detection_evaded);
    }

    #[test]
    fn defense_context_with_all_fields_populated() {
        let ctx = DefenseContext {
            has_waf: true,
            waf_vendor: Some("Cloudflare".to_string()),
            waf_blocked_categories: vec![
                VulnerabilityClass::SqlInjection,
                VulnerabilityClass::CrossSiteScripting,
            ],
            rate_limit_rps: Some(50.0),
            bot_detection_present: true,
            bot_detection_evaded: false,
        };

        assert!(ctx.has_waf);
        assert_eq!(ctx.waf_vendor.as_deref(), Some("Cloudflare"));
        assert_eq!(ctx.waf_blocked_categories.len(), 2);
        assert_eq!(
            ctx.waf_blocked_categories[0],
            VulnerabilityClass::SqlInjection
        );
        assert!((ctx.rate_limit_rps.unwrap() - 50.0).abs() < f64::EPSILON);
        assert!(ctx.bot_detection_present);
        assert!(!ctx.bot_detection_evaded);
    }

    #[test]
    fn defense_context_serializes_roundtrip() {
        let ctx = DefenseContext {
            has_waf: true,
            waf_vendor: Some("ModSecurity".to_string()),
            waf_blocked_categories: vec![VulnerabilityClass::CommandInjection],
            rate_limit_rps: Some(100.0),
            bot_detection_present: true,
            bot_detection_evaded: true,
        };

        let json = serde_json::to_string(&ctx).unwrap();
        let deserialized: DefenseContext = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.has_waf, ctx.has_waf);
        assert_eq!(deserialized.waf_vendor, ctx.waf_vendor);
        assert_eq!(deserialized.waf_blocked_categories.len(), 1);
        assert_eq!(
            deserialized.waf_blocked_categories[0],
            VulnerabilityClass::CommandInjection
        );
        assert_eq!(deserialized.rate_limit_rps, ctx.rate_limit_rps);
        assert_eq!(
            deserialized.bot_detection_present,
            ctx.bot_detection_present
        );
        assert_eq!(deserialized.bot_detection_evaded, ctx.bot_detection_evaded);
    }

    #[test]
    fn defense_context_default_serializes_roundtrip() {
        let ctx = DefenseContext::default();
        let json = serde_json::to_string(&ctx).unwrap();
        let deserialized: DefenseContext = serde_json::from_str(&json).unwrap();

        assert!(!deserialized.has_waf);
        assert!(deserialized.waf_vendor.is_none());
        assert!(deserialized.waf_blocked_categories.is_empty());
        assert!(deserialized.rate_limit_rps.is_none());
        assert!(!deserialized.bot_detection_present);
        assert!(!deserialized.bot_detection_evaded);
    }

    #[test]
    fn node_type_display_produces_human_readable_output() {
        let types = [
            (NodeType::Endpoint, "Endpoint"),
            (NodeType::Function, "Function"),
            (NodeType::DataStore, "Data Store"),
            (NodeType::Role, "Role"),
            (NodeType::Dependency, "Dependency"),
            (NodeType::Config, "Configuration"),
            (NodeType::User, "User"),
            (NodeType::Service, "Service"),
            (NodeType::Defense, "Defense"),
        ];

        let mut seen = std::collections::HashSet::new();
        for (variant, expected) in types {
            let display = format!("{}", variant);
            assert_eq!(display, expected);
            assert!(!display.is_empty());
            assert!(
                seen.insert(display),
                "Display strings must be unique per variant"
            );
        }
    }

    #[test]
    fn node_type_display_differs_from_debug_for_multiword_variants() {
        assert_ne!(
            format!("{}", NodeType::DataStore),
            format!("{:?}", NodeType::DataStore)
        );
        assert_ne!(
            format!("{}", NodeType::Config),
            format!("{:?}", NodeType::Config)
        );
    }

    #[test]
    fn edge_label_display_produces_human_readable_output() {
        let labels = [
            (EdgeLabel::Calls, "Calls"),
            (EdgeLabel::Trusts, "Trusts"),
            (EdgeLabel::Authenticates, "Authenticates"),
            (EdgeLabel::Reads, "Reads"),
            (EdgeLabel::Writes, "Writes"),
            (EdgeLabel::DependsOn, "Depends On"),
            (EdgeLabel::Exposes, "Exposes"),
            (EdgeLabel::ProtectedBy, "Protected By"),
        ];

        let mut seen = std::collections::HashSet::new();
        for (variant, expected) in labels {
            let display = format!("{}", variant);
            assert_eq!(display, expected);
            assert!(!display.is_empty());
            assert!(
                seen.insert(display),
                "Display strings must be unique per variant"
            );
        }
    }

    #[test]
    fn vulnerability_class_display_produces_human_readable_output() {
        let classes = [
            (VulnerabilityClass::SqlInjection, "SQL Injection"),
            (
                VulnerabilityClass::CrossSiteScripting,
                "Cross-Site Scripting",
            ),
            (VulnerabilityClass::CommandInjection, "Command Injection"),
            (VulnerabilityClass::PathTraversal, "Path Traversal"),
            (
                VulnerabilityClass::ServerSideRequestForgery,
                "Server-Side Request Forgery",
            ),
            (
                VulnerabilityClass::InsecureDeserialization,
                "Insecure Deserialization",
            ),
            (
                VulnerabilityClass::BrokenAuthentication,
                "Broken Authentication",
            ),
            (
                VulnerabilityClass::BrokenAuthorization,
                "Broken Authorization",
            ),
            (
                VulnerabilityClass::SecurityMisconfiguration,
                "Security Misconfiguration",
            ),
            (
                VulnerabilityClass::SensitiveDataExposure,
                "Sensitive Data Exposure",
            ),
            (
                VulnerabilityClass::ServerSideTemplateInjection,
                "Server-Side Template Injection",
            ),
            (VulnerabilityClass::HeaderInjection, "Header Injection"),
            (VulnerabilityClass::OpenRedirect, "Open Redirect"),
            (VulnerabilityClass::CrlfInjection, "CRLF Injection"),
            (
                VulnerabilityClass::KnownVulnerableDependency,
                "Known Vulnerable Dependency",
            ),
            (
                VulnerabilityClass::InsufficientInputValidation,
                "Insufficient Input Validation",
            ),
        ];

        let mut seen = std::collections::HashSet::new();
        for (variant, expected) in classes {
            let display = format!("{}", variant);
            assert_eq!(display, expected);
            assert!(!display.is_empty());
            assert!(
                seen.insert(display),
                "Display strings must be unique per variant"
            );
        }
    }

    #[test]
    fn vulnerability_class_display_differs_from_debug() {
        assert_ne!(
            format!("{}", VulnerabilityClass::SqlInjection),
            format!("{:?}", VulnerabilityClass::SqlInjection)
        );
        assert_ne!(
            format!("{}", VulnerabilityClass::CrossSiteScripting),
            format!("{:?}", VulnerabilityClass::CrossSiteScripting)
        );
    }

    #[test]
    fn evidence_level_display_produces_human_readable_output() {
        let levels = [
            (EvidenceLevel::Statistical, "Statistical"),
            (EvidenceLevel::Counterfactual, "Counterfactual"),
            (EvidenceLevel::Confirmed, "Confirmed"),
            (EvidenceLevel::Chained, "Chained"),
        ];

        let mut seen = std::collections::HashSet::new();
        for (variant, expected) in levels {
            let display = format!("{}", variant);
            assert_eq!(display, expected);
            assert!(!display.is_empty());
            assert!(
                seen.insert(display),
                "Display strings must be unique per variant"
            );
        }
    }

    #[test]
    fn confidence_score_clamps_to_bounds() {
        let finding = FindingData::new(
            1,
            VulnerabilityClass::SqlInjection,
            9.0,
            0.9,
            ModuleIdentifier::Fuzzing,
            1700000000000,
        )
        .with_confidence_score(1.5);

        assert!((finding.confidence_score.unwrap() - 1.0).abs() < f64::EPSILON);

        let finding2 = finding.with_confidence_score(-0.5);
        assert!((finding2.confidence_score.unwrap() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_from_evidence_confirmed_is_high() {
        let score = confidence_from_evidence(EvidenceLevel::Confirmed);
        assert!((score - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_from_evidence_statistical_is_low() {
        let score = confidence_from_evidence(EvidenceLevel::Statistical);
        assert!((score - 0.4).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_from_evidence_all_levels() {
        assert!(
            (confidence_from_evidence(EvidenceLevel::Counterfactual) - 0.7).abs() < f64::EPSILON
        );
        assert!((confidence_from_evidence(EvidenceLevel::Chained) - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn effective_confidence_uses_score_when_set() {
        let finding = FindingData::new(
            1,
            VulnerabilityClass::SqlInjection,
            9.0,
            0.9,
            ModuleIdentifier::Fuzzing,
            1700000000000,
        )
        .with_confidence_score(0.75);

        assert!((finding.effective_confidence() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn effective_confidence_falls_back_to_evidence_level() {
        let finding = FindingData::new(
            1,
            VulnerabilityClass::SqlInjection,
            9.0,
            0.9,
            ModuleIdentifier::Fuzzing,
            1700000000000,
        )
        .with_evidence_level(EvidenceLevel::Confirmed);

        assert!((finding.effective_confidence() - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_score_serializes_roundtrip() {
        let finding = FindingData::new(
            1,
            VulnerabilityClass::SqlInjection,
            9.0,
            0.9,
            ModuleIdentifier::Fuzzing,
            1700000000000,
        )
        .with_confidence_score(0.85);

        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: FindingData = serde_json::from_str(&json).unwrap();
        assert!((deserialized.confidence_score.unwrap() - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_score_absent_deserializes_as_none() {
        let finding = FindingData::new(
            1,
            VulnerabilityClass::SqlInjection,
            9.0,
            0.9,
            ModuleIdentifier::Fuzzing,
            1700000000000,
        );

        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: FindingData = serde_json::from_str(&json).unwrap();
        assert!(deserialized.confidence_score.is_none());
    }

    #[test]
    fn is_valid_edge_exhaustive_all_triples_covered() {
        let all_node_types = [
            NodeType::Endpoint,
            NodeType::Function,
            NodeType::DataStore,
            NodeType::Role,
            NodeType::Dependency,
            NodeType::Config,
            NodeType::User,
            NodeType::Service,
            NodeType::Defense,
        ];
        let all_labels = [
            EdgeLabel::Calls,
            EdgeLabel::Trusts,
            EdgeLabel::Authenticates,
            EdgeLabel::Reads,
            EdgeLabel::Writes,
            EdgeLabel::DependsOn,
            EdgeLabel::Exposes,
            EdgeLabel::ProtectedBy,
        ];

        let mut valid_count = 0;
        let total = all_node_types.len() * all_labels.len() * all_node_types.len();

        for src in &all_node_types {
            for label in &all_labels {
                for tgt in &all_node_types {
                    if is_valid_edge(*src, *label, *tgt) {
                        valid_count += 1;
                    }
                }
            }
        }

        assert_eq!(
            valid_count,
            valid_edge_count(),
            "Expected exactly {} valid triples, found {}",
            valid_edge_count(),
            valid_count
        );
        assert_eq!(total, 9 * 8 * 9, "Total triple space should be 648");
    }

    #[test]
    fn defense_context_clone_is_independent() {
        let original = DefenseContext {
            has_waf: true,
            waf_vendor: Some("AwsWaf".to_string()),
            waf_blocked_categories: vec![VulnerabilityClass::PathTraversal],
            rate_limit_rps: Some(25.0),
            bot_detection_present: false,
            bot_detection_evaded: false,
        };

        let mut cloned = original.clone();
        cloned.has_waf = false;
        cloned
            .waf_blocked_categories
            .push(VulnerabilityClass::SqlInjection);

        assert!(original.has_waf);
        assert_eq!(original.waf_blocked_categories.len(), 1);
        assert!(!cloned.has_waf);
        assert_eq!(cloned.waf_blocked_categories.len(), 2);
    }
}
