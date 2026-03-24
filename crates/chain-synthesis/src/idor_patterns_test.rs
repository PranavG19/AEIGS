use super::idor_patterns::*;

fn sample_finding() -> IdorFinding {
    IdorFinding {
        endpoint: "/api/users/profile".to_string(),
        method: IdorHttpMethod::Get,
        vulnerable_parameter: "user_id".to_string(),
        observed_id: "1042".to_string(),
        resource_type: "UserProfile".to_string(),
        privilege_level: PrivilegeLevel::User,
    }
}

fn sample_finding_uuid() -> IdorFinding {
    IdorFinding {
        endpoint: "/api/documents".to_string(),
        method: IdorHttpMethod::Get,
        vulnerable_parameter: "doc_id".to_string(),
        observed_id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
        resource_type: "Document".to_string(),
        privilege_level: PrivilegeLevel::User,
    }
}

// ---------------------------------------------------------------------------
// IdorPatternType
// ---------------------------------------------------------------------------

#[test]
fn pattern_type_display_all_variants() {
    assert_eq!(
        IdorPatternType::HorizontalEscalation.to_string(),
        "horizontal-escalation"
    );
    assert_eq!(
        IdorPatternType::VerticalEscalation.to_string(),
        "vertical-escalation"
    );
    assert_eq!(
        IdorPatternType::BulkEnumeration.to_string(),
        "bulk-enumeration"
    );
    assert_eq!(
        IdorPatternType::CrossObjectReference.to_string(),
        "cross-object-reference"
    );
    assert_eq!(
        IdorPatternType::IndirectReferenceMapping.to_string(),
        "indirect-reference-mapping"
    );
    assert_eq!(
        IdorPatternType::UuidPrediction.to_string(),
        "uuid-prediction"
    );
    assert_eq!(IdorPatternType::GraphQlIdor.to_string(), "graphql-idor");
    assert_eq!(
        IdorPatternType::ParameterTampering.to_string(),
        "parameter-tampering"
    );
}

// ---------------------------------------------------------------------------
// Horizontal escalation
// ---------------------------------------------------------------------------

#[test]
fn horizontal_escalation_numeric_id_generates_offset_steps() {
    let finding = sample_finding();
    let chain = generate_horizontal_escalation(&finding);

    assert_eq!(chain.pattern_type, IdorPatternType::HorizontalEscalation);
    assert!(chain.steps.len() >= 5);
    assert_eq!(chain.steps[0].step_number, 1);
    assert_eq!(chain.steps[2].payload, "1043");
    assert_eq!(chain.steps[3].payload, "1044");
    assert_eq!(chain.steps[4].payload, "1052");
    assert!(chain.risk_score > 0.0);
}

#[test]
fn horizontal_escalation_non_numeric_id() {
    let finding = IdorFinding {
        endpoint: "/api/docs".to_string(),
        method: IdorHttpMethod::Get,
        vulnerable_parameter: "slug".to_string(),
        observed_id: "my-document".to_string(),
        resource_type: "Document".to_string(),
        privilege_level: PrivilegeLevel::User,
    };
    let chain = generate_horizontal_escalation(&finding);
    assert_eq!(chain.steps.len(), 3);
    assert!(chain.steps[2].payload.contains("victim"));
}

// ---------------------------------------------------------------------------
// Vertical escalation
// ---------------------------------------------------------------------------

#[test]
fn vertical_escalation_user_to_admin() {
    let finding = sample_finding();
    let chain = generate_vertical_escalation(&finding, PrivilegeLevel::Admin);

    assert_eq!(chain.pattern_type, IdorPatternType::VerticalEscalation);
    assert_eq!(chain.steps.len(), 4);
    assert!(chain.impact_description.contains("admin"));
    assert_eq!(chain.risk_score, 9.0);
}

#[test]
fn vertical_escalation_preserves_finding() {
    let finding = sample_finding();
    let chain = generate_vertical_escalation(&finding, PrivilegeLevel::SuperAdmin);
    assert_eq!(chain.finding.endpoint, "/api/users/profile");
    assert!(chain.impact_description.contains("super-admin"));
}

// ---------------------------------------------------------------------------
// Bulk enumeration
// ---------------------------------------------------------------------------

#[test]
fn bulk_enumeration_calculates_record_count() {
    let finding = sample_finding();
    let chain = generate_bulk_enumeration(&finding, 1, 10001, 1);

    assert_eq!(chain.pattern_type, IdorPatternType::BulkEnumeration);
    assert_eq!(chain.steps.len(), 4);
    assert!(chain.steps[1].expected_outcome.contains("10000"));
    assert_eq!(chain.risk_score, 8.5);
}

#[test]
fn bulk_enumeration_zero_step_size_no_panic() {
    let finding = sample_finding();
    let chain = generate_bulk_enumeration(&finding, 0, 100, 0);
    assert_eq!(chain.steps.len(), 4);
}

#[test]
fn bulk_enumeration_inverted_range() {
    let finding = sample_finding();
    let chain = generate_bulk_enumeration(&finding, 100, 50, 1);
    assert!(chain.steps[1].expected_outcome.contains("0"));
}

// ---------------------------------------------------------------------------
// Cross-object reference graph
// ---------------------------------------------------------------------------

fn build_sample_graph() -> CrossObjectGraph {
    let mut graph = CrossObjectGraph::new();
    graph.add_object(ObjectNode {
        object_type: "UserProfile".to_string(),
        example_id: "1042".to_string(),
        endpoint: "/api/users".to_string(),
    });
    graph.add_object(ObjectNode {
        object_type: "Order".to_string(),
        example_id: "5001".to_string(),
        endpoint: "/api/orders".to_string(),
    });
    graph.add_object(ObjectNode {
        object_type: "Payment".to_string(),
        example_id: "9001".to_string(),
        endpoint: "/api/payments".to_string(),
    });

    graph.add_reference(
        "UserProfile",
        "Order",
        ObjectEdge {
            source_field: "user_id".to_string(),
            target_field: "owner_id".to_string(),
            traversal_method: "query_param".to_string(),
            requires_auth: true,
        },
    );
    graph.add_reference(
        "Order",
        "Payment",
        ObjectEdge {
            source_field: "order_id".to_string(),
            target_field: "order_ref".to_string(),
            traversal_method: "path_param".to_string(),
            requires_auth: false,
        },
    );
    graph
}

#[test]
fn cross_object_graph_construction() {
    let graph = build_sample_graph();
    assert_eq!(graph.node_count(), 3);
    assert_eq!(graph.edge_count(), 2);
}

#[test]
fn cross_object_graph_deduplicates_nodes() {
    let mut graph = CrossObjectGraph::new();
    let idx1 = graph.add_object(ObjectNode {
        object_type: "User".to_string(),
        example_id: "1".to_string(),
        endpoint: "/users".to_string(),
    });
    let idx2 = graph.add_object(ObjectNode {
        object_type: "User".to_string(),
        example_id: "2".to_string(),
        endpoint: "/users/v2".to_string(),
    });
    assert_eq!(idx1, idx2);
    assert_eq!(graph.node_count(), 1);
}

#[test]
fn cross_object_find_chains_depth_limited() {
    let graph = build_sample_graph();
    let chains = graph.find_chains("UserProfile", 1);
    assert!(chains.iter().all(|c| c.len() <= 2));
}

#[test]
fn cross_object_find_chains_full_depth() {
    let graph = build_sample_graph();
    let chains = graph.find_chains("UserProfile", 4);
    assert!(chains.len() >= 2);
    let longest = chains.iter().max_by_key(|c| c.len()).unwrap();
    assert_eq!(longest, &vec!["UserProfile", "Order", "Payment"]);
}

#[test]
fn cross_object_chain_generation() {
    let finding = sample_finding();
    let graph = build_sample_graph();
    let chains = generate_cross_object_chain(&finding, &graph, 4);
    assert!(!chains.is_empty());
    for chain in &chains {
        assert_eq!(chain.pattern_type, IdorPatternType::CrossObjectReference);
        assert!(chain.steps.len() >= 2);
    }
}

#[test]
fn cross_object_nonexistent_start_returns_empty() {
    let graph = build_sample_graph();
    let chains = graph.find_chains("Nonexistent", 4);
    assert!(chains.is_empty());
}

#[test]
fn cross_object_add_reference_missing_node_returns_false() {
    let mut graph = CrossObjectGraph::new();
    graph.add_object(ObjectNode {
        object_type: "A".to_string(),
        example_id: "1".to_string(),
        endpoint: "/a".to_string(),
    });
    let ok = graph.add_reference(
        "A",
        "Missing",
        ObjectEdge {
            source_field: "x".to_string(),
            target_field: "y".to_string(),
            traversal_method: "param".to_string(),
            requires_auth: false,
        },
    );
    assert!(!ok);
}

#[test]
fn cross_object_outgoing_references() {
    let graph = build_sample_graph();
    let refs = graph.outgoing_references("UserProfile");
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].0.object_type, "Order");
}

#[test]
fn cross_object_dot_export() {
    let graph = build_sample_graph();
    let dot = graph.to_dot();
    assert!(dot.contains("digraph CrossObjectIDOR"));
    assert!(dot.contains("UserProfile"));
    assert!(dot.contains("Order"));
    assert!(dot.contains("Payment"));
    assert!(dot.contains("->"));
}

// ---------------------------------------------------------------------------
// UUID v1 analysis
// ---------------------------------------------------------------------------

#[test]
fn uuid_v1_analysis_valid_uuid() {
    let analysis = analyze_uuid_v1("6ba7b810-9dad-11d1-80b4-00c04fd430c8");
    assert!(analysis.is_some());
    let a = analysis.unwrap();
    assert_eq!(a.mac_address, [0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8]);
    assert_eq!(a.predicted_next.len(), 3);
    assert!(a.timestamp_100ns > 0);
}

#[test]
fn uuid_v1_analysis_rejects_v4() {
    let result = analyze_uuid_v1("550e8400-e29b-41d4-a716-446655440000");
    assert!(result.is_none());
}

#[test]
fn uuid_v1_analysis_rejects_invalid_length() {
    assert!(analyze_uuid_v1("abc").is_none());
    assert!(analyze_uuid_v1("").is_none());
}

#[test]
fn uuid_v1_predicted_uuids_are_valid_format() {
    let analysis = analyze_uuid_v1("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap();
    for predicted in &analysis.predicted_next {
        assert_eq!(predicted.len(), 36);
        assert_eq!(predicted.chars().filter(|c| *c == '-').count(), 4);
        let version_char = predicted.chars().nth(14).unwrap();
        assert_eq!(version_char, '1');
    }
}

#[test]
fn uuid_prediction_chain_generation() {
    let finding = sample_finding_uuid();
    let analysis = analyze_uuid_v1(&finding.observed_id).unwrap();
    let chain = generate_uuid_prediction_chain(&finding, &analysis);

    assert_eq!(chain.pattern_type, IdorPatternType::UuidPrediction);
    assert!(chain.steps.len() >= 5);
    assert_eq!(chain.risk_score, 7.0);
}

// ---------------------------------------------------------------------------
// GraphQL IDOR
// ---------------------------------------------------------------------------

#[test]
fn graphql_idor_chain_with_traversal_paths() {
    let finding = IdorFinding {
        endpoint: "/graphql".to_string(),
        method: IdorHttpMethod::Post,
        vulnerable_parameter: "query".to_string(),
        observed_id: "user_1".to_string(),
        resource_type: "User".to_string(),
        privilege_level: PrivilegeLevel::User,
    };
    let paths = vec![
        GraphQlTraversalPath {
            query_path: vec!["user".to_string(), "orders".to_string()],
            target_field: "creditCard".to_string(),
            requires_variables: vec![("userId".to_string(), "String!".to_string())],
        },
        GraphQlTraversalPath {
            query_path: vec!["user".to_string()],
            target_field: "email".to_string(),
            requires_variables: vec![],
        },
    ];

    let chain = generate_graphql_idor_chain(&finding, &paths);
    assert_eq!(chain.pattern_type, IdorPatternType::GraphQlIdor);
    assert_eq!(chain.steps.len(), 3);
    assert!(chain.steps[0].payload.contains("__schema"));
    assert_eq!(chain.risk_score, 8.0);
}

#[test]
fn graphql_nested_query_builds_correctly() {
    let path = GraphQlTraversalPath {
        query_path: vec!["user".to_string(), "posts".to_string()],
        target_field: "comments".to_string(),
        requires_variables: vec![],
    };
    let chain = generate_graphql_idor_chain(
        &IdorFinding {
            endpoint: "/graphql".to_string(),
            method: IdorHttpMethod::Post,
            vulnerable_parameter: "query".to_string(),
            observed_id: "1".to_string(),
            resource_type: "User".to_string(),
            privilege_level: PrivilegeLevel::User,
        },
        &[path],
    );
    assert!(chain.steps[1].payload.contains("user"));
    assert!(chain.steps[1].payload.contains("posts"));
    assert!(chain.steps[1].payload.contains("comments"));
}

// ---------------------------------------------------------------------------
// Parameter tampering matrix
// ---------------------------------------------------------------------------

#[test]
fn tampering_matrix_confirmed_vulnerabilities() {
    let matrix = build_tampering_matrix(vec![
        TamperingMatrixEntry {
            endpoint: "/api/orders".to_string(),
            vulnerabilities: vec![
                ParameterVulnerability {
                    parameter: "order_id".to_string(),
                    methods: vec![IdorHttpMethod::Get],
                    id_type: IdType::Sequential,
                    confirmed: true,
                },
                ParameterVulnerability {
                    parameter: "status".to_string(),
                    methods: vec![IdorHttpMethod::Put],
                    id_type: IdType::Sequential,
                    confirmed: false,
                },
            ],
        },
        TamperingMatrixEntry {
            endpoint: "/api/payments".to_string(),
            vulnerabilities: vec![ParameterVulnerability {
                parameter: "payment_id".to_string(),
                methods: vec![IdorHttpMethod::Get, IdorHttpMethod::Delete],
                id_type: IdType::UuidV4,
                confirmed: true,
            }],
        },
    ]);

    let confirmed = matrix.confirmed_vulnerabilities();
    assert_eq!(confirmed.len(), 2);
    assert_eq!(matrix.entry_count(), 2);
    assert_eq!(matrix.total_vulnerabilities(), 3);
}

#[test]
fn tampering_matrix_filter_by_id_type() {
    let matrix = build_tampering_matrix(vec![TamperingMatrixEntry {
        endpoint: "/api/items".to_string(),
        vulnerabilities: vec![
            ParameterVulnerability {
                parameter: "item_id".to_string(),
                methods: vec![IdorHttpMethod::Get],
                id_type: IdType::Sequential,
                confirmed: true,
            },
            ParameterVulnerability {
                parameter: "ref".to_string(),
                methods: vec![IdorHttpMethod::Get],
                id_type: IdType::UuidV1,
                confirmed: true,
            },
        ],
    }]);

    let sequential = matrix.by_id_type(IdType::Sequential);
    assert_eq!(sequential.len(), 1);
    assert_eq!(sequential[0].1, "item_id");
}

#[test]
fn parameter_tampering_chain_generation() {
    let finding = sample_finding();
    let matrix = build_tampering_matrix(vec![TamperingMatrixEntry {
        endpoint: "/api/users/profile".to_string(),
        vulnerabilities: vec![ParameterVulnerability {
            parameter: "user_id".to_string(),
            methods: vec![IdorHttpMethod::Get],
            id_type: IdType::Sequential,
            confirmed: true,
        }],
    }]);

    let chain = generate_parameter_tampering_chain(&finding, &matrix);
    assert_eq!(chain.pattern_type, IdorPatternType::ParameterTampering);
    assert!(chain.steps.len() >= 2);
}

// ---------------------------------------------------------------------------
// Indirect reference mapping
// ---------------------------------------------------------------------------

#[test]
fn detect_encoding_jwt() {
    let encoded = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMSJ9.dGVzdF9zaWduYXR1cmU";
    assert_eq!(
        detect_indirect_encoding(encoded),
        Some(IndirectEncoding::Jwt)
    );
}

#[test]
fn detect_encoding_sha256() {
    let hex64 = "a".repeat(64);
    assert_eq!(
        detect_indirect_encoding(&hex64),
        Some(IndirectEncoding::Sha256Truncated)
    );
}

#[test]
fn detect_encoding_hex() {
    assert_eq!(
        detect_indirect_encoding("deadbeef"),
        Some(IndirectEncoding::Hex)
    );
}

#[test]
fn detect_encoding_base64() {
    assert_eq!(
        detect_indirect_encoding("dXNlcl8xMDQy=="),
        Some(IndirectEncoding::Base64)
    );
}

#[test]
fn detect_encoding_rotating_numeric() {
    assert_eq!(
        detect_indirect_encoding("839201"),
        Some(IndirectEncoding::RotatingNumeric)
    );
}

#[test]
fn detect_encoding_returns_none_for_short_values() {
    assert_eq!(detect_indirect_encoding("ab"), None);
}

#[test]
fn indirect_reference_chain_generation() {
    let finding = sample_finding();
    let mappings = vec![IndirectReferenceMap {
        encoded_value: "dXNlcl8xMDQy".to_string(),
        encoding: IndirectEncoding::Base64,
        decoded_components: vec!["user".to_string(), "1042".to_string()],
        predicted_pattern: "base64(user_{id})".to_string(),
    }];

    let chain = generate_indirect_reference_chain(&finding, &mappings);
    assert_eq!(
        chain.pattern_type,
        IdorPatternType::IndirectReferenceMapping
    );
    assert_eq!(chain.steps.len(), 2);
    assert_eq!(chain.risk_score, 6.5);
}

// ---------------------------------------------------------------------------
// generate_all_chains
// ---------------------------------------------------------------------------

#[test]
fn generate_all_chains_minimal() {
    let finding = sample_finding();
    let chains = generate_all_chains(&finding, None, None, None, None, None);
    assert!(chains.len() >= 3);
    let types: Vec<IdorPatternType> = chains.iter().map(|c| c.pattern_type).collect();
    assert!(types.contains(&IdorPatternType::HorizontalEscalation));
    assert!(types.contains(&IdorPatternType::VerticalEscalation));
    assert!(types.contains(&IdorPatternType::BulkEnumeration));
}

#[test]
fn generate_all_chains_with_all_options() {
    let finding = sample_finding_uuid();
    let graph = build_sample_graph();
    let analysis = analyze_uuid_v1("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap();
    let gql_paths = vec![GraphQlTraversalPath {
        query_path: vec!["node".to_string()],
        target_field: "secret".to_string(),
        requires_variables: vec![],
    }];
    let matrix = build_tampering_matrix(vec![TamperingMatrixEntry {
        endpoint: "/api/documents".to_string(),
        vulnerabilities: vec![ParameterVulnerability {
            parameter: "doc_id".to_string(),
            methods: vec![IdorHttpMethod::Get],
            id_type: IdType::UuidV1,
            confirmed: true,
        }],
    }]);
    let indirect = vec![IndirectReferenceMap {
        encoded_value: "aGVsbG8=".to_string(),
        encoding: IndirectEncoding::Base64,
        decoded_components: vec!["hello".to_string()],
        predicted_pattern: "base64({value})".to_string(),
    }];

    let chains = generate_all_chains(
        &finding,
        Some(&graph),
        Some(&analysis),
        Some(&gql_paths),
        Some(&matrix),
        Some(&indirect),
    );

    let types: std::collections::HashSet<IdorPatternType> =
        chains.iter().map(|c| c.pattern_type).collect();
    assert!(types.contains(&IdorPatternType::HorizontalEscalation));
    assert!(types.contains(&IdorPatternType::VerticalEscalation));
    assert!(types.contains(&IdorPatternType::BulkEnumeration));
    assert!(types.contains(&IdorPatternType::UuidPrediction));
    assert!(types.contains(&IdorPatternType::GraphQlIdor));
    assert!(types.contains(&IdorPatternType::ParameterTampering));
    assert!(types.contains(&IdorPatternType::IndirectReferenceMapping));
    assert!(types.len() >= 7);
}

// ---------------------------------------------------------------------------
// Display impls
// ---------------------------------------------------------------------------

#[test]
fn privilege_level_ordering() {
    assert!(PrivilegeLevel::Anonymous < PrivilegeLevel::User);
    assert!(PrivilegeLevel::User < PrivilegeLevel::Moderator);
    assert!(PrivilegeLevel::Moderator < PrivilegeLevel::Admin);
    assert!(PrivilegeLevel::Admin < PrivilegeLevel::SuperAdmin);
}

#[test]
fn id_type_display() {
    assert_eq!(IdType::Sequential.to_string(), "sequential");
    assert_eq!(IdType::UuidV1.to_string(), "uuid-v1");
    assert_eq!(IdType::UuidV4.to_string(), "uuid-v4");
    assert_eq!(IdType::HashBased.to_string(), "hash-based");
    assert_eq!(IdType::Encoded.to_string(), "encoded");
    assert_eq!(IdType::Composite.to_string(), "composite");
}

#[test]
fn idor_http_method_display() {
    assert_eq!(IdorHttpMethod::Get.to_string(), "GET");
    assert_eq!(IdorHttpMethod::Post.to_string(), "POST");
    assert_eq!(IdorHttpMethod::Put.to_string(), "PUT");
    assert_eq!(IdorHttpMethod::Patch.to_string(), "PATCH");
    assert_eq!(IdorHttpMethod::Delete.to_string(), "DELETE");
}

#[test]
fn indirect_encoding_display() {
    assert_eq!(IndirectEncoding::Base64.to_string(), "base64");
    assert_eq!(IndirectEncoding::Hex.to_string(), "hex");
    assert_eq!(IndirectEncoding::Jwt.to_string(), "jwt");
}

#[test]
fn cross_object_graph_default_is_empty() {
    let graph = CrossObjectGraph::default();
    assert_eq!(graph.node_count(), 0);
    assert_eq!(graph.edge_count(), 0);
}
