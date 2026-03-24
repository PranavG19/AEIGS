use super::idor_detector::*;

#[test]
fn classify_sequential_integer() {
    let result = IdorDetector::classify_id("12345").unwrap();
    assert_eq!(result.pattern, IdPatternType::Sequential);
    assert!(result.confidence > 0.8);
}

#[test]
fn classify_large_sequential_integer() {
    let result = IdorDetector::classify_id("9999999999").unwrap();
    assert_eq!(result.pattern, IdPatternType::Sequential);
}

#[test]
fn classify_uuid_v4() {
    let result = IdorDetector::classify_id("550e8400-e29b-41d4-a716-446655440000").unwrap();
    assert_eq!(result.pattern, IdPatternType::UuidV4);
    assert!(result.confidence > 0.8);
}

#[test]
fn classify_uuid_v1() {
    let result = IdorDetector::classify_id("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap();
    assert_eq!(result.pattern, IdPatternType::UuidV1);
    assert!(result.confidence > 0.9);
}

#[test]
fn classify_base64_encoded() {
    let result = IdorDetector::classify_id("dXNlcl8xMjM=").unwrap();
    assert_eq!(result.pattern, IdPatternType::Base64Encoded);
    assert!(result.decoded_value.is_some());
    assert_eq!(result.decoded_value.unwrap(), "user_123");
}

#[test]
fn classify_hex_encoded() {
    // "user1" = 75 73 65 72 31 — but that's all decimal digits too.
    // Use "Hello" = 48 65 6c 6c 6f which has non-decimal hex chars.
    let result = IdorDetector::classify_id("48656c6c6f").unwrap();
    assert_eq!(result.pattern, IdPatternType::HexEncoded);
    assert!(result.decoded_value.is_some());
    assert_eq!(result.decoded_value.unwrap(), "Hello");
}

#[test]
fn classify_hashid() {
    // Hashid requires mixed case + digits + alpha, length >= 5.
    // Must NOT match base64 heuristics (no +/=, and the base64 classifier
    // requires padding or special chars or mixed case — but mixed case alone
    // with length%4!=0 and no b64 specials won't trigger base64 since
    // padding_ok is false and has_b64_special is false).
    // Use 5-char value with mixed case+digit that has len%4=1.
    let result = IdorDetector::classify_id("aB3xY").unwrap();
    assert_eq!(result.pattern, IdPatternType::Hashid);
    assert!(result.confidence > 0.5);
}

#[test]
fn classify_empty_returns_none() {
    assert!(IdorDetector::classify_id("").is_none());
}

#[test]
fn supported_patterns_has_six_types() {
    let types = IdorDetector::supported_pattern_types();
    assert!(types.len() >= 6);
}

#[test]
fn uuid_v1_analysis_extracts_components() {
    let uuid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    let components = IdorDetector::analyze_uuid_v1(uuid).unwrap();
    assert!(!components.timestamp_hex.is_empty());
    assert!(components.timestamp_100ns_intervals > 0);
    assert_eq!(components.mac_address.matches(':').count(), 5);
    assert!(components.is_predictable);
}

#[test]
fn uuid_v1_analysis_rejects_v4() {
    let uuid_v4 = "550e8400-e29b-41d4-a716-446655440000";
    assert!(IdorDetector::analyze_uuid_v1(uuid_v4).is_none());
}

#[test]
fn uuid_v1_analysis_rejects_garbage() {
    assert!(IdorDetector::analyze_uuid_v1("not-a-uuid").is_none());
    assert!(IdorDetector::analyze_uuid_v1("").is_none());
}

#[test]
fn reference_point_discovery_finds_id_params() {
    let endpoints = vec![EndpointDescriptor {
        path: "/api/users/:user_id/orders".to_string(),
        method: "GET".to_string(),
        parameters: vec![
            ParameterDescriptor {
                name: "user_id".to_string(),
                location: ParameterLocation::Query,
                sample_value: Some("42".to_string()),
            },
            ParameterDescriptor {
                name: "sort".to_string(),
                location: ParameterLocation::Query,
                sample_value: Some("desc".to_string()),
            },
        ],
        requires_auth: true,
        admin_only: false,
    }];
    let refs = IdorDetector::discover_reference_points(&endpoints);
    assert!(refs.iter().any(|r| r.parameter_name == "user_id"));
    let user_ref = refs.iter().find(|r| r.parameter_name == "user_id").unwrap();
    assert_eq!(user_ref.pattern, IdPatternType::Sequential);
    assert!(user_ref.resource_type.is_some());
}

#[test]
fn reference_point_discovery_extracts_path_placeholders() {
    let endpoints = vec![EndpointDescriptor {
        path: "/api/orders/{order_id}".to_string(),
        method: "GET".to_string(),
        parameters: vec![],
        requires_auth: true,
        admin_only: false,
    }];
    let refs = IdorDetector::discover_reference_points(&endpoints);
    assert!(refs.iter().any(|r| r.parameter_name == "order_id"));
    let order_ref = refs
        .iter()
        .find(|r| r.parameter_name == "order_id")
        .unwrap();
    assert_eq!(order_ref.location, ParameterLocation::Path);
    assert_eq!(order_ref.resource_type, Some("orders".to_string()));
}

#[test]
fn response_diff_full_access() {
    let body = r#"{"id": 1, "name": "Alice", "email": "alice@example.com"}"#;
    let diff = IdorDetector::diff_responses(200, body, 200, body);
    assert_eq!(diff.access_result, AccessResult::FullAccess);
    assert!((diff.body_similarity - 1.0).abs() < f64::EPSILON);
}

#[test]
fn response_diff_denied() {
    let body_a = r#"{"id": 1, "name": "Alice"}"#;
    let body_b = r#"{"error": "forbidden"}"#;
    let diff = IdorDetector::diff_responses(200, body_a, 403, body_b);
    assert_eq!(diff.access_result, AccessResult::Error);
}

#[test]
fn response_diff_partial_access() {
    let body_a =
        r#"{"id": 1, "name": "Alice", "email": "alice@example.com", "ssn": "123-45-6789"}"#;
    let body_b = r#"{"id": 1, "name": "Alice", "email": "alice@example.com"}"#;
    let diff = IdorDetector::diff_responses(200, body_a, 200, body_b);
    assert!(
        diff.access_result == AccessResult::PartialAccess
            || diff.access_result == AccessResult::FullAccess
    );
}

#[test]
fn response_diff_error_status() {
    let diff = IdorDetector::diff_responses(200, "{}", 500, "Internal Server Error");
    assert_eq!(diff.access_result, AccessResult::Error);
}

#[test]
fn horizontal_test_plan_generation() {
    let endpoints = vec![EndpointDescriptor {
        path: "/api/users/profile".to_string(),
        method: "GET".to_string(),
        parameters: vec![ParameterDescriptor {
            name: "user_id".to_string(),
            location: ParameterLocation::Query,
            sample_value: Some("100".to_string()),
        }],
        requires_auth: true,
        admin_only: false,
    }];
    let known_ids = vec![("user_id", "100"), ("user_id", "200"), ("user_id", "300")];
    let plans = IdorDetector::plan_horizontal_tests(&endpoints, &known_ids);
    assert!(!plans.is_empty());
    let plan = &plans[0];
    assert_eq!(plan.target_parameter, "user_id");
    assert_eq!(plan.original_id, "100");
    assert!(!plan.replacement_ids.is_empty());
    assert!(plan
        .replacement_ids
        .iter()
        .any(|r| r == "200" || r == "300"));
}

#[test]
fn horizontal_test_skips_admin_endpoints() {
    let endpoints = vec![EndpointDescriptor {
        path: "/admin/users".to_string(),
        method: "GET".to_string(),
        parameters: vec![ParameterDescriptor {
            name: "user_id".to_string(),
            location: ParameterLocation::Query,
            sample_value: Some("1".to_string()),
        }],
        requires_auth: true,
        admin_only: true,
    }];
    let plans = IdorDetector::plan_horizontal_tests(&endpoints, &[]);
    assert!(plans.is_empty());
}

#[test]
fn vertical_test_plan_for_admin_endpoint() {
    let endpoints = vec![EndpointDescriptor {
        path: "/admin/config".to_string(),
        method: "GET".to_string(),
        parameters: vec![],
        requires_auth: true,
        admin_only: true,
    }];
    let plans = IdorDetector::plan_vertical_tests(&endpoints);
    assert_eq!(plans.len(), 2);
    assert!(plans
        .iter()
        .any(|p| p.test_with_privilege == PrivilegeLevel::RegularUser));
    assert!(plans
        .iter()
        .any(|p| p.test_with_privilege == PrivilegeLevel::Unauthenticated));
}

#[test]
fn vertical_test_plan_for_auth_endpoint() {
    let endpoints = vec![EndpointDescriptor {
        path: "/api/profile".to_string(),
        method: "GET".to_string(),
        parameters: vec![],
        requires_auth: true,
        admin_only: false,
    }];
    let plans = IdorDetector::plan_vertical_tests(&endpoints);
    assert_eq!(plans.len(), 1);
    assert_eq!(
        plans[0].test_with_privilege,
        PrivilegeLevel::Unauthenticated
    );
}

#[test]
fn chain_detection_listing_to_detail() {
    let endpoints = vec![
        EndpointDescriptor {
            path: "/api/orders".to_string(),
            method: "GET".to_string(),
            parameters: vec![],
            requires_auth: true,
            admin_only: false,
        },
        EndpointDescriptor {
            path: "/api/orders/:id".to_string(),
            method: "GET".to_string(),
            parameters: vec![],
            requires_auth: true,
            admin_only: false,
        },
    ];
    let chains = IdorDetector::detect_chains(&endpoints);
    assert!(!chains.is_empty());
    assert!(chains[0].steps.len() >= 2);
}

#[test]
fn chain_detection_listing_to_mutation() {
    let endpoints = vec![
        EndpointDescriptor {
            path: "/api/orders".to_string(),
            method: "GET".to_string(),
            parameters: vec![],
            requires_auth: true,
            admin_only: false,
        },
        EndpointDescriptor {
            path: "/api/orders/:id".to_string(),
            method: "DELETE".to_string(),
            parameters: vec![],
            requires_auth: true,
            admin_only: false,
        },
    ];
    let chains = IdorDetector::detect_chains(&endpoints);
    assert!(chains.iter().any(|c| c.severity == ChainSeverity::High));
}

#[test]
fn chain_detection_privilege_escalation() {
    let endpoints = vec![
        EndpointDescriptor {
            path: "/api/users".to_string(),
            method: "GET".to_string(),
            parameters: vec![],
            requires_auth: false,
            admin_only: false,
        },
        EndpointDescriptor {
            path: "/api/users/:id".to_string(),
            method: "GET".to_string(),
            parameters: vec![],
            requires_auth: true,
            admin_only: true,
        },
    ];
    let chains = IdorDetector::detect_chains(&endpoints);
    assert!(chains.iter().any(|c| c.severity == ChainSeverity::Critical));
}

#[test]
fn bulk_enumeration_plan_for_sequential() {
    let endpoints = vec![EndpointDescriptor {
        path: "/api/invoices".to_string(),
        method: "GET".to_string(),
        parameters: vec![ParameterDescriptor {
            name: "invoice_id".to_string(),
            location: ParameterLocation::Query,
            sample_value: Some("500".to_string()),
        }],
        requires_auth: true,
        admin_only: false,
    }];
    let plans = IdorDetector::plan_bulk_enumeration(&endpoints);
    assert!(!plans.is_empty());
    let plan = &plans[0];
    assert_eq!(plan.pattern, IdPatternType::Sequential);
    assert_eq!(plan.start_value, "400");
    assert!(plan.estimated_range > 0);
}

#[test]
fn bulk_enumeration_skips_non_get() {
    let endpoints = vec![EndpointDescriptor {
        path: "/api/invoices".to_string(),
        method: "POST".to_string(),
        parameters: vec![ParameterDescriptor {
            name: "invoice_id".to_string(),
            location: ParameterLocation::Body,
            sample_value: Some("500".to_string()),
        }],
        requires_auth: true,
        admin_only: false,
    }];
    let plans = IdorDetector::plan_bulk_enumeration(&endpoints);
    assert!(plans.is_empty());
}

#[test]
fn id_pattern_type_display() {
    assert_eq!(
        format!("{}", IdPatternType::Sequential),
        "sequential_integer"
    );
    assert_eq!(format!("{}", IdPatternType::UuidV1), "uuid_v1");
    assert_eq!(format!("{}", IdPatternType::UuidV4), "uuid_v4");
    assert_eq!(
        format!("{}", IdPatternType::Base64Encoded),
        "base64_encoded"
    );
    assert_eq!(format!("{}", IdPatternType::HexEncoded), "hex_encoded");
    assert_eq!(format!("{}", IdPatternType::Hashid), "hashid");
}

#[test]
fn privilege_level_display() {
    assert_eq!(
        format!("{}", PrivilegeLevel::Unauthenticated),
        "unauthenticated"
    );
    assert_eq!(format!("{}", PrivilegeLevel::RegularUser), "regular_user");
    assert_eq!(format!("{}", PrivilegeLevel::Admin), "admin");
}

#[test]
fn chain_severity_display() {
    assert_eq!(format!("{}", ChainSeverity::Low), "low");
    assert_eq!(format!("{}", ChainSeverity::Critical), "critical");
}

#[test]
fn access_result_display() {
    assert_eq!(format!("{}", AccessResult::FullAccess), "full_access");
    assert_eq!(format!("{}", AccessResult::Denied), "denied");
    assert_eq!(format!("{}", AccessResult::PartialAccess), "partial_access");
    assert_eq!(format!("{}", AccessResult::Error), "error");
}

#[test]
fn parameter_location_display() {
    assert_eq!(format!("{}", ParameterLocation::Path), "path");
    assert_eq!(format!("{}", ParameterLocation::Query), "query");
    assert_eq!(format!("{}", ParameterLocation::Body), "body");
    assert_eq!(format!("{}", ParameterLocation::Header), "header");
}

#[test]
fn body_similarity_identical() {
    let diff = IdorDetector::diff_responses(200, "hello", 200, "hello");
    assert!((diff.body_similarity - 1.0).abs() < f64::EPSILON);
}

#[test]
fn body_similarity_empty() {
    let diff = IdorDetector::diff_responses(200, "", 200, "");
    assert!((diff.body_similarity - 1.0).abs() < f64::EPSILON);
}

#[test]
fn body_similarity_completely_different() {
    let diff = IdorDetector::diff_responses(200, "abcdefghijklmnop", 200, "zyxwvutsrqponmlk");
    assert!(diff.body_similarity < 0.5);
}

#[test]
fn classify_base64_with_padding() {
    let result = IdorDetector::classify_id("SGVsbG8=").unwrap();
    assert_eq!(result.pattern, IdPatternType::Base64Encoded);
    assert_eq!(result.decoded_value.as_deref(), Some("Hello"));
}

#[test]
fn base64_with_special_chars() {
    let result = IdorDetector::classify_id("YWJj+ZGVm/w==").unwrap();
    assert_eq!(result.pattern, IdPatternType::Base64Encoded);
}

#[test]
fn hex_encoded_detection() {
    let result = IdorDetector::classify_id("48656c6c6f").unwrap();
    assert_eq!(result.pattern, IdPatternType::HexEncoded);
    assert_eq!(result.decoded_value.as_deref(), Some("Hello"));
}

#[test]
fn vertical_test_no_auth_no_plans() {
    let endpoints = vec![EndpointDescriptor {
        path: "/public/health".to_string(),
        method: "GET".to_string(),
        parameters: vec![],
        requires_auth: false,
        admin_only: false,
    }];
    let plans = IdorDetector::plan_vertical_tests(&endpoints);
    assert!(plans.is_empty());
}

#[test]
fn horizontal_test_generates_adjacent_ids() {
    let endpoints = vec![EndpointDescriptor {
        path: "/api/docs".to_string(),
        method: "GET".to_string(),
        parameters: vec![ParameterDescriptor {
            name: "document_id".to_string(),
            location: ParameterLocation::Query,
            sample_value: Some("50".to_string()),
        }],
        requires_auth: true,
        admin_only: false,
    }];
    let plans = IdorDetector::plan_horizontal_tests(&endpoints, &[]);
    assert!(!plans.is_empty());
    let plan = &plans[0];
    assert!(plan.replacement_ids.contains(&"49".to_string()));
    assert!(plan.replacement_ids.contains(&"51".to_string()));
}

#[test]
fn multiple_endpoints_chain_detection() {
    let endpoints = vec![
        EndpointDescriptor {
            path: "/api/products".to_string(),
            method: "GET".to_string(),
            parameters: vec![],
            requires_auth: false,
            admin_only: false,
        },
        EndpointDescriptor {
            path: "/api/products/:id".to_string(),
            method: "GET".to_string(),
            parameters: vec![],
            requires_auth: false,
            admin_only: false,
        },
        EndpointDescriptor {
            path: "/api/products/:id".to_string(),
            method: "PUT".to_string(),
            parameters: vec![],
            requires_auth: true,
            admin_only: false,
        },
        EndpointDescriptor {
            path: "/api/products/:id".to_string(),
            method: "DELETE".to_string(),
            parameters: vec![],
            requires_auth: true,
            admin_only: true,
        },
    ];
    let chains = IdorDetector::detect_chains(&endpoints);
    assert!(chains.len() >= 2);
}

#[test]
fn uuid_v1_mac_address_format() {
    let uuid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    let components = IdorDetector::analyze_uuid_v1(uuid).unwrap();
    let mac_parts: Vec<&str> = components.mac_address.split(':').collect();
    assert_eq!(mac_parts.len(), 6);
    for part in mac_parts {
        assert_eq!(part.len(), 2);
        assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[test]
fn reference_discovery_deduplicates() {
    let endpoints = vec![
        EndpointDescriptor {
            path: "/api/users".to_string(),
            method: "GET".to_string(),
            parameters: vec![ParameterDescriptor {
                name: "user_id".to_string(),
                location: ParameterLocation::Query,
                sample_value: Some("1".to_string()),
            }],
            requires_auth: true,
            admin_only: false,
        },
        EndpointDescriptor {
            path: "/api/orders".to_string(),
            method: "GET".to_string(),
            parameters: vec![ParameterDescriptor {
                name: "user_id".to_string(),
                location: ParameterLocation::Query,
                sample_value: Some("2".to_string()),
            }],
            requires_auth: true,
            admin_only: false,
        },
    ];
    let refs = IdorDetector::discover_reference_points(&endpoints);
    let user_id_refs: Vec<_> = refs
        .iter()
        .filter(|r| r.parameter_name == "user_id" && r.location == ParameterLocation::Query)
        .collect();
    assert_eq!(user_id_refs.len(), 1);
}
