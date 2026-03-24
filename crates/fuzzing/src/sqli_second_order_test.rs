use super::sqli_second_order::*;

#[test]
fn generates_at_least_ten_payload_trigger_pairs() {
    let pairs = generate_payload_trigger_pairs();
    assert!(
        pairs.len() >= 10,
        "Expected at least 10 pairs, got {}",
        pairs.len()
    );
}

#[test]
fn all_five_backends_have_time_delay_payloads() {
    let pairs = generate_payload_trigger_pairs();
    for backend in SqlBackend::all() {
        let count = pairs
            .iter()
            .filter(|p| {
                p.payload.backend == *backend
                    && p.payload.verification_method == VerificationMethod::TimeDelay
            })
            .count();
        assert!(count >= 1, "Backend {} has no time-delay payloads", backend);
    }
}

#[test]
fn all_five_backends_have_error_based_payloads() {
    let pairs = generate_payload_trigger_pairs();
    for backend in SqlBackend::all() {
        let count = pairs
            .iter()
            .filter(|p| {
                p.payload.backend == *backend
                    && p.payload.verification_method == VerificationMethod::ErrorBased
            })
            .count();
        assert!(
            count >= 1,
            "Backend {} has no error-based payloads",
            backend
        );
    }
}

#[test]
fn payload_trigger_pairs_have_unique_ids() {
    let pairs = generate_payload_trigger_pairs();
    let mut seen = std::collections::HashSet::new();
    for pair in &pairs {
        assert!(seen.insert(pair.id), "Duplicate pair id: {}", pair.id);
    }
}

#[test]
fn storage_endpoints_are_post_method() {
    let pairs = generate_payload_trigger_pairs();
    for pair in &pairs {
        assert_eq!(
            pair.storage_endpoint.method,
            HttpMethod::Post,
            "Storage endpoint {} should be POST",
            pair.storage_endpoint.path
        );
        assert_eq!(pair.storage_endpoint.role, EndpointRole::Storage);
    }
}

#[test]
fn trigger_endpoints_are_get_method() {
    let pairs = generate_payload_trigger_pairs();
    for pair in &pairs {
        assert_eq!(
            pair.trigger_endpoint.method,
            HttpMethod::Get,
            "Trigger endpoint {} should be GET",
            pair.trigger_endpoint.path
        );
        assert_eq!(pair.trigger_endpoint.role, EndpointRole::Trigger);
    }
}

#[test]
fn time_delay_payloads_have_nonzero_delay() {
    let pairs = generate_payload_trigger_pairs();
    for pair in pairs
        .iter()
        .filter(|p| p.payload.verification_method == VerificationMethod::TimeDelay)
    {
        assert!(
            pair.payload.delay_seconds > 0,
            "Time-delay payload should have nonzero delay"
        );
        assert!(pair.expected_delay_ms() > 0);
    }
}

#[test]
fn error_based_payloads_have_zero_delay() {
    let pairs = generate_payload_trigger_pairs();
    for pair in pairs
        .iter()
        .filter(|p| p.payload.verification_method == VerificationMethod::ErrorBased)
    {
        assert_eq!(
            pair.payload.delay_seconds, 0,
            "Error-based payload should have zero delay"
        );
    }
}

#[test]
fn generate_time_delay_pairs_filters_by_backend() {
    for backend in SqlBackend::all() {
        let pairs = generate_time_delay_pairs(*backend);
        for pair in &pairs {
            assert_eq!(pair.payload.backend, *backend);
            assert_eq!(
                pair.payload.verification_method,
                VerificationMethod::TimeDelay
            );
        }
    }
}

#[test]
fn generate_error_based_pairs_filters_by_backend() {
    for backend in SqlBackend::all() {
        let pairs = generate_error_based_pairs(*backend);
        for pair in &pairs {
            assert_eq!(pair.payload.backend, *backend);
            assert_eq!(
                pair.payload.verification_method,
                VerificationMethod::ErrorBased
            );
        }
    }
}

#[test]
fn identify_storage_vectors_finds_write_endpoints() {
    let endpoints = vec![
        ("/api/register", HttpMethod::Post),
        ("/api/login", HttpMethod::Post),
        ("/api/profile/update", HttpMethod::Put),
        ("/api/users", HttpMethod::Get),
        ("/api/comments/submit", HttpMethod::Post),
    ];
    let storage = identify_storage_vectors(&endpoints);
    assert!(storage.len() >= 3);
    assert!(storage.iter().any(|e| e.path.contains("register")));
    assert!(storage.iter().any(|e| e.path.contains("profile")));
    assert!(storage.iter().any(|e| e.path.contains("comment")));
}

#[test]
fn identify_storage_vectors_ignores_get_endpoints() {
    let endpoints = vec![
        ("/api/register", HttpMethod::Get),
        ("/api/profile", HttpMethod::Get),
    ];
    let storage = identify_storage_vectors(&endpoints);
    assert!(storage.is_empty());
}

#[test]
fn identify_trigger_vectors_finds_admin_endpoints() {
    let endpoints = vec![
        ("/admin/users/list", HttpMethod::Get),
        ("/api/login", HttpMethod::Post),
        ("/admin/export/csv", HttpMethod::Get),
        ("/admin/audit-log", HttpMethod::Get),
        ("/api/health", HttpMethod::Get),
    ];
    let triggers = identify_trigger_vectors(&endpoints);
    assert!(triggers.len() >= 3);
    assert!(triggers.iter().any(|e| e.path.contains("admin")));
    assert!(triggers.iter().any(|e| e.path.contains("export")));
}

#[test]
fn attack_chain_graph_basic_construction() {
    let mut graph = AttackChainGraph::new();
    graph.add_node(ChainNode {
        id: 0,
        endpoint: EndpointDescriptor::storage("/register", HttpMethod::Post, "username"),
        label: "Store".to_string(),
    });
    graph.add_node(ChainNode {
        id: 1,
        endpoint: EndpointDescriptor::trigger("/admin/users", HttpMethod::Get),
        label: "Trigger".to_string(),
    });
    graph.add_edge(ChainEdge {
        from: 0,
        to: 1,
        relationship: ChainRelationship::StoresDataFor,
    });
    assert_eq!(graph.node_count(), 2);
    assert_eq!(graph.edge_count(), 1);
    assert_eq!(graph.neighbors(0), &[1]);
    assert!(graph.neighbors(1).is_empty());
}

#[test]
fn attack_chain_graph_no_duplicate_nodes() {
    let mut graph = AttackChainGraph::new();
    let node = ChainNode {
        id: 0,
        endpoint: EndpointDescriptor::storage("/register", HttpMethod::Post, "username"),
        label: "Store".to_string(),
    };
    graph.add_node(node.clone());
    graph.add_node(node);
    assert_eq!(graph.node_count(), 1);
}

#[test]
fn attack_chain_find_paths_simple() {
    let mut graph = AttackChainGraph::new();
    for i in 0..3 {
        graph.add_node(ChainNode {
            id: i,
            endpoint: EndpointDescriptor::storage(&format!("/ep{i}"), HttpMethod::Post, "x"),
            label: format!("Node{i}"),
        });
    }
    graph.add_edge(ChainEdge {
        from: 0,
        to: 1,
        relationship: ChainRelationship::StoresDataFor,
    });
    graph.add_edge(ChainEdge {
        from: 1,
        to: 2,
        relationship: ChainRelationship::RevealsResultOf,
    });

    let paths = graph.find_attack_paths(0, 2);
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0], vec![0, 1, 2]);
}

#[test]
fn attack_chain_find_paths_multiple() {
    let mut graph = AttackChainGraph::new();
    for i in 0..4 {
        graph.add_node(ChainNode {
            id: i,
            endpoint: EndpointDescriptor::storage(&format!("/ep{i}"), HttpMethod::Post, "x"),
            label: format!("Node{i}"),
        });
    }
    graph.add_edge(ChainEdge {
        from: 0,
        to: 1,
        relationship: ChainRelationship::StoresDataFor,
    });
    graph.add_edge(ChainEdge {
        from: 0,
        to: 2,
        relationship: ChainRelationship::StoresDataFor,
    });
    graph.add_edge(ChainEdge {
        from: 1,
        to: 3,
        relationship: ChainRelationship::RevealsResultOf,
    });
    graph.add_edge(ChainEdge {
        from: 2,
        to: 3,
        relationship: ChainRelationship::RevealsResultOf,
    });

    let paths = graph.find_attack_paths(0, 3);
    assert_eq!(paths.len(), 2);
}

#[test]
fn attack_chain_source_and_sink_nodes() {
    let mut graph = AttackChainGraph::new();
    for i in 0..3 {
        graph.add_node(ChainNode {
            id: i,
            endpoint: EndpointDescriptor::storage(&format!("/ep{i}"), HttpMethod::Post, "x"),
            label: format!("Node{i}"),
        });
    }
    graph.add_edge(ChainEdge {
        from: 0,
        to: 1,
        relationship: ChainRelationship::StoresDataFor,
    });
    graph.add_edge(ChainEdge {
        from: 1,
        to: 2,
        relationship: ChainRelationship::RevealsResultOf,
    });

    let sources = graph.source_nodes();
    assert_eq!(sources, vec![0]);
    let sinks = graph.sink_nodes();
    assert_eq!(sinks, vec![2]);
}

#[test]
fn attack_chain_to_dot_output() {
    let graph = build_three_step_chain(
        EndpointDescriptor::storage("/register", HttpMethod::Post, "username"),
        EndpointDescriptor::trigger("/admin/users", HttpMethod::Get),
        EndpointDescriptor::verification("/admin/errors", HttpMethod::Get),
    );
    let dot = graph.to_dot();
    assert!(dot.contains("digraph attack_chain"));
    assert!(dot.contains("/register"));
    assert!(dot.contains("/admin/users"));
    assert!(dot.contains("/admin/errors"));
    assert!(dot.contains("stores-data-for"));
    assert!(dot.contains("reveals-result-of"));
    assert!(dot.contains("box"));
    assert!(dot.contains("diamond"));
    assert!(dot.contains("ellipse"));
}

#[test]
fn build_attack_chain_creates_full_graph() {
    let storage = vec![
        EndpointDescriptor::storage("/api/register", HttpMethod::Post, "username"),
        EndpointDescriptor::storage("/api/comments", HttpMethod::Post, "body"),
    ];
    let trigger = vec![EndpointDescriptor::trigger("/admin/users", HttpMethod::Get)];
    let verify = vec![EndpointDescriptor::verification(
        "/admin/errors",
        HttpMethod::Get,
    )];

    let graph = build_attack_chain(&storage, &trigger, &verify);
    assert_eq!(graph.node_count(), 4);
    assert_eq!(graph.edge_count(), 3);
}

#[test]
fn build_three_step_chain_structure() {
    let graph = build_three_step_chain(
        EndpointDescriptor::storage("/register", HttpMethod::Post, "username"),
        EndpointDescriptor::trigger("/admin/users", HttpMethod::Get),
        EndpointDescriptor::verification("/admin/errors", HttpMethod::Get),
    );
    assert_eq!(graph.node_count(), 3);
    assert_eq!(graph.edge_count(), 2);
    let paths = graph.find_attack_paths(0, 2);
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0], vec![0, 1, 2]);
}

#[test]
fn fingerprint_backend_detects_mysql() {
    let body = "You have an error in your SQL syntax; check the manual";
    let results = fingerprint_backend(body);
    assert!(!results.is_empty());
    assert_eq!(results[0].detected_backend, SqlBackend::MySQL);
    assert!(results[0].confidence >= 0.90);
}

#[test]
fn fingerprint_backend_detects_postgresql() {
    let body = "PSQLException: unterminated quoted string at or near";
    let results = fingerprint_backend(body);
    assert!(results.len() >= 2);
    let pg_results: Vec<_> = results
        .iter()
        .filter(|r| r.detected_backend == SqlBackend::PostgreSQL)
        .collect();
    assert!(!pg_results.is_empty());
}

#[test]
fn fingerprint_backend_detects_mssql() {
    let body = "Microsoft SQL Server error 'Unclosed quotation mark after the character string'";
    let results = fingerprint_backend(body);
    let mssql_results: Vec<_> = results
        .iter()
        .filter(|r| r.detected_backend == SqlBackend::MSSQL)
        .collect();
    assert!(mssql_results.len() >= 2);
}

#[test]
fn fingerprint_backend_detects_oracle() {
    let body = "ORA-01756: quoted string not properly terminated";
    let results = fingerprint_backend(body);
    assert!(!results.is_empty());
    assert_eq!(results[0].detected_backend, SqlBackend::Oracle);
}

#[test]
fn fingerprint_backend_detects_sqlite() {
    let body = "SQLITE_ERROR near \": syntax error";
    let results = fingerprint_backend(body);
    let sqlite_results: Vec<_> = results
        .iter()
        .filter(|r| r.detected_backend == SqlBackend::SQLite)
        .collect();
    assert!(!sqlite_results.is_empty());
}

#[test]
fn fingerprint_backend_returns_empty_for_unknown() {
    let body = "An unexpected error occurred. Please try again.";
    let results = fingerprint_backend(body);
    assert!(results.is_empty());
}

#[test]
fn timing_analysis_detects_triggered_delay() {
    let analysis = analyze_timing_response(100, 5200, 5000);
    assert!(analysis.triggered);
    assert!(analysis.confidence > 0.0);
    assert_eq!(analysis.difference_ms, 5100);
}

#[test]
fn timing_analysis_rejects_insufficient_delay() {
    let analysis = analyze_timing_response(100, 200, 5000);
    assert!(!analysis.triggered);
    assert_eq!(analysis.confidence, 0.0);
}

#[test]
fn timing_analysis_threshold_at_80_percent() {
    let analysis = analyze_timing_response(0, 4000, 5000);
    assert!(analysis.triggered, "80% of expected delay should trigger");
    let analysis_below = analyze_timing_response(0, 3900, 5000);
    assert!(
        !analysis_below.triggered,
        "Below 80% of expected delay should not trigger"
    );
}

#[test]
fn campaign_summary_covers_all_backends() {
    let pairs = generate_payload_trigger_pairs();
    let summary = summarize_campaign(&pairs);
    assert_eq!(summary.total_pairs, pairs.len());
    for backend in SqlBackend::all() {
        assert!(
            summary.pairs_by_backend.contains_key(backend),
            "Campaign missing backend: {}",
            backend
        );
    }
}

#[test]
fn campaign_summary_tracks_unique_endpoints() {
    let pairs = generate_payload_trigger_pairs();
    let summary = summarize_campaign(&pairs);
    assert!(summary.unique_storage_endpoints > 0);
    assert!(summary.unique_trigger_endpoints > 0);
}

#[test]
fn campaign_summary_has_multiple_verification_methods() {
    let pairs = generate_payload_trigger_pairs();
    let summary = summarize_campaign(&pairs);
    assert!(
        summary.pairs_by_method.len() >= 2,
        "Expected at least 2 verification methods"
    );
}

#[test]
fn endpoint_descriptor_builder_methods() {
    let storage = EndpointDescriptor::storage("/register", HttpMethod::Post, "username");
    assert_eq!(storage.role, EndpointRole::Storage);
    assert_eq!(storage.parameter, "username");
    assert_eq!(storage.content_type, "application/json");

    let trigger =
        EndpointDescriptor::trigger("/admin/users", HttpMethod::Get).with_content_type("text/html");
    assert_eq!(trigger.role, EndpointRole::Trigger);
    assert_eq!(trigger.content_type, "text/html");

    let verify = EndpointDescriptor::verification("/errors", HttpMethod::Get);
    assert_eq!(verify.role, EndpointRole::Verification);
}

#[test]
fn display_impls_return_expected_labels() {
    assert_eq!(format!("{}", SqlBackend::MySQL), "mysql");
    assert_eq!(format!("{}", SqlBackend::PostgreSQL), "postgresql");
    assert_eq!(format!("{}", HttpMethod::Post), "POST");
    assert_eq!(format!("{}", EndpointRole::Storage), "storage");
    assert_eq!(format!("{}", VerificationMethod::TimeDelay), "time-delay");
    assert_eq!(
        format!("{}", StoragePattern::UserRegistration),
        "user-registration"
    );
    assert_eq!(
        format!("{}", TriggerPattern::AdminUserList),
        "admin-user-list"
    );
    assert_eq!(
        format!("{}", ChainRelationship::StoresDataFor),
        "stores-data-for"
    );
}

#[test]
fn sql_backend_all_returns_five_variants() {
    assert_eq!(SqlBackend::all().len(), 5);
}

#[test]
fn content_diff_payloads_cover_all_backends() {
    let pairs = generate_payload_trigger_pairs();
    for backend in SqlBackend::all() {
        let count = pairs
            .iter()
            .filter(|p| {
                p.payload.backend == *backend
                    && p.payload.verification_method == VerificationMethod::ContentDiff
            })
            .count();
        assert!(
            count >= 1,
            "Backend {} has no content-diff payloads",
            backend
        );
    }
}
