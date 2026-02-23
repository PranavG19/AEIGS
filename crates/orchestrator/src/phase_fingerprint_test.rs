use super::*;

use aegis_fuzzing::{BotDetectionProfile, DefenseProfile, RateLimitProfile, WafProfile, WafVendor};
use aegis_knowledge_graph::graph::KnowledgeGraph;
use aegis_protocol::edge::EdgeLabel;
use aegis_protocol::operation::GraphOperation;
use clap::Parser;
use pipeline::apply_stealth_adjustments;

fn test_config() -> ScanConfig {
    ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080"]).unwrap()
}

fn test_context() -> ScanContext {
    let mut capabilities =
        aegis_supervisor::capability_manager::CapabilityManager::new(vec![0u8; 32]);
    pipeline::register_default_policies(&mut capabilities);
    ScanContext {
        config: test_config(),
        graph: Box::new(KnowledgeGraph::new()),
        defense_profile: None,
        capabilities,
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    }
}

#[test]
fn run_fingerprint_adds_defense_node() {
    let mut ctx = test_context();
    let before = ctx.graph.node_count().unwrap();

    let result = run_fingerprint(&mut ctx).unwrap();

    assert_eq!(ctx.graph.node_count().unwrap(), before + 1);
    assert_eq!(result.operations_applied, 1);
}

#[test]
fn run_fingerprint_sets_defense_profile() {
    let mut ctx = test_context();
    assert!(ctx.defense_profile.is_none());

    run_fingerprint(&mut ctx).unwrap();

    assert!(ctx.defense_profile.is_some());
}

#[test]
fn defense_properties_empty_profile_returns_empty() {
    let profile = DefenseProfile::empty(0);

    let props = phase_fingerprint::defense_properties(&profile);

    assert!(props.is_empty());
}

#[test]
fn defense_properties_waf_profile_includes_vendor_and_code() {
    let profile = DefenseProfile::empty(0).with_waf(WafProfile {
        vendor: WafVendor::Cloudflare,
        paranoia_level: None,
        blocked_response_code: 403,
        blocked_categories: vec![],
    });

    let props = phase_fingerprint::defense_properties(&profile);

    let keys: Vec<&str> = props.iter().map(|(k, _)| k.as_str()).collect();
    assert!(keys.contains(&"waf_vendor"));
    assert!(keys.contains(&"waf_blocked_code"));
    let code = props.iter().find(|(k, _)| k == "waf_blocked_code").unwrap();
    assert_eq!(code.1, "403");
}

#[test]
fn defense_properties_rate_limit_includes_code() {
    let profile = DefenseProfile::empty(0).with_rate_limit(RateLimitProfile {
        requests_per_second: Some(100.0),
        burst_allowance: Some(10),
        limit_response_code: 429,
        limit_window_seconds: Some(60),
    });

    let props = phase_fingerprint::defense_properties(&profile);

    let entry = props.iter().find(|(k, _)| k == "rate_limit_code").unwrap();
    assert_eq!(entry.1, "429");
}

#[test]
fn defense_properties_bot_detection_includes_detected() {
    let profile = DefenseProfile::empty(0).with_bot_detection(BotDetectionProfile {
        detected: true,
        detection_method: "js_challenge".to_string(),
        challenge_response_code: Some(503),
    });

    let props = phase_fingerprint::defense_properties(&profile);

    let entry = props.iter().find(|(k, _)| k == "bot_detected").unwrap();
    assert_eq!(entry.1, "true");
}

#[test]
fn build_protected_by_edges_creates_correct_edges() {
    let defense_node_id = 42;
    let endpoint_ids = vec![10, 20, 30];

    let entries = build_protected_by_edges(defense_node_id, &endpoint_ids, 0);

    assert_eq!(entries.len(), 3);
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(entry.sequence_number, i as u64 + 1);
        match &entry.operation {
            GraphOperation::AddEdge {
                source_node_id,
                target_node_id,
                label,
                weight,
            } => {
                assert_eq!(*source_node_id, endpoint_ids[i]);
                assert_eq!(*target_node_id, defense_node_id);
                assert!(matches!(label, EdgeLabel::ProtectedBy));
                assert!((weight - 1.0).abs() < f64::EPSILON);
            }
            _ => panic!("expected AddEdge operation"),
        }
    }
}

#[test]
fn build_protected_by_edges_empty_endpoints_returns_empty() {
    let entries = build_protected_by_edges(42, &[], 0);

    assert!(entries.is_empty());
}

#[test]
fn endpoint_properties_includes_path_and_method() {
    use aegis_enumeration::introspection::IntrospectedEndpoint;

    let ep = IntrospectedEndpoint {
        path: "/api/users".to_string(),
        method: "GET".to_string(),
        parameters: vec![],
        response_type: None,
        description: None,
        security_schemes: vec![],
        request_content_types: vec![],
        response_status_codes: vec![],
    };

    let props = phase_fingerprint::endpoint_properties(&ep);

    let map: std::collections::HashMap<&str, &str> = props
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(map["path"], "/api/users");
    assert_eq!(map["method"], "GET");
    assert!(!map.contains_key("parameters"));
    assert!(!map.contains_key("request_content_types"));
}

#[test]
fn endpoint_properties_serializes_parameters_as_json() {
    use aegis_enumeration::introspection::{
        EndpointParameter, IntrospectedEndpoint, ParameterLocation,
    };

    let ep = IntrospectedEndpoint {
        path: "/api/items".to_string(),
        method: "POST".to_string(),
        parameters: vec![
            EndpointParameter {
                name: "id".to_string(),
                location: ParameterLocation::Path,
                param_type: "integer".to_string(),
                required: true,
            },
            EndpointParameter {
                name: "q".to_string(),
                location: ParameterLocation::Query,
                param_type: "string".to_string(),
                required: false,
            },
            EndpointParameter {
                name: "payload".to_string(),
                location: ParameterLocation::Body,
                param_type: "object".to_string(),
                required: true,
            },
        ],
        response_type: None,
        description: None,
        security_schemes: vec![],
        request_content_types: vec!["application/json".to_string()],
        response_status_codes: vec![],
    };

    let props = phase_fingerprint::endpoint_properties(&ep);
    let map: std::collections::HashMap<&str, &str> = props
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let params_json: Vec<serde_json::Value> =
        serde_json::from_str(map["parameters"]).expect("parameters should be valid JSON");
    assert_eq!(params_json.len(), 3);
    assert_eq!(params_json[0]["name"], "id");
    assert_eq!(params_json[0]["location"], "Path");
    assert_eq!(params_json[0]["param_type"], "integer");
    assert_eq!(params_json[0]["required"], true);
    assert_eq!(params_json[1]["name"], "q");
    assert_eq!(params_json[1]["location"], "Query");
    assert_eq!(params_json[1]["required"], false);
    assert_eq!(params_json[2]["name"], "payload");
    assert_eq!(params_json[2]["location"], "Body");

    let content_types: Vec<String> =
        serde_json::from_str(map["request_content_types"]).expect("content types should be JSON");
    assert_eq!(content_types, vec!["application/json"]);
}

#[test]
fn endpoints_to_operations_creates_endpoint_nodes() {
    use aegis_enumeration::introspection::{
        EndpointParameter, IntrospectedEndpoint, ParameterLocation,
    };
    use aegis_protocol::node::NodeType;

    let endpoints = vec![
        IntrospectedEndpoint {
            path: "/api/users".to_string(),
            method: "GET".to_string(),
            parameters: vec![EndpointParameter {
                name: "page".to_string(),
                location: ParameterLocation::Query,
                param_type: "integer".to_string(),
                required: false,
            }],
            response_type: None,
            description: None,
            security_schemes: vec![],
            request_content_types: vec![],
            response_status_codes: vec![],
        },
        IntrospectedEndpoint {
            path: "/api/users".to_string(),
            method: "POST".to_string(),
            parameters: vec![EndpointParameter {
                name: "name".to_string(),
                location: ParameterLocation::Body,
                param_type: "string".to_string(),
                required: true,
            }],
            response_type: None,
            description: None,
            security_schemes: vec![],
            request_content_types: vec!["application/json".to_string()],
            response_status_codes: vec![],
        },
    ];

    let mut seq = 0u64;
    let ops = phase_fingerprint::endpoints_to_operations(&endpoints, &mut seq);

    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);

    for (i, op) in ops.iter().enumerate() {
        assert_eq!(op.sequence_number, (i + 1) as u64);
        match &op.operation {
            GraphOperation::AddNode {
                node_type,
                properties,
            } => {
                assert_eq!(*node_type, NodeType::Endpoint);
                let map: std::collections::HashMap<&str, &str> = properties
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                assert_eq!(map["path"], endpoints[i].path);
                assert_eq!(map["method"], endpoints[i].method);
                assert!(map.contains_key("parameters"));
            }
            _ => panic!("expected AddNode operation"),
        }
    }
}

#[test]
fn endpoints_to_operations_applied_to_graph_stores_parameters() {
    use aegis_enumeration::introspection::{
        EndpointParameter, IntrospectedEndpoint, ParameterLocation,
    };

    let mut ctx = test_context();
    let endpoints = vec![IntrospectedEndpoint {
        path: "/graphql".to_string(),
        method: "POST".to_string(),
        parameters: vec![
            EndpointParameter {
                name: "query".to_string(),
                location: ParameterLocation::Body,
                param_type: "string".to_string(),
                required: true,
            },
            EndpointParameter {
                name: "auth".to_string(),
                location: ParameterLocation::Header,
                param_type: "string".to_string(),
                required: false,
            },
        ],
        response_type: None,
        description: None,
        security_schemes: vec![],
        request_content_types: vec!["application/json".to_string()],
        response_status_codes: vec![],
    }];

    let mut seq = 0u64;
    let ops = phase_fingerprint::endpoints_to_operations(&endpoints, &mut seq);
    ctx.graph.apply_operations(&ops).unwrap();

    let endpoint_ids = ctx
        .graph
        .nodes_by_type(aegis_protocol::node::NodeType::Endpoint)
        .unwrap();
    assert_eq!(endpoint_ids.len(), 1);

    let node = ctx.graph.get_node(endpoint_ids[0]).unwrap().unwrap();
    assert_eq!(node.properties["path"], "/graphql");
    assert_eq!(node.properties["method"], "POST");

    let params_json: Vec<serde_json::Value> =
        serde_json::from_str(&node.properties["parameters"]).unwrap();
    assert_eq!(params_json.len(), 2);
    assert_eq!(params_json[0]["name"], "query");
    assert_eq!(params_json[0]["location"], "Body");
    assert_eq!(params_json[0]["required"], true);
    assert_eq!(params_json[1]["name"], "auth");
    assert_eq!(params_json[1]["location"], "Header");

    let content_types: Vec<String> =
        serde_json::from_str(&node.properties["request_content_types"]).unwrap();
    assert_eq!(content_types, vec!["application/json"]);
}

#[test]
fn probe_defenses_unreachable_target_returns_empty_profile() {
    let profile = probe_defenses("http://localhost:19999");

    assert!(profile.waf.is_none());
    assert!(profile.rate_limit.is_none());
    assert!(profile.bot_detection.is_none());
    assert!(profile.fingerprint_timestamp_ms > 0);
}

#[test]
fn apply_stealth_adjustments_waf_caps_rps() {
    let mut config = test_config();
    assert!(config.stealth.max_rps.is_none());

    let profile = DefenseProfile::empty(0).with_waf(WafProfile {
        vendor: WafVendor::ModSecurity,
        paranoia_level: Some(2),
        blocked_response_code: 403,
        blocked_categories: vec![],
    });

    apply_stealth_adjustments(&mut config, &profile);

    assert_eq!(config.stealth.max_rps, Some(5));
}

#[test]
fn apply_stealth_adjustments_waf_does_not_raise_existing_cap() {
    let mut config = test_config();
    config.stealth.max_rps = Some(3);

    let profile = DefenseProfile::empty(0).with_waf(WafProfile {
        vendor: WafVendor::Cloudflare,
        paranoia_level: None,
        blocked_response_code: 403,
        blocked_categories: vec![],
    });

    apply_stealth_adjustments(&mut config, &profile);

    assert_eq!(config.stealth.max_rps, Some(3));
}

#[test]
fn apply_stealth_adjustments_rate_limit_sets_80_percent() {
    let mut config = test_config();
    assert!(config.stealth.max_rps.is_none());

    let profile = DefenseProfile::empty(0).with_rate_limit(RateLimitProfile {
        requests_per_second: Some(10.0),
        burst_allowance: Some(20),
        limit_response_code: 429,
        limit_window_seconds: Some(60),
    });

    apply_stealth_adjustments(&mut config, &profile);

    assert_eq!(config.stealth.max_rps, Some(8));
}

#[test]
fn apply_stealth_adjustments_rate_limit_does_not_raise_existing_cap() {
    let mut config = test_config();
    config.stealth.max_rps = Some(2);

    let profile = DefenseProfile::empty(0).with_rate_limit(RateLimitProfile {
        requests_per_second: Some(100.0),
        burst_allowance: None,
        limit_response_code: 429,
        limit_window_seconds: None,
    });

    apply_stealth_adjustments(&mut config, &profile);

    assert_eq!(config.stealth.max_rps, Some(2));
}

#[test]
fn apply_stealth_adjustments_waf_and_rate_limit_combined() {
    let mut config = test_config();

    let profile = DefenseProfile::empty(0)
        .with_waf(WafProfile {
            vendor: WafVendor::AwsWaf,
            paranoia_level: None,
            blocked_response_code: 403,
            blocked_categories: vec![],
        })
        .with_rate_limit(RateLimitProfile {
            requests_per_second: Some(3.0),
            burst_allowance: None,
            limit_response_code: 429,
            limit_window_seconds: None,
        });

    apply_stealth_adjustments(&mut config, &profile);

    assert_eq!(config.stealth.max_rps, Some(2));
}

#[test]
fn apply_stealth_adjustments_bot_detection_alone_does_not_change_rps() {
    let mut config = test_config();

    let profile = DefenseProfile::empty(0).with_bot_detection(BotDetectionProfile {
        detected: true,
        detection_method: "header_analysis".to_string(),
        challenge_response_code: Some(403),
    });

    apply_stealth_adjustments(&mut config, &profile);

    assert!(config.stealth.max_rps.is_none());
}

#[test]
fn apply_stealth_adjustments_empty_profile_is_noop() {
    let mut config = test_config();
    let original_rps = config.stealth.max_rps;

    let profile = DefenseProfile::empty(0);

    apply_stealth_adjustments(&mut config, &profile);

    assert_eq!(config.stealth.max_rps, original_rps);
}

#[test]
fn apply_stealth_adjustments_rate_limit_minimum_1_rps() {
    let mut config = test_config();

    let profile = DefenseProfile::empty(0).with_rate_limit(RateLimitProfile {
        requests_per_second: Some(0.5),
        burst_allowance: None,
        limit_response_code: 429,
        limit_window_seconds: None,
    });

    apply_stealth_adjustments(&mut config, &profile);

    assert_eq!(config.stealth.max_rps, Some(1));
}

#[test]
fn run_fingerprint_with_unreachable_target_still_sets_profile() {
    let mut ctx = test_context();
    ctx.config.target = "http://localhost:19999".to_string();

    let result = run_fingerprint(&mut ctx).unwrap();

    assert!(ctx.defense_profile.is_some());
    assert_eq!(result.operations_applied, 1);
    let profile = ctx.defense_profile.unwrap();
    assert!(profile.waf.is_none());
    assert!(profile.rate_limit.is_none());
    assert!(profile.bot_detection.is_none());
}
