use crate::graph_ops::discovered_params_to_operations;
use crate::param_discoverer::{
    COMMON_PARAMS, DiscoveredParam, ParamDiscoverError, ParamDiscoverer, ParamEvidence,
    body_size_differs_significantly, detect_evidence,
};

use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier};

#[test]
fn common_params_has_at_least_60_entries() {
    assert!(
        COMMON_PARAMS.len() >= 60,
        "expected at least 60 common params, got {}",
        COMMON_PARAMS.len()
    );
}

#[test]
fn common_params_contains_auth_related() {
    assert!(COMMON_PARAMS.contains(&"token"));
    assert!(COMMON_PARAMS.contains(&"key"));
    assert!(COMMON_PARAMS.contains(&"api_key"));
    assert!(COMMON_PARAMS.contains(&"apikey"));
    assert!(COMMON_PARAMS.contains(&"secret"));
    assert!(COMMON_PARAMS.contains(&"password"));
    assert!(COMMON_PARAMS.contains(&"pass"));
}

#[test]
fn common_params_contains_pagination() {
    assert!(COMMON_PARAMS.contains(&"page"));
    assert!(COMMON_PARAMS.contains(&"limit"));
    assert!(COMMON_PARAMS.contains(&"offset"));
    assert!(COMMON_PARAMS.contains(&"sort"));
    assert!(COMMON_PARAMS.contains(&"order"));
}

#[test]
fn common_params_contains_search() {
    assert!(COMMON_PARAMS.contains(&"search"));
    assert!(COMMON_PARAMS.contains(&"q"));
    assert!(COMMON_PARAMS.contains(&"query"));
    assert!(COMMON_PARAMS.contains(&"filter"));
}

#[test]
fn common_params_contains_dangerous() {
    assert!(COMMON_PARAMS.contains(&"cmd"));
    assert!(COMMON_PARAMS.contains(&"command"));
    assert!(COMMON_PARAMS.contains(&"exec"));
    assert!(COMMON_PARAMS.contains(&"run"));
    assert!(COMMON_PARAMS.contains(&"debug"));
    assert!(COMMON_PARAMS.contains(&"admin"));
    assert!(COMMON_PARAMS.contains(&"template"));
    assert!(COMMON_PARAMS.contains(&"include"));
}

#[test]
fn common_params_contains_file_path_related() {
    assert!(COMMON_PARAMS.contains(&"file"));
    assert!(COMMON_PARAMS.contains(&"path"));
    assert!(COMMON_PARAMS.contains(&"dir"));
    assert!(COMMON_PARAMS.contains(&"folder"));
}

#[test]
fn common_params_contains_redirect_related() {
    assert!(COMMON_PARAMS.contains(&"redirect"));
    assert!(COMMON_PARAMS.contains(&"url"));
    assert!(COMMON_PARAMS.contains(&"next"));
    assert!(COMMON_PARAMS.contains(&"return"));
    assert!(COMMON_PARAMS.contains(&"ref"));
    assert!(COMMON_PARAMS.contains(&"callback"));
}

#[test]
fn common_params_contains_format_related() {
    assert!(COMMON_PARAMS.contains(&"format"));
    assert!(COMMON_PARAMS.contains(&"json"));
    assert!(COMMON_PARAMS.contains(&"xml"));
    assert!(COMMON_PARAMS.contains(&"html"));
    assert!(COMMON_PARAMS.contains(&"text"));
    assert!(COMMON_PARAMS.contains(&"csv"));
    assert!(COMMON_PARAMS.contains(&"output"));
}

#[test]
fn common_params_contains_crud_actions() {
    assert!(COMMON_PARAMS.contains(&"action"));
    assert!(COMMON_PARAMS.contains(&"delete"));
    assert!(COMMON_PARAMS.contains(&"update"));
    assert!(COMMON_PARAMS.contains(&"create"));
    assert!(COMMON_PARAMS.contains(&"export"));
    assert!(COMMON_PARAMS.contains(&"import"));
}

#[test]
fn common_params_has_no_duplicates() {
    let mut seen = std::collections::HashSet::new();
    for param in COMMON_PARAMS {
        assert!(
            seen.insert(param),
            "duplicate param in COMMON_PARAMS: {param}"
        );
    }
}

#[test]
fn detect_evidence_status_code_change() {
    let baseline_body = b"hello";
    let probe_body = b"hello";
    let result = detect_evidence(200, baseline_body, 403, probe_body);
    assert_eq!(result, Some(ParamEvidence::StatusCodeChange(200, 403)));
}

#[test]
fn detect_evidence_status_code_takes_priority_over_body() {
    let baseline_body = b"short";
    let probe_body = b"this is a much longer body that also differs in size";
    let result = detect_evidence(200, baseline_body, 500, probe_body);
    assert_eq!(result, Some(ParamEvidence::StatusCodeChange(200, 500)));
}

#[test]
fn detect_evidence_body_size_change() {
    let baseline_body = vec![0u8; 100];
    let probe_body = vec![0u8; 200];
    let result = detect_evidence(200, &baseline_body, 200, &probe_body);
    assert_eq!(result, Some(ParamEvidence::BodySizeChange(100, 200)));
}

#[test]
fn detect_evidence_content_change_same_size() {
    let baseline_body = b"aaaaaaaaaa";
    let probe_body = b"bbbbbbbbbb";
    let result = detect_evidence(200, baseline_body, 200, probe_body);
    assert_eq!(result, Some(ParamEvidence::ContentChange));
}

#[test]
fn detect_evidence_no_change() {
    let body = b"identical content";
    let result = detect_evidence(200, body, 200, body);
    assert_eq!(result, None);
}

#[test]
fn detect_evidence_empty_bodies_identical() {
    let result = detect_evidence(200, b"", 200, b"");
    assert_eq!(result, None);
}

#[test]
fn detect_evidence_small_body_size_diff_below_threshold() {
    let baseline = vec![0u8; 100];
    let probe = vec![0u8; 105];
    let result = detect_evidence(200, &baseline, 200, &probe);
    assert_eq!(
        result,
        Some(ParamEvidence::ContentChange),
        "5% size diff should not trigger BodySizeChange but content differs"
    );
}

#[test]
fn body_size_differs_both_zero() {
    assert!(!body_size_differs_significantly(0, 0));
}

#[test]
fn body_size_differs_exactly_at_threshold() {
    assert!(!body_size_differs_significantly(100, 90));
}

#[test]
fn body_size_differs_just_above_threshold() {
    assert!(body_size_differs_significantly(100, 89));
}

#[test]
fn body_size_differs_large_increase() {
    assert!(body_size_differs_significantly(100, 500));
}

#[test]
fn body_size_differs_large_decrease() {
    assert!(body_size_differs_significantly(500, 100));
}

#[test]
fn body_size_differs_one_zero() {
    assert!(body_size_differs_significantly(0, 100));
    assert!(body_size_differs_significantly(100, 0));
}

#[test]
fn body_size_differs_symmetrical() {
    let a_to_b = body_size_differs_significantly(100, 200);
    let b_to_a = body_size_differs_significantly(200, 100);
    assert_eq!(a_to_b, b_to_a);
}

#[test]
fn discoverer_new_succeeds() {
    let discoverer = ParamDiscoverer::new();
    assert!(discoverer.is_ok());
}

#[test]
fn discover_rejects_non_localhost() {
    let discoverer = ParamDiscoverer::new().unwrap();
    let result = discoverer.discover_params("http://example.com/api");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ParamDiscoverError::NonLocalhostTarget(_)
    ));
}

#[test]
fn discover_rejects_empty_url() {
    let discoverer = ParamDiscoverer::new().unwrap();
    let result = discoverer.discover_params("");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ParamDiscoverError::InvalidUrl(_)
    ));
}

#[test]
fn discover_accepts_localhost() {
    let discoverer = ParamDiscoverer::new().unwrap();
    let result = discoverer.discover_params("http://localhost:39999/api");
    assert!(result.is_ok());
}

#[test]
fn discover_accepts_127_0_0_1() {
    let discoverer = ParamDiscoverer::new().unwrap();
    let result = discoverer.discover_params("http://127.0.0.1:39999/api");
    assert!(result.is_ok());
}

#[test]
fn discover_accepts_ipv6_localhost() {
    let discoverer = ParamDiscoverer::new().unwrap();
    let result = discoverer.discover_params("http://[::1]:39999/api");
    assert!(result.is_ok());
}

#[test]
fn discoverer_debug_format() {
    let discoverer = ParamDiscoverer::new().unwrap();
    let debug = format!("{:?}", discoverer);
    assert!(debug.contains("ParamDiscoverer"));
}

#[test]
fn error_display_invalid_url() {
    let err = ParamDiscoverError::InvalidUrl("bad".to_string());
    assert_eq!(format!("{err}"), "invalid URL: bad");
}

#[test]
fn error_display_non_localhost() {
    let err = ParamDiscoverError::NonLocalhostTarget("http://evil.com".to_string());
    assert_eq!(format!("{err}"), "non-localhost target: http://evil.com");
}

#[test]
fn error_display_http_error() {
    let err = ParamDiscoverError::HttpError("timeout".to_string());
    assert_eq!(format!("{err}"), "HTTP error: timeout");
}

#[test]
fn error_is_std_error() {
    let err = ParamDiscoverError::InvalidUrl("test".to_string());
    let _: &dyn std::error::Error = &err;
}

#[test]
fn discovered_param_clone() {
    let param = DiscoveredParam {
        endpoint: "http://localhost:3000/api".to_string(),
        param_name: "debug".to_string(),
        evidence: ParamEvidence::StatusCodeChange(200, 500),
    };
    let cloned = param.clone();
    assert_eq!(param, cloned);
}

#[test]
fn param_evidence_clone() {
    let evidence = ParamEvidence::BodySizeChange(100, 200);
    let cloned = evidence.clone();
    assert_eq!(evidence, cloned);
}

#[test]
fn param_evidence_debug_format() {
    let e1 = ParamEvidence::StatusCodeChange(200, 403);
    assert!(format!("{e1:?}").contains("StatusCodeChange"));

    let e2 = ParamEvidence::BodySizeChange(100, 200);
    assert!(format!("{e2:?}").contains("BodySizeChange"));

    let e3 = ParamEvidence::ContentChange;
    assert!(format!("{e3:?}").contains("ContentChange"));
}

#[test]
fn discovered_params_to_operations_empty() {
    let ops = discovered_params_to_operations(&[], 0);
    assert!(ops.is_empty());
}

#[test]
fn discovered_params_to_operations_single_status_change() {
    let params = vec![DiscoveredParam {
        endpoint: "http://localhost:3000/api".to_string(),
        param_name: "debug".to_string(),
        evidence: ParamEvidence::StatusCodeChange(200, 500),
    }];

    let ops = discovered_params_to_operations(&params, 0);
    assert_eq!(ops.len(), 1);

    let entry = &ops[0];
    assert_eq!(entry.sequence_number, 1);
    assert_eq!(entry.module, ModuleIdentifier::Discovery);

    if let GraphOperation::AddNode {
        node_type,
        properties,
    } = &entry.operation
    {
        assert_eq!(*node_type, NodeType::Config);
        let props: std::collections::HashMap<&str, &str> = properties
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(props["endpoint"], "http://localhost:3000/api");
        assert_eq!(props["param_name"], "debug");
        assert_eq!(props["discovery_source"], "param_discovery");
        assert_eq!(props["evidence"], "status_code_change:200->500");
    } else {
        panic!("expected AddNode operation");
    }
}

#[test]
fn discovered_params_to_operations_body_size_evidence() {
    let params = vec![DiscoveredParam {
        endpoint: "http://localhost:3000/api".to_string(),
        param_name: "verbose".to_string(),
        evidence: ParamEvidence::BodySizeChange(100, 5000),
    }];

    let ops = discovered_params_to_operations(&params, 0);
    if let GraphOperation::AddNode { properties, .. } = &ops[0].operation {
        let props: std::collections::HashMap<&str, &str> = properties
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(props["evidence"], "body_size_change:100->5000");
    } else {
        panic!("expected AddNode operation");
    }
}

#[test]
fn discovered_params_to_operations_content_change_evidence() {
    let params = vec![DiscoveredParam {
        endpoint: "http://localhost:3000/api".to_string(),
        param_name: "format".to_string(),
        evidence: ParamEvidence::ContentChange,
    }];

    let ops = discovered_params_to_operations(&params, 0);
    if let GraphOperation::AddNode { properties, .. } = &ops[0].operation {
        let props: std::collections::HashMap<&str, &str> = properties
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(props["evidence"], "content_change");
    } else {
        panic!("expected AddNode operation");
    }
}

#[test]
fn discovered_params_to_operations_sequence_numbers() {
    let params = vec![
        DiscoveredParam {
            endpoint: "http://localhost:3000/api".to_string(),
            param_name: "debug".to_string(),
            evidence: ParamEvidence::StatusCodeChange(200, 500),
        },
        DiscoveredParam {
            endpoint: "http://localhost:3000/api".to_string(),
            param_name: "admin".to_string(),
            evidence: ParamEvidence::ContentChange,
        },
        DiscoveredParam {
            endpoint: "http://localhost:3000/api".to_string(),
            param_name: "verbose".to_string(),
            evidence: ParamEvidence::BodySizeChange(100, 300),
        },
    ];

    let ops = discovered_params_to_operations(&params, 10);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
    assert_eq!(ops[2].sequence_number, 13);
}

#[test]
fn discovered_params_to_operations_timestamps_nonzero() {
    let params = vec![DiscoveredParam {
        endpoint: "http://localhost:3000/api".to_string(),
        param_name: "debug".to_string(),
        evidence: ParamEvidence::StatusCodeChange(200, 500),
    }];

    let ops = discovered_params_to_operations(&params, 0);
    assert!(ops[0].timestamp_unix_ms > 0);
}
