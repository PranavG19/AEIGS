use crate::graph_ops::vhost_findings_to_operations;
use crate::vhost_discoverer::{
    BODY_SIZE_TOLERANCE, BaselineResponse, DiscoveredVhost, VHOST_PREFIXES, VhostDiscoverer,
    VhostError, build_evidence, build_vhost_hostname, is_different_from_baseline, simple_hash,
};

use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier};

#[test]
fn vhost_prefixes_has_at_least_30_entries() {
    assert!(VHOST_PREFIXES.len() >= 30);
}

#[test]
fn vhost_prefixes_contains_common_entries() {
    assert!(VHOST_PREFIXES.contains(&"admin"));
    assert!(VHOST_PREFIXES.contains(&"api"));
    assert!(VHOST_PREFIXES.contains(&"app"));
    assert!(VHOST_PREFIXES.contains(&"dashboard"));
    assert!(VHOST_PREFIXES.contains(&"dev"));
    assert!(VHOST_PREFIXES.contains(&"internal"));
    assert!(VHOST_PREFIXES.contains(&"staging"));
    assert!(VHOST_PREFIXES.contains(&"test"));
    assert!(VHOST_PREFIXES.contains(&"wiki"));
}

#[test]
fn vhost_prefixes_contains_devops_entries() {
    assert!(VHOST_PREFIXES.contains(&"ci"));
    assert!(VHOST_PREFIXES.contains(&"git"));
    assert!(VHOST_PREFIXES.contains(&"grafana"));
    assert!(VHOST_PREFIXES.contains(&"jenkins"));
    assert!(VHOST_PREFIXES.contains(&"jira"));
    assert!(VHOST_PREFIXES.contains(&"kibana"));
    assert!(VHOST_PREFIXES.contains(&"monitor"));
    assert!(VHOST_PREFIXES.contains(&"prometheus"));
    assert!(VHOST_PREFIXES.contains(&"vault"));
}

#[test]
fn vhost_prefixes_contains_infrastructure_entries() {
    assert!(VHOST_PREFIXES.contains(&"cdn"));
    assert!(VHOST_PREFIXES.contains(&"db"));
    assert!(VHOST_PREFIXES.contains(&"ftp"));
    assert!(VHOST_PREFIXES.contains(&"mail"));
    assert!(VHOST_PREFIXES.contains(&"static"));
    assert!(VHOST_PREFIXES.contains(&"vpn"));
}

#[test]
fn vhost_prefixes_sorted_alphabetically() {
    let mut sorted = VHOST_PREFIXES.to_vec();
    sorted.sort();
    assert_eq!(VHOST_PREFIXES, sorted.as_slice());
}

#[test]
fn vhost_prefixes_no_duplicates() {
    let mut seen = std::collections::HashSet::new();
    for prefix in VHOST_PREFIXES {
        assert!(seen.insert(prefix), "duplicate prefix: {prefix}");
    }
}

#[test]
fn build_vhost_hostname_basic() {
    assert_eq!(
        build_vhost_hostname("admin", "example.com"),
        "admin.example.com"
    );
}

#[test]
fn build_vhost_hostname_subdomain() {
    assert_eq!(
        build_vhost_hostname("api", "app.example.com"),
        "api.app.example.com"
    );
}

#[test]
fn build_vhost_hostname_all_prefixes_valid() {
    for prefix in VHOST_PREFIXES {
        let hostname = build_vhost_hostname(prefix, "test.local");
        assert!(hostname.starts_with(prefix));
        assert!(hostname.ends_with(".test.local"));
        assert_eq!(hostname, format!("{prefix}.test.local"));
    }
}

#[test]
fn is_different_status_code_differs() {
    let baseline = BaselineResponse {
        status_code: 200,
        body_size: 1000,
        body_hash: 12345,
    };
    assert!(is_different_from_baseline(404, 1000, 12345, &baseline));
}

#[test]
fn is_different_body_size_differs_beyond_tolerance() {
    let baseline = BaselineResponse {
        status_code: 200,
        body_size: 1000,
        body_hash: 12345,
    };
    let different_size = 1000 + BODY_SIZE_TOLERANCE + 1;
    assert!(is_different_from_baseline(
        200,
        different_size,
        12345,
        &baseline
    ));
}

#[test]
fn is_same_body_size_within_tolerance() {
    let baseline = BaselineResponse {
        status_code: 200,
        body_size: 1000,
        body_hash: 12345,
    };
    let similar_size = 1000 + BODY_SIZE_TOLERANCE;
    assert!(!is_different_from_baseline(
        200,
        similar_size,
        12345,
        &baseline
    ));
}

#[test]
fn is_different_body_hash_differs() {
    let baseline = BaselineResponse {
        status_code: 200,
        body_size: 1000,
        body_hash: 12345,
    };
    assert!(is_different_from_baseline(200, 1000, 99999, &baseline));
}

#[test]
fn is_same_empty_body_same_hash() {
    let baseline = BaselineResponse {
        status_code: 200,
        body_size: 0,
        body_hash: simple_hash(b""),
    };
    assert!(!is_different_from_baseline(
        200,
        0,
        simple_hash(b""),
        &baseline
    ));
}

#[test]
fn is_different_empty_body_different_hash_not_flagged() {
    let baseline = BaselineResponse {
        status_code: 200,
        body_size: 0,
        body_hash: 12345,
    };
    assert!(!is_different_from_baseline(200, 0, 99999, &baseline));
}

#[test]
fn is_same_exact_match() {
    let baseline = BaselineResponse {
        status_code: 200,
        body_size: 500,
        body_hash: 42,
    };
    assert!(!is_different_from_baseline(200, 500, 42, &baseline));
}

#[test]
fn build_evidence_status_differs() {
    let baseline = BaselineResponse {
        status_code: 200,
        body_size: 1000,
        body_hash: 0,
    };
    let evidence = build_evidence("admin.test.local", 302, 1000, &baseline);
    assert!(evidence.contains("admin.test.local"));
    assert!(evidence.contains("status 302"));
    assert!(evidence.contains("baseline 200"));
}

#[test]
fn build_evidence_body_size_differs() {
    let baseline = BaselineResponse {
        status_code: 200,
        body_size: 100,
        body_hash: 0,
    };
    let evidence = build_evidence("api.test.local", 200, 5000, &baseline);
    assert!(evidence.contains("api.test.local"));
    assert!(evidence.contains("body size 5000"));
    assert!(evidence.contains("baseline 100"));
}

#[test]
fn build_evidence_both_differ() {
    let baseline = BaselineResponse {
        status_code: 200,
        body_size: 100,
        body_hash: 0,
    };
    let evidence = build_evidence("dev.test.local", 302, 5000, &baseline);
    assert!(evidence.contains("status 302"));
    assert!(evidence.contains("body size 5000"));
}

#[test]
fn build_evidence_content_only_differs() {
    let baseline = BaselineResponse {
        status_code: 200,
        body_size: 100,
        body_hash: 0,
    };
    let evidence = build_evidence("wiki.test.local", 200, 100, &baseline);
    assert!(evidence.contains("different body content"));
}

#[test]
fn simple_hash_empty() {
    let h = simple_hash(b"");
    assert_eq!(h, 5381);
}

#[test]
fn simple_hash_deterministic() {
    let h1 = simple_hash(b"hello world");
    let h2 = simple_hash(b"hello world");
    assert_eq!(h1, h2);
}

#[test]
fn simple_hash_different_inputs() {
    let h1 = simple_hash(b"hello");
    let h2 = simple_hash(b"world");
    assert_ne!(h1, h2);
}

#[test]
fn discoverer_new_succeeds() {
    let discoverer = VhostDiscoverer::new();
    assert!(discoverer.is_ok());
}

#[test]
fn discover_rejects_non_localhost() {
    let discoverer = VhostDiscoverer::new().unwrap();
    let result = discoverer.discover_vhosts("http://example.com", "example.com");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        VhostError::NonLocalhostTarget(_)
    ));
}

#[test]
fn discover_rejects_empty_url() {
    let discoverer = VhostDiscoverer::new().unwrap();
    let result = discoverer.discover_vhosts("", "example.com");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), VhostError::InvalidUrl(_)));
}

#[test]
fn discover_accepts_localhost() {
    let discoverer = VhostDiscoverer::new().unwrap();
    let result = discoverer.discover_vhosts("http://localhost:39999", "test.local");
    assert!(result.is_ok());
}

#[test]
fn discover_accepts_127_0_0_1() {
    let discoverer = VhostDiscoverer::new().unwrap();
    let result = discoverer.discover_vhosts("http://127.0.0.1:39999", "test.local");
    assert!(result.is_ok());
}

#[test]
fn discover_accepts_ipv6_localhost() {
    let discoverer = VhostDiscoverer::new().unwrap();
    let result = discoverer.discover_vhosts("http://[::1]:39999", "test.local");
    assert!(result.is_ok());
}

#[test]
fn discoverer_debug_format() {
    let discoverer = VhostDiscoverer::new().unwrap();
    let debug = format!("{:?}", discoverer);
    assert!(debug.contains("VhostDiscoverer"));
}

#[test]
fn discovered_vhost_clone() {
    let vhost = DiscoveredVhost {
        hostname: "admin.test.local".to_string(),
        status_code: 200,
        content_length: 1234,
        evidence: "different status".to_string(),
    };
    let cloned = vhost.clone();
    assert_eq!(vhost, cloned);
}

#[test]
fn discovered_vhost_debug_format() {
    let vhost = DiscoveredVhost {
        hostname: "api.test.local".to_string(),
        status_code: 302,
        content_length: 0,
        evidence: "redirect".to_string(),
    };
    let debug = format!("{:?}", vhost);
    assert!(debug.contains("api.test.local"));
    assert!(debug.contains("302"));
}

#[test]
fn error_display_invalid_url() {
    let err = VhostError::InvalidUrl("bad".to_string());
    assert_eq!(format!("{err}"), "invalid URL: bad");
}

#[test]
fn error_display_non_localhost() {
    let err = VhostError::NonLocalhostTarget("http://evil.com".to_string());
    assert_eq!(format!("{err}"), "non-localhost target: http://evil.com");
}

#[test]
fn error_display_http_error() {
    let err = VhostError::HttpError("timeout".to_string());
    assert_eq!(format!("{err}"), "HTTP error: timeout");
}

#[test]
fn error_is_std_error() {
    let err = VhostError::InvalidUrl("test".to_string());
    let _: &dyn std::error::Error = &err;
}

#[test]
fn vhost_findings_to_operations_empty() {
    let ops = vhost_findings_to_operations(&[], 0);
    assert!(ops.is_empty());
}

#[test]
fn vhost_findings_to_operations_single() {
    let findings = vec![DiscoveredVhost {
        hostname: "admin.test.local".to_string(),
        status_code: 200,
        content_length: 4096,
        evidence: "different body content".to_string(),
    }];

    let ops = vhost_findings_to_operations(&findings, 0);
    assert_eq!(ops.len(), 1);

    let entry = &ops[0];
    assert_eq!(entry.sequence_number, 1);
    assert_eq!(entry.module, ModuleIdentifier::Discovery);

    if let GraphOperation::AddNode {
        node_type,
        properties,
    } = &entry.operation
    {
        assert_eq!(*node_type, NodeType::Endpoint);
        let props: std::collections::HashMap<&str, &str> = properties
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(props["hostname"], "admin.test.local");
        assert_eq!(props["discovery_source"], "vhost_discovery");
        assert_eq!(props["status_code"], "200");
        assert_eq!(props["content_length"], "4096");
        assert!(props.contains_key("evidence"));
    } else {
        panic!("expected AddNode operation");
    }
}

#[test]
fn vhost_findings_to_operations_sequence_numbers() {
    let findings = vec![
        DiscoveredVhost {
            hostname: "admin.test.local".to_string(),
            status_code: 200,
            content_length: 100,
            evidence: "test".to_string(),
        },
        DiscoveredVhost {
            hostname: "api.test.local".to_string(),
            status_code: 302,
            content_length: 0,
            evidence: "test".to_string(),
        },
        DiscoveredVhost {
            hostname: "dev.test.local".to_string(),
            status_code: 403,
            content_length: 500,
            evidence: "test".to_string(),
        },
    ];

    let ops = vhost_findings_to_operations(&findings, 10);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
    assert_eq!(ops[2].sequence_number, 13);
}

#[test]
fn vhost_findings_to_operations_timestamps_nonzero() {
    let findings = vec![DiscoveredVhost {
        hostname: "admin.test.local".to_string(),
        status_code: 200,
        content_length: 100,
        evidence: "test".to_string(),
    }];

    let ops = vhost_findings_to_operations(&findings, 0);
    assert!(ops[0].timestamp_unix_ms > 0);
}
