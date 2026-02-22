use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier};

use crate::brute_forcer::DiscoveredPath;
use crate::graph_ops::discovered_paths_to_operations;

#[test]
fn empty_paths_produce_no_operations() {
    let ops = discovered_paths_to_operations(&[], 0);
    assert!(ops.is_empty());
}

#[test]
fn single_path_produces_one_operation() {
    let paths = vec![DiscoveredPath {
        path: "admin".to_string(),
        status_code: 200,
        content_length: 5000,
        content_type: Some("text/html".to_string()),
        interesting: true,
    }];

    let ops = discovered_paths_to_operations(&paths, 0);
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
        assert_eq!(props["path"], "admin");
        assert_eq!(props["method"], "GET");
        assert_eq!(props["discovery_source"], "brute_force");
        assert_eq!(props["status_code"], "200");
        assert_eq!(props["content_length"], "5000");
        assert_eq!(props["content_type"], "text/html");
        assert_eq!(props["interesting"], "true");
    } else {
        panic!("expected AddNode operation");
    }
}

#[test]
fn sequence_numbers_are_consecutive() {
    let paths = vec![
        DiscoveredPath {
            path: "a".to_string(),
            status_code: 200,
            content_length: 100,
            content_type: None,
            interesting: false,
        },
        DiscoveredPath {
            path: "b".to_string(),
            status_code: 301,
            content_length: 0,
            content_type: None,
            interesting: false,
        },
        DiscoveredPath {
            path: "c".to_string(),
            status_code: 403,
            content_length: 50,
            content_type: None,
            interesting: false,
        },
    ];

    let ops = discovered_paths_to_operations(&paths, 10);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
    assert_eq!(ops[2].sequence_number, 13);
}

#[test]
fn no_content_type_omits_property() {
    let paths = vec![DiscoveredPath {
        path: "test".to_string(),
        status_code: 200,
        content_length: 100,
        content_type: None,
        interesting: false,
    }];

    let ops = discovered_paths_to_operations(&paths, 0);
    if let GraphOperation::AddNode { properties, .. } = &ops[0].operation {
        let has_content_type = properties.iter().any(|(k, _)| k == "content_type");
        assert!(
            !has_content_type,
            "content_type should be omitted when None"
        );
    } else {
        panic!("expected AddNode operation");
    }
}

#[test]
fn not_interesting_omits_interesting_property() {
    let paths = vec![DiscoveredPath {
        path: "index.html".to_string(),
        status_code: 200,
        content_length: 1000,
        content_type: None,
        interesting: false,
    }];

    let ops = discovered_paths_to_operations(&paths, 0);
    if let GraphOperation::AddNode { properties, .. } = &ops[0].operation {
        let has_interesting = properties.iter().any(|(k, _)| k == "interesting");
        assert!(!has_interesting, "interesting should be omitted when false");
    } else {
        panic!("expected AddNode operation");
    }
}

#[test]
fn timestamps_are_nonzero() {
    let paths = vec![DiscoveredPath {
        path: "test".to_string(),
        status_code: 200,
        content_length: 0,
        content_type: None,
        interesting: false,
    }];

    let ops = discovered_paths_to_operations(&paths, 0);
    assert!(ops[0].timestamp_unix_ms > 0);
}
