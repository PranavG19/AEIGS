use crate::http_version::*;

#[test]
fn version_to_operations_creates_node() {
    let info = HttpVersionInfo {
        version: "HTTP/2.0".to_string(),
        supports_h2: true,
    };
    let mut seq = 0;
    let ops = version_to_operations(&info, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode {
            node_type,
            properties,
        } => {
            assert_eq!(*node_type, aegis_protocol::node::NodeType::Service);
            let version = properties.iter().find(|(k, _)| k == "http_version").unwrap();
            assert_eq!(version.1, "HTTP/2.0");
            let h2 = properties.iter().find(|(k, _)| k == "supports_h2").unwrap();
            assert_eq!(h2.1, "true");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn version_to_operations_no_h2() {
    let info = HttpVersionInfo {
        version: "HTTP/1.1".to_string(),
        supports_h2: false,
    };
    let mut seq = 5;
    let ops = version_to_operations(&info, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode { properties, .. } => {
            let h2 = properties.iter().find(|(k, _)| k == "supports_h2").unwrap();
            assert_eq!(h2.1, "false");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn detect_http_version_skips_localhost() {
    let result = detect_http_version("http://localhost:8080");
    assert!(result.is_none());
}

#[test]
fn detect_http_version_skips_invalid() {
    let result = detect_http_version("not-a-url");
    assert!(result.is_none());
}
