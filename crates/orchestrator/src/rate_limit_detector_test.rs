use crate::rate_limit_detector::*;

#[test]
fn rate_limit_to_operations_creates_defense_node() {
    let info = RateLimitInfo {
        headers: vec![
            ("x-ratelimit-limit".to_string(), "100".to_string()),
            ("x-ratelimit-remaining".to_string(), "99".to_string()),
        ],
    };
    let mut seq = 0;
    let ops = rate_limit_to_operations(&info, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode {
            node_type,
            properties,
        } => {
            assert_eq!(*node_type, aegis_protocol::node::NodeType::Defense);
            let source = properties.iter().find(|(k, _)| k == "source").unwrap();
            assert_eq!(source.1, "rate_limit_detect");
            let limit = properties
                .iter()
                .find(|(k, _)| k == "x-ratelimit-limit")
                .unwrap();
            assert_eq!(limit.1, "100");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn rate_limit_to_operations_includes_all_headers() {
    let info = RateLimitInfo {
        headers: vec![
            ("x-ratelimit-limit".to_string(), "1000".to_string()),
            ("x-ratelimit-remaining".to_string(), "500".to_string()),
            ("x-ratelimit-reset".to_string(), "1700000000".to_string()),
        ],
    };
    let mut seq = 0;
    let ops = rate_limit_to_operations(&info, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode { properties, .. } => {
            assert_eq!(properties.len(), 4); // 3 headers + source
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn detect_rate_limits_skips_localhost() {
    let result = detect_rate_limits("http://localhost:8080");
    assert!(result.is_none());
}

#[test]
fn detect_rate_limits_skips_loopback() {
    let result = detect_rate_limits("http://127.0.0.1");
    assert!(result.is_none());
}
