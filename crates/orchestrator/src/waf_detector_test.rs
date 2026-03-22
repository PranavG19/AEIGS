use crate::waf_detector::*;

#[test]
fn waf_to_operations_creates_defense_nodes() {
    let detections = vec![
        WafDetection {
            waf_name: "cloudflare".to_string(),
            evidence: "header: cf-ray".to_string(),
        },
        WafDetection {
            waf_name: "nginx".to_string(),
            evidence: "server: nginx/1.24".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = waf_to_operations(&detections, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
    for op in &ops {
        match &op.operation {
            aegis_protocol::operation::GraphOperation::AddNode {
                node_type,
                properties,
            } => {
                assert_eq!(*node_type, aegis_protocol::node::NodeType::Defense);
                let source = properties.iter().find(|(k, _)| k == "source").unwrap();
                assert_eq!(source.1, "waf_detect");
            }
            _ => panic!("expected AddNode"),
        }
    }
}

#[test]
fn waf_to_operations_empty() {
    let mut seq = 5;
    let ops = waf_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn waf_to_operations_preserves_waf_name() {
    let detections = vec![WafDetection {
        waf_name: "cloudflare".to_string(),
        evidence: "header: cf-ray".to_string(),
    }];
    let mut seq = 0;
    let ops = waf_to_operations(&detections, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode { properties, .. } => {
            let waf = properties.iter().find(|(k, _)| k == "waf_name").unwrap();
            assert_eq!(waf.1, "cloudflare");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn detect_waf_skips_localhost() {
    let detections = detect_waf("http://localhost:8080");
    assert!(detections.is_empty());
}

#[test]
fn detect_waf_skips_invalid() {
    let detections = detect_waf("not-a-url");
    assert!(detections.is_empty());
}
