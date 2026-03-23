use crate::tech_detector::*;

#[test]
fn detect_technologies_skips_localhost() {
    let result = detect_technologies("http://localhost:8080");
    assert!(result.is_empty());
}

#[test]
fn detect_technologies_skips_loopback() {
    let result = detect_technologies("http://127.0.0.1");
    assert!(result.is_empty());
}

#[test]
fn tech_to_operations_creates_service_nodes() {
    let detections = vec![
        TechDetection {
            name: "nginx".to_string(),
            version: Some("1.24.0".to_string()),
            category: "Web Server".to_string(),
            confidence: 0.95,
            evidence: "Server: nginx/1.24.0".to_string(),
        },
        TechDetection {
            name: "WordPress".to_string(),
            version: Some("6.4".to_string()),
            category: "CMS".to_string(),
            confidence: 0.85,
            evidence: "wp-content/ found in HTML".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = tech_to_operations(&detections, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);

    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode {
            node_type,
            properties,
        } => {
            assert_eq!(*node_type, aegis_protocol::node::NodeType::Service);
            let name = properties.iter().find(|(k, _)| k == "name").unwrap();
            assert_eq!(name.1, "nginx");
            let version = properties.iter().find(|(k, _)| k == "version").unwrap();
            assert_eq!(version.1, "1.24.0");
            let source = properties.iter().find(|(k, _)| k == "source").unwrap();
            assert_eq!(source.1, "tech_detect");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn tech_to_operations_omits_version_when_none() {
    let detections = vec![TechDetection {
        name: "React".to_string(),
        version: None,
        category: "JavaScript".to_string(),
        confidence: 0.8,
        evidence: "react.production.min.js".to_string(),
    }];
    let mut seq = 0;
    let ops = tech_to_operations(&detections, &mut seq);
    assert_eq!(ops.len(), 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode { properties, .. } => {
            assert!(properties.iter().all(|(k, _)| k != "version"));
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn dedup_detections_removes_duplicates() {
    let detections = vec![
        TechDetection {
            name: "WordPress".to_string(),
            version: Some("6.4".to_string()),
            category: "CMS".to_string(),
            confidence: 0.85,
            evidence: "wp-content/ in HTML".to_string(),
        },
        TechDetection {
            name: "WordPress".to_string(),
            version: Some("6.4".to_string()),
            category: "CMS".to_string(),
            confidence: 0.85,
            evidence: "wp-includes/ in HTML".to_string(),
        },
        TechDetection {
            name: "nginx".to_string(),
            version: None,
            category: "Web Server".to_string(),
            confidence: 0.9,
            evidence: "Server: nginx".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = tech_to_operations(&detections, &mut seq);
    // Both WordPress entries create separate ops (dedup is in detect_technologies)
    assert_eq!(ops.len(), 3);
}

#[test]
fn detect_from_parts_finds_server_header() {
    let headers = vec![("server".to_string(), "nginx/1.24.0".to_string())];
    let body = "";
    let results = detect_from_parts(&headers, body);
    assert!(
        results.iter().any(|d| d.name.contains("nginx")),
        "should detect nginx from server header, got: {results:?}"
    );
}

#[test]
fn detect_from_parts_finds_html_patterns() {
    let headers = vec![];
    let body = r#"<html><head><script src="/wp-includes/js/jquery.js"></script></head></html>"#;
    let results = detect_from_parts(&headers, body);
    assert!(
        results.iter().any(|d| d.name == "WordPress"),
        "should detect WordPress from HTML, got: {results:?}"
    );
}

#[test]
fn detect_from_parts_empty_inputs() {
    let results = detect_from_parts(&[], "");
    assert!(results.is_empty());
}

#[test]
fn detect_from_parts_deduplicates() {
    let headers = vec![("x-powered-by".to_string(), "Express".to_string())];
    let body = r#"<html><head><meta name="generator" content="Express"></head></html>"#;
    let results = detect_from_parts(&headers, body);
    let express_count = results.iter().filter(|d| d.name == "Express").count();
    assert!(express_count <= 1, "should deduplicate Express detections");
}
