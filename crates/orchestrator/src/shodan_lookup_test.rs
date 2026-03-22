use crate::shodan_lookup::*;

#[test]
fn parse_internetdb_full_response() {
    let body = r#"{
        "cpes": ["cpe:/a:apache:http_server:2.4.51"],
        "hostnames": ["example.com"],
        "ip": "93.184.216.34",
        "ports": [80, 443],
        "tags": ["cloud"],
        "vulns": ["CVE-2021-44228", "CVE-2022-22965"]
    }"#;
    let result = parse_internetdb_response(body, "93.184.216.34").unwrap();
    assert_eq!(result.ip, "93.184.216.34");
    assert_eq!(result.ports, vec![80, 443]);
    assert_eq!(result.hostnames, vec!["example.com"]);
    assert_eq!(result.vulns.len(), 2);
    assert!(result.vulns.contains(&"CVE-2021-44228".to_string()));
    assert_eq!(result.cpes.len(), 1);
    assert_eq!(result.tags, vec!["cloud"]);
}

#[test]
fn parse_internetdb_empty_arrays() {
    let body = r#"{
        "cpes": [],
        "hostnames": [],
        "ip": "1.2.3.4",
        "ports": [],
        "tags": [],
        "vulns": []
    }"#;
    let result = parse_internetdb_response(body, "1.2.3.4").unwrap();
    assert!(result.ports.is_empty());
    assert!(result.vulns.is_empty());
    assert!(result.hostnames.is_empty());
}

#[test]
fn parse_internetdb_missing_fields() {
    let body = r#"{"ip": "1.2.3.4", "ports": [22]}"#;
    let result = parse_internetdb_response(body, "1.2.3.4").unwrap();
    assert_eq!(result.ports, vec![22]);
    assert!(result.vulns.is_empty());
    assert!(result.hostnames.is_empty());
    assert!(result.cpes.is_empty());
    assert!(result.tags.is_empty());
}

#[test]
fn parse_internetdb_invalid_json() {
    let result = parse_internetdb_response("not json", "1.2.3.4");
    assert!(result.is_none());
}

#[test]
fn parse_internetdb_not_object() {
    let result = parse_internetdb_response("[1,2,3]", "1.2.3.4");
    assert!(result.is_none());
}

#[test]
fn shodan_to_operations_ports_and_vulns() {
    let result = ShodanResult {
        ip: "93.184.216.34".to_string(),
        ports: vec![80, 443],
        hostnames: vec!["example.com".to_string()],
        vulns: vec!["CVE-2021-44228".to_string()],
        cpes: vec![],
        tags: vec![],
    };
    let mut seq = 0;
    let ops = shodan_to_operations(&result, &mut seq);
    // 2 ports (AddNode each) + 1 vuln (AddFinding) = 3
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);

    // First two should be AddNode for ports
    for op in &ops[..2] {
        match &op.operation {
            aegis_protocol::operation::GraphOperation::AddNode {
                node_type,
                properties,
            } => {
                assert_eq!(*node_type, aegis_protocol::node::NodeType::Service);
                let source = properties.iter().find(|(k, _)| k == "source").unwrap();
                assert_eq!(source.1, "shodan-internetdb");
            }
            _ => panic!("expected AddNode"),
        }
    }

    // Third should be AddFinding for vuln
    match &ops[2].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 7.0).abs() < 1e-9);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn shodan_to_operations_empty() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let mut seq = 5;
    let ops = shodan_to_operations(&result, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn shodan_to_operations_ports_only() {
    let result = ShodanResult {
        ip: "1.2.3.4".to_string(),
        ports: vec![22, 80, 443],
        hostnames: vec![],
        vulns: vec![],
        cpes: vec![],
        tags: vec![],
    };
    let mut seq = 0;
    let ops = shodan_to_operations(&result, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn shodan_lookup_skips_localhost() {
    let result = shodan_lookup("http://localhost:8080");
    assert!(result.is_none());
}

#[test]
fn shodan_lookup_skips_loopback() {
    let result = shodan_lookup("http://127.0.0.1:3000");
    assert!(result.is_none());
}

#[test]
fn resolve_ip_skips_loopback() {
    let result = resolve_ip("localhost");
    assert!(result.is_none());
}
