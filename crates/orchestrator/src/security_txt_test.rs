use crate::security_txt::*;

#[test]
fn parse_security_txt_extracts_fields() {
    let body = "Contact: mailto:security@example.com\nExpires: 2025-12-31T23:59:59z\n";
    let fields = parse_security_txt(body);
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].0, "contact");
    assert_eq!(fields[0].1, "mailto:security@example.com");
    assert_eq!(fields[1].0, "expires");
}

#[test]
fn parse_security_txt_skips_comments_and_blanks() {
    let body = "# This is a comment\n\nContact: mailto:sec@example.com\n# Another comment\n";
    let fields = parse_security_txt(body);
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].0, "contact");
}

#[test]
fn parse_security_txt_handles_multiple_contacts() {
    let body = "\
Contact: mailto:security@example.com\n\
Contact: https://hackerone.com/example\n\
Preferred-Languages: en\n\
Canonical: https://example.com/.well-known/security.txt\n\
Policy: https://example.com/security-policy\n\
Hiring: https://example.com/jobs\n";
    let fields = parse_security_txt(body);
    assert_eq!(fields.len(), 6);
    let contacts: Vec<_> = fields.iter().filter(|(k, _)| k == "contact").collect();
    assert_eq!(contacts.len(), 2);
}

#[test]
fn parse_security_txt_skips_empty_values() {
    let body = "Contact:\nExpires: 2025-12-31T23:59:59z\n";
    let fields = parse_security_txt(body);
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].0, "expires");
}

#[test]
fn security_txt_to_operations_creates_config_node() {
    let info = SecurityTxtInfo {
        fields: vec![
            ("contact".to_string(), "mailto:sec@example.com".to_string()),
            ("expires".to_string(), "2025-12-31T23:59:59z".to_string()),
        ],
        path: ".well-known/security.txt".to_string(),
    };
    let mut seq = 0;
    let ops = security_txt_to_operations(&info, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode {
            node_type,
            properties,
        } => {
            assert_eq!(*node_type, aegis_protocol::node::NodeType::Config);
            let source = properties.iter().find(|(k, _)| k == "source").unwrap();
            assert_eq!(source.1, "security_txt");
            let path_prop = properties.iter().find(|(k, _)| k == "path").unwrap();
            assert_eq!(path_prop.1, ".well-known/security.txt");
            assert_eq!(properties.len(), 4); // 2 fields + source + path
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn fetch_security_txt_skips_localhost() {
    let result = fetch_security_txt("http://localhost:8080");
    assert!(result.is_none());
}

#[test]
fn fetch_security_txt_skips_loopback() {
    let result = fetch_security_txt("http://127.0.0.1");
    assert!(result.is_none());
}

#[test]
fn parse_security_txt_handles_colons_in_values() {
    let body = "Contact: https://example.com:8443/security\n";
    let fields = parse_security_txt(body);
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].1, "https://example.com:8443/security");
}
