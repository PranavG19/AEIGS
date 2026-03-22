use crate::dns_enumerator::*;

#[test]
fn parse_dig_output_mx_records() {
    let stdout = "10 mail.example.com.\n20 mail2.example.com.\n";
    let records = parse_dig_output(stdout, "MX");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].record_type, "MX");
    assert_eq!(records[0].value, "10 mail.example.com");
    assert_eq!(records[1].value, "20 mail2.example.com");
}

#[test]
fn parse_dig_output_txt_records() {
    let stdout = "\"v=spf1 include:_spf.google.com ~all\"\n";
    let records = parse_dig_output(stdout, "TXT");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_type, "TXT");
}

#[test]
fn parse_dig_output_ns_records() {
    let stdout = "ns1.example.com.\nns2.example.com.\n";
    let records = parse_dig_output(stdout, "NS");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].value, "ns1.example.com");
    assert_eq!(records[1].value, "ns2.example.com");
}

#[test]
fn parse_dig_output_cname_records() {
    let stdout = "www.example.com.\n";
    let records = parse_dig_output(stdout, "CNAME");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].value, "www.example.com");
}

#[test]
fn parse_dig_output_empty() {
    let records = parse_dig_output("", "MX");
    assert!(records.is_empty());
}

#[test]
fn parse_dig_output_skips_comments() {
    let stdout = ";; comment\nns1.example.com.\n";
    let records = parse_dig_output(stdout, "NS");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].value, "ns1.example.com");
}

#[test]
fn parse_dig_output_strips_trailing_dot() {
    let stdout = "mail.example.com.\n";
    let records = parse_dig_output(stdout, "MX");
    assert_eq!(records[0].value, "mail.example.com");
}

#[test]
fn dns_to_operations_creates_service_nodes() {
    let records = vec![
        DnsRecord {
            record_type: "A".to_string(),
            value: "93.184.216.34".to_string(),
        },
        DnsRecord {
            record_type: "MX".to_string(),
            value: "10 mail.example.com".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = dns_to_operations(&records, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
    for op in &ops {
        match &op.operation {
            aegis_protocol::operation::GraphOperation::AddNode {
                node_type,
                properties,
            } => {
                assert_eq!(*node_type, aegis_protocol::node::NodeType::Service);
                let source = properties.iter().find(|(k, _)| k == "source").unwrap();
                assert_eq!(source.1, "dns");
            }
            _ => panic!("expected AddNode"),
        }
    }
}

#[test]
fn dns_to_operations_empty() {
    let mut seq = 5;
    let ops = dns_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn enumerate_dns_skips_localhost() {
    let records = enumerate_dns("http://localhost:8080");
    assert!(records.is_empty());
}

#[test]
fn enumerate_dns_skips_loopback() {
    let records = enumerate_dns("http://127.0.0.1");
    assert!(records.is_empty());
}

#[test]
fn enumerate_dns_skips_invalid() {
    let records = enumerate_dns("not-a-url");
    assert!(records.is_empty());
}
