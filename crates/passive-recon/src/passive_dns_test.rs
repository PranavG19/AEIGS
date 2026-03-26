use super::passive_dns::*;

#[test]
fn parse_security_trails_current_dns() {
    let json = r#"{
        "current_dns": {
            "a": {
                "first_seen": "2020-01-01",
                "values": [
                    {"ip": "93.184.216.34"},
                    {"ip": "93.184.216.35"}
                ]
            },
            "mx": {
                "values": [
                    {"host": "mail.example.com", "priority": 10}
                ]
            },
            "ns": {
                "values": [
                    {"value": "ns1.example.com"},
                    {"value": "ns2.example.com"}
                ]
            }
        }
    }"#;
    let records = parse_security_trails_response(json, "example.com");
    assert!(records.len() >= 4);

    let a_records: Vec<_> = records
        .iter()
        .filter(|r| r.record_type == DnsRecordType::A)
        .collect();
    assert_eq!(a_records.len(), 2);
    assert_eq!(a_records[0].record_value, "93.184.216.34");

    let mx_records: Vec<_> = records
        .iter()
        .filter(|r| r.record_type == DnsRecordType::Mx)
        .collect();
    assert_eq!(mx_records.len(), 1);
}

#[test]
fn parse_security_trails_subdomains() {
    let json = r#"{
        "subdomains": ["www", "api", "mail", "cdn"]
    }"#;
    let records = parse_security_trails_response(json, "example.com");
    assert_eq!(records.len(), 4);
    assert!(records.iter().any(|r| r.query_name == "www.example.com"));
    assert!(records.iter().any(|r| r.query_name == "api.example.com"));
}

#[test]
fn parse_security_trails_empty() {
    let records = parse_security_trails_response("{}", "example.com");
    assert!(records.is_empty());
}

#[test]
fn parse_security_trails_invalid() {
    let records = parse_security_trails_response("not json", "test.com");
    assert!(records.is_empty());
}

#[test]
fn parse_dnsdb_response_ndjson() {
    let body = r#"{"rrname":"example.com.","rrtype":"A","rdata":["93.184.216.34"],"count":500,"time_first":1600000000,"time_last":1700000000}
{"rrname":"example.com.","rrtype":"MX","rdata":["mail.example.com."],"count":100}
"#;
    let records = parse_dnsdb_response(body);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].query_name, "example.com");
    assert_eq!(records[0].record_type, DnsRecordType::A);
    assert_eq!(records[0].record_value, "93.184.216.34");
    assert_eq!(records[0].count, 500);
    assert!(records[0].first_seen.is_some());
    assert_eq!(records[1].record_type, DnsRecordType::Mx);
    assert_eq!(records[1].record_value, "mail.example.com");
}

#[test]
fn parse_dnsdb_response_empty() {
    let records = parse_dnsdb_response("");
    assert!(records.is_empty());
}

#[test]
fn parse_dnsdb_response_string_rdata() {
    let body = r#"{"rrname":"test.com.","rrtype":"CNAME","rdata":"cdn.test.com.","count":50}"#;
    let records = parse_dnsdb_response(body);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_type, DnsRecordType::Cname);
    assert_eq!(records[0].record_value, "cdn.test.com");
}

#[test]
fn parse_farsight_tags_source() {
    let body = r#"{"rrname":"x.com.","rrtype":"A","rdata":["1.2.3.4"],"count":1}"#;
    let records = parse_farsight_response(body);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].source, PassiveDnsSource::Farsight);
}

#[test]
fn parse_record_type_variants() {
    assert_eq!(parse_record_type("A"), DnsRecordType::A);
    assert_eq!(parse_record_type("AAAA"), DnsRecordType::Aaaa);
    assert_eq!(parse_record_type("CNAME"), DnsRecordType::Cname);
    assert_eq!(parse_record_type("MX"), DnsRecordType::Mx);
    assert_eq!(parse_record_type("TXT"), DnsRecordType::Txt);
    assert_eq!(parse_record_type("SRV"), DnsRecordType::Srv);
    assert_eq!(parse_record_type("DNSKEY"), DnsRecordType::Dnskey);
}

#[test]
fn deduplicate_records_merges() {
    let records = vec![
        PassiveDnsRecord {
            query_name: "test.com".to_string(),
            record_type: DnsRecordType::A,
            record_value: "1.2.3.4".to_string(),
            first_seen: Some("2020-01-01".to_string()),
            last_seen: None,
            count: 10,
            source: PassiveDnsSource::SecurityTrails,
        },
        PassiveDnsRecord {
            query_name: "test.com".to_string(),
            record_type: DnsRecordType::A,
            record_value: "1.2.3.4".to_string(),
            first_seen: None,
            last_seen: Some("2024-01-01".to_string()),
            count: 50,
            source: PassiveDnsSource::Dnsdb,
        },
    ];
    let deduped = deduplicate_records(records);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].count, 50);
    assert!(deduped[0].first_seen.is_some());
    assert!(deduped[0].last_seen.is_some());
}

#[test]
fn detect_changes_finds_diffs() {
    let old = vec![PassiveDnsRecord {
        query_name: "test.com".to_string(),
        record_type: DnsRecordType::A,
        record_value: "1.1.1.1".to_string(),
        first_seen: None,
        last_seen: None,
        count: 1,
        source: PassiveDnsSource::SecurityTrails,
    }];
    let new = vec![PassiveDnsRecord {
        query_name: "test.com".to_string(),
        record_type: DnsRecordType::A,
        record_value: "2.2.2.2".to_string(),
        first_seen: None,
        last_seen: None,
        count: 1,
        source: PassiveDnsSource::SecurityTrails,
    }];
    let changes = detect_changes(&old, &new);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].old_value, "1.1.1.1");
    assert_eq!(changes[0].new_value, "2.2.2.2");
}

#[test]
fn detect_changes_no_diff() {
    let same = vec![PassiveDnsRecord {
        query_name: "test.com".to_string(),
        record_type: DnsRecordType::A,
        record_value: "1.1.1.1".to_string(),
        first_seen: None,
        last_seen: None,
        count: 1,
        source: PassiveDnsSource::SecurityTrails,
    }];
    let changes = detect_changes(&same, &same);
    assert!(changes.is_empty());
}

#[test]
fn build_infrastructure_maps() {
    let records = vec![
        PassiveDnsRecord {
            query_name: "example.com".to_string(),
            record_type: DnsRecordType::A,
            record_value: "93.184.216.34".to_string(),
            first_seen: None,
            last_seen: None,
            count: 1,
            source: PassiveDnsSource::SecurityTrails,
        },
        PassiveDnsRecord {
            query_name: "example.com".to_string(),
            record_type: DnsRecordType::Ns,
            record_value: "ns1.example.com".to_string(),
            first_seen: None,
            last_seen: None,
            count: 1,
            source: PassiveDnsSource::SecurityTrails,
        },
        PassiveDnsRecord {
            query_name: "example.com".to_string(),
            record_type: DnsRecordType::Mx,
            record_value: "mail.example.com".to_string(),
            first_seen: None,
            last_seen: None,
            count: 1,
            source: PassiveDnsSource::SecurityTrails,
        },
        PassiveDnsRecord {
            query_name: "www.example.com".to_string(),
            record_type: DnsRecordType::Cname,
            record_value: "cdn.example.com".to_string(),
            first_seen: None,
            last_seen: None,
            count: 1,
            source: PassiveDnsSource::SecurityTrails,
        },
        PassiveDnsRecord {
            query_name: "api.example.com".to_string(),
            record_type: DnsRecordType::A,
            record_value: "93.184.216.34".to_string(),
            first_seen: None,
            last_seen: None,
            count: 1,
            source: PassiveDnsSource::SecurityTrails,
        },
    ];

    let infra = build_infrastructure("example.com", &records);
    assert_eq!(infra.nameservers, vec!["ns1.example.com"]);
    assert_eq!(infra.mail_servers, vec!["mail.example.com"]);
    assert!(infra.ip_addresses.contains(&"93.184.216.34".to_string()));
    assert!(infra.subdomains.contains(&"www.example.com".to_string()));
    assert!(infra.subdomains.contains(&"api.example.com".to_string()));
    assert!(!infra.cname_chains.is_empty());
    assert!(!infra.shared_ips.is_empty());
}

#[test]
fn build_passive_dns_report_full() {
    let records = vec![PassiveDnsRecord {
        query_name: "test.com".to_string(),
        record_type: DnsRecordType::A,
        record_value: "1.2.3.4".to_string(),
        first_seen: None,
        last_seen: None,
        count: 1,
        source: PassiveDnsSource::SecurityTrails,
    }];
    let report = build_passive_dns_report(
        "test.com",
        records,
        vec![],
        vec![PassiveDnsSource::SecurityTrails, PassiveDnsSource::Dnsdb],
    );
    assert_eq!(report.target_domain, "test.com");
    assert_eq!(report.total_records, 1);
    assert_eq!(report.unique_ips, 1);
    assert_eq!(report.sources_queried.len(), 2);
}

#[test]
fn passive_dns_source_display() {
    assert_eq!(
        PassiveDnsSource::SecurityTrails.to_string(),
        "SecurityTrails"
    );
    assert_eq!(PassiveDnsSource::Dnsdb.to_string(), "DNSDB");
    assert_eq!(PassiveDnsSource::Farsight.to_string(), "Farsight");
}

#[test]
fn dns_record_type_display() {
    assert_eq!(DnsRecordType::A.to_string(), "A");
    assert_eq!(DnsRecordType::Aaaa.to_string(), "AAAA");
    assert_eq!(DnsRecordType::Cname.to_string(), "CNAME");
    assert_eq!(DnsRecordType::Rrsig.to_string(), "RRSIG");
}
