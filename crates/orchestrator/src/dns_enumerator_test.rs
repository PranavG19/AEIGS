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

// --- DnsIssue Display tests ---

#[test]
fn display_open_resolver() {
    let issue = DnsIssue::OpenResolver {
        nameserver: "ns1.evil.com".to_string(),
    };
    assert_eq!(issue.to_string(), "open_resolver: ns1.evil.com");
}

#[test]
fn display_zone_transfer_possible() {
    let issue = DnsIssue::ZoneTransferPossible {
        nameserver: "ns2.example.com".to_string(),
    };
    assert_eq!(issue.to_string(), "zone_transfer_possible: ns2.example.com");
}

#[test]
fn display_missing_spf() {
    assert_eq!(DnsIssue::MissingSpf.to_string(), "missing_spf");
}

#[test]
fn display_weak_spf() {
    let issue = DnsIssue::WeakSpf {
        record: "v=spf1 +all".to_string(),
    };
    assert_eq!(issue.to_string(), "weak_spf: v=spf1 +all");
}

#[test]
fn display_missing_dmarc() {
    assert_eq!(DnsIssue::MissingDmarc.to_string(), "missing_dmarc");
}

#[test]
fn display_weak_dmarc() {
    let issue = DnsIssue::WeakDmarc {
        policy: "none".to_string(),
    };
    assert_eq!(issue.to_string(), "weak_dmarc: none");
}

#[test]
fn display_dangling_cname() {
    let issue = DnsIssue::DanglingCname {
        cname: "old.cdn.example.com".to_string(),
    };
    assert_eq!(issue.to_string(), "dangling_cname: old.cdn.example.com");
}

#[test]
fn display_internal_ip_leak() {
    let issue = DnsIssue::InternalIpLeak {
        ip: "10.0.0.5".to_string(),
    };
    assert_eq!(issue.to_string(), "internal_ip_leak: 10.0.0.5");
}

#[test]
fn display_wildcard_dns() {
    assert_eq!(DnsIssue::WildcardDns.to_string(), "wildcard_dns");
}

#[test]
fn display_missing_dnssec() {
    assert_eq!(DnsIssue::MissingDnssec.to_string(), "missing_dnssec");
}

#[test]
fn display_low_ttl() {
    let issue = DnsIssue::LowTtl {
        record_type: "A".to_string(),
        value: "93.184.216.34".to_string(),
    };
    assert_eq!(issue.to_string(), "low_ttl: A 93.184.216.34");
}

// --- Severity tests ---

#[test]
fn severity_zone_transfer_is_highest() {
    let zt = dns_issue_severity(&DnsIssue::ZoneTransferPossible {
        nameserver: "ns1.example.com".to_string(),
    });
    let or = dns_issue_severity(&DnsIssue::OpenResolver {
        nameserver: "ns1.example.com".to_string(),
    });
    assert!(zt > or);
}

#[test]
fn severity_open_resolver_above_dangling_cname() {
    let or = dns_issue_severity(&DnsIssue::OpenResolver {
        nameserver: "ns1.example.com".to_string(),
    });
    let dc = dns_issue_severity(&DnsIssue::DanglingCname {
        cname: "old.example.com".to_string(),
    });
    assert!(or > dc);
}

#[test]
fn severity_internal_ip_above_weak_spf() {
    let ip = dns_issue_severity(&DnsIssue::InternalIpLeak {
        ip: "10.0.0.1".to_string(),
    });
    let ws = dns_issue_severity(&DnsIssue::WeakSpf {
        record: "v=spf1 +all".to_string(),
    });
    assert!(ip > ws);
}

#[test]
fn severity_weak_spf_above_weak_dmarc() {
    let ws = dns_issue_severity(&DnsIssue::WeakSpf {
        record: "v=spf1 +all".to_string(),
    });
    let wd = dns_issue_severity(&DnsIssue::WeakDmarc {
        policy: "none".to_string(),
    });
    assert!(ws > wd);
}

#[test]
fn severity_missing_spf_above_missing_dmarc() {
    let ms = dns_issue_severity(&DnsIssue::MissingSpf);
    let md = dns_issue_severity(&DnsIssue::MissingDmarc);
    assert!(ms > md);
}

#[test]
fn severity_wildcard_above_missing_dnssec() {
    let wc = dns_issue_severity(&DnsIssue::WildcardDns);
    let ds = dns_issue_severity(&DnsIssue::MissingDnssec);
    assert!(wc > ds);
}

#[test]
fn severity_low_ttl_is_lowest() {
    let lt = dns_issue_severity(&DnsIssue::LowTtl {
        record_type: "A".to_string(),
        value: "1.2.3.4".to_string(),
    });
    let ds = dns_issue_severity(&DnsIssue::MissingDnssec);
    assert!(lt < ds);
}

#[test]
fn severity_all_variants_positive() {
    let all = vec![
        DnsIssue::OpenResolver {
            nameserver: "ns".to_string(),
        },
        DnsIssue::ZoneTransferPossible {
            nameserver: "ns".to_string(),
        },
        DnsIssue::MissingSpf,
        DnsIssue::WeakSpf {
            record: "r".to_string(),
        },
        DnsIssue::MissingDmarc,
        DnsIssue::WeakDmarc {
            policy: "p".to_string(),
        },
        DnsIssue::DanglingCname {
            cname: "c".to_string(),
        },
        DnsIssue::InternalIpLeak {
            ip: "i".to_string(),
        },
        DnsIssue::WildcardDns,
        DnsIssue::MissingDnssec,
        DnsIssue::LowTtl {
            record_type: "A".to_string(),
            value: "v".to_string(),
        },
    ];
    for issue in &all {
        assert!(dns_issue_severity(issue) > 0.0);
    }
}

// --- analyze_dns_records tests ---

#[test]
fn analyze_empty_records() {
    let issues = analyze_dns_records(&[]);
    assert!(issues.iter().any(|i| matches!(i, DnsIssue::MissingSpf)));
    assert!(issues.iter().any(|i| matches!(i, DnsIssue::MissingDmarc)));
}

#[test]
fn analyze_missing_spf_with_other_txt() {
    let records = vec![DnsRecord {
        record_type: "TXT".to_string(),
        value: "google-site-verification=abc123".to_string(),
    }];
    let issues = analyze_dns_records(&records);
    assert!(issues.iter().any(|i| matches!(i, DnsIssue::MissingSpf)));
}

#[test]
fn analyze_valid_spf_no_issue() {
    let records = vec![DnsRecord {
        record_type: "TXT".to_string(),
        value: "v=spf1 include:_spf.google.com ~all".to_string(),
    }];
    let issues = analyze_dns_records(&records);
    assert!(!issues.iter().any(|i| matches!(i, DnsIssue::MissingSpf)));
    assert!(!issues.iter().any(|i| matches!(i, DnsIssue::WeakSpf { .. })));
}

#[test]
fn analyze_weak_spf_plus_all() {
    let records = vec![DnsRecord {
        record_type: "TXT".to_string(),
        value: "v=spf1 +all".to_string(),
    }];
    let issues = analyze_dns_records(&records);
    assert!(!issues.iter().any(|i| matches!(i, DnsIssue::MissingSpf)));
    assert!(issues.iter().any(|i| matches!(i, DnsIssue::WeakSpf { .. })));
}

#[test]
fn analyze_spf_tilde_all_is_ok() {
    let records = vec![DnsRecord {
        record_type: "TXT".to_string(),
        value: "v=spf1 include:example.com ~all".to_string(),
    }];
    let issues = analyze_dns_records(&records);
    assert!(!issues.iter().any(|i| matches!(i, DnsIssue::WeakSpf { .. })));
}

#[test]
fn analyze_spf_dash_all_is_ok() {
    let records = vec![DnsRecord {
        record_type: "TXT".to_string(),
        value: "v=spf1 include:example.com -all".to_string(),
    }];
    let issues = analyze_dns_records(&records);
    assert!(!issues.iter().any(|i| matches!(i, DnsIssue::WeakSpf { .. })));
}

#[test]
fn analyze_missing_dmarc() {
    let records = vec![DnsRecord {
        record_type: "TXT".to_string(),
        value: "v=spf1 -all".to_string(),
    }];
    let issues = analyze_dns_records(&records);
    assert!(issues.iter().any(|i| matches!(i, DnsIssue::MissingDmarc)));
}

#[test]
fn analyze_valid_dmarc_quarantine() {
    let records = vec![
        DnsRecord {
            record_type: "TXT".to_string(),
            value: "v=spf1 -all".to_string(),
        },
        DnsRecord {
            record_type: "TXT".to_string(),
            value: "v=DMARC1; p=quarantine; rua=mailto:d@example.com".to_string(),
        },
    ];
    let issues = analyze_dns_records(&records);
    assert!(!issues.iter().any(|i| matches!(i, DnsIssue::MissingDmarc)));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DnsIssue::WeakDmarc { .. }))
    );
}

#[test]
fn analyze_valid_dmarc_reject() {
    let records = vec![
        DnsRecord {
            record_type: "TXT".to_string(),
            value: "v=spf1 -all".to_string(),
        },
        DnsRecord {
            record_type: "TXT".to_string(),
            value: "v=DMARC1; p=reject".to_string(),
        },
    ];
    let issues = analyze_dns_records(&records);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DnsIssue::WeakDmarc { .. }))
    );
}

#[test]
fn analyze_weak_dmarc_p_none() {
    let records = vec![DnsRecord {
        record_type: "TXT".to_string(),
        value: "v=DMARC1; p=none; rua=mailto:d@example.com".to_string(),
    }];
    let issues = analyze_dns_records(&records);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DnsIssue::WeakDmarc { policy } if policy == "none"))
    );
}

#[test]
fn analyze_internal_ip_10_range() {
    let records = vec![DnsRecord {
        record_type: "A".to_string(),
        value: "10.0.0.1".to_string(),
    }];
    let issues = analyze_dns_records(&records);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DnsIssue::InternalIpLeak { ip } if ip == "10.0.0.1"))
    );
}

#[test]
fn analyze_internal_ip_172_16_range() {
    let records = vec![DnsRecord {
        record_type: "A".to_string(),
        value: "172.16.0.1".to_string(),
    }];
    let issues = analyze_dns_records(&records);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DnsIssue::InternalIpLeak { ip } if ip == "172.16.0.1"))
    );
}

#[test]
fn analyze_internal_ip_172_31_range() {
    let records = vec![DnsRecord {
        record_type: "A".to_string(),
        value: "172.31.255.1".to_string(),
    }];
    let issues = analyze_dns_records(&records);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DnsIssue::InternalIpLeak { .. }))
    );
}

#[test]
fn analyze_172_15_is_not_internal() {
    let records = vec![DnsRecord {
        record_type: "A".to_string(),
        value: "172.15.0.1".to_string(),
    }];
    let issues = analyze_dns_records(&records);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DnsIssue::InternalIpLeak { .. }))
    );
}

#[test]
fn analyze_172_32_is_not_internal() {
    let records = vec![DnsRecord {
        record_type: "A".to_string(),
        value: "172.32.0.1".to_string(),
    }];
    let issues = analyze_dns_records(&records);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DnsIssue::InternalIpLeak { .. }))
    );
}

#[test]
fn analyze_internal_ip_192_168_range() {
    let records = vec![DnsRecord {
        record_type: "A".to_string(),
        value: "192.168.1.1".to_string(),
    }];
    let issues = analyze_dns_records(&records);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DnsIssue::InternalIpLeak { ip } if ip == "192.168.1.1"))
    );
}

#[test]
fn analyze_public_ip_not_flagged() {
    let records = vec![
        DnsRecord {
            record_type: "A".to_string(),
            value: "8.8.8.8".to_string(),
        },
        DnsRecord {
            record_type: "A".to_string(),
            value: "1.1.1.1".to_string(),
        },
    ];
    let issues = analyze_dns_records(&records);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DnsIssue::InternalIpLeak { .. }))
    );
}

#[test]
fn analyze_internal_ip_in_aaaa_record() {
    let records = vec![DnsRecord {
        record_type: "AAAA".to_string(),
        value: "10.0.0.5".to_string(),
    }];
    let issues = analyze_dns_records(&records);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DnsIssue::InternalIpLeak { .. }))
    );
}

#[test]
fn analyze_only_a_records_flags_missing_spf_and_dmarc() {
    let records = vec![DnsRecord {
        record_type: "A".to_string(),
        value: "93.184.216.34".to_string(),
    }];
    let issues = analyze_dns_records(&records);
    assert!(issues.iter().any(|i| matches!(i, DnsIssue::MissingSpf)));
    assert!(issues.iter().any(|i| matches!(i, DnsIssue::MissingDmarc)));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DnsIssue::InternalIpLeak { .. }))
    );
}

#[test]
fn analyze_only_txt_records_no_ip_issues() {
    let records = vec![
        DnsRecord {
            record_type: "TXT".to_string(),
            value: "v=spf1 -all".to_string(),
        },
        DnsRecord {
            record_type: "TXT".to_string(),
            value: "v=DMARC1; p=reject".to_string(),
        },
    ];
    let issues = analyze_dns_records(&records);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DnsIssue::InternalIpLeak { .. }))
    );
    assert!(!issues.iter().any(|i| matches!(i, DnsIssue::MissingSpf)));
    assert!(!issues.iter().any(|i| matches!(i, DnsIssue::MissingDmarc)));
}

#[test]
fn analyze_multiple_txt_with_spf() {
    let records = vec![
        DnsRecord {
            record_type: "TXT".to_string(),
            value: "google-site-verification=abc".to_string(),
        },
        DnsRecord {
            record_type: "TXT".to_string(),
            value: "v=spf1 include:example.com -all".to_string(),
        },
        DnsRecord {
            record_type: "TXT".to_string(),
            value: "facebook-domain-verification=xyz".to_string(),
        },
    ];
    let issues = analyze_dns_records(&records);
    assert!(!issues.iter().any(|i| matches!(i, DnsIssue::MissingSpf)));
    assert!(!issues.iter().any(|i| matches!(i, DnsIssue::WeakSpf { .. })));
}

#[test]
fn analyze_multiple_internal_ips() {
    let records = vec![
        DnsRecord {
            record_type: "A".to_string(),
            value: "10.0.0.1".to_string(),
        },
        DnsRecord {
            record_type: "A".to_string(),
            value: "192.168.0.1".to_string(),
        },
    ];
    let issues = analyze_dns_records(&records);
    let ip_leaks: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, DnsIssue::InternalIpLeak { .. }))
        .collect();
    assert_eq!(ip_leaks.len(), 2);
}

#[test]
fn analyze_ns_records_not_checked_for_ip() {
    let records = vec![DnsRecord {
        record_type: "NS".to_string(),
        value: "10.0.0.1".to_string(),
    }];
    let issues = analyze_dns_records(&records);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, DnsIssue::InternalIpLeak { .. }))
    );
}

#[test]
fn analyze_mixed_records_full_check() {
    let records = vec![
        DnsRecord {
            record_type: "A".to_string(),
            value: "93.184.216.34".to_string(),
        },
        DnsRecord {
            record_type: "A".to_string(),
            value: "10.0.0.5".to_string(),
        },
        DnsRecord {
            record_type: "TXT".to_string(),
            value: "v=spf1 +all".to_string(),
        },
        DnsRecord {
            record_type: "TXT".to_string(),
            value: "v=DMARC1; p=none".to_string(),
        },
        DnsRecord {
            record_type: "NS".to_string(),
            value: "ns1.example.com".to_string(),
        },
    ];
    let issues = analyze_dns_records(&records);
    assert!(issues.iter().any(|i| matches!(i, DnsIssue::WeakSpf { .. })));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DnsIssue::WeakDmarc { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, DnsIssue::InternalIpLeak { ip } if ip == "10.0.0.5"))
    );
    assert!(!issues.iter().any(|i| matches!(i, DnsIssue::MissingSpf)));
    assert!(!issues.iter().any(|i| matches!(i, DnsIssue::MissingDmarc)));
}

// --- dns_issues_to_operations tests ---

#[test]
fn issues_to_operations_empty() {
    let mut seq = 10;
    let ops = dns_issues_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 10);
}

#[test]
fn issues_to_operations_one_per_issue() {
    let issues = vec![DnsIssue::MissingSpf, DnsIssue::MissingDmarc];
    let mut seq = 0;
    let ops = dns_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn issues_to_operations_seq_increments() {
    let issues = vec![
        DnsIssue::MissingSpf,
        DnsIssue::WeakDmarc {
            policy: "none".to_string(),
        },
        DnsIssue::InternalIpLeak {
            ip: "10.0.0.1".to_string(),
        },
    ];
    let mut seq = 5;
    let ops = dns_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);
    assert_eq!(ops[0].sequence_number, 6);
    assert_eq!(ops[1].sequence_number, 7);
    assert_eq!(ops[2].sequence_number, 8);
}

#[test]
fn issues_to_operations_uses_add_finding() {
    let issues = vec![DnsIssue::MissingSpf];
    let mut seq = 0;
    let ops = dns_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            confidence,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
            );
            assert!((confidence.value() - 0.5).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn issues_to_operations_uses_passive_recon_module() {
    let issues = vec![DnsIssue::WildcardDns];
    let mut seq = 0;
    let ops = dns_issues_to_operations(&issues, &mut seq);
    assert_eq!(
        ops[0].module,
        aegis_protocol::operation::ModuleIdentifier::PassiveRecon
    );
}

// --- DnsIssue equality / clone tests ---

#[test]
fn dns_issue_clone_eq() {
    let issue = DnsIssue::WeakSpf {
        record: "v=spf1 +all".to_string(),
    };
    let cloned = issue.clone();
    assert_eq!(issue, cloned);
}

#[test]
fn dns_issue_ne_different_variants() {
    assert_ne!(DnsIssue::MissingSpf, DnsIssue::MissingDmarc);
}

#[test]
fn dns_issue_debug_format() {
    let issue = DnsIssue::MissingDnssec;
    let dbg = format!("{issue:?}");
    assert!(dbg.contains("MissingDnssec"));
}
