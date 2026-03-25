use super::dns_security::*;

#[test]
fn validate_domain_accepts_simple_domain() {
    let result = validate_domain("example.com");
    assert_eq!(result.unwrap(), "example.com");
}

#[test]
fn validate_domain_trims_trailing_dot() {
    let result = validate_domain("example.com.");
    assert_eq!(result.unwrap(), "example.com");
}

#[test]
fn validate_domain_lowercases() {
    let result = validate_domain("EXAMPLE.COM");
    assert_eq!(result.unwrap(), "example.com");
}

#[test]
fn validate_domain_rejects_empty() {
    let result = validate_domain("");
    assert!(result.is_err());
}

#[test]
fn validate_domain_rejects_hyphen_start() {
    let result = validate_domain("-bad.com");
    assert!(result.is_err());
}

#[test]
fn validate_domain_rejects_label_too_long() {
    let long_label = "a".repeat(64);
    let result = validate_domain(&format!("{}.com", long_label));
    assert!(result.is_err());
}

#[test]
fn build_axfr_request_produces_valid_packet() {
    let packet = build_axfr_request("example.com", 0x1234).unwrap();
    // Transaction ID
    assert_eq!(packet[0], 0x12);
    assert_eq!(packet[1], 0x34);
    // QDCOUNT = 1
    assert_eq!(packet[4], 0x00);
    assert_eq!(packet[5], 0x01);
    // QTYPE = AXFR (252 = 0x00FC)
    let qtype_offset = packet.len() - 4;
    assert_eq!(packet[qtype_offset], 0x00);
    assert_eq!(packet[qtype_offset + 1], 0xFC);
    // QCLASS = IN (1)
    assert_eq!(packet[qtype_offset + 2], 0x00);
    assert_eq!(packet[qtype_offset + 3], 0x01);
}

#[test]
fn build_axfr_request_encodes_labels() {
    let packet = build_axfr_request("sub.example.com", 0x0001).unwrap();
    // After 12-byte header: 3 s u b 7 e x a m p l e 3 c o m 0
    assert_eq!(packet[12], 3); // "sub" length
    assert_eq!(packet[13], b's');
    assert_eq!(packet[16], 7); // "example" length
}

#[test]
fn parse_axfr_response_rejects_short_data() {
    let result = parse_axfr_response(&[0u8; 5], "example.com");
    assert!(result.is_err());
}

#[test]
fn parse_axfr_response_detects_refused() {
    let mut header = [0u8; 12];
    header[2] = 0x80; // QR=1
    header[3] = 0x05; // RCODE=5 (REFUSED)
    let result = parse_axfr_response(&header, "example.com");
    assert!(matches!(result, Err(DnsSecurityError::QueryFailed(_))));
}

#[test]
fn parse_axfr_response_handles_zero_records() {
    let mut header = [0u8; 12];
    header[2] = 0x84; // QR=1, AA=1
    header[3] = 0x00; // RCODE=0
    // QDCOUNT=0, ANCOUNT=0
    let records = parse_axfr_response(&header, "example.com").unwrap();
    assert!(records.is_empty());
}

#[test]
fn parse_axfr_response_parses_a_record() {
    // Build minimal response: header + 1 A record
    let mut pkt = Vec::new();
    // Header
    pkt.extend_from_slice(&[0x12, 0x34]); // TXID
    pkt.extend_from_slice(&[0x84, 0x00]); // flags: QR+AA, RCODE=0
    pkt.extend_from_slice(&[0x00, 0x00]); // QDCOUNT=0
    pkt.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    // Answer: "test.com" A 192.168.1.1
    // Name: 4 t e s t 3 c o m 0
    pkt.extend_from_slice(&[4, b't', b'e', b's', b't', 3, b'c', b'o', b'm', 0]);
    // TYPE=A(1), CLASS=IN(1)
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    // TTL=300
    pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
    // RDLENGTH=4
    pkt.extend_from_slice(&[0x00, 0x04]);
    // RDATA: 192.168.1.1
    pkt.extend_from_slice(&[192, 168, 1, 1]);

    let records = parse_axfr_response(&pkt, "test.com").unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_type, DnsRecordType::A);
    assert_eq!(records[0].value, "192.168.1.1");
    assert_eq!(records[0].ttl, 300);
    assert_eq!(records[0].name, "test.com");
}

#[test]
fn parse_spf_record_rejects_non_spf() {
    assert!(parse_spf_record("not an spf record").is_none());
}

#[test]
fn parse_spf_record_basic_pass_all() {
    let spf = parse_spf_record("v=spf1 +all").unwrap();
    assert_eq!(spf.all_qualifier, SpfQualifier::Pass);
    assert_eq!(spf.grade, DnsSeverity::Critical);
    assert!(!spf.issues.is_empty());
}

#[test]
fn parse_spf_record_hard_fail() {
    let spf = parse_spf_record("v=spf1 include:_spf.google.com -all").unwrap();
    assert_eq!(spf.all_qualifier, SpfQualifier::Fail);
    assert_eq!(spf.mechanisms.len(), 1);
    assert_eq!(spf.mechanisms[0].mechanism_type, "include");
    assert_eq!(spf.dns_lookup_count, 1);
}

#[test]
fn parse_spf_record_softfail_flagged() {
    let spf = parse_spf_record("v=spf1 ip4:1.2.3.0/24 ~all").unwrap();
    assert_eq!(spf.all_qualifier, SpfQualifier::SoftFail);
    assert!(spf.issues.iter().any(|i| i.contains("~all")));
}

#[test]
fn parse_spf_record_exceeds_dns_lookups() {
    let record = "v=spf1 include:a include:b include:c include:d include:e include:f include:g include:h include:i include:j include:k -all";
    let spf = parse_spf_record(record).unwrap();
    assert!(spf.dns_lookup_count > 10);
    assert!(spf.issues.iter().any(|i| i.contains("10 DNS lookup limit")));
}

#[test]
fn parse_spf_no_all_mechanism() {
    let spf = parse_spf_record("v=spf1 ip4:10.0.0.0/8").unwrap();
    assert_eq!(spf.all_qualifier, SpfQualifier::None);
    assert!(spf.issues.iter().any(|i| i.contains("no 'all' mechanism")));
}

#[test]
fn parse_dkim_record_missing() {
    let analysis = parse_dkim_record("selector1", None);
    assert!(!analysis.public_key_present);
    assert_eq!(analysis.grade, DnsSeverity::High);
}

#[test]
fn parse_dkim_record_valid() {
    let record = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
    let analysis = parse_dkim_record("selector1", Some(record));
    assert!(analysis.public_key_present);
    assert_eq!(analysis.version, Some("DKIM1".into()));
    assert_eq!(analysis.key_type, Some("rsa".into()));
}

#[test]
fn parse_dkim_record_empty_key() {
    let record = "v=DKIM1; k=rsa; p=";
    let analysis = parse_dkim_record("default", Some(record));
    assert!(!analysis.public_key_present);
    assert!(analysis.issues.iter().any(|i| i.contains("revoked")));
}

#[test]
fn parse_dmarc_record_missing() {
    let analysis = parse_dmarc_record(None);
    assert_eq!(analysis.policy, DmarcPolicy::Missing);
    assert_eq!(analysis.grade, DnsSeverity::High);
}

#[test]
fn parse_dmarc_record_reject_with_reporting() {
    let record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100";
    let analysis = parse_dmarc_record(Some(record));
    assert_eq!(analysis.policy, DmarcPolicy::Reject);
    assert_eq!(analysis.percentage, 100);
    assert!(!analysis.rua.is_empty());
    assert_eq!(analysis.grade, DnsSeverity::Info);
}

#[test]
fn parse_dmarc_record_none_policy() {
    let record = "v=DMARC1; p=none";
    let analysis = parse_dmarc_record(Some(record));
    assert_eq!(analysis.policy, DmarcPolicy::None);
    assert_eq!(analysis.grade, DnsSeverity::Medium);
    assert!(analysis.issues.iter().any(|i| i.contains("none")));
}

#[test]
fn parse_dmarc_record_partial_percentage() {
    let record = "v=DMARC1; p=quarantine; pct=50; rua=mailto:r@x.com";
    let analysis = parse_dmarc_record(Some(record));
    assert_eq!(analysis.percentage, 50);
    assert!(analysis.issues.iter().any(|i| i.contains("50%")));
}

#[test]
fn parse_dmarc_subdomain_policy() {
    let record = "v=DMARC1; p=reject; sp=none; rua=mailto:d@x.com";
    let analysis = parse_dmarc_record(Some(record));
    assert_eq!(analysis.subdomain_policy, Some(DmarcPolicy::None));
}

#[test]
fn audit_email_authentication_combined() {
    let result = audit_email_authentication(
        "example.com",
        Some("v=spf1 include:_spf.google.com -all"),
        &[(
            "selector1",
            Some("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"),
        )],
        Some("v=DMARC1; p=reject; rua=mailto:dmarc@example.com"),
    )
    .unwrap();

    assert!(result.spf.is_some());
    assert_eq!(result.dkim.len(), 1);
    assert!(result.dmarc.is_some());
}

#[test]
fn evaluate_dnssec_fully_signed() {
    let records = vec![
        DnsRecord {
            name: "example.com".into(),
            record_type: DnsRecordType::Dnskey,
            ttl: 3600,
            value: "257 3 13 abc".into(),
        },
        DnsRecord {
            name: "example.com".into(),
            record_type: DnsRecordType::Rrsig,
            ttl: 3600,
            value: "A 13 2 3600".into(),
        },
        DnsRecord {
            name: "example.com".into(),
            record_type: DnsRecordType::Nsec,
            ttl: 3600,
            value: "next.example.com".into(),
        },
        DnsRecord {
            name: "example.com".into(),
            record_type: DnsRecordType::Ds,
            ttl: 3600,
            value: "12345 13 2 abc".into(),
        },
    ];
    let status = evaluate_dnssec("example.com", &records).unwrap();
    assert!(status.fully_signed);
    assert!(status.has_dnskey);
    assert!(status.has_rrsig);
    assert!(status.has_nsec);
    assert!(status.has_ds);
    assert_eq!(status.grade(), DnsSeverity::Info);
}

#[test]
fn evaluate_dnssec_no_records() {
    let status = evaluate_dnssec("example.com", &[]).unwrap();
    assert!(!status.fully_signed);
    assert!(!status.has_dnskey);
    assert_eq!(status.grade(), DnsSeverity::High);
}

#[test]
fn generate_cache_poisoning_payloads_count() {
    let payloads = generate_cache_poisoning_payloads("example.com", "6.6.6.6", 5).unwrap();
    assert_eq!(payloads.len(), 5);
    for p in &payloads {
        assert!(p.target_domain.contains("example.com"));
        assert_eq!(p.spoofed_answer, "6.6.6.6");
        assert!(p.authority_injection.contains("example.com"));
    }
}

#[test]
fn generate_cache_poisoning_payloads_unique_txids() {
    let payloads = generate_cache_poisoning_payloads("test.org", "1.2.3.4", 10).unwrap();
    let txids: std::collections::HashSet<u16> = payloads.iter().map(|p| p.transaction_id).collect();
    assert_eq!(txids.len(), 10);
}

#[test]
fn check_dangling_records_cloud_cname() {
    let records = vec![DnsRecord {
        name: "app.example.com".into(),
        record_type: DnsRecordType::Cname,
        ttl: 3600,
        value: "old-bucket.s3.amazonaws.com".into(),
    }];
    let dangling = check_dangling_records(&records);
    assert_eq!(dangling.len(), 1);
    assert!(matches!(
        dangling[0].reason,
        DanglingReason::UnclaimedCloud(_)
    ));
    assert_eq!(dangling[0].risk, DnsSeverity::High);
}

#[test]
fn check_dangling_records_orphaned_cname() {
    let records = vec![DnsRecord {
        name: "alias.example.com".into(),
        record_type: DnsRecordType::Cname,
        ttl: 300,
        value: "gone.nowhere.test".into(),
    }];
    let dangling = check_dangling_records(&records);
    assert_eq!(dangling.len(), 1);
    assert_eq!(dangling[0].reason, DanglingReason::OrphanedCname);
}

#[test]
fn check_dangling_records_documentation_ip() {
    let records = vec![DnsRecord {
        name: "dead.example.com".into(),
        record_type: DnsRecordType::A,
        ttl: 3600,
        value: "192.0.2.1".into(),
    }];
    let dangling = check_dangling_records(&records);
    assert_eq!(dangling.len(), 1);
    assert_eq!(dangling[0].reason, DanglingReason::NxdomainTarget);
}

#[test]
fn check_dangling_records_no_false_positives() {
    let records = vec![
        DnsRecord {
            name: "www.example.com".into(),
            record_type: DnsRecordType::A,
            ttl: 300,
            value: "93.184.216.34".into(),
        },
        DnsRecord {
            name: "mx.example.com".into(),
            record_type: DnsRecordType::Mx,
            ttl: 300,
            value: "10 mail.example.com".into(),
        },
    ];
    let dangling = check_dangling_records(&records);
    assert!(dangling.is_empty());
}

#[test]
fn evaluate_nsec_walk_walkable() {
    let records = vec![
        DnsRecord {
            name: "alpha.example.com".into(),
            record_type: DnsRecordType::Nsec,
            ttl: 300,
            value: "beta.example.com A NS".into(),
        },
        DnsRecord {
            name: "beta.example.com".into(),
            record_type: DnsRecordType::Nsec,
            ttl: 300,
            value: "gamma.example.com A".into(),
        },
    ];
    let result = evaluate_nsec_walk("example.com", &records).unwrap();
    assert!(result.walkable);
    assert!(!result.uses_nsec3);
    assert_eq!(result.discovered_names.len(), 2);
}

#[test]
fn evaluate_nsec_walk_nsec3_not_walkable() {
    let records = vec![DnsRecord {
        name: "abc123.example.com".into(),
        record_type: DnsRecordType::Nsec3,
        ttl: 300,
        value: "01000a00deadbeef".into(),
    }];
    let result = evaluate_nsec_walk("example.com", &records).unwrap();
    assert!(!result.walkable);
    assert!(result.uses_nsec3);
}

#[test]
fn assess_amplification_open_resolver() {
    let result = assess_amplification("8.8.8.8", 44, 512, true);
    assert!(result.open_resolver);
    assert!(result.amplification_factor > 10.0);
}

#[test]
fn assess_amplification_closed_resolver() {
    let result = assess_amplification("10.0.0.1", 44, 44, false);
    assert!(!result.open_resolver);
    assert!(!result.recursion_available);
}

#[test]
fn assess_amplification_zero_query_size() {
    let result = assess_amplification("1.1.1.1", 0, 100, true);
    assert_eq!(result.amplification_factor, 0.0);
}

#[test]
fn check_delegation_lame() {
    let result = check_delegation(
        "sub.example.com",
        &[("ns1.dead.com", false), ("ns2.dead.com", false)],
    )
    .unwrap();
    assert!(result.lame_delegation);
}

#[test]
fn check_delegation_healthy() {
    let result = check_delegation(
        "sub.example.com",
        &[("ns1.ok.com", true), ("ns2.ok.com", true)],
    )
    .unwrap();
    assert!(!result.lame_delegation);
}

#[test]
fn check_delegation_missing_glue() {
    let result = check_delegation("sub.example.com", &[("ns1.sub.example.com", true)]).unwrap();
    assert!(result.missing_glue);
}

#[test]
fn evaluate_rebinding_vulnerable() {
    let result = evaluate_rebinding("test.com", "1.2.3.4", "127.0.0.1", 0, false).unwrap();
    assert!(result.vulnerable);
    assert!(result.description.contains("vulnerable"));
}

#[test]
fn evaluate_rebinding_blocked() {
    let result = evaluate_rebinding("test.com", "1.2.3.4", "10.0.0.1", 60, true).unwrap();
    assert!(!result.vulnerable);
    assert!(result.description.contains("defense active"));
}

#[test]
fn evaluate_rebinding_external_target() {
    let result = evaluate_rebinding("test.com", "1.2.3.4", "8.8.8.8", 300, false).unwrap();
    assert!(!result.vulnerable);
}

#[test]
fn supported_check_types_has_nine() {
    assert_eq!(supported_check_types().len(), 9);
}

#[test]
fn generate_findings_zone_transfer() {
    let audit = DnsSecurityAudit {
        domain: "example.com".into(),
        zone_transfer: vec![ZoneTransferResult {
            domain: "example.com".into(),
            nameserver: "ns1.example.com".into(),
            success: true,
            records: vec![DnsRecord {
                name: "a.example.com".into(),
                record_type: DnsRecordType::A,
                ttl: 300,
                value: "1.2.3.4".into(),
            }],
            error: None,
        }],
        dnssec: None,
        cache_poisoning_payloads: vec![],
        rebinding_tests: vec![],
        dangling_records: vec![],
        email_auth: None,
        nsec_walk: None,
        amplification: vec![],
        delegation: vec![],
        findings: vec![],
    };
    let findings = generate_findings(&audit);
    assert!(!findings.is_empty());
    assert!(
        findings
            .iter()
            .any(|f| f.check_type == DnsCheckType::ZoneTransfer)
    );
    assert!(findings.iter().any(|f| f.severity == DnsSeverity::Critical));
}

#[test]
fn generate_findings_comprehensive() {
    let audit = DnsSecurityAudit {
        domain: "example.com".into(),
        zone_transfer: vec![],
        dnssec: Some(DnssecStatus {
            domain: "example.com".into(),
            has_dnskey: false,
            has_rrsig: false,
            has_nsec: false,
            has_nsec3: false,
            has_ds: false,
            fully_signed: false,
        }),
        cache_poisoning_payloads: generate_cache_poisoning_payloads("example.com", "6.6.6.6", 3)
            .unwrap(),
        rebinding_tests: vec![RebindingTestResult {
            domain: "example.com".into(),
            initial_ip: "1.2.3.4".into(),
            rebind_ip: "192.168.1.1".into(),
            ttl_used: 0,
            vulnerable: true,
            description: "vulnerable".into(),
        }],
        dangling_records: vec![DanglingRecord {
            record: DnsRecord {
                name: "old.example.com".into(),
                record_type: DnsRecordType::Cname,
                ttl: 300,
                value: "dead.herokuapp.com".into(),
            },
            reason: DanglingReason::UnclaimedCloud("Heroku".into()),
            risk: DnsSeverity::High,
        }],
        email_auth: Some(EmailAuthAudit {
            domain: "example.com".into(),
            spf: Some(SpfAnalysis {
                raw_record: "v=spf1 +all".into(),
                version: Some("spf1".into()),
                mechanisms: vec![],
                all_qualifier: SpfQualifier::Pass,
                dns_lookup_count: 0,
                issues: vec!["SPF uses +all".into()],
                grade: DnsSeverity::Critical,
            }),
            dkim: vec![],
            dmarc: Some(parse_dmarc_record(None)),
            overall_grade: DnsSeverity::Critical,
        }),
        nsec_walk: Some(NsecWalkResult {
            domain: "example.com".into(),
            walkable: true,
            discovered_names: vec!["a.example.com".into()],
            uses_nsec3: false,
            nsec3_salt: None,
            nsec3_iterations: None,
        }),
        amplification: vec![AmplificationResult {
            resolver_ip: "1.2.3.4".into(),
            query_size: 44,
            response_size: 4000,
            amplification_factor: 90.9,
            open_resolver: true,
            recursion_available: true,
        }],
        delegation: vec![DelegationResult {
            subdomain: "sub.example.com".into(),
            delegated_ns: vec!["ns1.dead.com".into()],
            ns_reachable: vec![false],
            lame_delegation: true,
            missing_glue: false,
        }],
        findings: vec![],
    };
    let findings = generate_findings(&audit);

    let check_types: std::collections::HashSet<DnsCheckType> =
        findings.iter().map(|f| f.check_type).collect();

    // Should have findings from at least 7 different check types
    assert!(
        check_types.len() >= 7,
        "Expected >=7 check types, got {}: {:?}",
        check_types.len(),
        check_types
    );
}

#[test]
fn dns_severity_ordering() {
    assert!(DnsSeverity::Critical > DnsSeverity::High);
    assert!(DnsSeverity::High > DnsSeverity::Medium);
    assert!(DnsSeverity::Medium > DnsSeverity::Low);
    assert!(DnsSeverity::Low > DnsSeverity::Info);
}

#[test]
fn dns_record_type_display() {
    assert_eq!(DnsRecordType::A.to_string(), "A");
    assert_eq!(DnsRecordType::Aaaa.to_string(), "AAAA");
    assert_eq!(DnsRecordType::Dnskey.to_string(), "DNSKEY");
    assert_eq!(DnsRecordType::Axfr.to_string(), "AXFR");
}

#[test]
fn dns_check_type_display() {
    assert_eq!(
        DnsCheckType::ZoneTransfer.to_string(),
        "Zone Transfer (AXFR)"
    );
    assert_eq!(
        DnsCheckType::EmailAuthentication.to_string(),
        "Email Authentication (SPF/DKIM/DMARC)"
    );
}

#[test]
fn dangling_reason_display() {
    assert_eq!(
        DanglingReason::NxdomainTarget.to_string(),
        "Target returns NXDOMAIN"
    );
    assert_eq!(
        DanglingReason::UnclaimedCloud("AWS".into()).to_string(),
        "Unclaimed AWS resource"
    );
}

#[test]
fn dmarc_policy_display() {
    assert_eq!(DmarcPolicy::Reject.to_string(), "reject");
    assert_eq!(DmarcPolicy::Missing.to_string(), "missing");
}

#[test]
fn spf_qualifier_display() {
    assert_eq!(SpfQualifier::Pass.to_string(), "+");
    assert_eq!(SpfQualifier::Fail.to_string(), "-");
    assert_eq!(SpfQualifier::SoftFail.to_string(), "~");
}

#[test]
fn check_dangling_records_multiple_cloud_providers() {
    let records = vec![
        DnsRecord {
            name: "a.example.com".into(),
            record_type: DnsRecordType::Cname,
            ttl: 300,
            value: "x.herokuapp.com".into(),
        },
        DnsRecord {
            name: "b.example.com".into(),
            record_type: DnsRecordType::Cname,
            ttl: 300,
            value: "y.netlify.app".into(),
        },
        DnsRecord {
            name: "c.example.com".into(),
            record_type: DnsRecordType::Cname,
            ttl: 300,
            value: "z.github.io".into(),
        },
    ];
    let dangling = check_dangling_records(&records);
    assert_eq!(dangling.len(), 3);
}

#[test]
fn nsec3_params_parsing() {
    let records = vec![DnsRecord {
        name: "hash.example.com".into(),
        record_type: DnsRecordType::Nsec3,
        ttl: 300,
        value: "0100000aff".into(),
    }];
    let result = evaluate_nsec_walk("example.com", &records).unwrap();
    assert!(result.uses_nsec3);
    assert!(result.nsec3_iterations.is_some());
}

#[test]
fn parse_axfr_response_with_txt_record() {
    let mut pkt = Vec::new();
    // Header
    pkt.extend_from_slice(&[0x00, 0x01]); // TXID
    pkt.extend_from_slice(&[0x84, 0x00]); // flags
    pkt.extend_from_slice(&[0x00, 0x00]); // QDCOUNT=0
    pkt.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NS+AR

    // Name: "x.com" => 1 x 3 c o m 0
    pkt.extend_from_slice(&[1, b'x', 3, b'c', b'o', b'm', 0]);
    // TYPE=TXT(16), CLASS=IN
    pkt.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]);
    // TTL=60
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
    // RDLENGTH = 1 (string length byte) + 5 (string)
    pkt.extend_from_slice(&[0x00, 0x06]);
    // TXT RDATA: length-prefixed string "hello"
    pkt.push(5);
    pkt.extend_from_slice(b"hello");

    let records = parse_axfr_response(&pkt, "x.com").unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_type, DnsRecordType::Txt);
    assert_eq!(records[0].value, "hello");
}
