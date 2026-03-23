use crate::email_security::*;

#[test]
fn check_spf_present_with_hardfail() {
    let records = vec!["v=spf1 include:_spf.google.com -all".to_string()];
    let issues = check_spf_issues(&records);
    assert!(issues.is_empty());
}

#[test]
fn check_spf_missing() {
    let records: Vec<String> = vec![];
    let issues = check_spf_issues(&records);
    assert!(issues.contains(&EmailIssue::MissingSpf));
}

#[test]
fn check_spf_weak_plus_all() {
    let records = vec!["v=spf1 +all".to_string()];
    let issues = check_spf_issues(&records);
    assert!(issues.contains(&EmailIssue::WeakSpf));
}

#[test]
fn check_spf_weak_neutral_all() {
    let records = vec!["v=spf1 ?all".to_string()];
    let issues = check_spf_issues(&records);
    assert!(issues.contains(&EmailIssue::WeakSpf));
}

#[test]
fn check_dmarc_present_with_reject() {
    let records = vec!["v=DMARC1; p=reject; rua=mailto:dmarc@example.com".to_string()];
    let issues = check_dmarc_issues(&records);
    assert!(issues.is_empty());
}

#[test]
fn check_dmarc_missing() {
    let records: Vec<String> = vec![];
    let issues = check_dmarc_issues(&records);
    assert!(issues.contains(&EmailIssue::MissingDmarc));
}

#[test]
fn check_dmarc_weak_none_policy() {
    let records = vec!["v=DMARC1; p=none".to_string()];
    let issues = check_dmarc_issues(&records);
    assert!(issues.contains(&EmailIssue::WeakDmarc));
}

#[test]
fn email_severity_ordering() {
    assert!(email_severity(&EmailIssue::WeakSpf) > email_severity(&EmailIssue::WeakDmarc));
    assert!(email_severity(&EmailIssue::WeakDmarc) > email_severity(&EmailIssue::MissingSpf));
    assert!(email_severity(&EmailIssue::MissingSpf) > email_severity(&EmailIssue::MissingDmarc));
    assert!(email_severity(&EmailIssue::MissingDmarc) > email_severity(&EmailIssue::MissingDkim));
}

#[test]
fn email_issue_display() {
    assert_eq!(EmailIssue::MissingSpf.to_string(), "missing_spf");
    assert_eq!(EmailIssue::WeakSpf.to_string(), "weak_spf");
    assert_eq!(EmailIssue::MissingDmarc.to_string(), "missing_dmarc");
    assert_eq!(EmailIssue::WeakDmarc.to_string(), "weak_dmarc");
    assert_eq!(EmailIssue::MissingDkim.to_string(), "missing_dkim");
}

#[test]
fn email_findings_to_operations_creates_findings() {
    let issues = vec![EmailIssue::MissingSpf, EmailIssue::MissingDmarc];
    let mut seq = 0;
    let ops = email_findings_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
    for op in &ops {
        match &op.operation {
            aegis_protocol::operation::GraphOperation::AddFinding {
                vulnerability_class,
                ..
            } => {
                assert_eq!(
                    *vulnerability_class,
                    aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
                );
            }
            _ => panic!("expected AddFinding"),
        }
    }
}

#[test]
fn email_findings_to_operations_empty() {
    let mut seq = 3;
    let ops = email_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 3);
}

#[test]
fn check_email_security_skips_localhost() {
    let issues = check_email_security("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn check_email_security_skips_loopback() {
    let issues = check_email_security("http://127.0.0.1");
    assert!(issues.is_empty());
}

#[test]
fn email_security_issue_display_missing_spf() {
    assert_eq!(EmailSecurityIssue::MissingSpf.to_string(), "missing_spf");
}

#[test]
fn email_security_issue_display_weak_spf() {
    let issue = EmailSecurityIssue::WeakSpf {
        record: "v=spf1 +all".to_string(),
    };
    assert_eq!(issue.to_string(), "weak_spf: v=spf1 +all");
}

#[test]
fn email_security_issue_display_spf_too_many_lookups() {
    let issue = EmailSecurityIssue::SpfTooManyLookups { count: 15 };
    assert_eq!(issue.to_string(), "spf_too_many_lookups: 15");
}

#[test]
fn email_security_issue_display_spf_all_mechanism() {
    let issue = EmailSecurityIssue::SpfAllMechanism {
        mechanism: "+all".to_string(),
    };
    assert_eq!(issue.to_string(), "spf_all_mechanism: +all");
}

#[test]
fn email_security_issue_display_missing_dmarc() {
    assert_eq!(
        EmailSecurityIssue::MissingDmarc.to_string(),
        "missing_dmarc"
    );
}

#[test]
fn email_security_issue_display_weak_dmarc() {
    let issue = EmailSecurityIssue::WeakDmarc {
        policy: "none".to_string(),
    };
    assert_eq!(issue.to_string(), "weak_dmarc: none");
}

#[test]
fn email_security_issue_display_dmarc_no_reporting() {
    assert_eq!(
        EmailSecurityIssue::DmarcNoReporting.to_string(),
        "dmarc_no_reporting"
    );
}

#[test]
fn email_security_issue_display_dmarc_subdomain_weak() {
    let issue = EmailSecurityIssue::DmarcSubdomainWeak {
        policy: "none".to_string(),
    };
    assert_eq!(issue.to_string(), "dmarc_subdomain_weak: none");
}

#[test]
fn email_security_issue_display_missing_dkim() {
    assert_eq!(EmailSecurityIssue::MissingDkim.to_string(), "missing_dkim");
}

#[test]
fn email_security_issue_display_multiple_dkim_selectors() {
    let issue = EmailSecurityIssue::MultipleDkimSelectors { count: 3 };
    assert_eq!(issue.to_string(), "multiple_dkim_selectors: 3");
}

#[test]
fn email_security_issue_display_missing_mta_sts() {
    assert_eq!(
        EmailSecurityIssue::MissingMtaSts.to_string(),
        "missing_mta_sts"
    );
}

#[test]
fn email_security_issue_display_missing_tls_rpt() {
    assert_eq!(
        EmailSecurityIssue::MissingTlsRpt.to_string(),
        "missing_tls_rpt"
    );
}

#[test]
fn email_security_severity_spf_all_mechanism_plus_all() {
    let issue = EmailSecurityIssue::SpfAllMechanism {
        mechanism: "+all".to_string(),
    };
    assert_eq!(email_security_severity(&issue), 7.0);
}

#[test]
fn email_security_severity_spf_all_mechanism_neutral() {
    let issue = EmailSecurityIssue::SpfAllMechanism {
        mechanism: "?all".to_string(),
    };
    assert_eq!(email_security_severity(&issue), 5.5);
}

#[test]
fn email_security_severity_weak_dmarc() {
    let issue = EmailSecurityIssue::WeakDmarc {
        policy: "none".to_string(),
    };
    assert_eq!(email_security_severity(&issue), 5.5);
}

#[test]
fn email_security_severity_weak_spf() {
    let issue = EmailSecurityIssue::WeakSpf {
        record: "v=spf1 ~all".to_string(),
    };
    assert_eq!(email_security_severity(&issue), 5.0);
}

#[test]
fn email_security_severity_dmarc_subdomain_weak() {
    let issue = EmailSecurityIssue::DmarcSubdomainWeak {
        policy: "none".to_string(),
    };
    assert_eq!(email_security_severity(&issue), 5.0);
}

#[test]
fn email_security_severity_missing_spf() {
    assert_eq!(
        email_security_severity(&EmailSecurityIssue::MissingSpf),
        4.5
    );
}

#[test]
fn email_security_severity_missing_dmarc() {
    assert_eq!(
        email_security_severity(&EmailSecurityIssue::MissingDmarc),
        4.0
    );
}

#[test]
fn email_security_severity_dmarc_no_reporting() {
    assert_eq!(
        email_security_severity(&EmailSecurityIssue::DmarcNoReporting),
        3.5
    );
}

#[test]
fn email_security_severity_spf_too_many_lookups() {
    let issue = EmailSecurityIssue::SpfTooManyLookups { count: 15 };
    assert_eq!(email_security_severity(&issue), 3.5);
}

#[test]
fn email_security_severity_missing_dkim() {
    assert_eq!(
        email_security_severity(&EmailSecurityIssue::MissingDkim),
        3.0
    );
}

#[test]
fn email_security_severity_missing_mta_sts() {
    assert_eq!(
        email_security_severity(&EmailSecurityIssue::MissingMtaSts),
        2.5
    );
}

#[test]
fn email_security_severity_multiple_dkim_selectors() {
    let issue = EmailSecurityIssue::MultipleDkimSelectors { count: 3 };
    assert_eq!(email_security_severity(&issue), 2.0);
}

#[test]
fn email_security_severity_missing_tls_rpt() {
    assert_eq!(
        email_security_severity(&EmailSecurityIssue::MissingTlsRpt),
        2.0
    );
}

#[test]
fn analyze_email_records_missing_spf() {
    let issues = analyze_email_records(&[], &[], &[]);
    assert!(issues.contains(&EmailSecurityIssue::MissingSpf));
}

#[test]
fn analyze_email_records_weak_spf_plus_all() {
    let txt = vec!["v=spf1 +all".to_string()];
    let issues = analyze_email_records(&txt, &[], &[]);
    assert!(issues.iter().any(|i| matches!(
        i,
        EmailSecurityIssue::SpfAllMechanism { mechanism } if mechanism == "+all"
    )));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EmailSecurityIssue::WeakSpf { .. }))
    );
}

#[test]
fn analyze_email_records_weak_spf_neutral_all() {
    let txt = vec!["v=spf1 ?all".to_string()];
    let issues = analyze_email_records(&txt, &[], &[]);
    assert!(issues.iter().any(|i| matches!(
        i,
        EmailSecurityIssue::SpfAllMechanism { mechanism } if mechanism == "?all"
    )));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EmailSecurityIssue::WeakSpf { .. }))
    );
}

#[test]
fn analyze_email_records_weak_spf_softfail() {
    let txt = vec!["v=spf1 include:_spf.google.com ~all".to_string()];
    let issues = analyze_email_records(&txt, &[], &[]);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EmailSecurityIssue::WeakSpf { .. }))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EmailSecurityIssue::SpfAllMechanism { .. }))
    );
}

#[test]
fn analyze_email_records_spf_hard_fail_no_issue() {
    let txt = vec!["v=spf1 include:_spf.google.com -all".to_string()];
    let issues = analyze_email_records(&txt, &[], &["v=DKIM1".to_string()]);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EmailSecurityIssue::WeakSpf { .. }))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EmailSecurityIssue::MissingSpf))
    );
}

#[test]
fn analyze_email_records_spf_too_many_lookups() {
    let txt = vec![
        "v=spf1 include:a include:b include:c include:d include:e include:f include:g include:h include:i include:j include:k -all".to_string(),
    ];
    let issues = analyze_email_records(&txt, &[], &[]);
    assert!(issues.iter().any(|i| matches!(
        i,
        EmailSecurityIssue::SpfTooManyLookups { count } if *count == 11
    )));
}

#[test]
fn analyze_email_records_spf_under_10_lookups_no_issue() {
    let txt = vec!["v=spf1 include:a include:b include:c -all".to_string()];
    let issues = analyze_email_records(&txt, &[], &["v=DKIM1".to_string()]);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EmailSecurityIssue::SpfTooManyLookups { .. }))
    );
}

#[test]
fn analyze_email_records_missing_dmarc() {
    let issues = analyze_email_records(&[], &[], &[]);
    assert!(issues.contains(&EmailSecurityIssue::MissingDmarc));
}

#[test]
fn analyze_email_records_weak_dmarc_none_policy() {
    let dmarc = vec!["v=DMARC1; p=none".to_string()];
    let issues = analyze_email_records(&[], &dmarc, &[]);
    assert!(issues.iter().any(|i| matches!(
        i,
        EmailSecurityIssue::WeakDmarc { policy } if policy == "none"
    )));
}

#[test]
fn analyze_email_records_dmarc_reject_no_issue() {
    let dmarc = vec!["v=DMARC1; p=reject; rua=mailto:dmarc@example.com".to_string()];
    let issues = analyze_email_records(&[], &dmarc, &["v=DKIM1".to_string()]);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EmailSecurityIssue::WeakDmarc { .. }))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EmailSecurityIssue::MissingDmarc))
    );
}

#[test]
fn analyze_email_records_dmarc_no_reporting() {
    let dmarc = vec!["v=DMARC1; p=reject".to_string()];
    let issues = analyze_email_records(&[], &dmarc, &[]);
    assert!(issues.contains(&EmailSecurityIssue::DmarcNoReporting));
}

#[test]
fn analyze_email_records_dmarc_with_reporting() {
    let dmarc = vec!["v=DMARC1; p=reject; rua=mailto:dmarc@example.com".to_string()];
    let issues = analyze_email_records(&[], &dmarc, &[]);
    assert!(!issues.contains(&EmailSecurityIssue::DmarcNoReporting));
}

#[test]
fn analyze_email_records_dmarc_subdomain_weak() {
    let dmarc = vec!["v=DMARC1; p=reject; sp=none".to_string()];
    let issues = analyze_email_records(&[], &dmarc, &[]);
    assert!(issues.iter().any(|i| matches!(
        i,
        EmailSecurityIssue::DmarcSubdomainWeak { policy } if policy == "none"
    )));
}

#[test]
fn analyze_email_records_missing_dkim() {
    let issues = analyze_email_records(&[], &[], &[]);
    assert!(issues.contains(&EmailSecurityIssue::MissingDkim));
}

#[test]
fn analyze_email_records_dkim_present_no_issue() {
    let dkim = vec!["v=DKIM1; k=rsa; p=MIGfMA0GCS...".to_string()];
    let txt = vec![
        "v=spf1 -all".to_string(),
        "v=STSv1 id=123".to_string(),
        "v=TLSRPTv1 rua=mailto:tlsrpt@example.com".to_string(),
    ];
    let dmarc = vec!["v=DMARC1; p=reject; rua=mailto:dmarc@example.com".to_string()];
    let issues = analyze_email_records(&txt, &dmarc, &dkim);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EmailSecurityIssue::MissingDkim))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EmailSecurityIssue::MultipleDkimSelectors { .. }))
    );
}

#[test]
fn analyze_email_records_multiple_dkim_selectors() {
    let dkim = vec![
        "v=DKIM1; k=rsa; p=key1".to_string(),
        "v=DKIM1; k=rsa; p=key2".to_string(),
        "v=DKIM1; k=rsa; p=key3".to_string(),
    ];
    let issues = analyze_email_records(&[], &[], &dkim);
    assert!(issues.iter().any(|i| matches!(
        i,
        EmailSecurityIssue::MultipleDkimSelectors { count } if *count == 3
    )));
}

#[test]
fn analyze_email_records_missing_mta_sts() {
    let issues = analyze_email_records(&[], &[], &[]);
    assert!(issues.contains(&EmailSecurityIssue::MissingMtaSts));
}

#[test]
fn analyze_email_records_mta_sts_present() {
    let txt = vec!["v=STSv1 id=123".to_string()];
    let issues = analyze_email_records(&txt, &[], &[]);
    assert!(!issues.contains(&EmailSecurityIssue::MissingMtaSts));
}

#[test]
fn analyze_email_records_missing_tls_rpt() {
    let issues = analyze_email_records(&[], &[], &[]);
    assert!(issues.contains(&EmailSecurityIssue::MissingTlsRpt));
}

#[test]
fn analyze_email_records_tls_rpt_present() {
    let txt = vec!["v=TLSRPTv1 rua=mailto:tlsrpt@example.com".to_string()];
    let issues = analyze_email_records(&txt, &[], &[]);
    assert!(!issues.contains(&EmailSecurityIssue::MissingTlsRpt));
}

#[test]
fn analyze_email_records_all_clean() {
    let txt = vec![
        "v=spf1 include:_spf.google.com -all".to_string(),
        "v=STSv1 id=123".to_string(),
        "v=TLSRPTv1 rua=mailto:tlsrpt@example.com".to_string(),
    ];
    let dmarc = vec!["v=DMARC1; p=reject; rua=mailto:dmarc@example.com".to_string()];
    let dkim = vec!["v=DKIM1; k=rsa; p=MIGfMA0GCS...".to_string()];
    let issues = analyze_email_records(&txt, &dmarc, &dkim);
    assert_eq!(issues.len(), 0);
}

#[test]
fn analyze_email_records_all_missing() {
    let issues = analyze_email_records(&[], &[], &[]);
    assert!(issues.contains(&EmailSecurityIssue::MissingSpf));
    assert!(issues.contains(&EmailSecurityIssue::MissingDmarc));
    assert!(issues.contains(&EmailSecurityIssue::MissingDkim));
    assert!(issues.contains(&EmailSecurityIssue::MissingMtaSts));
    assert!(issues.contains(&EmailSecurityIssue::MissingTlsRpt));
    assert_eq!(issues.len(), 5);
}

#[test]
fn email_security_to_operations_empty() {
    let mut seq = 5;
    let ops = email_security_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn email_security_to_operations_single() {
    let issues = vec![EmailSecurityIssue::MissingSpf];
    let mut seq = 0;
    let ops = email_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn email_security_to_operations_multiple() {
    let issues = vec![
        EmailSecurityIssue::MissingSpf,
        EmailSecurityIssue::MissingDmarc,
        EmailSecurityIssue::MissingDkim,
    ];
    let mut seq = 0;
    let ops = email_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
    for op in &ops {
        match &op.operation {
            aegis_protocol::operation::GraphOperation::AddFinding {
                vulnerability_class,
                confidence,
                ..
            } => {
                assert_eq!(
                    *vulnerability_class,
                    aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
                );
                assert_eq!(confidence.value(), 0.5);
            }
            _ => panic!("expected AddFinding"),
        }
    }
}
