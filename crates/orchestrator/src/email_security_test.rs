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
