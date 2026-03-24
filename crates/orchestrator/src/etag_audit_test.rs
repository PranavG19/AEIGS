use crate::etag_audit::*;

// --- Detection: InodeLeak ---

#[test]
fn apache_inode_etag_detected() {
    let issues = analyze_etag(Some(r#""5f3a1b-264-5e8c4a0e""#));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::InodeLeak { .. }))
    );
}

#[test]
fn three_hex_parts_is_inode() {
    let issues = analyze_etag(Some(r#""1a2b-3c4d-5e6f""#));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::InodeLeak { .. }))
    );
}

#[test]
fn non_hex_parts_not_inode() {
    let issues = analyze_etag(Some(r#""hello-world-foo""#));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EtagIssue::InodeLeak { .. }))
    );
}

#[test]
fn two_parts_not_inode() {
    let issues = analyze_etag(Some(r#""abc-def""#));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EtagIssue::InodeLeak { .. }))
    );
}

#[test]
fn is_apache_inode_etag_helper() {
    assert!(is_apache_inode_etag("5f3a1b-264-5e8c4a0e"));
    assert!(!is_apache_inode_etag("abc-def"));
    assert!(!is_apache_inode_etag("hello-world-foo"));
    assert!(!is_apache_inode_etag(""));
}

// --- Detection: WeakEtag ---

#[test]
fn weak_etag_flagged() {
    let issues = analyze_etag(Some(r#"W/"abc123""#));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::WeakEtag { .. }))
    );
}

#[test]
fn strong_etag_not_weak() {
    let issues = analyze_etag(Some(r#""abc123""#));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EtagIssue::WeakEtag { .. }))
    );
}

// --- Detection: LongEtag ---

#[test]
fn long_etag_flagged() {
    let long = format!(r#""{}""#, "a".repeat(70));
    let issues = analyze_etag(Some(&long));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::LongEtag { length: 70, .. }))
    );
}

#[test]
fn normal_length_etag_ok() {
    let issues = analyze_etag(Some(r#""abc123def456""#));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EtagIssue::LongEtag { .. }))
    );
}

// --- Detection: TimestampLeak ---

#[test]
fn timestamp_decimal_detected() {
    let issues = analyze_etag(Some(r#""1700000000""#));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::TimestampLeak { .. }))
    );
}

#[test]
fn timestamp_hex_detected() {
    let issues = analyze_etag(Some(r#""65548d80""#));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::TimestampLeak { .. }))
    );
}

#[test]
fn non_timestamp_number_not_flagged() {
    let issues = analyze_etag(Some(r#""12345""#));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EtagIssue::TimestampLeak { .. }))
    );
}

// --- Detection: SequentialEtag ---

#[test]
fn sequential_small_number_detected() {
    let issues = analyze_etag(Some(r#""42""#));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::SequentialEtag { .. }))
    );
}

#[test]
fn sequential_boundary_9999() {
    let issues = analyze_etag(Some(r#""9999""#));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::SequentialEtag { .. }))
    );
}

#[test]
fn sequential_boundary_10000_not_flagged() {
    let issues = analyze_etag(Some(r#""10000""#));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EtagIssue::SequentialEtag { .. }))
    );
}

#[test]
fn sequential_zero() {
    let issues = analyze_etag(Some(r#""0""#));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::SequentialEtag { .. }))
    );
}

// --- Detection: UnquotedEtag ---

#[test]
fn unquoted_etag_detected() {
    let issues = analyze_etag(Some("abc123"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::UnquotedEtag { .. }))
    );
}

#[test]
fn quoted_etag_not_unquoted() {
    let issues = analyze_etag(Some(r#""abc123""#));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EtagIssue::UnquotedEtag { .. }))
    );
}

#[test]
fn weak_quoted_etag_not_unquoted() {
    let issues = analyze_etag(Some(r#"W/"abc123""#));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EtagIssue::UnquotedEtag { .. }))
    );
}

// --- Detection: EmptyEtag ---

#[test]
fn empty_etag_detected() {
    let issues = analyze_etag(Some(""));
    assert!(issues.iter().any(|i| matches!(i, EtagIssue::EmptyEtag)));
}

#[test]
fn whitespace_only_is_empty() {
    let issues = analyze_etag(Some("   "));
    assert!(issues.iter().any(|i| matches!(i, EtagIssue::EmptyEtag)));
}

// --- Detection: InternalPathLeak ---

#[test]
fn path_in_etag_detected() {
    let issues = analyze_etag(Some(r#""/var/www/cache/item.html""#));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::InternalPathLeak { .. }))
    );
}

#[test]
fn no_path_no_leak() {
    let issues = analyze_etag(Some(r#""abc123""#));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EtagIssue::InternalPathLeak { .. }))
    );
}

// --- Detection: HashMismatch ---

#[test]
fn corrupted_md5_detected() {
    let issues = analyze_etag(Some(r#""d41d8cd98f00b204e980099zecf8427e""#));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::HashMismatch { .. }))
    );
}

#[test]
fn corrupted_sha1_detected() {
    let bad_sha1 = format!(r#""{}z""#, "a".repeat(39));
    let issues = analyze_etag(Some(&bad_sha1));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::HashMismatch { .. }))
    );
}

#[test]
fn valid_sha1_no_mismatch() {
    let issues = analyze_etag(Some(r#""33a64df551425fcc55e4d42a148795d9f25f89d4""#));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EtagIssue::HashMismatch { .. }))
    );
}

#[test]
fn valid_md5_no_mismatch() {
    let issues = analyze_etag(Some(r#""d41d8cd98f00b204e9800998ecf8427e""#));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EtagIssue::HashMismatch { .. }))
    );
}

// --- No header ---

#[test]
fn no_header_no_issues() {
    let issues = analyze_etag(None);
    assert!(issues.is_empty());
}

// --- Normal hash etag produces no issues ---

#[test]
fn normal_hash_etag_clean() {
    let issues = analyze_etag(Some(r#""33a64df551425fcc55e4d42a148795d9f25f89d4""#));
    assert!(issues.is_empty());
}

// --- Display ---

#[test]
fn display_inode_leak() {
    let issue = EtagIssue::InodeLeak {
        etag: "5f3a1b-264-5e8c4a0e".into(),
    };
    assert_eq!(issue.to_string(), "inode_leak: 5f3a1b-264-5e8c4a0e");
}

#[test]
fn display_weak_etag() {
    let issue = EtagIssue::WeakEtag { etag: "abc".into() };
    assert_eq!(issue.to_string(), "weak_etag: abc");
}

#[test]
fn display_long_etag() {
    let issue = EtagIssue::LongEtag {
        etag: "x".repeat(70),
        length: 70,
    };
    assert!(issue.to_string().contains("long_etag:"));
    assert!(issue.to_string().contains("70 chars"));
}

#[test]
fn display_timestamp_leak() {
    let issue = EtagIssue::TimestampLeak {
        etag: "1700000000".into(),
    };
    assert_eq!(issue.to_string(), "timestamp_leak: 1700000000");
}

#[test]
fn display_sequential_etag() {
    let issue = EtagIssue::SequentialEtag { etag: "42".into() };
    assert_eq!(issue.to_string(), "sequential_etag: 42");
}

#[test]
fn display_unquoted_etag() {
    let issue = EtagIssue::UnquotedEtag { raw: "abc".into() };
    assert_eq!(issue.to_string(), "unquoted_etag: abc");
}

#[test]
fn display_empty_etag() {
    assert_eq!(EtagIssue::EmptyEtag.to_string(), "empty_etag");
}

#[test]
fn display_internal_path_leak() {
    let issue = EtagIssue::InternalPathLeak {
        etag: "/var/www/x".into(),
    };
    assert_eq!(issue.to_string(), "internal_path_leak: /var/www/x");
}

#[test]
fn display_hash_mismatch() {
    let issue = EtagIssue::HashMismatch {
        etag: "badhash".into(),
    };
    assert_eq!(issue.to_string(), "hash_mismatch: badhash");
}

// --- Severity ---

#[test]
fn severity_inode_leak() {
    assert_eq!(
        etag_severity(&EtagIssue::InodeLeak {
            etag: String::new()
        }),
        4.0
    );
}

#[test]
fn severity_weak_etag() {
    assert_eq!(
        etag_severity(&EtagIssue::WeakEtag {
            etag: String::new()
        }),
        1.5
    );
}

#[test]
fn severity_long_etag() {
    assert_eq!(
        etag_severity(&EtagIssue::LongEtag {
            etag: String::new(),
            length: 70
        }),
        2.5
    );
}

#[test]
fn severity_timestamp_leak() {
    assert_eq!(
        etag_severity(&EtagIssue::TimestampLeak {
            etag: String::new()
        }),
        3.0
    );
}

#[test]
fn severity_sequential_etag() {
    assert_eq!(
        etag_severity(&EtagIssue::SequentialEtag {
            etag: String::new()
        }),
        3.5
    );
}

#[test]
fn severity_unquoted_etag() {
    assert_eq!(
        etag_severity(&EtagIssue::UnquotedEtag { raw: String::new() }),
        1.0
    );
}

#[test]
fn severity_empty_etag() {
    assert_eq!(etag_severity(&EtagIssue::EmptyEtag), 0.5);
}

#[test]
fn severity_internal_path_leak() {
    assert_eq!(
        etag_severity(&EtagIssue::InternalPathLeak {
            etag: String::new()
        }),
        4.5
    );
}

#[test]
fn severity_hash_mismatch() {
    assert_eq!(
        etag_severity(&EtagIssue::HashMismatch {
            etag: String::new()
        }),
        1.0
    );
}

// --- Operations ---

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = etag_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_one_per_issue() {
    let issues = analyze_etag(Some(r#""5f3a1b-264-5e8c4a0e""#));
    assert!(!issues.is_empty());
    let mut seq = 5;
    let ops = etag_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), issues.len());
    assert_eq!(seq, 5 + issues.len() as u64);
}

#[test]
fn operations_multiple_issues() {
    let issues = vec![
        EtagIssue::InodeLeak {
            etag: "a-b-c".into(),
        },
        EtagIssue::WeakEtag {
            etag: "a-b-c".into(),
        },
        EtagIssue::LongEtag {
            etag: "x".repeat(70),
            length: 70,
        },
    ];
    let mut seq = 0;
    let ops = etag_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn operations_confidence_is_half() {
    let issues = vec![EtagIssue::EmptyEtag];
    let mut seq = 0;
    let ops = etag_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    if let aegis_protocol::operation::GraphOperation::AddFinding { confidence, .. } =
        &ops[0].operation
    {
        assert!((confidence.value() - 0.5).abs() < f64::EPSILON);
    } else {
        panic!("expected AddFinding");
    }
}

// --- Edge cases ---

#[test]
fn four_hex_parts_not_inode() {
    let issues = analyze_etag(Some(r#""aa-bb-cc-dd""#));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EtagIssue::InodeLeak { .. }))
    );
}

#[test]
fn empty_parts_not_inode() {
    let issues = analyze_etag(Some(r#""aa--cc""#));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, EtagIssue::InodeLeak { .. }))
    );
}

#[test]
fn combined_weak_and_inode() {
    let issues = analyze_etag(Some(r#"W/"5f3a1b-264-5e8c4a0e""#));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::WeakEtag { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::InodeLeak { .. }))
    );
}

#[test]
fn unquoted_sequential_both_flagged() {
    let issues = analyze_etag(Some("42"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::UnquotedEtag { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, EtagIssue::SequentialEtag { .. }))
    );
}

#[test]
fn empty_etag_returns_only_empty() {
    let issues = analyze_etag(Some(""));
    assert_eq!(issues.len(), 1);
    assert!(matches!(issues[0], EtagIssue::EmptyEtag));
}
