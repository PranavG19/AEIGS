use crate::method_scanner::*;

// --- analyze_methods: individual variant detection ---

#[test]
fn analyze_detects_trace() {
    let issues = analyze_methods("GET, TRACE");
    assert!(issues.contains(&MethodIssue::TraceEnabled));
}

#[test]
fn analyze_detects_connect() {
    let issues = analyze_methods("GET, CONNECT");
    assert!(issues.contains(&MethodIssue::ConnectEnabled));
}

#[test]
fn analyze_detects_put() {
    let issues = analyze_methods("GET, PUT");
    assert!(issues.contains(&MethodIssue::PutEnabled));
}

#[test]
fn analyze_detects_delete() {
    let issues = analyze_methods("GET, DELETE");
    assert!(issues.contains(&MethodIssue::DeleteEnabled));
}

#[test]
fn analyze_detects_patch() {
    let issues = analyze_methods("GET, PATCH");
    assert!(issues.contains(&MethodIssue::PatchEnabled));
}

#[test]
fn analyze_detects_webdav_propfind() {
    let issues = analyze_methods("GET, PROPFIND");
    assert!(issues.contains(&MethodIssue::WebdavPropfind));
}

#[test]
fn analyze_detects_webdav_mkcol() {
    let issues = analyze_methods("GET, MKCOL");
    assert!(issues.contains(&MethodIssue::WebdavMkcol));
}

#[test]
fn analyze_detects_webdav_copy() {
    let issues = analyze_methods("GET, COPY");
    assert!(issues.contains(&MethodIssue::WebdavCopy));
}

#[test]
fn analyze_detects_webdav_move() {
    let issues = analyze_methods("GET, MOVE");
    assert!(issues.contains(&MethodIssue::WebdavMove));
}

#[test]
fn analyze_detects_options_exposed() {
    let issues = analyze_methods("GET, OPTIONS");
    assert!(issues.contains(&MethodIssue::OptionsExposed));
}

#[test]
fn analyze_detects_wildcard_allow() {
    let issues = analyze_methods("GET, *");
    assert!(issues.contains(&MethodIssue::WildcardAllow));
}

#[test]
fn analyze_excessive_methods_boundary_seven_ok() {
    let issues = analyze_methods("GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MethodIssue::ExcessiveMethods { .. }))
    );
}

#[test]
fn analyze_excessive_methods_boundary_eight_flagged() {
    let issues = analyze_methods("GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE");
    let excessive = issues
        .iter()
        .find(|i| matches!(i, MethodIssue::ExcessiveMethods { .. }));
    assert_eq!(excessive, Some(&MethodIssue::ExcessiveMethods { count: 8 }));
}

// --- analyze_methods: edge cases ---

#[test]
fn analyze_empty_allow_header() {
    let issues = analyze_methods("");
    assert!(issues.is_empty());
}

#[test]
fn analyze_only_get_post() {
    let issues = analyze_methods("GET, POST");
    assert!(issues.is_empty());
}

#[test]
fn analyze_case_insensitive() {
    let issues = analyze_methods("get, put, trace, options");
    assert!(issues.contains(&MethodIssue::PutEnabled));
    assert!(issues.contains(&MethodIssue::TraceEnabled));
    assert!(issues.contains(&MethodIssue::OptionsExposed));
}

#[test]
fn analyze_extra_whitespace() {
    let issues = analyze_methods("  GET ,  TRACE ,  PUT  ");
    assert!(issues.contains(&MethodIssue::TraceEnabled));
    assert!(issues.contains(&MethodIssue::PutEnabled));
}

#[test]
fn analyze_all_webdav_methods() {
    let issues = analyze_methods("GET, PROPFIND, MKCOL, COPY, MOVE");
    assert!(issues.contains(&MethodIssue::WebdavPropfind));
    assert!(issues.contains(&MethodIssue::WebdavMkcol));
    assert!(issues.contains(&MethodIssue::WebdavCopy));
    assert!(issues.contains(&MethodIssue::WebdavMove));
}

#[test]
fn analyze_wildcard_with_methods() {
    let issues = analyze_methods("*, GET, POST");
    assert!(issues.contains(&MethodIssue::WildcardAllow));
}

#[test]
fn analyze_mixed_case_webdav() {
    let issues = analyze_methods("propfind, Mkcol, COPY");
    assert!(issues.contains(&MethodIssue::WebdavPropfind));
    assert!(issues.contains(&MethodIssue::WebdavMkcol));
    assert!(issues.contains(&MethodIssue::WebdavCopy));
}

// --- Display ---

#[test]
fn display_trace_enabled() {
    assert_eq!(MethodIssue::TraceEnabled.to_string(), "trace_enabled");
}

#[test]
fn display_connect_enabled() {
    assert_eq!(MethodIssue::ConnectEnabled.to_string(), "connect_enabled");
}

#[test]
fn display_put_enabled() {
    assert_eq!(MethodIssue::PutEnabled.to_string(), "put_enabled");
}

#[test]
fn display_delete_enabled() {
    assert_eq!(MethodIssue::DeleteEnabled.to_string(), "delete_enabled");
}

#[test]
fn display_patch_enabled() {
    assert_eq!(MethodIssue::PatchEnabled.to_string(), "patch_enabled");
}

#[test]
fn display_webdav_propfind() {
    assert_eq!(MethodIssue::WebdavPropfind.to_string(), "webdav_propfind");
}

#[test]
fn display_webdav_mkcol() {
    assert_eq!(MethodIssue::WebdavMkcol.to_string(), "webdav_mkcol");
}

#[test]
fn display_webdav_copy() {
    assert_eq!(MethodIssue::WebdavCopy.to_string(), "webdav_copy");
}

#[test]
fn display_webdav_move() {
    assert_eq!(MethodIssue::WebdavMove.to_string(), "webdav_move");
}

#[test]
fn display_excessive_methods() {
    assert_eq!(
        MethodIssue::ExcessiveMethods { count: 12 }.to_string(),
        "excessive_methods_12"
    );
}

#[test]
fn display_options_exposed() {
    assert_eq!(MethodIssue::OptionsExposed.to_string(), "options_exposed");
}

#[test]
fn display_wildcard_allow() {
    assert_eq!(MethodIssue::WildcardAllow.to_string(), "wildcard_allow");
}

// --- method_severity ---

#[test]
fn severity_trace() {
    assert_eq!(method_severity(&MethodIssue::TraceEnabled), 5.0);
}

#[test]
fn severity_connect() {
    assert_eq!(method_severity(&MethodIssue::ConnectEnabled), 4.0);
}

#[test]
fn severity_put() {
    assert_eq!(method_severity(&MethodIssue::PutEnabled), 4.5);
}

#[test]
fn severity_delete() {
    assert_eq!(method_severity(&MethodIssue::DeleteEnabled), 4.5);
}

#[test]
fn severity_patch() {
    assert_eq!(method_severity(&MethodIssue::PatchEnabled), 3.0);
}

#[test]
fn severity_webdav_propfind() {
    assert_eq!(method_severity(&MethodIssue::WebdavPropfind), 4.0);
}

#[test]
fn severity_webdav_mkcol() {
    assert_eq!(method_severity(&MethodIssue::WebdavMkcol), 4.0);
}

#[test]
fn severity_webdav_copy() {
    assert_eq!(method_severity(&MethodIssue::WebdavCopy), 4.0);
}

#[test]
fn severity_webdav_move() {
    assert_eq!(method_severity(&MethodIssue::WebdavMove), 4.0);
}

#[test]
fn severity_excessive_methods() {
    assert_eq!(
        method_severity(&MethodIssue::ExcessiveMethods { count: 9 }),
        3.0
    );
}

#[test]
fn severity_options_exposed() {
    assert_eq!(method_severity(&MethodIssue::OptionsExposed), 1.5);
}

#[test]
fn severity_wildcard_allow() {
    assert_eq!(method_severity(&MethodIssue::WildcardAllow), 5.5);
}

// --- method_findings_to_operations ---

#[test]
fn ops_empty_issues() {
    let mut seq = 0;
    let ops = method_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn ops_single_issue() {
    let mut seq = 0;
    let ops = method_findings_to_operations(&[MethodIssue::TraceEnabled], &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn ops_multiple_issues_one_per_issue() {
    let issues = vec![
        MethodIssue::TraceEnabled,
        MethodIssue::PutEnabled,
        MethodIssue::OptionsExposed,
    ];
    let mut seq = 0;
    let ops = method_findings_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn ops_sequence_increments_from_nonzero() {
    let mut seq = 10;
    let ops = method_findings_to_operations(
        &[MethodIssue::DeleteEnabled, MethodIssue::PatchEnabled],
        &mut seq,
    );
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 12);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
}

#[test]
fn ops_severity_matches_issue() {
    let mut seq = 0;
    let ops = method_findings_to_operations(&[MethodIssue::WildcardAllow], &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 5.5);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn ops_confidence_is_half() {
    let mut seq = 0;
    let ops = method_findings_to_operations(&[MethodIssue::ConnectEnabled], &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { confidence, .. } => {
            assert!((confidence.value() - 0.5).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

// --- parse_allow_header backward compat ---

#[test]
fn parse_allow_header_basic() {
    let result = parse_allow_header("GET, POST, OPTIONS");
    assert_eq!(result.allowed_methods, vec!["GET", "POST", "OPTIONS"]);
    assert!(result.dangerous_methods.is_empty());
}

#[test]
fn parse_allow_header_with_dangerous() {
    let result = parse_allow_header("GET, PUT, DELETE, OPTIONS");
    assert_eq!(result.dangerous_methods, vec!["PUT", "DELETE"]);
}

// --- scan_methods ---

#[test]
fn scan_methods_skips_localhost() {
    let result = scan_methods("http://localhost:8080");
    assert!(result.is_none());
}

#[test]
fn scan_methods_skips_invalid() {
    let result = scan_methods("not-a-url");
    assert!(result.is_none());
}

// --- integration: analyze -> ops round-trip ---

#[test]
fn round_trip_analyze_to_ops() {
    let issues = analyze_methods("GET, PUT, DELETE, TRACE, PROPFIND, MKCOL, COPY, MOVE, OPTIONS");
    let mut seq = 0;
    let ops = method_findings_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), issues.len());
    assert_eq!(seq as usize, issues.len());
}

#[test]
fn round_trip_safe_header_no_ops() {
    let issues = analyze_methods("GET, POST, HEAD");
    let mut seq = 0;
    let ops = method_findings_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}
