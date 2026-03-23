use crate::document_domain_audit::*;

// --- Detection: Assignment (literal string RHS) ---

#[test]
fn detects_assignment_with_double_quotes() {
    let html = r#"<script>document.domain = "example.com";</script>"#;
    let issues = find_document_domain(html);
    assert!(issues.iter().any(|i| matches!(i, DocumentDomainIssue::Assignment { .. })));
}

#[test]
fn detects_assignment_with_single_quotes() {
    let html = "<script>document.domain = 'example.com';</script>";
    let issues = find_document_domain(html);
    assert!(issues.iter().any(|i| matches!(i, DocumentDomainIssue::Assignment { .. })));
}

#[test]
fn assignment_snippet_contains_domain() {
    let html = r#"<script>document.domain = "example.com";</script>"#;
    let issues = find_document_domain(html);
    let assign = issues.iter().find(|i| matches!(i, DocumentDomainIssue::Assignment { .. }));
    assert!(assign.is_some());
    if let DocumentDomainIssue::Assignment { snippet } = assign.unwrap() {
        assert!(snippet.contains("document.domain"));
    }
}

// --- Detection: DynamicAssignment (variable RHS) ---

#[test]
fn detects_dynamic_assignment_variable() {
    let html = r#"<script>document.domain = myVar;</script>"#;
    let issues = find_document_domain(html);
    assert!(issues.iter().any(|i| matches!(i, DocumentDomainIssue::DynamicAssignment { .. })));
}

#[test]
fn detects_dynamic_assignment_location_hostname() {
    let html = r#"<script>document.domain = location.hostname;</script>"#;
    let issues = find_document_domain(html);
    assert!(issues.iter().any(|i| matches!(i, DocumentDomainIssue::DynamicAssignment { .. })));
}

#[test]
fn dynamic_assignment_snippet_present() {
    let html = r#"<script>document.domain = location.hostname;</script>"#;
    let issues = find_document_domain(html);
    let dyn_issue = issues.iter().find(|i| matches!(i, DocumentDomainIssue::DynamicAssignment { .. }));
    assert!(dyn_issue.is_some());
    if let DocumentDomainIssue::DynamicAssignment { snippet } = dyn_issue.unwrap() {
        assert!(snippet.contains("document.domain"));
    }
}

// --- Detection: DeprecatedApiUsage ---

#[test]
fn always_emits_deprecated_api_usage() {
    let html = r#"<script>document.domain = "x";</script>"#;
    let issues = find_document_domain(html);
    assert!(issues.iter().any(|i| matches!(i, DocumentDomainIssue::DeprecatedApiUsage)));
}

#[test]
fn deprecated_api_on_read_only() {
    let html = r#"<script>if (document.domain == "x") {}</script>"#;
    let issues = find_document_domain(html);
    assert!(issues.iter().any(|i| matches!(i, DocumentDomainIssue::DeprecatedApiUsage)));
}

// --- Detection: DocumentDomainInEval ---

#[test]
fn detects_eval_in_same_block() {
    let html = r#"<script>document.domain = "x"; eval("alert(1)");</script>"#;
    let issues = find_document_domain(html);
    assert!(issues.iter().any(|i| matches!(i, DocumentDomainIssue::DocumentDomainInEval { .. })));
}

#[test]
fn no_eval_when_eval_absent() {
    let html = r#"<script>document.domain = "x";</script>"#;
    let issues = find_document_domain(html);
    assert!(!issues.iter().any(|i| matches!(i, DocumentDomainIssue::DocumentDomainInEval { .. })));
}

#[test]
fn eval_snippet_contains_eval() {
    let html = r#"<script>document.domain = "x"; eval("code");</script>"#;
    let issues = find_document_domain(html);
    let eval_issue = issues.iter().find(|i| matches!(i, DocumentDomainIssue::DocumentDomainInEval { .. }));
    assert!(eval_issue.is_some());
    if let DocumentDomainIssue::DocumentDomainInEval { snippet } = eval_issue.unwrap() {
        assert!(snippet.contains("eval("));
    }
}

// --- Detection: DocumentDomainRead ---

#[test]
fn detects_read_with_equality_check() {
    let html = r#"<script>if (document.domain == "x") {}</script>"#;
    let issues = find_document_domain(html);
    assert!(issues.iter().any(|i| matches!(i, DocumentDomainIssue::DocumentDomainRead)));
}

#[test]
fn detects_read_with_inequality_check() {
    let html = r#"<script>if (document.domain != "x") {}</script>"#;
    let issues = find_document_domain(html);
    assert!(issues.iter().any(|i| matches!(i, DocumentDomainIssue::DocumentDomainRead)));
}

// --- Detection: ConditionalAssignment ---

#[test]
fn detects_conditional_with_if() {
    let html = r#"<script>if (cond) document.domain = "x";</script>"#;
    let issues = find_document_domain(html);
    assert!(issues.iter().any(|i| matches!(i, DocumentDomainIssue::ConditionalAssignment { .. })));
}

#[test]
fn detects_conditional_with_ternary() {
    let html = r#"<script>cond ? document.domain = "a" : null;</script>"#;
    let issues = find_document_domain(html);
    assert!(issues.iter().any(|i| matches!(i, DocumentDomainIssue::ConditionalAssignment { .. })));
}

// --- Display ---

#[test]
fn display_assignment() {
    let issue = DocumentDomainIssue::Assignment { snippet: "doc".into() };
    assert_eq!(format!("{issue}"), "assignment: doc");
}

#[test]
fn display_dynamic_assignment() {
    let issue = DocumentDomainIssue::DynamicAssignment { snippet: "dyn".into() };
    assert_eq!(format!("{issue}"), "dynamic_assignment: dyn");
}

#[test]
fn display_parent_domain_relaxation() {
    let issue = DocumentDomainIssue::ParentDomainRelaxation { snippet: "parent".into() };
    assert_eq!(format!("{issue}"), "parent_domain_relaxation: parent");
}

#[test]
fn display_deprecated_api_usage() {
    let issue = DocumentDomainIssue::DeprecatedApiUsage;
    assert_eq!(format!("{issue}"), "deprecated_api_usage");
}

#[test]
fn display_document_domain_in_eval() {
    let issue = DocumentDomainIssue::DocumentDomainInEval { snippet: "ev".into() };
    assert_eq!(format!("{issue}"), "document_domain_in_eval: ev");
}

#[test]
fn display_document_domain_read() {
    let issue = DocumentDomainIssue::DocumentDomainRead;
    assert_eq!(format!("{issue}"), "document_domain_read");
}

#[test]
fn display_conditional_assignment() {
    let issue = DocumentDomainIssue::ConditionalAssignment { snippet: "cond".into() };
    assert_eq!(format!("{issue}"), "conditional_assignment: cond");
}

// --- Severity ---

#[test]
fn severity_assignment() {
    let v = document_domain_severity(&DocumentDomainIssue::Assignment { snippet: String::new() });
    assert!((v - 5.0).abs() < f64::EPSILON);
}

#[test]
fn severity_dynamic_assignment() {
    let v = document_domain_severity(&DocumentDomainIssue::DynamicAssignment { snippet: String::new() });
    assert!((v - 6.5).abs() < f64::EPSILON);
}

#[test]
fn severity_parent_domain_relaxation() {
    let v = document_domain_severity(&DocumentDomainIssue::ParentDomainRelaxation { snippet: String::new() });
    assert!((v - 7.0).abs() < f64::EPSILON);
}

#[test]
fn severity_deprecated_api_usage() {
    let v = document_domain_severity(&DocumentDomainIssue::DeprecatedApiUsage);
    assert!((v - 3.0).abs() < f64::EPSILON);
}

#[test]
fn severity_document_domain_in_eval() {
    let v = document_domain_severity(&DocumentDomainIssue::DocumentDomainInEval { snippet: String::new() });
    assert!((v - 7.5).abs() < f64::EPSILON);
}

#[test]
fn severity_document_domain_read() {
    let v = document_domain_severity(&DocumentDomainIssue::DocumentDomainRead);
    assert!((v - 2.0).abs() < f64::EPSILON);
}

#[test]
fn severity_conditional_assignment() {
    let v = document_domain_severity(&DocumentDomainIssue::ConditionalAssignment { snippet: String::new() });
    assert!((v - 5.5).abs() < f64::EPSILON);
}

// --- to_operations ---

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = document_domain_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_one_per_issue() {
    let issues = vec![
        DocumentDomainIssue::DeprecatedApiUsage,
        DocumentDomainIssue::Assignment { snippet: "x".into() },
    ];
    let mut seq = 0;
    let ops = document_domain_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn operations_sequence_increments() {
    let issues = vec![
        DocumentDomainIssue::DeprecatedApiUsage,
        DocumentDomainIssue::DocumentDomainRead,
        DocumentDomainIssue::Assignment { snippet: "s".into() },
    ];
    let mut seq = 10;
    let ops = document_domain_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
}

#[test]
fn operations_from_full_detection() {
    let html = r#"<script>document.domain = "x";</script>"#;
    let issues = find_document_domain(html);
    let mut seq = 0;
    let ops = document_domain_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), issues.len());
    assert_eq!(seq as usize, issues.len());
}

// --- Edge cases ---

#[test]
fn no_script_tags() {
    let html = "<html><body>Hello</body></html>";
    let issues = find_document_domain(html);
    assert!(issues.is_empty());
}

#[test]
fn empty_html() {
    let issues = find_document_domain("");
    assert!(issues.is_empty());
}

#[test]
fn ignores_external_scripts() {
    let html = r#"<script src="app.js">document.domain = "x";</script>"#;
    let issues = find_document_domain(html);
    assert!(issues.is_empty());
}

#[test]
fn case_insensitive_tag() {
    let html = r#"<SCRIPT>document.domain = "foo";</SCRIPT>"#;
    let issues = find_document_domain(html);
    assert!(issues.iter().any(|i| matches!(i, DocumentDomainIssue::Assignment { .. })));
}

#[test]
fn multiple_script_blocks_separate_issues() {
    let html = concat!(
        r#"<script>document.domain = "a.com";</script>"#,
        r#"<script>document.domain = "b.com";</script>"#,
    );
    let issues = find_document_domain(html);
    let assignments: Vec<_> = issues.iter().filter(|i| matches!(i, DocumentDomainIssue::Assignment { .. })).collect();
    assert_eq!(assignments.len(), 2);
}

#[test]
fn script_without_document_domain() {
    let html = r#"<script>var x = 1; console.log(x);</script>"#;
    let issues = find_document_domain(html);
    assert!(issues.is_empty());
}

#[test]
fn unclosed_script_tag() {
    let html = r#"<script>document.domain = "x";"#;
    let issues = find_document_domain(html);
    assert!(!issues.is_empty());
}

#[test]
fn snippet_truncated_at_120_chars() {
    let long_line = format!(
        r#"<script>document.domain = "{}".slice(0,99);</script>"#,
        "a".repeat(200)
    );
    let issues = find_document_domain(&long_line);
    let assign = issues.iter().find(|i| matches!(i, DocumentDomainIssue::Assignment { .. }));
    assert!(assign.is_some());
    if let DocumentDomainIssue::Assignment { snippet } = assign.unwrap() {
        assert!(snippet.len() <= 120);
        assert!(snippet.ends_with("..."));
    }
}

#[test]
fn eval_in_separate_block_no_detection() {
    let html = r#"<script>document.domain = "x";</script><script>eval("y");</script>"#;
    let issues = find_document_domain(html);
    assert!(!issues.iter().any(|i| matches!(i, DocumentDomainIssue::DocumentDomainInEval { .. })));
}

#[test]
fn multiple_assignments_same_block() {
    let html = "<script>\ndocument.domain = \"a\";\ndocument.domain = \"b\";\n</script>";
    let issues = find_document_domain(html);
    let assignments: Vec<_> = issues.iter().filter(|i| matches!(i, DocumentDomainIssue::Assignment { .. })).collect();
    assert_eq!(assignments.len(), 2);
}

#[test]
fn dynamic_vs_static_distinguished() {
    let html = concat!(
        r#"<script>document.domain = "literal";</script>"#,
        r#"<script>document.domain = someVar;</script>"#,
    );
    let issues = find_document_domain(html);
    assert!(issues.iter().any(|i| matches!(i, DocumentDomainIssue::Assignment { .. })));
    assert!(issues.iter().any(|i| matches!(i, DocumentDomainIssue::DynamicAssignment { .. })));
}

#[test]
fn conditional_also_counts_as_assignment() {
    let html = r#"<script>if (cond) document.domain = "x";</script>"#;
    let issues = find_document_domain(html);
    assert!(issues.iter().any(|i| matches!(i, DocumentDomainIssue::ConditionalAssignment { .. })));
    assert!(issues.iter().any(|i| matches!(i, DocumentDomainIssue::Assignment { .. })));
}
