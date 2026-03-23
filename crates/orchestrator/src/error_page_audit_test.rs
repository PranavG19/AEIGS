use crate::error_page_audit::{analyze_error_body, error_page_to_operations, ErrorPageLeak};

#[test]
fn detects_python_traceback() {
    let body = "Error\nTraceback (most recent call last):\n  File \"app.py\"";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "python_traceback"));
}

#[test]
fn detects_java_stacktrace() {
    let body = "Error at java.lang.Thread.run(Thread.java:750)";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "java_stacktrace"));
}

#[test]
fn detects_node_stacktrace() {
    let body = "TypeError: Cannot read property\n    at Object.<anonymous>";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "node_stacktrace"));
}

#[test]
fn detects_go_stacktrace() {
    let body = "goroutine 1 [running]:\nmain.main()";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "go_stacktrace"));
}

#[test]
fn detects_sql_error() {
    let body = "SQLSTATE[42000]: Syntax error or access violation";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "sql_error"));
}

#[test]
fn detects_django_debug() {
    let body = "<h1>Django Debug page</h1><p>Settings</p>";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "django_debug"));
}

#[test]
fn detects_internal_path() {
    let body = "Error loading config from /var/www/app/config.json";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "internal_path"));
}

#[test]
fn detects_windows_path() {
    let body = r"Error: file not found at C:\inetpub\wwwroot\web.config";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "internal_path"));
}

#[test]
fn detects_whoops_debug() {
    let body = "<div class='Whoops!'>Stack trace</div>";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "whoops_debug"));
}

#[test]
fn no_leaks_in_clean_page() {
    let body = "<html><body><h1>404 - Page Not Found</h1></body></html>";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.is_empty());
}

#[test]
fn deduplicates_same_category() {
    let body = "SQLSTATE[42000] error\nmysql_connect() failed";
    let leaks = analyze_error_body(body, "/test");
    let sql_count = leaks.iter().filter(|l| l.pattern_name == "sql_error").count();
    assert_eq!(sql_count, 1);
}

#[test]
fn multiple_categories() {
    let body = "Traceback (most recent call last):\n  /var/www/app.py";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.len() >= 2);
}

#[test]
fn operations_empty_when_no_leaks() {
    let mut seq = 0;
    let ops = error_page_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_leaks() {
    let leaks = vec![ErrorPageLeak {
        path: "/test".to_string(),
        pattern_name: "python_traceback".to_string(),
        severity: 7.0,
    }];
    let mut seq = 0;
    let ops = error_page_to_operations(&leaks, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn preserves_path_in_leak() {
    let body = "Traceback (most recent call last):";
    let leaks = analyze_error_body(body, "/custom-path");
    assert!(leaks.iter().all(|l| l.path == "/custom-path"));
}
