use crate::method_scanner::*;

#[test]
fn parse_allow_header_basic() {
    let result = parse_allow_header("GET, POST, OPTIONS");
    assert_eq!(result.allowed_methods, vec!["GET", "POST", "OPTIONS"]);
    assert!(result.dangerous_methods.is_empty());
}

#[test]
fn parse_allow_header_with_dangerous() {
    let result = parse_allow_header("GET, PUT, DELETE, OPTIONS");
    assert_eq!(
        result.allowed_methods,
        vec!["GET", "PUT", "DELETE", "OPTIONS"]
    );
    assert_eq!(result.dangerous_methods, vec!["PUT", "DELETE"]);
}

#[test]
fn parse_allow_header_trace() {
    let result = parse_allow_header("GET, TRACE, OPTIONS");
    assert_eq!(result.dangerous_methods, vec!["TRACE"]);
}

#[test]
fn parse_allow_header_case_insensitive() {
    let result = parse_allow_header("get, put, options");
    assert_eq!(result.allowed_methods, vec!["GET", "PUT", "OPTIONS"]);
    assert_eq!(result.dangerous_methods, vec!["PUT"]);
}

#[test]
fn parse_allow_header_empty() {
    let result = parse_allow_header("");
    assert!(result.allowed_methods.is_empty());
    assert!(result.dangerous_methods.is_empty());
}

#[test]
fn parse_allow_header_extra_whitespace() {
    let result = parse_allow_header("  GET ,  POST ,  PUT  ");
    assert_eq!(result.allowed_methods, vec!["GET", "POST", "PUT"]);
    assert_eq!(result.dangerous_methods, vec!["PUT"]);
}

#[test]
fn method_findings_no_dangerous() {
    let result = MethodResult {
        allowed_methods: vec!["GET".to_string(), "POST".to_string()],
        dangerous_methods: vec![],
    };
    let mut seq = 0;
    let ops = method_findings_to_operations(&result, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn method_findings_with_trace() {
    let result = MethodResult {
        allowed_methods: vec!["GET".to_string(), "TRACE".to_string()],
        dangerous_methods: vec!["TRACE".to_string()],
    };
    let mut seq = 0;
    let ops = method_findings_to_operations(&result, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 5.0);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn method_findings_severity_takes_max() {
    let result = MethodResult {
        allowed_methods: vec!["PUT".to_string(), "TRACE".to_string()],
        dangerous_methods: vec!["PUT".to_string(), "TRACE".to_string()],
    };
    let mut seq = 0;
    let ops = method_findings_to_operations(&result, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 5.0);
        }
        _ => panic!("expected AddFinding"),
    }
}

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
