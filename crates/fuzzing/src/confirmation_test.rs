use std::time::Duration;

use aegis_protocol::finding::VulnerabilityClass;

use crate::confirmation::{
    EvidenceType, build_confirmation_registry, confirm_sql_boolean_diff, confirm_sql_error_message,
    confirm_sql_time_delay, confirm_sql_union_column_count,
};
use crate::executor::FuzzResponse;
use crate::oracle::BaselineProfile;

fn make_response(body: &str, status: u16, response_time: Duration) -> FuzzResponse {
    FuzzResponse {
        request_id: 1,
        status_code: status,
        body: body.to_string(),
        headers: Vec::new(),
        response_time,
        body_size_bytes: body.len(),
    }
}

fn make_baseline() -> BaselineProfile {
    BaselineProfile {
        endpoint: "/test".to_string(),
        method: "GET".to_string(),
        expected_status_codes: vec![200],
        mean_response_time_ms: 50.0,
        p99_response_time_ms: 100.0,
        mean_body_size: 500.0,
        body_size_std_dev: 50.0,
    }
}

#[test]
fn registry_contains_sql_injection_functions() {
    let registry = build_confirmation_registry();
    assert!(registry.contains_key(&VulnerabilityClass::SqlInjection));
    assert_eq!(registry[&VulnerabilityClass::SqlInjection].len(), 4);
}

#[test]
fn sql_error_message_detects_mysql_syntax_error() {
    let treatment = make_response(
        "You have an error in your SQL syntax near '1'",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_sql_error_message(&treatment, &control, "' OR 1=1--", &baseline);
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert_eq!(ev.evidence_type, EvidenceType::SqlErrorMessage);
    assert!((ev.confidence - 0.95).abs() < f64::EPSILON);
}

#[test]
fn sql_error_message_detects_ora_error() {
    let treatment = make_response(
        "ORA-00933: SQL command not properly ended",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_sql_error_message(&treatment, &control, "'", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn sql_error_message_detects_postgresql_error() {
    let treatment = make_response(
        "PostgreSQL query ERROR: syntax error at or near",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_sql_error_message(&treatment, &control, "'", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn sql_error_message_detects_sqlstate() {
    let treatment = make_response(
        "SQLSTATE[42000]: Syntax error",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_sql_error_message(&treatment, &control, "'", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn sql_error_message_detects_sqlite_error() {
    let treatment = make_response(
        "sqlite3.OperationalError: near syntax",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_sql_error_message(&treatment, &control, "'", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn sql_error_message_detects_ole_db() {
    let treatment = make_response(
        "Microsoft OLE DB Provider for SQL Server",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_sql_error_message(&treatment, &control, "'", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn sql_error_message_detects_unclosed_quotation() {
    let treatment = make_response(
        "Unclosed quotation mark after the character string",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_sql_error_message(&treatment, &control, "'", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn sql_error_message_detects_quoted_string_not_terminated() {
    let treatment = make_response(
        "quoted string not properly terminated",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_sql_error_message(&treatment, &control, "'", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn sql_error_message_ignores_error_present_in_control() {
    let treatment = make_response(
        "You have an error in your SQL syntax",
        500,
        Duration::from_millis(50),
    );
    let control = make_response(
        "You have an error in your SQL syntax",
        500,
        Duration::from_millis(50),
    );
    let baseline = make_baseline();

    let evidence = confirm_sql_error_message(&treatment, &control, "'", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn sql_error_message_returns_none_when_no_pattern_matches() {
    let treatment = make_response("normal page content", 200, Duration::from_millis(50));
    let control = make_response("normal page content", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_sql_error_message(&treatment, &control, "'", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn sql_time_delay_detects_sleep_injection() {
    let treatment = make_response("OK", 200, Duration::from_secs(5));
    let control = make_response("OK", 200, Duration::from_millis(100));
    let baseline = make_baseline();

    let evidence = confirm_sql_time_delay(&treatment, &control, "' OR SLEEP(5)--", &baseline);
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert_eq!(ev.evidence_type, EvidenceType::TimeBasedDelay);
    assert!((ev.confidence - 0.90).abs() < f64::EPSILON);
}

#[test]
fn sql_time_delay_detects_pg_sleep() {
    let treatment = make_response("OK", 200, Duration::from_secs(3));
    let control = make_response("OK", 200, Duration::from_millis(100));
    let baseline = make_baseline();

    let evidence =
        confirm_sql_time_delay(&treatment, &control, "'; SELECT pg_sleep(3)--", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn sql_time_delay_detects_waitfor() {
    let treatment = make_response("OK", 200, Duration::from_secs(5));
    let control = make_response("OK", 200, Duration::from_millis(100));
    let baseline = make_baseline();

    let evidence = confirm_sql_time_delay(&treatment, &control, "'; WAITFOR(5)--", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn sql_time_delay_returns_none_when_no_time_keyword() {
    let treatment = make_response("OK", 200, Duration::from_secs(5));
    let control = make_response("OK", 200, Duration::from_millis(100));
    let baseline = make_baseline();

    let evidence = confirm_sql_time_delay(&treatment, &control, "' OR 1=1--", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn sql_time_delay_returns_none_when_delta_insufficient() {
    let treatment = make_response("OK", 200, Duration::from_millis(500));
    let control = make_response("OK", 200, Duration::from_millis(200));
    let baseline = make_baseline();

    let evidence = confirm_sql_time_delay(&treatment, &control, "' OR SLEEP(5)--", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn sql_boolean_diff_detects_body_divergence() {
    let treatment = make_response(
        "Welcome back, admin! Here is your secret data panel.",
        200,
        Duration::from_millis(50),
    );
    let control = make_response(
        "Invalid login credentials. Please try again.",
        200,
        Duration::from_millis(50),
    );
    let baseline = make_baseline();

    let evidence = confirm_sql_boolean_diff(&treatment, &control, "' OR 1=1--", &baseline);
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert_eq!(ev.evidence_type, EvidenceType::BehaviorDifference);
    assert!((ev.confidence - 0.85).abs() < f64::EPSILON);
}

#[test]
fn sql_boolean_diff_returns_none_when_status_codes_differ() {
    let treatment = make_response("data", 200, Duration::from_millis(50));
    let control = make_response("error", 500, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_sql_boolean_diff(&treatment, &control, "' OR 1=1--", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn sql_boolean_diff_returns_none_when_bodies_similar() {
    let treatment = make_response("same content here", 200, Duration::from_millis(50));
    let control = make_response("same content here", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_sql_boolean_diff(&treatment, &control, "' OR 1=1--", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn sql_union_column_count_detects_successful_union() {
    let treatment = make_response(
        "admin,password123,admin@test.com",
        200,
        Duration::from_millis(50),
    );
    let control = make_response("normal page", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_sql_union_column_count(
        &treatment,
        &control,
        "' UNION SELECT null,null,null--",
        &baseline,
    );
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert_eq!(ev.evidence_type, EvidenceType::BehaviorDifference);
    assert!((ev.confidence - 0.80).abs() < f64::EPSILON);
}

#[test]
fn sql_union_column_count_returns_none_when_sql_error_in_treatment() {
    let treatment = make_response(
        "You have an error in your SQL syntax",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("normal page", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_sql_union_column_count(
        &treatment,
        &control,
        "' UNION SELECT null,null--",
        &baseline,
    );
    assert!(evidence.is_none());
}

#[test]
fn sql_union_column_count_returns_none_when_no_union_in_payload() {
    let treatment = make_response("data", 200, Duration::from_millis(50));
    let control = make_response("normal page", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_sql_union_column_count(&treatment, &control, "' OR 1=1--", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn sql_union_column_count_handles_union_all_select() {
    let treatment = make_response("data,data,data", 200, Duration::from_millis(50));
    let control = make_response("normal page", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_sql_union_column_count(
        &treatment,
        &control,
        "' UNION ALL SELECT null,null,null--",
        &baseline,
    );
    assert!(evidence.is_some());
}
