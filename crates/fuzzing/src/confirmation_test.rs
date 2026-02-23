use std::time::Duration;

use aegis_protocol::finding::VulnerabilityClass;

use crate::confirmation::{
    EvidenceType, build_confirmation_registry, confirm_cmd_output_patterns, confirm_cmd_time_delay,
    confirm_deserialization_error_pattern, confirm_nosql_error_pattern, confirm_nosql_time_delay,
    confirm_path_traversal_file_contents, confirm_redirect_to_payload_domain,
    confirm_sql_boolean_diff, confirm_sql_error_message, confirm_sql_time_delay,
    confirm_sql_union_column_count, confirm_ssrf_internal_content, confirm_ssti_evaluation,
    confirm_xss_reflection_in_attribute, confirm_xss_reflection_in_html_context,
    confirm_xss_reflection_in_js_context,
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

fn make_response_with_headers(
    body: &str,
    status: u16,
    headers: Vec<(String, String)>,
) -> FuzzResponse {
    FuzzResponse {
        request_id: 1,
        status_code: status,
        body: body.to_string(),
        headers,
        response_time: Duration::from_millis(50),
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
        status_code_counts: std::collections::HashMap::from([(200, 10)]),
        total_baseline_responses: 10,
        response_times_ms: vec![40.0, 45.0, 48.0, 50.0, 50.0, 52.0, 55.0, 58.0, 60.0, 100.0],
        body_sizes: vec![450, 470, 480, 490, 500, 500, 510, 520, 530, 550],
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

#[test]
fn registry_contains_xss_functions() {
    let registry = build_confirmation_registry();
    assert!(registry.contains_key(&VulnerabilityClass::CrossSiteScripting));
    assert_eq!(registry[&VulnerabilityClass::CrossSiteScripting].len(), 3);
}

#[test]
fn registry_contains_ssti_functions() {
    let registry = build_confirmation_registry();
    assert!(registry.contains_key(&VulnerabilityClass::ServerSideTemplateInjection));
    assert_eq!(
        registry[&VulnerabilityClass::ServerSideTemplateInjection].len(),
        1
    );
}

#[test]
fn registry_contains_cmd_injection_functions() {
    let registry = build_confirmation_registry();
    assert!(registry.contains_key(&VulnerabilityClass::CommandInjection));
    assert_eq!(registry[&VulnerabilityClass::CommandInjection].len(), 2);
}

#[test]
fn xss_html_context_detects_reflected_payload() {
    let treatment = make_response(
        "<div><script>alert(1)</script></div>",
        200,
        Duration::from_millis(50),
    );
    let control = make_response("<div>safe content</div>", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_xss_reflection_in_html_context(
        &treatment,
        &control,
        "<script>alert(1)</script>",
        &baseline,
    );
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert_eq!(ev.evidence_type, EvidenceType::ReflectedPayload);
    assert!((ev.confidence - 0.90).abs() < f64::EPSILON);
}

#[test]
fn xss_html_context_rejects_short_payload() {
    let treatment = make_response("<b>ab</b>", 200, Duration::from_millis(50));
    let control = make_response("safe", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_xss_reflection_in_html_context(&treatment, &control, "ab", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn xss_html_context_rejects_payload_in_control() {
    let payload = "<img src=x onerror=alert(1)>";
    let treatment = make_response(
        &format!("<div>{payload}</div>"),
        200,
        Duration::from_millis(50),
    );
    let control = make_response(
        &format!("<div>{payload}</div>"),
        200,
        Duration::from_millis(50),
    );
    let baseline = make_baseline();

    let evidence = confirm_xss_reflection_in_html_context(&treatment, &control, payload, &baseline);
    assert!(evidence.is_none());
}

#[test]
fn xss_html_context_rejects_html_encoded_only() {
    let payload = "<script>alert(1)</script>";
    let encoded = "&lt;script&gt;alert(1)&lt;/script&gt;";
    let treatment = make_response(
        &format!("<div>{encoded}</div>"),
        200,
        Duration::from_millis(50),
    );
    let control = make_response("<div>safe</div>", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_xss_reflection_in_html_context(&treatment, &control, payload, &baseline);
    assert!(evidence.is_none());
}

#[test]
fn xss_html_context_rejects_payload_not_in_treatment() {
    let treatment = make_response("<div>no payload here</div>", 200, Duration::from_millis(50));
    let control = make_response("<div>safe</div>", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_xss_reflection_in_html_context(
        &treatment,
        &control,
        "<script>alert(1)</script>",
        &baseline,
    );
    assert!(evidence.is_none());
}

#[test]
fn xss_attribute_detects_payload_in_href() {
    let treatment = make_response(
        r#"<a href="javascript:alert(1)">click</a>"#,
        200,
        Duration::from_millis(50),
    );
    let control = make_response("<a href='/safe'>click</a>", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_xss_reflection_in_attribute(&treatment, &control, "javascript:alert(1)", &baseline);
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert_eq!(ev.evidence_type, EvidenceType::ReflectedPayload);
    assert!((ev.confidence - 0.88).abs() < f64::EPSILON);
}

#[test]
fn xss_attribute_detects_payload_in_onclick() {
    let treatment = make_response(
        r#"<button onclick="alert(document.cookie)">go</button>"#,
        200,
        Duration::from_millis(50),
    );
    let control = make_response("<button>go</button>", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_xss_reflection_in_attribute(
        &treatment,
        &control,
        "alert(document.cookie)",
        &baseline,
    );
    assert!(evidence.is_some());
}

#[test]
fn xss_attribute_detects_payload_in_onerror() {
    let treatment = make_response(
        r#"<img src="x" onerror="alert(1)">"#,
        200,
        Duration::from_millis(50),
    );
    let control = make_response(r#"<img src="safe.png">"#, 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_xss_reflection_in_attribute(&treatment, &control, "alert(1)", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn xss_attribute_returns_none_when_no_attribute_context() {
    let treatment = make_response(
        "<div>just text with alert(1)</div>",
        200,
        Duration::from_millis(50),
    );
    let control = make_response("<div>safe</div>", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_xss_reflection_in_attribute(&treatment, &control, "alert(1)", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn xss_js_context_detects_payload_in_script_block() {
    let treatment = make_response(
        "<html><script>var x = 'INJECTED';</script></html>",
        200,
        Duration::from_millis(50),
    );
    let control = make_response(
        "<html><script>var x = 'safe';</script></html>",
        200,
        Duration::from_millis(50),
    );
    let baseline = make_baseline();

    let evidence =
        confirm_xss_reflection_in_js_context(&treatment, &control, "INJECTED", &baseline);
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert_eq!(ev.evidence_type, EvidenceType::ReflectedPayload);
    assert!((ev.confidence - 0.92).abs() < f64::EPSILON);
}

#[test]
fn xss_js_context_returns_none_when_payload_outside_script() {
    let treatment = make_response(
        "<html><div>INJECTED</div><script>safe();</script></html>",
        200,
        Duration::from_millis(50),
    );
    let control = make_response(
        "<html><div>safe</div><script>safe();</script></html>",
        200,
        Duration::from_millis(50),
    );
    let baseline = make_baseline();

    let evidence =
        confirm_xss_reflection_in_js_context(&treatment, &control, "INJECTED", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn xss_js_context_returns_none_when_no_script_blocks() {
    let treatment = make_response(
        "<html><div>INJECTED content</div></html>",
        200,
        Duration::from_millis(50),
    );
    let control = make_response(
        "<html><div>safe</div></html>",
        200,
        Duration::from_millis(50),
    );
    let baseline = make_baseline();

    let evidence =
        confirm_xss_reflection_in_js_context(&treatment, &control, "INJECTED", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn ssti_detects_jinja2_evaluation() {
    let treatment = make_response("Hello 49 World", 200, Duration::from_millis(50));
    let control = make_response("Hello World", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssti_evaluation(&treatment, &control, "Hello {{7*7}} World", &baseline);
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert_eq!(ev.evidence_type, EvidenceType::TemplateEvaluation);
    assert!((ev.confidence - 0.95).abs() < f64::EPSILON);
}

#[test]
fn ssti_detects_freemarker_evaluation() {
    let treatment = make_response("result=49", 200, Duration::from_millis(50));
    let control = make_response("result=", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssti_evaluation(&treatment, &control, "result=${7*7}", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn ssti_detects_erb_evaluation() {
    let treatment = make_response("got 49 ok", 200, Duration::from_millis(50));
    let control = make_response("got ok", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssti_evaluation(&treatment, &control, "got <%= 7*7 %> ok", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn ssti_detects_ruby_hash_evaluation() {
    let treatment = make_response("val: 49", 200, Duration::from_millis(50));
    let control = make_response("val: none", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssti_evaluation(&treatment, &control, "val: #{7*7}", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn ssti_detects_string_multiplication() {
    let treatment = make_response("7777777", 200, Duration::from_millis(50));
    let control = make_response("empty", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssti_evaluation(&treatment, &control, "{{7*'7'}}", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn ssti_returns_none_when_result_in_control() {
    let treatment = make_response("page with 49 in it", 200, Duration::from_millis(50));
    let control = make_response("page with 49 in it", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssti_evaluation(&treatment, &control, "{{7*7}}", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn ssti_returns_none_when_no_probe_in_payload() {
    let treatment = make_response("result is 49", 200, Duration::from_millis(50));
    let control = make_response("result is nope", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_ssti_evaluation(&treatment, &control, "some unrelated payload", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn ssti_returns_none_when_result_not_in_treatment() {
    let treatment = make_response("nothing here", 200, Duration::from_millis(50));
    let control = make_response("also nothing", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssti_evaluation(&treatment, &control, "{{7*7}}", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn cmd_output_detects_id_command() {
    let treatment = make_response(
        "uid=1000(www-data) gid=1000",
        200,
        Duration::from_millis(50),
    );
    let control = make_response("normal page", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_cmd_output_patterns(&treatment, &control, "; id", &baseline);
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert_eq!(ev.evidence_type, EvidenceType::CommandOutput);
    assert!((ev.confidence - 0.95).abs() < f64::EPSILON);
}

#[test]
fn cmd_output_detects_etc_passwd() {
    let treatment = make_response(
        "root:x:0:0:root:/root:/bin/bash",
        200,
        Duration::from_millis(50),
    );
    let control = make_response("normal page", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_cmd_output_patterns(&treatment, &control, "; cat /etc/passwd", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn cmd_output_detects_ls_output() {
    let treatment = make_response(
        "total 48\ndrwxr-xr-x 5 user user 4096",
        200,
        Duration::from_millis(50),
    );
    let control = make_response("normal page", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_cmd_output_patterns(&treatment, &control, "; ls -la", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn cmd_output_detects_windows_ipconfig() {
    let treatment = make_response(
        "Windows IP Configuration\n\nEthernet adapter",
        200,
        Duration::from_millis(50),
    );
    let control = make_response("normal page", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_cmd_output_patterns(&treatment, &control, "& ipconfig", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn cmd_output_detects_os_release() {
    let treatment = make_response(
        "PRETTY_NAME=\"Ubuntu 22.04\"",
        200,
        Duration::from_millis(50),
    );
    let control = make_response("normal page", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_cmd_output_patterns(&treatment, &control, "; cat /etc/os-release", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn cmd_output_returns_none_when_pattern_in_control() {
    let body = "uid=1000(www-data) gid=1000";
    let treatment = make_response(body, 200, Duration::from_millis(50));
    let control = make_response(body, 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_cmd_output_patterns(&treatment, &control, "; id", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn cmd_output_returns_none_when_no_pattern_matches() {
    let treatment = make_response("safe page content", 200, Duration::from_millis(50));
    let control = make_response("safe page content", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_cmd_output_patterns(&treatment, &control, "; id", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn cmd_time_delay_detects_sleep_command() {
    let treatment = make_response("OK", 200, Duration::from_secs(5));
    let control = make_response("OK", 200, Duration::from_millis(100));
    let baseline = make_baseline();

    let evidence = confirm_cmd_time_delay(&treatment, &control, "; sleep 5", &baseline);
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert_eq!(ev.evidence_type, EvidenceType::TimeBasedDelay);
    assert!((ev.confidence - 0.88).abs() < f64::EPSILON);
}

#[test]
fn cmd_time_delay_detects_ping_command() {
    let treatment = make_response("OK", 200, Duration::from_secs(3));
    let control = make_response("OK", 200, Duration::from_millis(100));
    let baseline = make_baseline();

    let evidence = confirm_cmd_time_delay(&treatment, &control, "| ping 3", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn cmd_time_delay_detects_timeout_command() {
    let treatment = make_response("OK", 200, Duration::from_secs(4));
    let control = make_response("OK", 200, Duration::from_millis(100));
    let baseline = make_baseline();

    let evidence = confirm_cmd_time_delay(&treatment, &control, "& timeout 4", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn cmd_time_delay_returns_none_when_no_time_keyword() {
    let treatment = make_response("OK", 200, Duration::from_secs(5));
    let control = make_response("OK", 200, Duration::from_millis(100));
    let baseline = make_baseline();

    let evidence = confirm_cmd_time_delay(&treatment, &control, "; id", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn cmd_time_delay_returns_none_when_delta_insufficient() {
    let treatment = make_response("OK", 200, Duration::from_millis(500));
    let control = make_response("OK", 200, Duration::from_millis(200));
    let baseline = make_baseline();

    let evidence = confirm_cmd_time_delay(&treatment, &control, "; sleep 5", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn registry_contains_path_traversal_functions() {
    let registry = build_confirmation_registry();
    assert!(registry.contains_key(&VulnerabilityClass::PathTraversal));
    assert_eq!(registry[&VulnerabilityClass::PathTraversal].len(), 1);
}

#[test]
fn registry_contains_open_redirect_functions() {
    let registry = build_confirmation_registry();
    assert!(registry.contains_key(&VulnerabilityClass::OpenRedirect));
    assert_eq!(registry[&VulnerabilityClass::OpenRedirect].len(), 1);
}

#[test]
fn registry_contains_insecure_deserialization_functions() {
    let registry = build_confirmation_registry();
    assert!(registry.contains_key(&VulnerabilityClass::InsecureDeserialization));
    assert_eq!(
        registry[&VulnerabilityClass::InsecureDeserialization].len(),
        1
    );
}

#[test]
fn registry_contains_ssrf_functions() {
    let registry = build_confirmation_registry();
    assert!(registry.contains_key(&VulnerabilityClass::ServerSideRequestForgery));
    assert_eq!(
        registry[&VulnerabilityClass::ServerSideRequestForgery].len(),
        1
    );
}

#[test]
fn path_traversal_detects_etc_passwd() {
    let treatment = make_response(
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
        200,
        Duration::from_millis(50),
    );
    let control = make_response("File not found", 404, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_path_traversal_file_contents(&treatment, &control, "../../etc/passwd", &baseline);
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert_eq!(ev.evidence_type, EvidenceType::PathContents);
    assert!((ev.confidence - 0.92).abs() < f64::EPSILON);
}

#[test]
fn path_traversal_detects_windows_boot_ini() {
    let treatment = make_response(
        "[boot loader]\ntimeout=30\ndefault=multi(0)",
        200,
        Duration::from_millis(50),
    );
    let control = make_response("Not found", 404, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_path_traversal_file_contents(&treatment, &control, "..\\..\\boot.ini", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn path_traversal_detects_windows_win_ini() {
    let treatment = make_response(
        "[extensions]\ntxt=notepad.exe",
        200,
        Duration::from_millis(50),
    );
    let control = make_response("Not found", 404, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_path_traversal_file_contents(
        &treatment,
        &control,
        "..\\..\\windows\\win.ini",
        &baseline,
    );
    assert!(evidence.is_some());
}

#[test]
fn path_traversal_returns_none_when_pattern_in_control() {
    let body = "root:x:0:0:root:/root:/bin/bash";
    let treatment = make_response(body, 200, Duration::from_millis(50));
    let control = make_response(body, 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_path_traversal_file_contents(&treatment, &control, "../../etc/passwd", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn path_traversal_returns_none_when_no_pattern_matches() {
    let treatment = make_response("normal page content", 200, Duration::from_millis(50));
    let control = make_response("normal page content", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_path_traversal_file_contents(&treatment, &control, "../../etc/passwd", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn redirect_detects_evil_com_in_location_header() {
    let treatment = make_response_with_headers(
        "",
        302,
        vec![("Location".to_string(), "https://evil.com/phish".to_string())],
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_redirect_to_payload_domain(&treatment, &control, "https://evil.com", &baseline);
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert_eq!(ev.evidence_type, EvidenceType::RedirectToExternal);
    assert!((ev.confidence - 0.90).abs() < f64::EPSILON);
}

#[test]
fn redirect_detects_protocol_relative_location() {
    let treatment = make_response_with_headers(
        "",
        302,
        vec![("Location".to_string(), "//attacker.com/steal".to_string())],
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_redirect_to_payload_domain(&treatment, &control, "attacker.com", &baseline);
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert!((ev.confidence - 0.90).abs() < f64::EPSILON);
}

#[test]
fn redirect_detects_payload_domain_in_location() {
    let treatment = make_response_with_headers(
        "",
        302,
        vec![(
            "location".to_string(),
            "https://attacker.example.com/path".to_string(),
        )],
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_redirect_to_payload_domain(&treatment, &control, "attacker.example.com", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn redirect_detects_status_only_redirect() {
    let treatment = make_response("", 301, Duration::from_millis(50));
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_redirect_to_payload_domain(&treatment, &control, "https://evil.com", &baseline);
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert!((ev.confidence - 0.80).abs() < f64::EPSILON);
}

#[test]
fn redirect_returns_none_when_both_redirect() {
    let treatment = make_response("", 302, Duration::from_millis(50));
    let control = make_response("", 301, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_redirect_to_payload_domain(&treatment, &control, "https://evil.com", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn redirect_returns_none_when_no_redirect_behavior() {
    let treatment = make_response("OK", 200, Duration::from_millis(50));
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_redirect_to_payload_domain(&treatment, &control, "https://evil.com", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn redirect_header_match_is_case_insensitive() {
    let treatment = make_response_with_headers(
        "",
        302,
        vec![("LOCATION".to_string(), "https://evil.com/x".to_string())],
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_redirect_to_payload_domain(&treatment, &control, "evil.com", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn deserialization_detects_class_not_found_exception() {
    let treatment = make_response(
        "java.lang.ClassNotFoundException: com.evil.Exploit",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_deserialization_error_pattern(&treatment, &control, "rO0ABXNy...", &baseline);
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert_eq!(ev.evidence_type, EvidenceType::DeserializationMarker);
    assert!((ev.confidence - 0.85).abs() < f64::EPSILON);
}

#[test]
fn deserialization_detects_object_input_stream() {
    let treatment = make_response(
        "Error: java.io.ObjectInputStream failed to deserialize",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_deserialization_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn deserialization_detects_php_unserialize() {
    let treatment = make_response(
        "Warning: unserialize() expects parameter 1",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_deserialization_error_pattern(&treatment, &control, "O:4:\"Test\"", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn deserialization_detects_pickle_loads() {
    let treatment = make_response(
        "pickle.loads failed with invalid opcode",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_deserialization_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn deserialization_detects_node_serialize() {
    let treatment = make_response(
        "node-serialize: Error during deserialization",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_deserialization_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn deserialization_detects_marshalling_error() {
    let treatment = make_response(
        "Internal Server Error: marshalling error occurred",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_deserialization_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn deserialization_returns_none_when_pattern_in_control() {
    let body = "node-serialize: Error during deserialization";
    let treatment = make_response(body, 500, Duration::from_millis(50));
    let control = make_response(body, 500, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_deserialization_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn deserialization_returns_none_when_no_pattern_matches() {
    let treatment = make_response("normal error page", 500, Duration::from_millis(50));
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence =
        confirm_deserialization_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn ssrf_detects_instance_identity() {
    let treatment = make_response(
        "{\"instanceId\": \"i-1234\", \"instance-identity\": \"doc\"}",
        200,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssrf_internal_content(
        &treatment,
        &control,
        "http://169.254.169.254/latest/",
        &baseline,
    );
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert_eq!(ev.evidence_type, EvidenceType::InformationDisclosure);
    assert!((ev.confidence - 0.88).abs() < f64::EPSILON);
}

#[test]
fn ssrf_detects_metadata_endpoint() {
    let treatment = make_response(
        "ami-id\nmeta-data\ninstance-type",
        200,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssrf_internal_content(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn ssrf_detects_link_local_address() {
    let treatment = make_response(
        "Response from 169.254.169.254: OK",
        200,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssrf_internal_content(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn ssrf_detects_10_x_internal_ip() {
    let treatment = make_response(
        "Connected to 10.0.1.5 on port 8080",
        200,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssrf_internal_content(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn ssrf_detects_172_16_internal_ip() {
    let treatment = make_response("Host: 172.16.0.1 responded", 200, Duration::from_millis(50));
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssrf_internal_content(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn ssrf_detects_192_168_internal_ip() {
    let treatment = make_response("Fetched from 192.168.1.100", 200, Duration::from_millis(50));
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssrf_internal_content(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn ssrf_detects_body_size_amplification() {
    let small_body = "OK";
    let large_body = "A".repeat(500);
    let treatment = FuzzResponse {
        request_id: 1,
        status_code: 200,
        body: large_body.clone(),
        headers: Vec::new(),
        response_time: Duration::from_millis(50),
        body_size_bytes: large_body.len(),
    };
    let control = FuzzResponse {
        request_id: 1,
        status_code: 200,
        body: small_body.to_string(),
        headers: Vec::new(),
        response_time: Duration::from_millis(50),
        body_size_bytes: small_body.len(),
    };
    let baseline = make_baseline();

    let evidence = confirm_ssrf_internal_content(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
    assert!(evidence.unwrap().description.contains("bytes"));
}

#[test]
fn ssrf_returns_none_when_pattern_in_control() {
    let body = "Connected to 10.0.1.5 on port 8080";
    let treatment = make_response(body, 200, Duration::from_millis(50));
    let control = make_response(body, 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssrf_internal_content(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn ssrf_returns_none_when_no_indicators() {
    let treatment = make_response("normal page content", 200, Duration::from_millis(50));
    let control = make_response("normal page content", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssrf_internal_content(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn ssrf_body_size_check_ignores_zero_control() {
    let treatment = make_response("some content", 200, Duration::from_millis(50));
    let control = FuzzResponse {
        request_id: 1,
        status_code: 200,
        body: String::new(),
        headers: Vec::new(),
        response_time: Duration::from_millis(50),
        body_size_bytes: 0,
    };
    let baseline = make_baseline();

    let evidence = confirm_ssrf_internal_content(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn ssrf_does_not_match_172_15_as_internal() {
    let treatment = make_response("Connected to 172.15.0.1", 200, Duration::from_millis(50));
    let control = make_response("Connected to public host", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssrf_internal_content(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn ssrf_does_not_match_172_32_as_internal() {
    let treatment = make_response("Connected to 172.32.0.1", 200, Duration::from_millis(50));
    let control = make_response("Connected to public host", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_ssrf_internal_content(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn registry_contains_nosql_injection_functions() {
    let registry = build_confirmation_registry();
    assert!(registry.contains_key(&VulnerabilityClass::NoSqlInjection));
    assert_eq!(registry[&VulnerabilityClass::NoSqlInjection].len(), 2);
}

#[test]
fn nosql_error_detects_mongo_error() {
    let treatment = make_response(
        "MongoError: bad query selector",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_nosql_error_pattern(&treatment, &control, "{\"$ne\": \"\"}", &baseline);
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert_eq!(ev.evidence_type, EvidenceType::NoSqlErrorMessage);
    assert!((ev.confidence - 0.92).abs() < f64::EPSILON);
}

#[test]
fn nosql_error_detects_mongo_server_error() {
    let treatment = make_response(
        "MongoServerError: unknown operator $gte",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_nosql_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn nosql_error_detects_mongo_network_error() {
    let treatment = make_response(
        "MongoNetworkError: connection refused",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_nosql_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn nosql_error_detects_cast_error() {
    let treatment = make_response(
        "CastError: Cast to ObjectId failed",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_nosql_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn nosql_error_detects_bson_type_error() {
    let treatment = make_response(
        "BSONTypeError: invalid BSON type",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_nosql_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn nosql_error_detects_validation_error() {
    let treatment = make_response(
        "ValidationError: user validation failed",
        400,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_nosql_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn nosql_error_detects_duplicate_key() {
    let treatment = make_response(
        "E11000 duplicate key error collection: test.users",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_nosql_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn nosql_error_detects_operator_reflected_where() {
    let treatment = make_response(
        "Error: unknown $where clause provided",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_nosql_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn nosql_error_detects_operator_reflected_ne() {
    let treatment = make_response(
        "Error: $ne operator not allowed",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_nosql_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn nosql_error_detects_operator_reflected_gt() {
    let treatment = make_response(
        "Bad request: $gt is not a valid field",
        400,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_nosql_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn nosql_error_detects_cql_syntax_error() {
    let treatment = make_response(
        "CQL syntax error at line 1:23",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_nosql_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn nosql_error_detects_syntax_exception() {
    let treatment = make_response(
        "SyntaxException: line 1:0 no viable alternative",
        500,
        Duration::from_millis(50),
    );
    let control = make_response("OK", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_nosql_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_some());
}

#[test]
fn nosql_error_ignores_pattern_present_in_control() {
    let body = "MongoError: something went wrong";
    let treatment = make_response(body, 500, Duration::from_millis(50));
    let control = make_response(body, 500, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_nosql_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn nosql_error_returns_none_when_no_pattern_matches() {
    let treatment = make_response("normal page content", 200, Duration::from_millis(50));
    let control = make_response("normal page content", 200, Duration::from_millis(50));
    let baseline = make_baseline();

    let evidence = confirm_nosql_error_pattern(&treatment, &control, "payload", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn nosql_time_delay_detects_sleep_5000() {
    let treatment = make_response("OK", 200, Duration::from_secs(5));
    let control = make_response("OK", 200, Duration::from_millis(100));
    let baseline = make_baseline();

    let evidence = confirm_nosql_time_delay(
        &treatment,
        &control,
        "{\"$where\": \"sleep(5000)\"}",
        &baseline,
    );
    assert!(evidence.is_some());
    let ev = evidence.unwrap();
    assert_eq!(ev.evidence_type, EvidenceType::TimeBasedDelay);
    assert!((ev.confidence - 0.88).abs() < f64::EPSILON);
}

#[test]
fn nosql_time_delay_returns_none_when_no_sleep_keyword() {
    let treatment = make_response("OK", 200, Duration::from_secs(5));
    let control = make_response("OK", 200, Duration::from_millis(100));
    let baseline = make_baseline();

    let evidence = confirm_nosql_time_delay(&treatment, &control, "{\"$ne\": \"\"}", &baseline);
    assert!(evidence.is_none());
}

#[test]
fn nosql_time_delay_returns_none_when_delta_insufficient() {
    let treatment = make_response("OK", 200, Duration::from_millis(500));
    let control = make_response("OK", 200, Duration::from_millis(200));
    let baseline = make_baseline();

    let evidence = confirm_nosql_time_delay(
        &treatment,
        &control,
        "{\"$where\": \"sleep(5000)\"}",
        &baseline,
    );
    assert!(evidence.is_none());
}
