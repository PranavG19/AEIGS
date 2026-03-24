use super::*;
use crate::types::RecordedExchange;

fn sample_exchange() -> RecordedExchange {
    RecordedExchange {
        id: 1,
        request_method: "GET".to_string(),
        request_url: "http://localhost:8080/api/users?id=42&role=admin".to_string(),
        request_headers: vec![
            ("Host".to_string(), "localhost:8080".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        request_body: b"{\"name\":\"test\",\"value\":\"123\"}".to_vec(),
        response_status: 200,
        response_headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Request-Id".to_string(), "abc123".to_string()),
        ],
        response_body: b"{\"ok\":true}".to_vec(),
        timestamp_ms: 1700000000000,
        duration_ms: 50,
        in_scope: true,
        tags: vec![],
    }
}

fn sample_exchange_no_params() -> RecordedExchange {
    RecordedExchange {
        id: 2,
        request_method: "POST".to_string(),
        request_url: "http://localhost:8080/api/login".to_string(),
        request_headers: vec![
            ("Host".to_string(), "localhost:8080".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        request_body: b"{\"user\":\"admin\",\"pass\":\"secret\"}".to_vec(),
        response_status: 200,
        response_headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        response_body: b"{\"token\":\"xyz\"}".to_vec(),
        timestamp_ms: 1700000001000,
        duration_ms: 100,
        in_scope: true,
        tags: vec![],
    }
}

// ===== AC1: ≥50 mutations across ≥6 dimensions =====

#[test]
fn generates_at_least_50_mutations() {
    let exchange = sample_exchange();
    let matrix = MutationMatrix::generate(&exchange);
    assert!(
        matrix.mutations.len() >= 50,
        "expected ≥50 mutations, got {}",
        matrix.mutations.len()
    );
}

#[test]
fn covers_at_least_6_dimensions() {
    let exchange = sample_exchange();
    let matrix = MutationMatrix::generate(&exchange);
    let dim_count = matrix.dimension_count();
    assert!(dim_count >= 6, "expected ≥6 dimensions, got {dim_count}");
}

#[test]
fn all_six_dimensions_present() {
    let exchange = sample_exchange();
    let matrix = MutationMatrix::generate(&exchange);
    let counts = matrix.counts_by_dimension();
    for dim in AttackDimension::ALL {
        assert!(counts.contains_key(dim), "missing dimension: {:?}", dim);
    }
}

// ===== AC2: ResponseDiff flags =====

#[test]
fn diff_flags_status_code_change() {
    let baseline = sample_exchange();
    let diff = ResponseDiff::compute(&baseline, 403, &[], 10, 50);
    assert!(diff.status_code_changed);
    assert!(diff.is_interesting);
}

#[test]
fn diff_flags_body_length_delta_over_10pct() {
    let baseline = sample_exchange();
    let big_body_len = (baseline.response_body.len() as f64 * 1.2) as usize;
    let diff = ResponseDiff::compute(&baseline, 200, &baseline.response_headers, big_body_len, 50);
    assert!(diff.body_length_delta_pct > 10.0);
    assert!(diff.is_interesting);
}

#[test]
fn diff_flags_new_headers() {
    let baseline = sample_exchange();
    let mut resp_headers = baseline.response_headers.clone();
    resp_headers.push(("X-New-Header".to_string(), "surprise".to_string()));
    let diff = ResponseDiff::compute(
        &baseline,
        200,
        &resp_headers,
        baseline.response_body.len(),
        50,
    );
    assert!(!diff.new_headers.is_empty());
    assert!(diff.is_interesting);
}

#[test]
fn diff_flags_timing_delta_over_2x() {
    let baseline = sample_exchange();
    let diff = ResponseDiff::compute(
        &baseline,
        200,
        &baseline.response_headers,
        baseline.response_body.len(),
        150, // 3x the baseline 50ms
    );
    assert!(diff.timing_ratio > 2.0);
    assert!(diff.is_interesting);
}

#[test]
fn diff_not_interesting_when_all_normal() {
    let baseline = sample_exchange();
    let diff = ResponseDiff::compute(
        &baseline,
        200,
        &baseline.response_headers,
        baseline.response_body.len(),
        50,
    );
    assert!(!diff.is_interesting);
}

// ===== AC3: Parameter pollution duplicates params =====

#[test]
fn parameter_pollution_duplicates_params_with_conflicting_values() {
    let exchange = sample_exchange();
    let mutations = generate_parameter_pollution(&exchange);
    assert!(!mutations.is_empty());
    for m in &mutations {
        assert_eq!(m.dimension, AttackDimension::ParameterPollution);
        // URL should contain duplicate param key
        let url = &m.url;
        assert!(
            url.contains('?'),
            "mutation URL should have query string: {url}"
        );
    }
    // Verify at least one mutation has a duplicated param key
    let has_dup = mutations.iter().any(|m| {
        let (_, params) = extract_query_params(&m.url);
        let keys: Vec<&str> = params.iter().map(|(k, _)| k.as_str()).collect();
        keys.len() != keys.iter().collect::<std::collections::HashSet<_>>().len()
    });
    assert!(
        has_dup,
        "should have at least one mutation with duplicated param key"
    );
}

#[test]
fn parameter_pollution_injects_synthetic_when_no_params() {
    let exchange = sample_exchange_no_params();
    let mutations = generate_parameter_pollution(&exchange);
    assert!(!mutations.is_empty());
    for m in &mutations {
        assert_eq!(m.dimension, AttackDimension::ParameterPollution);
        assert!(m.url.contains('?'), "should inject query params");
    }
}

// ===== AC4: Verb tampering =====

#[test]
fn verb_tampering_cycles_all_methods() {
    let exchange = sample_exchange(); // GET
    let mutations = generate_verb_tampering(&exchange);
    let methods: Vec<&str> = mutations.iter().map(|m| m.method.as_str()).collect();
    assert!(methods.contains(&"POST"));
    assert!(methods.contains(&"PUT"));
    assert!(methods.contains(&"PATCH"));
    assert!(methods.contains(&"DELETE"));
}

#[test]
fn verb_tampering_excludes_original_method() {
    let exchange = sample_exchange(); // GET
    let mutations = generate_verb_tampering(&exchange);
    assert!(
        mutations.iter().all(|m| m.method != "GET"),
        "should not include original method"
    );
}

// ===== AC5: Content-type confusion =====

#[test]
fn content_type_confusion_generates_json_xml_multipart() {
    let exchange = sample_exchange();
    let mutations = generate_content_type_confusion(&exchange);
    let content_types: Vec<String> = mutations
        .iter()
        .flat_map(|m| {
            m.headers
                .iter()
                .filter(|(k, _)| k.to_lowercase() == "content-type")
                .map(|(_, v)| v.clone())
        })
        .collect();
    assert!(content_types
        .iter()
        .any(|ct| ct.contains("application/json")));
    assert!(content_types
        .iter()
        .any(|ct| ct.contains("application/xml")));
    assert!(content_types
        .iter()
        .any(|ct| ct.contains("multipart/form-data")));
}

#[test]
fn content_type_confusion_xml_is_valid_xml() {
    let exchange = sample_exchange();
    let mutations = generate_content_type_confusion(&exchange);
    let xml_mutation = mutations
        .iter()
        .find(|m| m.description.contains("application/xml"))
        .expect("should have XML mutation");
    let body = std::str::from_utf8(&xml_mutation.body).unwrap();
    assert!(body.starts_with("<?xml"));
    assert!(body.contains("<root>"));
    assert!(body.contains("</root>"));
}

#[test]
fn content_type_confusion_multipart_has_boundary() {
    let exchange = sample_exchange();
    let mutations = generate_content_type_confusion(&exchange);
    let mp_mutation = mutations
        .iter()
        .find(|m| m.description.contains("multipart"))
        .expect("should have multipart mutation");
    let body = std::str::from_utf8(&mp_mutation.body).unwrap();
    assert!(body.contains("Content-Disposition: form-data"));
}

// ===== AC6: Path normalization =====

#[test]
fn path_normalization_includes_dot_dot_semicolon() {
    let exchange = sample_exchange();
    let mutations = generate_path_normalization(&exchange);
    assert!(mutations.iter().any(|m| m.url.contains("..;/")));
}

#[test]
fn path_normalization_includes_dot_slash() {
    let exchange = sample_exchange();
    let mutations = generate_path_normalization(&exchange);
    assert!(mutations.iter().any(|m| m.url.contains("/./")));
}

#[test]
fn path_normalization_includes_encoded_traversal() {
    let exchange = sample_exchange();
    let mutations = generate_path_normalization(&exchange);
    assert!(mutations.iter().any(|m| m.url.contains("%2e%2e/")));
}

// ===== AC7: Encoding ladder =====

#[test]
fn encoding_ladder_generates_url_encoded() {
    let exchange = sample_exchange();
    let mutations = generate_encoding_ladder(&exchange);
    assert!(mutations
        .iter()
        .any(|m| m.description.contains("url-encoded")));
}

#[test]
fn encoding_ladder_generates_double_encoded() {
    let exchange = sample_exchange();
    let mutations = generate_encoding_ladder(&exchange);
    assert!(mutations.iter().any(|m| m.description.contains("double")));
}

#[test]
fn encoding_ladder_generates_unicode_encoded() {
    let exchange = sample_exchange();
    let mutations = generate_encoding_ladder(&exchange);
    assert!(mutations.iter().any(|m| m.description.contains("unicode")));
}

#[test]
fn encoding_ladder_generates_hex_encoded() {
    let exchange = sample_exchange();
    let mutations = generate_encoding_ladder(&exchange);
    assert!(mutations.iter().any(|m| m.description.contains("hex")));
}

// ===== Dimension labels =====

#[test]
fn dimension_labels_are_unique() {
    let labels: Vec<&str> = AttackDimension::ALL.iter().map(|d| d.label()).collect();
    let unique: std::collections::HashSet<&str> = labels.iter().copied().collect();
    assert_eq!(labels.len(), unique.len());
}

// ===== Edge cases =====

#[test]
fn mutation_matrix_with_empty_body() {
    let mut exchange = sample_exchange();
    exchange.request_body = vec![];
    let matrix = MutationMatrix::generate(&exchange);
    assert!(matrix.mutations.len() >= 50);
    assert!(matrix.dimension_count() >= 6);
}

#[test]
fn mutation_matrix_preserves_baseline() {
    let exchange = sample_exchange();
    let matrix = MutationMatrix::generate(&exchange);
    assert_eq!(matrix.baseline.id, exchange.id);
    assert_eq!(matrix.baseline.request_url, exchange.request_url);
}

#[test]
fn counts_by_dimension_sums_to_total() {
    let exchange = sample_exchange();
    let matrix = MutationMatrix::generate(&exchange);
    let total: usize = matrix.counts_by_dimension().values().sum();
    assert_eq!(total, matrix.mutations.len());
}

#[test]
fn diff_with_zero_baseline_duration_no_panic() {
    let mut baseline = sample_exchange();
    baseline.duration_ms = 0;
    let diff = ResponseDiff::compute(
        &baseline,
        200,
        &baseline.response_headers,
        baseline.response_body.len(),
        100,
    );
    assert!(diff.timing_ratio.is_finite());
}

#[test]
fn diff_with_empty_baseline_body_no_panic() {
    let mut baseline = sample_exchange();
    baseline.response_body = vec![];
    let diff = ResponseDiff::compute(&baseline, 200, &[], 1000, 50);
    assert!(diff.body_length_delta_pct.is_finite());
}

#[test]
fn header_injection_includes_crlf() {
    let exchange = sample_exchange();
    let mutations = generate_header_injection(&exchange);
    assert!(mutations
        .iter()
        .any(|m| { m.headers.iter().any(|(_, v)| v.contains("\r\n")) }));
}

#[test]
fn header_injection_includes_host_override() {
    let exchange = sample_exchange();
    let mutations = generate_header_injection(&exchange);
    assert!(mutations.iter().any(|m| m.description.contains("Host")));
}

#[test]
fn verb_tampering_preserves_url_and_body() {
    let exchange = sample_exchange();
    let mutations = generate_verb_tampering(&exchange);
    for m in &mutations {
        assert_eq!(m.url, exchange.request_url);
        assert_eq!(m.body, exchange.request_body);
    }
}
