use std::collections::HashMap;

use crate::code_path_analyzer::*;

fn base_request() -> HttpRequest {
    let mut params = HashMap::new();
    params.insert("id".to_string(), "123".to_string());
    params.insert("action".to_string(), "view".to_string());

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("accept".to_string(), "application/json".to_string());

    HttpRequest {
        method: "GET".to_string(),
        url: "/api/users".to_string(),
        headers,
        body: Some("{\"query\": \"test\"}".to_string()),
        params,
    }
}

fn baseline_response() -> HttpResponse {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("x-request-id".to_string(), "abc123".to_string());

    HttpResponse {
        status: 200,
        headers,
        body: "{\"result\": \"ok\"}".to_string(),
    }
}

fn different_response() -> HttpResponse {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/html".to_string());

    HttpResponse {
        status: 403,
        headers,
        body: "<html>Forbidden</html>".to_string(),
    }
}

// ─── Config builder ─────────────────────────────────────────────────

#[test]
fn config_builder_chain_works() {
    let config = CodePathConfig::default()
        .with_target_url("https://target.test/api")
        .with_timeout_ms(10000)
        .with_max_variations(100);
    assert_eq!(config.target_url, "https://target.test/api");
    assert_eq!(config.timeout_ms, 10000);
    assert_eq!(config.max_variations, 100);
}

#[test]
fn config_default_values() {
    let config = CodePathConfig::default();
    assert!(config.target_url.is_empty());
    assert_eq!(config.timeout_ms, 5000);
    assert_eq!(config.max_variations, 50);
}

// ─── Variation generation covers all types ──────────────────────────

#[test]
fn variations_cover_all_types() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default().with_max_variations(200));
    let variations = analyzer.generate_variations(&base_request());

    let types_present: std::collections::HashSet<VariationType> =
        variations.iter().map(|v| v.variation_type).collect();

    for vt in all_variation_types() {
        assert!(
            types_present.contains(&vt),
            "Missing variation type: {}",
            vt
        );
    }
}

#[test]
fn variations_respect_max_limit() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default().with_max_variations(3));
    let variations = analyzer.generate_variations(&base_request());
    assert!(variations.len() <= 3);
}

#[test]
fn variations_have_descriptions() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default());
    let variations = analyzer.generate_variations(&base_request());
    for v in &variations {
        assert!(
            !v.description.is_empty(),
            "Variation must have a description"
        );
    }
}

// ─── Response hashing ───────────────────────────────────────────────

#[test]
fn hash_response_consistent() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default());
    let response = baseline_response();
    let hash1 = analyzer.hash_response(&response);
    let hash2 = analyzer.hash_response(&response);
    assert_eq!(hash1, hash2, "Same response must produce same hash");
}

#[test]
fn different_responses_produce_different_hashes() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default());
    let hash1 = analyzer.hash_response(&baseline_response());
    let hash2 = analyzer.hash_response(&different_response());
    assert_ne!(
        hash1.combined, hash2.combined,
        "Different responses must produce different combined hashes"
    );
}

#[test]
fn hash_status_differs_for_different_status_codes() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default());
    let resp1 = baseline_response();
    let mut resp2 = baseline_response();
    resp2.status = 404;
    let hash1 = analyzer.hash_response(&resp1);
    let hash2 = analyzer.hash_response(&resp2);
    assert_ne!(hash1.status_hash, hash2.status_hash);
}

#[test]
fn hash_headers_differ_for_different_header_keys() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default());
    let mut resp1 = baseline_response();
    let mut resp2 = baseline_response();
    resp2
        .headers
        .insert("x-extra".to_string(), "val".to_string());
    let hash1 = analyzer.hash_response(&resp1);
    let hash2 = analyzer.hash_response(&resp2);
    assert_ne!(hash1.header_hash, hash2.header_hash);
}

#[test]
fn hash_body_differs_for_different_body() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default());
    let mut resp1 = baseline_response();
    let mut resp2 = baseline_response();
    resp1.body = "body_a".to_string();
    resp2.body = "body_b".to_string();
    let hash1 = analyzer.hash_response(&resp1);
    let hash2 = analyzer.hash_response(&resp2);
    assert_ne!(hash1.body_hash, hash2.body_hash);
}

// ─── Coverage map ───────────────────────────────────────────────────

#[test]
fn coverage_map_groups_correctly() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default());
    let hash_a = ResponseHash {
        status_hash: 1,
        header_hash: 2,
        body_hash: 3,
        combined: 100,
    };
    let hash_b = ResponseHash {
        status_hash: 4,
        header_hash: 5,
        body_hash: 6,
        combined: 200,
    };

    let results = vec![
        VariationResult {
            variation: RequestVariation {
                description: "v1".to_string(),
                modified_request: base_request(),
                variation_type: VariationType::Encoding,
            },
            response_hash: hash_a,
            differs_from_baseline: false,
        },
        VariationResult {
            variation: RequestVariation {
                description: "v2".to_string(),
                modified_request: base_request(),
                variation_type: VariationType::NullByte,
            },
            response_hash: hash_b,
            differs_from_baseline: true,
        },
        VariationResult {
            variation: RequestVariation {
                description: "v3".to_string(),
                modified_request: base_request(),
                variation_type: VariationType::CaseChange,
            },
            response_hash: hash_a,
            differs_from_baseline: false,
        },
    ];

    let map = analyzer.build_coverage_map(&results);
    assert_eq!(map.total_unique_paths, 2);
    assert_eq!(map.paths[&100].len(), 2);
    assert_eq!(map.paths[&200].len(), 1);
    assert!(map.paths[&100].contains(&VariationType::Encoding));
    assert!(map.paths[&100].contains(&VariationType::CaseChange));
    assert!(map.paths[&200].contains(&VariationType::NullByte));
}

#[test]
fn coverage_map_empty_results() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default());
    let map = analyzer.build_coverage_map(&[]);
    assert_eq!(map.total_unique_paths, 0);
    assert!(map.paths.is_empty());
}

// ─── Full analysis ──────────────────────────────────────────────────

#[test]
fn analyze_detects_different_code_paths() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default().with_max_variations(200));
    let base = base_request();
    let baseline = baseline_response();
    let variations = analyzer.generate_variations(&base);

    let mut responses: Vec<HttpResponse> = Vec::new();
    for (i, _) in variations.iter().enumerate() {
        if i % 3 == 0 {
            responses.push(different_response());
        } else {
            responses.push(baseline_response());
        }
    }

    let analysis = analyzer.analyze(&base, &baseline, &responses);
    assert!(
        analysis.unique_paths >= 2,
        "Must detect at least 2 unique paths"
    );
    assert!(!analysis.interesting_variations.is_empty());
}

#[test]
fn analyze_all_same_responses() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default());
    let base = base_request();
    let baseline = baseline_response();
    let variations = analyzer.generate_variations(&base);

    let responses: Vec<HttpResponse> = (0..variations.len()).map(|_| baseline_response()).collect();

    let analysis = analyzer.analyze(&base, &baseline, &responses);
    assert_eq!(analysis.unique_paths, 1);
    assert!(analysis.interesting_variations.is_empty());
}

// ─── Null byte variation construction ───────────────────────────────

#[test]
fn null_byte_variation_contains_null() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default());
    let variations = analyzer.generate_variations(&base_request());
    let null_variations: Vec<_> = variations
        .iter()
        .filter(|v| v.variation_type == VariationType::NullByte)
        .collect();
    assert!(!null_variations.is_empty());

    let has_null_in_url = null_variations
        .iter()
        .any(|v| v.modified_request.url.contains('\x00'));
    let has_null_in_params = null_variations.iter().any(|v| {
        v.modified_request
            .params
            .values()
            .any(|val| val.contains('\x00'))
    });
    assert!(
        has_null_in_url || has_null_in_params,
        "Null byte variations must contain \\x00 in URL or params"
    );
}

// ─── Specific variation types ───────────────────────────────────────

#[test]
fn encoding_variations_modify_url() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default());
    let base = base_request();
    let variations = analyzer.generate_variations(&base);
    let encoding: Vec<_> = variations
        .iter()
        .filter(|v| v.variation_type == VariationType::Encoding)
        .collect();
    assert!(!encoding.is_empty());
    let any_modified = encoding.iter().any(|v| v.modified_request.url != base.url);
    assert!(any_modified, "Encoding variations must modify the URL");
}

#[test]
fn method_variations_change_method() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default());
    let base = base_request();
    let variations = analyzer.generate_variations(&base);
    let method_vars: Vec<_> = variations
        .iter()
        .filter(|v| v.variation_type == VariationType::MethodChange)
        .collect();
    assert!(!method_vars.is_empty());
    for v in &method_vars {
        assert_ne!(v.modified_request.method, base.method);
    }
}

#[test]
fn path_traversal_variations_inject_sequences() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default());
    let variations = analyzer.generate_variations(&base_request());
    let traversal: Vec<_> = variations
        .iter()
        .filter(|v| v.variation_type == VariationType::PathTraversal)
        .collect();
    assert!(!traversal.is_empty());
    let has_dotdot = traversal
        .iter()
        .any(|v| v.modified_request.url.contains(".."));
    assert!(has_dotdot, "Path traversal must contain '..'");
}

// ─── VariationType Display ──────────────────────────────────────────

#[test]
fn variation_type_display_is_human_readable() {
    assert_eq!(format!("{}", VariationType::Encoding), "Encoding");
    assert_eq!(format!("{}", VariationType::NullByte), "Null Byte");
    assert_eq!(
        format!("{}", VariationType::ContentTypeSwitch),
        "Content-Type Switch"
    );
}

// ─── all_variation_types ────────────────────────────────────────────

#[test]
fn all_variation_types_returns_nine() {
    assert_eq!(all_variation_types().len(), 9);
}

// ─── Edge cases ─────────────────────────────────────────────────────

#[test]
fn variations_with_no_params() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default());
    let req = HttpRequest {
        method: "GET".to_string(),
        url: "/simple".to_string(),
        headers: HashMap::new(),
        body: None,
        params: HashMap::new(),
    };
    let variations = analyzer.generate_variations(&req);
    assert!(
        !variations.is_empty(),
        "Must still produce variations for a minimal request"
    );
}

#[test]
fn hash_empty_response() {
    let analyzer = CodePathAnalyzer::new(CodePathConfig::default());
    let resp = HttpResponse {
        status: 204,
        headers: HashMap::new(),
        body: String::new(),
    };
    let hash = analyzer.hash_response(&resp);
    assert_ne!(
        hash.combined, 0,
        "Hash should not be zero even for empty response"
    );
}
