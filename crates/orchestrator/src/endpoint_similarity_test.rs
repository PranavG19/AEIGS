use crate::endpoint_similarity::*;
use aegis_protocol::finding::VulnerabilityClass;

fn sig(
    endpoint: &str,
    method: &str,
    params: &[&str],
    vulns: &[VulnerabilityClass],
) -> EndpointSignature {
    EndpointSignature {
        endpoint: endpoint.to_string(),
        method: method.to_string(),
        parameters: params.iter().map(|s| s.to_string()).collect(),
        vulnerability_classes_found: vulns.to_vec(),
    }
}

#[test]
fn test_tokenize_endpoint_splits_path_segments() {
    let s = sig("/api/users/search", "GET", &[], &[]);
    let tokens = tokenize_endpoint(&s);
    assert_eq!(tokens, vec!["api", "users", "search", "get"]);
}

#[test]
fn test_tokenize_endpoint_normalizes_param_segments() {
    let s = sig("/api/users/:id", "GET", &[], &[]);
    let tokens = tokenize_endpoint(&s);
    assert!(tokens.contains(&"param_segment".to_string()));
    assert!(!tokens.contains(&":id".to_string()));
}

#[test]
fn test_tokenize_endpoint_normalizes_uuid_segments() {
    let s = sig(
        "/api/users/550e8400-e29b-41d4-a716-446655440000",
        "GET",
        &[],
        &[],
    );
    let tokens = tokenize_endpoint(&s);
    assert!(tokens.contains(&"uuid_segment".to_string()));
}

#[test]
fn test_tokenize_endpoint_includes_parameters() {
    let s = sig("/api/users", "POST", &["username", "email"], &[]);
    let tokens = tokenize_endpoint(&s);
    assert!(tokens.contains(&"username".to_string()));
    assert!(tokens.contains(&"email".to_string()));
}

#[test]
fn test_tfidf_index_build() {
    let sigs = vec![
        sig("/api/users", "GET", &[], &[]),
        sig("/api/products", "GET", &[], &[]),
        sig("/health", "GET", &[], &[]),
    ];
    let index = TfIdfIndex::build(&sigs);
    assert_eq!(index.endpoint_count(), 3);
}

#[test]
fn test_cosine_similarity_identical_endpoints() {
    let sigs = vec![
        sig("/api/users", "GET", &["name"], &[]),
        sig("/api/users", "GET", &["name"], &[]),
    ];
    let index = TfIdfIndex::build(&sigs);
    let sim = index.cosine_similarity(0, 1);
    assert!((sim - 1.0).abs() < 1e-9, "expected ~1.0, got {sim}");
}

#[test]
fn test_cosine_similarity_different_endpoints() {
    let sigs = vec![
        sig("/api/users", "GET", &[], &[]),
        sig("/api/products", "GET", &[], &[]),
        sig("/health", "POST", &[], &[]),
    ];
    let index = TfIdfIndex::build(&sigs);
    let sim = index.cosine_similarity(0, 1);
    assert!(sim > 0.0, "expected partial similarity, got {sim}");
    assert!(sim < 1.0, "expected less than 1.0, got {sim}");
}

#[test]
fn test_cosine_similarity_completely_different() {
    let sigs = vec![
        sig("/health", "GET", &[], &[]),
        sig("/api/users/:id/orders", "POST", &["quantity"], &[]),
    ];
    let index = TfIdfIndex::build(&sigs);
    let sim = index.cosine_similarity(0, 1);
    assert!(sim < 0.3, "expected low similarity, got {sim}");
}

#[test]
fn test_find_similar_above_threshold() {
    let sigs = vec![
        sig("/api/users", "GET", &[], &[]),
        sig("/api/users/:id", "GET", &[], &[]),
        sig("/health", "GET", &[], &[]),
    ];
    let index = TfIdfIndex::build(&sigs);
    let similar = index.find_similar(0, 0.5);
    let indices: Vec<usize> = similar.iter().map(|&(i, _)| i).collect();
    assert!(
        indices.contains(&1),
        "expected /api/users/:id to be similar to /api/users"
    );
}

#[test]
fn test_find_similar_sorted_descending() {
    let sigs = vec![
        sig("/api/users", "GET", &["name"], &[]),
        sig("/api/users/:id", "GET", &["name"], &[]),
        sig("/api/products", "GET", &[], &[]),
        sig("/health", "GET", &[], &[]),
    ];
    let index = TfIdfIndex::build(&sigs);
    let similar = index.find_similar(0, 0.0);
    for window in similar.windows(2) {
        assert!(
            window[0].1 >= window[1].1,
            "expected descending order: {} >= {}",
            window[0].1,
            window[1].1
        );
    }
}

#[test]
fn test_transfer_findings_creates_transferred() {
    let sigs = vec![
        sig(
            "/api/users",
            "GET",
            &[],
            &[VulnerabilityClass::SqlInjection],
        ),
        sig("/api/products", "GET", &[], &[]),
    ];
    let targets = vec![(1, 0.8)];
    let transferred = transfer_findings(0, &targets, &sigs);
    assert_eq!(transferred.len(), 1);
    assert_eq!(
        transferred[0].vulnerability_class,
        VulnerabilityClass::SqlInjection
    );
    assert_eq!(transferred[0].source_endpoint, "/api/users");
    assert_eq!(transferred[0].target_endpoint, "/api/products");
    assert!((transferred[0].similarity_score - 0.8).abs() < 1e-9);
    assert!((transferred[0].confidence - 0.72).abs() < 1e-9);
}

#[test]
fn test_transfer_findings_empty_for_no_findings() {
    let sigs = vec![
        sig("/api/users", "GET", &[], &[]),
        sig("/api/products", "GET", &[], &[]),
    ];
    let targets = vec![(1, 0.8)];
    let transferred = transfer_findings(0, &targets, &sigs);
    assert!(transferred.is_empty());
}

#[test]
fn test_trigram_jaccard_identical_paths() {
    let a = extract_trigrams("/api/users");
    let b = extract_trigrams("/api/users");
    let sim = trigram_jaccard(&a, &b);
    assert!((sim - 1.0).abs() < 1e-9);
}

#[test]
fn test_trigram_jaccard_disjoint_paths() {
    let a = extract_trigrams("/xyz");
    let b = extract_trigrams("/abc");
    let sim = trigram_jaccard(&a, &b);
    assert!(
        sim < 0.5,
        "expected low Jaccard for disjoint paths, got {sim}"
    );
}

#[test]
fn test_trigram_jaccard_empty_paths() {
    let a = extract_trigrams("");
    let b = extract_trigrams("");
    let sim = trigram_jaccard(&a, &b);
    assert!((sim - 1.0).abs() < 1e-9);
}

#[test]
fn test_extract_trigrams_short_path_returns_empty() {
    let trigrams = extract_trigrams("/a");
    assert!(trigrams.is_empty());
}

#[test]
fn test_blended_similarity_identical_is_one() {
    let sigs = vec![
        sig("/api/users/search", "GET", &["q"], &[]),
        sig("/api/users/search", "GET", &["q"], &[]),
    ];
    let index = TfIdfIndex::build(&sigs);
    let sim = index.cosine_similarity(0, 1);
    assert!(
        (sim - 1.0).abs() < 1e-9,
        "expected 1.0 for identical, got {sim}"
    );
}

#[test]
fn test_blended_similarity_combines_cosine_and_trigram() {
    let sigs = vec![
        sig("/api/users", "GET", &[], &[]),
        sig("/api/usrs", "GET", &[], &[]),
    ];
    let index = TfIdfIndex::build(&sigs);
    let sim = index.cosine_similarity(0, 1);
    assert!(
        sim > 0.3,
        "expected moderate similarity due to trigram overlap, got {sim}"
    );
}

#[test]
fn test_positional_weighting_favors_early_tokens() {
    let sigs = vec![
        sig("/api/users/orders", "GET", &[], &[]),
        sig("/api/users/reviews", "GET", &[], &[]),
        sig("/xyz/abc/users", "GET", &[], &[]),
    ];
    let index = TfIdfIndex::build(&sigs);
    let sim_01 = index.cosine_similarity(0, 1);
    let sim_02 = index.cosine_similarity(0, 2);
    assert!(
        sim_01 > sim_02,
        "endpoints sharing early tokens should be more similar: {sim_01} vs {sim_02}"
    );
}

#[test]
fn test_single_endpoint_index() {
    let sigs = vec![sig("/api/users", "GET", &[], &[])];
    let index = TfIdfIndex::build(&sigs);
    assert_eq!(index.endpoint_count(), 1);
    let similar = index.find_similar(0, 0.0);
    assert!(similar.is_empty());
}

#[test]
fn test_empty_endpoint_index() {
    let sigs: Vec<EndpointSignature> = vec![];
    let index = TfIdfIndex::build(&sigs);
    assert_eq!(index.endpoint_count(), 0);
}

#[test]
fn test_tokenize_numeric_id_segments() {
    let s = sig("/api/v2/users/12345/orders/67890", "GET", &[], &[]);
    let tokens = tokenize_endpoint(&s);
    assert!(tokens.contains(&"12345".to_string()));
    assert!(tokens.contains(&"67890".to_string()));
}

#[test]
fn test_extract_trigrams_exactly_three_chars() {
    let trigrams = extract_trigrams("/ab");
    assert_eq!(trigrams.len(), 1);
}

#[test]
fn test_trigram_jaccard_one_empty_one_not() {
    let a = extract_trigrams("");
    let b = extract_trigrams("/api/users");
    let sim = trigram_jaccard(&a, &b);
    assert!(
        (sim - 0.0).abs() < 1e-9,
        "expected 0.0 for empty vs non-empty, got {sim}"
    );
}

#[test]
fn test_blended_similarity_formula_weights() {
    let sigs = vec![
        sig("/api/users", "GET", &[], &[]),
        sig("/api/items", "GET", &[], &[]),
    ];
    let index = TfIdfIndex::build(&sigs);
    let blended = index.cosine_similarity(0, 1);
    assert!(
        blended > 0.0 && blended < 1.0,
        "blended score should be between 0 and 1, got {blended}"
    );
}

#[test]
fn test_transfer_findings_multiple_vuln_classes() {
    let sigs = vec![
        sig(
            "/api/users",
            "GET",
            &[],
            &[
                VulnerabilityClass::SqlInjection,
                VulnerabilityClass::CrossSiteScripting,
            ],
        ),
        sig("/api/products", "GET", &[], &[]),
    ];
    let targets = vec![(1, 0.9)];
    let transferred = transfer_findings(0, &targets, &sigs);
    assert_eq!(transferred.len(), 2);
    let classes: Vec<VulnerabilityClass> =
        transferred.iter().map(|t| t.vulnerability_class).collect();
    assert!(classes.contains(&VulnerabilityClass::SqlInjection));
    assert!(classes.contains(&VulnerabilityClass::CrossSiteScripting));
}

#[test]
fn test_transfer_findings_confidence_capped_at_one() {
    let sigs = vec![
        sig(
            "/api/users",
            "GET",
            &[],
            &[VulnerabilityClass::SqlInjection],
        ),
        sig("/api/products", "GET", &[], &[]),
    ];
    let targets = vec![(1, 1.5)];
    let transferred = transfer_findings(0, &targets, &sigs);
    assert_eq!(transferred.len(), 1);
    assert!(
        transferred[0].confidence <= 1.0,
        "confidence should be capped at 1.0, got {}",
        transferred[0].confidence
    );
}

#[test]
fn test_transfer_findings_zero_similarity() {
    let sigs = vec![
        sig(
            "/api/users",
            "GET",
            &[],
            &[VulnerabilityClass::SqlInjection],
        ),
        sig("/api/products", "GET", &[], &[]),
    ];
    let targets = vec![(1, 0.0)];
    let transferred = transfer_findings(0, &targets, &sigs);
    assert_eq!(transferred.len(), 1);
    assert!((transferred[0].confidence - 0.0).abs() < 1e-9);
}

#[test]
fn test_transfer_findings_to_multiple_targets() {
    let sigs = vec![
        sig(
            "/api/users",
            "GET",
            &[],
            &[VulnerabilityClass::SqlInjection],
        ),
        sig("/api/products", "GET", &[], &[]),
        sig("/api/orders", "GET", &[], &[]),
    ];
    let targets = vec![(1, 0.8), (2, 0.6)];
    let transferred = transfer_findings(0, &targets, &sigs);
    assert_eq!(transferred.len(), 2);
    assert_eq!(transferred[0].target_endpoint, "/api/products");
    assert_eq!(transferred[1].target_endpoint, "/api/orders");
}

#[test]
fn test_transfer_findings_empty_targets() {
    let sigs = vec![sig(
        "/api/users",
        "GET",
        &[],
        &[VulnerabilityClass::SqlInjection],
    )];
    let targets: Vec<(usize, f64)> = vec![];
    let transferred = transfer_findings(0, &targets, &sigs);
    assert!(transferred.is_empty());
}

#[test]
fn test_find_similar_excludes_self() {
    let sigs = vec![sig("/api/users", "GET", &["name"], &[])];
    let index = TfIdfIndex::build(&sigs);
    let similar = index.find_similar(0, 0.0);
    assert!(
        !similar.iter().any(|&(i, _)| i == 0),
        "find_similar should exclude self"
    );
}

#[test]
fn test_cosine_similarity_symmetric() {
    let sigs = vec![
        sig("/api/users", "GET", &["name"], &[]),
        sig("/api/products", "POST", &["title"], &[]),
    ];
    let index = TfIdfIndex::build(&sigs);
    let sim_01 = index.cosine_similarity(0, 1);
    let sim_10 = index.cosine_similarity(1, 0);
    assert!(
        (sim_01 - sim_10).abs() < 1e-9,
        "cosine should be symmetric: {sim_01} vs {sim_10}"
    );
}

#[test]
fn test_tokenize_empty_path() {
    let s = sig("", "GET", &[], &[]);
    let tokens = tokenize_endpoint(&s);
    assert_eq!(tokens, vec!["get"]);
}

#[test]
fn test_tokenize_root_path() {
    let s = sig("/", "POST", &[], &[]);
    let tokens = tokenize_endpoint(&s);
    assert_eq!(tokens, vec!["post"]);
}
