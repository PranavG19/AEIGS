use super::*;

#[test]
fn default_config_has_expected_values() {
    let config = DedupConfig::default();
    assert_eq!(config.min_duplicates_to_skip, 3);
    assert!((config.similarity_threshold - 0.95).abs() < 1e-9);
    assert_eq!(config.max_tracked_responses, 10_000);
    assert!(!config.include_headers_in_hash);
    assert!(config.ignore_status_codes.is_empty());
}

#[test]
fn builder_pattern_chains_correctly() {
    let config = DedupConfig::default()
        .with_min_duplicates(5)
        .with_similarity_threshold(0.8)
        .with_max_tracked(500)
        .with_headers_in_hash(true)
        .with_ignored_status_codes(vec![200, 301]);
    assert_eq!(config.min_duplicates_to_skip, 5);
    assert!((config.similarity_threshold - 0.8).abs() < 1e-9);
    assert_eq!(config.max_tracked_responses, 500);
    assert!(config.include_headers_in_hash);
    assert_eq!(config.ignore_status_codes, vec![200, 301]);
}

#[test]
fn builder_clamps_similarity_threshold() {
    let above = DedupConfig::default().with_similarity_threshold(2.0);
    assert!((above.similarity_threshold - 1.0).abs() < 1e-9);

    let below = DedupConfig::default().with_similarity_threshold(-0.5);
    assert!((below.similarity_threshold - 0.0).abs() < 1e-9);
}

#[test]
fn builder_clamps_min_duplicates_to_at_least_one() {
    let config = DedupConfig::default().with_min_duplicates(0);
    assert_eq!(config.min_duplicates_to_skip, 1);
}

#[test]
fn fingerprint_creation_is_deterministic() {
    let body = b"<html>404 Not Found</html>";
    let fp_a = ResponseDeduplicator::fingerprint_response(404, body, Some("text/html"));
    let fp_b = ResponseDeduplicator::fingerprint_response(404, body, Some("text/html"));
    assert_eq!(fp_a, fp_b);
    assert_eq!(fp_a.body_hash, fp_b.body_hash);
    assert_eq!(fp_a.content_length, fp_b.content_length);
}

#[test]
fn record_response_creates_group() {
    let mut dedup = ResponseDeduplicator::with_default_config();
    let fp = ResponseDeduplicator::fingerprint_response(200, b"ok", None);
    dedup.record_response("/api/users", fp.clone());

    let group = dedup.get_duplicate_group(&fp).unwrap();
    assert_eq!(group.endpoints.len(), 1);
    assert_eq!(group.endpoints[0], "/api/users");
    assert!(!group.should_skip);
}

#[test]
fn duplicate_detection_same_fingerprint_different_endpoints() {
    let mut dedup = ResponseDeduplicator::with_default_config();
    let fp = ResponseDeduplicator::fingerprint_response(404, b"not found", None);

    dedup.record_response("/api/users", fp.clone());
    dedup.record_response("/api/products", fp.clone());

    let group = dedup.get_duplicate_group(&fp).unwrap();
    assert_eq!(group.endpoints.len(), 2);
    assert!(group.endpoints.contains(&"/api/users".to_string()));
    assert!(group.endpoints.contains(&"/api/products".to_string()));
}

#[test]
fn should_skip_after_min_duplicates_reached() {
    let config = DedupConfig::default().with_min_duplicates(3);
    let mut dedup = ResponseDeduplicator::new(config);
    let fp = ResponseDeduplicator::fingerprint_response(404, b"not found", None);

    dedup.record_response("/ep1", fp.clone());
    assert!(!dedup.should_skip("/ep1"));

    dedup.record_response("/ep2", fp.clone());
    assert!(!dedup.should_skip("/ep2"));

    dedup.record_response("/ep3", fp.clone());
    assert!(dedup.should_skip("/ep3"));
    assert!(dedup.should_skip("/ep1"));
    assert!(dedup.should_skip("/ep2"));
}

#[test]
fn should_not_skip_below_threshold() {
    let config = DedupConfig::default().with_min_duplicates(5);
    let mut dedup = ResponseDeduplicator::new(config);
    let fp = ResponseDeduplicator::fingerprint_response(404, b"not found", None);

    for i in 0..4 {
        dedup.record_response(&format!("/ep{i}"), fp.clone());
    }

    assert!(!dedup.should_skip("/ep0"));
    assert!(!dedup.should_skip_fingerprint(&fp));
}

#[test]
fn ignored_status_codes_are_not_tracked() {
    let config = DedupConfig::default().with_ignored_status_codes(vec![200]);
    let mut dedup = ResponseDeduplicator::new(config);
    let fp = ResponseDeduplicator::fingerprint_response(200, b"ok", None);

    dedup.record_response("/api/health", fp.clone());
    dedup.record_response("/api/ping", fp.clone());
    dedup.record_response("/api/status", fp.clone());

    assert!(!dedup.should_skip("/api/health"));
    assert_eq!(dedup.total_endpoints_tracked(), 0);
    assert_eq!(dedup.unique_fingerprint_count(), 0);
}

#[test]
fn non_ignored_status_codes_still_tracked() {
    let config = DedupConfig::default().with_ignored_status_codes(vec![200]);
    let mut dedup = ResponseDeduplicator::new(config);

    let fp_404 = ResponseDeduplicator::fingerprint_response(404, b"not found", None);
    dedup.record_response("/api/missing", fp_404.clone());
    assert_eq!(dedup.total_endpoints_tracked(), 1);
}

#[test]
fn endpoint_to_fingerprint_lookup() {
    let mut dedup = ResponseDeduplicator::with_default_config();
    let fp = ResponseDeduplicator::fingerprint_response(200, b"hello", Some("text/plain"));
    dedup.record_response("/api/greet", fp.clone());

    let retrieved = dedup.get_endpoint_fingerprint("/api/greet").unwrap();
    assert_eq!(retrieved, &fp);
    assert!(dedup.get_endpoint_fingerprint("/unknown").is_none());
}

#[test]
fn duplicate_groups_listing() {
    let config = DedupConfig::default().with_min_duplicates(2);
    let mut dedup = ResponseDeduplicator::new(config);

    let fp_a = ResponseDeduplicator::fingerprint_response(404, b"not found", None);
    dedup.record_response("/ep1", fp_a.clone());
    dedup.record_response("/ep2", fp_a.clone());

    let fp_b = ResponseDeduplicator::fingerprint_response(500, b"error", None);
    dedup.record_response("/ep3", fp_b.clone());

    let groups = dedup.duplicate_groups();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].fingerprint, fp_a);
}

#[test]
fn skippable_endpoints_listing() {
    let config = DedupConfig::default().with_min_duplicates(2);
    let mut dedup = ResponseDeduplicator::new(config);

    let fp = ResponseDeduplicator::fingerprint_response(404, b"not found", None);
    dedup.record_response("/ep1", fp.clone());
    dedup.record_response("/ep2", fp.clone());

    let fp_unique = ResponseDeduplicator::fingerprint_response(200, b"unique body", None);
    dedup.record_response("/ep3", fp_unique);

    let skippable = dedup.skippable_endpoints();
    assert_eq!(skippable.len(), 2);
    assert!(skippable.contains(&"/ep1"));
    assert!(skippable.contains(&"/ep2"));
    assert!(!skippable.contains(&"/ep3"));
}

#[test]
fn stats_tracking() {
    let config = DedupConfig::default().with_min_duplicates(2);
    let mut dedup = ResponseDeduplicator::new(config);

    let fp = ResponseDeduplicator::fingerprint_response(404, b"nope", None);
    dedup.record_response("/a", fp.clone());
    dedup.record_response("/b", fp.clone());
    dedup.record_response("/c", fp.clone());

    let stats = dedup.stats();
    assert_eq!(stats.total_responses_seen, 3);
    assert_eq!(stats.unique_fingerprints, 1);
    assert_eq!(stats.duplicate_groups, 1);
    assert!(stats.endpoints_skipped > 0);
}

#[test]
fn reset_clears_all_state() {
    let mut dedup = ResponseDeduplicator::with_default_config();
    let fp = ResponseDeduplicator::fingerprint_response(200, b"data", None);

    dedup.record_response("/ep1", fp.clone());
    dedup.record_response("/ep2", fp.clone());
    dedup.record_response("/ep3", fp.clone());

    assert!(dedup.total_endpoints_tracked() > 0);

    dedup.reset();

    assert_eq!(dedup.total_endpoints_tracked(), 0);
    assert_eq!(dedup.unique_fingerprint_count(), 0);
    assert_eq!(dedup.stats().total_responses_seen, 0);
    assert_eq!(dedup.stats().unique_fingerprints, 0);
    assert_eq!(dedup.stats().duplicate_groups, 0);
    assert_eq!(dedup.stats().endpoints_skipped, 0);
    assert_eq!(dedup.stats().bytes_saved_estimate, 0);
    assert!(!dedup.should_skip("/ep1"));
}

#[test]
fn max_tracked_limit_prevents_unbounded_growth() {
    let config = DedupConfig::default().with_max_tracked(3);
    let mut dedup = ResponseDeduplicator::new(config);

    for i in 0..10 {
        let fp =
            ResponseDeduplicator::fingerprint_response(200, format!("body-{i}").as_bytes(), None);
        dedup.record_response(&format!("/ep{i}"), fp);
    }

    assert!(dedup.total_endpoints_tracked() <= 3);
}

#[test]
fn different_responses_produce_different_fingerprints() {
    let fp_a = ResponseDeduplicator::fingerprint_response(200, b"hello", None);
    let fp_b = ResponseDeduplicator::fingerprint_response(200, b"world", None);
    let fp_c = ResponseDeduplicator::fingerprint_response(404, b"hello", None);

    assert_ne!(fp_a, fp_b);
    assert_ne!(fp_a, fp_c);
    assert_ne!(fp_b, fp_c);
}

#[test]
fn content_type_in_fingerprint() {
    let fp_html = ResponseDeduplicator::fingerprint_response(200, b"body", Some("text/html"));
    let fp_json =
        ResponseDeduplicator::fingerprint_response(200, b"body", Some("application/json"));
    let fp_none = ResponseDeduplicator::fingerprint_response(200, b"body", None);

    assert_ne!(fp_html, fp_json);
    assert_ne!(fp_html, fp_none);
    assert_ne!(fp_json, fp_none);
}

#[test]
fn recording_same_endpoint_twice_does_not_duplicate_in_group() {
    let mut dedup = ResponseDeduplicator::with_default_config();
    let fp = ResponseDeduplicator::fingerprint_response(200, b"ok", None);

    dedup.record_response("/api/users", fp.clone());
    dedup.record_response("/api/users", fp.clone());

    let group = dedup.get_duplicate_group(&fp).unwrap();
    assert_eq!(group.endpoints.len(), 1);
}

#[test]
fn should_skip_returns_false_for_unknown_endpoint() {
    let dedup = ResponseDeduplicator::with_default_config();
    assert!(!dedup.should_skip("/never/recorded"));
}

#[test]
fn should_skip_fingerprint_returns_false_for_unknown_fingerprint() {
    let dedup = ResponseDeduplicator::with_default_config();
    let fp = ResponseDeduplicator::fingerprint_response(418, b"teapot", None);
    assert!(!dedup.should_skip_fingerprint(&fp));
}

#[test]
fn empty_body_fingerprint() {
    let fp = ResponseDeduplicator::fingerprint_response(204, b"", None);
    assert_eq!(fp.content_length, 0);
    assert_eq!(fp.status_code, 204);
}

#[test]
fn large_body_fingerprint_captures_length() {
    let body = vec![0xABu8; 1_000_000];
    let fp = ResponseDeduplicator::fingerprint_response(200, &body, None);
    assert_eq!(fp.content_length, 1_000_000);
}

#[test]
fn unique_fingerprint_count_reflects_distinct_responses() {
    let mut dedup = ResponseDeduplicator::with_default_config();

    let fp_a = ResponseDeduplicator::fingerprint_response(200, b"alpha", None);
    let fp_b = ResponseDeduplicator::fingerprint_response(200, b"beta", None);

    dedup.record_response("/a", fp_a);
    dedup.record_response("/b", fp_b);

    assert_eq!(dedup.unique_fingerprint_count(), 2);
}

#[test]
fn bytes_saved_estimate_accumulates() {
    let config = DedupConfig::default().with_min_duplicates(2);
    let mut dedup = ResponseDeduplicator::new(config);

    let body = b"repeated-body-content";
    let fp = ResponseDeduplicator::fingerprint_response(404, body, None);

    dedup.record_response("/ep1", fp.clone());
    let saved_before = dedup.stats().bytes_saved_estimate;

    dedup.record_response("/ep2", fp.clone());
    dedup.record_response("/ep3", fp.clone());

    assert!(dedup.stats().bytes_saved_estimate > saved_before);
}

#[test]
fn multiple_distinct_groups_tracked_independently() {
    let config = DedupConfig::default().with_min_duplicates(2);
    let mut dedup = ResponseDeduplicator::new(config);

    let fp_404 = ResponseDeduplicator::fingerprint_response(404, b"not found", None);
    let fp_500 = ResponseDeduplicator::fingerprint_response(500, b"server error", None);

    dedup.record_response("/a1", fp_404.clone());
    dedup.record_response("/a2", fp_404.clone());

    dedup.record_response("/b1", fp_500.clone());

    assert!(dedup.should_skip("/a1"));
    assert!(!dedup.should_skip("/b1"));

    dedup.record_response("/b2", fp_500.clone());
    assert!(dedup.should_skip("/b1"));

    assert_eq!(dedup.duplicate_groups().len(), 2);
}
