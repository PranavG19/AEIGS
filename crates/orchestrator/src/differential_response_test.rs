use super::*;

fn make_baseline_fingerprint() -> ResponseFingerprint {
    ResponseFingerprint::from_response(
        200,
        &[
            ("Content-Type".to_string(), "text/html".to_string()),
            ("Server".to_string(), "nginx".to_string()),
        ],
        "<html><body>Hello World</body></html>",
        50.0,
    )
}

fn make_blocked_fingerprint() -> ResponseFingerprint {
    ResponseFingerprint::from_response(
        403,
        &[
            ("Content-Type".to_string(), "text/html".to_string()),
            ("Server".to_string(), "nginx".to_string()),
            ("X-WAF-Block".to_string(), "true".to_string()),
        ],
        "<html><body>Access Denied - Your request was blocked by the WAF</body></html>",
        10.0,
    )
}

#[test]
fn response_fingerprint_basic_fields() {
    let fp = make_baseline_fingerprint();
    assert_eq!(fp.status_code, 200);
    assert_eq!(fp.content_type.as_deref(), Some("text/html"));
    assert_eq!(fp.server_header.as_deref(), Some("nginx"));
    assert!(fp.body_length > 0);
    assert!(fp.body_hash > 0);
}

#[test]
fn response_fingerprint_detects_waf_headers() {
    let fp = make_blocked_fingerprint();
    assert!(fp.has_waf_headers, "Should detect X-WAF-Block header");
}

#[test]
fn response_fingerprint_no_waf_headers() {
    let fp = make_baseline_fingerprint();
    assert!(!fp.has_waf_headers);
}

#[test]
fn response_fingerprint_cf_ray_detected() {
    let fp = ResponseFingerprint::from_response(
        200,
        &[("cf-ray".to_string(), "abc123".to_string())],
        "ok",
        10.0,
    );
    assert!(fp.has_waf_headers);
}

#[test]
fn fingerprint_similarity_identical() {
    let fp = make_baseline_fingerprint();
    let sim = fingerprint_similarity(&fp, &fp);
    assert!(
        (sim - 1.0).abs() < 0.01,
        "Identical fingerprints should have similarity 1.0, got {}",
        sim
    );
}

#[test]
fn fingerprint_similarity_different() {
    let baseline = make_baseline_fingerprint();
    let blocked = make_blocked_fingerprint();
    let sim = fingerprint_similarity(&baseline, &blocked);
    assert!(
        sim < 0.5,
        "Different responses should have low similarity, got {}",
        sim
    );
}

#[test]
fn classify_decision_allowed() {
    let baseline = make_baseline_fingerprint();
    let block_pattern = make_blocked_fingerprint();
    let probe = make_baseline_fingerprint();

    let decision = classify_decision(&probe, &baseline, &block_pattern);
    assert_eq!(decision, WafDecision::Allowed);
}

#[test]
fn classify_decision_blocked() {
    let baseline = make_baseline_fingerprint();
    let block_pattern = make_blocked_fingerprint();
    let probe = make_blocked_fingerprint();

    let decision = classify_decision(&probe, &baseline, &block_pattern);
    assert_eq!(decision, WafDecision::Blocked);
}

#[test]
fn classify_decision_rate_limited() {
    let baseline = make_baseline_fingerprint();
    let block_pattern = make_blocked_fingerprint();
    let probe = ResponseFingerprint::from_response(
        429,
        &[("Retry-After".to_string(), "60".to_string())],
        "Too Many Requests",
        5.0,
    );

    let decision = classify_decision(&probe, &baseline, &block_pattern);
    assert_eq!(decision, WafDecision::RateLimited);
}

#[test]
fn classify_decision_challenged() {
    let baseline = make_baseline_fingerprint();
    let block_pattern = make_blocked_fingerprint();
    let probe = ResponseFingerprint::from_response(
        503,
        &[],
        "<html>Please complete this challenge to continue</html>",
        100.0,
    );

    let decision = classify_decision(&probe, &baseline, &block_pattern);
    assert_eq!(decision, WafDecision::Challenged);
}

#[test]
fn generate_mutations_comprehensive() {
    let mutations = generate_mutations("<script>alert(1)</script>");

    assert!(
        mutations.len() >= 12,
        "Should generate 12+ mutations, got {}",
        mutations.len()
    );

    let types: Vec<&MutationType> = mutations.iter().map(|(t, _)| t).collect();
    assert!(types.contains(&&MutationType::Original));
    assert!(types.contains(&&MutationType::UrlEncoded));
    assert!(types.contains(&&MutationType::DoubleUrlEncoded));
    assert!(types.contains(&&MutationType::CaseToggled));
    assert!(types.contains(&&MutationType::CommentInserted));
    assert!(types.contains(&&MutationType::JsonWrapped));
}

#[test]
fn url_encode_special_chars() {
    let mutations = generate_mutations("<script>");
    let url_encoded = mutations
        .iter()
        .find(|(t, _)| *t == MutationType::UrlEncoded);
    assert!(url_encoded.is_some());
    let (_, encoded) = url_encoded.unwrap();
    assert!(encoded.contains("%3C"), "< should be encoded to %3C");
    assert!(encoded.contains("%3E"), "> should be encoded to %3E");
    assert!(!encoded.contains('<'));
}

#[test]
fn double_url_encode_applied() {
    let mutations = generate_mutations("<");
    let double_encoded = mutations
        .iter()
        .find(|(t, _)| *t == MutationType::DoubleUrlEncoded);
    assert!(double_encoded.is_some());
    let (_, encoded) = double_encoded.unwrap();
    assert!(encoded.contains("%25"), "% should be encoded again to %25");
}

#[test]
fn unicode_normalization_applied() {
    let mutations = generate_mutations("<script>");
    let unicode = mutations
        .iter()
        .find(|(t, _)| *t == MutationType::UnicodeNormalized);
    assert!(unicode.is_some());
    let (_, normalized) = unicode.unwrap();
    assert!(
        !normalized.contains('<'),
        "< should be replaced with fullwidth variant"
    );
}

#[test]
fn html_entity_encoding_applied() {
    let mutations = generate_mutations("<script>");
    let entity = mutations
        .iter()
        .find(|(t, _)| *t == MutationType::HtmlEntityEncoded);
    assert!(entity.is_some());
    let (_, encoded) = entity.unwrap();
    assert!(encoded.contains("&#60;"), "< should be &#60;");
}

#[test]
fn case_toggle_applied() {
    let mutations = generate_mutations("select");
    let toggled = mutations
        .iter()
        .find(|(t, _)| *t == MutationType::CaseToggled);
    assert!(toggled.is_some());
    let (_, result) = toggled.unwrap();
    assert_ne!(result, "select");
    assert_eq!(result.to_lowercase(), "select");
}

#[test]
fn comment_insertion_applied() {
    let mutations = generate_mutations("SELECT * FROM");
    let commented = mutations
        .iter()
        .find(|(t, _)| *t == MutationType::CommentInserted);
    assert!(commented.is_some());
    let (_, result) = commented.unwrap();
    assert!(result.contains("/**/"), "Should insert SQL-style comments");
}

#[test]
fn json_wrapping_applied() {
    let mutations = generate_mutations("test payload");
    let json = mutations
        .iter()
        .find(|(t, _)| *t == MutationType::JsonWrapped);
    assert!(json.is_some());
    let (_, result) = json.unwrap();
    assert!(result.starts_with('{'));
    assert!(result.contains("value"));
}

#[test]
fn xml_wrapping_applied() {
    let mutations = generate_mutations("test");
    let xml = mutations
        .iter()
        .find(|(t, _)| *t == MutationType::XmlWrapped);
    assert!(xml.is_some());
    let (_, result) = xml.unwrap();
    assert!(result.starts_with("<value>"));
    assert!(result.ends_with("</value>"));
}

#[test]
fn infer_waf_rules_case_sensitive() {
    let probes = vec![
        DifferentialProbe {
            payload: "<script>alert(1)</script>".to_string(),
            mutation: MutationType::Original,
            fingerprint: make_blocked_fingerprint(),
            decision: WafDecision::Blocked,
        },
        DifferentialProbe {
            payload: "<ScRiPt>AlErT(1)</sCrIpT>".to_string(),
            mutation: MutationType::CaseToggled,
            fingerprint: make_baseline_fingerprint(),
            decision: WafDecision::Allowed,
        },
    ];

    let rules = infer_waf_rules(&probes);
    assert!(!rules.is_empty(), "Should infer case-sensitivity rule");

    let case_rule = rules
        .iter()
        .find(|r| r.rule_type == InferredRuleType::StringMatch);
    assert!(case_rule.is_some(), "Should find string match rule");
    assert!(case_rule.unwrap().confidence >= 0.7);
}

#[test]
fn infer_waf_rules_encoding_bypass() {
    let probes = vec![
        DifferentialProbe {
            payload: "<script>".to_string(),
            mutation: MutationType::Original,
            fingerprint: make_blocked_fingerprint(),
            decision: WafDecision::Blocked,
        },
        DifferentialProbe {
            payload: "%3Cscript%3E".to_string(),
            mutation: MutationType::UrlEncoded,
            fingerprint: make_baseline_fingerprint(),
            decision: WafDecision::Allowed,
        },
    ];

    let rules = infer_waf_rules(&probes);
    assert!(!rules.is_empty());

    let enc_rule = rules.iter().find(|r| r.pattern.contains("encoding"));
    assert!(enc_rule.is_some(), "Should infer encoding-unaware rule");
}

#[test]
fn infer_waf_rules_no_rules_when_all_blocked() {
    let probes = vec![
        DifferentialProbe {
            payload: "<script>".to_string(),
            mutation: MutationType::Original,
            fingerprint: make_blocked_fingerprint(),
            decision: WafDecision::Blocked,
        },
        DifferentialProbe {
            payload: "%3Cscript%3E".to_string(),
            mutation: MutationType::UrlEncoded,
            fingerprint: make_blocked_fingerprint(),
            decision: WafDecision::Blocked,
        },
    ];

    let rules = infer_waf_rules(&probes);
    assert!(
        rules.is_empty(),
        "No rules should be inferred when everything is blocked"
    );
}

#[test]
fn analysis_summary_counts() {
    let probes = vec![
        DifferentialProbe {
            payload: "benign".to_string(),
            mutation: MutationType::Baseline,
            fingerprint: make_baseline_fingerprint(),
            decision: WafDecision::Allowed,
        },
        DifferentialProbe {
            payload: "<script>".to_string(),
            mutation: MutationType::Original,
            fingerprint: make_blocked_fingerprint(),
            decision: WafDecision::Blocked,
        },
        DifferentialProbe {
            payload: "%3Cscript%3E".to_string(),
            mutation: MutationType::UrlEncoded,
            fingerprint: make_baseline_fingerprint(),
            decision: WafDecision::Allowed,
        },
    ];

    let summary = generate_analysis_summary(&probes);
    assert_eq!(summary.total_probes, 3);
    assert_eq!(summary.allowed_count, 2);
    assert_eq!(summary.blocked_count, 1);
    assert_eq!(summary.rate_limited_count, 0);
}

#[test]
fn analysis_summary_waf_strictness() {
    let probes = vec![
        DifferentialProbe {
            payload: "a".to_string(),
            mutation: MutationType::Original,
            fingerprint: make_blocked_fingerprint(),
            decision: WafDecision::Blocked,
        },
        DifferentialProbe {
            payload: "b".to_string(),
            mutation: MutationType::UrlEncoded,
            fingerprint: make_blocked_fingerprint(),
            decision: WafDecision::Blocked,
        },
        DifferentialProbe {
            payload: "c".to_string(),
            mutation: MutationType::CaseToggled,
            fingerprint: make_baseline_fingerprint(),
            decision: WafDecision::Allowed,
        },
    ];

    let summary = generate_analysis_summary(&probes);
    assert!(
        (summary.waf_strictness - 0.6667).abs() < 0.01,
        "2 blocked out of 3 = 0.667"
    );
}

#[test]
fn analysis_summary_bypass_mutations_listed() {
    let probes = vec![
        DifferentialProbe {
            payload: "<script>".to_string(),
            mutation: MutationType::Original,
            fingerprint: make_blocked_fingerprint(),
            decision: WafDecision::Blocked,
        },
        DifferentialProbe {
            payload: "%3Cscript%3E".to_string(),
            mutation: MutationType::UrlEncoded,
            fingerprint: make_baseline_fingerprint(),
            decision: WafDecision::Allowed,
        },
        DifferentialProbe {
            payload: "<ScRiPt>".to_string(),
            mutation: MutationType::CaseToggled,
            fingerprint: make_baseline_fingerprint(),
            decision: WafDecision::Allowed,
        },
    ];

    let summary = generate_analysis_summary(&probes);
    assert!(summary
        .bypass_mutations
        .contains(&"url_encoded".to_string()));
    assert!(summary
        .bypass_mutations
        .contains(&"case_toggled".to_string()));
}

#[test]
fn waf_decision_display() {
    assert_eq!(WafDecision::Allowed.to_string(), "ALLOWED");
    assert_eq!(WafDecision::Blocked.to_string(), "BLOCKED");
    assert_eq!(WafDecision::RateLimited.to_string(), "RATE_LIMITED");
    assert_eq!(WafDecision::Challenged.to_string(), "CHALLENGED");
    assert_eq!(WafDecision::Unknown.to_string(), "UNKNOWN");
}

#[test]
fn mutation_type_display() {
    assert_eq!(MutationType::Baseline.to_string(), "baseline");
    assert_eq!(MutationType::Original.to_string(), "original");
    assert_eq!(MutationType::UrlEncoded.to_string(), "url_encoded");
    assert_eq!(
        MutationType::DoubleUrlEncoded.to_string(),
        "double_url_encoded"
    );
    assert_eq!(
        MutationType::Custom("test".to_string()).to_string(),
        "custom:test"
    );
}

#[test]
fn inferred_rule_type_display() {
    assert_eq!(InferredRuleType::StringMatch.to_string(), "string_match");
    assert_eq!(InferredRuleType::RegexPattern.to_string(), "regex_pattern");
    assert_eq!(
        InferredRuleType::EncodingAware.to_string(),
        "encoding_aware"
    );
}

#[test]
fn fragment_appended_mutation() {
    let mutations = generate_mutations("test");
    let fragment = mutations
        .iter()
        .find(|(t, _)| *t == MutationType::FragmentAppended);
    assert!(fragment.is_some());
    let (_, result) = fragment.unwrap();
    assert!(result.ends_with("#fragment"));
}

#[test]
fn null_byte_insertion() {
    let mutations = generate_mutations("test payload here");
    let null_byte = mutations
        .iter()
        .find(|(t, _)| *t == MutationType::NullByteInserted);
    assert!(null_byte.is_some());
    let (_, result) = null_byte.unwrap();
    assert!(result.contains("%00"));
}

#[test]
fn body_snippet_truncated() {
    let long_body = "x".repeat(500);
    let fp = ResponseFingerprint::from_response(200, &[], &long_body, 10.0);
    assert_eq!(
        fp.body_snippet.len(),
        200,
        "Snippet should be truncated to 200 chars"
    );
    assert_eq!(fp.body_length, 500, "Body length should reflect full body");
}
