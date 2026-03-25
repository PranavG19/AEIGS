use super::waf_rule_reverser::*;

fn blocked_probe(payload: &str) -> WafProbe {
    WafProbe {
        payload: payload.to_string(),
        outcome: ProbeOutcome::Blocked,
        encoding: None,
        status_code: 403,
    }
}

fn allowed_probe(payload: &str) -> WafProbe {
    WafProbe {
        payload: payload.to_string(),
        outcome: ProbeOutcome::Allowed,
        encoding: None,
        status_code: 200,
    }
}

#[test]
fn test_record_probes() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probe(blocked_probe("SELECT * FROM users"));
    reverser.record_probe(allowed_probe("hello world"));
    assert_eq!(reverser.probe_count(), 2);
    assert_eq!(reverser.blocked_count(), 1);
    assert_eq!(reverser.allowed_count(), 1);
}

#[test]
fn test_record_probes_batch() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probes(vec![
        blocked_probe("SELECT 1"),
        blocked_probe("UNION SELECT"),
        allowed_probe("normal text"),
    ]);
    assert_eq!(reverser.probe_count(), 3);
    assert_eq!(reverser.blocked_count(), 2);
}

#[test]
fn test_binary_search_trigger() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probe(blocked_probe("SELECT * FROM users WHERE id=1"));
    reverser.record_probe(blocked_probe("SELECT"));
    reverser.record_probe(allowed_probe("hello"));

    let result = reverser.binary_search_trigger("SELECT * FROM users WHERE id=1");
    assert!(!result.minimal_trigger.is_empty());
    assert!(result.minimal_trigger.len() <= "SELECT * FROM users WHERE id=1".len());
}

#[test]
fn test_binary_search_single_char() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probe(blocked_probe("<"));
    let result = reverser.binary_search_trigger("<");
    assert_eq!(result.minimal_trigger, "<");
    assert_eq!(result.search_steps, 0);
}

#[test]
fn test_binary_search_caching() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probe(blocked_probe("<script>"));

    let result1 = reverser.binary_search_trigger("<script>");
    let result2 = reverser.binary_search_trigger("<script>");
    assert_eq!(result1.minimal_trigger, result2.minimal_trigger);
    assert_eq!(result1.search_steps, result2.search_steps);
}

#[test]
fn test_char_substitutions_angle_bracket() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probe(blocked_probe("<script>"));

    let result = reverser.probe_char_substitutions('<');
    assert_eq!(result.original, '<');
    assert!(!result.substitutions.is_empty());
}

#[test]
fn test_char_substitutions_quote() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probe(blocked_probe("' OR 1=1"));

    let result = reverser.probe_char_substitutions('\'');
    assert_eq!(result.original, '\'');
    assert!(!result.substitutions.is_empty());
}

#[test]
fn test_char_substitution_caching() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probe(blocked_probe("<"));

    let result1 = reverser.probe_char_substitutions('<');
    let result2 = reverser.probe_char_substitutions('<');
    assert_eq!(result1.original, result2.original);
    assert_eq!(
        result1.effective_bypasses.len(),
        result2.effective_bypasses.len()
    );
}

#[test]
fn test_discover_bypass_encodings() {
    let reverser = WafRuleReverser::new();
    let results = reverser.discover_bypass_encodings("<script>alert(1)</script>");
    assert_eq!(results.len(), 8);
    let encoding_names: Vec<&str> = results.iter().map(|r| r.encoding.as_str()).collect();
    assert!(encoding_names.contains(&"url"));
    assert!(encoding_names.contains(&"double-url"));
    assert!(encoding_names.contains(&"unicode"));
    assert!(encoding_names.contains(&"html-entity"));
    assert!(encoding_names.contains(&"hex"));
    assert!(encoding_names.contains(&"octal"));
    assert!(encoding_names.contains(&"overlong-utf8"));
    assert!(encoding_names.contains(&"base64"));
}

#[test]
fn test_discover_encodings_bypass_when_not_blocked() {
    let reverser = WafRuleReverser::new();
    let results = reverser.discover_bypass_encodings("test");
    for r in &results {
        assert!(
            r.bypasses_waf,
            "Encoded payload should bypass since nothing is blocked"
        );
    }
}

#[test]
fn test_combination_testing() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probe(blocked_probe("SELECT"));
    reverser.record_probe(blocked_probe("UNION"));
    reverser.record_probe(allowed_probe("hello"));

    let payloads = vec!["SELECT".to_string(), "UNION".to_string()];
    let results = reverser.test_combinations(&payloads);
    assert_eq!(results.len(), 1);
    assert!(results[0].a_blocked);
    assert!(results[0].b_blocked);
}

#[test]
fn test_combination_bypass_detection() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probe(blocked_probe("payload_a"));
    reverser.record_probe(allowed_probe("payload_apayload_b"));

    let payloads = vec!["payload_a".to_string(), "payload_b".to_string()];
    let results = reverser.test_combinations(&payloads);
    assert_eq!(results.len(), 1);
    assert!(results[0].a_blocked);
    assert!(!results[0].b_blocked);
}

#[test]
fn test_analyze_sqli_rules() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probes(vec![
        blocked_probe("SELECT * FROM users"),
        blocked_probe("UNION SELECT 1,2,3"),
        blocked_probe("DROP TABLE users"),
        allowed_probe("hello world"),
        allowed_probe("normal query"),
    ]);

    let rules = reverser.analyze();
    assert!(!rules.is_empty());
    let rule = &rules[0];
    assert!(!rule.trigger_tokens.is_empty());
    assert_eq!(rule.rule_pattern, "sqli-keyword-filter");
    assert!(rule.confidence > 0.0);
}

#[test]
fn test_analyze_xss_rules() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probes(vec![
        blocked_probe("<script>alert(1)</script>"),
        blocked_probe("<img onerror=alert(1)>"),
        allowed_probe("normal text"),
    ]);

    let rules = reverser.analyze();
    assert!(!rules.is_empty());
    assert_eq!(rules[0].rule_pattern, "xss-tag-filter");
}

#[test]
fn test_analyze_empty_probes() {
    let mut reverser = WafRuleReverser::new();
    let rules = reverser.analyze();
    assert!(rules.is_empty());
}

#[test]
fn test_analyze_no_blocked() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probe(allowed_probe("test"));
    let rules = reverser.analyze();
    assert!(rules.is_empty());
}

#[test]
fn test_analyze_command_injection_pattern() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probes(vec![
        blocked_probe("; cat /etc/passwd"),
        blocked_probe("| ls -la"),
        allowed_probe("safe input"),
    ]);

    let rules = reverser.analyze();
    assert!(!rules.is_empty());
    assert_eq!(rules[0].rule_pattern, "command-injection-filter");
}

#[test]
fn test_analyze_path_traversal_pattern() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probes(vec![
        blocked_probe("../../etc/passwd"),
        blocked_probe("../../../etc/shadow"),
        allowed_probe("index.html"),
    ]);

    let rules = reverser.analyze();
    assert!(!rules.is_empty());
    assert_eq!(rules[0].rule_pattern, "path-traversal-filter");
}

#[test]
fn test_analyze_blocked_chars_extracted() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probes(vec![blocked_probe("<script>"), allowed_probe("safe text")]);

    let rules = reverser.analyze();
    assert!(!rules.is_empty());
    assert!(
        rules[0].blocked_chars.contains(&'<') || rules[0].blocked_chars.contains(&'>'),
        "Should detect angle brackets as blocked chars"
    );
}

#[test]
fn test_analyze_confidence_range() {
    let mut reverser = WafRuleReverser::new();
    for i in 0..15 {
        reverser.record_probe(blocked_probe(&format!("SELECT {}", i)));
    }
    for i in 0..5 {
        reverser.record_probe(allowed_probe(&format!("safe {}", i)));
    }

    let rules = reverser.analyze();
    assert!(!rules.is_empty());
    assert!(rules[0].confidence > 0.0);
    assert!(rules[0].confidence <= 1.0);
}

#[test]
fn test_probe_outcome_variants() {
    let probes = vec![
        WafProbe {
            payload: "test".to_string(),
            outcome: ProbeOutcome::Blocked,
            encoding: None,
            status_code: 403,
        },
        WafProbe {
            payload: "test".to_string(),
            outcome: ProbeOutcome::Allowed,
            encoding: None,
            status_code: 200,
        },
        WafProbe {
            payload: "test".to_string(),
            outcome: ProbeOutcome::RateLimited,
            encoding: None,
            status_code: 429,
        },
        WafProbe {
            payload: "test".to_string(),
            outcome: ProbeOutcome::Error,
            encoding: None,
            status_code: 500,
        },
    ];

    let mut reverser = WafRuleReverser::new();
    reverser.record_probes(probes);
    assert_eq!(reverser.probe_count(), 4);
}

#[test]
fn test_combination_with_three_payloads() {
    let mut reverser = WafRuleReverser::new();
    reverser.record_probes(vec![
        blocked_probe("A"),
        blocked_probe("B"),
        blocked_probe("C"),
    ]);

    let payloads = vec!["A".to_string(), "B".to_string(), "C".to_string()];
    let results = reverser.test_combinations(&payloads);
    assert_eq!(results.len(), 3);
}
