use super::*;

fn blocked(payload: &str, strategy: ProbeStrategy) -> ProbeResult {
    ProbeResult {
        payload: payload.to_string(),
        blocked: true,
        status_code: Some(403),
        strategy,
    }
}

fn allowed(payload: &str, strategy: ProbeStrategy) -> ProbeResult {
    ProbeResult {
        payload: payload.to_string(),
        blocked: false,
        status_code: Some(200),
        strategy,
    }
}

struct MockWaf {
    rules: Vec<regex::Regex>,
}

impl MockWaf {
    fn new(patterns: &[&str]) -> Self {
        Self {
            rules: patterns
                .iter()
                .map(|p| regex::Regex::new(p).unwrap())
                .collect(),
        }
    }

    fn probe(&self, payload: &str, strategy: ProbeStrategy) -> ProbeResult {
        let is_blocked = self.rules.iter().any(|r| r.is_match(payload));
        ProbeResult {
            payload: payload.to_string(),
            blocked: is_blocked,
            status_code: Some(if is_blocked { 403 } else { 200 }),
            strategy,
        }
    }
}

#[test]
fn empty_probes_returns_empty_grammar() {
    let engine = WafGrammarInference::new();
    let grammar = engine.infer_grammar(&[]);
    assert!(grammar.rules.is_empty());
    assert_eq!(grammar.probe_count, 0);
    assert_eq!(grammar.false_positive_rate, 0.0);
}

#[test]
fn single_sqli_rule_recovered() {
    let engine = WafGrammarInference::new();
    let probes = vec![
        blocked("' OR 1=1--", ProbeStrategy::BinarySearch),
        blocked("' OR 'a'='a", ProbeStrategy::BinarySearch),
        blocked("admin' OR 1=1", ProbeStrategy::CharSubstitution),
        allowed("normal input", ProbeStrategy::BinarySearch),
        allowed("hello world", ProbeStrategy::BinarySearch),
    ];
    let grammar = engine.infer_grammar(&probes);
    assert!(!grammar.rules.is_empty());
    assert_eq!(grammar.probe_count, 5);
}

#[test]
fn xss_rule_recovered() {
    let engine = WafGrammarInference::new();
    let probes = vec![
        blocked("<script>alert(1)</script>", ProbeStrategy::BinarySearch),
        blocked(
            "<script>document.cookie</script>",
            ProbeStrategy::BinarySearch,
        ),
        blocked("<img onerror=alert(1)>", ProbeStrategy::CharSubstitution),
        allowed("<b>bold text</b>", ProbeStrategy::BinarySearch),
        allowed("normal text", ProbeStrategy::BinarySearch),
    ];
    let grammar = engine.infer_grammar(&probes);
    assert!(!grammar.rules.is_empty());
    let xss_rule = grammar.rules.iter().find(|r| r.pattern.starts_with("xss:"));
    assert!(xss_rule.is_some());
}

#[test]
fn command_injection_rule_recovered() {
    let engine = WafGrammarInference::new();
    let probes = vec![
        blocked("; cat /etc/passwd", ProbeStrategy::BinarySearch),
        blocked("; ls -la", ProbeStrategy::BinarySearch),
        blocked("| whoami", ProbeStrategy::CharSubstitution),
        allowed("normal; fine", ProbeStrategy::BinarySearch),
    ];
    let grammar = engine.infer_grammar(&probes);
    assert!(!grammar.rules.is_empty());
}

#[test]
fn path_traversal_rule_recovered() {
    let engine = WafGrammarInference::new();
    let probes = vec![
        blocked("../../etc/passwd", ProbeStrategy::BinarySearch),
        blocked("../../../etc/shadow", ProbeStrategy::BinarySearch),
        blocked("%2e%2e/etc/hosts", ProbeStrategy::EncodingLadder),
        allowed("/valid/path", ProbeStrategy::BinarySearch),
    ];
    let grammar = engine.infer_grammar(&probes);
    let path_rule = grammar
        .rules
        .iter()
        .find(|r| r.pattern.starts_with("path:"));
    assert!(path_rule.is_some());
}

#[test]
fn multiple_rules_recovered_from_mixed_probes() {
    let engine = WafGrammarInference::new();
    let probes = vec![
        blocked("' OR 1=1--", ProbeStrategy::BinarySearch),
        blocked("<script>alert(1)</script>", ProbeStrategy::BinarySearch),
        blocked("; cat /etc/passwd", ProbeStrategy::BinarySearch),
        blocked("../../etc/passwd", ProbeStrategy::BinarySearch),
        allowed("safe input", ProbeStrategy::BinarySearch),
        allowed("another safe one", ProbeStrategy::BinarySearch),
    ];
    let grammar = engine.infer_grammar(&probes);
    assert!(grammar.rules.len() >= 3);
}

#[test]
fn confidence_increases_with_more_samples() {
    let engine = WafGrammarInference::new();

    let few = vec![
        blocked("' OR 1=1--", ProbeStrategy::BinarySearch),
        allowed("safe", ProbeStrategy::BinarySearch),
        allowed("safe2", ProbeStrategy::BinarySearch),
        allowed("safe3", ProbeStrategy::BinarySearch),
        allowed("safe4", ProbeStrategy::BinarySearch),
        allowed("safe5", ProbeStrategy::BinarySearch),
        allowed("safe6", ProbeStrategy::BinarySearch),
        allowed("safe7", ProbeStrategy::BinarySearch),
        allowed("safe8", ProbeStrategy::BinarySearch),
        allowed("safe9", ProbeStrategy::BinarySearch),
    ];
    let grammar_few = engine.infer_grammar(&few);

    let many = vec![
        blocked("' OR 1=1--", ProbeStrategy::BinarySearch),
        blocked("' OR 'a'='a", ProbeStrategy::BinarySearch),
        blocked("admin' OR 1=1", ProbeStrategy::CharSubstitution),
        blocked("UNION SELECT NULL", ProbeStrategy::BinarySearch),
        blocked("1; DROP TABLE--", ProbeStrategy::BinarySearch),
        allowed("safe", ProbeStrategy::BinarySearch),
        allowed("safe2", ProbeStrategy::BinarySearch),
        allowed("safe3", ProbeStrategy::BinarySearch),
        allowed("safe4", ProbeStrategy::BinarySearch),
        allowed("safe5", ProbeStrategy::BinarySearch),
    ];
    let grammar_many = engine.infer_grammar(&many);

    let max_few = grammar_few
        .rules
        .iter()
        .map(|r| r.confidence)
        .fold(0.0_f64, f64::max);
    let max_many = grammar_many
        .rules
        .iter()
        .map(|r| r.confidence)
        .fold(0.0_f64, f64::max);

    assert!(max_many >= max_few);
}

#[test]
fn generate_bypass_produces_candidates_for_sqli() {
    let engine = WafGrammarInference::new();
    let probes = vec![
        blocked("' OR 1=1--", ProbeStrategy::BinarySearch),
        blocked("' OR 'a'='a", ProbeStrategy::BinarySearch),
        allowed("safe input", ProbeStrategy::BinarySearch),
    ];
    let grammar = engine.infer_grammar(&probes);
    let bypasses = engine.generate_bypass(&grammar, "' OR 1=1--");
    assert!(!bypasses.is_empty());
    assert!(bypasses.len() > 1);
}

#[test]
fn generate_bypass_for_xss() {
    let engine = WafGrammarInference::new();
    let probes = vec![
        blocked("<script>alert(1)</script>", ProbeStrategy::BinarySearch),
        blocked("<script>x</script>", ProbeStrategy::BinarySearch),
        allowed("no tags here", ProbeStrategy::BinarySearch),
    ];
    let grammar = engine.infer_grammar(&probes);
    let bypasses = engine.generate_bypass(&grammar, "<script>alert(1)</script>");
    assert!(bypasses.len() > 1);
}

#[test]
fn bypass_for_clean_payload_returns_self() {
    let engine = WafGrammarInference::new();
    let grammar = WafGrammar {
        rules: vec![InferredWafRule {
            pattern: "sqli:select".to_string(),
            confidence: 0.9,
            blocked_samples: vec!["select * from users".to_string()],
            allowed_samples: Vec::new(),
            boundary_chars: vec!['*', ' '],
        }],
        probe_count: 1,
        false_positive_rate: 0.0,
    };
    let bypasses = engine.generate_bypass(&grammar, "totally clean input");
    assert_eq!(bypasses, vec!["totally clean input"]);
}

#[test]
fn suggest_next_probe_for_low_confidence_rule() {
    let engine = WafGrammarInference::new();
    let grammar = WafGrammar {
        rules: vec![InferredWafRule {
            pattern: "sqli:union".to_string(),
            confidence: 0.4,
            blocked_samples: vec!["UNION SELECT".to_string()],
            allowed_samples: Vec::new(),
            boundary_chars: vec![' ', '('],
        }],
        probe_count: 5,
        false_positive_rate: 0.0,
    };
    let suggestions = engine.suggest_next_probe(&grammar);
    assert!(!suggestions.is_empty());
}

#[test]
fn suggest_next_probe_includes_exploration_for_missing_categories() {
    let engine = WafGrammarInference::new();
    let grammar = WafGrammar {
        rules: vec![InferredWafRule {
            pattern: "sqli:select".to_string(),
            confidence: 0.9,
            blocked_samples: vec!["SELECT * FROM".to_string()],
            allowed_samples: Vec::new(),
            boundary_chars: vec!['*'],
        }],
        probe_count: 10,
        false_positive_rate: 0.0,
    };
    let suggestions = engine.suggest_next_probe(&grammar);
    let has_xss = suggestions
        .iter()
        .any(|s| s.contains("script") || s.contains("onerror"));
    let has_cmdi = suggestions
        .iter()
        .any(|s| s.contains("cat") || s.contains("whoami"));
    assert!(has_xss);
    assert!(has_cmdi);
}

#[test]
fn false_positive_rate_computed_correctly() {
    let engine = WafGrammarInference::new();
    let probes = vec![
        blocked("' OR 1=1--", ProbeStrategy::BinarySearch),
        blocked("random gibberish blocked", ProbeStrategy::BinarySearch),
        allowed("safe", ProbeStrategy::BinarySearch),
    ];
    let grammar = engine.infer_grammar(&probes);
    assert!(grammar.false_positive_rate >= 0.0);
    assert!(grammar.false_positive_rate <= 1.0);
}

#[test]
fn probe_strategy_display_all_variants() {
    let strategies = [
        ProbeStrategy::BinarySearch,
        ProbeStrategy::CharSubstitution,
        ProbeStrategy::EncodingLadder,
        ProbeStrategy::CaseMutation,
        ProbeStrategy::NullByteInsertion,
        ProbeStrategy::WhitespaceProbing,
        ProbeStrategy::CommentInjection,
        ProbeStrategy::TokenSplitting,
    ];
    for s in &strategies {
        let display = format!("{s}");
        assert!(!display.is_empty());
    }
    assert_eq!(strategies.len(), 8);
}

#[test]
fn config_builder_pattern() {
    let config = InferenceConfig::default()
        .with_min_confidence(0.5)
        .with_max_probes(100)
        .with_dedup_threshold(0.9);
    assert_eq!(config.min_confidence, 0.5);
    assert_eq!(config.max_probes, 100);
    assert_eq!(config.dedup_threshold, 0.9);
}

#[test]
fn config_clamps_confidence() {
    let config = InferenceConfig::default().with_min_confidence(2.0);
    assert_eq!(config.min_confidence, 1.0);

    let config = InferenceConfig::default().with_min_confidence(-1.0);
    assert_eq!(config.min_confidence, 0.0);
}

#[test]
fn engine_with_custom_config() {
    let config = InferenceConfig::default().with_min_confidence(0.8);
    let engine = WafGrammarInference::new().with_config(config);
    let probes = vec![
        blocked("' OR 1=1--", ProbeStrategy::BinarySearch),
        allowed("safe", ProbeStrategy::BinarySearch),
        allowed("safe2", ProbeStrategy::BinarySearch),
        allowed("safe3", ProbeStrategy::BinarySearch),
        allowed("safe4", ProbeStrategy::BinarySearch),
        allowed("safe5", ProbeStrategy::BinarySearch),
        allowed("safe6", ProbeStrategy::BinarySearch),
        allowed("safe7", ProbeStrategy::BinarySearch),
        allowed("safe8", ProbeStrategy::BinarySearch),
        allowed("safe9", ProbeStrategy::BinarySearch),
    ];
    let grammar = engine.infer_grammar(&probes);
    for rule in &grammar.rules {
        assert!(rule.confidence >= 0.8);
    }
}

#[test]
fn grammar_serializable() {
    let grammar = WafGrammar {
        rules: vec![InferredWafRule {
            pattern: "sqli:select".to_string(),
            confidence: 0.85,
            blocked_samples: vec!["SELECT * FROM users".to_string()],
            allowed_samples: vec!["safe query".to_string()],
            boundary_chars: vec!['*', ' '],
        }],
        probe_count: 10,
        false_positive_rate: 0.05,
    };
    let json = serde_json::to_string(&grammar).unwrap();
    let deserialized: WafGrammar = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.rules.len(), 1);
    assert_eq!(deserialized.probe_count, 10);
}

#[test]
fn extract_trigger_pattern_sqli() {
    let pattern = extract_trigger_pattern("' OR 1=1--");
    assert!(pattern.starts_with("sqli:"));
}

#[test]
fn extract_trigger_pattern_xss() {
    let pattern = extract_trigger_pattern("<script>alert(1)</script>");
    assert!(pattern.starts_with("xss:"));
}

#[test]
fn extract_trigger_pattern_cmdi() {
    let pattern = extract_trigger_pattern("; cat /etc/passwd");
    assert!(pattern.starts_with("cmdi:"));
}

#[test]
fn extract_trigger_pattern_path() {
    let pattern = extract_trigger_pattern("../../etc/passwd");
    assert!(pattern.starts_with("path:"));
}

#[test]
fn extract_trigger_pattern_unknown() {
    let pattern = extract_trigger_pattern("abcdefghij");
    assert!(pattern.starts_with("unknown:"));
}

#[test]
fn boundary_chars_extracted_from_blocked_and_allowed() {
    let blocked_samples = vec!["<script>".to_string(), "<img src=x>".to_string()];
    let allowed_samples = vec!["safe text".to_string()];
    let chars = extract_boundary_chars(&blocked_samples, &allowed_samples);
    assert!(!chars.is_empty());
}

#[test]
fn dedup_rules_removes_similar() {
    let rules = vec![
        InferredWafRule {
            pattern: "sqli:select".to_string(),
            confidence: 0.9,
            blocked_samples: vec!["SELECT * FROM".to_string()],
            allowed_samples: Vec::new(),
            boundary_chars: Vec::new(),
        },
        InferredWafRule {
            pattern: "sqli:select".to_string(),
            confidence: 0.5,
            blocked_samples: vec!["select from".to_string()],
            allowed_samples: Vec::new(),
            boundary_chars: Vec::new(),
        },
    ];
    let deduped = dedup_rules(rules, 0.8);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].confidence, 0.9);
}

#[test]
fn mock_waf_recovers_most_rules() {
    let waf = MockWaf::new(&[
        r"(?i)union\s+select",
        r"(?i)<script",
        r"(?i)onerror\s*=",
        r"\.\./",
        r";\s*(cat|ls|whoami)",
    ]);

    let test_payloads = vec![
        ("UNION SELECT NULL", ProbeStrategy::BinarySearch),
        ("union select 1,2,3", ProbeStrategy::CaseMutation),
        ("UNion SElect", ProbeStrategy::CaseMutation),
        ("<script>alert(1)</script>", ProbeStrategy::BinarySearch),
        ("<SCRIPT>x</SCRIPT>", ProbeStrategy::CaseMutation),
        ("<ScRiPt>", ProbeStrategy::CaseMutation),
        ("onerror = alert(1)", ProbeStrategy::BinarySearch),
        ("onerror=alert(1)", ProbeStrategy::CharSubstitution),
        ("../../etc/passwd", ProbeStrategy::BinarySearch),
        ("../../../etc/shadow", ProbeStrategy::BinarySearch),
        ("%2e%2e/test", ProbeStrategy::EncodingLadder),
        ("; cat /etc/passwd", ProbeStrategy::BinarySearch),
        ("; whoami", ProbeStrategy::BinarySearch),
        ("; ls -la /", ProbeStrategy::BinarySearch),
        ("safe input text", ProbeStrategy::BinarySearch),
        ("normal query", ProbeStrategy::BinarySearch),
        ("hello world", ProbeStrategy::BinarySearch),
        ("just a number 42", ProbeStrategy::BinarySearch),
        ("/valid/path/here", ProbeStrategy::BinarySearch),
        ("benign html <b>bold</b>", ProbeStrategy::BinarySearch),
    ];

    let probes: Vec<ProbeResult> = test_payloads
        .iter()
        .map(|(payload, strategy)| waf.probe(payload, *strategy))
        .collect();

    let engine = WafGrammarInference::new();
    let grammar = engine.infer_grammar(&probes);

    assert!(grammar.rules.len() >= 3);
    assert!(grammar.probe_count <= 200);

    let categories: HashSet<&str> = grammar
        .rules
        .iter()
        .filter_map(|r| r.pattern.split(':').next())
        .collect();
    assert!(categories.len() >= 3);
}

#[test]
fn mock_waf_bypass_generation() {
    let waf = MockWaf::new(&[r"(?i)union\s+select", r"(?i)<script"]);

    let probes: Vec<ProbeResult> = vec![
        waf.probe("UNION SELECT NULL", ProbeStrategy::BinarySearch),
        waf.probe("<script>alert(1)</script>", ProbeStrategy::BinarySearch),
        waf.probe("safe input", ProbeStrategy::BinarySearch),
    ];

    let engine = WafGrammarInference::new();
    let grammar = engine.infer_grammar(&probes);

    for rule in &grammar.rules {
        let sample = rule.blocked_samples.first().unwrap();
        let bypasses = engine.generate_bypass(&grammar, sample);
        assert!(
            !bypasses.is_empty(),
            "no bypass generated for rule: {}",
            rule.pattern
        );
    }
}

#[test]
fn encoding_ladder_produces_variants() {
    let results = apply_encoding_ladder("' or 1=1--", "sqli:' or");
    assert!(results.len() >= 3);
    let has_encoded = results.iter().any(|r| r != "' or 1=1--");
    assert!(has_encoded);
}

#[test]
fn case_mutation_produces_variants() {
    let results = apply_case_mutations("select * from users", "sqli:select");
    assert!(!results.is_empty());
    let has_upper = results.iter().any(|r| r.contains("SELECT"));
    assert!(has_upper);
}

#[test]
fn comment_injection_produces_variants() {
    let results = apply_comment_injection("union select null", "sqli:union");
    assert!(!results.is_empty());
    let has_comment = results.iter().any(|r| r.contains("/*"));
    assert!(has_comment);
}

#[test]
fn null_byte_insertion_produces_variants() {
    let results = apply_null_byte_insertion("<script>alert(1)</script>", "xss:<script");
    assert!(!results.is_empty());
}

#[test]
fn token_splitting_produces_variants() {
    let results = apply_token_splitting("UNION SELECT NULL", "sqli:union");
    assert!(!results.is_empty());
    assert!(results.len() >= 2);
}

#[test]
fn whitespace_probing_produces_variants() {
    let results = apply_whitespace_insertion("UNION SELECT", "sqli:union");
    assert!(!results.is_empty());
}

#[test]
fn char_substitution_with_homoglyphs() {
    let results = apply_char_substitution("<script>alert(1)</script>", &['<', '>', '(', ')']);
    assert!(!results.is_empty());
    let has_homoglyph = results.iter().any(|r| r != "<script>alert(1)</script>");
    assert!(has_homoglyph);
}

#[test]
fn default_engine_works() {
    let engine = WafGrammarInference::default();
    let grammar = engine.infer_grammar(&[]);
    assert!(grammar.rules.is_empty());
}

#[test]
fn all_probes_allowed_no_rules() {
    let engine = WafGrammarInference::new();
    let probes = vec![
        allowed("safe1", ProbeStrategy::BinarySearch),
        allowed("safe2", ProbeStrategy::BinarySearch),
        allowed("safe3", ProbeStrategy::BinarySearch),
    ];
    let grammar = engine.infer_grammar(&probes);
    assert!(grammar.rules.is_empty());
    assert_eq!(grammar.false_positive_rate, 0.0);
}

#[test]
fn rules_sorted_by_confidence_descending() {
    let engine = WafGrammarInference::new();
    let probes = vec![
        blocked("' OR 1=1--", ProbeStrategy::BinarySearch),
        blocked("<script>alert(1)</script>", ProbeStrategy::BinarySearch),
        blocked("<script>x</script>", ProbeStrategy::BinarySearch),
        blocked("<img onerror=alert(1)>", ProbeStrategy::BinarySearch),
        allowed("safe", ProbeStrategy::BinarySearch),
    ];
    let grammar = engine.infer_grammar(&probes);
    for window in grammar.rules.windows(2) {
        assert!(window[0].confidence >= window[1].confidence);
    }
}
