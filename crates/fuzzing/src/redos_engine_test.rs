use super::redos_engine::*;

#[test]
fn all_patterns_returns_ten() {
    assert_eq!(RedosVulnPattern::all().len(), 10);
}

#[test]
fn each_pattern_has_nonzero_severity() {
    for p in RedosVulnPattern::all() {
        assert!(p.severity() > 0.0, "{p} has zero severity");
    }
}

#[test]
fn each_pattern_has_example_regex() {
    for p in RedosVulnPattern::all() {
        let re = p.example_regex();
        assert!(!re.is_empty(), "{p} has empty example regex");
    }
}

#[test]
fn each_pattern_has_description() {
    for p in RedosVulnPattern::all() {
        assert!(!p.description().is_empty(), "{p} missing description");
    }
}

#[test]
fn pattern_display_is_kebab_case() {
    for p in RedosVulnPattern::all() {
        let display = format!("{p}");
        assert!(
            display.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
            "Display '{display}' is not kebab-case"
        );
    }
}

#[test]
fn generate_payloads_returns_at_least_ten() {
    let engine = RedosEngine::new();
    let payloads = engine.generate_payloads();
    assert!(
        payloads.len() >= 10,
        "Expected >=10 payloads, got {}",
        payloads.len()
    );
}

#[test]
fn payload_evil_strings_are_nonempty() {
    let engine = RedosEngine::new();
    for payload in engine.generate_payloads() {
        assert!(
            !payload.evil_string.is_empty(),
            "Empty evil string for {}",
            payload.pattern
        );
    }
}

#[test]
fn payload_target_regexes_are_nonempty() {
    let engine = RedosEngine::new();
    for payload in engine.generate_payloads() {
        assert!(
            !payload.target_regex.is_empty(),
            "Empty target regex for {}",
            payload.pattern
        );
    }
}

#[test]
fn analyze_nested_quantifier_regex() {
    let engine = RedosEngine::new();
    let result = engine.analyze_regex(r"(a+)+$");
    assert!(result.vulnerable);
    assert!(result
        .matched_patterns
        .contains(&RedosVulnPattern::NestedQuantifiers));
    assert!(result.estimated_severity >= 7.0);
}

#[test]
fn analyze_star_height_regex() {
    let engine = RedosEngine::new();
    let result = engine.analyze_regex(r"(a*)*$");
    assert!(result.vulnerable);
    assert!(result
        .matched_patterns
        .contains(&RedosVulnPattern::StarHeight));
}

#[test]
fn analyze_overlapping_alternation() {
    let engine = RedosEngine::new();
    let result = engine.analyze_regex(r"(a|a)+$");
    assert!(result.vulnerable);
    assert!(result
        .matched_patterns
        .contains(&RedosVulnPattern::OverlappingAlternation));
}

#[test]
fn analyze_safe_regex_not_vulnerable() {
    let engine = RedosEngine::new();
    let result = engine.analyze_regex(r"^[a-z]+$");
    assert!(!result.vulnerable);
    assert!(result.matched_patterns.is_empty());
    assert_eq!(result.estimated_severity, 0.0);
}

#[test]
fn analyze_empty_regex() {
    let engine = RedosEngine::new();
    let result = engine.analyze_regex("");
    assert!(!result.vulnerable);
}

#[test]
fn analyze_unbounded_repetition() {
    let engine = RedosEngine::new();
    let result = engine.analyze_regex(r"(.*a){10}");
    assert!(result.vulnerable);
    assert!(result
        .matched_patterns
        .contains(&RedosVulnPattern::UnboundedRepetitionAmbiguous));
}

#[test]
fn analyze_backreference_quantifier() {
    let engine = RedosEngine::new();
    let result = engine.analyze_regex(r"(a+)\1+$");
    assert!(result.vulnerable);
    assert!(result
        .matched_patterns
        .contains(&RedosVulnPattern::BackreferenceWithQuantifier));
}

#[test]
fn analyze_lazy_inside_greedy() {
    let engine = RedosEngine::new();
    let result = engine.analyze_regex(r"(a+?)*$");
    assert!(result.vulnerable);
    assert!(result
        .matched_patterns
        .contains(&RedosVulnPattern::LazyInsideGreedy));
}

#[test]
fn analyze_overlapping_char_classes() {
    let engine = RedosEngine::new();
    let result = engine.analyze_regex(r"([a-zA-Z]+)*$");
    assert!(result.vulnerable);
    assert!(result
        .matched_patterns
        .contains(&RedosVulnPattern::OverlappingCharacterClasses));
}

#[test]
fn analyze_recursive_group() {
    let engine = RedosEngine::new();
    let result = engine.analyze_regex(r"((a+b)+c)+$");
    assert!(result.vulnerable);
    assert!(result
        .matched_patterns
        .contains(&RedosVulnPattern::RecursiveGroupRepetition));
}

#[test]
fn analyze_anchored_alternation() {
    let engine = RedosEngine::new();
    let result = engine.analyze_regex(r"^(a+|b+|ab)+$");
    assert!(result.vulnerable);
    assert!(result
        .matched_patterns
        .contains(&RedosVulnPattern::AnchoredAlternationBomb));
}

#[test]
fn timing_detection_returns_result() {
    let engine = RedosEngine::new().with_timing_iterations(4);
    let result = engine.detect_via_timing(r"^[a-z]+$");
    assert!(result.is_some());
    let timing = result.unwrap();
    assert_eq!(timing.input_lengths.len(), 4);
    assert_eq!(timing.durations_us.len(), 4);
}

#[test]
fn timing_detection_invalid_regex_returns_none() {
    let engine = RedosEngine::new();
    let result = engine.detect_via_timing(r"(((");
    assert!(result.is_none());
}

#[test]
fn timing_growth_ratio_is_finite() {
    let engine = RedosEngine::new().with_timing_iterations(3);
    let result = engine.detect_via_timing(r"^(a+)+$").unwrap();
    assert!(result.growth_ratio.is_finite());
}

#[test]
fn polyglot_payloads_nonempty() {
    let engine = RedosEngine::new();
    let polyglots = engine.generate_polyglot_payloads();
    assert!(
        polyglots.len() >= 3,
        "Expected >=3 polyglots, got {}",
        polyglots.len()
    );
}

#[test]
fn polyglot_each_has_multiple_engines() {
    let engine = RedosEngine::new();
    for poly in engine.generate_polyglot_payloads() {
        assert!(
            poly.target_engines.len() >= 2,
            "Polyglot '{}' targets too few engines",
            poly.description
        );
    }
}

#[test]
fn polyglot_each_has_trigger_patterns() {
    let engine = RedosEngine::new();
    for poly in engine.generate_polyglot_payloads() {
        assert!(
            !poly.trigger_patterns.is_empty(),
            "Polyglot '{}' missing trigger patterns",
            poly.description
        );
    }
}

#[test]
fn extract_regex_from_js_source() {
    let engine = RedosEngine::new();
    let source = r#"
        var emailRegex = /^([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$/;
        var nameRegex = /^[a-z]+$/;
    "#;
    let regexes = engine.extract_regex_from_source(source);
    assert!(!regexes.is_empty());
}

#[test]
fn extract_regex_from_constructor() {
    let engine = RedosEngine::new();
    let source = r#"new RegExp('(a+)+$')"#;
    let regexes = engine.extract_regex_from_source(source);
    assert!(regexes.contains(&"(a+)+$".to_string()));
}

#[test]
fn extract_regex_from_error_message() {
    let engine = RedosEngine::new();
    let source = r#"pattern: "(a+)+$""#;
    let regexes = engine.extract_regex_from_source(source);
    assert!(regexes.contains(&"(a+)+$".to_string()));
}

#[test]
fn extract_regex_returns_empty_for_plain_text() {
    let engine = RedosEngine::new();
    let source = "Hello world, no regex here";
    let regexes = engine.extract_regex_from_source(source);
    assert!(regexes.is_empty());
}

#[test]
fn build_http_payloads_has_ten() {
    let engine = RedosEngine::new();
    let payloads = engine.build_http_payloads();
    assert_eq!(payloads.len(), 10);
    for (value, desc) in &payloads {
        assert!(!value.is_empty());
        assert!(desc.starts_with("ReDoS-"));
    }
}

#[test]
fn escalating_payloads_grow_in_length() {
    let engine = RedosEngine::new();
    let escalating = engine.generate_escalating_payloads(RedosVulnPattern::NestedQuantifiers, 5);
    assert_eq!(escalating.len(), 5);
    for i in 1..escalating.len() {
        assert!(
            escalating[i].1.len() > escalating[i - 1].1.len(),
            "Payload at step {} is not longer than step {}",
            i,
            i - 1
        );
    }
}

#[test]
fn quick_redos_check_finds_vulnerable() {
    let result = quick_redos_check(r"(a+)+$");
    assert!(result.is_some());
    let evils = result.unwrap();
    assert!(!evils.is_empty());
}

#[test]
fn quick_redos_check_returns_none_for_safe() {
    let result = quick_redos_check(r"^hello$");
    assert!(result.is_none());
}

#[test]
fn all_redos_payloads_convenience() {
    let payloads = all_redos_payloads();
    assert!(payloads.len() >= 10);
}

#[test]
fn measure_regex_time_returns_duration() {
    let dur = measure_regex_time(r"^[a-z]+$", "hello");
    assert!(dur.is_some());
}

#[test]
fn measure_regex_time_invalid_returns_none() {
    let dur = measure_regex_time(r"(((", "hello");
    assert!(dur.is_none());
}

#[test]
fn backtrack_complexity_display() {
    assert_eq!(format!("{}", BacktrackComplexity::Exponential), "O(2^n)");
    assert_eq!(format!("{}", BacktrackComplexity::Polynomial), "O(n^k)");
    assert_eq!(
        format!("{}", BacktrackComplexity::SuperLinear),
        "O(n log n)"
    );
}

#[test]
fn regex_engine_display() {
    assert_eq!(format!("{}", RegexEngine::JavaScript), "JavaScript");
    assert_eq!(format!("{}", RegexEngine::Pcre), "PCRE");
    assert_eq!(format!("{}", RegexEngine::DotNet), ".NET");
}

#[test]
fn engine_builder_methods() {
    let engine = RedosEngine::new()
        .with_max_payload_length(100)
        .with_timing_iterations(10)
        .with_growth_threshold(5.0);
    let payloads = engine.generate_payloads();
    for p in &payloads {
        assert!(p.evil_string.len() >= 100);
    }
}

#[test]
fn generate_evil_for_specific_pattern() {
    let engine = RedosEngine::new().with_max_payload_length(30);
    let payload = engine.generate_evil_for_pattern(RedosVulnPattern::StarHeight);
    assert_eq!(payload.pattern, RedosVulnPattern::StarHeight);
    assert!(payload.evil_string.len() > 20);
    assert_eq!(
        payload.expected_complexity,
        BacktrackComplexity::Exponential
    );
}

#[test]
fn evil_strings_returned_from_analysis() {
    let engine = RedosEngine::new();
    let result = engine.analyze_regex(r"(a+)+$");
    assert!(!result.evil_strings.is_empty());
    for evil in &result.evil_strings {
        assert!(!evil.is_empty());
    }
}

#[test]
fn lookahead_pattern_detected() {
    let engine = RedosEngine::new();
    let result = engine.analyze_regex(r"(?=a+b)a+$");
    assert!(result.vulnerable);
    assert!(result
        .matched_patterns
        .contains(&RedosVulnPattern::LookaheadWithBacktracking));
}

#[test]
fn multiple_patterns_detected_simultaneously() {
    let engine = RedosEngine::new();
    let result = engine.analyze_regex(r"((a+)+b)*$");
    assert!(result.vulnerable);
    assert!(result.matched_patterns.len() >= 2);
}
