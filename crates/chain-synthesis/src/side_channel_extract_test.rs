use crate::side_channel_extract::*;

// =========================================================================
// Helper: build a config with sensible defaults
// =========================================================================

fn base_config(technique: SideChannelTechnique) -> ExtractionConfig {
    ExtractionConfig {
        technique,
        target_field: "@@version".into(),
        max_length: 5,
        charset: CharacterSet::Hex,
        injection_point: "id".into(),
    }
}

// =========================================================================
// Timing oracle
// =========================================================================

#[test]
fn test_timing_oracle_plan_generation() {
    let config = base_config(SideChannelTechnique::TimingOracle);
    let plan = plan_timing_oracle(&config).unwrap();

    let charset_len = 16; // hex: 0-9, a-f
    let expected_probes = config.max_length * charset_len;
    assert_eq!(plan.total_probes, expected_probes);
    assert_eq!(plan.probes.len(), expected_probes);
    assert_eq!(plan.technique, SideChannelTechnique::TimingOracle);
    assert!(plan.estimated_time_ms > 0);
}

// =========================================================================
// Error-based extraction
// =========================================================================

#[test]
fn test_error_based_fewer_probes_than_timing() {
    let config = base_config(SideChannelTechnique::ErrorBased);
    let timing_plan = plan_timing_oracle(&config).unwrap();
    let error_plan = plan_error_based_extraction(&config).unwrap();

    assert_eq!(error_plan.total_probes, config.max_length);
    assert!(error_plan.total_probes < timing_plan.total_probes);

    for probe in &error_plan.probes {
        assert_eq!(probe.technique, SideChannelTechnique::ErrorBased);
        assert!(probe.test_value.is_empty());
    }
}

// =========================================================================
// Behavioral extraction
// =========================================================================

#[test]
fn test_behavioral_extraction_plan() {
    let config = base_config(SideChannelTechnique::BehavioralExtraction);
    let plan = plan_behavioral_extraction(&config).unwrap();

    let charset_len = 16;
    assert_eq!(plan.total_probes, config.max_length * charset_len);
    assert_eq!(plan.technique, SideChannelTechnique::BehavioralExtraction);

    for probe in &plan.probes {
        assert!(
            matches!(probe.expected_indicator, ResponseIndicator::StatusCode(200)),
            "behavioral probes should expect status 200",
        );
    }
}

// =========================================================================
// Cache timing
// =========================================================================

#[test]
fn test_cache_timing_plan() {
    let config = base_config(SideChannelTechnique::CacheTiming);
    let plan = plan_cache_timing_extraction(&config).unwrap();

    let charset_len = 16;
    assert_eq!(plan.total_probes, config.max_length * charset_len);
    assert_eq!(plan.technique, SideChannelTechnique::CacheTiming);

    for probe in &plan.probes {
        assert!(
            matches!(probe.expected_indicator, ResponseIndicator::CacheHit),
            "cache timing probes should expect cache hit",
        );
    }
}

// =========================================================================
// Optimization
// =========================================================================

#[test]
fn test_optimize_reduces_probe_count() {
    let config = base_config(SideChannelTechnique::TimingOracle);
    let mut plan = plan_timing_oracle(&config).unwrap();

    let dup = plan.probes[0].clone();
    plan.probes.push(dup);
    plan.total_probes = plan.probes.len();

    let optimized = optimize_extraction_plan(&plan);

    assert!(
        optimized.total_probes < plan.total_probes,
        "optimization should have removed the duplicate probe",
    );
    assert!(optimized
        .optimization_notes
        .iter()
        .any(|n| n.contains("duplicate")));
}

#[test]
fn test_optimize_adds_binary_search_note() {
    let config = ExtractionConfig {
        technique: SideChannelTechnique::TimingOracle,
        target_field: "@@version".into(),
        max_length: 3,
        charset: CharacterSet::Numeric,
        injection_point: "id".into(),
    };
    let plan = plan_timing_oracle(&config).unwrap();
    let optimized = optimize_extraction_plan(&plan);

    assert!(optimized
        .optimization_notes
        .iter()
        .any(|n| n.contains("binary search") || n.contains("Binary search")));
}

// =========================================================================
// Time estimation
// =========================================================================

#[test]
fn test_estimate_timing_accuracy() {
    let config = base_config(SideChannelTechnique::ErrorBased);
    let plan = plan_error_based_extraction(&config).unwrap();
    let est = estimate_extraction_time(&plan);

    assert_eq!(est.total_probes, plan.total_probes);
    assert_eq!(est.probes_per_character, 1);
    assert!(est.best_case_ms <= est.average_case_ms);
    assert!(est.average_case_ms <= est.worst_case_ms);
    assert!(est.worst_case_ms > 0);
}

#[test]
fn test_estimate_timing_zero_probes() {
    let plan = ExtractionPlan {
        technique: SideChannelTechnique::TimingOracle,
        target_description: String::new(),
        total_probes: 0,
        estimated_time_ms: 0,
        probes: vec![],
        optimization_notes: vec![],
    };
    let est = estimate_extraction_time(&plan);
    assert_eq!(est.best_case_ms, 0);
    assert_eq!(est.worst_case_ms, 0);
    assert_eq!(est.total_probes, 0);
}

// =========================================================================
// Charset resolution
// =========================================================================

#[test]
fn test_charset_resolution_alphanumeric() {
    let chars = resolve_charset_public(&CharacterSet::Alphanumeric);
    assert_eq!(chars.len(), 62);
    assert!(chars.contains(&'a'));
    assert!(chars.contains(&'Z'));
    assert!(chars.contains(&'9'));
}

#[test]
fn test_charset_resolution_printable() {
    let chars = resolve_charset_public(&CharacterSet::Printable);
    assert_eq!(chars.len(), 95);
    assert!(chars.contains(&' '));
    assert!(chars.contains(&'~'));
}

#[test]
fn test_charset_resolution_hex() {
    let chars = resolve_charset_public(&CharacterSet::Hex);
    assert_eq!(chars.len(), 16);
    assert!(chars.contains(&'0'));
    assert!(chars.contains(&'f'));
    assert!(!chars.contains(&'g'));
}

#[test]
fn test_charset_resolution_numeric() {
    let chars = resolve_charset_public(&CharacterSet::Numeric);
    assert_eq!(chars.len(), 10);
    assert!(chars.contains(&'0'));
    assert!(chars.contains(&'9'));
    assert!(!chars.contains(&'a'));
}

#[test]
fn test_charset_resolution_custom() {
    let custom = vec!['x', 'y', 'z'];
    let chars = resolve_charset_public(&CharacterSet::Custom(custom.clone()));
    assert_eq!(chars, custom);
}

/// Expose `resolve_charset` for test access via a plan round-trip: build
/// a config, generate probes, count unique test_values at position 1.
fn resolve_charset_public(cs: &CharacterSet) -> Vec<char> {
    let config = ExtractionConfig {
        technique: SideChannelTechnique::BehavioralExtraction,
        target_field: "test".into(),
        max_length: 1,
        charset: cs.clone(),
        injection_point: "p".into(),
    };
    let plan = plan_behavioral_extraction(&config).unwrap();
    plan.probes
        .iter()
        .map(|p| p.test_value.chars().next().unwrap())
        .collect()
}

// =========================================================================
// Invalid config errors
// =========================================================================

#[test]
fn test_invalid_config_empty_charset() {
    let config = ExtractionConfig {
        technique: SideChannelTechnique::TimingOracle,
        target_field: "@@version".into(),
        max_length: 5,
        charset: CharacterSet::Custom(vec![]),
        injection_point: "id".into(),
    };
    let result = plan_timing_oracle(&config);
    assert!(matches!(result, Err(SideChannelError::CharsetEmpty)));
}

#[test]
fn test_invalid_config_zero_max_length() {
    let config = ExtractionConfig {
        technique: SideChannelTechnique::TimingOracle,
        target_field: "@@version".into(),
        max_length: 0,
        charset: CharacterSet::Hex,
        injection_point: "id".into(),
    };
    let result = plan_timing_oracle(&config);
    assert!(matches!(result, Err(SideChannelError::MaxLengthZero)));
}

#[test]
fn test_invalid_config_empty_target() {
    let config = ExtractionConfig {
        technique: SideChannelTechnique::TimingOracle,
        target_field: String::new(),
        max_length: 5,
        charset: CharacterSet::Hex,
        injection_point: "id".into(),
    };
    let result = plan_timing_oracle(&config);
    assert!(matches!(result, Err(SideChannelError::InvalidConfig(_))));
}

// =========================================================================
// Probe payload validity
// =========================================================================

#[test]
fn test_probes_have_valid_payloads() {
    let config = base_config(SideChannelTechnique::TimingOracle);
    let plan = plan_timing_oracle(&config).unwrap();

    for probe in &plan.probes {
        assert!(!probe.payload.is_empty(), "payload must not be empty");
        assert!(
            probe.payload.contains(&config.target_field),
            "payload should reference target field",
        );
        assert!(probe.position >= 1);
        assert!(probe.position <= config.max_length);
    }
}

#[test]
fn test_error_based_probes_contain_extractvalue() {
    let config = base_config(SideChannelTechnique::ErrorBased);
    let plan = plan_error_based_extraction(&config).unwrap();

    for probe in &plan.probes {
        assert!(
            probe.payload.contains("EXTRACTVALUE"),
            "error-based payloads should use EXTRACTVALUE",
        );
    }
}

#[test]
fn test_behavioral_probes_contain_substring() {
    let config = base_config(SideChannelTechnique::BehavioralExtraction);
    let plan = plan_behavioral_extraction(&config).unwrap();

    for probe in &plan.probes {
        assert!(
            probe.payload.contains("SUBSTRING"),
            "behavioral payloads should use SUBSTRING",
        );
    }
}

// =========================================================================
// Display impls
// =========================================================================

#[test]
fn test_display_impls() {
    assert_eq!(
        format!("{}", SideChannelTechnique::TimingOracle),
        "timing-oracle",
    );
    assert_eq!(
        format!("{}", SideChannelTechnique::ErrorBased),
        "error-based",
    );
    assert_eq!(
        format!("{}", SideChannelTechnique::BehavioralExtraction),
        "behavioral-extraction",
    );
    assert_eq!(
        format!("{}", SideChannelTechnique::CacheTiming),
        "cache-timing",
    );

    let indicator = ResponseIndicator::TimingThreshold {
        min_ms: 100,
        max_ms: 500,
    };
    let display = format!("{indicator}");
    assert!(display.contains("100"));
    assert!(display.contains("500"));

    assert!(format!("{}", ResponseIndicator::CacheHit).contains("cache hit"));
    assert!(format!("{}", ResponseIndicator::CacheMiss).contains("cache miss"));

    assert!(format!("{}", CharacterSet::Hex).contains("16"));
    assert!(format!("{}", CharacterSet::Alphanumeric).contains("62"));

    let err = SideChannelError::MaxLengthZero;
    assert!(format!("{err}").contains("zero"));

    let err = SideChannelError::CharsetEmpty;
    assert!(format!("{err}").contains("empty"));

    let err = SideChannelError::InvalidConfig("bad".into());
    assert!(format!("{err}").contains("bad"));

    let err = SideChannelError::UnsupportedTechnique("nope".into());
    assert!(format!("{err}").contains("nope"));
}
