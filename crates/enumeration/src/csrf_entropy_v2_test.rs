use crate::csrf_entropy_v2::*;

#[test]
fn shannon_entropy_empty_corpus_returns_zero() {
    let analyzer = CsrfEntropyAnalyzer::new();
    assert_eq!(analyzer.calculate_shannon_entropy(), 0.0);
    assert_eq!(analyzer.calculate_min_entropy(), 0.0);
}

#[test]
fn shannon_entropy_single_char_tokens_zero_entropy() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    for i in 0..10 {
        analyzer.collect_token_sample("aaaa".to_string(), 1000 + i);
    }
    assert_eq!(analyzer.calculate_shannon_entropy(), 0.0);
}

#[test]
fn shannon_entropy_diverse_hex_tokens_high_entropy() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    let tokens = [
        "a3f8c92b1e47d065",
        "f8b2c3a4e5d6f7a8",
        "b9c0d1e2f3a4b5c6",
        "d7e8f9a0b1c2d3e4",
        "1234abcd5678ef90",
        "fedcba9876543210",
        "0a1b2c3d4e5f6789",
        "9f8e7d6c5b4a3210",
    ];
    for (i, t) in tokens.iter().enumerate() {
        analyzer.collect_token_sample(t.to_string(), 1000 + i as u64 * 100);
    }
    let shannon = analyzer.calculate_shannon_entropy();
    assert!(shannon > 3.0, "Expected high entropy, got {}", shannon);
}

#[test]
fn min_entropy_less_than_or_equal_to_shannon() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    for i in 0..20 {
        analyzer.collect_token_sample(format!("{:016x}", i * 7919 + 12345), i * 50);
    }
    let shannon = analyzer.calculate_shannon_entropy();
    let min_ent = analyzer.calculate_min_entropy();
    assert!(
        min_ent <= shannon + 0.001,
        "Min entropy {} should be <= Shannon entropy {}",
        min_ent,
        shannon
    );
}

#[test]
fn detect_sequential_numeric_tokens() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    for i in 0..10 {
        analyzer.collect_token_sample(format!("{}", 1000 + i), i * 100);
    }
    assert!(
        analyzer.detect_sequential_pattern(),
        "Should detect sequential numeric tokens"
    );
}

#[test]
fn detect_sequential_hex_tokens() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    for i in 0..10u64 {
        analyzer.collect_token_sample(format!("{:x}", 0xff00 + i * 3), i * 100);
    }
    assert!(
        analyzer.detect_sequential_pattern(),
        "Should detect sequential hex tokens"
    );
}

#[test]
fn non_sequential_tokens_not_flagged() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    let values = ["a3f8c92b", "1e47d065", "f8b2c3a4", "e5d6f7a8", "b9c0d1e2"];
    for (i, v) in values.iter().enumerate() {
        analyzer.collect_token_sample(v.to_string(), i as u64 * 100);
    }
    assert!(
        !analyzer.detect_sequential_pattern(),
        "Random-looking tokens should not be flagged as sequential"
    );
}

#[test]
fn detect_static_tokens_via_weakness() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    for i in 0..5 {
        analyzer.collect_token_sample("same_token_every_time".to_string(), i * 100);
    }
    let analysis = analyzer.analyze_entropy();
    assert_eq!(analysis.weakness_type, Some(TokenWeakness::StaticToken));
}

#[test]
fn detect_short_length_weakness() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    let short_tokens = ["ab", "cd", "ef", "12", "34", "56", "78", "9a", "bc", "de"];
    for (i, t) in short_tokens.iter().enumerate() {
        analyzer.collect_token_sample(t.to_string(), i as u64 * 100);
    }
    let analysis = analyzer.analyze_entropy();
    assert_eq!(analysis.weakness_type, Some(TokenWeakness::ShortLength));
}

#[test]
fn detect_timestamp_pattern_correlated_values() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    let base_ts: u64 = 1700000000000;
    for i in 0..10 {
        let ts = base_ts + i * 1000;
        analyzer.collect_token_sample(format!("{}", ts + 5), ts);
    }
    assert!(
        analyzer.detect_timestamp_pattern(),
        "Should detect timestamp-correlated tokens"
    );
}

#[test]
fn timestamp_pattern_not_detected_for_random() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    let base_ts: u64 = 1700000000000;
    let random_vals: [u64; 5] = [42, 999999999, 7, 8675309, 31337];
    for (i, &v) in random_vals.iter().enumerate() {
        analyzer.collect_token_sample(format!("{}", v), base_ts + i as u64 * 1000);
    }
    assert!(
        !analyzer.detect_timestamp_pattern(),
        "Random values should not match timestamp pattern"
    );
}

#[test]
fn mt19937_untemper_roundtrip() {
    let test_values: [u32; 5] = [0, 1, 0xDEADBEEF, 0xFFFFFFFF, 0x12345678];
    for &original in &test_values {
        let tempered = mt19937_temper_for_test(original);
        let recovered = mt19937_untemper(tempered);
        assert_eq!(
            recovered, original,
            "Untemper roundtrip failed for 0x{:08X}: got 0x{:08X}",
            original, recovered
        );
    }
}

fn mt19937_temper_for_test(mut y: u32) -> u32 {
    y ^= y >> 11;
    y ^= (y << 7) & 0x9D2C5680;
    y ^= (y << 15) & 0xEFC60000;
    y ^= y >> 18;
    y
}

#[test]
fn mt19937_state_recovery_from_624_outputs() {
    let seed = 42u32;
    let outputs = mt19937_sequence(seed, MT19937_N + 5);

    let mut analyzer = CsrfEntropyAnalyzer::new();
    for (i, &val) in outputs.iter().enumerate() {
        analyzer.collect_token_sample(format!("{}", val), i as u64 * 10);
    }

    let recovery = analyzer.attempt_mt19937_recovery();
    assert!(
        recovery.is_some(),
        "Should recover MT19937 state from 624 outputs"
    );

    let state = recovery.unwrap();
    assert_eq!(state.state.len(), MT19937_N);
    assert_eq!(state.recovered_from_outputs, MT19937_N);

    let predicted = mt19937_generate_from_state(&state.state, state.index);
    assert_eq!(
        predicted, outputs[MT19937_N],
        "Predicted output should match actual MT19937 output #625"
    );
}

const MT19937_N: usize = 624;

#[test]
fn mt19937_prediction_via_analyzer() {
    let seed = 1337u32;
    let outputs = mt19937_sequence(seed, MT19937_N + 1);

    let mut analyzer = CsrfEntropyAnalyzer::new();
    for (i, &val) in outputs[..MT19937_N + 1].iter().enumerate() {
        analyzer.collect_token_sample(format!("{}", val), i as u64 * 10);
    }

    let prediction = analyzer.predict_next_token();
    assert!(prediction.is_some(), "Should produce a prediction");
    let pred = prediction.unwrap();
    assert_eq!(pred.method_used, "mt19937_state_recovery");
    assert!(pred.confidence > 0.9);
}

#[test]
fn sequential_prediction_produces_correct_next() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    for i in 0..5 {
        analyzer.collect_token_sample(format!("{}", 100 + i * 7), i * 100);
    }
    let prediction = analyzer.predict_next_token();
    assert!(prediction.is_some());
    let pred = prediction.unwrap();
    assert_eq!(pred.predicted_next, "135");
    assert_eq!(pred.method_used, "sequential_extrapolation");
}

#[test]
fn static_token_prediction_returns_same_value() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    for i in 0..5 {
        analyzer.collect_token_sample("fixed_csrf_token".to_string(), i * 100);
    }
    let prediction = analyzer.predict_next_token();
    assert!(prediction.is_some());
    let pred = prediction.unwrap();
    assert_eq!(pred.predicted_next, "fixed_csrf_token");
    assert_eq!(pred.method_used, "static_token");
    assert_eq!(pred.confidence, 1.0);
}

#[test]
fn charset_analysis_hex_tokens() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    for i in 0..5 {
        analyzer.collect_token_sample(format!("{:016x}", 0xABCD0000u64 + i), i * 100);
    }
    let charset = analyzer.analyze_charset();
    assert!(charset.hex_only);
    assert!(!charset.numeric_only);
}

#[test]
fn charset_analysis_numeric_only_tokens() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    for i in 0..5 {
        analyzer.collect_token_sample(format!("{}", 1000000 + i), i * 100);
    }
    let charset = analyzer.analyze_charset();
    assert!(charset.numeric_only);
    assert!(charset.hex_only);
}

#[test]
fn generate_report_contains_all_fields() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    for i in 0..10 {
        analyzer.collect_token_sample(format!("{}", 500 + i), i * 100);
    }
    let report = analyzer.generate_report();
    assert_eq!(report.samples_collected, 10);
    assert!(report.shannon_entropy > 0.0);
    assert!(report.min_entropy > 0.0);
    assert!(report.detected_weakness.is_some());
    assert!(!report.recommendations.is_empty());
}

#[test]
fn entropy_analysis_sufficient_for_strong_tokens() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    let strong_tokens = [
        "8a3f1b9c72d4e605a8b2c3d4e5f60718",
        "f1e2d3c4b5a69708192a3b4c5d6e7f80",
        "0192837465afbcde1029384756fabcde",
        "deadbeefcafebabe0102030405060708",
        "aabbccdd11223344eeff00998877665a",
        "1f2e3d4c5b6a79081726354463524110",
        "f0e1d2c3b4a5968778695a4b3c2d1e0f",
        "abcdef0123456789fedcba9876543210",
    ];
    for (i, t) in strong_tokens.iter().enumerate() {
        analyzer.collect_token_sample(t.to_string(), i as u64 * 500);
    }
    let analysis = analyzer.analyze_entropy();
    assert!(
        analysis.is_sufficient,
        "Strong 32-char hex tokens should have sufficient entropy"
    );
    assert!(
        analysis.weakness_type.is_none(),
        "Strong tokens should have no weakness, got {:?}",
        analysis.weakness_type
    );
}

#[test]
fn prng_type_detection_unknown_for_random_looking() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    let pseudo_random: [u64; 8] = [
        0x7a3f1b9c72d4e605,
        0xf1e2d3c4b5a69708,
        0x0192837465afbcde,
        0xdeadbeefcafebabe,
        0xaabbccdd11223344,
        0x1f2e3d4c5b6a7908,
        0xf0e1d2c3b4a59687,
        0xabcdef0123456789,
    ];
    for (i, &v) in pseudo_random.iter().enumerate() {
        analyzer.collect_token_sample(format!("{:016x}", v), i as u64 * 100);
    }
    let prng = analyzer.detect_prng_type();
    assert!(
        matches!(prng, PrngType::SystemRandom | PrngType::Unknown),
        "High-entropy non-patterned values should be SystemRandom or Unknown, got {}",
        prng
    );
}

#[test]
fn display_impls_produce_expected_strings() {
    assert_eq!(format!("{}", TokenWeakness::LowEntropy), "Low Entropy");
    assert_eq!(format!("{}", TokenWeakness::Sequential), "Sequential");
    assert_eq!(
        format!("{}", TokenWeakness::TimestampBased),
        "Timestamp Based"
    );
    assert_eq!(
        format!("{}", TokenWeakness::MersenneTwisterRecoverable),
        "Mersenne Twister Recoverable"
    );
    assert_eq!(format!("{}", PrngType::MersenneTwister), "Mersenne Twister");
    assert_eq!(format!("{}", PrngType::LCG), "LCG");
    assert_eq!(format!("{}", PrngType::XorShift), "XorShift");
    assert_eq!(format!("{}", PrngType::SystemRandom), "System Random");
    assert_eq!(format!("{}", PrngType::Unknown), "Unknown");
}

#[test]
fn default_analyzer_is_empty() {
    let analyzer = CsrfEntropyAnalyzer::default();
    assert!(analyzer.samples().is_empty());
    assert_eq!(analyzer.calculate_shannon_entropy(), 0.0);
}

#[test]
fn mt19937_seed_produces_deterministic_sequence() {
    let seq_a = mt19937_sequence(12345, 10);
    let seq_b = mt19937_sequence(12345, 10);
    assert_eq!(seq_a, seq_b, "Same seed must produce identical sequences");
    let seq_c = mt19937_sequence(54321, 10);
    assert_ne!(
        seq_a, seq_c,
        "Different seeds should produce different sequences"
    );
}

#[test]
fn entropy_report_serializable() {
    let mut analyzer = CsrfEntropyAnalyzer::new();
    for i in 0..5 {
        analyzer.collect_token_sample(format!("{:08x}", i * 1000 + 42), i * 100);
    }
    let report = analyzer.generate_report();
    let json = serde_json::to_string(&report);
    assert!(json.is_ok(), "EntropyReport should serialize to JSON");
    let deserialized: Result<EntropyReport, _> = serde_json::from_str(&json.unwrap());
    assert!(
        deserialized.is_ok(),
        "EntropyReport should deserialize from JSON"
    );
}
