#[cfg(test)]
mod tests {
    use crate::stealth_config::StealthConfig;

    #[test]
    fn default_max_requests_per_second() {
        let config = StealthConfig::default();
        assert!((config.max_requests_per_second - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn default_jitter_range() {
        let config = StealthConfig::default();
        assert_eq!(config.jitter_range_ms, (50, 200));
    }

    #[test]
    fn default_min_delay() {
        let config = StealthConfig::default();
        assert_eq!(config.min_delay_ms, 50);
    }

    #[test]
    fn default_max_delay() {
        let config = StealthConfig::default();
        assert_eq!(config.max_delay_ms, 500);
    }

    #[test]
    fn default_session_rotation_interval() {
        let config = StealthConfig::default();
        assert_eq!(config.session_rotation_interval, 100);
    }

    #[test]
    fn default_prefer_blind_payloads() {
        let config = StealthConfig::default();
        assert!(!config.prefer_blind_payloads);
    }

    #[test]
    fn default_avoid_signature_payloads() {
        let config = StealthConfig::default();
        assert!(!config.avoid_signature_payloads);
    }

    #[test]
    fn benchmark_creates_config_with_expected_values() {
        let config = StealthConfig::benchmark();
        assert_eq!(config.max_requests_per_second, f64::MAX);
        assert_eq!(config.jitter_range_ms, (0, 0));
        assert_eq!(config.min_delay_ms, 0);
        assert_eq!(config.max_delay_ms, 0);
        assert_eq!(config.session_rotation_interval, 0);
        assert!(!config.prefer_blind_payloads);
        assert!(!config.avoid_signature_payloads);
    }

    #[test]
    fn benchmark_has_zero_jitter_and_delay() {
        let config = StealthConfig::benchmark();
        assert_eq!(config.jitter_range_ms.0, 0);
        assert_eq!(config.jitter_range_ms.1, 0);
        assert_eq!(config.min_delay_ms, 0);
        assert_eq!(config.max_delay_ms, 0);
    }

    #[test]
    fn benchmark_has_maximum_rps() {
        let config = StealthConfig::benchmark();
        assert_eq!(config.max_requests_per_second, f64::MAX);
    }

    #[test]
    fn aggressive_max_requests_per_second() {
        let config = StealthConfig::aggressive();
        assert!((config.max_requests_per_second - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggressive_jitter_range() {
        let config = StealthConfig::aggressive();
        assert_eq!(config.jitter_range_ms, (0, 50));
    }

    #[test]
    fn aggressive_delays() {
        let config = StealthConfig::aggressive();
        assert_eq!(config.min_delay_ms, 0);
        assert_eq!(config.max_delay_ms, 100);
    }

    #[test]
    fn aggressive_no_session_rotation() {
        let config = StealthConfig::aggressive();
        assert_eq!(config.session_rotation_interval, 0);
    }

    #[test]
    fn aggressive_bools_false() {
        let config = StealthConfig::aggressive();
        assert!(!config.prefer_blind_payloads);
        assert!(!config.avoid_signature_payloads);
    }

    #[test]
    fn paranoid_max_requests_per_second() {
        let config = StealthConfig::paranoid();
        assert!((config.max_requests_per_second - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn paranoid_jitter_range() {
        let config = StealthConfig::paranoid();
        assert_eq!(config.jitter_range_ms, (500, 2000));
    }

    #[test]
    fn paranoid_delays() {
        let config = StealthConfig::paranoid();
        assert_eq!(config.min_delay_ms, 500);
        assert_eq!(config.max_delay_ms, 5000);
    }

    #[test]
    fn paranoid_session_rotation_interval() {
        let config = StealthConfig::paranoid();
        assert_eq!(config.session_rotation_interval, 20);
    }

    #[test]
    fn paranoid_bools_true() {
        let config = StealthConfig::paranoid();
        assert!(config.prefer_blind_payloads);
        assert!(config.avoid_signature_payloads);
    }

    #[test]
    fn with_max_requests_per_second_modifies_only_target() {
        let original = StealthConfig::default();
        let modified = original.clone().with_max_requests_per_second(25.0);
        assert!((modified.max_requests_per_second - 25.0).abs() < f64::EPSILON);
        assert_eq!(modified.jitter_range_ms, original.jitter_range_ms);
        assert_eq!(modified.min_delay_ms, original.min_delay_ms);
        assert_eq!(modified.max_delay_ms, original.max_delay_ms);
        assert_eq!(
            modified.session_rotation_interval,
            original.session_rotation_interval
        );
        assert_eq!(
            modified.prefer_blind_payloads,
            original.prefer_blind_payloads
        );
        assert_eq!(
            modified.avoid_signature_payloads,
            original.avoid_signature_payloads
        );
    }

    #[test]
    fn with_jitter_range_ms_modifies_only_target() {
        let original = StealthConfig::default();
        let modified = original.clone().with_jitter_range_ms(100, 400);
        assert_eq!(modified.jitter_range_ms, (100, 400));
        assert!(
            (modified.max_requests_per_second - original.max_requests_per_second).abs()
                < f64::EPSILON
        );
        assert_eq!(modified.min_delay_ms, original.min_delay_ms);
        assert_eq!(modified.max_delay_ms, original.max_delay_ms);
        assert_eq!(
            modified.session_rotation_interval,
            original.session_rotation_interval
        );
        assert_eq!(
            modified.prefer_blind_payloads,
            original.prefer_blind_payloads
        );
        assert_eq!(
            modified.avoid_signature_payloads,
            original.avoid_signature_payloads
        );
    }

    #[test]
    fn with_min_delay_ms_modifies_only_target() {
        let original = StealthConfig::default();
        let modified = original.clone().with_min_delay_ms(200);
        assert_eq!(modified.min_delay_ms, 200);
        assert!(
            (modified.max_requests_per_second - original.max_requests_per_second).abs()
                < f64::EPSILON
        );
        assert_eq!(modified.jitter_range_ms, original.jitter_range_ms);
        assert_eq!(modified.max_delay_ms, original.max_delay_ms);
        assert_eq!(
            modified.session_rotation_interval,
            original.session_rotation_interval
        );
        assert_eq!(
            modified.prefer_blind_payloads,
            original.prefer_blind_payloads
        );
        assert_eq!(
            modified.avoid_signature_payloads,
            original.avoid_signature_payloads
        );
    }

    #[test]
    fn with_max_delay_ms_modifies_only_target() {
        let original = StealthConfig::default();
        let modified = original.clone().with_max_delay_ms(1000);
        assert_eq!(modified.max_delay_ms, 1000);
        assert!(
            (modified.max_requests_per_second - original.max_requests_per_second).abs()
                < f64::EPSILON
        );
        assert_eq!(modified.jitter_range_ms, original.jitter_range_ms);
        assert_eq!(modified.min_delay_ms, original.min_delay_ms);
        assert_eq!(
            modified.session_rotation_interval,
            original.session_rotation_interval
        );
        assert_eq!(
            modified.prefer_blind_payloads,
            original.prefer_blind_payloads
        );
        assert_eq!(
            modified.avoid_signature_payloads,
            original.avoid_signature_payloads
        );
    }

    #[test]
    fn with_session_rotation_interval_modifies_only_target() {
        let original = StealthConfig::default();
        let modified = original.clone().with_session_rotation_interval(50);
        assert_eq!(modified.session_rotation_interval, 50);
        assert!(
            (modified.max_requests_per_second - original.max_requests_per_second).abs()
                < f64::EPSILON
        );
        assert_eq!(modified.jitter_range_ms, original.jitter_range_ms);
        assert_eq!(modified.min_delay_ms, original.min_delay_ms);
        assert_eq!(modified.max_delay_ms, original.max_delay_ms);
        assert_eq!(
            modified.prefer_blind_payloads,
            original.prefer_blind_payloads
        );
        assert_eq!(
            modified.avoid_signature_payloads,
            original.avoid_signature_payloads
        );
    }

    #[test]
    fn with_prefer_blind_payloads_modifies_only_target() {
        let original = StealthConfig::default();
        let modified = original.clone().with_prefer_blind_payloads(true);
        assert!(modified.prefer_blind_payloads);
        assert!(
            (modified.max_requests_per_second - original.max_requests_per_second).abs()
                < f64::EPSILON
        );
        assert_eq!(modified.jitter_range_ms, original.jitter_range_ms);
        assert_eq!(modified.min_delay_ms, original.min_delay_ms);
        assert_eq!(modified.max_delay_ms, original.max_delay_ms);
        assert_eq!(
            modified.session_rotation_interval,
            original.session_rotation_interval
        );
        assert_eq!(
            modified.avoid_signature_payloads,
            original.avoid_signature_payloads
        );
    }

    #[test]
    fn with_avoid_signature_payloads_modifies_only_target() {
        let original = StealthConfig::default();
        let modified = original.clone().with_avoid_signature_payloads(true);
        assert!(modified.avoid_signature_payloads);
        assert!(
            (modified.max_requests_per_second - original.max_requests_per_second).abs()
                < f64::EPSILON
        );
        assert_eq!(modified.jitter_range_ms, original.jitter_range_ms);
        assert_eq!(modified.min_delay_ms, original.min_delay_ms);
        assert_eq!(modified.max_delay_ms, original.max_delay_ms);
        assert_eq!(
            modified.session_rotation_interval,
            original.session_rotation_interval
        );
        assert_eq!(
            modified.prefer_blind_payloads,
            original.prefer_blind_payloads
        );
    }

    #[test]
    fn builder_chaining_applies_all_modifications() {
        let config = StealthConfig::default()
            .with_max_requests_per_second(30.0)
            .with_jitter_range_ms(10, 100)
            .with_min_delay_ms(5)
            .with_max_delay_ms(250)
            .with_session_rotation_interval(75)
            .with_prefer_blind_payloads(true)
            .with_avoid_signature_payloads(true);

        assert!((config.max_requests_per_second - 30.0).abs() < f64::EPSILON);
        assert_eq!(config.jitter_range_ms, (10, 100));
        assert_eq!(config.min_delay_ms, 5);
        assert_eq!(config.max_delay_ms, 250);
        assert_eq!(config.session_rotation_interval, 75);
        assert!(config.prefer_blind_payloads);
        assert!(config.avoid_signature_payloads);
    }

    #[test]
    fn builder_chaining_from_aggressive() {
        let config = StealthConfig::aggressive()
            .with_max_requests_per_second(100.0)
            .with_prefer_blind_payloads(true);

        assert!((config.max_requests_per_second - 100.0).abs() < f64::EPSILON);
        assert!(config.prefer_blind_payloads);
        assert_eq!(config.jitter_range_ms, (0, 50));
        assert_eq!(config.min_delay_ms, 0);
        assert_eq!(config.max_delay_ms, 100);
        assert_eq!(config.session_rotation_interval, 0);
        assert!(!config.avoid_signature_payloads);
    }

    #[test]
    fn builder_chaining_from_paranoid() {
        let config = StealthConfig::paranoid()
            .with_max_delay_ms(10000)
            .with_session_rotation_interval(10);

        assert!((config.max_requests_per_second - 2.0).abs() < f64::EPSILON);
        assert_eq!(config.jitter_range_ms, (500, 2000));
        assert_eq!(config.min_delay_ms, 500);
        assert_eq!(config.max_delay_ms, 10000);
        assert_eq!(config.session_rotation_interval, 10);
        assert!(config.prefer_blind_payloads);
        assert!(config.avoid_signature_payloads);
    }

    #[test]
    fn serde_roundtrip_default() {
        let original = StealthConfig::default();
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: StealthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn serde_roundtrip_aggressive() {
        let original = StealthConfig::aggressive();
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: StealthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn serde_roundtrip_paranoid() {
        let original = StealthConfig::paranoid();
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: StealthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn serde_roundtrip_custom() {
        let original = StealthConfig::default()
            .with_max_requests_per_second(42.5)
            .with_jitter_range_ms(1, 999)
            .with_prefer_blind_payloads(true);
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: StealthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn partial_eq_two_defaults_are_equal() {
        let a = StealthConfig::default();
        let b = StealthConfig::default();
        assert_eq!(a, b);
    }

    #[test]
    fn partial_eq_two_aggressives_are_equal() {
        let a = StealthConfig::aggressive();
        let b = StealthConfig::aggressive();
        assert_eq!(a, b);
    }

    #[test]
    fn partial_eq_two_paranoids_are_equal() {
        let a = StealthConfig::paranoid();
        let b = StealthConfig::paranoid();
        assert_eq!(a, b);
    }

    #[test]
    fn partial_eq_different_presets_not_equal() {
        assert_ne!(StealthConfig::default(), StealthConfig::aggressive());
        assert_ne!(StealthConfig::default(), StealthConfig::paranoid());
        assert_ne!(StealthConfig::aggressive(), StealthConfig::paranoid());
    }

    #[test]
    fn partial_eq_modified_not_equal_to_default() {
        let default = StealthConfig::default();
        let modified = StealthConfig::default().with_max_requests_per_second(99.0);
        assert_ne!(default, modified);
    }

    #[test]
    fn clone_produces_equal_copy() {
        let original = StealthConfig::paranoid();
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn clone_is_independent() {
        let original = StealthConfig::default();
        let mut cloned = original.clone();
        cloned.max_requests_per_second = 999.0;
        cloned.prefer_blind_payloads = true;
        assert!((original.max_requests_per_second - 10.0).abs() < f64::EPSILON);
        assert!(!original.prefer_blind_payloads);
        assert_ne!(original, cloned);
    }

    #[test]
    fn debug_format_contains_struct_name() {
        let config = StealthConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("StealthConfig"));
    }

    #[test]
    fn serde_json_contains_expected_keys() {
        let config = StealthConfig::default();
        let json: serde_json::Value = serde_json::to_value(&config).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("max_requests_per_second"));
        assert!(obj.contains_key("jitter_range_ms"));
        assert!(obj.contains_key("min_delay_ms"));
        assert!(obj.contains_key("max_delay_ms"));
        assert!(obj.contains_key("session_rotation_interval"));
        assert!(obj.contains_key("prefer_blind_payloads"));
        assert!(obj.contains_key("avoid_signature_payloads"));
        assert_eq!(obj.len(), 7);
    }

    #[test]
    fn with_builder_overwrite_same_field_twice() {
        let config = StealthConfig::default()
            .with_max_requests_per_second(5.0)
            .with_max_requests_per_second(15.0);
        assert!((config.max_requests_per_second - 15.0).abs() < f64::EPSILON);
    }
}
