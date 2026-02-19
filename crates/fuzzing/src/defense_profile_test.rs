#[cfg(test)]
mod tests {
    use crate::defense_profile::{
        BotDetectionProfile, DefenseProfile, DefenseType, RateLimitProfile, WafProfile, WafVendor,
    };
    use aegis_protocol::finding::VulnerabilityClass;

    fn sample_waf() -> WafProfile {
        WafProfile {
            vendor: WafVendor::Cloudflare,
            paranoia_level: Some(2),
            blocked_response_code: 403,
            blocked_categories: vec![
                VulnerabilityClass::SqlInjection,
                VulnerabilityClass::CrossSiteScripting,
            ],
        }
    }

    fn sample_rate_limit() -> RateLimitProfile {
        RateLimitProfile {
            requests_per_second: Some(100.0),
            burst_allowance: Some(20),
            limit_response_code: 429,
            limit_window_seconds: Some(60),
        }
    }

    fn sample_bot_detection() -> BotDetectionProfile {
        BotDetectionProfile {
            detected: true,
            detection_method: "javascript_challenge".to_string(),
            challenge_response_code: Some(503),
        }
    }

    #[test]
    fn empty_creates_profile_with_all_none_fields() {
        let profile = DefenseProfile::empty(1000);
        assert!(profile.waf.is_none());
        assert!(profile.rate_limit.is_none());
        assert!(profile.bot_detection.is_none());
    }

    #[test]
    fn empty_stores_correct_timestamp() {
        let profile = DefenseProfile::empty(1707235200000);
        assert_eq!(profile.fingerprint_timestamp_ms, 1707235200000);
    }

    #[test]
    fn with_waf_sets_waf_field() {
        let profile = DefenseProfile::empty(1000).with_waf(sample_waf());
        assert!(profile.waf.is_some());
        let waf = profile.waf.unwrap();
        assert_eq!(waf.vendor, WafVendor::Cloudflare);
        assert_eq!(waf.paranoia_level, Some(2));
        assert_eq!(waf.blocked_response_code, 403);
        assert_eq!(waf.blocked_categories.len(), 2);
    }

    #[test]
    fn with_rate_limit_sets_rate_limit_field() {
        let profile = DefenseProfile::empty(1000).with_rate_limit(sample_rate_limit());
        assert!(profile.rate_limit.is_some());
        let rl = profile.rate_limit.unwrap();
        assert_eq!(rl.requests_per_second, Some(100.0));
        assert_eq!(rl.burst_allowance, Some(20));
        assert_eq!(rl.limit_response_code, 429);
        assert_eq!(rl.limit_window_seconds, Some(60));
    }

    #[test]
    fn with_bot_detection_sets_bot_detection_field() {
        let profile = DefenseProfile::empty(1000).with_bot_detection(sample_bot_detection());
        assert!(profile.bot_detection.is_some());
        let bd = profile.bot_detection.unwrap();
        assert!(bd.detected);
        assert_eq!(bd.detection_method, "javascript_challenge");
        assert_eq!(bd.challenge_response_code, Some(503));
    }

    #[test]
    fn builder_chaining_sets_all_fields() {
        let profile = DefenseProfile::empty(5000)
            .with_waf(sample_waf())
            .with_rate_limit(sample_rate_limit())
            .with_bot_detection(sample_bot_detection());

        assert!(profile.waf.is_some());
        assert!(profile.rate_limit.is_some());
        assert!(profile.bot_detection.is_some());
        assert_eq!(profile.fingerprint_timestamp_ms, 5000);
    }

    #[test]
    fn defense_types_returns_none_for_empty_profile() {
        let profile = DefenseProfile::empty(1000);
        let types = profile.defense_types();
        assert_eq!(types, vec![DefenseType::None]);
    }

    #[test]
    fn defense_types_returns_waf_when_only_waf_set() {
        let profile = DefenseProfile::empty(1000).with_waf(sample_waf());
        let types = profile.defense_types();
        assert_eq!(types, vec![DefenseType::Waf]);
    }

    #[test]
    fn defense_types_returns_rate_limiter_when_only_rate_limit_set() {
        let profile = DefenseProfile::empty(1000).with_rate_limit(sample_rate_limit());
        let types = profile.defense_types();
        assert_eq!(types, vec![DefenseType::RateLimiter]);
    }

    #[test]
    fn defense_types_returns_bot_detection_when_only_bot_detection_set() {
        let profile = DefenseProfile::empty(1000).with_bot_detection(sample_bot_detection());
        let types = profile.defense_types();
        assert_eq!(types, vec![DefenseType::BotDetection]);
    }

    #[test]
    fn defense_types_returns_all_three_when_all_set() {
        let profile = DefenseProfile::empty(1000)
            .with_waf(sample_waf())
            .with_rate_limit(sample_rate_limit())
            .with_bot_detection(sample_bot_detection());
        let types = profile.defense_types();
        assert_eq!(
            types,
            vec![
                DefenseType::Waf,
                DefenseType::RateLimiter,
                DefenseType::BotDetection,
            ]
        );
    }

    #[test]
    fn defense_types_returns_correct_subset_waf_and_bot_detection() {
        let profile = DefenseProfile::empty(1000)
            .with_waf(sample_waf())
            .with_bot_detection(sample_bot_detection());
        let types = profile.defense_types();
        assert_eq!(types, vec![DefenseType::Waf, DefenseType::BotDetection]);
    }

    #[test]
    fn defense_types_returns_correct_subset_rate_limit_and_bot_detection() {
        let profile = DefenseProfile::empty(1000)
            .with_rate_limit(sample_rate_limit())
            .with_bot_detection(sample_bot_detection());
        let types = profile.defense_types();
        assert_eq!(
            types,
            vec![DefenseType::RateLimiter, DefenseType::BotDetection]
        );
    }

    #[test]
    fn defense_type_enum_serialization_roundtrip() {
        let variants = [
            DefenseType::Waf,
            DefenseType::RateLimiter,
            DefenseType::BotDetection,
            DefenseType::TlsTermination,
            DefenseType::None,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let deserialized: DefenseType = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, deserialized);
        }
    }

    #[test]
    fn defense_type_serializes_to_expected_strings() {
        assert_eq!(serde_json::to_string(&DefenseType::Waf).unwrap(), "\"Waf\"");
        assert_eq!(
            serde_json::to_string(&DefenseType::RateLimiter).unwrap(),
            "\"RateLimiter\""
        );
        assert_eq!(
            serde_json::to_string(&DefenseType::BotDetection).unwrap(),
            "\"BotDetection\""
        );
        assert_eq!(
            serde_json::to_string(&DefenseType::TlsTermination).unwrap(),
            "\"TlsTermination\""
        );
        assert_eq!(
            serde_json::to_string(&DefenseType::None).unwrap(),
            "\"None\""
        );
    }

    #[test]
    fn waf_vendor_enum_serialization_roundtrip() {
        let variants = [
            WafVendor::ModSecurity,
            WafVendor::Cloudflare,
            WafVendor::AwsWaf,
            WafVendor::Imperva,
            WafVendor::Akamai,
            WafVendor::Unknown,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let deserialized: WafVendor = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, deserialized);
        }
    }

    #[test]
    fn waf_vendor_serializes_to_expected_strings() {
        assert_eq!(
            serde_json::to_string(&WafVendor::ModSecurity).unwrap(),
            "\"ModSecurity\""
        );
        assert_eq!(
            serde_json::to_string(&WafVendor::Cloudflare).unwrap(),
            "\"Cloudflare\""
        );
        assert_eq!(
            serde_json::to_string(&WafVendor::AwsWaf).unwrap(),
            "\"AwsWaf\""
        );
        assert_eq!(
            serde_json::to_string(&WafVendor::Imperva).unwrap(),
            "\"Imperva\""
        );
        assert_eq!(
            serde_json::to_string(&WafVendor::Akamai).unwrap(),
            "\"Akamai\""
        );
        assert_eq!(
            serde_json::to_string(&WafVendor::Unknown).unwrap(),
            "\"Unknown\""
        );
    }

    #[test]
    fn waf_profile_fields_are_accessible() {
        let waf = sample_waf();
        assert_eq!(waf.vendor, WafVendor::Cloudflare);
        assert_eq!(waf.paranoia_level, Some(2));
        assert_eq!(waf.blocked_response_code, 403);
        assert_eq!(waf.blocked_categories[0], VulnerabilityClass::SqlInjection);
        assert_eq!(
            waf.blocked_categories[1],
            VulnerabilityClass::CrossSiteScripting
        );
    }

    #[test]
    fn waf_profile_with_no_paranoia_level() {
        let waf = WafProfile {
            vendor: WafVendor::AwsWaf,
            paranoia_level: None,
            blocked_response_code: 406,
            blocked_categories: vec![],
        };
        assert_eq!(waf.vendor, WafVendor::AwsWaf);
        assert!(waf.paranoia_level.is_none());
        assert_eq!(waf.blocked_response_code, 406);
        assert!(waf.blocked_categories.is_empty());
    }

    #[test]
    fn rate_limit_profile_fields_are_accessible() {
        let rl = sample_rate_limit();
        assert_eq!(rl.requests_per_second, Some(100.0));
        assert_eq!(rl.burst_allowance, Some(20));
        assert_eq!(rl.limit_response_code, 429);
        assert_eq!(rl.limit_window_seconds, Some(60));
    }

    #[test]
    fn rate_limit_profile_with_none_optional_fields() {
        let rl = RateLimitProfile {
            requests_per_second: None,
            burst_allowance: None,
            limit_response_code: 429,
            limit_window_seconds: None,
        };
        assert!(rl.requests_per_second.is_none());
        assert!(rl.burst_allowance.is_none());
        assert_eq!(rl.limit_response_code, 429);
        assert!(rl.limit_window_seconds.is_none());
    }

    #[test]
    fn bot_detection_profile_fields_are_accessible() {
        let bd = sample_bot_detection();
        assert!(bd.detected);
        assert_eq!(bd.detection_method, "javascript_challenge");
        assert_eq!(bd.challenge_response_code, Some(503));
    }

    #[test]
    fn bot_detection_profile_not_detected() {
        let bd = BotDetectionProfile {
            detected: false,
            detection_method: "none".to_string(),
            challenge_response_code: None,
        };
        assert!(!bd.detected);
        assert_eq!(bd.detection_method, "none");
        assert!(bd.challenge_response_code.is_none());
    }

    #[test]
    fn full_defense_profile_serialization_roundtrip() {
        let profile = DefenseProfile::empty(9999)
            .with_waf(sample_waf())
            .with_rate_limit(sample_rate_limit())
            .with_bot_detection(sample_bot_detection());

        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: DefenseProfile = serde_json::from_str(&json).unwrap();

        assert_eq!(
            deserialized.fingerprint_timestamp_ms,
            profile.fingerprint_timestamp_ms
        );

        let waf = deserialized.waf.unwrap();
        assert_eq!(waf.vendor, WafVendor::Cloudflare);
        assert_eq!(waf.paranoia_level, Some(2));
        assert_eq!(waf.blocked_response_code, 403);
        assert_eq!(waf.blocked_categories.len(), 2);

        let rl = deserialized.rate_limit.unwrap();
        assert_eq!(rl.requests_per_second, Some(100.0));
        assert_eq!(rl.burst_allowance, Some(20));
        assert_eq!(rl.limit_response_code, 429);
        assert_eq!(rl.limit_window_seconds, Some(60));

        let bd = deserialized.bot_detection.unwrap();
        assert!(bd.detected);
        assert_eq!(bd.detection_method, "javascript_challenge");
        assert_eq!(bd.challenge_response_code, Some(503));
    }

    #[test]
    fn empty_profile_serialization_roundtrip() {
        let profile = DefenseProfile::empty(42);
        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: DefenseProfile = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.fingerprint_timestamp_ms, 42);
        assert!(deserialized.waf.is_none());
        assert!(deserialized.rate_limit.is_none());
        assert!(deserialized.bot_detection.is_none());
    }

    #[test]
    fn defense_type_clone_and_copy() {
        let dt = DefenseType::Waf;
        let cloned = dt.clone();
        let copied = dt;
        assert_eq!(dt, cloned);
        assert_eq!(dt, copied);
    }

    #[test]
    fn defense_type_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(DefenseType::Waf);
        set.insert(DefenseType::RateLimiter);
        set.insert(DefenseType::Waf);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn waf_vendor_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(WafVendor::Cloudflare);
        set.insert(WafVendor::AwsWaf);
        set.insert(WafVendor::Cloudflare);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn defense_profile_clone() {
        let profile = DefenseProfile::empty(1000)
            .with_waf(sample_waf())
            .with_rate_limit(sample_rate_limit());
        let cloned = profile.clone();
        assert_eq!(
            cloned.fingerprint_timestamp_ms,
            profile.fingerprint_timestamp_ms
        );
        assert!(cloned.waf.is_some());
        assert!(cloned.rate_limit.is_some());
        assert!(cloned.bot_detection.is_none());
    }
}
