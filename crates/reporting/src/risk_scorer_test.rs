#[cfg(test)]
mod tests {
    use crate::risk_scorer::{
        DefenseScoreContext, RiskInput, ScoredFinding, compute_effective_severity,
        compute_risk_score, rank_findings, score_with_defense, sort_by_confidence,
        top_remediation_targets,
    };
    use aegis_fuzzing::{
        BotDetectionProfile, DefenseProfile, RateLimitProfile, WafProfile, WafVendor,
    };
    use aegis_protocol::finding::VulnerabilityClass;

    fn default_input() -> RiskInput {
        RiskInput {
            vulnerability_class: VulnerabilityClass::SqlInjection,
            cvss_exploitability: 8.0,
            is_authenticated: false,
            is_rate_limited: false,
            has_waf: false,
            attack_path_count: 5,
            reachable_critical_assets: 3,
            asset_pii_weight: 1.0,
            confidence: 0.9,
        }
    }

    fn waf_input() -> RiskInput {
        RiskInput {
            vulnerability_class: VulnerabilityClass::SqlInjection,
            cvss_exploitability: 8.0,
            is_authenticated: false,
            is_rate_limited: false,
            has_waf: true,
            attack_path_count: 5,
            reachable_critical_assets: 3,
            asset_pii_weight: 1.0,
            confidence: 0.9,
        }
    }

    fn rate_limited_input() -> RiskInput {
        RiskInput {
            vulnerability_class: VulnerabilityClass::SqlInjection,
            cvss_exploitability: 8.0,
            is_authenticated: false,
            is_rate_limited: true,
            has_waf: false,
            attack_path_count: 5,
            reachable_critical_assets: 3,
            asset_pii_weight: 1.0,
            confidence: 0.9,
        }
    }

    fn sqli_blocking_waf() -> WafProfile {
        WafProfile {
            vendor: WafVendor::ModSecurity,
            paranoia_level: Some(2),
            blocked_response_code: 403,
            blocked_categories: vec![VulnerabilityClass::SqlInjection],
        }
    }

    fn non_sqli_blocking_waf() -> WafProfile {
        WafProfile {
            vendor: WafVendor::Cloudflare,
            paranoia_level: Some(1),
            blocked_response_code: 403,
            blocked_categories: vec![VulnerabilityClass::CrossSiteScripting],
        }
    }

    #[test]
    fn basic_risk_score_is_positive() {
        let score = compute_risk_score(&default_input());
        assert!(score.composite > 0.0);
        assert!(score.composite <= 100.0);
    }

    #[test]
    fn exploitability_clamped_to_ten() {
        let mut input = default_input();
        input.cvss_exploitability = 15.0;
        let score = compute_risk_score(&input);
        assert!(score.exploitability <= 10.0);
    }

    #[test]
    fn authentication_reduces_exploitability() {
        let unauthenticated = compute_risk_score(&default_input());
        let mut input = default_input();
        input.is_authenticated = true;
        let authenticated = compute_risk_score(&input);
        assert!(authenticated.exploitability < unauthenticated.exploitability);
    }

    #[test]
    fn rate_limiting_reduces_exploitability() {
        let base = compute_risk_score(&default_input());
        let mut input = default_input();
        input.is_rate_limited = true;
        let limited = compute_risk_score(&input);
        assert!(limited.exploitability < base.exploitability);
    }

    #[test]
    fn waf_reduces_exploitability() {
        let base = compute_risk_score(&default_input());
        let mut input = default_input();
        input.has_waf = true;
        let waf = compute_risk_score(&input);
        assert!(waf.exploitability < base.exploitability);
    }

    #[test]
    fn all_mitigations_stack() {
        let mut input = default_input();
        input.is_authenticated = true;
        input.is_rate_limited = true;
        input.has_waf = true;
        let score = compute_risk_score(&input);
        assert!(score.exploitability < 8.0 * 0.7 * 0.8 * 0.6 + 0.01);
    }

    #[test]
    fn zero_attack_paths_gives_zero_reachability() {
        let mut input = default_input();
        input.attack_path_count = 0;
        let score = compute_risk_score(&input);
        assert_eq!(score.reachability, 0.0);
        assert_eq!(score.composite, 0.0);
    }

    #[test]
    fn more_paths_increases_reachability() {
        let mut few = default_input();
        few.attack_path_count = 2;
        let mut many = default_input();
        many.attack_path_count = 100;

        let score_few = compute_risk_score(&few);
        let score_many = compute_risk_score(&many);
        assert!(score_many.reachability > score_few.reachability);
    }

    #[test]
    fn reachability_capped_at_ten() {
        let mut input = default_input();
        input.attack_path_count = u32::MAX;
        let score = compute_risk_score(&input);
        assert!(score.reachability <= 10.0);
    }

    #[test]
    fn blast_radius_increases_with_assets() {
        let mut low = default_input();
        low.reachable_critical_assets = 1;
        let mut high = default_input();
        high.reachable_critical_assets = 10;

        let score_low = compute_risk_score(&low);
        let score_high = compute_risk_score(&high);
        assert!(score_high.blast_radius > score_low.blast_radius);
    }

    #[test]
    fn pii_weight_amplifies_blast_radius() {
        let mut low_pii = default_input();
        low_pii.asset_pii_weight = 0.5;
        let mut high_pii = default_input();
        high_pii.asset_pii_weight = 2.0;

        let score_low = compute_risk_score(&low_pii);
        let score_high = compute_risk_score(&high_pii);
        assert!(score_high.blast_radius > score_low.blast_radius);
    }

    #[test]
    fn confidence_scales_composite() {
        let mut high_conf = default_input();
        high_conf.confidence = 1.0;
        let mut low_conf = default_input();
        low_conf.confidence = 0.5;

        let score_high = compute_risk_score(&high_conf);
        let score_low = compute_risk_score(&low_conf);
        assert!(score_high.composite > score_low.composite);
    }

    #[test]
    fn confidence_clamped_to_zero_one() {
        let mut input = default_input();
        input.confidence = 5.0;
        let score = compute_risk_score(&input);
        assert!(score.confidence <= 1.0);
    }

    #[test]
    fn rank_findings_descending_order() {
        let mut high = default_input();
        high.cvss_exploitability = 9.0;
        high.attack_path_count = 10;

        let mut low = default_input();
        low.cvss_exploitability = 2.0;
        low.attack_path_count = 1;

        let ranked = rank_findings(&[low, high]);
        assert_eq!(ranked[0].0, 1);
        assert_eq!(ranked[1].0, 0);
        assert!(ranked[0].1.composite >= ranked[1].1.composite);
    }

    #[test]
    fn top_remediation_targets_respects_budget() {
        let inputs = vec![default_input(), default_input(), default_input()];
        let targets = top_remediation_targets(&inputs, 2);
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn top_remediation_targets_empty_input() {
        let targets = top_remediation_targets(&[], 5);
        assert!(targets.is_empty());
    }

    #[test]
    fn zero_budget_returns_empty() {
        let targets = top_remediation_targets(&[default_input()], 0);
        assert!(targets.is_empty());
    }

    #[test]
    fn composite_score_range() {
        let mut input = default_input();
        input.cvss_exploitability = 10.0;
        input.attack_path_count = 1000;
        input.reachable_critical_assets = 10;
        input.asset_pii_weight = 2.0;
        input.confidence = 1.0;

        let score = compute_risk_score(&input);
        assert!(score.composite >= 0.0);
        assert!(score.composite <= 100.0);
    }

    #[test]
    fn test_defense_score_context_derives() {
        let ctx = DefenseScoreContext {
            waf_present: true,
            waf_bypassed: false,
            bypass_technique: Some("encoding".to_string()),
            rate_limit_present: true,
            bot_detection_present: false,
            bot_detection_evaded: false,
        };

        let cloned = ctx.clone();
        assert_eq!(format!("{:?}", ctx), format!("{:?}", cloned));
    }

    #[test]
    fn test_defense_score_context_serialization_roundtrip() {
        let ctx = DefenseScoreContext {
            waf_present: true,
            waf_bypassed: true,
            bypass_technique: Some("double-encoding".to_string()),
            rate_limit_present: false,
            bot_detection_present: true,
            bot_detection_evaded: false,
        };

        let json = serde_json::to_string(&ctx).unwrap();
        let deserialized: DefenseScoreContext = serde_json::from_str(&json).unwrap();

        assert_eq!(format!("{:?}", ctx), format!("{:?}", deserialized));
    }

    #[test]
    fn test_scored_finding_has_defense_context() {
        let input = waf_input();
        let defense = DefenseProfile::empty(1000).with_waf(sqli_blocking_waf());

        let scored = score_with_defense(&input, &defense, false, None);
        assert!(scored.defense_context.is_some());

        let ctx = scored.defense_context.unwrap();
        assert!(ctx.waf_present);
        assert!(!ctx.waf_bypassed);
    }

    #[test]
    fn test_scored_finding_without_defense_context() {
        let scored = ScoredFinding {
            finding_id: 42,
            composite_score: 5.0,
            exploitability: 3.0,
            reachability: 2.0,
            blast_radius: 1.0,
            confidence: 0.8,
            defense_context: None,
        };

        assert!(scored.defense_context.is_none());
        assert_eq!(scored.finding_id, 42);
    }

    #[test]
    fn test_score_with_no_defenses() {
        let input = default_input();
        let defense = DefenseProfile::empty(1000);

        let base = compute_risk_score(&input);
        let scored = score_with_defense(&input, &defense, false, None);

        let epsilon = 1e-10;
        assert!((scored.composite_score - base.composite).abs() < epsilon);
        assert!((scored.exploitability - base.exploitability).abs() < epsilon);
        assert!((scored.reachability - base.reachability).abs() < epsilon);
        assert!((scored.blast_radius - base.blast_radius).abs() < epsilon);
        assert!((scored.confidence - base.confidence).abs() < epsilon);
    }

    #[test]
    fn test_score_with_waf_evasion_succeeded() {
        let input = waf_input();
        let defense = DefenseProfile::empty(1000).with_waf(sqli_blocking_waf());

        let scored = score_with_defense(&input, &defense, true, Some("encoding".to_string()));

        let base_exploitability = 8.0 * 0.6;
        let undone = base_exploitability / 0.6;
        let epsilon = 1e-10;
        assert!((scored.exploitability - undone).abs() < epsilon);

        let ctx = scored.defense_context.unwrap();
        assert!(ctx.waf_bypassed);
        assert_eq!(ctx.bypass_technique, Some("encoding".to_string()));
    }

    #[test]
    fn test_score_with_waf_evasion_failed_blocked_category() {
        let input = waf_input();
        let defense = DefenseProfile::empty(1000).with_waf(sqli_blocking_waf());

        let scored = score_with_defense(&input, &defense, false, None);

        let base_exploitability = 8.0 * 0.6;
        let undone = base_exploitability / 0.6;
        let expected = undone * 0.3;
        let epsilon = 1e-10;
        assert!((scored.exploitability - expected).abs() < epsilon);
    }

    #[test]
    fn test_score_with_waf_evasion_failed_unblocked_category() {
        let input = waf_input();
        let defense = DefenseProfile::empty(1000).with_waf(non_sqli_blocking_waf());

        let scored = score_with_defense(&input, &defense, false, None);

        let base_exploitability = 8.0 * 0.6;
        let undone = base_exploitability / 0.6;
        let expected = undone * 0.8;
        let epsilon = 1e-10;
        assert!((scored.exploitability - expected).abs() < epsilon);
    }

    #[test]
    fn test_score_with_rate_limit_strict() {
        let input = rate_limited_input();
        let rl = RateLimitProfile {
            requests_per_second: Some(5.0),
            burst_allowance: Some(10),
            limit_response_code: 429,
            limit_window_seconds: Some(60),
        };
        let defense = DefenseProfile::empty(1000).with_rate_limit(rl);

        let scored = score_with_defense(&input, &defense, false, None);

        let base_exploitability = 8.0 * 0.8;
        let undone = base_exploitability / 0.8;
        let expected = undone * 0.6;
        let epsilon = 1e-10;
        assert!((scored.exploitability - expected).abs() < epsilon);
    }

    #[test]
    fn test_score_with_rate_limit_loose() {
        let input = rate_limited_input();
        let rl = RateLimitProfile {
            requests_per_second: Some(200.0),
            burst_allowance: Some(500),
            limit_response_code: 429,
            limit_window_seconds: Some(60),
        };
        let defense = DefenseProfile::empty(1000).with_rate_limit(rl);

        let scored = score_with_defense(&input, &defense, false, None);

        let base_exploitability = 8.0 * 0.8;
        let undone = base_exploitability / 0.8;
        let expected = undone * 0.95;
        let epsilon = 1e-10;
        assert!((scored.exploitability - expected).abs() < epsilon);
    }

    #[test]
    fn test_score_with_rate_limit_medium() {
        let input = rate_limited_input();
        let rl = RateLimitProfile {
            requests_per_second: Some(50.0),
            burst_allowance: Some(100),
            limit_response_code: 429,
            limit_window_seconds: Some(60),
        };
        let defense = DefenseProfile::empty(1000).with_rate_limit(rl);

        let scored = score_with_defense(&input, &defense, false, None);

        let base_exploitability = 8.0 * 0.8;
        let undone = base_exploitability / 0.8;
        let expected_factor = 0.6 + (50.0 - 10.0) / 90.0 * 0.35;
        let expected = undone * expected_factor;
        let epsilon = 1e-10;
        assert!((scored.exploitability - expected).abs() < epsilon);
    }

    #[test]
    fn test_score_with_bot_detection_evaded() {
        let input = default_input();
        let bd = BotDetectionProfile {
            detected: true,
            detection_method: "fingerprint".to_string(),
            challenge_response_code: Some(403),
        };
        let defense = DefenseProfile::empty(1000).with_bot_detection(bd);

        let base = compute_risk_score(&input);
        let scored = score_with_defense(&input, &defense, true, None);

        let epsilon = 1e-10;
        assert!((scored.exploitability - base.exploitability).abs() < epsilon);

        let ctx = scored.defense_context.unwrap();
        assert!(ctx.bot_detection_present);
        assert!(ctx.bot_detection_evaded);
    }

    #[test]
    fn test_score_with_bot_detection_not_evaded() {
        let input = default_input();
        let bd = BotDetectionProfile {
            detected: true,
            detection_method: "fingerprint".to_string(),
            challenge_response_code: Some(403),
        };
        let defense = DefenseProfile::empty(1000).with_bot_detection(bd);

        let base = compute_risk_score(&input);
        let scored = score_with_defense(&input, &defense, false, None);

        let expected = base.exploitability * 0.5;
        let epsilon = 1e-10;
        assert!((scored.exploitability - expected).abs() < epsilon);

        let ctx = scored.defense_context.unwrap();
        assert!(ctx.bot_detection_present);
        assert!(!ctx.bot_detection_evaded);
    }

    #[test]
    fn test_score_with_all_defenses() {
        let mut input = default_input();
        input.has_waf = true;
        input.is_rate_limited = true;

        let waf = sqli_blocking_waf();
        let rl = RateLimitProfile {
            requests_per_second: Some(5.0),
            burst_allowance: Some(10),
            limit_response_code: 429,
            limit_window_seconds: Some(60),
        };
        let bd = BotDetectionProfile {
            detected: true,
            detection_method: "captcha".to_string(),
            challenge_response_code: Some(429),
        };

        let defense = DefenseProfile::empty(1000)
            .with_waf(waf)
            .with_rate_limit(rl)
            .with_bot_detection(bd);

        let scored = score_with_defense(&input, &defense, false, None);

        let base_exploitability = 8.0 * 0.7_f64.powf(0.0) * 0.8 * 0.6;
        let waf_undone = base_exploitability / 0.6;
        let after_waf = waf_undone * 0.3;
        let rl_undone = after_waf / 0.8;
        let after_rl = rl_undone * 0.6;
        let after_bd = after_rl * 0.5;

        let epsilon = 1e-10;
        assert!((scored.exploitability - after_bd).abs() < epsilon);

        let ctx = scored.defense_context.as_ref().unwrap();
        assert!(ctx.waf_present);
        assert!(!ctx.waf_bypassed);
        assert!(ctx.rate_limit_present);
        assert!(ctx.bot_detection_present);
        assert!(!ctx.bot_detection_evaded);
    }

    #[test]
    fn test_waf_present_but_input_has_waf_false() {
        let input = default_input();
        let defense = DefenseProfile::empty(1000).with_waf(sqli_blocking_waf());

        let base = compute_risk_score(&input);
        let scored = score_with_defense(&input, &defense, false, None);

        let epsilon = 1e-10;
        assert!((scored.exploitability - base.exploitability).abs() < epsilon);
    }

    #[test]
    fn test_rate_limit_present_but_input_not_rate_limited() {
        let input = default_input();
        let rl = RateLimitProfile {
            requests_per_second: Some(50.0),
            burst_allowance: Some(100),
            limit_response_code: 429,
            limit_window_seconds: Some(60),
        };
        let defense = DefenseProfile::empty(1000).with_rate_limit(rl);

        let scored = score_with_defense(&input, &defense, false, None);

        let expected_factor = 0.6 + (50.0 - 10.0) / 90.0 * 0.35;
        let expected = 8.0 * expected_factor;
        let epsilon = 1e-10;
        assert!((scored.exploitability - expected).abs() < epsilon);
    }

    #[test]
    fn test_rate_limit_with_no_requests_per_second() {
        let input = rate_limited_input();
        let rl = RateLimitProfile {
            requests_per_second: None,
            burst_allowance: None,
            limit_response_code: 429,
            limit_window_seconds: None,
        };
        let defense = DefenseProfile::empty(1000).with_rate_limit(rl);

        let scored = score_with_defense(&input, &defense, false, None);

        let base_exploitability = 8.0 * 0.8;
        let undone = base_exploitability / 0.8;
        let expected = undone * 0.8;
        let epsilon = 1e-10;
        assert!((scored.exploitability - expected).abs() < epsilon);
    }

    #[test]
    fn test_bot_detection_present_but_not_detected() {
        let input = default_input();
        let bd = BotDetectionProfile {
            detected: false,
            detection_method: "fingerprint".to_string(),
            challenge_response_code: None,
        };
        let defense = DefenseProfile::empty(1000).with_bot_detection(bd);

        let base = compute_risk_score(&input);
        let scored = score_with_defense(&input, &defense, false, None);

        let epsilon = 1e-10;
        assert!((scored.exploitability - base.exploitability).abs() < epsilon);
    }

    #[test]
    fn test_score_with_defense_returns_scored_finding_with_context() {
        let input = waf_input();
        let defense = DefenseProfile::empty(1000).with_waf(sqli_blocking_waf());

        let scored = score_with_defense(&input, &defense, true, Some("chunked".to_string()));

        assert_eq!(scored.finding_id, 0);
        assert!(scored.composite_score >= 0.0);
        assert!(scored.composite_score <= 100.0);
        assert!(scored.exploitability >= 0.0);
        assert!(scored.exploitability <= 10.0);
        assert!(scored.reachability >= 0.0);
        assert!(scored.blast_radius >= 0.0);
        assert!(scored.confidence >= 0.0);
        assert!(scored.confidence <= 1.0);

        let ctx = scored.defense_context.unwrap();
        assert!(ctx.waf_present);
        assert!(ctx.waf_bypassed);
        assert_eq!(ctx.bypass_technique, Some("chunked".to_string()));
        assert!(!ctx.rate_limit_present);
        assert!(!ctx.bot_detection_present);
        assert!(!ctx.bot_detection_evaded);
    }

    #[test]
    fn test_effective_severity_full_confidence() {
        let severity = 8.0;
        let effective = compute_effective_severity(severity, 1.0);
        let epsilon = 1e-10;
        assert!((effective - 8.0).abs() < epsilon);
    }

    #[test]
    fn test_effective_severity_half_confidence() {
        let severity = 8.0;
        let effective = compute_effective_severity(severity, 0.5);
        let epsilon = 1e-10;
        assert!((effective - 4.0).abs() < epsilon);
    }

    #[test]
    fn test_sort_by_confidence_descending() {
        let mut findings = vec![
            ScoredFinding {
                finding_id: 1,
                composite_score: 50.0,
                exploitability: 5.0,
                reachability: 5.0,
                blast_radius: 5.0,
                confidence: 0.3,
                defense_context: None,
            },
            ScoredFinding {
                finding_id: 2,
                composite_score: 40.0,
                exploitability: 4.0,
                reachability: 4.0,
                blast_radius: 4.0,
                confidence: 0.9,
                defense_context: None,
            },
            ScoredFinding {
                finding_id: 3,
                composite_score: 60.0,
                exploitability: 6.0,
                reachability: 6.0,
                blast_radius: 6.0,
                confidence: 0.6,
                defense_context: None,
            },
        ];

        sort_by_confidence(&mut findings);

        assert_eq!(findings[0].finding_id, 2);
        assert_eq!(findings[1].finding_id, 3);
        assert_eq!(findings[2].finding_id, 1);
    }
}
