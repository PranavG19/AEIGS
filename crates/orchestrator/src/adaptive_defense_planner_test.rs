use super::adaptive_defense_planner::*;
use aegis_protocol::defense_context::DefenseContext;
use aegis_protocol::finding::VulnerabilityClass;
use std::collections::HashMap;

fn waf_defense() -> DefenseContext {
    DefenseContext {
        has_waf: true,
        waf_vendor: Some("ModSecurity".to_string()),
        waf_blocked_categories: vec![
            VulnerabilityClass::SqlInjection,
            VulnerabilityClass::CrossSiteScripting,
        ],
        rate_limit_rps: Some(10.0),
        bot_detection_present: true,
        bot_detection_evaded: false,
    }
}

fn blocked_batch(batch_id: u64) -> BatchOutcome {
    BatchOutcome {
        batch_id,
        total_requests: 20,
        blocked_count: 15,
        rate_limited_count: 0,
        bot_detected_count: 0,
        successful_count: 5,
        block_signatures: vec![BlockSignature {
            status_code: 403,
            body_fingerprint: "ModSecurity action".to_string(),
            matched_rule_id: Some("942100".to_string()),
            blocked_parameter: Some("id".to_string()),
            blocked_pattern: None,
        }],
        response_codes: HashMap::from([(403, 15), (200, 5)]),
    }
}

fn rate_limited_batch(batch_id: u64) -> BatchOutcome {
    BatchOutcome {
        batch_id,
        total_requests: 50,
        blocked_count: 0,
        rate_limited_count: 30,
        bot_detected_count: 0,
        successful_count: 20,
        block_signatures: vec![BlockSignature {
            status_code: 429,
            body_fingerprint: "rate limit exceeded".to_string(),
            matched_rule_id: None,
            blocked_parameter: None,
            blocked_pattern: None,
        }],
        response_codes: HashMap::from([(429, 30), (200, 20)]),
    }
}

fn bot_detected_batch(batch_id: u64) -> BatchOutcome {
    BatchOutcome {
        batch_id,
        total_requests: 10,
        blocked_count: 8,
        rate_limited_count: 0,
        bot_detected_count: 8,
        successful_count: 2,
        block_signatures: vec![BlockSignature {
            status_code: 403,
            body_fingerprint: "bot detected captcha required".to_string(),
            matched_rule_id: Some("bot-check-001".to_string()),
            blocked_parameter: None,
            blocked_pattern: None,
        }],
        response_codes: HashMap::from([(403, 8), (200, 2)]),
    }
}

#[test]
fn initial_replan_produces_policy() {
    let mut planner = AdaptiveDefensePlanner::new(waf_defense());
    let policy = planner.replan(blocked_batch(1));

    assert_eq!(policy.generation, 1);
    assert!(!policy.techniques.is_empty());
    assert!(!policy.reasoning.is_empty());
    assert!(policy.estimated_bypass_probability > 0.0);
    assert!(policy.estimated_bypass_probability <= 1.0);
}

#[test]
fn generation_increments_per_replan() {
    let mut planner = AdaptiveDefensePlanner::new(waf_defense());
    let p1 = planner.replan(blocked_batch(1));
    let p2 = planner.replan(blocked_batch(2));
    let p3 = planner.replan(blocked_batch(3));

    assert_eq!(p1.generation, 1);
    assert_eq!(p2.generation, 2);
    assert_eq!(p3.generation, 3);
    assert_eq!(planner.current_generation(), 3);
}

#[test]
fn rate_limit_triggers_timing_adjustment() {
    let mut planner = AdaptiveDefensePlanner::new(waf_defense());
    let policy = planner.replan(rate_limited_batch(1));

    assert!(policy.timing_config.base_delay_ms > 100);
    assert!(policy.timing_config.burst_size <= 3);

    let has_throttle = policy
        .techniques
        .iter()
        .any(|t| t.category == EvasionCategory::TimingControl);
    assert!(has_throttle);
}

#[test]
fn bot_detection_triggers_persona_rotation() {
    let mut planner = AdaptiveDefensePlanner::new(waf_defense());
    let policy = planner.replan(bot_detected_batch(1));

    let has_rotation = policy
        .techniques
        .iter()
        .any(|t| t.category == EvasionCategory::IdentityRotation);
    assert!(has_rotation);

    assert!(policy.header_overrides.contains_key("Accept-Language"));
}

#[test]
fn waf_keyword_match_adds_payload_transforms() {
    let mut planner = AdaptiveDefensePlanner::new(waf_defense());
    let policy = planner.replan(blocked_batch(1));

    assert!(!policy.payload_transforms.is_empty());
    let has_case = policy
        .payload_transforms
        .iter()
        .any(|t| t.name.contains("case"));
    assert!(has_case);
}

#[test]
fn history_tracks_outcomes() {
    let mut planner = AdaptiveDefensePlanner::new(waf_defense());
    planner.replan(blocked_batch(1));
    planner.replan(blocked_batch(2));

    assert_eq!(planner.history().total_generations(), 2);
}

#[test]
fn block_rate_calculated() {
    let mut planner = AdaptiveDefensePlanner::new(waf_defense());
    planner.replan(blocked_batch(1));

    assert!((planner.history().last_block_rate() - 0.75).abs() < 0.01);
}

#[test]
fn improving_trend_detected() {
    let mut planner = AdaptiveDefensePlanner::new(waf_defense());

    let heavy_block = BatchOutcome {
        batch_id: 1,
        total_requests: 20,
        blocked_count: 18,
        rate_limited_count: 0,
        bot_detected_count: 0,
        successful_count: 2,
        block_signatures: vec![BlockSignature {
            status_code: 403,
            body_fingerprint: "blocked".to_string(),
            matched_rule_id: Some("rule-1".to_string()),
            blocked_parameter: None,
            blocked_pattern: None,
        }],
        response_codes: HashMap::from([(403, 18), (200, 2)]),
    };

    let lighter_block = BatchOutcome {
        batch_id: 2,
        total_requests: 20,
        blocked_count: 5,
        rate_limited_count: 0,
        bot_detected_count: 0,
        successful_count: 15,
        block_signatures: vec![BlockSignature {
            status_code: 403,
            body_fingerprint: "blocked".to_string(),
            matched_rule_id: Some("rule-1".to_string()),
            blocked_parameter: None,
            blocked_pattern: None,
        }],
        response_codes: HashMap::from([(403, 5), (200, 15)]),
    };

    planner.replan(heavy_block);
    planner.replan(lighter_block);

    assert_eq!(planner.history().trend(), BlockTrend::Improving);
}

#[test]
fn worsening_trend_detected() {
    let mut planner = AdaptiveDefensePlanner::new(waf_defense());

    let light = BatchOutcome {
        batch_id: 1,
        total_requests: 20,
        blocked_count: 3,
        rate_limited_count: 0,
        bot_detected_count: 0,
        successful_count: 17,
        block_signatures: vec![],
        response_codes: HashMap::from([(403, 3), (200, 17)]),
    };

    let heavy = BatchOutcome {
        batch_id: 2,
        total_requests: 20,
        blocked_count: 16,
        rate_limited_count: 0,
        bot_detected_count: 0,
        successful_count: 4,
        block_signatures: vec![BlockSignature {
            status_code: 403,
            body_fingerprint: "blocked".to_string(),
            matched_rule_id: Some("rule-1".to_string()),
            blocked_parameter: None,
            blocked_pattern: None,
        }],
        response_codes: HashMap::from([(403, 16), (200, 4)]),
    };

    planner.replan(light);
    planner.replan(heavy);

    assert_eq!(planner.history().trend(), BlockTrend::Worsening);
}

#[test]
fn content_type_block_adds_header_override() {
    let mut planner = AdaptiveDefensePlanner::new(waf_defense());
    let outcome = BatchOutcome {
        batch_id: 1,
        total_requests: 10,
        blocked_count: 10,
        rate_limited_count: 0,
        bot_detected_count: 0,
        successful_count: 0,
        block_signatures: vec![BlockSignature {
            status_code: 415,
            body_fingerprint: "unsupported media type".to_string(),
            matched_rule_id: None,
            blocked_parameter: None,
            blocked_pattern: None,
        }],
        response_codes: HashMap::from([(415, 10)]),
    };

    let policy = planner.replan(outcome);
    assert!(policy.header_overrides.contains_key("Content-Type"));
}

#[test]
fn payload_length_block_adds_chunking() {
    let mut planner = AdaptiveDefensePlanner::new(waf_defense());
    let outcome = BatchOutcome {
        batch_id: 1,
        total_requests: 10,
        blocked_count: 10,
        rate_limited_count: 0,
        bot_detected_count: 0,
        successful_count: 0,
        block_signatures: vec![BlockSignature {
            status_code: 413,
            body_fingerprint: "payload too large".to_string(),
            matched_rule_id: None,
            blocked_parameter: None,
            blocked_pattern: None,
        }],
        response_codes: HashMap::from([(413, 10)]),
    };

    let policy = planner.replan(outcome);
    let has_chunking = policy
        .techniques
        .iter()
        .any(|t| t.name.contains("chunking"));
    assert!(has_chunking);
}

#[test]
fn regex_pattern_match_adds_encoding() {
    let mut planner = AdaptiveDefensePlanner::new(waf_defense());
    let outcome = BatchOutcome {
        batch_id: 1,
        total_requests: 10,
        blocked_count: 8,
        rate_limited_count: 0,
        bot_detected_count: 0,
        successful_count: 2,
        block_signatures: vec![BlockSignature {
            status_code: 403,
            body_fingerprint: "forbidden".to_string(),
            matched_rule_id: None,
            blocked_parameter: Some("query".to_string()),
            blocked_pattern: Some("(union|select)".to_string()),
        }],
        response_codes: HashMap::from([(403, 8), (200, 2)]),
    };

    let policy = planner.replan(outcome);
    let has_encoding = policy
        .techniques
        .iter()
        .any(|t| t.name.contains("encoding"));
    assert!(has_encoding);
}

#[test]
fn empty_batch_no_panic() {
    let mut planner = AdaptiveDefensePlanner::new(DefenseContext::default());
    let outcome = BatchOutcome {
        batch_id: 1,
        total_requests: 0,
        blocked_count: 0,
        rate_limited_count: 0,
        bot_detected_count: 0,
        successful_count: 0,
        block_signatures: Vec::new(),
        response_codes: HashMap::new(),
    };

    let policy = planner.replan(outcome);
    assert_eq!(policy.generation, 1);
}

#[test]
fn update_defense_context() {
    let mut planner = AdaptiveDefensePlanner::new(DefenseContext::default());
    planner.update_defense_context(waf_defense());
    let policy = planner.replan(blocked_batch(1));
    assert!(!policy.reasoning.is_empty());
}

#[test]
fn policy_id_format() {
    let mut planner = AdaptiveDefensePlanner::new(waf_defense());
    let policy = planner.replan(blocked_batch(1));
    assert!(policy.policy_id.starts_with("evasion-policy-gen-"));
    assert!(policy.policy_id.contains("001"));
}

#[test]
fn successive_replans_increase_timing_delay() {
    let mut planner = AdaptiveDefensePlanner::new(waf_defense());

    let p1 = planner.replan(rate_limited_batch(1));
    let p2 = planner.replan(rate_limited_batch(2));

    assert!(p2.timing_config.base_delay_ms >= p1.timing_config.base_delay_ms);
}

#[test]
fn insufficient_trend_with_single_generation() {
    let mut planner = AdaptiveDefensePlanner::new(waf_defense());
    planner.replan(blocked_batch(1));
    assert_eq!(planner.history().trend(), BlockTrend::Insufficient);
}

#[test]
fn unknown_block_gets_broad_spectrum() {
    let mut planner = AdaptiveDefensePlanner::new(waf_defense());
    let outcome = BatchOutcome {
        batch_id: 1,
        total_requests: 10,
        blocked_count: 10,
        rate_limited_count: 0,
        bot_detected_count: 0,
        successful_count: 0,
        block_signatures: vec![BlockSignature {
            status_code: 503,
            body_fingerprint: "service unavailable".to_string(),
            matched_rule_id: None,
            blocked_parameter: None,
            blocked_pattern: None,
        }],
        response_codes: HashMap::from([(503, 10)]),
    };

    let policy = planner.replan(outcome);
    let has_broad = policy
        .payload_transforms
        .iter()
        .any(|t| t.name.contains("broad_spectrum"));
    assert!(has_broad);
}
