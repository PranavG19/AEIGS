use super::adaptive_evasion::*;
use super::evasion_catalogue::{PayloadType, StealthLevel};
use super::waf_fingerprinter_v2::WafVendor;

fn success_feedback(technique_id: u32) -> EvasionFeedback {
    EvasionFeedback {
        technique_id,
        outcome: AdaptiveOutcome::Success,
        response_code: 200,
        latency_ms: 100,
        payload: "test".to_string(),
    }
}

fn blocked_feedback(technique_id: u32) -> EvasionFeedback {
    EvasionFeedback {
        technique_id,
        outcome: AdaptiveOutcome::Blocked,
        response_code: 403,
        latency_ms: 50,
        payload: "test".to_string(),
    }
}

fn rate_limited_feedback(technique_id: u32) -> EvasionFeedback {
    EvasionFeedback {
        technique_id,
        outcome: AdaptiveOutcome::RateLimited,
        response_code: 429,
        latency_ms: 30,
        payload: "test".to_string(),
    }
}

#[test]
fn test_starts_in_stealth_phase() {
    let controller = AdaptiveEvasionController::new();
    assert_eq!(controller.current_phase(), EscalationPhase::Stealth);
}

#[test]
fn test_next_action_returns_ghost_in_stealth() {
    let controller = AdaptiveEvasionController::new().with_payload_type(PayloadType::Sqli);
    let action = controller.next_action();
    assert!(action.is_some());
    let action = action.unwrap();
    assert_eq!(action.stealth_level, StealthLevel::Ghost);
}

#[test]
fn test_record_success_resets_blocks() {
    let mut controller = AdaptiveEvasionController::new();
    controller.record_feedback(blocked_feedback(1));
    controller.record_feedback(blocked_feedback(1));
    controller.record_feedback(success_feedback(2));
    let state = controller.state();
    assert_eq!(state.consecutive_blocks, 0);
}

#[test]
fn test_escalation_after_threshold() {
    let mut controller = AdaptiveEvasionController::new().with_escalation_threshold(2);

    assert_eq!(controller.current_phase(), EscalationPhase::Stealth);
    controller.record_feedback(blocked_feedback(1));
    controller.record_feedback(blocked_feedback(2));
    assert_eq!(controller.current_phase(), EscalationPhase::Moderate);
}

#[test]
fn test_escalation_progressive() {
    let mut controller = AdaptiveEvasionController::new().with_escalation_threshold(1);

    assert_eq!(controller.current_phase(), EscalationPhase::Stealth);
    controller.record_feedback(blocked_feedback(1));
    assert_eq!(controller.current_phase(), EscalationPhase::Moderate);
    controller.record_feedback(blocked_feedback(2));
    assert_eq!(controller.current_phase(), EscalationPhase::Aggressive);
    controller.record_feedback(blocked_feedback(3));
    assert_eq!(controller.current_phase(), EscalationPhase::AllOut);
    controller.record_feedback(blocked_feedback(4));
    assert_eq!(controller.current_phase(), EscalationPhase::AllOut);
}

#[test]
fn test_technique_blocked_after_repeated_failure() {
    let mut controller = AdaptiveEvasionController::new().with_escalation_threshold(10);

    controller.record_feedback(blocked_feedback(42));
    controller.record_feedback(blocked_feedback(42));
    assert!(controller.is_technique_blocked(42));
}

#[test]
fn test_blocked_technique_not_recommended() {
    let mut controller = AdaptiveEvasionController::new().with_payload_type(PayloadType::Sqli);

    controller.block_technique(21);
    controller.block_technique(22);
    controller.block_technique(23);

    let action = controller.next_action();
    if let Some(a) = action {
        assert_ne!(a.technique_id, 21);
        assert_ne!(a.technique_id, 22);
        assert_ne!(a.technique_id, 23);
    }
}

#[test]
fn test_vendor_filtering() {
    let controller = AdaptiveEvasionController::new()
        .with_vendor(WafVendor::Cloudflare)
        .with_payload_type(PayloadType::Xss);

    let action = controller.next_action();
    assert!(action.is_some());
}

#[test]
fn test_next_actions_multiple() {
    let controller = AdaptiveEvasionController::new().with_payload_type(PayloadType::Sqli);

    let actions = controller.next_actions(5);
    assert!(!actions.is_empty());
    assert!(actions.len() <= 5);

    for i in 0..actions.len() - 1 {
        assert!(actions[i].expected_success_rate >= actions[i + 1].expected_success_rate);
    }
}

#[test]
fn test_state_tracking() {
    let mut controller = AdaptiveEvasionController::new();

    controller.record_feedback(success_feedback(1));
    controller.record_feedback(success_feedback(2));
    controller.record_feedback(blocked_feedback(3));

    let state = controller.state();
    assert_eq!(state.total_attempts, 3);
    assert_eq!(state.total_successes, 2);
    assert_eq!(state.total_blocks, 1);
    assert!(state.overall_success_rate > 0.6);
}

#[test]
fn test_manual_escalate() {
    let mut controller = AdaptiveEvasionController::new();
    assert_eq!(controller.current_phase(), EscalationPhase::Stealth);
    controller.escalate();
    assert_eq!(controller.current_phase(), EscalationPhase::Moderate);
    controller.escalate();
    assert_eq!(controller.current_phase(), EscalationPhase::Aggressive);
}

#[test]
fn test_reset_phase() {
    let mut controller = AdaptiveEvasionController::new();
    controller.escalate();
    controller.escalate();
    assert_eq!(controller.current_phase(), EscalationPhase::Aggressive);
    controller.reset_phase();
    assert_eq!(controller.current_phase(), EscalationPhase::Stealth);
}

#[test]
fn test_manual_block_technique() {
    let mut controller = AdaptiveEvasionController::new();
    assert!(!controller.is_technique_blocked(99));
    controller.block_technique(99);
    assert!(controller.is_technique_blocked(99));
    assert_eq!(controller.blocked_technique_count(), 1);
}

#[test]
fn test_clear_blocked() {
    let mut controller = AdaptiveEvasionController::new();
    controller.block_technique(1);
    controller.block_technique(2);
    controller.block_technique(3);
    assert_eq!(controller.blocked_technique_count(), 3);
    controller.clear_blocked();
    assert_eq!(controller.blocked_technique_count(), 0);
}

#[test]
fn test_rate_limited_causes_escalation() {
    let mut controller = AdaptiveEvasionController::new().with_escalation_threshold(2);

    controller.record_feedback(rate_limited_feedback(1));
    controller.record_feedback(rate_limited_feedback(2));
    assert_eq!(controller.current_phase(), EscalationPhase::Moderate);
}

#[test]
fn test_success_rate_blending() {
    let mut controller = AdaptiveEvasionController::new().with_payload_type(PayloadType::Xss);

    controller.record_feedback(success_feedback(1));
    controller.record_feedback(success_feedback(1));
    controller.record_feedback(success_feedback(1));

    let action = controller.next_action();
    assert!(action.is_some());
}

#[test]
fn test_novelty_bonus_for_untried() {
    let mut controller = AdaptiveEvasionController::new().with_payload_type(PayloadType::Sqli);

    for _ in 0..5 {
        controller.record_feedback(success_feedback(21));
    }

    let actions = controller.next_actions(10);
    assert!(!actions.is_empty());
}

#[test]
fn test_escalation_display() {
    assert_eq!(format!("{}", EscalationPhase::Stealth), "stealth");
    assert_eq!(format!("{}", EscalationPhase::Moderate), "moderate");
    assert_eq!(format!("{}", EscalationPhase::Aggressive), "aggressive");
    assert_eq!(format!("{}", EscalationPhase::AllOut), "all-out");
}

#[test]
fn test_escalation_ordering() {
    assert!(EscalationPhase::Stealth < EscalationPhase::Moderate);
    assert!(EscalationPhase::Moderate < EscalationPhase::Aggressive);
    assert!(EscalationPhase::Aggressive < EscalationPhase::AllOut);
}

#[test]
fn test_all_outcome_variants() {
    let mut controller = AdaptiveEvasionController::new().with_escalation_threshold(100);

    let outcomes = vec![
        AdaptiveOutcome::Success,
        AdaptiveOutcome::Blocked,
        AdaptiveOutcome::RateLimited,
        AdaptiveOutcome::Detected,
        AdaptiveOutcome::Timeout,
        AdaptiveOutcome::Error,
    ];
    for (i, outcome) in outcomes.into_iter().enumerate() {
        controller.record_feedback(EvasionFeedback {
            technique_id: (i + 100) as u32,
            outcome,
            response_code: 200,
            latency_ms: 50,
            payload: "test".to_string(),
        });
    }
    assert_eq!(controller.state().total_attempts, 6);
}

#[test]
fn test_controller_state_serializable() {
    let mut controller = AdaptiveEvasionController::new();
    controller.record_feedback(success_feedback(1));
    controller.record_feedback(blocked_feedback(2));

    let state = controller.state();
    let json = serde_json::to_string(&state).unwrap();
    let deserialized: ControllerState = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.total_attempts, 2);
    assert_eq!(deserialized.total_successes, 1);
}

#[test]
fn test_action_has_reasoning() {
    let controller = AdaptiveEvasionController::new()
        .with_vendor(WafVendor::Cloudflare)
        .with_payload_type(PayloadType::Xss);

    let action = controller.next_action();
    assert!(action.is_some());
    assert!(!action.unwrap().reasoning.is_empty());
}

#[test]
fn test_moderate_phase_allows_stealthy() {
    let mut controller = AdaptiveEvasionController::new().with_payload_type(PayloadType::Sqli);

    controller.escalate();
    assert_eq!(controller.current_phase(), EscalationPhase::Moderate);

    let action = controller.next_action();
    assert!(action.is_some());
    let a = action.unwrap();
    assert!(a.stealth_level >= StealthLevel::Stealthy);
}

#[test]
fn test_all_out_allows_loud() {
    let mut controller = AdaptiveEvasionController::new().with_payload_type(PayloadType::Xss);

    controller.escalate();
    controller.escalate();
    controller.escalate();
    assert_eq!(controller.current_phase(), EscalationPhase::AllOut);

    let actions = controller.next_actions(20);
    assert!(!actions.is_empty());
}

#[test]
fn test_feedback_updates_score() {
    let mut controller = AdaptiveEvasionController::new().with_payload_type(PayloadType::Sqli);

    controller.record_feedback(success_feedback(21));
    controller.record_feedback(success_feedback(21));
    controller.record_feedback(success_feedback(21));

    controller.escalate();
    controller.escalate();
    controller.escalate();

    let actions = controller.next_actions(20);
    let tech_21 = actions.iter().find(|a| a.technique_id == 21);
    if let Some(t) = tech_21 {
        assert!(t.expected_success_rate > 0.5);
    }
}
