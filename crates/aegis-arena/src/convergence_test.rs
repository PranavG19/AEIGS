use super::*;

// ─── Escalation tier tests ──────────────────────────────────────────────────

#[test]
fn escalation_tier_basic_rounds() {
    assert_eq!(EscalationTier::for_round(1), EscalationTier::Basic);
    assert_eq!(EscalationTier::for_round(3), EscalationTier::Basic);
    assert_eq!(EscalationTier::for_round(5), EscalationTier::Basic);
}

#[test]
fn escalation_tier_expanded_rounds() {
    assert_eq!(EscalationTier::for_round(6), EscalationTier::Expanded);
    assert_eq!(EscalationTier::for_round(8), EscalationTier::Expanded);
    assert_eq!(EscalationTier::for_round(10), EscalationTier::Expanded);
}

#[test]
fn escalation_tier_evasion_rounds() {
    assert_eq!(EscalationTier::for_round(11), EscalationTier::Evasion);
    assert_eq!(EscalationTier::for_round(13), EscalationTier::Evasion);
    assert_eq!(EscalationTier::for_round(15), EscalationTier::Evasion);
}

#[test]
fn escalation_tier_full_arsenal_rounds() {
    assert_eq!(EscalationTier::for_round(16), EscalationTier::FullArsenal);
    assert_eq!(EscalationTier::for_round(20), EscalationTier::FullArsenal);
    assert_eq!(EscalationTier::for_round(100), EscalationTier::FullArsenal);
}

#[test]
fn escalation_endpoints_expand() {
    let basic = EscalationTier::Basic.available_endpoints();
    let expanded = EscalationTier::Expanded.available_endpoints();
    assert!(
        expanded.len() > basic.len(),
        "Expanded tier should have more endpoints"
    );
    assert!(expanded.contains(&"/api/v2/query"));
    assert!(expanded.contains(&"/upload"));
}

#[test]
fn escalation_capabilities() {
    assert!(!EscalationTier::Basic.red_evasion_enabled());
    assert!(!EscalationTier::Expanded.red_evasion_enabled());
    assert!(EscalationTier::Evasion.red_evasion_enabled());
    assert!(EscalationTier::FullArsenal.red_evasion_enabled());

    assert!(!EscalationTier::Basic.blue_detection_tools());
    assert!(!EscalationTier::Evasion.blue_detection_tools());
    assert!(EscalationTier::FullArsenal.blue_detection_tools());
}

// ─── Stuck detection tests ──────────────────────────────────────────────────

#[test]
fn stuck_detector_initial_state() {
    let detector = StuckDetector::new();
    assert!(!detector.red_stuck());
    assert!(!detector.blue_stuck());
}

#[test]
fn stuck_detector_red_stuck_after_threshold() {
    let mut detector = StuckDetector::new();
    detector.record_red_output(true);
    assert!(!detector.red_stuck());
    detector.record_red_output(true);
    assert!(
        detector.red_stuck(),
        "Red should be stuck after 2 empty outputs"
    );
}

#[test]
fn stuck_detector_resets_on_good_output() {
    let mut detector = StuckDetector::new();
    detector.record_red_output(true);
    detector.record_red_output(false); // good output resets
    assert_eq!(detector.consecutive_red_empty, 0);
    detector.record_red_output(true);
    assert!(!detector.red_stuck(), "Should need 2 more after reset");
}

#[test]
fn stuck_detector_blue_stuck() {
    let mut detector = StuckDetector::new();
    detector.record_blue_output(true);
    detector.record_blue_output(true);
    assert!(detector.blue_stuck());
}

#[test]
fn stuck_detector_independent_tracking() {
    let mut detector = StuckDetector::new();
    detector.record_red_output(true);
    detector.record_red_output(true);
    assert!(detector.red_stuck());
    assert!(!detector.blue_stuck(), "Blue should be independent of red");
}

// ─── Convergence detection tests ────────────────────────────────────────────

#[test]
fn convergence_initial_state() {
    let detector = ConvergenceDetector::new();
    assert!(!detector.has_converged());
}

#[test]
fn convergence_after_stale_rounds() {
    let mut detector = ConvergenceDetector::new();
    for _ in 0..5 {
        detector.record_round(false, false, false);
    }
    assert!(
        detector.has_converged(),
        "Should converge after 5 rounds with no new vulns and no bypass"
    );
}

#[test]
fn convergence_resets_on_new_vuln() {
    let mut detector = ConvergenceDetector::new();
    for _ in 0..4 {
        detector.record_round(false, false, false);
    }
    assert!(!detector.has_converged());
    detector.record_round(true, false, false); // new vuln resets
    assert!(!detector.has_converged());
}

#[test]
fn convergence_resets_on_bypass() {
    let mut detector = ConvergenceDetector::new();
    for _ in 0..4 {
        detector.record_round(false, false, false);
    }
    detector.record_round(false, true, false); // bypass resets
    assert!(!detector.has_converged());
}

#[test]
fn red_domination_detected() {
    let mut detector = ConvergenceDetector::new();
    for _ in 0..3 {
        detector.record_round(true, true, true);
    }
    assert!(detector.red_dominating());
    assert!(!detector.blue_dominating());
}

#[test]
fn blue_domination_detected() {
    let mut detector = ConvergenceDetector::new();
    for _ in 0..3 {
        detector.record_round(false, false, false);
    }
    assert!(detector.blue_dominating());
    assert!(!detector.red_dominating());
}

#[test]
fn domination_resets_on_change() {
    let mut detector = ConvergenceDetector::new();
    detector.record_round(true, true, true);
    detector.record_round(true, true, true);
    // Red was dominating (2 rounds), but now blue wins
    detector.record_round(false, false, false);
    assert!(!detector.red_dominating());
    assert_eq!(detector.red_domination_rounds, 0);
}

// ─── Difficulty adjuster tests ──────────────────────────────────────────────

#[test]
fn difficulty_adjusts_for_red_domination() {
    let mut adjuster = DifficultyAdjuster::new();
    let mut convergence = ConvergenceDetector::new();
    for _ in 0..3 {
        convergence.record_round(true, true, true);
    }
    adjuster.adjust(&convergence);
    assert_eq!(
        adjuster.blue_bonus_patches, 2,
        "Blue should get bonus patches"
    );
    assert_eq!(adjuster.red_extra_time_ms, 0);
}

#[test]
fn difficulty_adjusts_for_blue_domination() {
    let mut adjuster = DifficultyAdjuster::new();
    let mut convergence = ConvergenceDetector::new();
    for _ in 0..3 {
        convergence.record_round(false, false, false);
    }
    adjuster.adjust(&convergence);
    assert!(adjuster.red_extra_time_ms > 0, "Red should get extra time");
    assert_eq!(adjuster.blue_bonus_patches, 0);
}

#[test]
fn difficulty_no_adjustment_when_balanced() {
    let mut adjuster = DifficultyAdjuster::new();
    let mut convergence = ConvergenceDetector::new();
    convergence.record_round(true, false, true);
    convergence.record_round(false, true, false);
    adjuster.adjust(&convergence);
    assert_eq!(adjuster.blue_bonus_patches, 0);
    assert_eq!(adjuster.red_extra_time_ms, 0);
}
