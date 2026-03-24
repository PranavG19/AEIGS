use super::*;
use crate::waf_grammar::{ProbeResult, ProbeStrategy};

fn blocked_probe(payload: &str) -> ProbeResult {
    ProbeResult {
        payload: payload.to_string(),
        blocked: true,
        status_code: Some(403),
        strategy: ProbeStrategy::BinarySearch,
    }
}

fn allowed_probe(payload: &str) -> ProbeResult {
    ProbeResult {
        payload: payload.to_string(),
        blocked: false,
        status_code: Some(200),
        strategy: ProbeStrategy::BinarySearch,
    }
}

#[test]
fn new_orchestrator_starts_with_zero_counts() {
    let orch = WafEvasionOrchestrator::new(OrchestratorConfig::default());
    assert_eq!(orch.attempt_count(), 0);
    assert_eq!(orch.bypass_count(), 0);
    assert_eq!(orch.bypass_rate(), 0.0);
}

#[test]
fn learn_from_probes_builds_grammar() {
    let mut orch = WafEvasionOrchestrator::new(OrchestratorConfig::default());
    assert!(orch.current_grammar().is_none());
    let probes = vec![
        blocked_probe("' OR 1=1--"),
        blocked_probe("' UNION SELECT NULL--"),
        allowed_probe("hello world"),
    ];
    orch.learn_from_probes(&probes);
    assert!(orch.current_grammar().is_some());
}

#[test]
fn plan_evasion_increments_attempt_count() {
    let mut orch = WafEvasionOrchestrator::with_seed(OrchestratorConfig::default(), 42);
    orch.plan_evasion("' OR 1=1--", "https://target.com", None);
    assert_eq!(orch.attempt_count(), 1);
}

#[test]
fn plan_evasion_returns_obfuscated_payload() {
    let mut orch = WafEvasionOrchestrator::with_seed(OrchestratorConfig::default(), 42);
    let strategy = orch.plan_evasion("' OR 1=1--", "https://target.com", None);
    assert!(strategy.obfuscated_payload.is_some());
    assert!(!strategy.techniques_applied.is_empty());
}

#[test]
fn plan_evasion_with_grammar_uses_bypass() {
    let mut orch = WafEvasionOrchestrator::with_seed(OrchestratorConfig::default(), 42);
    let probes = vec![
        blocked_probe("' OR 1=1--"),
        blocked_probe("UNION SELECT NULL"),
        allowed_probe("hello"),
    ];
    orch.learn_from_probes(&probes);
    let strategy = orch.plan_evasion("' OR 1=1--", "https://target.com", Some("cloudflare"));
    assert!(strategy.obfuscated_payload.is_some());
}

#[test]
fn record_outcome_tracks_success() {
    let mut orch = WafEvasionOrchestrator::new(OrchestratorConfig::default());
    orch.record_outcome(
        "cloudflare",
        &[EvasionTechnique::PayloadObfuscation],
        EvasionOutcome::Success,
    );
    assert_eq!(orch.bypass_count(), 1);
}

#[test]
fn record_outcome_tracks_failure() {
    let mut orch = WafEvasionOrchestrator::new(OrchestratorConfig::default());
    orch.record_outcome(
        "cloudflare",
        &[EvasionTechnique::PayloadObfuscation],
        EvasionOutcome::Blocked,
    );
    assert_eq!(orch.bypass_count(), 0);
}

#[test]
fn technique_ranking_returns_sorted() {
    let mut orch = WafEvasionOrchestrator::new(OrchestratorConfig::default());
    for _ in 0..10 {
        orch.record_outcome(
            "akamai",
            &[EvasionTechnique::EncodingLadder],
            EvasionOutcome::Success,
        );
    }
    for _ in 0..10 {
        orch.record_outcome(
            "akamai",
            &[EvasionTechnique::CaseMutation],
            EvasionOutcome::Blocked,
        );
    }
    orch.record_outcome(
        "akamai",
        &[EvasionTechnique::CaseMutation],
        EvasionOutcome::Success,
    );
    let ranking = orch.technique_ranking("akamai");
    assert!(!ranking.is_empty());
    assert_eq!(ranking[0].0, EvasionTechnique::EncodingLadder);
    assert!(ranking[0].1 > ranking.last().unwrap().1);
}

#[test]
fn best_technique_returns_highest_success() {
    let mut orch = WafEvasionOrchestrator::new(OrchestratorConfig::default());
    for _ in 0..5 {
        orch.record_outcome(
            "modsec",
            &[EvasionTechnique::CommentInjection],
            EvasionOutcome::Success,
        );
    }
    for _ in 0..5 {
        orch.record_outcome(
            "modsec",
            &[EvasionTechnique::IpRotation],
            EvasionOutcome::Blocked,
        );
    }
    assert_eq!(
        orch.best_technique("modsec"),
        Some(EvasionTechnique::CommentInjection)
    );
}

#[test]
fn best_technique_unknown_vendor_returns_none() {
    let orch = WafEvasionOrchestrator::new(OrchestratorConfig::default());
    assert!(orch.best_technique("unknown_waf").is_none());
}

#[test]
fn bypass_rate_calculation() {
    let mut orch = WafEvasionOrchestrator::with_seed(OrchestratorConfig::default(), 42);
    orch.plan_evasion("a", "t", None);
    orch.plan_evasion("b", "t", None);
    orch.record_outcome(
        "waf",
        &[EvasionTechnique::PayloadObfuscation],
        EvasionOutcome::Success,
    );
    assert!(orch.bypass_rate() > 0.0);
}

#[test]
fn suggest_probes_empty_without_grammar() {
    let orch = WafEvasionOrchestrator::new(OrchestratorConfig::default());
    assert!(orch.suggest_probes().is_empty());
}

#[test]
fn suggest_probes_non_empty_with_grammar() {
    let mut orch = WafEvasionOrchestrator::new(OrchestratorConfig::default());
    let probes = vec![blocked_probe("' OR 1=1--"), allowed_probe("hello")];
    orch.learn_from_probes(&probes);
    assert!(!orch.suggest_probes().is_empty());
}

#[test]
fn evasion_technique_display() {
    assert_eq!(
        format!("{}", EvasionTechnique::PayloadObfuscation),
        "payload-obfuscation"
    );
    assert_eq!(format!("{}", EvasionTechnique::IpRotation), "ip-rotation");
    assert_eq!(
        format!("{}", EvasionTechnique::TimingEvasion),
        "timing-evasion"
    );
    assert_eq!(
        format!("{}", EvasionTechnique::FingerprintRotation),
        "fingerprint-rotation"
    );
}

#[test]
fn vendor_profile_tracks_multiple_techniques() {
    let mut profile = VendorProfile::new("cloudflare");
    profile.record_attempt(EvasionTechnique::EncodingLadder, true);
    profile.record_attempt(EvasionTechnique::EncodingLadder, true);
    profile.record_attempt(EvasionTechnique::CaseMutation, false);
    let stats = profile
        .technique_stats
        .get(&EvasionTechnique::EncodingLadder)
        .unwrap();
    assert_eq!(stats.attempts, 2);
    assert_eq!(stats.successes, 2);
    assert_eq!(stats.success_rate(), 1.0);
}

#[test]
fn default_orchestrator_config() {
    let config = OrchestratorConfig::default();
    assert_eq!(config.max_retries, 5);
    assert!(config.adaptive_fallback);
    assert_eq!(config.obfuscation_depth, 2);
}

#[test]
fn strategy_includes_rotation_flag() {
    let mut orch = WafEvasionOrchestrator::with_seed(OrchestratorConfig::default(), 42);
    let strategy = orch.plan_evasion("test", "target", None);
    assert!(strategy.rotate_fingerprint);
}

#[test]
fn vendor_profiles_accessible() {
    let mut orch = WafEvasionOrchestrator::new(OrchestratorConfig::default());
    orch.record_outcome(
        "waf1",
        &[EvasionTechnique::IpRotation],
        EvasionOutcome::Success,
    );
    orch.record_outcome(
        "waf2",
        &[EvasionTechnique::IpRotation],
        EvasionOutcome::Blocked,
    );
    assert_eq!(orch.vendor_profiles().len(), 2);
}
