use super::payload_scorer::*;
use aegis_protocol::finding::VulnerabilityClass;

fn ts_express() -> TechStack {
    TechStack::new("nginx", "express", "javascript")
}

fn ts_django() -> TechStack {
    TechStack::new("nginx", "django", "python")
}

fn ts_flask() -> TechStack {
    TechStack::new("nginx", "flask", "python")
}

fn outcome(
    payload: &str,
    vuln: VulnerabilityClass,
    ts: &TechStack,
    success: bool,
) -> PayloadOutcome {
    PayloadOutcome {
        payload: payload.to_string(),
        vulnerability_class: vuln,
        tech_stack: ts.clone(),
        success,
    }
}

// ── Basic recording ──────────────────────────────────────────────

#[test]
fn record_single_success() {
    let mut scorer = PayloadEffectivenessScorer::new();
    let ts = ts_express();
    scorer.record(&outcome(
        "' OR 1=1--",
        VulnerabilityClass::SqlInjection,
        &ts,
        true,
    ));
    let s = scorer
        .get_score("' OR 1=1--", &ts, VulnerabilityClass::SqlInjection)
        .unwrap();
    assert_eq!(s.successes, 1);
    assert_eq!(s.failures, 0);
    assert!(s.effectiveness > 0.5);
}

#[test]
fn record_single_failure() {
    let mut scorer = PayloadEffectivenessScorer::new();
    let ts = ts_express();
    scorer.record(&outcome(
        "' OR 1=1--",
        VulnerabilityClass::SqlInjection,
        &ts,
        false,
    ));
    let s = scorer
        .get_score("' OR 1=1--", &ts, VulnerabilityClass::SqlInjection)
        .unwrap();
    assert_eq!(s.successes, 0);
    assert_eq!(s.failures, 1);
    assert!(s.effectiveness < 0.5);
}

// ── Bayesian updates converge ────────────────────────────────────

#[test]
fn bayesian_update_converges_with_data() {
    let mut scorer = PayloadEffectivenessScorer::new();
    let ts = ts_express();
    for _ in 0..100 {
        scorer.record(&outcome(
            "payload_good",
            VulnerabilityClass::SqlInjection,
            &ts,
            true,
        ));
    }
    let s = scorer
        .get_score("payload_good", &ts, VulnerabilityClass::SqlInjection)
        .unwrap();
    assert!(
        s.effectiveness > 0.95,
        "Expected >0.95, got {}",
        s.effectiveness
    );
    assert!(
        s.confidence > 0.9,
        "Expected high confidence, got {}",
        s.confidence
    );
}

#[test]
fn bayesian_update_reflects_mixed_results() {
    let mut scorer = PayloadEffectivenessScorer::new();
    let ts = ts_express();
    for _ in 0..50 {
        scorer.record(&outcome("p1", VulnerabilityClass::SqlInjection, &ts, true));
        scorer.record(&outcome("p1", VulnerabilityClass::SqlInjection, &ts, false));
    }
    let s = scorer
        .get_score("p1", &ts, VulnerabilityClass::SqlInjection)
        .unwrap();
    assert!(
        (s.effectiveness - 0.5).abs() < 0.05,
        "Expected ~0.5, got {}",
        s.effectiveness
    );
}

// ── Top payloads ranking ─────────────────────────────────────────

#[test]
fn top_payloads_returns_sorted_by_effectiveness() {
    let mut scorer = PayloadEffectivenessScorer::new();
    let ts = ts_express();
    let vuln = VulnerabilityClass::SqlInjection;

    for _ in 0..10 {
        scorer.record(&outcome("good", vuln, &ts, true));
    }
    for _ in 0..10 {
        scorer.record(&outcome("bad", vuln, &ts, false));
    }
    for _ in 0..5 {
        scorer.record(&outcome("mid", vuln, &ts, true));
        scorer.record(&outcome("mid", vuln, &ts, false));
    }

    let top = scorer.top_payloads(&ts, vuln, 3);
    assert_eq!(top.len(), 3);
    assert_eq!(top[0].payload, "good");
    assert!(top[0].effectiveness > top[1].effectiveness);
    assert!(top[1].effectiveness > top[2].effectiveness);
}

#[test]
fn top_payloads_respects_n_limit() {
    let mut scorer = PayloadEffectivenessScorer::new();
    let ts = ts_express();
    let vuln = VulnerabilityClass::CrossSiteScripting;
    for i in 0..20 {
        scorer.record(&outcome(&format!("xss_{i}"), vuln, &ts, true));
    }
    let top = scorer.top_payloads(&ts, vuln, 5);
    assert_eq!(top.len(), 5);
}

// ── Dead payload pruning ─────────────────────────────────────────

#[test]
fn dead_payloads_identified_after_enough_failures() {
    let mut scorer = PayloadEffectivenessScorer::new().with_prune_settings(10, 0.15);
    let ts = ts_express();
    let vuln = VulnerabilityClass::SqlInjection;

    for _ in 0..15 {
        scorer.record(&outcome("never_works", vuln, &ts, false));
    }
    scorer.record(&outcome("sometimes_works", vuln, &ts, true));

    let dead = scorer.dead_payloads();
    assert!(dead.iter().any(|s| s.payload == "never_works"));
    assert!(!dead.iter().any(|s| s.payload == "sometimes_works"));
}

#[test]
fn dead_payloads_ignores_low_sample_count() {
    let mut scorer = PayloadEffectivenessScorer::new().with_prune_settings(10, 0.15);
    let ts = ts_express();
    let vuln = VulnerabilityClass::SqlInjection;

    for _ in 0..3 {
        scorer.record(&outcome("too_few", vuln, &ts, false));
    }
    let dead = scorer.dead_payloads();
    assert!(dead.is_empty());
}

// ── Cross-target learning ────────────────────────────────────────

#[test]
fn cross_target_recommends_from_similar_stack() {
    let mut scorer = PayloadEffectivenessScorer::new();
    let ts_a = ts_django();
    let ts_b = ts_flask();
    let vuln = VulnerabilityClass::SqlInjection;

    for _ in 0..20 {
        scorer.record(&outcome("universal_sqli", vuln, &ts_a, true));
    }

    let recs = scorer.cross_target_recommendations(&ts_b, vuln, 0.3, 5);
    assert!(!recs.is_empty(), "Expected cross-target recommendations");
    assert!(recs[0].payload == "universal_sqli");
}

#[test]
fn cross_target_excludes_dissimilar_stacks() {
    let mut scorer = PayloadEffectivenessScorer::new();
    let ts_a = TechStack::new("apache", "spring", "java");
    let ts_b = TechStack::new("nginx", "express", "javascript");
    let vuln = VulnerabilityClass::SqlInjection;

    for _ in 0..20 {
        scorer.record(&outcome("java_specific", vuln, &ts_a, true));
    }

    let recs = scorer.cross_target_recommendations(&ts_b, vuln, 0.5, 5);
    assert!(recs.is_empty(), "Expected no recs for dissimilar stack");
}

// ── TechStack similarity ─────────────────────────────────────────

#[test]
fn identical_stacks_have_full_similarity() {
    let a = ts_express();
    let b = ts_express();
    assert!((a.similarity(&b) - 1.0).abs() < f64::EPSILON);
}

#[test]
fn completely_different_stacks_have_zero_similarity() {
    let a = TechStack::new("apache", "spring", "java");
    let b = TechStack::new("nginx", "express", "javascript");
    assert!((a.similarity(&b)).abs() < f64::EPSILON);
}

#[test]
fn partial_overlap_gives_fractional_similarity() {
    let a = TechStack::new("nginx", "django", "python");
    let b = TechStack::new("nginx", "flask", "python");
    let sim = a.similarity(&b);
    assert!(sim > 0.0 && sim < 1.0, "Expected partial sim, got {sim}");
}

// ── Batch recording ──────────────────────────────────────────────

#[test]
fn batch_records_all_outcomes() {
    let mut scorer = PayloadEffectivenessScorer::new();
    let ts = ts_express();
    let vuln = VulnerabilityClass::CrossSiteScripting;
    let outcomes = vec![
        outcome("xss1", vuln, &ts, true),
        outcome("xss2", vuln, &ts, false),
        outcome("xss1", vuln, &ts, true),
    ];
    scorer.record_batch(&outcomes);
    assert_eq!(scorer.tracked_count(), 2);
    let s = scorer.get_score("xss1", &ts, vuln).unwrap();
    assert_eq!(s.successes, 2);
}

// ── Tracked count ────────────────────────────────────────────────

#[test]
fn tracked_count_starts_at_zero() {
    let scorer = PayloadEffectivenessScorer::new();
    assert_eq!(scorer.tracked_count(), 0);
}

#[test]
fn different_vuln_classes_tracked_separately() {
    let mut scorer = PayloadEffectivenessScorer::new();
    let ts = ts_express();
    scorer.record(&outcome("p", VulnerabilityClass::SqlInjection, &ts, true));
    scorer.record(&outcome(
        "p",
        VulnerabilityClass::CrossSiteScripting,
        &ts,
        true,
    ));
    assert_eq!(scorer.tracked_count(), 2);
}
