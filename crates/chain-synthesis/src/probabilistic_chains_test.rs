use super::probabilistic_chains::{ProbabilisticChainEngine, ProbabilisticEdge};

// ---------------------------------------------------------------------------
// Helper: build a simple linear chain  A -> B -> C -> D
// ---------------------------------------------------------------------------
fn linear_chain() -> ProbabilisticChainEngine {
    let mut engine = ProbabilisticChainEngine::new();
    let a = engine.add_node("A");
    let b = engine.add_node("B");
    let c = engine.add_node("C");
    let d = engine.add_node("D");
    engine.add_edge(a, b, 0.9, 10, 1000);
    engine.add_edge(b, c, 0.8, 10, 1000);
    engine.add_edge(c, d, 0.7, 10, 1000);
    engine
}

// ---------------------------------------------------------------------------
// Helper: build a diamond graph with two parallel paths
//         A -> B -> D (0.9 * 0.8 = 0.72)
//         A -> C -> D (0.5 * 0.6 = 0.30)
// ---------------------------------------------------------------------------
fn diamond_graph() -> ProbabilisticChainEngine {
    let mut engine = ProbabilisticChainEngine::new();
    let a = engine.add_node("A");
    let b = engine.add_node("B");
    let c = engine.add_node("C");
    let d = engine.add_node("D");
    engine.add_edge(a, b, 0.9, 10, 1000);
    engine.add_edge(a, c, 0.5, 10, 1000);
    engine.add_edge(b, d, 0.8, 10, 1000);
    engine.add_edge(c, d, 0.6, 10, 1000);
    engine
}

// ---------------------------------------------------------------------------
// Fixture 3: 20+ node attack scenario (acceptance criterion 1, 4)
//
//   entry0 ---> xss1 ---> jwt2 ---> priv_esc3 ---> rce4 (GOAL)
//                |                       ^
//                v                       |
//              ssrf5 ---> internal6 -----+
//                |
//                v
//              cloud7 ---> secrets8 ---> admin9 ---> rce4
//
//   entry10 --> sqli11 --> db12 --> leak13 --> phish14 --> creds15 --> vpn16 --> lateral17 --> dc18 --> rce4
//
//   (decoy) entry19 --> dead20 (no path to rce4)
// ---------------------------------------------------------------------------
fn large_attack_graph() -> ProbabilisticChainEngine {
    let mut e = ProbabilisticChainEngine::new();
    let entry0 = e.add_node("entry0");
    let xss1 = e.add_node("xss1");
    let jwt2 = e.add_node("jwt2");
    let priv_esc3 = e.add_node("priv_esc3");
    let rce4 = e.add_node("rce4");
    let ssrf5 = e.add_node("ssrf5");
    let internal6 = e.add_node("internal6");
    let cloud7 = e.add_node("cloud7");
    let secrets8 = e.add_node("secrets8");
    let admin9 = e.add_node("admin9");
    let entry10 = e.add_node("entry10");
    let sqli11 = e.add_node("sqli11");
    let db12 = e.add_node("db12");
    let leak13 = e.add_node("leak13");
    let phish14 = e.add_node("phish14");
    let creds15 = e.add_node("creds15");
    let vpn16 = e.add_node("vpn16");
    let lateral17 = e.add_node("lateral17");
    let dc18 = e.add_node("dc18");
    let entry19 = e.add_node("entry19");
    let dead20 = e.add_node("dead20");

    // Path 1: entry0 -> xss1 -> jwt2 -> priv_esc3 -> rce4
    //   EV = 0.85 * 0.70 * 0.60 * 0.90 = 0.3213
    e.add_edge(entry0, xss1, 0.85, 20, 100);
    e.add_edge(xss1, jwt2, 0.70, 15, 100);
    e.add_edge(jwt2, priv_esc3, 0.60, 10, 100);
    e.add_edge(priv_esc3, rce4, 0.90, 25, 100);

    // Path 1b fork: entry0 -> xss1 -> ssrf5 -> internal6 -> priv_esc3 -> rce4
    //   EV = 0.85 * 0.40 * 0.75 * 0.60 * 0.90 = 0.13770
    e.add_edge(xss1, ssrf5, 0.40, 5, 100);
    e.add_edge(ssrf5, internal6, 0.75, 8, 100);
    e.add_edge(internal6, priv_esc3, 0.60, 10, 100);

    // Path 1c fork: entry0 -> xss1 -> ssrf5 -> cloud7 -> secrets8 -> admin9 -> rce4
    //   EV = 0.85 * 0.40 * 0.30 * 0.55 * 0.80 * 0.95 = 0.042636
    e.add_edge(ssrf5, cloud7, 0.30, 3, 100);
    e.add_edge(cloud7, secrets8, 0.55, 4, 100);
    e.add_edge(secrets8, admin9, 0.80, 12, 100);
    e.add_edge(admin9, rce4, 0.95, 30, 100);

    // Path 2: entry10 -> sqli11 -> db12 -> leak13 -> phish14 -> creds15 -> vpn16 -> lateral17 -> dc18 -> rce4
    //   EV = 0.60 * 0.50 * 0.80 * 0.30 * 0.70 * 0.65 * 0.55 * 0.40 * 0.85 = 0.0061236...
    e.add_edge(entry10, sqli11, 0.60, 10, 100);
    e.add_edge(sqli11, db12, 0.50, 10, 100);
    e.add_edge(db12, leak13, 0.80, 10, 100);
    e.add_edge(leak13, phish14, 0.30, 10, 100);
    e.add_edge(phish14, creds15, 0.70, 10, 100);
    e.add_edge(creds15, vpn16, 0.65, 10, 100);
    e.add_edge(vpn16, lateral17, 0.55, 10, 100);
    e.add_edge(lateral17, dc18, 0.40, 10, 100);
    e.add_edge(dc18, rce4, 0.85, 10, 100);

    // Decoy path (dead end)
    e.add_edge(entry19, dead20, 0.99, 50, 100);

    e
}

// ===========================================================================
// ProbabilisticEdge unit tests
// ===========================================================================

#[test]
fn edge_new_clamps_probability() {
    let e = ProbabilisticEdge::new(1.5, 5, 0);
    assert!((e.success_probability - 1.0).abs() < f64::EPSILON);

    let e2 = ProbabilisticEdge::new(-0.3, 5, 0);
    assert!(e2.success_probability.abs() < f64::EPSILON);
}

#[test]
fn edge_zero_evidence_uniform_prior() {
    let e = ProbabilisticEdge::new(0.7, 0, 0);
    assert!((e.alpha() - 1.0).abs() < f64::EPSILON);
    assert!((e.beta_param() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn edge_with_evidence_alpha_beta() {
    let e = ProbabilisticEdge::new(0.8, 10, 0);
    assert!((e.alpha() - 8.0).abs() < 1e-10);
    assert!((e.beta_param() - 2.0).abs() < 1e-10);
}

#[test]
fn edge_variance_decreases_with_evidence() {
    let low_evidence = ProbabilisticEdge::new(0.5, 2, 0);
    let high_evidence = ProbabilisticEdge::new(0.5, 100, 0);
    assert!(low_evidence.variance() > high_evidence.variance());
}

#[test]
fn edge_bayesian_update_success() {
    let mut e = ProbabilisticEdge::new(0.5, 0, 0);
    // starts at Beta(1,1) → mean 0.5
    e.bayesian_update(true, 100);
    // now Beta(2,1) → mean 2/3
    let expected = 2.0 / 3.0;
    assert!((e.success_probability - expected).abs() < 1e-10);
    assert_eq!(e.evidence_count, 1);
    assert_eq!(e.last_updated, 100);
}

#[test]
fn edge_bayesian_update_failure() {
    let mut e = ProbabilisticEdge::new(0.5, 0, 0);
    e.bayesian_update(false, 200);
    // Beta(1,2) → mean 1/3
    let expected = 1.0 / 3.0;
    assert!((e.success_probability - expected).abs() < 1e-10);
    assert_eq!(e.evidence_count, 1);
}

#[test]
fn edge_multiple_bayesian_updates() {
    let mut e = ProbabilisticEdge::new(0.5, 0, 0);
    // 3 successes, 1 failure: Beta(4, 2) → mean 4/6 = 0.666...
    e.bayesian_update(true, 10);
    e.bayesian_update(true, 20);
    e.bayesian_update(true, 30);
    e.bayesian_update(false, 40);
    let expected = 4.0 / 6.0;
    assert!((e.success_probability - expected).abs() < 1e-10);
    assert_eq!(e.evidence_count, 4);
}

#[test]
fn edge_variance_formula_manual() {
    // Beta(3, 7): variance = 3*7 / (10^2 * 11) = 21/1100
    let e = ProbabilisticEdge::new(0.3, 10, 0);
    let expected = 21.0 / 1100.0;
    assert!((e.variance() - expected).abs() < 1e-10);
}

// ===========================================================================
// Engine construction tests
// ===========================================================================

#[test]
fn engine_new_empty() {
    let engine = ProbabilisticChainEngine::new();
    assert_eq!(engine.node_count(), 0);
    assert_eq!(engine.edge_count(), 0);
}

#[test]
fn engine_default_empty() {
    let engine = ProbabilisticChainEngine::default();
    assert_eq!(engine.node_count(), 0);
}

#[test]
fn engine_add_nodes_and_edges() {
    let engine = linear_chain();
    assert_eq!(engine.node_count(), 4);
    assert_eq!(engine.edge_count(), 3);
}

#[test]
fn engine_node_by_label() {
    let engine = linear_chain();
    assert!(engine.node_by_label("A").is_some());
    assert!(engine.node_by_label("D").is_some());
    assert!(engine.node_by_label("Z").is_none());
}

#[test]
fn engine_node_label_round_trip() {
    let engine = linear_chain();
    let idx = engine.node_by_label("B").unwrap();
    assert_eq!(engine.node_label(idx), "B");
}

// ===========================================================================
// highest_ev_paths tests
// ===========================================================================

#[test]
fn highest_ev_linear_single_path() {
    let engine = linear_chain();
    let a = engine.node_by_label("A").unwrap();
    let d = engine.node_by_label("D").unwrap();
    let paths = engine.highest_ev_paths(a, d, 5);
    assert_eq!(paths.len(), 1);
    let (path, ev) = &paths[0];
    assert_eq!(path.len(), 4);
    // 0.9 * 0.8 * 0.7 = 0.504
    assert!((ev - 0.504).abs() < 1e-10);
}

#[test]
fn highest_ev_diamond_two_paths() {
    let engine = diamond_graph();
    let a = engine.node_by_label("A").unwrap();
    let d = engine.node_by_label("D").unwrap();
    let paths = engine.highest_ev_paths(a, d, 5);
    assert_eq!(paths.len(), 2);

    // Best path: A->B->D with EV 0.72
    let (_, ev1) = &paths[0];
    assert!((ev1 - 0.72).abs() < 1e-10);

    // Second: A->C->D with EV 0.30
    let (_, ev2) = &paths[1];
    assert!((ev2 - 0.30).abs() < 1e-10);
}

#[test]
fn highest_ev_k_zero_returns_empty() {
    let engine = linear_chain();
    let a = engine.node_by_label("A").unwrap();
    let d = engine.node_by_label("D").unwrap();
    assert!(engine.highest_ev_paths(a, d, 0).is_empty());
}

#[test]
fn highest_ev_unreachable_returns_empty() {
    let mut engine = ProbabilisticChainEngine::new();
    let a = engine.add_node("A");
    let b = engine.add_node("B");
    // no edges
    let _ = b;
    assert!(engine.highest_ev_paths(a, b, 5).is_empty());
}

#[test]
fn highest_ev_same_node_returns_empty() {
    let engine = linear_chain();
    let a = engine.node_by_label("A").unwrap();
    let paths = engine.highest_ev_paths(a, a, 5);
    assert!(paths.is_empty());
}

#[test]
fn highest_ev_large_graph_top3() {
    let engine = large_attack_graph();
    let entry0 = engine.node_by_label("entry0").unwrap();
    let rce4 = engine.node_by_label("rce4").unwrap();
    let paths = engine.highest_ev_paths(entry0, rce4, 3);
    assert_eq!(paths.len(), 3);

    // Path 1: entry0->xss1->jwt2->priv_esc3->rce4 EV=0.85*0.70*0.60*0.90
    let expected_best = 0.85 * 0.70 * 0.60 * 0.90;
    assert!(
        (paths[0].1 - expected_best).abs() < 1e-10,
        "best path EV mismatch: got {}, expected {}",
        paths[0].1,
        expected_best
    );

    // Path 2: entry0->xss1->ssrf5->internal6->priv_esc3->rce4
    let expected_second = 0.85 * 0.40 * 0.75 * 0.60 * 0.90;
    assert!(
        (paths[1].1 - expected_second).abs() < 1e-10,
        "second path EV mismatch: got {}, expected {}",
        paths[1].1,
        expected_second
    );

    // Path 3: entry0->xss1->ssrf5->cloud7->secrets8->admin9->rce4
    let expected_third = 0.85 * 0.40 * 0.30 * 0.55 * 0.80 * 0.95;
    assert!(
        (paths[2].1 - expected_third).abs() < 1e-10,
        "third path EV mismatch: got {}, expected {}",
        paths[2].1,
        expected_third
    );
}

#[test]
fn highest_ev_large_graph_from_entry10() {
    let engine = large_attack_graph();
    let entry10 = engine.node_by_label("entry10").unwrap();
    let rce4 = engine.node_by_label("rce4").unwrap();
    let paths = engine.highest_ev_paths(entry10, rce4, 1);
    assert_eq!(paths.len(), 1);

    let expected = 0.60 * 0.50 * 0.80 * 0.30 * 0.70 * 0.65 * 0.55 * 0.40 * 0.85;
    assert!(
        (paths[0].1 - expected).abs() < 1e-10,
        "long chain EV mismatch: got {}, expected {}",
        paths[0].1,
        expected
    );
}

#[test]
fn highest_ev_dead_end_no_path() {
    let engine = large_attack_graph();
    let entry19 = engine.node_by_label("entry19").unwrap();
    let rce4 = engine.node_by_label("rce4").unwrap();
    assert!(engine.highest_ev_paths(entry19, rce4, 5).is_empty());
}

// ===========================================================================
// expected_value tests
// ===========================================================================

#[test]
fn expected_value_linear() {
    let engine = linear_chain();
    let a = engine.node_by_label("A").unwrap();
    let d = engine.node_by_label("D").unwrap();
    let ev = engine.expected_value(a, d);
    assert!((ev - 0.504).abs() < 1e-10);
}

#[test]
fn expected_value_same_node() {
    let engine = linear_chain();
    let a = engine.node_by_label("A").unwrap();
    assert!((engine.expected_value(a, a) - 1.0).abs() < f64::EPSILON);
}

#[test]
fn expected_value_unreachable() {
    let mut engine = ProbabilisticChainEngine::new();
    let a = engine.add_node("A");
    let b = engine.add_node("B");
    assert!(engine.expected_value(a, b).abs() < f64::EPSILON);
}

// ===========================================================================
// most_informative_probe tests
// ===========================================================================

#[test]
fn most_informative_probe_empty_graph() {
    let engine = ProbabilisticChainEngine::new();
    assert!(engine.most_informative_probe().is_none());
}

#[test]
fn most_informative_probe_picks_highest_variance() {
    let mut engine = ProbabilisticChainEngine::new();
    let a = engine.add_node("A");
    let b = engine.add_node("B");
    let c = engine.add_node("C");

    // High evidence → low variance
    let _e1 = engine.add_edge(a, b, 0.5, 100, 0);
    // Low evidence → high variance
    let e2 = engine.add_edge(b, c, 0.5, 2, 0);

    let probe = engine.most_informative_probe().unwrap();
    assert_eq!(probe, e2);
}

#[test]
fn most_informative_probe_uniform_prior_most_uncertain() {
    let mut engine = ProbabilisticChainEngine::new();
    let a = engine.add_node("A");
    let b = engine.add_node("B");
    let c = engine.add_node("C");
    let d = engine.add_node("D");

    // Zero evidence = Beta(1,1) → variance = 1/12 ≈ 0.0833
    let e_uncertain = engine.add_edge(a, b, 0.5, 0, 0);
    // 50 observations → very low variance
    let _e_certain = engine.add_edge(c, d, 0.8, 50, 0);

    let probe = engine.most_informative_probe().unwrap();
    assert_eq!(probe, e_uncertain);
}

// ===========================================================================
// update_posterior tests
// ===========================================================================

#[test]
fn update_posterior_success_increases_probability() {
    let mut engine = ProbabilisticChainEngine::new();
    let a = engine.add_node("A");
    let b = engine.add_node("B");
    let edge = engine.add_edge(a, b, 0.5, 0, 0);

    let before = engine.edge_weight(edge).unwrap().success_probability;
    engine.update_posterior(edge, true);
    let after = engine.edge_weight(edge).unwrap().success_probability;
    assert!(after > before);
}

#[test]
fn update_posterior_failure_decreases_probability() {
    let mut engine = ProbabilisticChainEngine::new();
    let a = engine.add_node("A");
    let b = engine.add_node("B");
    let edge = engine.add_edge(a, b, 0.5, 0, 0);

    let before = engine.edge_weight(edge).unwrap().success_probability;
    engine.update_posterior(edge, false);
    let after = engine.edge_weight(edge).unwrap().success_probability;
    assert!(after < before);
}

#[test]
fn update_posterior_bayesian_values_match_manual() {
    let mut engine = ProbabilisticChainEngine::new();
    let a = engine.add_node("A");
    let b = engine.add_node("B");
    // Start with Beta(1,1)
    let edge = engine.add_edge(a, b, 0.5, 0, 0);

    // 7 successes, 3 failures → Beta(8, 4) → mean = 8/12 = 0.666...
    for _ in 0..7 {
        engine.update_posterior(edge, true);
    }
    for _ in 0..3 {
        engine.update_posterior(edge, false);
    }

    let w = engine.edge_weight(edge).unwrap();
    let expected_mean = 8.0 / 12.0;
    assert!(
        (w.success_probability - expected_mean).abs() < 1e-10,
        "posterior mean mismatch: got {}, expected {}",
        w.success_probability,
        expected_mean
    );
    assert!((w.alpha() - 8.0).abs() < 1e-10);
    assert!((w.beta_param() - 4.0).abs() < 1e-10);
    assert_eq!(w.evidence_count, 10);
}

#[test]
fn update_posterior_reduces_variance() {
    let mut engine = ProbabilisticChainEngine::new();
    let a = engine.add_node("A");
    let b = engine.add_node("B");
    let edge = engine.add_edge(a, b, 0.5, 0, 0);

    let var_before = engine.edge_weight(edge).unwrap().variance();
    engine.update_posterior(edge, true);
    let var_after = engine.edge_weight(edge).unwrap().variance();
    assert!(var_after < var_before);
}

// ===========================================================================
// edges_by_uncertainty tests
// ===========================================================================

#[test]
fn edges_by_uncertainty_descending_order() {
    let engine = diamond_graph();
    let ranked = engine.edges_by_uncertainty();
    for pair in ranked.windows(2) {
        assert!(pair[0].1 >= pair[1].1);
    }
}

// ===========================================================================
// total_path_probability tests
// ===========================================================================

#[test]
fn total_path_probability_diamond() {
    let engine = diamond_graph();
    let a = engine.node_by_label("A").unwrap();
    let d = engine.node_by_label("D").unwrap();
    let total = engine.total_path_probability(a, d, 100);
    // 0.72 + 0.30 = 1.02 (can exceed 1.0 because paths are not mutually exclusive)
    assert!((total - 1.02).abs() < 1e-10);
}

// ===========================================================================
// Fixture graph 3: manual calculation comparison (acceptance criterion 4)
// ===========================================================================

#[test]
fn fixture_triangle_manual_verification() {
    // Triangle: A->B->C, A->C
    //   Path 1: A->B->C  EV = 0.6 * 0.8 = 0.48
    //   Path 2: A->C     EV = 0.3
    let mut engine = ProbabilisticChainEngine::new();
    let a = engine.add_node("A");
    let b = engine.add_node("B");
    let c = engine.add_node("C");
    engine.add_edge(a, b, 0.6, 10, 0);
    engine.add_edge(b, c, 0.8, 10, 0);
    engine.add_edge(a, c, 0.3, 10, 0);

    let paths = engine.highest_ev_paths(a, c, 10);
    assert_eq!(paths.len(), 2);
    assert!((paths[0].1 - 0.48).abs() < 1e-10);
    assert!((paths[1].1 - 0.30).abs() < 1e-10);
}

#[test]
fn fixture_star_manual_verification() {
    // Star: center -> {n1, n2, n3, n4, n5}, n5 is the target
    // Only direct path: center -> n5 with EV = 0.42
    let mut engine = ProbabilisticChainEngine::new();
    let center = engine.add_node("center");
    let n1 = engine.add_node("n1");
    let n2 = engine.add_node("n2");
    let n3 = engine.add_node("n3");
    let n4 = engine.add_node("n4");
    let n5 = engine.add_node("n5");
    engine.add_edge(center, n1, 0.9, 10, 0);
    engine.add_edge(center, n2, 0.8, 10, 0);
    engine.add_edge(center, n3, 0.7, 10, 0);
    engine.add_edge(center, n4, 0.6, 10, 0);
    engine.add_edge(center, n5, 0.42, 10, 0);

    let ev = engine.expected_value(center, n5);
    assert!((ev - 0.42).abs() < 1e-10);
    let _ = (n1, n2, n3, n4);
}

#[test]
fn fixture_cascade_manual_verification() {
    // A -> B -> C -> D -> E, probabilities: 0.9, 0.95, 0.85, 0.80
    // EV = 0.9 * 0.95 * 0.85 * 0.80 = 0.5814
    let mut engine = ProbabilisticChainEngine::new();
    let a = engine.add_node("A");
    let b = engine.add_node("B");
    let c = engine.add_node("C");
    let d = engine.add_node("D");
    let e_node = engine.add_node("E");
    engine.add_edge(a, b, 0.9, 20, 0);
    engine.add_edge(b, c, 0.95, 20, 0);
    engine.add_edge(c, d, 0.85, 20, 0);
    engine.add_edge(d, e_node, 0.80, 20, 0);

    let ev = engine.expected_value(a, e_node);
    let expected = 0.9 * 0.95 * 0.85 * 0.80;
    assert!(
        (ev - expected).abs() < 1e-10,
        "cascade EV mismatch: got {ev}, expected {expected}"
    );
}

// ===========================================================================
// Posterior affects path ranking
// ===========================================================================

#[test]
fn posterior_update_changes_path_ranking() {
    let mut engine = ProbabilisticChainEngine::new();
    let a = engine.add_node("A");
    let b = engine.add_node("B");
    let c = engine.add_node("C");
    let d = engine.add_node("D");

    // Path A->B->D: 0.5 * 0.5 = 0.25
    let e_ab = engine.add_edge(a, b, 0.5, 0, 0);
    engine.add_edge(b, d, 0.5, 0, 0);
    // Path A->C->D: 0.4 * 0.5 = 0.20
    engine.add_edge(a, c, 0.4, 0, 0);
    engine.add_edge(c, d, 0.5, 0, 0);

    // Initially A->B->D is better
    let paths = engine.highest_ev_paths(a, d, 2);
    assert!(paths[0].1 > paths[1].1);

    // Now A->B fails repeatedly, driving its probability down
    for _ in 0..20 {
        engine.update_posterior(e_ab, false);
    }

    // A->C->D should now be the best path
    let paths_after = engine.highest_ev_paths(a, d, 2);
    // the path through C should now beat the path through B
    let path_c_ev = paths_after
        .iter()
        .find(|(p, _)| {
            let labels: Vec<&str> = p.iter().map(|&idx| engine.node_label(idx)).collect();
            labels.contains(&"C")
        })
        .map(|(_, ev)| *ev)
        .unwrap();
    let path_b_ev = paths_after
        .iter()
        .find(|(p, _)| {
            let labels: Vec<&str> = p.iter().map(|&idx| engine.node_label(idx)).collect();
            labels.contains(&"B")
        })
        .map(|(_, ev)| *ev)
        .unwrap();
    assert!(path_c_ev > path_b_ev);
}

// ===========================================================================
// Edge accessors
// ===========================================================================

#[test]
fn all_edges_returns_correct_count() {
    let engine = diamond_graph();
    assert_eq!(engine.all_edges().len(), 4);
}

#[test]
fn edge_endpoints_correct() {
    let mut engine = ProbabilisticChainEngine::new();
    let a = engine.add_node("A");
    let b = engine.add_node("B");
    let edge = engine.add_edge(a, b, 0.5, 0, 0);
    let (src, tgt) = engine.edge_endpoints(edge).unwrap();
    assert_eq!(src, a);
    assert_eq!(tgt, b);
}

#[test]
fn edge_weight_accessible() {
    let mut engine = ProbabilisticChainEngine::new();
    let a = engine.add_node("A");
    let b = engine.add_node("B");
    let edge = engine.add_edge(a, b, 0.75, 10, 42);
    let w = engine.edge_weight(edge).unwrap();
    assert!((w.success_probability - 0.75).abs() < 1e-10);
    assert_eq!(w.evidence_count, 10);
    assert_eq!(w.last_updated, 42);
}

// ===========================================================================
// Cycle handling — engine must not infinite-loop on cycles
// ===========================================================================

#[test]
fn cycle_does_not_hang() {
    let mut engine = ProbabilisticChainEngine::new();
    let a = engine.add_node("A");
    let b = engine.add_node("B");
    let c = engine.add_node("C");
    engine.add_edge(a, b, 0.9, 10, 0);
    engine.add_edge(b, c, 0.8, 10, 0);
    engine.add_edge(c, a, 0.7, 10, 0); // back-edge creating cycle

    let paths = engine.highest_ev_paths(a, c, 5);
    assert_eq!(paths.len(), 1);
    assert!((paths[0].1 - 0.72).abs() < 1e-10);
}

// ===========================================================================
// Large graph node count (acceptance criterion 1: 20+ nodes)
// ===========================================================================

#[test]
fn large_graph_has_21_nodes() {
    let engine = large_attack_graph();
    assert_eq!(engine.node_count(), 21);
}
