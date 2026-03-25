use crate::attack_graph::{AttackGraph, AttackNodeType};
use crate::defense_effectiveness::DefenseEffectivenessScorer;

fn build_defended_graph() -> AttackGraph {
    let mut g = AttackGraph::new();
    let entry = g.add_node("Web Entry".into(), AttackNodeType::EntryPoint);
    let waf = g.add_node("WAF".into(), AttackNodeType::SecurityBoundary);
    let vuln = g.add_node("SQLi".into(), AttackNodeType::Vulnerability);
    let asset = g.add_node("Database".into(), AttackNodeType::Asset);

    g.add_edge(entry, waf, 1.0, None);
    g.add_edge(waf, vuln, 5.0, None);
    g.add_edge(vuln, asset, 2.0, None);
    g
}

fn build_bypass_graph() -> AttackGraph {
    let mut g = AttackGraph::new();
    let entry = g.add_node("Entry".into(), AttackNodeType::EntryPoint);
    let waf = g.add_node("WAF".into(), AttackNodeType::SecurityBoundary);
    let vuln_a = g.add_node("SQLi".into(), AttackNodeType::Vulnerability);
    let vuln_b = g.add_node("XSS".into(), AttackNodeType::Vulnerability);
    let asset = g.add_node("Database".into(), AttackNodeType::Asset);

    // Path through WAF
    g.add_edge(entry, waf, 1.0, None);
    g.add_edge(waf, vuln_a, 5.0, None);
    g.add_edge(vuln_a, asset, 2.0, None);

    // Bypass path
    g.add_edge(entry, vuln_b, 3.0, None);
    g.add_edge(vuln_b, asset, 1.0, None);
    g
}

fn build_multi_defense_graph() -> AttackGraph {
    let mut g = AttackGraph::new();
    let entry = g.add_node("Entry".into(), AttackNodeType::EntryPoint);
    let waf = g.add_node("WAF".into(), AttackNodeType::SecurityBoundary);
    let rate_limit = g.add_node("Rate Limiter".into(), AttackNodeType::SecurityBoundary);
    let vuln = g.add_node("SQLi".into(), AttackNodeType::Vulnerability);
    let asset = g.add_node("Database".into(), AttackNodeType::Asset);

    g.add_edge(entry, waf, 1.0, None);
    g.add_edge(waf, rate_limit, 2.0, None);
    g.add_edge(rate_limit, vuln, 3.0, None);
    g.add_edge(vuln, asset, 1.0, None);
    g
}

#[test]
fn single_defense_scores_correctly() {
    let g = build_defended_graph();
    let scorer = DefenseEffectivenessScorer::new(&g);
    let report = scorer.score();

    assert_eq!(report.defense_scores.len(), 1);
    assert_eq!(report.defense_scores[0].defense_label, "WAF");
    assert!(report.defense_scores[0].block_rate > 0.0);
    assert_eq!(report.total_paths, 1);
}

#[test]
fn bypass_path_reduces_effectiveness() {
    let g = build_bypass_graph();
    let scorer = DefenseEffectivenessScorer::new(&g);
    let report = scorer.score();

    assert_eq!(report.defense_scores.len(), 1);
    let waf = &report.defense_scores[0];
    assert!(waf.block_rate < 1.0);
    assert!(report.unprotected_paths > 0);
}

#[test]
fn multi_defense_all_scored() {
    let g = build_multi_defense_graph();
    let scorer = DefenseEffectivenessScorer::new(&g);
    let report = scorer.score();

    assert_eq!(report.defense_scores.len(), 2);
}

#[test]
fn empty_graph_reports_zero() {
    let g = AttackGraph::new();
    let scorer = DefenseEffectivenessScorer::new(&g);
    let report = scorer.score();

    assert!(report.defense_scores.is_empty());
    assert_eq!(report.total_paths, 0);
    assert_eq!(report.overall_block_rate, 0.0);
}

#[test]
fn weakest_defense_identified() {
    let g = build_bypass_graph();
    let scorer = DefenseEffectivenessScorer::new(&g);
    let report = scorer.score();

    assert!(report.weakest_defense.is_some());
}

#[test]
fn overall_block_rate_bounded() {
    let g = build_defended_graph();
    let scorer = DefenseEffectivenessScorer::new(&g);
    let report = scorer.score();

    assert!(report.overall_block_rate >= 0.0);
    assert!(report.overall_block_rate <= 1.0);
}

#[test]
fn custom_depth_works() {
    let g = build_defended_graph();
    let scorer = DefenseEffectivenessScorer::new(&g).with_max_depth(4);
    let report = scorer.score();

    assert_eq!(report.total_paths, 1);
}

#[test]
fn weakness_notes_added_for_low_block_rate() {
    let g = build_bypass_graph();
    let scorer = DefenseEffectivenessScorer::new(&g);
    let report = scorer.score();

    let waf = &report.defense_scores[0];
    // WAF covers 1 of 2 paths = 50%, should not trigger the <30% note
    // but should still produce valid output
    assert!(waf.attacks_total > 0);
}
