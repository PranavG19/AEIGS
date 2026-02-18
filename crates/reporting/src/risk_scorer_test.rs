#[cfg(test)]
mod tests {
    use crate::risk_scorer::{
        RiskInput, compute_risk_score, rank_findings, top_remediation_targets,
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
}
