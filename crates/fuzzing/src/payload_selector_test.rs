#[cfg(test)]
mod tests {
    use crate::payload_selector::{PayloadSelector, PayloadStats};

    fn make_stats(payload: &str, attempts: u32, successes: u32) -> PayloadStats {
        PayloadStats {
            payload: payload.to_string(),
            attempts,
            successes,
        }
    }

    #[test]
    fn empty_history_returns_candidates_unchanged() {
        let selector = PayloadSelector::new(vec![]);
        let candidates: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
        let ranked = selector.rank_payloads(&candidates);
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked, candidates);
    }

    #[test]
    fn novel_payloads_ranked_before_known() {
        let history = vec![make_stats("known-a", 10, 5), make_stats("known-b", 10, 3)];
        let selector = PayloadSelector::new(history);
        let candidates: Vec<String> = vec![
            "known-a".into(),
            "novel-x".into(),
            "known-b".into(),
            "novel-y".into(),
        ];
        let ranked = selector.rank_payloads(&candidates);
        assert_eq!(ranked[0], "novel-x");
        assert_eq!(ranked[1], "novel-y");
        assert!(ranked.contains(&"known-a".to_string()));
        assert!(ranked.contains(&"known-b".to_string()));
    }

    #[test]
    fn higher_success_rate_ranked_higher() {
        let history = vec![
            make_stats("high-success", 100, 80),
            make_stats("low-success", 100, 20),
        ];
        let selector = PayloadSelector::new(history);
        let candidates: Vec<String> = vec!["low-success".into(), "high-success".into()];
        let ranked = selector.rank_payloads(&candidates);
        assert_eq!(ranked[0], "high-success");
        assert_eq!(ranked[1], "low-success");
    }

    #[test]
    fn ucb1_exploration_bonus_for_fewer_attempts() {
        let history = vec![
            make_stats("well-tested", 1000, 300),
            make_stats("barely-tested", 5, 2),
        ];
        let selector = PayloadSelector::new(history);
        let score_well = selector.ucb1_score("well-tested");
        let score_barely = selector.ucb1_score("barely-tested");
        assert!(
            score_barely > score_well,
            "barely-tested ({score_barely}) should outscore well-tested ({score_well}) due to exploration bonus"
        );
    }

    #[test]
    fn select_payloads_limits_count() {
        let selector = PayloadSelector::new(vec![]);
        let candidates: Vec<String> = (0..10).map(|i| format!("payload-{i}")).collect();
        let selected = selector.select_payloads(&candidates, 3);
        assert_eq!(selected.len(), 3);
    }

    #[test]
    fn zero_attempts_in_stats_treated_as_novel() {
        let history = vec![make_stats("zero-attempts", 0, 0)];
        let selector = PayloadSelector::new(history);
        let score = selector.ucb1_score("zero-attempts");
        assert!(score.is_infinite());
    }

    #[test]
    fn ucb1_score_computation_matches_formula() {
        let history = vec![
            make_stats("payload-a", 10, 7),
            make_stats("payload-b", 20, 4),
        ];
        let selector = PayloadSelector::new(history);

        // total_attempts = 30
        // payload-a: success_rate = 7/10 = 0.7, exploration = sqrt(2 * ln(30) / 10)
        let total: f64 = 30.0;
        let expected_a = 0.7 + (2.0 * total.ln() / 10.0).sqrt();
        let actual_a = selector.ucb1_score("payload-a");
        assert!(
            (actual_a - expected_a).abs() < 1e-10,
            "payload-a: expected {expected_a}, got {actual_a}"
        );

        // payload-b: success_rate = 4/20 = 0.2, exploration = sqrt(2 * ln(30) / 20)
        let expected_b = 0.2 + (2.0 * total.ln() / 20.0).sqrt();
        let actual_b = selector.ucb1_score("payload-b");
        assert!(
            (actual_b - expected_b).abs() < 1e-10,
            "payload-b: expected {expected_b}, got {actual_b}"
        );
    }

    #[test]
    fn known_payload_count_and_total_attempts() {
        let history = vec![
            make_stats("a", 10, 5),
            make_stats("b", 20, 8),
            make_stats("c", 30, 12),
        ];
        let selector = PayloadSelector::new(history);
        assert_eq!(selector.known_payload_count(), 3);
        assert_eq!(selector.total_attempts(), 60);
    }
}
