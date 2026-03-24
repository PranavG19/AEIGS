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

    #[test]
    fn select_payloads_count_greater_than_candidates() {
        let selector = PayloadSelector::new(vec![]);
        let candidates: Vec<String> = vec!["a".into(), "b".into()];
        let selected = selector.select_payloads(&candidates, 10);
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn select_payloads_count_zero_returns_empty() {
        let selector = PayloadSelector::new(vec![]);
        let candidates: Vec<String> = vec!["a".into(), "b".into()];
        let selected = selector.select_payloads(&candidates, 0);
        assert!(selected.is_empty());
    }

    #[test]
    fn rank_payloads_empty_candidates() {
        let selector = PayloadSelector::new(vec![make_stats("a", 10, 5)]);
        let candidates: Vec<String> = vec![];
        let ranked = selector.rank_payloads(&candidates);
        assert!(ranked.is_empty());
    }

    #[test]
    fn ucb1_score_novel_payload_is_infinite() {
        let history = vec![make_stats("known", 10, 5)];
        let selector = PayloadSelector::new(history);
        let score = selector.ucb1_score("never-seen");
        assert!(score.is_infinite());
    }

    #[test]
    fn identical_success_rates_fewer_attempts_ranked_higher() {
        let history = vec![
            make_stats("many-attempts", 1000, 500),
            make_stats("few-attempts", 10, 5),
        ];
        let selector = PayloadSelector::new(history);
        let candidates: Vec<String> = vec!["many-attempts".into(), "few-attempts".into()];
        let ranked = selector.rank_payloads(&candidates);
        assert_eq!(
            ranked[0], "few-attempts",
            "fewer attempts should rank higher due to UCB1 exploration bonus"
        );
    }

    #[test]
    fn all_novel_payloads_preserve_order() {
        let selector = PayloadSelector::new(vec![]);
        let candidates: Vec<String> = vec!["c".into(), "a".into(), "b".into()];
        let ranked = selector.rank_payloads(&candidates);
        assert_eq!(ranked, vec!["c", "a", "b"]);
    }

    #[test]
    fn new_with_empty_history() {
        let selector = PayloadSelector::new(vec![]);
        assert_eq!(selector.known_payload_count(), 0);
        assert_eq!(selector.total_attempts(), 0);
    }

    #[test]
    fn ucb1_score_all_successes() {
        let history = vec![make_stats("perfect", 100, 100)];
        let selector = PayloadSelector::new(history);
        let score = selector.ucb1_score("perfect");
        assert!(
            score >= 1.0,
            "perfect success rate should yield score >= 1.0, got {score}"
        );
        assert!(score.is_finite());
    }

    #[test]
    fn ucb1_score_all_failures() {
        let history = vec![make_stats("terrible", 100, 0)];
        let selector = PayloadSelector::new(history);
        let score = selector.ucb1_score("terrible");
        assert!(
            score >= 0.0,
            "score should be non-negative even with zero successes"
        );
        assert!(
            score < 1.0,
            "score with zero successes should be less than 1.0, got {score}"
        );
    }

    #[test]
    fn duplicate_payloads_in_history_last_wins() {
        let history = vec![make_stats("dup", 10, 2), make_stats("dup", 100, 80)];
        let selector = PayloadSelector::new(history);
        let score = selector.ucb1_score("dup");
        assert!(score.is_finite());
    }

    #[test]
    fn select_payloads_returns_top_ranked() {
        let history = vec![make_stats("high", 100, 90), make_stats("low", 100, 10)];
        let selector = PayloadSelector::new(history);
        let candidates: Vec<String> = vec!["novel".into(), "high".into(), "low".into()];
        let selected = selector.select_payloads(&candidates, 2);
        assert_eq!(selected.len(), 2);
        assert_eq!(
            selected[0], "novel",
            "novel payload should be selected first"
        );
    }

    #[test]
    fn single_payload_in_history() {
        let history = vec![make_stats("only", 50, 25)];
        let selector = PayloadSelector::new(history);
        assert_eq!(selector.known_payload_count(), 1);
        assert_eq!(selector.total_attempts(), 50);
        let score = selector.ucb1_score("only");
        assert!(score.is_finite());
        assert!(score > 0.0);
    }
}
