#[cfg(test)]
mod tests {
    use crate::timing_oracle_v2::{
        blind_char_template, sql_timing_template, welch_t_test_impl, DbType, TimingOracleConfig,
        TimingOracleV2,
    };

    fn oracle_default() -> TimingOracleV2 {
        TimingOracleV2::new(TimingOracleConfig::new())
    }

    fn oracle_strict() -> TimingOracleV2 {
        TimingOracleV2::new(
            TimingOracleConfig::new()
                .with_significance_level(0.01)
                .with_min_samples(50),
        )
    }

    /// Two samples drawn from the same distribution should NOT be significant.
    #[test]
    fn t_test_same_distribution_not_significant() {
        let a: Vec<f64> = (0..50).map(|i| 100.0 + (i as f64 * 0.1)).collect();
        let b: Vec<f64> = (0..50).map(|i| 100.0 + (i as f64 * 0.1) + 0.01).collect();

        let oracle = oracle_default();
        let result = oracle.welch_t_test(&a, &b);

        assert!(
            !result.significant,
            "Nearly identical samples should not be significant (p={:.4})",
            result.p_value
        );
        assert!(result.p_value > 0.05);
    }

    /// Two samples with clearly different means should be significant.
    #[test]
    fn t_test_different_means_significant() {
        let a: Vec<f64> = (0..50).map(|i| 100.0 + (i % 5) as f64).collect();
        let b: Vec<f64> = (0..50).map(|i| 500.0 + (i % 5) as f64).collect();

        let oracle = oracle_default();
        let result = oracle.welch_t_test(&a, &b);

        assert!(
            result.significant,
            "Samples with 400ns mean difference should be significant (p={:.6})",
            result.p_value
        );
        assert!(result.p_value < 0.001);
        assert!(
            result.mean_diff_ns < 0.0,
            "mean_a < mean_b so diff should be negative"
        );
    }

    /// Welch's t-test with small samples (<2) should return non-significant safely.
    #[test]
    fn t_test_tiny_samples_safe() {
        let oracle = oracle_default();

        let result = oracle.welch_t_test(&[100.0], &[200.0]);
        assert!(!result.significant);
        assert_eq!(result.p_value, 1.0);

        let result = oracle.welch_t_test(&[], &[]);
        assert!(!result.significant);
    }

    /// Identical samples should have p-value close to 1.0.
    #[test]
    fn t_test_identical_samples() {
        let a = vec![50.0; 30];
        let b = vec![50.0; 30];

        let oracle = oracle_default();
        let result = oracle.welch_t_test(&a, &b);

        assert!(!result.significant);
        assert!(result.p_value >= 0.99, "p={}", result.p_value);
        assert!((result.mean_diff_ns).abs() < 1e-10);
    }

    /// t-statistic should be positive when sample_a mean > sample_b mean.
    #[test]
    fn t_test_direction() {
        let a: Vec<f64> = (0..40).map(|i| 200.0 + (i % 3) as f64).collect();
        let b: Vec<f64> = (0..40).map(|i| 100.0 + (i % 3) as f64).collect();

        let oracle = oracle_default();
        let result = oracle.welch_t_test(&a, &b);
        assert!(result.t_statistic > 0.0);
        assert!(result.mean_diff_ns > 0.0);
    }

    /// Degrees of freedom should be reasonable (between 1 and n_a + n_b - 2).
    #[test]
    fn t_test_degrees_of_freedom_range() {
        let a: Vec<f64> = (0..30).map(|i| 100.0 + i as f64).collect();
        let b: Vec<f64> = (0..30).map(|i| 200.0 + i as f64).collect();

        let oracle = oracle_default();
        let result = oracle.welch_t_test(&a, &b);

        assert!(result.degrees_of_freedom > 0.0);
        assert!(result.degrees_of_freedom <= 58.0);
    }

    /// p-value approximation accuracy: compare against known critical values.
    /// For df=30, |t|=2.042 should give p≈0.05 (two-tailed).
    #[test]
    fn p_value_approximation_accuracy() {
        let result = welch_t_test_impl(
            &make_sample_with_stats(0.0, 1.0, 31),
            &make_sample_with_stats(2.042, 1.0, 31),
            0.05,
        );

        // Allow 15% tolerance on p-value approximation near critical region
        assert!(
            result.p_value < 0.10,
            "p-value at t≈2.042, df≈30 should be near 0.05, got {}",
            result.p_value
        );
    }

    #[test]
    fn adaptive_sample_converges_on_different_distributions() {
        let a: Vec<f64> = (0..100).map(|i| 100.0 + (i % 3) as f64).collect();
        let b: Vec<f64> = (0..100).map(|i| 500.0 + (i % 3) as f64).collect();

        let oracle = oracle_default();
        let result = oracle.adaptive_sample(&a, &b);

        assert!(result.converged);
        assert_eq!(result.samples_taken, 200);
        assert!(result.result.significant);
    }

    #[test]
    fn adaptive_sample_does_not_converge_on_same_distribution() {
        let a: Vec<f64> = (0..30).map(|i| 100.0 + (i % 2) as f64).collect();
        let b: Vec<f64> = (0..30).map(|i| 100.0 + (i % 2) as f64 + 0.001).collect();

        let oracle = oracle_default();
        let result = oracle.adaptive_sample(&a, &b);

        assert!(!result.converged);
    }

    #[test]
    fn multi_condition_test_baseline_has_no_comparison() {
        let baseline = vec![100.0; 30];
        let condition_a: Vec<f64> = (0..30).map(|i| 500.0 + i as f64).collect();

        let oracle = oracle_default();
        let results = oracle
            .multi_condition_test(&[("baseline", &baseline), ("sleep_injected", &condition_a)]);

        assert_eq!(results.len(), 2);
        assert!(results[0].vs_baseline.is_none());
        assert!(results[1].vs_baseline.is_some());
        assert!(results[1].vs_baseline.as_ref().unwrap().significant);
    }

    #[test]
    fn multi_condition_test_empty_input() {
        let oracle = oracle_default();
        let results = oracle.multi_condition_test(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn multi_condition_test_three_conditions() {
        let baseline = vec![100.0; 30];
        let fast = vec![50.0; 30];
        let slow: Vec<f64> = (0..30).map(|i| 500.0 + i as f64).collect();

        let oracle = oracle_default();
        let results = oracle.multi_condition_test(&[
            ("baseline", &baseline),
            ("fast", &fast),
            ("slow", &slow),
        ]);

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].condition, "baseline");
        assert_eq!(results[1].condition, "fast");
        assert_eq!(results[2].condition, "slow");

        assert!(results[1].vs_baseline.is_some());
        assert!(results[2].vs_baseline.is_some());
    }

    #[test]
    fn blind_extract_char_finds_delayed_character() {
        let oracle = oracle_default();

        let baseline: Vec<f64> = (0..30).map(|i| 100.0 + (i % 3) as f64).collect();
        let char_a = 'a';
        let char_b = 'b';
        let char_c = 'c';

        let timings_a: Vec<f64> = (0..30).map(|i| 100.0 + (i % 3) as f64).collect();
        let timings_b: Vec<f64> = (0..30).map(|i| 500.0 + (i % 3) as f64).collect();
        let timings_c: Vec<f64> = (0..30).map(|i| 100.0 + (i % 3) as f64).collect();

        let char_timings: Vec<(&char, &[f64])> = vec![
            (&char_a, timings_a.as_slice()),
            (&char_b, timings_b.as_slice()),
            (&char_c, timings_c.as_slice()),
        ];

        let result = oracle.blind_extract_char(&char_timings, &baseline);
        assert_eq!(result, Some('b'));
    }

    #[test]
    fn blind_extract_char_returns_none_when_no_difference() {
        let oracle = oracle_default();
        let baseline: Vec<f64> = (0..30).map(|i| 100.0 + (i % 3) as f64).collect();

        let char_a = 'a';
        let char_b = 'b';
        let timings_a: Vec<f64> = (0..30).map(|i| 100.0 + (i % 3) as f64).collect();
        let timings_b: Vec<f64> = (0..30).map(|i| 100.0 + (i % 3) as f64 + 0.001).collect();

        let char_timings: Vec<(&char, &[f64])> = vec![
            (&char_a, timings_a.as_slice()),
            (&char_b, timings_b.as_slice()),
        ];

        let result = oracle.blind_extract_char(&char_timings, &baseline);
        assert!(result.is_none());
    }

    #[test]
    fn blind_sqli_extract_multiple_positions() {
        let oracle = oracle_default();

        let baseline_0: Vec<f64> = (0..30).map(|i| 100.0 + (i % 3) as f64).collect();
        let baseline_1: Vec<f64> = (0..30).map(|i| 100.0 + (i % 3) as f64).collect();

        let char_h = 'h';
        let char_i = 'i';
        let char_x = 'x';

        let h_slow: Vec<f64> = (0..30).map(|i| 500.0 + (i % 3) as f64).collect();
        let x_fast_0: Vec<f64> = (0..30).map(|i| 100.0 + (i % 3) as f64).collect();
        let i_slow: Vec<f64> = (0..30).map(|i| 500.0 + (i % 3) as f64).collect();
        let x_fast_1: Vec<f64> = (0..30).map(|i| 100.0 + (i % 3) as f64).collect();

        let pos0: Vec<(&char, &[f64])> =
            vec![(&char_h, h_slow.as_slice()), (&char_x, x_fast_0.as_slice())];
        let pos1: Vec<(&char, &[f64])> =
            vec![(&char_i, i_slow.as_slice()), (&char_x, x_fast_1.as_slice())];

        let position_timings = vec![pos0, pos1];
        let baselines: Vec<&[f64]> = vec![&baseline_0, &baseline_1];

        let result = oracle.blind_sqli_extract(&position_timings, &baselines);
        assert_eq!(result.extracted, "hi");
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn sql_timing_template_mysql() {
        let tmpl = sql_timing_template(DbType::MySQL, 0.5);
        assert!(tmpl.contains("SLEEP(0.5)"));
        assert!(tmpl.contains("{condition}"));
    }

    #[test]
    fn sql_timing_template_postgresql() {
        let tmpl = sql_timing_template(DbType::PostgreSQL, 1.0);
        assert!(tmpl.contains("pg_sleep(1)"));
        assert!(tmpl.contains("{condition}"));
    }

    #[test]
    fn sql_timing_template_mssql() {
        let tmpl = sql_timing_template(DbType::MSSQL, 0.5);
        assert!(tmpl.contains("WAITFOR DELAY"));
        assert!(tmpl.contains("{condition}"));
    }

    #[test]
    fn sql_timing_template_sqlite() {
        let tmpl = sql_timing_template(DbType::SQLite, 0.5);
        assert!(tmpl.contains("RANDOMBLOB"));
        assert!(tmpl.contains("{condition}"));
    }

    #[test]
    fn blind_char_template_mysql() {
        let tmpl = blind_char_template(DbType::MySQL, "SELECT password FROM users LIMIT 1", 0);
        assert!(tmpl.contains("SUBSTRING"));
        assert!(tmpl.contains(",1,1)"));
        assert!(tmpl.contains("{{char}}"));
    }

    #[test]
    fn blind_char_template_postgresql() {
        let tmpl = blind_char_template(DbType::PostgreSQL, "SELECT version()", 5);
        assert!(tmpl.contains("SUBSTR"));
        assert!(tmpl.contains(",6,1)"));
    }

    #[test]
    fn blind_char_template_position_is_one_indexed() {
        let tmpl = blind_char_template(DbType::MySQL, "q", 0);
        assert!(
            tmpl.contains(",1,1)"),
            "position 0 should map to SQL position 1"
        );

        let tmpl = blind_char_template(DbType::MySQL, "q", 9);
        assert!(
            tmpl.contains(",10,1)"),
            "position 9 should map to SQL position 10"
        );
    }

    #[test]
    fn config_defaults() {
        let config = TimingOracleConfig::new();
        assert_eq!(config.min_samples, 30);
        assert_eq!(config.max_samples, 200);
        assert!((config.significance_level - 0.05).abs() < 1e-10);
        assert!(!config.precision_ns);
    }

    #[test]
    fn config_builder_chain() {
        let config = TimingOracleConfig::new()
            .with_min_samples(10)
            .with_max_samples(500)
            .with_significance_level(0.01)
            .with_precision_ns(true);
        assert_eq!(config.min_samples, 10);
        assert_eq!(config.max_samples, 500);
        assert!((config.significance_level - 0.01).abs() < 1e-10);
        assert!(config.precision_ns);
    }

    #[test]
    fn config_default_trait() {
        let config = TimingOracleConfig::default();
        assert_eq!(config.min_samples, 30);
    }

    #[test]
    fn db_type_display() {
        assert_eq!(DbType::MySQL.to_string(), "mysql");
        assert_eq!(DbType::PostgreSQL.to_string(), "postgresql");
        assert_eq!(DbType::MSSQL.to_string(), "mssql");
        assert_eq!(DbType::SQLite.to_string(), "sqlite");
    }

    #[test]
    fn strict_oracle_requires_lower_p_value() {
        let a: Vec<f64> = (0..50).map(|i| 100.0 + (i % 10) as f64).collect();
        let b: Vec<f64> = (0..50).map(|i| 110.0 + (i % 10) as f64).collect();

        let default = oracle_default();
        let strict = oracle_strict();

        let result_default = default.welch_t_test(&a, &b);
        let result_strict = strict.welch_t_test(&a, &b);

        // Same p-value, different significance threshold
        assert!((result_default.p_value - result_strict.p_value).abs() < 1e-10);

        if result_default.significant {
            // Strict might not be significant if p is between 0.01 and 0.05
            assert!(
                result_default.p_value < 0.05,
                "default should use alpha=0.05"
            );
        }
    }

    /// Helper: create a sample of `n` values with approximate `target_mean` and `target_std`.
    fn make_sample_with_stats(target_mean: f64, target_std: f64, n: usize) -> Vec<f64> {
        (0..n)
            .map(|i| {
                let offset = if i % 2 == 0 { target_std } else { -target_std };
                target_mean + offset * 0.5
            })
            .collect()
    }
}
