use super::*;
use aegis_protocol::finding::VulnerabilityClass;

#[test]
fn timing_distribution_from_empty_samples() {
    let dist = TimingDistribution::from_samples(&[]);
    assert_eq!(dist.sample_count, 0);
    assert_eq!(dist.mean_ms, 0.0);
}

#[test]
fn timing_distribution_single_sample() {
    let dist = TimingDistribution::from_samples(&[100.0]);
    assert_eq!(dist.sample_count, 1);
    assert!((dist.mean_ms - 100.0).abs() < 0.01);
    assert!((dist.median_ms - 100.0).abs() < 0.01);
    assert!((dist.min_ms - 100.0).abs() < 0.01);
    assert!((dist.max_ms - 100.0).abs() < 0.01);
}

#[test]
fn timing_distribution_basic_stats() {
    let samples = vec![100.0, 200.0, 300.0, 400.0, 500.0];
    let dist = TimingDistribution::from_samples(&samples);

    assert_eq!(dist.sample_count, 5);
    assert!((dist.mean_ms - 300.0).abs() < 0.01);
    assert!((dist.median_ms - 300.0).abs() < 0.01);
    assert!((dist.min_ms - 100.0).abs() < 0.01);
    assert!((dist.max_ms - 500.0).abs() < 0.01);
    assert!(dist.std_dev_ms > 0.0);
}

#[test]
fn timing_distribution_even_sample_median() {
    let samples = vec![100.0, 200.0, 300.0, 400.0];
    let dist = TimingDistribution::from_samples(&samples);
    assert!((dist.median_ms - 250.0).abs() < 0.01);
}

#[test]
fn welch_t_test_significant_difference() {
    let treatment = TimingDistribution::from_samples(&[
        5100.0, 5200.0, 5050.0, 5150.0, 5300.0, 5080.0, 5220.0, 5190.0, 5110.0, 5170.0,
    ]);
    let control = TimingDistribution::from_samples(&[
        100.0, 110.0, 90.0, 120.0, 105.0, 95.0, 115.0, 108.0, 102.0, 98.0,
    ]);

    let result = welch_t_test(&treatment, &control, 0.01);

    assert!(
        result.is_significant,
        "Should detect 5-second timing difference"
    );
    assert!(result.t_statistic > 0.0, "Treatment should be slower");
    assert!(result.p_value < 0.01, "p-value should be < 0.01");
    assert!((result.mean_difference_ms - 5000.0).abs() < 200.0);
}

#[test]
fn welch_t_test_no_significant_difference() {
    let treatment = TimingDistribution::from_samples(&[
        100.0, 105.0, 102.0, 98.0, 103.0, 101.0, 104.0, 99.0, 97.0, 106.0,
    ]);
    let control = TimingDistribution::from_samples(&[
        101.0, 104.0, 100.0, 103.0, 99.0, 102.0, 105.0, 98.0, 100.0, 103.0,
    ]);

    let result = welch_t_test(&treatment, &control, 0.05);

    assert!(
        !result.is_significant,
        "Overlapping distributions should not be significant, p={}",
        result.p_value
    );
}

#[test]
fn welch_t_test_insufficient_samples() {
    let treatment = TimingDistribution::from_samples(&[5000.0]);
    let control = TimingDistribution::from_samples(&[100.0]);

    let result = welch_t_test(&treatment, &control, 0.05);
    assert!(
        !result.is_significant,
        "Single samples cannot be significant"
    );
    assert_eq!(result.p_value, 1.0);
}

#[test]
fn welch_t_test_zero_variance() {
    let treatment = TimingDistribution::from_samples(&[5000.0, 5000.0, 5000.0, 5000.0]);
    let control = TimingDistribution::from_samples(&[100.0, 100.0, 100.0, 100.0]);

    let result = welch_t_test(&treatment, &control, 0.01);
    assert!(
        result.is_significant,
        "Identical-value groups with large gap should be significant"
    );
}

#[test]
fn generate_sqli_payloads() {
    let payloads = generate_timing_payloads(BlindVulnType::BlindSqli, 5.0);
    assert!(
        payloads.len() >= 4,
        "Should generate multiple SQL timing variants"
    );

    let mysql_sleep = &payloads[0];
    assert!(mysql_sleep.treatment.contains("SLEEP"));
    assert!(!mysql_sleep.control.contains("SLEEP"));
    assert!(!mysql_sleep.label.is_empty());
}

#[test]
fn generate_cmdi_payloads() {
    let payloads = generate_timing_payloads(BlindVulnType::BlindCmdi, 5.0);
    assert!(payloads.len() >= 4);

    let unix_sleep = &payloads[0];
    assert!(unix_sleep.treatment.contains("sleep"));
    assert!(!unix_sleep.control.contains("sleep"));
}

#[test]
fn generate_ssrf_payloads() {
    let payloads = generate_timing_payloads(BlindVulnType::BlindSsrf, 3.0);
    assert!(!payloads.is_empty());

    let dns_probe = &payloads[0];
    assert!(dns_probe.treatment.contains("invalid"));
    assert!(dns_probe.control.contains("127.0.0.1"));
}

#[test]
fn generate_ssti_payloads() {
    let payloads = generate_timing_payloads(BlindVulnType::BlindSsti, 2.0);
    assert!(!payloads.is_empty());
}

#[test]
fn generate_xxe_payloads() {
    let payloads = generate_timing_payloads(BlindVulnType::BlindXxe, 3.0);
    assert!(!payloads.is_empty());
    assert!(payloads[0].treatment.contains("DOCTYPE"));
}

#[test]
fn generate_nosql_payloads() {
    let payloads = generate_timing_payloads(BlindVulnType::BlindNosql, 5.0);
    assert!(payloads.len() >= 2);
    assert!(payloads[0].treatment.contains("$where"));
}

#[test]
fn generate_ldap_payloads() {
    let payloads = generate_timing_payloads(BlindVulnType::BlindLdap, 3.0);
    assert!(!payloads.is_empty());
}

#[test]
fn generate_xpath_payloads() {
    let payloads = generate_timing_payloads(BlindVulnType::BlindXpath, 3.0);
    assert!(!payloads.is_empty());
}

#[test]
fn analyze_confirmed_blind_sqli() {
    let config = TimingOracleConfig {
        vuln_type: BlindVulnType::BlindSqli,
        delay_seconds: 5.0,
        significance_level: 0.01,
        jitter_tolerance_ms: 200,
        sample_count: 10,
        ..Default::default()
    };

    let payload = TimingPayloadPair {
        treatment: "1' AND SLEEP(5)-- -".to_string(),
        control: "1' AND 1=1-- -".to_string(),
        label: "MySQL SLEEP".to_string(),
    };

    let mut samples = Vec::new();
    for _ in 0..10 {
        samples.push(TimingSample {
            response_time_ms: 5100.0 + (rand_float() * 100.0),
            status_code: 200,
            is_treatment: true,
        });
        samples.push(TimingSample {
            response_time_ms: 100.0 + (rand_float() * 20.0),
            status_code: 200,
            is_treatment: false,
        });
    }

    let result = analyze_timing_oracle(&samples, &config, &payload);

    assert_eq!(result.verdict, TimingVerdict::Confirmed);
    assert!(result.confidence > 0.7);
    assert!(result.observed_delay_ms > 4000.0);
    assert_eq!(result.vuln_type, BlindVulnType::BlindSqli);
}

#[test]
fn analyze_not_vulnerable() {
    let config = TimingOracleConfig {
        vuln_type: BlindVulnType::BlindCmdi,
        delay_seconds: 5.0,
        significance_level: 0.01,
        jitter_tolerance_ms: 200,
        sample_count: 10,
        ..Default::default()
    };

    let payload = TimingPayloadPair {
        treatment: "; sleep 5".to_string(),
        control: "; echo test".to_string(),
        label: "Unix sleep".to_string(),
    };

    let mut samples = Vec::new();
    for i in 0..10 {
        samples.push(TimingSample {
            response_time_ms: 100.0 + (i as f64 * 1.5),
            status_code: 200,
            is_treatment: true,
        });
        samples.push(TimingSample {
            response_time_ms: 99.0 + (i as f64 * 1.5),
            status_code: 200,
            is_treatment: false,
        });
    }

    let result = analyze_timing_oracle(&samples, &config, &payload);

    assert_eq!(result.verdict, TimingVerdict::NotVulnerable);
}

#[test]
fn analyze_suspicious_wrong_magnitude() {
    let config = TimingOracleConfig {
        vuln_type: BlindVulnType::BlindSqli,
        delay_seconds: 5.0,
        significance_level: 0.01,
        jitter_tolerance_ms: 200,
        sample_count: 10,
        ..Default::default()
    };

    let payload = TimingPayloadPair {
        treatment: "test".to_string(),
        control: "test".to_string(),
        label: "test".to_string(),
    };

    let mut samples = Vec::new();
    for _ in 0..10 {
        samples.push(TimingSample {
            response_time_ms: 15000.0 + (rand_float() * 100.0),
            status_code: 200,
            is_treatment: true,
        });
        samples.push(TimingSample {
            response_time_ms: 100.0 + (rand_float() * 20.0),
            status_code: 200,
            is_treatment: false,
        });
    }

    let result = analyze_timing_oracle(&samples, &config, &payload);

    assert!(
        result.verdict == TimingVerdict::Suspicious || result.verdict == TimingVerdict::Confirmed,
        "15s delay for 5s expected should be suspicious or confirmed, got: {}",
        result.verdict,
    );
}

#[test]
fn remove_outliers_basic() {
    let samples = vec![
        100.0, 102.0, 98.0, 101.0, 99.0, 103.0, 97.0, 100.0, 5000.0, 100.0,
    ];
    let cleaned = remove_outliers(&samples);
    assert!(
        !cleaned.contains(&5000.0),
        "Should remove the 5000ms outlier"
    );
    assert!(cleaned.len() >= 8);
}

#[test]
fn remove_outliers_too_few_samples() {
    let samples = vec![100.0, 200.0, 300.0];
    let cleaned = remove_outliers(&samples);
    assert_eq!(
        cleaned.len(),
        3,
        "Should not remove outliers with < 4 samples"
    );
}

#[test]
fn remove_outliers_uniform_data() {
    let samples = vec![100.0, 100.0, 100.0, 100.0, 100.0];
    let cleaned = remove_outliers(&samples);
    assert_eq!(cleaned.len(), 5, "Should keep all uniform data");
}

#[test]
fn cohens_d_large_effect() {
    let treatment = TimingDistribution::from_samples(&[5100.0, 5200.0, 5050.0, 5150.0, 5300.0]);
    let control = TimingDistribution::from_samples(&[100.0, 110.0, 90.0, 120.0, 105.0]);

    let d = cohens_d(&treatment, &control);
    assert!(
        d > 5.0,
        "5-second difference should produce very large Cohen's d"
    );
}

#[test]
fn cohens_d_negligible_effect() {
    let treatment = TimingDistribution::from_samples(&[100.0, 102.0, 101.0, 99.0, 103.0]);
    let control = TimingDistribution::from_samples(&[100.0, 101.0, 99.0, 102.0, 100.0]);

    let d = cohens_d(&treatment, &control);
    assert!(
        d.abs() < 0.5,
        "Similar distributions should have small effect size"
    );
}

#[test]
fn cohens_d_insufficient_samples() {
    let treatment = TimingDistribution::from_samples(&[5000.0]);
    let control = TimingDistribution::from_samples(&[100.0]);

    let d = cohens_d(&treatment, &control);
    assert_eq!(d, 0.0);
}

#[test]
fn optimal_sample_count_high_variance() {
    let treatment = TimingDistribution::from_samples(&[5000.0, 5500.0, 4500.0, 6000.0, 4000.0]);
    let control = TimingDistribution::from_samples(&[100.0, 150.0, 50.0, 200.0, 80.0]);

    let n = optimal_sample_count(&treatment, &control, 5000.0);
    assert!(n >= 5 && n <= 100);
}

#[test]
fn optimal_sample_count_low_variance() {
    let treatment = TimingDistribution::from_samples(&[5000.0, 5001.0, 4999.0, 5002.0, 4998.0]);
    let control = TimingDistribution::from_samples(&[100.0, 101.0, 99.0, 100.0, 100.0]);

    let n = optimal_sample_count(&treatment, &control, 5000.0);
    assert!(n >= 5, "Even low variance needs minimum samples");
}

#[test]
fn optimal_sample_count_tiny_delay() {
    let treatment = TimingDistribution::from_samples(&[100.0, 100.0, 100.0]);
    let control = TimingDistribution::from_samples(&[100.0, 100.0, 100.0]);

    let n = optimal_sample_count(&treatment, &control, 0.5);
    assert_eq!(n, 30, "Tiny delay should use default sample count");
}

#[test]
fn confirmation_delays_are_proportional() {
    let delays = generate_confirmation_delays(5.0);
    assert_eq!(delays.len(), 4);
    assert!((delays[0] - 2.5).abs() < 0.01);
    assert!((delays[1] - 5.0).abs() < 0.01);
    assert!((delays[2] - 7.5).abs() < 0.01);
    assert!((delays[3] - 10.0).abs() < 0.01);
}

#[test]
fn delay_correlation_perfect_linear() {
    let injected = vec![2.0, 4.0, 6.0, 8.0];
    let observed = vec![2000.0, 4000.0, 6000.0, 8000.0];

    let r = delay_correlation(&injected, &observed);
    assert!((r - 1.0).abs() < 0.01, "Perfect linear should give r=1.0");
}

#[test]
fn delay_correlation_no_relationship() {
    let injected = vec![2.0, 4.0, 6.0, 8.0, 10.0];
    let observed = vec![100.0, 102.0, 98.0, 101.0, 99.0];

    let r = delay_correlation(&injected, &observed);
    assert!(
        r.abs() < 0.5,
        "No timing relationship should give low correlation"
    );
}

#[test]
fn delay_correlation_insufficient_data() {
    let r = delay_correlation(&[1.0], &[100.0]);
    assert_eq!(r, 0.0);
}

#[test]
fn delay_correlation_empty() {
    let r = delay_correlation(&[], &[]);
    assert_eq!(r, 0.0);
}

#[test]
fn blind_vuln_type_to_vulnerability_class() {
    assert_eq!(
        BlindVulnType::BlindSqli.to_vulnerability_class(),
        VulnerabilityClass::SqlInjection
    );
    assert_eq!(
        BlindVulnType::BlindCmdi.to_vulnerability_class(),
        VulnerabilityClass::CommandInjection
    );
    assert_eq!(
        BlindVulnType::BlindSsrf.to_vulnerability_class(),
        VulnerabilityClass::ServerSideRequestForgery
    );
    assert_eq!(
        BlindVulnType::BlindSsti.to_vulnerability_class(),
        VulnerabilityClass::ServerSideTemplateInjection
    );
}

#[test]
fn blind_vuln_type_display() {
    assert_eq!(BlindVulnType::BlindSqli.to_string(), "blind_sqli");
    assert_eq!(BlindVulnType::BlindCmdi.to_string(), "blind_cmdi");
    assert_eq!(BlindVulnType::BlindSsrf.to_string(), "blind_ssrf");
    assert_eq!(BlindVulnType::BlindSsti.to_string(), "blind_ssti");
    assert_eq!(BlindVulnType::BlindLdap.to_string(), "blind_ldap");
    assert_eq!(BlindVulnType::BlindXxe.to_string(), "blind_xxe");
    assert_eq!(BlindVulnType::BlindXpath.to_string(), "blind_xpath");
    assert_eq!(BlindVulnType::BlindNosql.to_string(), "blind_nosql");
}

#[test]
fn timing_verdict_display() {
    assert_eq!(TimingVerdict::Confirmed.to_string(), "CONFIRMED");
    assert_eq!(TimingVerdict::Suspicious.to_string(), "SUSPICIOUS");
    assert_eq!(TimingVerdict::Inconclusive.to_string(), "INCONCLUSIVE");
    assert_eq!(TimingVerdict::NotVulnerable.to_string(), "NOT_VULNERABLE");
}

#[test]
fn default_delay_seconds_reasonable() {
    for vuln_type in &[
        BlindVulnType::BlindSqli,
        BlindVulnType::BlindCmdi,
        BlindVulnType::BlindSsrf,
        BlindVulnType::BlindSsti,
        BlindVulnType::BlindLdap,
        BlindVulnType::BlindXxe,
        BlindVulnType::BlindXpath,
        BlindVulnType::BlindNosql,
    ] {
        let delay = vuln_type.default_delay_seconds();
        assert!(
            delay >= 1.0 && delay <= 10.0,
            "Delay for {} should be 1-10s",
            vuln_type
        );
    }
}

#[test]
fn config_default_values() {
    let config = TimingOracleConfig::default();
    assert_eq!(config.vuln_type, BlindVulnType::BlindSqli);
    assert_eq!(config.sample_count, 10);
    assert_eq!(config.significance_level, 0.01);
    assert_eq!(config.warmup_requests, 3);
}

#[test]
fn format_finding_confirmed() {
    let result = TimingOracleResult {
        vuln_type: BlindVulnType::BlindSqli,
        payload_label: "MySQL SLEEP".to_string(),
        treatment_payload: "test".to_string(),
        control_payload: "test".to_string(),
        treatment_dist: TimingDistribution::from_samples(&[5000.0]),
        control_dist: TimingDistribution::from_samples(&[100.0]),
        t_test: WelchTTestResult {
            t_statistic: 50.0,
            degrees_of_freedom: 18.0,
            p_value: 0.0001,
            mean_difference_ms: 4900.0,
            is_significant: true,
            significance_level: 0.01,
        },
        verdict: TimingVerdict::Confirmed,
        confidence: 0.95,
        expected_delay_ms: 5000.0,
        observed_delay_ms: 4900.0,
    };

    let summary = format_finding(&result);
    assert!(summary.contains("CONFIRMED"));
    assert!(summary.contains("blind_sqli"));
    assert!(summary.contains("MySQL SLEEP"));
    assert!(summary.contains("VULNERABLE"));
}

#[test]
fn format_finding_not_vulnerable() {
    let result = TimingOracleResult {
        vuln_type: BlindVulnType::BlindCmdi,
        payload_label: "Unix sleep".to_string(),
        treatment_payload: "test".to_string(),
        control_payload: "test".to_string(),
        treatment_dist: TimingDistribution::from_samples(&[100.0]),
        control_dist: TimingDistribution::from_samples(&[100.0]),
        t_test: WelchTTestResult {
            t_statistic: 0.1,
            degrees_of_freedom: 18.0,
            p_value: 0.92,
            mean_difference_ms: 1.0,
            is_significant: false,
            significance_level: 0.01,
        },
        verdict: TimingVerdict::NotVulnerable,
        confidence: 0.05,
        expected_delay_ms: 5000.0,
        observed_delay_ms: 1.0,
    };

    let summary = format_finding(&result);
    assert!(summary.contains("NOT_VULNERABLE"));
    assert!(summary.contains("CLEAN"));
}

#[test]
fn t_distribution_p_value_known_values() {
    let p = t_distribution_p_value(0.0, 10.0);
    assert!((p - 1.0).abs() < 0.05, "t=0 should give p≈1.0, got {}", p);

    let p_large = t_distribution_p_value(100.0, 10.0);
    assert!(
        p_large < 0.001,
        "Very large t should give p≈0, got {}",
        p_large
    );
}

#[test]
fn t_distribution_p_value_edge_cases() {
    let p = t_distribution_p_value(f64::INFINITY, 10.0);
    assert_eq!(p, 0.0);

    let p = t_distribution_p_value(f64::NAN, 10.0);
    assert_eq!(p, 1.0);

    let p = t_distribution_p_value(1.0, 0.0);
    assert_eq!(p, 1.0);
}

#[test]
fn all_payload_types_generate_nonempty() {
    let all_types = [
        BlindVulnType::BlindSqli,
        BlindVulnType::BlindCmdi,
        BlindVulnType::BlindSsrf,
        BlindVulnType::BlindSsti,
        BlindVulnType::BlindLdap,
        BlindVulnType::BlindXxe,
        BlindVulnType::BlindXpath,
        BlindVulnType::BlindNosql,
    ];

    for vuln_type in &all_types {
        let payloads = generate_timing_payloads(*vuln_type, 5.0);
        assert!(
            !payloads.is_empty(),
            "No payloads generated for {}",
            vuln_type
        );
        for payload in &payloads {
            assert!(
                !payload.treatment.is_empty(),
                "Empty treatment for {}",
                vuln_type
            );
            assert!(
                !payload.control.is_empty(),
                "Empty control for {}",
                vuln_type
            );
            assert!(!payload.label.is_empty(), "Empty label for {}", vuln_type);
        }
    }
}

#[test]
fn analyze_inconclusive_with_jitter() {
    let config = TimingOracleConfig {
        vuln_type: BlindVulnType::BlindSqli,
        delay_seconds: 5.0,
        significance_level: 0.01,
        jitter_tolerance_ms: 200,
        sample_count: 10,
        ..Default::default()
    };

    let payload = TimingPayloadPair {
        treatment: "test".to_string(),
        control: "test".to_string(),
        label: "test".to_string(),
    };

    let mut samples = Vec::new();
    for i in 0..10 {
        samples.push(TimingSample {
            response_time_ms: 400.0 + (i as f64 * 50.0),
            status_code: 200,
            is_treatment: true,
        });
        samples.push(TimingSample {
            response_time_ms: 100.0 + (i as f64 * 50.0),
            status_code: 200,
            is_treatment: false,
        });
    }

    let result = analyze_timing_oracle(&samples, &config, &payload);

    assert!(
        result.verdict == TimingVerdict::NotVulnerable
            || result.verdict == TimingVerdict::Inconclusive
            || result.verdict == TimingVerdict::Suspicious,
        "300ms difference for 5s expected should not be Confirmed, got {}",
        result.verdict,
    );
}

/// Deterministic pseudo-random float for reproducible tests.
/// Uses a simple linear congruential generator seeded by call count.
fn rand_float() -> f64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(42);
    let val = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mixed = val
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (mixed >> 33) as f64 / (1u64 << 31) as f64
}
