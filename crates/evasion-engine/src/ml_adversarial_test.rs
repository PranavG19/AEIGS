use super::ml_adversarial::*;

#[test]
fn ndr_features_have_valid_weights() {
    let features = [
        NdrFeature::InterArrivalTime,
        NdrFeature::PacketSizeDistribution,
        NdrFeature::TlsRecordLength,
        NdrFeature::TcpWindowSize,
        NdrFeature::PayloadEntropy,
        NdrFeature::ByteFrequency,
        NdrFeature::FlowDuration,
        NdrFeature::PacketCount,
        NdrFeature::BurstRatio,
        NdrFeature::ProtocolDistribution,
    ];
    let total_weight: f64 = features.iter().map(|f| f.classifier_weight()).sum();
    assert!(
        (total_weight - 1.0).abs() < 0.01,
        "classifier weights must sum to ~1.0, got {total_weight}"
    );
}

#[test]
fn ndr_features_have_valid_benign_ranges() {
    let features = [
        NdrFeature::InterArrivalTime,
        NdrFeature::PacketSizeDistribution,
        NdrFeature::TlsRecordLength,
        NdrFeature::TcpWindowSize,
        NdrFeature::PayloadEntropy,
        NdrFeature::ByteFrequency,
        NdrFeature::FlowDuration,
        NdrFeature::PacketCount,
        NdrFeature::BurstRatio,
        NdrFeature::ProtocolDistribution,
    ];
    for f in &features {
        let (min, max) = f.benign_range();
        assert!(min < max, "{f:?} benign range min >= max");
    }
}

#[test]
fn benign_vector_has_low_detection_score() {
    let benign = benign_browsing_vector();
    let score = benign.detection_score();
    assert!(
        score < 0.3,
        "benign traffic should have low score, got {score:.4}"
    );
}

#[test]
fn malicious_vector_has_high_detection_score() {
    let malicious = malicious_c2_vector();
    let score = malicious.detection_score();
    assert!(
        score > 0.1,
        "malicious C2 traffic should have elevated score, got {score:.4}"
    );
}

#[test]
fn feature_vector_set_and_get() {
    let mut fv = FeatureVector::new();
    fv.set(NdrFeature::InterArrivalTime, 0.5);
    assert_eq!(fv.get(&NdrFeature::InterArrivalTime), 0.5);
    assert_eq!(fv.get(&NdrFeature::PacketCount), 0.0); // unset returns 0
    assert_eq!(fv.feature_count(), 1);
}

#[test]
fn feature_vector_with_perturbation_does_not_mutate_original() {
    let mut fv = FeatureVector::new();
    fv.set(NdrFeature::InterArrivalTime, 0.5);
    fv.set(NdrFeature::PacketCount, 100.0);

    let perturbed = fv.with_perturbation(NdrFeature::InterArrivalTime, 1.0);
    assert_eq!(fv.get(&NdrFeature::InterArrivalTime), 0.5);
    assert_eq!(perturbed.get(&NdrFeature::InterArrivalTime), 1.0);
    assert_eq!(perturbed.get(&NdrFeature::PacketCount), 100.0);
}

#[test]
fn optimizer_converges_on_already_benign_vector() {
    let config = PerturbationConfig::default().with_target_score(0.3);
    let mut perturber = AdversarialPerturber::with_seed(config, 42);

    let benign = benign_browsing_vector();
    let result = perturber.optimize(&benign).unwrap();
    assert!(result.converged);
    assert_eq!(result.iterations_used, 0);
    assert!(result.perturbations.is_empty());
}

#[test]
fn optimizer_reduces_detection_score() {
    let config = PerturbationConfig::default()
        .with_target_score(0.3)
        .with_max_iterations(200);
    let mut perturber = AdversarialPerturber::with_seed(config, 42);

    let malicious = malicious_c2_vector();
    let original_score = malicious.detection_score();

    let result = perturber.optimize(&malicious).unwrap();
    assert!(
        result.optimized_score <= original_score,
        "optimized score ({:.4}) should be <= original ({:.4})",
        result.optimized_score,
        original_score
    );
}

#[test]
fn optimizer_tracks_perturbation_deltas() {
    let config = PerturbationConfig::default()
        .with_target_score(0.15)
        .with_max_iterations(300);
    let mut perturber = AdversarialPerturber::with_seed(config, 42);

    let malicious = malicious_c2_vector();
    let result = perturber.optimize(&malicious).unwrap();

    if !result.perturbations.is_empty() {
        for (_feature, delta) in &result.perturbations {
            assert!(delta.absolute_change >= 0.0);
            assert!(delta.relative_change >= 0.0);
        }
    }
}

#[test]
fn optimizer_respects_targeted_features() {
    let config = PerturbationConfig::default()
        .with_target_score(0.3)
        .with_max_iterations(200);
    let mut perturber = AdversarialPerturber::with_seed(config, 42).target_features(vec![
        NdrFeature::InterArrivalTime,
        NdrFeature::PacketSizeDistribution,
    ]);

    let malicious = malicious_c2_vector();
    let result = perturber.optimize(&malicious).unwrap();

    for feature in result.perturbations.keys() {
        assert!(
            *feature == NdrFeature::InterArrivalTime
                || *feature == NdrFeature::PacketSizeDistribution,
            "only targeted features should be perturbed, got {feature:?}"
        );
    }
}

#[test]
fn optimizer_rejects_empty_vector() {
    let config = PerturbationConfig::default();
    let mut perturber = AdversarialPerturber::with_seed(config, 42);

    let empty = FeatureVector::new();
    let result = perturber.optimize(&empty);
    assert!(result.is_err());
}

#[test]
fn apply_perturbations_modifies_vector() {
    let config = PerturbationConfig::default()
        .with_target_score(0.2)
        .with_max_iterations(200);
    let mut perturber = AdversarialPerturber::with_seed(config, 42);

    let malicious = malicious_c2_vector();
    let result = perturber.optimize(&malicious).unwrap();

    if !result.perturbations.is_empty() {
        let modified = perturber.apply_perturbations(&malicious, &result.perturbations);
        let new_score = modified.detection_score();
        assert!(
            new_score <= malicious.detection_score(),
            "applied perturbations should reduce score"
        );
    }
}

#[test]
fn statistics_tracking() {
    let config = PerturbationConfig::default().with_target_score(0.5);
    let mut perturber = AdversarialPerturber::with_seed(config, 42);

    assert_eq!(perturber.total_optimizations(), 0);
    assert_eq!(perturber.successful_evasions(), 0);
    assert_eq!(perturber.evasion_rate(), 0.0);

    let benign = benign_browsing_vector();
    let _ = perturber.optimize(&benign).unwrap();
    assert_eq!(perturber.total_optimizations(), 1);
    assert_eq!(perturber.successful_evasions(), 1);
    assert_eq!(perturber.evasion_rate(), 1.0);
}

#[test]
fn detection_score_is_zero_for_perfectly_benign() {
    let mut fv = FeatureVector::new();
    fv.set(NdrFeature::InterArrivalTime, 1.0);
    fv.set(NdrFeature::PacketSizeDistribution, 500.0);
    fv.set(NdrFeature::TlsRecordLength, 4000.0);
    fv.set(NdrFeature::TcpWindowSize, 32768.0);
    fv.set(NdrFeature::PayloadEntropy, 5.0);

    let score = fv.detection_score();
    assert!(
        score < 0.01,
        "all-in-range features should score ~0, got {score:.4}"
    );
}

#[test]
fn perturbation_config_builder() {
    let config = PerturbationConfig::default()
        .with_target_score(0.2)
        .with_max_iterations(100)
        .with_max_perturbation_ratio(0.5);

    assert_eq!(config.target_score, 0.2);
    assert_eq!(config.max_iterations, 100);
    assert_eq!(config.max_perturbation_ratio, 0.5);
}

#[test]
fn nelder_mead_improves_over_iterations() {
    let config = PerturbationConfig::default()
        .with_target_score(0.05)
        .with_max_iterations(100);
    let mut perturber = AdversarialPerturber::with_seed(config, 42);

    let malicious = malicious_c2_vector();
    let original_score = malicious.detection_score();
    let result = perturber.optimize(&malicious).unwrap();

    assert!(
        result.optimized_score <= original_score,
        "optimizer must not make things worse"
    );
    assert!(
        result.iterations_used > 0,
        "should run at least one iteration on malicious vector"
    );
}

#[test]
fn optimized_vector_maintains_unperturbed_features() {
    let config = PerturbationConfig::default()
        .with_target_score(0.3)
        .with_max_iterations(100);
    let mut perturber = AdversarialPerturber::with_seed(config, 42)
        .target_features(vec![NdrFeature::InterArrivalTime]);

    let malicious = malicious_c2_vector();
    let result = perturber.optimize(&malicious).unwrap();

    // Non-targeted features should remain unchanged
    let orig_packet_count = malicious.get(&NdrFeature::PacketCount);
    let opt_packet_count = result.optimized_vector.get(&NdrFeature::PacketCount);
    assert!(
        (orig_packet_count - opt_packet_count).abs() < 1e-10,
        "non-targeted features must not change"
    );
}
