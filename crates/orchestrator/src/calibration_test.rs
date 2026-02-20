use super::*;

use aegis_protocol::finding::{EvidenceLevel, FindingData, VulnerabilityClass};
use aegis_protocol::operation::ModuleIdentifier;

use crate::benchmark::{GroundTruth, GroundTruthEntry};

fn make_finding_with_confidence(id: u64, class: VulnerabilityClass, score: f64) -> FindingData {
    FindingData::new(
        id,
        class,
        7.0,
        0.8,
        ModuleIdentifier::Fuzzing,
        1700000000000,
    )
    .with_evidence_level(EvidenceLevel::Confirmed)
    .with_confidence_score(score)
}

fn make_finding(id: u64, class: VulnerabilityClass) -> FindingData {
    FindingData::new(
        id,
        class,
        7.0,
        0.8,
        ModuleIdentifier::Fuzzing,
        1700000000000,
    )
    .with_evidence_level(EvidenceLevel::Confirmed)
}

#[test]
fn perfect_calibration_ece_near_zero() {
    // 5 pairs at confidence=0.8, 4 are true positives → 80% TP rate
    // Using 5 pairs avoids FP accumulation error: sum(5 * 0.8) = 4.0 exactly
    let pairs: Vec<CalibrationPair> = (0..5)
        .map(|i| CalibrationPair {
            confidence: 0.8,
            is_true_positive: i < 4,
        })
        .collect();

    let report = compute_calibration(&pairs, 10);

    assert!(report.expected_calibration_error < 1e-9);
    assert_eq!(report.total_pairs, 5);
    assert_eq!(report.overconfident_bins, 0);
    assert_eq!(report.underconfident_bins, 0);
}

#[test]
fn overconfident_has_positive_ece() {
    // 4 pairs at confidence=0.75, only 1 is true positive → 25% TP rate
    // mean_confidence = 0.75, actual_positive_rate = 0.25 → gap = 0.5
    // ECE = (4/4) * 0.5 = 0.5
    let pairs: Vec<CalibrationPair> = (0..4)
        .map(|i| CalibrationPair {
            confidence: 0.75,
            is_true_positive: i < 1,
        })
        .collect();

    let report = compute_calibration(&pairs, 10);

    assert!((report.expected_calibration_error - 0.5).abs() < 1e-9);
    assert_eq!(report.overconfident_bins, 1);
    assert_eq!(report.underconfident_bins, 0);
}

#[test]
fn underconfident_has_positive_ece() {
    // 5 pairs at confidence=0.25, 4 are true positives → 80% TP rate
    // mean_confidence = 0.25, actual_positive_rate = 0.8 → gap = 0.55
    // ECE = (5/5) * 0.55 = 0.55
    let pairs: Vec<CalibrationPair> = (0..5)
        .map(|i| CalibrationPair {
            confidence: 0.25,
            is_true_positive: i < 4,
        })
        .collect();

    let report = compute_calibration(&pairs, 10);

    assert!((report.expected_calibration_error - 0.55).abs() < 1e-9);
    assert_eq!(report.overconfident_bins, 0);
    assert_eq!(report.underconfident_bins, 1);
}

#[test]
fn empty_pairs_gives_zero_ece() {
    let report = compute_calibration(&[], 10);

    assert!((report.expected_calibration_error - 0.0).abs() < 1e-9);
    assert_eq!(report.total_pairs, 0);
    assert_eq!(report.overconfident_bins, 0);
    assert_eq!(report.underconfident_bins, 0);
    assert!(is_well_calibrated(&report, 0.1));
}

#[test]
fn single_pair_valid_bin_assignment() {
    let pairs = vec![CalibrationPair {
        confidence: 0.55,
        is_true_positive: true,
    }];

    let report = compute_calibration(&pairs, 10);

    assert_eq!(report.total_pairs, 1);
    // confidence 0.55 falls in bin [0.5, 0.6)
    let bin = &report.bins[5];
    assert_eq!(bin.count, 1);
    assert!((bin.mean_confidence - 0.55).abs() < 1e-9);
    assert!((bin.actual_positive_rate - 1.0).abs() < 1e-9);
    // ECE = (1/1) * |0.55 - 1.0| = 0.45
    assert!((report.expected_calibration_error - 0.45).abs() < 1e-9);
}

#[test]
fn mixed_bins_with_varying_rates() {
    // Bin [0.2, 0.3): 2 pairs at 0.25, 1 TP → actual_rate = 0.5
    // Bin [0.7, 0.8): 3 pairs at 0.75, 2 TP → actual_rate = 2/3
    let pairs = vec![
        CalibrationPair {
            confidence: 0.25,
            is_true_positive: true,
        },
        CalibrationPair {
            confidence: 0.25,
            is_true_positive: false,
        },
        CalibrationPair {
            confidence: 0.75,
            is_true_positive: true,
        },
        CalibrationPair {
            confidence: 0.75,
            is_true_positive: true,
        },
        CalibrationPair {
            confidence: 0.75,
            is_true_positive: false,
        },
    ];

    let report = compute_calibration(&pairs, 10);

    assert_eq!(report.total_pairs, 5);

    let bin2 = &report.bins[2];
    assert_eq!(bin2.count, 2);
    assert!((bin2.actual_positive_rate - 0.5).abs() < 1e-9);

    let bin7 = &report.bins[7];
    assert_eq!(bin7.count, 3);
    assert!((bin7.actual_positive_rate - 2.0 / 3.0).abs() < 1e-9);

    // ECE = (2/5) * |0.25 - 0.5| + (3/5) * |0.75 - 2/3|
    //     = 0.4 * 0.25 + 0.6 * (1/12)
    //     = 0.1 + 0.05 = 0.15
    assert!((report.expected_calibration_error - 0.15).abs() < 1e-9);
}

#[test]
fn collect_calibration_pairs_with_ground_truth() {
    let gt = GroundTruth {
        entries: vec![
            GroundTruthEntry {
                endpoint: "/api/search".to_string(),
                vulnerability_class: VulnerabilityClass::SqlInjection,
            },
            GroundTruthEntry {
                endpoint: "/api/comments".to_string(),
                vulnerability_class: VulnerabilityClass::CrossSiteScripting,
            },
        ],
    };

    let findings = vec![
        make_finding_with_confidence(0, VulnerabilityClass::SqlInjection, 0.85),
        make_finding_with_confidence(1, VulnerabilityClass::CommandInjection, 0.6),
        make_finding_with_confidence(2, VulnerabilityClass::CrossSiteScripting, 0.75),
    ];

    let pairs = collect_calibration_pairs(&findings, &gt);

    assert_eq!(pairs.len(), 3);
    assert!(pairs[0].is_true_positive);
    assert!((pairs[0].confidence - 0.85).abs() < 1e-9);
    assert!(!pairs[1].is_true_positive);
    assert!((pairs[1].confidence - 0.6).abs() < 1e-9);
    assert!(pairs[2].is_true_positive);
    assert!((pairs[2].confidence - 0.75).abs() < 1e-9);
}

#[test]
fn collect_calibration_pairs_uses_effective_confidence_fallback() {
    let gt = GroundTruth {
        entries: vec![GroundTruthEntry {
            endpoint: "/api/search".to_string(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
        }],
    };

    // 0.9 confidence_from_evidence for Confirmed
    let findings = vec![make_finding(0, VulnerabilityClass::SqlInjection)];

    let pairs = collect_calibration_pairs(&findings, &gt);

    assert_eq!(pairs.len(), 1);
    assert!(pairs[0].is_true_positive);
    assert!((pairs[0].confidence - 0.9).abs() < 1e-9);
}

#[test]
fn collect_calibration_pairs_greedy_matching_consumes_gt_entries() {
    let gt = GroundTruth {
        entries: vec![GroundTruthEntry {
            endpoint: "/api/search".to_string(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
        }],
    };

    let findings = vec![
        make_finding_with_confidence(0, VulnerabilityClass::SqlInjection, 0.8),
        make_finding_with_confidence(1, VulnerabilityClass::SqlInjection, 0.7),
    ];

    let pairs = collect_calibration_pairs(&findings, &gt);

    assert_eq!(pairs.len(), 2);
    assert!(pairs[0].is_true_positive);
    assert!(!pairs[1].is_true_positive);
}

#[test]
fn is_well_calibrated_threshold_check() {
    // 4 pairs at confidence=0.5, 2 TPs → mean=0.5, rate=0.5 → ECE=0 (perfect)
    let perfect: Vec<CalibrationPair> = (0..4)
        .map(|i| CalibrationPair {
            confidence: 0.5,
            is_true_positive: i < 2,
        })
        .collect();

    let report_good = compute_calibration(&perfect, 10);
    assert!(is_well_calibrated(&report_good, 0.1));
    assert!(is_well_calibrated(&report_good, 0.0));

    // 4 pairs at confidence=0.75, 1 TP → mean=0.75, rate=0.25 → ECE=0.5
    let bad: Vec<CalibrationPair> = (0..4)
        .map(|i| CalibrationPair {
            confidence: 0.75,
            is_true_positive: i < 1,
        })
        .collect();

    let report_bad = compute_calibration(&bad, 10);
    assert!(!is_well_calibrated(&report_bad, 0.1));
    assert!(!is_well_calibrated(&report_bad, 0.49));
    assert!(is_well_calibrated(&report_bad, 0.5));
    assert!(is_well_calibrated(&report_bad, 0.6));
}

#[test]
fn empty_bins_use_midpoint_and_zero_rate() {
    let pairs = vec![CalibrationPair {
        confidence: 0.95,
        is_true_positive: true,
    }];

    let report = compute_calibration(&pairs, 10);

    // Bin [0.0, 0.1) should be empty with midpoint 0.05
    let bin0 = &report.bins[0];
    assert_eq!(bin0.count, 0);
    assert!((bin0.mean_confidence - 0.05).abs() < 1e-9);
    assert!((bin0.actual_positive_rate - 0.0).abs() < 1e-9);

    // Only the last bin [0.9, 1.0] has data
    let bin9 = &report.bins[9];
    assert_eq!(bin9.count, 1);
}

#[test]
fn confidence_at_bin_boundary_goes_to_higher_bin() {
    // 0.5 should go to bin [0.5, 0.6), not [0.4, 0.5)
    let pairs = vec![CalibrationPair {
        confidence: 0.5,
        is_true_positive: true,
    }];

    let report = compute_calibration(&pairs, 10);

    assert_eq!(report.bins[4].count, 0);
    assert_eq!(report.bins[5].count, 1);
}

#[test]
fn confidence_exactly_one_goes_to_last_bin() {
    let pairs = vec![CalibrationPair {
        confidence: 1.0,
        is_true_positive: true,
    }];

    let report = compute_calibration(&pairs, 10);

    assert_eq!(report.bins[9].count, 1);
}
