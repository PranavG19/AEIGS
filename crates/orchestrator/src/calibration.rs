use aegis_protocol::finding::FindingData;

use crate::benchmark::GroundTruth;

/// A single observation pairing a finding's confidence score with its ground truth label.
#[derive(Debug, Clone)]
pub struct CalibrationPair {
    pub confidence: f64,
    pub is_true_positive: bool,
}

/// A single bin in a calibration histogram.
#[derive(Debug, Clone)]
pub struct CalibrationBin {
    pub bin_start: f64,
    pub bin_end: f64,
    pub mean_confidence: f64,
    pub actual_positive_rate: f64,
    pub count: usize,
}

/// Calibration analysis of a set of confidence-scored findings.
#[derive(Debug, Clone)]
pub struct CalibrationReport {
    pub bins: Vec<CalibrationBin>,
    pub expected_calibration_error: f64,
    pub total_pairs: usize,
    pub overconfident_bins: usize,
    pub underconfident_bins: usize,
}

/// Pairs each finding's effective confidence with whether it matches a ground truth entry.
///
/// Uses greedy matching by vulnerability class: each ground truth entry can match at most one
/// finding. Unmatched findings are labeled as false positives.
pub fn collect_calibration_pairs(
    findings: &[FindingData],
    ground_truth: &GroundTruth,
) -> Vec<CalibrationPair> {
    let mut matched_gt = vec![false; ground_truth.entries.len()];

    findings
        .iter()
        .map(|finding| {
            let is_tp = find_greedy_match(finding, ground_truth, &mut matched_gt);
            CalibrationPair {
                confidence: finding.effective_confidence(),
                is_true_positive: is_tp,
            }
        })
        .collect()
}

fn find_greedy_match(
    finding: &FindingData,
    ground_truth: &GroundTruth,
    matched_gt: &mut [bool],
) -> bool {
    for (gi, gt_entry) in ground_truth.entries.iter().enumerate() {
        if !matched_gt[gi] && finding.vulnerability_class == gt_entry.vulnerability_class {
            matched_gt[gi] = true;
            return true;
        }
    }
    false
}

/// Computes calibration metrics by binning confidence scores into equal-width intervals.
///
/// Empty bins use the bin midpoint as mean_confidence with actual_positive_rate of 0.0
/// and are excluded from the ECE calculation.
pub fn compute_calibration(pairs: &[CalibrationPair], num_bins: usize) -> CalibrationReport {
    let bin_width = 1.0 / num_bins as f64;
    let bins: Vec<CalibrationBin> = (0..num_bins)
        .map(|i| build_bin(i, bin_width, pairs))
        .collect();

    let total_pairs = pairs.len();
    let ece = compute_ece(&bins, total_pairs);
    let overconfident_bins = bins
        .iter()
        .filter(|b| b.count > 0 && b.mean_confidence > b.actual_positive_rate)
        .count();
    let underconfident_bins = bins
        .iter()
        .filter(|b| b.count > 0 && b.mean_confidence < b.actual_positive_rate)
        .count();

    CalibrationReport {
        bins,
        expected_calibration_error: ece,
        total_pairs,
        overconfident_bins,
        underconfident_bins,
    }
}

fn build_bin(index: usize, bin_width: f64, pairs: &[CalibrationPair]) -> CalibrationBin {
    let bin_start = index as f64 * bin_width;
    let bin_end = bin_start + bin_width;

    let in_bin: Vec<&CalibrationPair> = pairs
        .iter()
        .filter(|p| is_in_bin(p.confidence, bin_start, bin_end, bin_end >= 1.0))
        .collect();

    if in_bin.is_empty() {
        // midpoint = bin_start + bin_width / 2
        return CalibrationBin {
            bin_start,
            bin_end,
            mean_confidence: bin_start + bin_width / 2.0,
            actual_positive_rate: 0.0,
            count: 0,
        };
    }

    let count = in_bin.len();
    let mean_confidence = in_bin.iter().map(|p| p.confidence).sum::<f64>() / count as f64;
    let tp_count = in_bin.iter().filter(|p| p.is_true_positive).count();
    let actual_positive_rate = tp_count as f64 / count as f64;

    CalibrationBin {
        bin_start,
        bin_end,
        mean_confidence,
        actual_positive_rate,
        count,
    }
}

fn is_in_bin(value: f64, start: f64, end: f64, is_last_bin: bool) -> bool {
    if is_last_bin {
        value >= start && value <= end
    } else {
        value >= start && value < end
    }
}

/// ECE = sum over non-empty bins of (count_i / total) * |mean_conf_i - actual_rate_i|
fn compute_ece(bins: &[CalibrationBin], total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    bins.iter()
        .filter(|b| b.count > 0)
        .map(|b| {
            (b.count as f64 / total as f64) * (b.mean_confidence - b.actual_positive_rate).abs()
        })
        .sum()
}

/// Returns true if the calibration report's ECE is at or below the given threshold.
pub fn is_well_calibrated(report: &CalibrationReport, max_ece: f64) -> bool {
    report.expected_calibration_error <= max_ece
}

#[cfg(test)]
#[path = "calibration_test.rs"]
mod calibration_test;
