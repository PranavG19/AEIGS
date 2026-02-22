from __future__ import annotations

from hypothesis_engine.calibration import (
    CalibrationBin,
    apply_calibration,
    build_calibration_bins,
    compute_calibration_report,
    fit_temperature_scaling,
    record_prediction,
)


class TestBuildCalibrationBins:
    def test_default_ten_bins(self) -> None:
        bins = build_calibration_bins()
        assert len(bins) == 10
        assert bins[0].bin_lower == 0.0
        assert bins[9].bin_upper == 1.0

    def test_custom_bin_count(self) -> None:
        bins = build_calibration_bins(num_bins=5)
        assert len(bins) == 5
        assert abs(bins[0].bin_upper - 0.2) < 1e-9


class TestRecordPrediction:
    def test_record_into_correct_bin(self) -> None:
        bins = build_calibration_bins()
        record_prediction(bins, 0.75, True)
        assert bins[7].count == 1
        assert bins[7].predictions == [0.75]
        assert bins[7].outcomes == [True]

    def test_record_boundary_value_1_0(self) -> None:
        bins = build_calibration_bins()
        record_prediction(bins, 1.0, True)
        assert bins[9].count == 1

    def test_record_clamps_out_of_range(self) -> None:
        bins = build_calibration_bins()
        record_prediction(bins, 1.5, False)
        assert bins[9].count == 1

    def test_record_zero(self) -> None:
        bins = build_calibration_bins()
        record_prediction(bins, 0.0, False)
        assert bins[0].count == 1


class TestCalibrationBin:
    def test_empty_bin_properties(self) -> None:
        b = CalibrationBin(bin_lower=0.3, bin_upper=0.4)
        assert b.count == 0
        assert b.mean_confidence == 0.35
        assert b.actual_positive_rate == 0.0

    def test_populated_bin_properties(self) -> None:
        b = CalibrationBin(
            bin_lower=0.7, bin_upper=0.8,
            predictions=[0.72, 0.78, 0.75],
            outcomes=[True, True, False],
        )
        assert b.count == 3
        assert abs(b.mean_confidence - 0.75) < 1e-9
        assert abs(b.actual_positive_rate - 2.0 / 3.0) < 1e-9

    def test_calibration_error(self) -> None:
        b = CalibrationBin(
            bin_lower=0.8, bin_upper=0.9,
            predictions=[0.85, 0.85],
            outcomes=[True, False],
        )
        assert abs(b.calibration_error - abs(0.85 - 0.5)) < 1e-9


class TestComputeCalibrationReport:
    def test_empty_bins(self) -> None:
        bins = build_calibration_bins()
        report = compute_calibration_report(bins)
        assert report.total_predictions == 0
        assert report.expected_calibration_error == 0.0

    def test_perfectly_calibrated(self) -> None:
        bins = build_calibration_bins(num_bins=2)
        for _ in range(10):
            record_prediction(bins, 0.25, False)
        for _ in range(10):
            record_prediction(bins, 0.75, True)
        report = compute_calibration_report(bins)
        assert report.total_predictions == 20
        assert report.expected_calibration_error < 0.3

    def test_overconfident_detection(self) -> None:
        bins = build_calibration_bins(num_bins=5)
        for _ in range(10):
            record_prediction(bins, 0.9, False)
        report = compute_calibration_report(bins)
        assert len(report.overconfident_ranges) > 0

    def test_underconfident_detection(self) -> None:
        bins = build_calibration_bins(num_bins=5)
        for _ in range(10):
            record_prediction(bins, 0.1, True)
        report = compute_calibration_report(bins)
        assert len(report.underconfident_ranges) > 0


class TestTemperatureScaling:
    def test_default_with_no_data(self) -> None:
        bins = build_calibration_bins()
        a, b = fit_temperature_scaling(bins)
        assert a == 1.0
        assert b == 0.0

    def test_fit_with_data(self) -> None:
        bins = build_calibration_bins()
        for _ in range(20):
            record_prediction(bins, 0.9, True)
        for _ in range(20):
            record_prediction(bins, 0.1, False)
        a, b = fit_temperature_scaling(bins)
        assert a != 1.0 or b != 0.0


class TestApplyCalibration:
    def test_identity_scaling(self) -> None:
        # sigmoid(1.0 * 0.0 + 0.0) = sigmoid(0) = 0.5
        result = apply_calibration(0.0, 1.0, 0.0)
        assert abs(result - 0.5) < 0.01

    def test_high_confidence_maps_high(self) -> None:
        result = apply_calibration(0.9, 2.0, -1.0)
        assert result > 0.5

    def test_clamps_extreme_logits(self) -> None:
        result = apply_calibration(100.0, 1.0, 0.0)
        assert result <= 1.0
        result = apply_calibration(-100.0, 1.0, 0.0)
        assert result >= 0.0
