from __future__ import annotations

import json
import tempfile
from pathlib import Path

from hypothesis_engine.calibration import (
    CalibrationBin,
    apply_calibration,
    build_calibration_bins,
    compute_calibration_report,
    compute_ece_for_fixtures,
    fit_temperature_scaling,
    fit_temperature_scaling_cv,
    record_prediction,
    should_recalibrate,
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


class TestShouldRecalibrate:
    def test_returns_true_when_last_model_is_none(self) -> None:
        assert should_recalibrate("claude-sonnet-4-6", None) is True

    def test_returns_true_when_models_differ(self) -> None:
        assert should_recalibrate("claude-sonnet-4-6", "claude-3-haiku") is True

    def test_returns_false_when_models_match(self) -> None:
        assert should_recalibrate("claude-sonnet-4-6", "claude-sonnet-4-6") is False

    def test_empty_string_model_ids(self) -> None:
        assert should_recalibrate("", "") is False

    def test_empty_vs_nonempty(self) -> None:
        assert should_recalibrate("claude-sonnet-4-6", "") is True


class TestComputeEceForFixtures:
    def _make_fixture(
        self,
        ground_truth: list[dict],
        golden_hypotheses: list[dict],
    ) -> dict:
        return {
            "app_name": "test-app",
            "scan_context": {"technology_stack": ["Test"]},
            "ground_truth": ground_truth,
            "golden_hypotheses": golden_hypotheses,
        }

    def test_returns_none_for_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = compute_ece_for_fixtures(Path(tmpdir), "model-1")
            assert result is None

    def test_returns_none_for_no_json_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "readme.txt").write_text("not a fixture")
            result = compute_ece_for_fixtures(Path(tmpdir), "model-1")
            assert result is None

    def test_returns_float_for_valid_fixtures(self) -> None:
        fixture = self._make_fixture(
            ground_truth=[
                {"endpoint": "/api/search", "vulnerability_class": "SQL Injection"},
            ],
            golden_hypotheses=[
                {
                    "condition": "IF /api/search accepts raw SQL",
                    "vulnerability_class": "SQL Injection",
                    "reasoning": "r",
                    "test_approach": "t",
                    "confidence": 0.8,
                },
            ],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test_app.json").write_text(json.dumps(fixture))
            result = compute_ece_for_fixtures(Path(tmpdir), "model-1")
            assert result is not None
            assert 0.0 <= result <= 1.0

    def test_handles_malformed_json_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "bad.json").write_text("{broken json")
            result = compute_ece_for_fixtures(Path(tmpdir), "model-1")
            assert result is None

    def test_skips_fixtures_without_ground_truth(self) -> None:
        fixture = {"app_name": "test-app", "golden_hypotheses": []}
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "empty.json").write_text(json.dumps(fixture))
            result = compute_ece_for_fixtures(Path(tmpdir), "model-1")
            assert result is None

    def test_real_fixtures_produce_valid_ece(self) -> None:
        fixtures_dir = Path(__file__).parent.parent.parent / "tests" / "fixtures"
        if not fixtures_dir.exists():
            return
        result = compute_ece_for_fixtures(fixtures_dir, "test-model")
        assert result is not None
        assert 0.0 <= result <= 1.0

    def test_unmatched_hypothesis_is_false_prediction(self) -> None:
        fixture = self._make_fixture(
            ground_truth=[
                {"endpoint": "/api/search", "vulnerability_class": "SQL Injection"},
            ],
            golden_hypotheses=[
                {
                    "condition": "IF /different/endpoint has XSS",
                    "vulnerability_class": "Cross-Site Scripting",
                    "reasoning": "r",
                    "test_approach": "t",
                    "confidence": 0.9,
                },
            ],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test_app.json").write_text(json.dumps(fixture))
            result = compute_ece_for_fixtures(Path(tmpdir), "model-1")
            assert result is not None
            assert result > 0.0


class TestFitTemperatureScalingCv:
    def _make_group(
        self,
        predictions: list[float],
        outcomes: list[bool],
    ) -> list[CalibrationBin]:
        bins = build_calibration_bins()
        for pred, outcome in zip(predictions, outcomes):
            record_prediction(bins, pred, outcome)
        return bins

    def test_falls_back_with_fewer_than_k_groups(self) -> None:
        group1 = self._make_group(
            [0.9] * 10 + [0.1] * 10,
            [True] * 10 + [False] * 10,
        )
        a, b = fit_temperature_scaling_cv([group1], k=3)
        a_direct, b_direct = fit_temperature_scaling(group1)
        assert abs(a - a_direct) < 1e-9
        assert abs(b - b_direct) < 1e-9

    def test_with_exactly_k_groups(self) -> None:
        groups = [
            self._make_group([0.9] * 10 + [0.1] * 10, [True] * 10 + [False] * 10),
            self._make_group([0.8] * 10 + [0.2] * 10, [True] * 10 + [False] * 10),
            self._make_group([0.7] * 10 + [0.3] * 10, [True] * 10 + [False] * 10),
        ]
        a, b = fit_temperature_scaling_cv(groups, k=3)
        assert isinstance(a, float)
        assert isinstance(b, float)

    def test_with_more_than_k_groups(self) -> None:
        groups = [
            self._make_group([0.9] * 10 + [0.1] * 10, [True] * 10 + [False] * 10),
            self._make_group([0.8] * 10 + [0.2] * 10, [True] * 10 + [False] * 10),
            self._make_group([0.7] * 10 + [0.3] * 10, [True] * 10 + [False] * 10),
            self._make_group([0.6] * 10 + [0.4] * 10, [True] * 10 + [False] * 10),
        ]
        a, b = fit_temperature_scaling_cv(groups, k=3)
        assert isinstance(a, float)
        assert isinstance(b, float)

    def test_empty_groups_list(self) -> None:
        a, b = fit_temperature_scaling_cv([], k=3)
        assert a == 1.0
        assert b == 0.0

    def test_single_group_matches_regular_fit(self) -> None:
        group = self._make_group(
            [0.85] * 15 + [0.15] * 15,
            [True] * 15 + [False] * 15,
        )
        a_cv, b_cv = fit_temperature_scaling_cv([group], k=3)
        a_reg, b_reg = fit_temperature_scaling(group)
        assert abs(a_cv - a_reg) < 1e-9
        assert abs(b_cv - b_reg) < 1e-9

    def test_cv_result_is_average_of_folds(self) -> None:
        groups = [
            self._make_group([0.9] * 10, [True] * 10),
            self._make_group([0.1] * 10, [False] * 10),
            self._make_group([0.5] * 10, [True] * 5 + [False] * 5),
        ]
        a, b = fit_temperature_scaling_cv(groups, k=3)
        fold_a_values = []
        fold_b_values = []
        for held_out in range(3):
            train_bins: list[CalibrationBin] = []
            for i, g in enumerate(groups):
                if i != held_out:
                    train_bins.extend(g)
            fa, fb = fit_temperature_scaling(train_bins)
            fold_a_values.append(fa)
            fold_b_values.append(fb)
        expected_a = sum(fold_a_values) / 3
        expected_b = sum(fold_b_values) / 3
        assert abs(a - expected_a) < 1e-9
        assert abs(b - expected_b) < 1e-9
