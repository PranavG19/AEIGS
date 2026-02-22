from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CalibrationBin:
    bin_lower: float
    bin_upper: float
    predictions: list[float] = field(default_factory=list)
    outcomes: list[bool] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.predictions)

    @property
    def mean_confidence(self) -> float:
        if not self.predictions:
            return (self.bin_lower + self.bin_upper) / 2
        return sum(self.predictions) / len(self.predictions)

    @property
    def actual_positive_rate(self) -> float:
        if not self.outcomes:
            return 0.0
        return sum(self.outcomes) / len(self.outcomes)

    @property
    def calibration_error(self) -> float:
        return abs(self.mean_confidence - self.actual_positive_rate)


@dataclass
class CalibrationReport:
    bins: list[CalibrationBin]
    total_predictions: int
    expected_calibration_error: float
    overconfident_ranges: list[tuple[float, float]]
    underconfident_ranges: list[tuple[float, float]]
    temperature_a: float = 1.0
    temperature_b: float = 0.0


def build_calibration_bins(num_bins: int = 10) -> list[CalibrationBin]:
    step = 1.0 / num_bins
    return [
        CalibrationBin(bin_lower=i * step, bin_upper=(i + 1) * step)
        for i in range(num_bins)
    ]


def record_prediction(
    bins: list[CalibrationBin],
    confidence: float,
    was_correct: bool,
) -> None:
    confidence = max(0.0, min(1.0, confidence))
    for b in bins:
        if b.bin_lower <= confidence < b.bin_upper or (
            b.bin_upper == 1.0 and confidence == 1.0
        ):
            b.predictions.append(confidence)
            b.outcomes.append(was_correct)
            return


def compute_calibration_report(bins: list[CalibrationBin]) -> CalibrationReport:
    total = sum(b.count for b in bins)
    if total == 0:
        return CalibrationReport(
            bins=bins,
            total_predictions=0,
            expected_calibration_error=0.0,
            overconfident_ranges=[],
            underconfident_ranges=[],
        )

    ece = sum(b.count * b.calibration_error for b in bins) / total

    overconfident: list[tuple[float, float]] = []
    underconfident: list[tuple[float, float]] = []

    for b in bins:
        if b.count < 3:
            continue
        if b.mean_confidence > b.actual_positive_rate + 0.1:
            overconfident.append((b.bin_lower, b.bin_upper))
        elif b.actual_positive_rate > b.mean_confidence + 0.1:
            underconfident.append((b.bin_lower, b.bin_upper))

    a, b_param = fit_temperature_scaling(bins)

    return CalibrationReport(
        bins=bins,
        total_predictions=total,
        expected_calibration_error=ece,
        overconfident_ranges=overconfident,
        underconfident_ranges=underconfident,
        temperature_a=a,
        temperature_b=b_param,
    )


def fit_temperature_scaling(
    bins: list[CalibrationBin],
    learning_rate: float = 0.01,
    iterations: int = 100,
) -> tuple[float, float]:
    """Fit sigmoid temperature scaling: calibrated = sigmoid(a * raw + b).

    Uses gradient descent on log loss to find optimal a and b.
    Returns (a, b) tuple. Default (1.0, 0.0) if no data.
    """
    all_preds: list[float] = []
    all_outcomes: list[float] = []
    for b_item in bins:
        for pred, outcome in zip(b_item.predictions, b_item.outcomes):
            all_preds.append(pred)
            all_outcomes.append(1.0 if outcome else 0.0)

    if len(all_preds) < 5:
        return (1.0, 0.0)

    a = 1.0
    b = 0.0

    for _ in range(iterations):
        grad_a = 0.0
        grad_b = 0.0
        for raw, actual in zip(all_preds, all_outcomes):
            logit = a * raw + b
            logit = max(-20.0, min(20.0, logit))
            calibrated = 1.0 / (1.0 + math.exp(-logit))
            calibrated = max(1e-7, min(1.0 - 1e-7, calibrated))
            error = calibrated - actual
            grad_a += error * raw
            grad_b += error

        n = len(all_preds)
        a -= learning_rate * grad_a / n
        b -= learning_rate * grad_b / n

    return (a, b)


def apply_calibration(raw_confidence: float, a: float, b: float) -> float:
    logit = a * raw_confidence + b
    logit = max(-20.0, min(20.0, logit))
    return 1.0 / (1.0 + math.exp(-logit))


def should_recalibrate(
    current_model_id: str,
    last_model_id: str | None,
) -> bool:
    """Return True when the LLM model has changed and recalibration is needed."""
    if last_model_id is None:
        return True
    return current_model_id != last_model_id


def compute_ece_for_fixtures(
    fixtures_dir: Path,
    model_id: str,
) -> float | None:
    """Compute expected calibration error against ground truth fixtures.

    Loads all JSON fixture files from `fixtures_dir`, builds calibration bins
    from golden hypothesis confidences matched against ground truth, and returns
    the ECE. Returns None if no fixture files are found or no predictions can be
    made.

    The `model_id` parameter is recorded for provenance but does not affect the
    computation — calibration is evaluated on the golden hypotheses in the
    fixtures, not on live model output.
    """
    fixture_files = sorted(fixtures_dir.glob("*.json"))
    if not fixture_files:
        return None

    bins = build_calibration_bins()
    recorded_any = False

    for fixture_path in fixture_files:
        try:
            fixture = json.loads(fixture_path.read_text())
        except (json.JSONDecodeError, OSError):
            continue

        ground_truth = fixture.get("ground_truth", [])
        golden_hypotheses = fixture.get("golden_hypotheses", [])
        if not ground_truth or not golden_hypotheses:
            continue

        gt_set = {
            (g["endpoint"], g["vulnerability_class"]) for g in ground_truth
        }

        for h in golden_hypotheses:
            confidence = h.get("confidence", 0.5)
            condition = h.get("condition", "")
            vuln_class = h.get("vulnerability_class", "")
            matched = any(
                vuln_class == gt_class and gt_endpoint in condition
                for gt_endpoint, gt_class in gt_set
            )
            record_prediction(bins, confidence, matched)
            recorded_any = True

    if not recorded_any:
        return None

    report = compute_calibration_report(bins)
    return report.expected_calibration_error


def fit_temperature_scaling_cv(
    bins_groups: list[list[CalibrationBin]],
    k: int = 3,
) -> tuple[float, float]:
    """Cross-validate temperature scaling across groups of calibration bins.

    Implements leave-one-out cross-validation when enough groups are available.
    Each fold trains on all groups except one and validates on the held-out group.
    Returns the average (a, b) across folds.

    Falls back to fitting on all groups combined if fewer than `k` groups are
    provided.
    """
    if len(bins_groups) < k:
        combined: list[CalibrationBin] = []
        for group in bins_groups:
            combined.extend(group)
        return fit_temperature_scaling(combined)

    fold_a_values: list[float] = []
    fold_b_values: list[float] = []

    for held_out_idx in range(len(bins_groups)):
        train_bins: list[CalibrationBin] = []
        for i, group in enumerate(bins_groups):
            if i != held_out_idx:
                train_bins.extend(group)
        a, b = fit_temperature_scaling(train_bins)
        fold_a_values.append(a)
        fold_b_values.append(b)

    avg_a = sum(fold_a_values) / len(fold_a_values)
    avg_b = sum(fold_b_values) / len(fold_b_values)
    return (avg_a, avg_b)
