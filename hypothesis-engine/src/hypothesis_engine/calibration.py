from __future__ import annotations

import math
from dataclasses import dataclass, field


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
