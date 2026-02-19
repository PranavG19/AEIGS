from __future__ import annotations

import json
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

from hypothesis_engine.generator import Hypothesis


class HypothesisOutcome(str, Enum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class LabeledHypothesis(BaseModel):
    hypothesis: Hypothesis
    outcome: HypothesisOutcome
    anomaly_score: float = 0.0
    anomaly_details: str = ""
    evasion_attempt: bool = False


class FeedbackStats(BaseModel):
    total_hypotheses: int = 0
    confirmed: int = 0
    refuted: int = 0
    inconclusive: int = 0
    confirmation_rate: float = 0.0
    class_accuracy: dict[str, float] = Field(default_factory=dict)


DEFAULT_CLASS_THRESHOLDS: dict[str, float] = {
    "SqlInjection": 0.4,
    "CrossSiteScripting": 0.3,
    "CommandInjection": 0.6,
    "BrokenAuthentication": 0.7,
    "BrokenAuthorization": 0.7,
}


class FeedbackManager:
    def __init__(
        self,
        confirmation_threshold: float = 0.5,
        class_thresholds: dict[str, float] | None = None,
        default_threshold: float | None = None,
    ) -> None:
        self._labeled: list[LabeledHypothesis] = []
        self._default_threshold = default_threshold if default_threshold is not None else confirmation_threshold
        if class_thresholds is not None:
            self._class_thresholds = dict(class_thresholds)
        else:
            self._class_thresholds = dict(DEFAULT_CLASS_THRESHOLDS)

    def _threshold_for(self, vulnerability_class: str) -> float:
        return self._class_thresholds.get(vulnerability_class, self._default_threshold)

    def label_hypothesis(
        self,
        hypothesis: Hypothesis,
        anomaly_detected: bool,
        anomaly_score: float = 0.0,
        anomaly_details: str = "",
        evasion_attempt: bool = False,
    ) -> LabeledHypothesis:
        threshold = self._threshold_for(hypothesis.vulnerability_class)
        if anomaly_detected and anomaly_score >= threshold:
            outcome = HypothesisOutcome.CONFIRMED
        elif anomaly_detected:
            outcome = HypothesisOutcome.INCONCLUSIVE
        else:
            outcome = HypothesisOutcome.REFUTED

        labeled = LabeledHypothesis(
            hypothesis=hypothesis,
            outcome=outcome,
            anomaly_score=anomaly_score,
            anomaly_details=anomaly_details,
            evasion_attempt=evasion_attempt,
        )
        self._labeled.append(labeled)
        return labeled

    def compute_stats(self) -> FeedbackStats:
        total = len(self._labeled)
        if total == 0:
            return FeedbackStats()

        confirmed = sum(1 for lh in self._labeled if lh.outcome == HypothesisOutcome.CONFIRMED)
        refuted = sum(1 for lh in self._labeled if lh.outcome == HypothesisOutcome.REFUTED)
        inconclusive = sum(
            1 for lh in self._labeled if lh.outcome == HypothesisOutcome.INCONCLUSIVE
        )

        non_inconclusive = confirmed + refuted
        confirmation_rate = confirmed / non_inconclusive if non_inconclusive > 0 else 0.0

        class_counts: dict[str, list[bool]] = {}
        for lh in self._labeled:
            vuln_class = lh.hypothesis.vulnerability_class
            if vuln_class not in class_counts:
                class_counts[vuln_class] = []
            class_counts[vuln_class].append(lh.outcome == HypothesisOutcome.CONFIRMED)

        class_accuracy: dict[str, float] = {}
        for vuln_class, outcomes in class_counts.items():
            if outcomes:
                class_accuracy[vuln_class] = sum(outcomes) / len(outcomes)

        return FeedbackStats(
            total_hypotheses=total,
            confirmed=confirmed,
            refuted=refuted,
            inconclusive=inconclusive,
            confirmation_rate=confirmation_rate,
            class_accuracy=class_accuracy,
        )

    def labeled_hypotheses(self) -> list[LabeledHypothesis]:
        return list(self._labeled)

    def confirmed_hypotheses(self) -> list[LabeledHypothesis]:
        return [lh for lh in self._labeled if lh.outcome == HypothesisOutcome.CONFIRMED]

    def export_training_data(self, output_path: Path) -> int:
        records: list[dict[str, object]] = []
        for lh in self._labeled:
            records.append(
                {
                    "condition": lh.hypothesis.condition,
                    "vulnerability_class": lh.hypothesis.vulnerability_class,
                    "reasoning": lh.hypothesis.reasoning,
                    "test_approach": lh.hypothesis.test_approach,
                    "confidence": lh.hypothesis.confidence,
                    "outcome": lh.outcome.value,
                    "anomaly_score": lh.anomaly_score,
                    "evasion_attempt": lh.evasion_attempt,
                }
            )

        output_path.write_text(json.dumps(records, indent=2))
        return len(records)

    def load_training_data(self, input_path: Path) -> int:
        raw = json.loads(input_path.read_text())
        count = 0
        for item in raw:
            if not isinstance(item, dict):
                continue
            try:
                hypothesis = Hypothesis(
                    condition=item["condition"],
                    vulnerability_class=item["vulnerability_class"],
                    reasoning=item["reasoning"],
                    test_approach=item["test_approach"],
                    confidence=float(item["confidence"]),
                )
                outcome = HypothesisOutcome(item["outcome"])
                labeled = LabeledHypothesis(
                    hypothesis=hypothesis,
                    outcome=outcome,
                    anomaly_score=float(item.get("anomaly_score", 0.0)),
                    evasion_attempt=bool(item.get("evasion_attempt", False)),
                )
                self._labeled.append(labeled)
                count += 1
            except (KeyError, ValueError, TypeError):
                continue

        return count
