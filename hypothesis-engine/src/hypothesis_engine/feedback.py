from __future__ import annotations

import json
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

from hypothesis_engine.generator import Hypothesis

MAX_FEEDBACK_CHARS = 2000
_TRUNCATION_NOTICE = "[truncated — further findings omitted]"


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


class BiasReport(BaseModel):
    is_skewed: bool
    dominant_class: str | None = None
    dominant_fraction: float = 0.0
    class_distribution: dict[str, int] = Field(default_factory=dict)
    rounds_tracked: int = 0


class BiasDetector:
    def __init__(self) -> None:
        self._round_distributions: list[dict[str, int]] = []

    @property
    def round_distributions(self) -> list[dict[str, int]]:
        return list(self._round_distributions)

    def record_round(self, hypotheses: list[Hypothesis]) -> None:
        counts: dict[str, int] = {}
        for h in hypotheses:
            counts[h.vulnerability_class] = counts.get(h.vulnerability_class, 0) + 1
        self._round_distributions.append(counts)

    def detect_skew(self, threshold: float = 0.5) -> BiasReport:
        if not self._round_distributions:
            return BiasReport(is_skewed=False, rounds_tracked=0)

        totals: dict[str, int] = {}
        for dist in self._round_distributions:
            for cls, count in dist.items():
                totals[cls] = totals.get(cls, 0) + count

        grand_total = sum(totals.values())
        if grand_total == 0:
            return BiasReport(
                is_skewed=False,
                class_distribution=totals,
                rounds_tracked=len(self._round_distributions),
            )

        dominant_class = max(totals, key=lambda c: totals[c])
        dominant_fraction = totals[dominant_class] / grand_total

        return BiasReport(
            is_skewed=dominant_fraction > threshold,
            dominant_class=dominant_class if dominant_fraction > threshold else None,
            dominant_fraction=dominant_fraction,
            class_distribution=totals,
            rounds_tracked=len(self._round_distributions),
        )

    def suggest_diversity_classes(
        self, confirmed_classes: set[str], all_classes: list[str]
    ) -> list[str]:
        return [c for c in all_classes if c not in confirmed_classes]


def build_diversity_prompt(bias_report: BiasReport, diversity_classes: list[str]) -> str:
    parts: list[str] = []
    if bias_report.is_skewed and bias_report.dominant_class is not None:
        pct = bias_report.dominant_fraction * 100
        parts.append(
            f"WARNING: Hypothesis generation shows distributional skew toward "
            f"{bias_report.dominant_class} ({pct:.0f}%). "
            f"Prioritize hypotheses for under-represented classes: "
            f"{', '.join(c for c in bias_report.class_distribution if c != bias_report.dominant_class)}"
        )
    if diversity_classes:
        parts.append(
            "The following vulnerability classes have not yet been confirmed "
            f"and should be explored: {', '.join(diversity_classes)}"
        )
    return "\n".join(parts)


def build_feedback_summary(confirmed_findings: list[LabeledHypothesis]) -> str:
    """Build a prompt-safe feedback string from confirmed findings.

    Only metadata fields (vulnerability_class, outcome, anomaly_score) are
    included. The anomaly_details field is intentionally excluded because it
    may contain target-controlled content that could inject instructions into
    the LLM prompt.
    """
    sorted_findings = sorted(confirmed_findings, key=lambda lh: lh.anomaly_score, reverse=True)
    summary = ""
    for lh in sorted_findings:
        # Format using only metadata from our own system — never target-controlled fields
        entry = (
            f"  - {lh.hypothesis.vulnerability_class} [{lh.outcome.value}]"
            f" score={lh.anomaly_score:.2f}\n"
        )
        if len(summary) + len(entry) > MAX_FEEDBACK_CHARS - len(_TRUNCATION_NOTICE):
            summary += _TRUNCATION_NOTICE
            break
        summary += entry
    return summary
