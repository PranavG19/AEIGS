import json
from pathlib import Path

from hypothesis_engine.feedback import (
    FeedbackManager,
    HypothesisOutcome,
    LabeledHypothesis,
)
from hypothesis_engine.generator import Hypothesis


def make_hypothesis(vuln_class: str = "SQL Injection", confidence: float = 0.8) -> Hypothesis:
    return Hypothesis(
        condition=f"IF {vuln_class} is possible",
        vulnerability_class=vuln_class,
        reasoning="test reasoning",
        test_approach="test approach",
        confidence=confidence,
    )


class TestFeedbackManager:
    def test_label_confirmed(self) -> None:
        fm = FeedbackManager(confirmation_threshold=0.5)
        h = make_hypothesis()
        labeled = fm.label_hypothesis(h, anomaly_detected=True, anomaly_score=0.8)
        assert labeled.outcome == HypothesisOutcome.CONFIRMED

    def test_label_refuted(self) -> None:
        fm = FeedbackManager()
        h = make_hypothesis()
        labeled = fm.label_hypothesis(h, anomaly_detected=False)
        assert labeled.outcome == HypothesisOutcome.REFUTED

    def test_label_inconclusive(self) -> None:
        fm = FeedbackManager(confirmation_threshold=0.7)
        h = make_hypothesis()
        labeled = fm.label_hypothesis(h, anomaly_detected=True, anomaly_score=0.3)
        assert labeled.outcome == HypothesisOutcome.INCONCLUSIVE

    def test_labeled_hypotheses_accumulate(self) -> None:
        fm = FeedbackManager()
        fm.label_hypothesis(make_hypothesis(), anomaly_detected=True, anomaly_score=0.8)
        fm.label_hypothesis(make_hypothesis(), anomaly_detected=False)
        assert len(fm.labeled_hypotheses()) == 2

    def test_confirmed_hypotheses_filter(self) -> None:
        fm = FeedbackManager()
        fm.label_hypothesis(make_hypothesis(), anomaly_detected=True, anomaly_score=0.8)
        fm.label_hypothesis(make_hypothesis(), anomaly_detected=False)
        assert len(fm.confirmed_hypotheses()) == 1


class TestFeedbackStats:
    def test_empty_stats(self) -> None:
        fm = FeedbackManager()
        stats = fm.compute_stats()
        assert stats.total_hypotheses == 0
        assert stats.confirmation_rate == 0.0

    def test_stats_counts(self) -> None:
        fm = FeedbackManager(confirmation_threshold=0.5)
        fm.label_hypothesis(make_hypothesis(), anomaly_detected=True, anomaly_score=0.8)
        fm.label_hypothesis(make_hypothesis(), anomaly_detected=False)
        fm.label_hypothesis(make_hypothesis(), anomaly_detected=True, anomaly_score=0.3)

        stats = fm.compute_stats()
        assert stats.total_hypotheses == 3
        assert stats.confirmed == 1
        assert stats.refuted == 1
        assert stats.inconclusive == 1

    def test_confirmation_rate(self) -> None:
        fm = FeedbackManager()
        fm.label_hypothesis(make_hypothesis(), anomaly_detected=True, anomaly_score=0.8)
        fm.label_hypothesis(make_hypothesis(), anomaly_detected=False)

        stats = fm.compute_stats()
        assert stats.confirmation_rate == 0.5

    def test_class_accuracy(self) -> None:
        fm = FeedbackManager()
        fm.label_hypothesis(make_hypothesis("SQLi"), anomaly_detected=True, anomaly_score=0.8)
        fm.label_hypothesis(make_hypothesis("SQLi"), anomaly_detected=False)
        fm.label_hypothesis(make_hypothesis("XSS"), anomaly_detected=True, anomaly_score=0.9)

        stats = fm.compute_stats()
        assert stats.class_accuracy["SQLi"] == 0.5
        assert stats.class_accuracy["XSS"] == 1.0

    def test_confirmation_rate_excludes_inconclusive(self) -> None:
        fm = FeedbackManager(confirmation_threshold=0.7)
        fm.label_hypothesis(make_hypothesis(), anomaly_detected=True, anomaly_score=0.9)
        fm.label_hypothesis(make_hypothesis(), anomaly_detected=True, anomaly_score=0.3)

        stats = fm.compute_stats()
        assert stats.confirmation_rate == 1.0


class TestExportImport:
    def test_export_creates_file(self, tmp_path: Path) -> None:
        fm = FeedbackManager()
        fm.label_hypothesis(make_hypothesis(), anomaly_detected=True, anomaly_score=0.8)
        output = tmp_path / "training.json"
        count = fm.export_training_data(output)
        assert count == 1
        assert output.exists()

    def test_export_valid_json(self, tmp_path: Path) -> None:
        fm = FeedbackManager()
        fm.label_hypothesis(
            make_hypothesis(), anomaly_detected=True, anomaly_score=0.8, anomaly_details="detail"
        )
        output = tmp_path / "training.json"
        fm.export_training_data(output)

        data = json.loads(output.read_text())
        assert len(data) == 1
        assert data[0]["outcome"] == "confirmed"
        assert data[0]["vulnerability_class"] == "SQL Injection"

    def test_import_roundtrip(self, tmp_path: Path) -> None:
        fm1 = FeedbackManager()
        fm1.label_hypothesis(make_hypothesis("SQLi"), anomaly_detected=True, anomaly_score=0.8)
        fm1.label_hypothesis(make_hypothesis("XSS"), anomaly_detected=False)

        output = tmp_path / "training.json"
        fm1.export_training_data(output)

        fm2 = FeedbackManager()
        count = fm2.load_training_data(output)
        assert count == 2
        assert len(fm2.labeled_hypotheses()) == 2

    def test_import_skips_invalid_records(self, tmp_path: Path) -> None:
        output = tmp_path / "training.json"
        output.write_text('[{"invalid": "record"}, "not_a_dict"]')

        fm = FeedbackManager()
        count = fm.load_training_data(output)
        assert count == 0

    def test_export_empty(self, tmp_path: Path) -> None:
        fm = FeedbackManager()
        output = tmp_path / "training.json"
        count = fm.export_training_data(output)
        assert count == 0
        data = json.loads(output.read_text())
        assert data == []


class TestHypothesisOutcome:
    def test_outcome_values(self) -> None:
        assert HypothesisOutcome.CONFIRMED.value == "confirmed"
        assert HypothesisOutcome.REFUTED.value == "refuted"
        assert HypothesisOutcome.INCONCLUSIVE.value == "inconclusive"

    def test_labeled_hypothesis_model(self) -> None:
        h = make_hypothesis()
        lh = LabeledHypothesis(
            hypothesis=h,
            outcome=HypothesisOutcome.CONFIRMED,
            anomaly_score=0.9,
            anomaly_details="SQL error detected",
        )
        assert lh.anomaly_details == "SQL error detected"
