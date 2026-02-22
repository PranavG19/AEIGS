import json
from pathlib import Path

from hypothesis_engine.feedback import (
    DEFAULT_CLASS_THRESHOLDS,
    BiasDetector,
    BiasReport,
    FeedbackManager,
    HypothesisOutcome,
    LabeledHypothesis,
    build_diversity_prompt,
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


class TestEvasionAttempt:
    def test_evasion_attempt_defaults_false(self) -> None:
        fm = FeedbackManager()
        labeled = fm.label_hypothesis(make_hypothesis(), anomaly_detected=True, anomaly_score=0.8)
        assert labeled.evasion_attempt is False

    def test_evasion_attempt_set_true(self) -> None:
        fm = FeedbackManager()
        labeled = fm.label_hypothesis(
            make_hypothesis(), anomaly_detected=True, anomaly_score=0.8, evasion_attempt=True
        )
        assert labeled.evasion_attempt is True

    def test_evasion_attempt_in_export(self, tmp_path: Path) -> None:
        fm = FeedbackManager()
        fm.label_hypothesis(
            make_hypothesis(), anomaly_detected=True, anomaly_score=0.8, evasion_attempt=True
        )
        fm.label_hypothesis(make_hypothesis(), anomaly_detected=False, evasion_attempt=False)
        output = tmp_path / "training.json"
        fm.export_training_data(output)

        data = json.loads(output.read_text())
        assert data[0]["evasion_attempt"] is True
        assert data[1]["evasion_attempt"] is False

    def test_evasion_attempt_roundtrip(self, tmp_path: Path) -> None:
        fm1 = FeedbackManager()
        fm1.label_hypothesis(
            make_hypothesis(), anomaly_detected=True, anomaly_score=0.8, evasion_attempt=True
        )
        output = tmp_path / "training.json"
        fm1.export_training_data(output)

        fm2 = FeedbackManager()
        fm2.load_training_data(output)
        assert fm2.labeled_hypotheses()[0].evasion_attempt is True

    def test_evasion_labeled_hypothesis_model(self) -> None:
        h = make_hypothesis()
        lh = LabeledHypothesis(
            hypothesis=h,
            outcome=HypothesisOutcome.CONFIRMED,
            evasion_attempt=True,
        )
        assert lh.evasion_attempt is True


class TestPerClassThresholds:
    def test_sql_injection_confirmed_at_lower_threshold(self) -> None:
        fm = FeedbackManager()
        h = make_hypothesis("SqlInjection")
        labeled = fm.label_hypothesis(h, anomaly_detected=True, anomaly_score=0.45)
        assert labeled.outcome == HypothesisOutcome.CONFIRMED

    def test_xss_confirmed_at_lower_threshold(self) -> None:
        fm = FeedbackManager()
        h = make_hypothesis("CrossSiteScripting")
        labeled = fm.label_hypothesis(h, anomaly_detected=True, anomaly_score=0.35)
        assert labeled.outcome == HypothesisOutcome.CONFIRMED

    def test_broken_auth_inconclusive_below_threshold(self) -> None:
        fm = FeedbackManager()
        h = make_hypothesis("BrokenAuthentication")
        labeled = fm.label_hypothesis(h, anomaly_detected=True, anomaly_score=0.6)
        assert labeled.outcome == HypothesisOutcome.INCONCLUSIVE

    def test_unknown_class_uses_default_threshold(self) -> None:
        fm = FeedbackManager()
        h = make_hypothesis("UnknownVulnClass")
        labeled = fm.label_hypothesis(h, anomaly_detected=True, anomaly_score=0.5)
        assert labeled.outcome == HypothesisOutcome.CONFIRMED

    def test_backwards_compat_confirmation_threshold(self) -> None:
        fm = FeedbackManager(confirmation_threshold=0.9)
        h = make_hypothesis("UnknownVulnClass")
        labeled = fm.label_hypothesis(h, anomaly_detected=True, anomaly_score=0.85)
        assert labeled.outcome == HypothesisOutcome.INCONCLUSIVE


class TestBiasDetector:
    def test_bias_detector_empty_rounds(self) -> None:
        bd = BiasDetector()
        report = bd.detect_skew()
        assert report.is_skewed is False
        assert report.rounds_tracked == 0
        assert report.dominant_class is None
        assert report.class_distribution == {}

    def test_bias_detector_uniform_distribution(self) -> None:
        bd = BiasDetector()
        bd.record_round([
            make_hypothesis("SQLi"),
            make_hypothesis("XSS"),
            make_hypothesis("IDOR"),
            make_hypothesis("SSRF"),
        ])
        report = bd.detect_skew()
        assert report.is_skewed is False
        assert report.dominant_class is None
        assert report.dominant_fraction == 0.25
        assert report.rounds_tracked == 1

    def test_bias_detector_skewed_distribution(self) -> None:
        bd = BiasDetector()
        bd.record_round([
            make_hypothesis("SQLi"),
            make_hypothesis("SQLi"),
            make_hypothesis("SQLi"),
            make_hypothesis("XSS"),
        ])
        report = bd.detect_skew()
        assert report.is_skewed is True
        assert report.dominant_class == "SQLi"
        assert report.dominant_fraction == 0.75
        assert report.class_distribution == {"SQLi": 3, "XSS": 1}

    def test_bias_detector_custom_threshold(self) -> None:
        bd = BiasDetector()
        bd.record_round([
            make_hypothesis("SQLi"),
            make_hypothesis("SQLi"),
            make_hypothesis("XSS"),
        ])
        report_strict = bd.detect_skew(threshold=0.6)
        assert report_strict.is_skewed is True
        assert report_strict.dominant_class == "SQLi"

        report_lenient = bd.detect_skew(threshold=0.8)
        assert report_lenient.is_skewed is False
        assert report_lenient.dominant_class is None

    def test_suggest_diversity_classes(self) -> None:
        bd = BiasDetector()
        all_classes = ["SQLi", "XSS", "IDOR", "SSRF"]
        confirmed = {"SQLi", "IDOR"}
        result = bd.suggest_diversity_classes(confirmed, all_classes)
        assert result == ["XSS", "SSRF"]

    def test_suggest_diversity_classes_all_confirmed(self) -> None:
        bd = BiasDetector()
        all_classes = ["SQLi", "XSS"]
        confirmed = {"SQLi", "XSS"}
        result = bd.suggest_diversity_classes(confirmed, all_classes)
        assert result == []

    def test_build_diversity_prompt_with_skew(self) -> None:
        report = BiasReport(
            is_skewed=True,
            dominant_class="SQLi",
            dominant_fraction=0.75,
            class_distribution={"SQLi": 6, "XSS": 2},
            rounds_tracked=2,
        )
        prompt = build_diversity_prompt(report, ["IDOR", "SSRF"])
        assert "WARNING" in prompt
        assert "SQLi" in prompt
        assert "75%" in prompt
        assert "XSS" in prompt
        assert "IDOR" in prompt
        assert "SSRF" in prompt

    def test_build_diversity_prompt_no_skew(self) -> None:
        report = BiasReport(
            is_skewed=False,
            dominant_fraction=0.25,
            class_distribution={"SQLi": 1, "XSS": 1},
            rounds_tracked=1,
        )
        prompt = build_diversity_prompt(report, [])
        assert "WARNING" not in prompt
        assert prompt == ""

    def test_bias_detector_multiple_rounds(self) -> None:
        bd = BiasDetector()
        bd.record_round([make_hypothesis("SQLi"), make_hypothesis("XSS")])
        bd.record_round([make_hypothesis("SQLi"), make_hypothesis("SQLi")])
        bd.record_round([make_hypothesis("IDOR")])

        report = bd.detect_skew()
        assert report.rounds_tracked == 3
        assert report.class_distribution == {"SQLi": 3, "XSS": 1, "IDOR": 1}
        assert report.dominant_fraction == 3 / 5
        assert report.is_skewed is True
        assert report.dominant_class == "SQLi"


class TestFromHistory:
    def test_high_rate_lowers_threshold(self) -> None:
        rates = {"SqlInjection": 0.85}
        thresholds = FeedbackManager.from_history(rates)
        assert thresholds["SqlInjection"] == 0.3

    def test_low_rate_raises_threshold(self) -> None:
        rates = {"PathTraversal": 0.1}
        thresholds = FeedbackManager.from_history(rates)
        assert thresholds["PathTraversal"] == 0.7

    def test_moderate_rate_keeps_default(self) -> None:
        rates = {"CommandInjection": 0.5}
        thresholds = FeedbackManager.from_history(rates)
        assert thresholds["CommandInjection"] == 0.5

    def test_empty_rates_returns_empty(self) -> None:
        thresholds = FeedbackManager.from_history({})
        assert thresholds == {}

    def test_boundary_values(self) -> None:
        rates = {"A": 0.7, "B": 0.3, "C": 0.71, "D": 0.29}
        thresholds = FeedbackManager.from_history(rates)
        assert thresholds["A"] == 0.5
        assert thresholds["B"] == 0.5
        assert thresholds["C"] == 0.3
        assert thresholds["D"] == 0.7


class TestHistoricalRatesBlending:
    def test_historical_rates_blend_with_defaults(self) -> None:
        fm = FeedbackManager(historical_rates={"SqlInjection": 0.9})
        threshold = fm._threshold_for("SqlInjection")
        expected = 0.5 * DEFAULT_CLASS_THRESHOLDS["SqlInjection"] + 0.5 * 0.3
        assert abs(threshold - expected) < 1e-9

    def test_historical_rates_introduce_new_class(self) -> None:
        fm = FeedbackManager(
            confirmation_threshold=0.5,
            historical_rates={"PathTraversal": 0.1},
        )
        threshold = fm._threshold_for("PathTraversal")
        expected = 0.5 * 0.5 + 0.5 * 0.7
        assert abs(threshold - expected) < 1e-9

    def test_no_historical_rates_uses_defaults(self) -> None:
        fm = FeedbackManager()
        assert fm._threshold_for("SqlInjection") == DEFAULT_CLASS_THRESHOLDS["SqlInjection"]

    def test_none_historical_rates_same_as_no_rates(self) -> None:
        fm_none = FeedbackManager(historical_rates=None)
        fm_default = FeedbackManager()
        assert fm_none._threshold_for("SqlInjection") == fm_default._threshold_for("SqlInjection")
        assert fm_none._threshold_for("UnknownClass") == fm_default._threshold_for("UnknownClass")

    def test_historical_rates_affect_labeling(self) -> None:
        fm = FeedbackManager(historical_rates={"SqlInjection": 0.9})
        h = make_hypothesis("SqlInjection")
        threshold = fm._threshold_for("SqlInjection")
        labeled = fm.label_hypothesis(h, anomaly_detected=True, anomaly_score=threshold)
        assert labeled.outcome == HypothesisOutcome.CONFIRMED
