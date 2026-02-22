from hypothesis_engine.generator import Hypothesis
from hypothesis_engine.uncertainty import (
    adjust_confidence,
    extract_uncertainty_score,
    prioritize_hypotheses,
)


def _make_hypothesis(
    confidence: float = 0.8,
    insufficient_data: bool = False,
    vuln_class: str = "SQL Injection",
) -> Hypothesis:
    return Hypothesis(
        condition="IF endpoint accepts input",
        vulnerability_class=vuln_class,
        reasoning="test reasoning",
        test_approach="send payloads",
        confidence=confidence,
        insufficient_data=insufficient_data,
    )


class TestExtractUncertaintyScore:
    def test_extract_uncertainty_score_no_patterns(self) -> None:
        score = extract_uncertainty_score("The application processes user input normally.")
        assert score == 0.5

    def test_extract_uncertainty_score_all_speculative(self) -> None:
        score = extract_uncertainty_score(
            "The technology stack suggests it is commonly vulnerable. "
            "Without seeing the source, it might be exploitable."
        )
        assert score < 0.2

    def test_extract_uncertainty_score_all_structural(self) -> None:
        score = extract_uncertainty_score(
            "Input flows directly to the query. "
            "No validation or sanitization is present. "
            "Graph shows an unprotected endpoint."
        )
        assert score > 0.8

    def test_extract_uncertainty_score_mixed(self) -> None:
        score = extract_uncertainty_score(
            "Input flows to the query without sanitization. "
            "The technology stack suggests default configuration."
        )
        assert 0.2 < score < 0.8


class TestAdjustConfidence:
    def test_adjust_confidence_reduces_with_uncertainty(self) -> None:
        h = _make_hypothesis(confidence=0.8)
        adjusted = adjust_confidence(h, 0.5)
        assert adjusted.confidence < h.confidence
        assert adjusted.confidence == 0.4

    def test_adjust_confidence_insufficient_data_capped(self) -> None:
        h = _make_hypothesis(confidence=0.9, insufficient_data=True)
        adjusted = adjust_confidence(h, 1.0)
        assert adjusted.confidence <= 0.2

    def test_adjust_confidence_clamped_to_bounds(self) -> None:
        h = _make_hypothesis(confidence=0.8)
        adjusted_low = adjust_confidence(h, 0.0)
        assert adjusted_low.confidence >= 0.0

        adjusted_high = adjust_confidence(h, 1.0)
        assert adjusted_high.confidence <= 1.0

    def test_adjust_confidence_does_not_mutate_original(self) -> None:
        h = _make_hypothesis(confidence=0.8)
        adjusted = adjust_confidence(h, 0.5)
        assert h.confidence == 0.8
        assert adjusted.confidence == 0.4


class TestPrioritizeHypotheses:
    def test_prioritize_hypotheses_by_confidence(self) -> None:
        h1 = _make_hypothesis(confidence=0.3)
        h2 = _make_hypothesis(confidence=0.9)
        h3 = _make_hypothesis(confidence=0.6)
        result = prioritize_hypotheses([h1, h2, h3])
        assert [h.confidence for h in result] == [0.9, 0.6, 0.3]

    def test_prioritize_hypotheses_insufficient_data_last(self) -> None:
        h_high = _make_hypothesis(confidence=0.9, insufficient_data=True)
        h_low = _make_hypothesis(confidence=0.2)
        h_mid = _make_hypothesis(confidence=0.5)
        result = prioritize_hypotheses([h_high, h_low, h_mid])
        assert not result[0].insufficient_data
        assert not result[1].insufficient_data
        assert result[2].insufficient_data

    def test_prioritize_hypotheses_empty_list(self) -> None:
        result = prioritize_hypotheses([])
        assert result == []
