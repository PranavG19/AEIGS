from __future__ import annotations

from unittest.mock import MagicMock

from hypothesis_engine.bedrock_client import LlmBackend, TokenUsage
from hypothesis_engine.generator import (
    GenerationResult,
    Hypothesis,
    HypothesisGenerator,
    ScanContext,
    _consistency_key,
)


class TestConsistencyKey:
    def test_extracts_endpoint_from_condition(self) -> None:
        h = Hypothesis(
            condition="IF endpoint /api/search accepts parameter q",
            vulnerability_class="SQL Injection",
            reasoning="test",
            test_approach="test",
            confidence=0.8,
        )
        key = _consistency_key(h)
        assert key == ("SQL Injection", "/api/search")

    def test_no_endpoint_in_condition(self) -> None:
        h = Hypothesis(
            condition="IF the application uses default settings",
            vulnerability_class="Security Misconfiguration",
            reasoning="test",
            test_approach="test",
            confidence=0.5,
        )
        key = _consistency_key(h)
        assert key == ("Security Misconfiguration", "")

    def test_strips_trailing_punctuation(self) -> None:
        h = Hypothesis(
            condition="IF endpoint /api/users, which handles user data",
            vulnerability_class="SQL Injection",
            reasoning="test",
            test_approach="test",
            confidence=0.7,
        )
        key = _consistency_key(h)
        assert key == ("SQL Injection", "/api/users")


class TestGenerateWithConsistency:
    def _make_generator_with_rounds(
        self, round_hypotheses: list[list[Hypothesis]]
    ) -> HypothesisGenerator:
        call_count = 0

        class RoundMockBackend(LlmBackend):
            def invoke(self, messages, system="", max_tokens=4096):
                nonlocal call_count
                idx = call_count
                call_count += 1
                hyps = round_hypotheses[idx % len(round_hypotheses)]
                import json
                json_str = json.dumps([h.model_dump() for h in hyps])
                return (json_str, TokenUsage(input_tokens=10, output_tokens=20))

            def invoke_structured(self, messages, output_schema, system="", max_tokens=4096):
                return self.invoke(messages, system, max_tokens)

        return HypothesisGenerator(client=RoundMockBackend())

    def test_filters_to_consistent_hypotheses(self) -> None:
        consistent_h = Hypothesis(
            condition="IF endpoint /api/search accepts parameter q",
            vulnerability_class="SQL Injection",
            reasoning="test",
            test_approach="test",
            confidence=0.8,
        )
        inconsistent_h = Hypothesis(
            condition="IF endpoint /api/random is vulnerable",
            vulnerability_class="Path Traversal",
            reasoning="test",
            test_approach="test",
            confidence=0.6,
        )

        gen = self._make_generator_with_rounds([
            [consistent_h, inconsistent_h],
            [consistent_h],
            [consistent_h],
        ])

        ctx = ScanContext()
        result = gen.generate_with_consistency(ctx, num_rounds=3, agreement_threshold=2)

        classes = [h.vulnerability_class for h in result.hypotheses]
        assert "SQL Injection" in classes
        assert "Path Traversal" not in classes

    def test_agreement_threshold_respected(self) -> None:
        h = Hypothesis(
            condition="IF endpoint /api/test is vulnerable",
            vulnerability_class="XSS",
            reasoning="test",
            test_approach="test",
            confidence=0.7,
        )
        gen = self._make_generator_with_rounds([
            [h],
            [],
            [],
        ])

        ctx = ScanContext()
        result = gen.generate_with_consistency(ctx, num_rounds=3, agreement_threshold=2)
        assert len(result.hypotheses) == 0

    def test_token_usage_accumulated(self) -> None:
        h = Hypothesis(
            condition="IF endpoint /test is vulnerable",
            vulnerability_class="XSS",
            reasoning="test",
            test_approach="test",
            confidence=0.5,
        )
        gen = self._make_generator_with_rounds([[h], [h], [h]])

        ctx = ScanContext()
        result = gen.generate_with_consistency(ctx, num_rounds=3)
        assert result.input_tokens == 30
        assert result.output_tokens == 60

    def test_uses_median_confidence_not_max(self) -> None:
        low = Hypothesis(
            condition="IF endpoint /api/search is injectable",
            vulnerability_class="SQL Injection",
            reasoning="low",
            test_approach="test",
            confidence=0.5,
        )
        high = Hypothesis(
            condition="IF endpoint /api/search accepts unvalidated input",
            vulnerability_class="SQL Injection",
            reasoning="high",
            test_approach="test",
            confidence=0.9,
        )
        mid = Hypothesis(
            condition="IF endpoint /api/search has no parameterization",
            vulnerability_class="SQL Injection",
            reasoning="mid",
            test_approach="test",
            confidence=0.7,
        )
        gen = self._make_generator_with_rounds([[low], [high], [mid]])

        ctx = ScanContext()
        result = gen.generate_with_consistency(ctx, num_rounds=3, agreement_threshold=2)
        assert len(result.hypotheses) == 1
        assert result.hypotheses[0].confidence == 0.7
