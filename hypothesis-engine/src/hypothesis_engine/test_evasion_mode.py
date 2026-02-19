import json
from unittest.mock import MagicMock, patch

import pytest

from hypothesis_engine.bedrock_client import TokenUsage
from hypothesis_engine.evasion_mode import (
    EvasionContext,
    EvasionHypothesisGenerator,
    EvasionPayload,
    EvasionResult,
)


class TestEvasionContext:
    def test_context_creation(self) -> None:
        ctx = EvasionContext(
            vulnerability_class="sqli",
            blocked_payload="' OR 1=1--",
            defense_type="WAF",
            defense_vendor="ModSecurity",
            response_code=403,
            response_snippet="Forbidden",
        )
        assert ctx.vulnerability_class == "sqli"
        assert ctx.blocked_payload == "' OR 1=1--"
        assert ctx.defense_type == "WAF"
        assert ctx.defense_vendor == "ModSecurity"
        assert ctx.response_code == 403
        assert ctx.response_snippet == "Forbidden"

    def test_context_defaults(self) -> None:
        ctx = EvasionContext(
            vulnerability_class="xss",
            blocked_payload="<script>alert(1)</script>",
            defense_type="WAF",
            defense_vendor="Cloudflare",
            response_code=403,
            response_snippet="Blocked",
        )
        assert ctx.previously_attempted_evasions == []


class TestEvasionPayload:
    def test_payload_creation(self) -> None:
        p = EvasionPayload(
            payload="' /*!50000OR*/ 1=1--",
            strategy="MySQL version comment bypass",
            confidence=0.7,
        )
        assert p.payload == "' /*!50000OR*/ 1=1--"
        assert p.strategy == "MySQL version comment bypass"
        assert p.confidence == 0.7

    def test_confidence_bounds(self) -> None:
        with pytest.raises(Exception):
            EvasionPayload(
                payload="test",
                strategy="test",
                confidence=1.5,
            )
        with pytest.raises(Exception):
            EvasionPayload(
                payload="test",
                strategy="test",
                confidence=-0.1,
            )


class TestEvasionResult:
    def test_result_creation(self) -> None:
        evasions = [
            EvasionPayload(
                payload="' /*!50000OR*/ 1=1--",
                strategy="MySQL version comment bypass",
                confidence=0.7,
            )
        ]
        result = EvasionResult(
            evasions=evasions,
            model_id="global.anthropic.claude-sonnet-4-6",
            generation_time_ms=1234.5,
        )
        assert len(result.evasions) == 1
        assert result.model_id == "global.anthropic.claude-sonnet-4-6"
        assert result.generation_time_ms == 1234.5

    def test_empty_evasions(self) -> None:
        result = EvasionResult(
            evasions=[],
            model_id="test-model",
            generation_time_ms=0.0,
        )
        assert result.evasions == []


class TestBuildSystemPrompt:
    def setup_method(self) -> None:
        self.generator = EvasionHypothesisGenerator.__new__(
            EvasionHypothesisGenerator
        )
        self.generator._bypass_examples = {
            "sqli": [
                {"payload": "' OR 1=1--", "technique": "tautology", "targets": ["generic"]},
            ],
            "xss": [
                {"payload": "<script>alert(1)</script>", "technique": "basic_script", "targets": ["generic"]},
            ],
        }

    def test_system_prompt_contains_vulnerability_class(self) -> None:
        ctx = EvasionContext(
            vulnerability_class="sqli",
            blocked_payload="' OR 1=1--",
            defense_type="WAF",
            defense_vendor="ModSecurity",
            response_code=403,
            response_snippet="Forbidden",
        )
        prompt = self.generator._build_system_prompt(ctx)
        assert "sqli" in prompt

    def test_system_prompt_mentions_defense(self) -> None:
        ctx = EvasionContext(
            vulnerability_class="xss",
            blocked_payload="<script>alert(1)</script>",
            defense_type="WAF",
            defense_vendor="Cloudflare",
            response_code=403,
            response_snippet="Blocked",
        )
        prompt = self.generator._build_system_prompt(ctx)
        assert "WAF" in prompt
        assert "Cloudflare" in prompt


class TestParseEvasions:
    def setup_method(self) -> None:
        self.generator = EvasionHypothesisGenerator.__new__(
            EvasionHypothesisGenerator
        )

    def test_parse_valid_json_array(self) -> None:
        response = json.dumps([
            {"payload": "' /*!50000OR*/ 1=1--", "strategy": "version comment", "confidence": 0.8},
            {"payload": "%27%20OR%201%3D1--", "strategy": "url encoding", "confidence": 0.6},
        ])
        results = self.generator._parse_evasions(response, max_evasions=10)
        assert len(results) == 2
        assert results[0].payload == "' /*!50000OR*/ 1=1--"
        assert results[0].confidence == 0.8

    def test_parse_empty_response(self) -> None:
        results = self.generator._parse_evasions("", max_evasions=10)
        assert results == []

    def test_parse_invalid_json(self) -> None:
        results = self.generator._parse_evasions("not json at all", max_evasions=10)
        assert results == []

    def test_parse_skips_invalid_items(self) -> None:
        response = json.dumps([
            {"payload": "test", "strategy": "test strategy", "confidence": 0.5},
            "not_an_object",
            42,
        ])
        results = self.generator._parse_evasions(response, max_evasions=10)
        assert len(results) == 1

    def test_parse_respects_max_evasions(self) -> None:
        items = [
            {"payload": f"payload_{i}", "strategy": f"strategy_{i}", "confidence": 0.5}
            for i in range(20)
        ]
        response = json.dumps(items)
        results = self.generator._parse_evasions(response, max_evasions=3)
        assert len(results) == 3

    def test_parse_with_surrounding_text(self) -> None:
        response = (
            'Here are the evasion payloads:\n'
            '[{"payload": "test", "strategy": "test strategy", "confidence": 0.9}]\n'
            'End of results.'
        )
        results = self.generator._parse_evasions(response, max_evasions=10)
        assert len(results) == 1
        assert results[0].confidence == 0.9


class TestBypassExamplesLoading:
    def test_bypass_examples_loaded(self) -> None:
        generator = EvasionHypothesisGenerator.__new__(
            EvasionHypothesisGenerator
        )
        generator._bypass_examples = generator._load_bypass_examples()
        assert isinstance(generator._bypass_examples, dict)
        assert len(generator._bypass_examples) > 0
        assert "sqli" in generator._bypass_examples
        assert "xss" in generator._bypass_examples


class TestGetRelevantExamples:
    def setup_method(self) -> None:
        self.generator = EvasionHypothesisGenerator.__new__(
            EvasionHypothesisGenerator
        )
        self.generator._bypass_examples = {
            "sqli": [{"payload": "test", "technique": "tautology", "targets": ["generic"]}],
            "xss": [{"payload": "<img>", "technique": "img_tag", "targets": ["generic"]}],
        }

    def test_returns_empty_for_unknown_class(self) -> None:
        results = self.generator._get_relevant_examples("unknown_vulnerability")
        assert results == []

    def test_returns_empty_for_no_match(self) -> None:
        results = self.generator._get_relevant_examples("rce")
        assert results == []


class TestBuildSystemPromptEdgeCases:
    def setup_method(self) -> None:
        self.generator = EvasionHypothesisGenerator.__new__(
            EvasionHypothesisGenerator
        )
        self.generator._bypass_examples = {}

    def test_no_bypass_examples_section(self) -> None:
        ctx = EvasionContext(
            vulnerability_class="unknown_class",
            blocked_payload="test",
            defense_type="WAF",
            defense_vendor="TestVendor",
            response_code=403,
            response_snippet="Blocked",
        )
        prompt = self.generator._build_system_prompt(ctx)
        assert "Known bypass examples" not in prompt
        assert "unknown_class" in prompt

    def test_with_previously_attempted_evasions(self) -> None:
        ctx = EvasionContext(
            vulnerability_class="unknown_class",
            blocked_payload="test",
            defense_type="WAF",
            defense_vendor="TestVendor",
            response_code=403,
            response_snippet="Blocked",
            previously_attempted_evasions=["attempt1", "attempt2"],
        )
        prompt = self.generator._build_system_prompt(ctx)
        assert "attempt1" in prompt
        assert "attempt2" in prompt


class TestParseEvasionsEdgeCases:
    def setup_method(self) -> None:
        self.generator = EvasionHypothesisGenerator.__new__(
            EvasionHypothesisGenerator
        )

    def test_parse_valid_brackets_invalid_json(self) -> None:
        results = self.generator._parse_evasions("[{not valid json}]", max_evasions=10)
        assert results == []

    def test_parse_value_error_in_evasion(self) -> None:
        response = json.dumps([
            {"payload": "test", "strategy": "test", "confidence": "not_a_number"},
        ])
        results = self.generator._parse_evasions(response, max_evasions=10)
        assert results == []

    def test_parse_skips_empty_payload(self) -> None:
        response = json.dumps([
            {"payload": "", "strategy": "test", "confidence": 0.5},
        ])
        results = self.generator._parse_evasions(response, max_evasions=10)
        assert results == []

    def test_parse_skips_empty_strategy(self) -> None:
        response = json.dumps([
            {"payload": "test", "strategy": "", "confidence": 0.5},
        ])
        results = self.generator._parse_evasions(response, max_evasions=10)
        assert results == []


class TestEvasionHypothesisGeneratorInit:
    @patch("hypothesis_engine.evasion_mode.BedrockClient.__init__", return_value=None)
    def test_init_calls_super_and_loads_examples(self, mock_super_init: MagicMock) -> None:
        with patch.object(EvasionHypothesisGenerator, "_load_bypass_examples", return_value={"sqli": []}):
            generator = EvasionHypothesisGenerator()
        mock_super_init.assert_called_once_with(
            model_id="global.anthropic.claude-sonnet-4-6",
            aws_profile="ziya",
            max_retries=3,
            timeout_seconds=120,
        )
        assert generator._bypass_examples == {"sqli": []}


class TestGenerateEvasions:
    def setup_method(self) -> None:
        self.generator = EvasionHypothesisGenerator.__new__(
            EvasionHypothesisGenerator
        )
        self.generator._model_id = "global.anthropic.claude-sonnet-4-6"
        self.generator._bypass_examples = {
            "sqli": [{"payload": "test", "technique": "tautology", "targets": ["generic"]}],
        }

    def test_generate_evasions_returns_result(self) -> None:
        mock_response = json.dumps([
            {"payload": "' /*!OR*/ 1=1--", "strategy": "version comment", "confidence": 0.8},
        ])
        self.generator.invoke = MagicMock(return_value=(mock_response, TokenUsage()))

        ctx = EvasionContext(
            vulnerability_class="sqli",
            blocked_payload="' OR 1=1--",
            defense_type="WAF",
            defense_vendor="ModSecurity",
            response_code=403,
            response_snippet="Forbidden",
        )
        result = self.generator.generate_evasions(ctx, max_evasions=5)

        assert isinstance(result, EvasionResult)
        assert len(result.evasions) == 1
        assert result.evasions[0].payload == "' /*!OR*/ 1=1--"
        assert result.model_id == "global.anthropic.claude-sonnet-4-6"
        assert result.generation_time_ms >= 0
        self.generator.invoke.assert_called_once()

    def test_generate_evasions_empty_response(self) -> None:
        self.generator.invoke = MagicMock(return_value=("no json", TokenUsage()))

        ctx = EvasionContext(
            vulnerability_class="sqli",
            blocked_payload="test",
            defense_type="WAF",
            defense_vendor="Test",
            response_code=403,
            response_snippet="Blocked",
        )
        result = self.generator.generate_evasions(ctx)
        assert result.evasions == []
