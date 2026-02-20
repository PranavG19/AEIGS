from unittest.mock import MagicMock, patch

import pytest

from hypothesis_engine.bedrock_client import BedrockClient, LlmBackend, TokenUsage
from hypothesis_engine.generator import (
    GenerationResult,
    Hypothesis,
    HypothesisGenerator,
    ScanContext,
    build_user_prompt,
    create_backend,
    parse_hypotheses_from_response,
)
from hypothesis_engine.openai_client import OpenAiClient


class TestScanContext:
    def test_empty_context_has_defaults(self) -> None:
        ctx = ScanContext()
        assert ctx.technology_stack == []
        assert ctx.high_centrality_nodes == []
        assert ctx.findings_summary == []

    def test_context_with_stack(self) -> None:
        ctx = ScanContext(technology_stack=["Express", "PostgreSQL"])
        assert len(ctx.technology_stack) == 2


class TestBuildUserPrompt:
    def test_empty_context_returns_fallback(self) -> None:
        ctx = ScanContext()
        prompt = build_user_prompt(ctx)
        assert "No context available" in prompt

    def test_tech_stack_included(self) -> None:
        ctx = ScanContext(technology_stack=["Django", "MySQL"])
        prompt = build_user_prompt(ctx)
        assert "Django" in prompt
        assert "MySQL" in prompt

    def test_findings_included(self) -> None:
        ctx = ScanContext(findings_summary=["SQLi in /login", "XSS in /search"])
        prompt = build_user_prompt(ctx)
        assert "SQLi in /login" in prompt

    def test_high_risk_functions_included(self) -> None:
        ctx = ScanContext(
            high_risk_functions=[{"name": "query_user", "file": "db.py"}]
        )
        prompt = build_user_prompt(ctx)
        assert "query_user" in prompt

    def test_auth_matrix_included(self) -> None:
        ctx = ScanContext(authorization_matrix_summary="GET /admin: user=403, admin=200")
        prompt = build_user_prompt(ctx)
        assert "/admin" in prompt

    def test_vulnerable_deps_included(self) -> None:
        ctx = ScanContext(known_vulnerable_dependencies=["lodash@4.17.20 (CVE-2021-23337)"])
        prompt = build_user_prompt(ctx)
        assert "lodash" in prompt

    def test_centrality_nodes_included(self) -> None:
        ctx = ScanContext(
            high_centrality_nodes=[{"label": "auth_endpoint", "type": "Endpoint"}]
        )
        prompt = build_user_prompt(ctx)
        assert "auth_endpoint" in prompt


class TestFeedbackSummary:
    def test_feedback_summary_defaults_to_empty_list(self) -> None:
        ctx = ScanContext()
        assert ctx.feedback_summary == []

    def test_empty_feedback_summary_excluded_from_prompt(self) -> None:
        ctx = ScanContext(technology_stack=["Flask"])
        prompt = build_user_prompt(ctx)
        assert "Prior Round Feedback" not in prompt

    def test_populated_feedback_summary_included_in_prompt(self) -> None:
        ctx = ScanContext(
            technology_stack=["Express"],
            feedback_summary=[
                {
                    "condition": "IF /login accepts unsanitized input",
                    "vulnerability_class": "SQL Injection",
                    "outcome": "confirmed",
                    "anomaly_score": 0.92,
                },
                {
                    "condition": "IF /search reflects user input",
                    "vulnerability_class": "XSS",
                    "outcome": "refuted",
                    "anomaly_score": 0.15,
                },
            ],
        )
        prompt = build_user_prompt(ctx)
        assert "## Prior Round Feedback" in prompt
        assert "IF /login accepts unsanitized input" in prompt
        assert "confirmed" in prompt
        assert "0.92" in prompt
        assert "IF /search reflects user input" in prompt
        assert "refuted" in prompt
        assert "0.15" in prompt


class TestParseHypotheses:
    def test_parse_valid_json_array(self) -> None:
        response = """Here are the hypotheses:
[
  {
    "condition": "IF login uses string concat",
    "vulnerability_class": "SQL Injection",
    "reasoning": "BECAUSE no parameterized queries",
    "test_approach": "CAN BE TESTED BY sending payloads",
    "confidence": 0.8
  }
]"""
        _trace, results = parse_hypotheses_from_response(response)
        assert len(results) == 1
        assert results[0].vulnerability_class == "SQL Injection"
        assert results[0].confidence == 0.8

    def test_parse_multiple_hypotheses(self) -> None:
        response = """[
  {"condition": "IF a", "vulnerability_class": "XSS", "reasoning": "r", "test_approach": "t", "confidence": 0.7},
  {"condition": "IF b", "vulnerability_class": "SQLi", "reasoning": "r", "test_approach": "t", "confidence": 0.6}
]"""
        _trace, results = parse_hypotheses_from_response(response)
        assert len(results) == 2

    def test_parse_empty_response(self) -> None:
        _trace, results = parse_hypotheses_from_response("")
        assert results == []

    def test_parse_invalid_json(self) -> None:
        _trace, results = parse_hypotheses_from_response("not json at all")
        assert results == []

    def test_parse_skips_invalid_items(self) -> None:
        response = '[{"condition": "IF x", "vulnerability_class": "XSS", "reasoning": "r", "test_approach": "t", "confidence": 0.5}, "not_an_object"]'
        _trace, results = parse_hypotheses_from_response(response)
        assert len(results) == 1

    def test_parse_skips_empty_condition(self) -> None:
        response = '[{"condition": "", "vulnerability_class": "XSS", "reasoning": "r", "test_approach": "t", "confidence": 0.5}]'
        _trace, results = parse_hypotheses_from_response(response)
        assert len(results) == 0

    def test_parse_default_confidence(self) -> None:
        response = '[{"condition": "IF x", "vulnerability_class": "XSS", "reasoning": "r", "test_approach": "t"}]'
        _trace, results = parse_hypotheses_from_response(response)
        assert len(results) == 1
        assert results[0].confidence == 0.5

    def test_parse_with_surrounding_text(self) -> None:
        response = 'Here are my findings:\n[{"condition": "IF x", "vulnerability_class": "XSS", "reasoning": "r", "test_approach": "t", "confidence": 0.9}]\nEnd of analysis.'
        _trace, results = parse_hypotheses_from_response(response)
        assert len(results) == 1


class TestHypothesisModel:
    def test_hypothesis_creation(self) -> None:
        h = Hypothesis(
            condition="IF login endpoint",
            vulnerability_class="SQL Injection",
            reasoning="no parameterized queries",
            test_approach="send payloads",
            confidence=0.8,
        )
        assert h.condition == "IF login endpoint"
        assert h.confidence == 0.8

    def test_confidence_bounds(self) -> None:
        import pytest

        with pytest.raises(Exception):
            Hypothesis(
                condition="x",
                vulnerability_class="y",
                reasoning="r",
                test_approach="t",
                confidence=1.5,
            )

    def test_confidence_lower_bound(self) -> None:
        import pytest

        with pytest.raises(Exception):
            Hypothesis(
                condition="x",
                vulnerability_class="y",
                reasoning="r",
                test_approach="t",
                confidence=-0.1,
            )


class TestParseHypothesesEdgeCases:
    def test_parse_valid_brackets_invalid_json(self) -> None:
        response = "[{this is not valid json}]"
        _trace, results = parse_hypotheses_from_response(response)
        assert results == []

    def test_parse_value_error_in_hypothesis(self) -> None:
        response = '[{"condition": "IF x", "vulnerability_class": "XSS", "reasoning": "r", "test_approach": "t", "confidence": "not_a_number"}]'
        _trace, results = parse_hypotheses_from_response(response)
        assert results == []


class TestReasoningTrace:
    def test_generation_result_has_reasoning_trace_field(self) -> None:
        result = GenerationResult(
            hypotheses=[],
            model_id="test",
            generation_time_ms=0.0,
        )
        assert result.reasoning_trace == ""

    def test_reasoning_text_before_json_captured(self) -> None:
        response = (
            "The application uses Express with no input validation on the login endpoint. "
            "This suggests SQL injection is likely.\n\n"
            '[{"condition": "IF login uses string concat", "vulnerability_class": "SQLi", '
            '"reasoning": "r", "test_approach": "t", "confidence": 0.9}]'
        )
        trace, hypotheses = parse_hypotheses_from_response(response)
        assert "Express" in trace
        assert "SQL injection" in trace
        assert len(hypotheses) == 1

    def test_pure_json_response_has_empty_reasoning_trace(self) -> None:
        response = '[{"condition": "IF x", "vulnerability_class": "XSS", "reasoning": "r", "test_approach": "t", "confidence": 0.7}]'
        trace, hypotheses = parse_hypotheses_from_response(response)
        assert trace == ""
        assert len(hypotheses) == 1


class TestHypothesisGeneratorInit:
    @patch("hypothesis_engine.generator.BedrockClient.__init__", return_value=None)
    def test_default_init(self, mock_bedrock_init: MagicMock) -> None:
        generator = HypothesisGenerator()
        mock_bedrock_init.assert_called_once_with(
            model_id="global.anthropic.claude-sonnet-4-6",
            aws_profile=None,
            max_retries=3,
            timeout_seconds=120,
        )
        assert isinstance(generator, HypothesisGenerator)

    def test_init_with_custom_client(self) -> None:
        class StubBackend(LlmBackend):
            def invoke(
                self,
                messages: list[dict[str, str]],
                system: str = "",
                max_tokens: int = 4096,
            ) -> tuple[str, TokenUsage]:
                return ("stub", TokenUsage())

        stub = StubBackend()
        generator = HypothesisGenerator(client=stub)
        assert generator._client is stub


class TestHypothesisGeneratorGenerate:
    def setup_method(self) -> None:
        mock_client = MagicMock(spec=LlmBackend)
        self.generator = HypothesisGenerator(client=mock_client)
        self.generator._model_id = "global.anthropic.claude-sonnet-4-6"

    def test_generate_returns_result(self) -> None:
        mock_response = '[{"condition": "IF login", "vulnerability_class": "SQLi", "reasoning": "r", "test_approach": "t", "confidence": 0.8}]'
        mock_usage = TokenUsage(input_tokens=150, output_tokens=300)
        self.generator.invoke = MagicMock(return_value=(mock_response, mock_usage))

        ctx = ScanContext(technology_stack=["Express"])
        result = self.generator.generate(ctx)

        assert isinstance(result, GenerationResult)
        assert len(result.hypotheses) == 1
        assert result.hypotheses[0].vulnerability_class == "SQLi"
        assert result.model_id == "global.anthropic.claude-sonnet-4-6"
        assert result.generation_time_ms >= 0
        assert result.reasoning_trace == ""
        assert result.input_tokens == 150
        assert result.output_tokens == 300

    def test_generate_captures_reasoning_trace(self) -> None:
        mock_response = (
            "Looking at the Express stack, the login endpoint lacks parameterized queries.\n\n"
            '[{"condition": "IF login", "vulnerability_class": "SQLi", "reasoning": "r", "test_approach": "t", "confidence": 0.8}]'
        )
        mock_usage = TokenUsage(input_tokens=50, output_tokens=100)
        self.generator.invoke = MagicMock(return_value=(mock_response, mock_usage))

        ctx = ScanContext(technology_stack=["Express"])
        result = self.generator.generate(ctx)

        assert "Express" in result.reasoning_trace
        assert "parameterized queries" in result.reasoning_trace
        assert len(result.hypotheses) == 1

    def test_generate_respects_max_hypotheses(self) -> None:
        items = [
            {"condition": f"IF cond_{i}", "vulnerability_class": "XSS", "reasoning": "r", "test_approach": "t", "confidence": 0.5}
            for i in range(10)
        ]
        import json
        mock_response = json.dumps(items)
        mock_usage = TokenUsage()
        self.generator.invoke = MagicMock(return_value=(mock_response, mock_usage))

        ctx = ScanContext()
        result = self.generator.generate(ctx, max_hypotheses=3)
        assert len(result.hypotheses) == 3

    def test_generate_empty_response(self) -> None:
        mock_usage = TokenUsage()
        self.generator.invoke = MagicMock(return_value=("no json here", mock_usage))

        ctx = ScanContext()
        result = self.generator.generate(ctx)
        assert result.hypotheses == []
        assert result.input_tokens == 0
        assert result.output_tokens == 0


class TestGenerateStructuredOutput:
    def setup_method(self) -> None:
        mock_client = MagicMock(spec=LlmBackend)
        self.generator = HypothesisGenerator(client=mock_client)
        self.generator._model_id = "global.anthropic.claude-sonnet-4-6"

    def test_generate_uses_invoke_structured_on_success(self) -> None:
        import json

        hypotheses_data = [
            {
                "condition": "IF login accepts raw SQL",
                "vulnerability_class": "SQL Injection",
                "reasoning": "no parameterization",
                "test_approach": "send payloads",
                "confidence": 0.9,
            }
        ]
        mock_usage = TokenUsage(input_tokens=100, output_tokens=200)
        self.generator._client.invoke_structured.return_value = (
            json.dumps(hypotheses_data),
            mock_usage,
        )

        ctx = ScanContext(technology_stack=["Express"])
        result = self.generator.generate(ctx)

        self.generator._client.invoke_structured.assert_called_once()
        self.generator._client.invoke.assert_not_called()
        assert len(result.hypotheses) == 1
        assert result.hypotheses[0].vulnerability_class == "SQL Injection"
        assert result.reasoning_trace == ""
        assert result.input_tokens == 100
        assert result.output_tokens == 200

    def test_generate_falls_back_when_invoke_structured_raises(self) -> None:
        import json

        self.generator._client.invoke_structured.side_effect = RuntimeError("API error")
        fallback_data = [
            {
                "condition": "IF /search reflects input",
                "vulnerability_class": "XSS",
                "reasoning": "reflected without encoding",
                "test_approach": "inject script tag",
                "confidence": 0.7,
            }
        ]
        mock_usage = TokenUsage(input_tokens=50, output_tokens=80)
        self.generator._client.invoke.return_value = (json.dumps(fallback_data), mock_usage)

        ctx = ScanContext(technology_stack=["Express"])
        result = self.generator.generate(ctx)

        self.generator._client.invoke_structured.assert_called_once()
        self.generator._client.invoke.assert_called_once()
        assert len(result.hypotheses) == 1
        assert result.hypotheses[0].vulnerability_class == "XSS"

    def test_generate_falls_back_when_invoke_structured_returns_malformed_json(self) -> None:
        import json

        self.generator._client.invoke_structured.return_value = (
            "this is not valid json",
            TokenUsage(input_tokens=10, output_tokens=10),
        )
        fallback_data = [
            {
                "condition": "IF /admin lacks auth",
                "vulnerability_class": "Broken Access Control",
                "reasoning": "no token check",
                "test_approach": "request without token",
                "confidence": 0.85,
            }
        ]
        mock_usage = TokenUsage(input_tokens=60, output_tokens=90)
        self.generator._client.invoke.return_value = (json.dumps(fallback_data), mock_usage)

        ctx = ScanContext(technology_stack=["Django"])
        result = self.generator.generate(ctx)

        assert len(result.hypotheses) == 1
        assert result.hypotheses[0].vulnerability_class == "Broken Access Control"
        self.generator._client.invoke.assert_called_once()


class TestCreateBackend:
    @patch("hypothesis_engine.generator.BedrockClient.__init__", return_value=None)
    def test_bedrock_returns_bedrock_client(self, mock_init: MagicMock) -> None:
        backend = create_backend("bedrock")
        assert isinstance(backend, BedrockClient)

    def test_openai_returns_openai_client(self) -> None:
        backend = create_backend("openai", api_key="sk-test")
        assert isinstance(backend, OpenAiClient)

    def test_ollama_returns_openai_client_with_localhost_url(self) -> None:
        backend = create_backend("ollama")
        assert isinstance(backend, OpenAiClient)
        assert backend._base_url == "http://localhost:11434/v1"

    def test_ollama_allows_base_url_override(self) -> None:
        backend = create_backend("ollama", base_url="http://custom:1234/v1")
        assert isinstance(backend, OpenAiClient)
        assert backend._base_url == "http://custom:1234/v1"

    def test_unknown_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Unknown backend type: bogus"):
            create_backend("bogus")
