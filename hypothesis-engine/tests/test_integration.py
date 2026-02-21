from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from hypothesis_engine.bedrock_client import BedrockClient, LlmBackend, TokenUsage
from hypothesis_engine.compiler import CompilationResult, HypothesisCompiler
from hypothesis_engine.evasion_mode import (
    EvasionContext,
    EvasionHypothesisGenerator,
    EvasionResult,
)
from hypothesis_engine.feedback import FeedbackManager, build_feedback_summary
from hypothesis_engine.generator import (
    GenerationResult,
    Hypothesis,
    HypothesisGenerator,
    ScanContext,
    create_backend,
)
from hypothesis_engine.openai_client import OpenAiClient
from hypothesis_engine.uncertainty import extract_uncertainty_score


class MockLlmBackend(LlmBackend):
    """LlmBackend that returns canned JSON responses without external services.

    Tracks cumulative token usage across all invocations so tests can verify
    token accounting through multi-call flows.
    """

    def __init__(self, response_text: str, input_tokens: int = 50, output_tokens: int = 100) -> None:
        self._response_text = response_text
        self._input_tokens = input_tokens
        self._output_tokens = output_tokens
        self.call_count = 0
        self.cumulative_input_tokens = 0
        self.cumulative_output_tokens = 0

    def invoke(
        self,
        messages: list[dict[str, str]],
        system: str = "",
        max_tokens: int = 4096,
    ) -> tuple[str, TokenUsage]:
        self.call_count += 1
        self.cumulative_input_tokens += self._input_tokens
        self.cumulative_output_tokens += self._output_tokens
        return (self._response_text, TokenUsage(input_tokens=self._input_tokens, output_tokens=self._output_tokens))

    def invoke_structured(
        self,
        messages: list[dict[str, str]],
        output_schema: dict,
        system: str = "",
        max_tokens: int = 4096,
    ) -> tuple[str, TokenUsage]:
        raise RuntimeError("MockLlmBackend does not support structured output")


HYPOTHESIS_JSON = json.dumps([
    {
        "condition": "IF /api/login accepts SQL metacharacters in username field",
        "vulnerability_class": "SQL Injection",
        "reasoning": "BECAUSE the login endpoint concatenates user input into SQL queries",
        "test_approach": "CAN BE TESTED BY sending ' OR 1=1-- as username",
        "confidence": 0.85,
    },
    {
        "condition": "IF /search reflects user input without encoding",
        "vulnerability_class": "Cross-Site Scripting",
        "reasoning": "BECAUSE search results echo the query parameter unescaped",
        "test_approach": "CAN BE TESTED BY injecting <script>alert(1)</script>",
        "confidence": 0.7,
    },
])

COMPILATION_JSON = json.dumps([
    {
        "target_endpoint": "/api/login",
        "http_method": "POST",
        "parameters": [{"name": "username", "value": "' OR 1=1--", "location": "body"}],
        "payload_patterns": ["' OR 1=1--", "' UNION SELECT NULL--"],
        "expected_anomalies": [{"anomaly_type": "content", "description": "SQL error message in response body"}],
        "priority": 0.9,
    }
])

EVASION_JSON = json.dumps([
    {
        "payload": "' /*!50000OR*/ 1=1--",
        "strategy": "MySQL version comment bypass to evade WAF pattern matching",
        "confidence": 0.8,
    },
    {
        "payload": "%27%20OR%201%3D1--",
        "strategy": "URL-encoded SQL injection to bypass string-matching rules",
        "confidence": 0.6,
    },
])


@pytest.fixture
def mock_hypothesis_backend() -> MockLlmBackend:
    return MockLlmBackend(response_text=HYPOTHESIS_JSON, input_tokens=120, output_tokens=350)


@pytest.fixture
def mock_compilation_backend() -> MockLlmBackend:
    return MockLlmBackend(response_text=COMPILATION_JSON, input_tokens=80, output_tokens=200)


@pytest.fixture
def mock_evasion_backend() -> MockLlmBackend:
    return MockLlmBackend(response_text=EVASION_JSON, input_tokens=90, output_tokens=250)


@pytest.fixture
def sample_scan_context() -> ScanContext:
    return ScanContext(
        technology_stack=["Express", "PostgreSQL"],
        findings_summary=["Possible SQL injection in /api/login"],
    )


@pytest.fixture
def sample_evasion_context() -> EvasionContext:
    return EvasionContext(
        vulnerability_class="sqli",
        blocked_payload="' OR 1=1--",
        defense_type="WAF",
        defense_vendor="ModSecurity",
        response_code=403,
        response_snippet="Forbidden - ModSecurity Action",
    )


class TestMockBackendGeneratesHypotheses:
    def test_mock_backend_generates_hypotheses(
        self,
        mock_hypothesis_backend: MockLlmBackend,
        sample_scan_context: ScanContext,
    ) -> None:
        generator = HypothesisGenerator(client=mock_hypothesis_backend)
        result = generator.generate(sample_scan_context)

        assert isinstance(result, GenerationResult)
        assert len(result.hypotheses) == 2
        assert result.hypotheses[0].vulnerability_class == "SQL Injection"
        assert result.hypotheses[0].confidence == 0.85
        assert result.hypotheses[1].vulnerability_class == "Cross-Site Scripting"
        assert result.hypotheses[1].confidence == 0.7
        assert result.model_id == "global.anthropic.claude-sonnet-4-6"
        assert result.generation_time_ms >= 0
        assert mock_hypothesis_backend.call_count >= 1


class TestMockBackendCompilesTests:
    def test_mock_backend_compiles_tests(
        self,
        mock_compilation_backend: MockLlmBackend,
    ) -> None:
        compiler = HypothesisCompiler(client=mock_compilation_backend)
        hypothesis = Hypothesis(
            condition="IF /api/login accepts SQL metacharacters",
            vulnerability_class="SQL Injection",
            reasoning="BECAUSE no parameterized queries",
            test_approach="CAN BE TESTED BY sending SQL payloads",
            confidence=0.85,
        )
        result = compiler.compile_batch([hypothesis])

        assert isinstance(result, CompilationResult)
        assert len(result.specifications) == 1
        assert result.specifications[0].target_endpoint == "/api/login"
        assert result.specifications[0].http_method == "POST"
        assert len(result.specifications[0].parameters) == 1
        assert result.specifications[0].parameters[0].name == "username"
        assert result.failed_compilations == 0
        assert result.compilation_time_ms >= 0
        assert mock_compilation_backend.call_count == 1


class TestMockBackendEvasionTactics:
    def test_mock_backend_evasion_tactics(
        self,
        mock_evasion_backend: MockLlmBackend,
        sample_evasion_context: EvasionContext,
    ) -> None:
        evasion_gen = EvasionHypothesisGenerator(client=mock_evasion_backend)
        result = evasion_gen.generate_evasions(sample_evasion_context, max_evasions=10)

        assert isinstance(result, EvasionResult)
        assert len(result.evasions) == 2
        assert result.evasions[0].payload == "' /*!50000OR*/ 1=1--"
        assert "MySQL version comment" in result.evasions[0].strategy
        assert result.evasions[0].confidence == 0.8
        assert result.evasions[1].payload == "%27%20OR%201%3D1--"
        assert result.model_id == "global.anthropic.claude-sonnet-4-6"
        assert result.generation_time_ms >= 0
        assert mock_evasion_backend.call_count == 1


class TestFeedbackLoopMultiRound:
    def test_feedback_loop_multi_round(
        self,
        mock_hypothesis_backend: MockLlmBackend,
        sample_scan_context: ScanContext,
    ) -> None:
        generator = HypothesisGenerator(client=mock_hypothesis_backend)
        feedback_mgr = FeedbackManager(confirmation_threshold=0.5)

        round_1_result = generator.generate(sample_scan_context)
        assert len(round_1_result.hypotheses) >= 1

        for hypothesis in round_1_result.hypotheses:
            if hypothesis.vulnerability_class == "SQL Injection":
                feedback_mgr.label_hypothesis(
                    hypothesis, anomaly_detected=True, anomaly_score=0.9
                )
            else:
                feedback_mgr.label_hypothesis(
                    hypothesis, anomaly_detected=False, anomaly_score=0.1
                )

        stats = feedback_mgr.compute_stats()
        assert stats.total_hypotheses == 2
        assert stats.confirmed >= 1

        confirmed = feedback_mgr.confirmed_hypotheses()
        feedback_summary = build_feedback_summary(confirmed)
        assert "SQL Injection" in feedback_summary
        assert "confirmed" in feedback_summary

        round_2_context = sample_scan_context.model_copy(
            update={"feedback_summary": feedback_summary}
        )
        assert round_2_context.feedback_summary != ""

        round_2_result = generator.generate(round_2_context)
        assert isinstance(round_2_result, GenerationResult)
        assert len(round_2_result.hypotheses) >= 1
        assert mock_hypothesis_backend.call_count >= 2


class TestTokenUsageTracked:
    def test_token_usage_tracked(self) -> None:
        mock_backend = MockLlmBackend(
            response_text=HYPOTHESIS_JSON, input_tokens=100, output_tokens=200
        )
        generator = HypothesisGenerator(client=mock_backend)
        ctx = ScanContext(technology_stack=["Flask"])

        result_1 = generator.generate(ctx)
        assert result_1.input_tokens == 100
        assert result_1.output_tokens == 200

        result_2 = generator.generate(ctx)
        assert result_2.input_tokens == 100
        assert result_2.output_tokens == 200

        assert mock_backend.cumulative_input_tokens == 200
        assert mock_backend.cumulative_output_tokens == 400
        assert mock_backend.call_count == 2

        compilation_backend = MockLlmBackend(
            response_text=COMPILATION_JSON, input_tokens=60, output_tokens=150
        )
        compiler = HypothesisCompiler(client=compilation_backend)
        hypotheses = result_1.hypotheses
        batch_result = compiler.compile_batch(hypotheses)

        assert batch_result.input_tokens == 60 * len(hypotheses)
        assert batch_result.output_tokens == 150 * len(hypotheses)
        assert compilation_backend.cumulative_input_tokens == 60 * len(hypotheses)
        assert compilation_backend.cumulative_output_tokens == 150 * len(hypotheses)


class TestUncertaintyHedgingDetected:
    def test_uncertainty_hedging_detected(self) -> None:
        hedging_text = (
            "The endpoint might possibly be vulnerable to SQL injection. "
            "It is uncertain, but the evidence indicates input is reflected."
        )
        score = extract_uncertainty_score(hedging_text)
        assert score > 0.0
        assert score < 0.5


class TestUncertaintyConfidenceDetected:
    def test_uncertainty_confidence_detected(self) -> None:
        confident_text = (
            "The evidence clearly confirms that the endpoint is vulnerable. "
            "Testing demonstrates the SQL injection flaw."
        )
        score = extract_uncertainty_score(confident_text)
        assert score > 0.5


class TestBypassCorpusLoadsWhenPresent:
    def test_bypass_corpus_loads_when_present(
        self, tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import hypothesis_engine.evasion_mode as evasion_module

        fake_corpus = {
            "sqli": [
                {"payload": "' OR 1=1--", "technique": "tautology"},
                {"payload": "' UNION SELECT NULL--", "technique": "union_based"},
            ],
            "xss": [
                {"payload": "<script>alert(1)</script>", "technique": "basic_script"},
            ],
        }
        corpus_file = tmp_path / "bypass_examples.json"
        corpus_file.write_text(json.dumps(fake_corpus))

        monkeypatch.setattr(evasion_module, "__file__", str(tmp_path / "evasion_mode.py"))

        mock_backend = MockLlmBackend(response_text=EVASION_JSON)
        generator = EvasionHypothesisGenerator(client=mock_backend)

        assert isinstance(generator._bypass_examples, dict)
        assert "sqli" in generator._bypass_examples
        assert "xss" in generator._bypass_examples
        assert len(generator._bypass_examples["sqli"]) == 2
        assert generator._bypass_examples["sqli"][0]["payload"] == "' OR 1=1--"


class TestBypassCorpusWarnsWhenMissing:
    def test_bypass_corpus_warns_when_missing(
        self, tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import hypothesis_engine.evasion_mode as evasion_module

        monkeypatch.setattr(evasion_module, "__file__", str(tmp_path / "evasion_mode.py"))

        mock_backend = MockLlmBackend(response_text=EVASION_JSON)
        with pytest.warns(RuntimeWarning, match="bypass_examples.json not found"):
            generator = EvasionHypothesisGenerator(client=mock_backend)

        assert generator._bypass_examples == {}


class TestCreateBackendFactory:
    @patch("hypothesis_engine.generator.BedrockClient.__init__", return_value=None)
    def test_create_backend_factory(self, mock_bedrock_init) -> None:
        bedrock_backend = create_backend("bedrock")
        assert isinstance(bedrock_backend, BedrockClient)

        openai_backend = create_backend("openai", api_key="sk-test-key", base_url="http://localhost:9999/v1")
        assert isinstance(openai_backend, OpenAiClient)
        assert openai_backend._base_url == "http://localhost:9999/v1"

        ollama_backend = create_backend("ollama")
        assert isinstance(ollama_backend, OpenAiClient)
        assert ollama_backend._base_url == "http://localhost:11434/v1"

        with pytest.raises(ValueError, match="Unknown backend type"):
            create_backend("nonexistent_backend")
