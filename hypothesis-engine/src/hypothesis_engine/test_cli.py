from unittest.mock import MagicMock, patch

from hypothesis_engine.bedrock_client import LlmBackend, TokenUsage
from hypothesis_engine.cli import handle_request


def _mock_backend() -> MagicMock:
    return MagicMock(spec=LlmBackend)


def _sample_context() -> dict:
    return {
        "technology_stack": ["express", "postgres"],
        "findings_summary": [],
    }


def _sample_hypothesis_dict() -> dict:
    return {
        "condition": "IF login uses string concat",
        "vulnerability_class": "SQL Injection",
        "reasoning": "BECAUSE no parameterized queries",
        "test_approach": "CAN BE TESTED BY sending payloads",
        "confidence": 0.8,
    }


class TestHandleGenerate:
    def test_generate_returns_hypotheses(self) -> None:
        mock_backend = _mock_backend()
        mock_backend.invoke_structured.return_value = (
            '[{"condition": "IF x", "vulnerability_class": "XSS", '
            '"reasoning": "BECAUSE y", "test_approach": "CAN BE TESTED BY z", '
            '"confidence": 0.7}]',
            TokenUsage(input_tokens=100, output_tokens=50),
        )

        with patch("hypothesis_engine.cli.create_backend", return_value=mock_backend):
            result = handle_request({
                "action": "generate",
                "backend": "bedrock",
                "context": _sample_context(),
            })

        assert "error" not in result
        assert len(result["hypotheses"]) == 1
        assert result["hypotheses"][0]["condition"] == "IF x"
        assert result["hypotheses"][0]["vulnerability_class"] == "XSS"
        assert result["model_id"] == "global.anthropic.claude-sonnet-4-6"
        assert result["input_tokens"] == 100
        assert result["output_tokens"] == 50

    def test_generate_with_backend_kwargs(self) -> None:
        mock_backend = _mock_backend()
        mock_backend.invoke_structured.return_value = ("[]", TokenUsage())

        with patch("hypothesis_engine.cli.create_backend", return_value=mock_backend) as mock_create:
            handle_request({
                "action": "generate",
                "backend": "openai",
                "backend_kwargs": {"api_key": "test-key", "model": "gpt-4o"},
                "context": _sample_context(),
            })

        mock_create.assert_called_once_with("openai", api_key="test-key", model="gpt-4o")

    def test_generate_empty_context(self) -> None:
        mock_backend = _mock_backend()
        mock_backend.invoke_structured.return_value = ("[]", TokenUsage())

        with patch("hypothesis_engine.cli.create_backend", return_value=mock_backend):
            result = handle_request({
                "action": "generate",
                "backend": "bedrock",
                "context": {},
            })

        assert "error" not in result
        assert result["hypotheses"] == []

    def test_generate_missing_backend_returns_error(self) -> None:
        result = handle_request({
            "action": "generate",
            "context": _sample_context(),
        })

        assert "error" in result

    def test_generate_missing_context_returns_error(self) -> None:
        mock_backend = _mock_backend()

        with patch("hypothesis_engine.cli.create_backend", return_value=mock_backend):
            result = handle_request({
                "action": "generate",
                "backend": "bedrock",
            })

        assert "error" in result

    def test_generate_reasoning_trace_preserved(self) -> None:
        mock_backend = _mock_backend()
        mock_backend.invoke_structured.side_effect = Exception("no structured support")
        mock_backend.invoke.return_value = (
            "Some reasoning here.\n"
            '[{"condition": "IF x", "vulnerability_class": "XSS", '
            '"reasoning": "y", "test_approach": "z", "confidence": 0.5}]',
            TokenUsage(input_tokens=80, output_tokens=40),
        )

        with patch("hypothesis_engine.cli.create_backend", return_value=mock_backend):
            result = handle_request({
                "action": "generate",
                "backend": "bedrock",
                "context": _sample_context(),
            })

        assert "error" not in result
        assert result["reasoning_trace"] == "Some reasoning here."


class TestHandleCompile:
    def test_compile_returns_specifications(self) -> None:
        mock_backend = _mock_backend()
        mock_backend.invoke.return_value = (
            '[{"target_endpoint": "/login", "http_method": "POST", "priority": 0.9}]',
            TokenUsage(input_tokens=150, output_tokens=60),
        )

        with patch("hypothesis_engine.cli.create_backend", return_value=mock_backend):
            result = handle_request({
                "action": "compile",
                "backend": "bedrock",
                "hypotheses": [_sample_hypothesis_dict()],
            })

        assert "error" not in result
        assert len(result["specifications"]) == 1
        assert result["specifications"][0]["target_endpoint"] == "/login"
        assert result["specifications"][0]["http_method"] == "POST"
        assert result["failed_compilations"] == 0
        assert result["input_tokens"] == 150
        assert result["output_tokens"] == 60
        assert result["compilation_time_ms"] >= 0

    def test_compile_multiple_hypotheses(self) -> None:
        mock_backend = _mock_backend()
        mock_backend.invoke.return_value = (
            '[{"target_endpoint": "/api", "http_method": "GET"}]',
            TokenUsage(input_tokens=100, output_tokens=50),
        )

        h1 = _sample_hypothesis_dict()
        h2 = {
            "condition": "IF search uses eval",
            "vulnerability_class": "RCE",
            "reasoning": "BECAUSE user input in eval",
            "test_approach": "CAN BE TESTED BY injecting code",
            "confidence": 0.7,
        }

        with patch("hypothesis_engine.cli.create_backend", return_value=mock_backend):
            result = handle_request({
                "action": "compile",
                "backend": "bedrock",
                "hypotheses": [h1, h2],
            })

        assert len(result["specifications"]) == 2
        assert result["input_tokens"] == 200
        assert result["output_tokens"] == 100

    def test_compile_empty_hypotheses(self) -> None:
        mock_backend = _mock_backend()

        with patch("hypothesis_engine.cli.create_backend", return_value=mock_backend):
            result = handle_request({
                "action": "compile",
                "backend": "bedrock",
                "hypotheses": [],
            })

        assert result["specifications"] == []
        assert result["failed_compilations"] == 0

    def test_compile_missing_hypotheses_returns_error(self) -> None:
        mock_backend = _mock_backend()

        with patch("hypothesis_engine.cli.create_backend", return_value=mock_backend):
            result = handle_request({
                "action": "compile",
                "backend": "bedrock",
            })

        assert "error" in result

    def test_compile_with_llm_failure_counts_failures(self) -> None:
        mock_backend = _mock_backend()
        mock_backend.invoke.side_effect = RuntimeError("LLM error")

        with patch("hypothesis_engine.cli.create_backend", return_value=mock_backend):
            result = handle_request({
                "action": "compile",
                "backend": "bedrock",
                "hypotheses": [_sample_hypothesis_dict()],
            })

        assert result["specifications"] == []
        assert result["failed_compilations"] == 1


class TestUnknownAction:
    def test_unknown_action_returns_error(self) -> None:
        result = handle_request({"action": "foobar"})
        assert result == {"error": "Unknown action: foobar"}

    def test_missing_action_returns_error(self) -> None:
        result = handle_request({})
        assert result == {"error": "Unknown action: None"}


class TestMalformedRequest:
    def test_generate_with_invalid_backend_type(self) -> None:
        result = handle_request({
            "action": "generate",
            "backend": "nonexistent",
            "context": _sample_context(),
        })
        assert "error" in result
        assert "Unknown backend type" in result["error"]

    def test_compile_with_malformed_hypothesis(self) -> None:
        mock_backend = _mock_backend()

        with patch("hypothesis_engine.cli.create_backend", return_value=mock_backend):
            result = handle_request({
                "action": "compile",
                "backend": "bedrock",
                "hypotheses": [{"not_a_valid_field": True}],
            })

        assert "error" in result
