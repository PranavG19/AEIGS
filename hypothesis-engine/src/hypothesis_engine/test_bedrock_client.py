from __future__ import annotations

import io
import json
from unittest.mock import ANY, MagicMock, patch

import pytest

from hypothesis_engine.bedrock_client import BedrockClient, LlmBackend, TokenUsage


class TestBedrockClientDefaults:
    def test_default_model_id(self) -> None:
        client = BedrockClient()
        assert client._model_id == "global.anthropic.claude-sonnet-4-6"

    def test_default_aws_profile(self) -> None:
        client = BedrockClient()
        assert client._aws_profile is None

    def test_default_max_retries(self) -> None:
        client = BedrockClient()
        assert client._max_retries == 3

    def test_default_timeout_seconds(self) -> None:
        client = BedrockClient()
        assert client._timeout_seconds == 120

    def test_custom_parameters(self) -> None:
        client = BedrockClient(
            model_id="custom-model",
            aws_profile="other",
            max_retries=5,
            timeout_seconds=60,
        )
        assert client._model_id == "custom-model"
        assert client._aws_profile == "other"
        assert client._max_retries == 5
        assert client._timeout_seconds == 60

    def test_client_initially_none(self) -> None:
        client = BedrockClient()
        assert client._client is None


class TestGetClient:
    @patch("hypothesis_engine.bedrock_client.boto3.Session")
    def test_creates_bedrock_runtime_client(self, mock_session_cls: MagicMock) -> None:
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_boto_client = MagicMock()
        mock_session.client.return_value = mock_boto_client

        client = BedrockClient(aws_profile="test-profile")
        result = client._get_client()

        mock_session_cls.assert_called_once_with(profile_name="test-profile")
        mock_session.client.assert_called_once_with(
            "bedrock-runtime", region_name="us-east-1", config=ANY
        )
        assert result is mock_boto_client

    @patch("hypothesis_engine.bedrock_client.boto3.Session")
    def test_none_profile_creates_session_without_profile_name(
        self, mock_session_cls: MagicMock
    ) -> None:
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_boto_client = MagicMock()
        mock_session.client.return_value = mock_boto_client

        client = BedrockClient(aws_profile=None)
        result = client._get_client()

        mock_session_cls.assert_called_once_with()
        mock_session.client.assert_called_once_with(
            "bedrock-runtime", region_name="us-east-1", config=ANY
        )
        assert result is mock_boto_client

    @patch("hypothesis_engine.bedrock_client.boto3.Session")
    def test_caches_client(self, mock_session_cls: MagicMock) -> None:
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        client = BedrockClient()
        first = client._get_client()
        second = client._get_client()

        assert first is second
        mock_session_cls.assert_called_once()

    @patch("hypothesis_engine.bedrock_client.boto3.Session")
    def test_passes_timeout_config_to_boto3(self, mock_session_cls: MagicMock) -> None:
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        client = BedrockClient(timeout_seconds=60)
        client._get_client()

        config = mock_session.client.call_args.kwargs["config"]
        assert config.read_timeout == 60
        assert config.connect_timeout == 30

    @patch("hypothesis_engine.bedrock_client.boto3.Session")
    def test_connect_timeout_capped_at_30(self, mock_session_cls: MagicMock) -> None:
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        client = BedrockClient(timeout_seconds=10)
        client._get_client()

        config = mock_session.client.call_args.kwargs["config"]
        assert config.read_timeout == 10
        assert config.connect_timeout == 10


class TestInvoke:
    def _make_response(
        self, text: str, input_tokens: int = 10, output_tokens: int = 20
    ) -> dict:
        body_bytes = json.dumps(
            {
                "content": [{"text": text}],
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                },
            }
        ).encode()
        return {"body": io.BytesIO(body_bytes)}

    def test_invoke_sends_correct_body(self) -> None:
        client = BedrockClient()
        mock_boto = MagicMock()
        mock_boto.invoke_model.return_value = self._make_response("hello")
        client._client = mock_boto

        client.invoke(
            messages=[{"role": "user", "content": "test"}],
            system="system prompt",
            max_tokens=2048,
        )

        call_kwargs = mock_boto.invoke_model.call_args.kwargs
        sent_body = json.loads(call_kwargs["body"])
        assert sent_body["anthropic_version"] == "bedrock-2023-05-31"
        assert sent_body["max_tokens"] == 2048
        assert sent_body["system"] == "system prompt"
        assert sent_body["messages"] == [{"role": "user", "content": "test"}]

    def test_invoke_returns_text_and_usage_tuple(self) -> None:
        client = BedrockClient()
        mock_boto = MagicMock()
        mock_boto.invoke_model.return_value = self._make_response(
            "result text", input_tokens=100, output_tokens=200
        )
        client._client = mock_boto

        text, usage = client.invoke(
            messages=[{"role": "user", "content": "test"}],
            system="sys",
        )
        assert text == "result text"
        assert isinstance(usage, TokenUsage)
        assert usage.input_tokens == 100
        assert usage.output_tokens == 200

    def test_invoke_default_max_tokens(self) -> None:
        client = BedrockClient()
        mock_boto = MagicMock()
        mock_boto.invoke_model.return_value = self._make_response("ok")
        client._client = mock_boto

        client.invoke(
            messages=[{"role": "user", "content": "test"}],
            system="sys",
        )

        sent_body = json.loads(mock_boto.invoke_model.call_args.kwargs["body"])
        assert sent_body["max_tokens"] == 4096

    def test_invoke_uses_model_id(self) -> None:
        client = BedrockClient(model_id="my-model")
        mock_boto = MagicMock()
        mock_boto.invoke_model.return_value = self._make_response("ok")
        client._client = mock_boto

        client.invoke(
            messages=[{"role": "user", "content": "test"}],
            system="sys",
        )

        assert mock_boto.invoke_model.call_args.kwargs["modelId"] == "my-model"

    def test_invoke_missing_usage_defaults_to_zero(self) -> None:
        client = BedrockClient()
        mock_boto = MagicMock()
        body_bytes = json.dumps({"content": [{"text": "hello"}]}).encode()
        mock_boto.invoke_model.return_value = {"body": io.BytesIO(body_bytes)}
        client._client = mock_boto

        text, usage = client.invoke(
            messages=[{"role": "user", "content": "test"}],
            system="sys",
        )
        assert text == "hello"
        assert usage.input_tokens == 0
        assert usage.output_tokens == 0


class TestRetryBehavior:
    def _make_response(self, text: str) -> dict:
        body_bytes = json.dumps(
            {
                "content": [{"text": text}],
                "usage": {"input_tokens": 10, "output_tokens": 20},
            }
        ).encode()
        return {"body": io.BytesIO(body_bytes)}

    @patch("hypothesis_engine.bedrock_client.time.sleep")
    def test_retries_on_failure(self, mock_sleep: MagicMock) -> None:
        client = BedrockClient(max_retries=3)
        mock_boto = MagicMock()
        mock_boto.invoke_model.side_effect = [
            RuntimeError("transient"),
            self._make_response("success"),
        ]
        client._client = mock_boto

        text, usage = client.invoke(
            messages=[{"role": "user", "content": "test"}],
            system="sys",
        )
        assert text == "success"
        assert mock_boto.invoke_model.call_count == 2
        mock_sleep.assert_called_once_with(1.0)

    @patch("hypothesis_engine.bedrock_client.time.sleep")
    def test_raises_after_all_retries_exhausted(self, mock_sleep: MagicMock) -> None:
        client = BedrockClient(max_retries=3)
        mock_boto = MagicMock()
        mock_boto.invoke_model.side_effect = RuntimeError("persistent error")
        client._client = mock_boto

        with pytest.raises(RuntimeError, match="Failed after 3 retries"):
            client.invoke(
                messages=[{"role": "user", "content": "test"}],
                system="sys",
            )

        assert mock_boto.invoke_model.call_count == 3
        assert mock_sleep.call_count == 2

    @patch("hypothesis_engine.bedrock_client.time.sleep")
    def test_exponential_backoff_delays(self, mock_sleep: MagicMock) -> None:
        client = BedrockClient(max_retries=3)
        mock_boto = MagicMock()
        mock_boto.invoke_model.side_effect = RuntimeError("fail")
        client._client = mock_boto

        with pytest.raises(RuntimeError):
            client.invoke(
                messages=[{"role": "user", "content": "test"}],
                system="sys",
            )

        delays = [call.args[0] for call in mock_sleep.call_args_list]
        assert delays == [1.0, 2.0]

    @patch("hypothesis_engine.bedrock_client.time.sleep")
    def test_no_sleep_after_last_attempt(self, mock_sleep: MagicMock) -> None:
        client = BedrockClient(max_retries=1)
        mock_boto = MagicMock()
        mock_boto.invoke_model.side_effect = RuntimeError("fail")
        client._client = mock_boto

        with pytest.raises(RuntimeError):
            client.invoke(
                messages=[{"role": "user", "content": "test"}],
                system="sys",
            )

        mock_sleep.assert_not_called()

    @patch("hypothesis_engine.bedrock_client.time.sleep")
    def test_succeeds_on_first_try_no_sleep(self, mock_sleep: MagicMock) -> None:
        client = BedrockClient()
        mock_boto = MagicMock()
        mock_boto.invoke_model.return_value = self._make_response("ok")
        client._client = mock_boto

        text, usage = client.invoke(
            messages=[{"role": "user", "content": "test"}],
            system="sys",
        )
        assert text == "ok"
        mock_sleep.assert_not_called()


class TestTokenUsage:
    def test_token_usage_defaults(self) -> None:
        usage = TokenUsage()
        assert usage.input_tokens == 0
        assert usage.output_tokens == 0

    def test_token_usage_with_values(self) -> None:
        usage = TokenUsage(input_tokens=150, output_tokens=300)
        assert usage.input_tokens == 150
        assert usage.output_tokens == 300


class TestLlmBackend:
    def test_bedrock_client_is_instance_of_llm_backend(self) -> None:
        client = BedrockClient()
        assert isinstance(client, LlmBackend)

    def test_llm_backend_cannot_be_instantiated(self) -> None:
        with pytest.raises(TypeError, match="abstract method"):
            LlmBackend()  # type: ignore[abstract]

    def test_mock_implementation_substitutes_for_bedrock_client(self) -> None:
        class MockBackend(LlmBackend):
            def invoke(
                self,
                messages: list[dict[str, str]],
                system: str = "",
                max_tokens: int = 4096,
            ) -> tuple[str, TokenUsage]:
                return ("mock response", TokenUsage(input_tokens=1, output_tokens=2))

        backend: LlmBackend = MockBackend()
        text, usage = backend.invoke(
            messages=[{"role": "user", "content": "hello"}],
            system="test",
        )
        assert text == "mock response"
        assert usage.input_tokens == 1
        assert usage.output_tokens == 2
        assert isinstance(backend, LlmBackend)
