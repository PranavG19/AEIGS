from __future__ import annotations

import json
import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from hypothesis_engine.bedrock_client import LlmBackend, TokenUsage
from hypothesis_engine.openai_client import OpenAiClient


class TestOpenAiClientIsLlmBackend:
    def test_instance_of_llm_backend(self) -> None:
        client = OpenAiClient()
        assert isinstance(client, LlmBackend)


class TestOpenAiClientDefaults:
    def test_default_api_key(self) -> None:
        client = OpenAiClient()
        assert client._api_key == ""

    def test_default_base_url(self) -> None:
        client = OpenAiClient()
        assert client._base_url == "https://api.openai.com/v1"

    def test_default_model(self) -> None:
        client = OpenAiClient()
        assert client._model == "gpt-4o"

    def test_default_max_retries(self) -> None:
        client = OpenAiClient()
        assert client._max_retries == 3

    def test_default_timeout_seconds(self) -> None:
        client = OpenAiClient()
        assert client._timeout_seconds == 120

    def test_custom_parameters(self) -> None:
        client = OpenAiClient(
            api_key="sk-test",
            base_url="http://localhost:11434/v1",
            model="llama3",
            max_retries=5,
            timeout_seconds=60,
        )
        assert client._api_key == "sk-test"
        assert client._base_url == "http://localhost:11434/v1"
        assert client._model == "llama3"
        assert client._max_retries == 5
        assert client._timeout_seconds == 60

    def test_trailing_slash_stripped_from_base_url(self) -> None:
        client = OpenAiClient(base_url="http://localhost:11434/v1/")
        assert client._base_url == "http://localhost:11434/v1"


def _make_openai_response(
    text: str = "hello",
    prompt_tokens: int = 10,
    completion_tokens: int = 20,
) -> bytes:
    return json.dumps(
        {
            "choices": [{"message": {"content": text}}],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
            },
        }
    ).encode()


class TestRequestStructure:
    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_request_body_has_correct_structure(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = _make_openai_response()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = OpenAiClient(api_key="sk-test", model="gpt-4o")
        client.invoke(
            messages=[{"role": "user", "content": "test"}],
            system="be helpful",
            max_tokens=2048,
        )

        req = mock_urlopen.call_args[0][0]
        sent_body = json.loads(req.data)
        assert sent_body["model"] == "gpt-4o"
        assert sent_body["max_tokens"] == 2048
        assert sent_body["messages"][0] == {"role": "system", "content": "be helpful"}
        assert sent_body["messages"][1] == {"role": "user", "content": "test"}

    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_no_system_message_when_system_empty(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = _make_openai_response()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = OpenAiClient()
        client.invoke(messages=[{"role": "user", "content": "test"}])

        req = mock_urlopen.call_args[0][0]
        sent_body = json.loads(req.data)
        assert len(sent_body["messages"]) == 1
        assert sent_body["messages"][0]["role"] == "user"

    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_authorization_header_set_when_api_key_provided(
        self, mock_urlopen: MagicMock
    ) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = _make_openai_response()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = OpenAiClient(api_key="sk-secret")
        client.invoke(messages=[{"role": "user", "content": "test"}])

        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Authorization") == "Bearer sk-secret"

    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_no_authorization_header_when_api_key_empty(
        self, mock_urlopen: MagicMock
    ) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = _make_openai_response()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = OpenAiClient(api_key="")
        client.invoke(messages=[{"role": "user", "content": "test"}])

        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Authorization") is None


class TestCustomBaseUrl:
    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_custom_base_url_used_in_request(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = _make_openai_response()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = OpenAiClient(base_url="http://localhost:11434/v1")
        client.invoke(messages=[{"role": "user", "content": "test"}])

        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "http://localhost:11434/v1/chat/completions"


class TestResponseParsing:
    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_returns_text_and_usage(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = _make_openai_response(
            text="result", prompt_tokens=100, completion_tokens=200
        )
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = OpenAiClient()
        text, usage = client.invoke(messages=[{"role": "user", "content": "test"}])

        assert text == "result"
        assert isinstance(usage, TokenUsage)
        assert usage.input_tokens == 100
        assert usage.output_tokens == 200

    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_missing_usage_defaults_to_zero(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {"choices": [{"message": {"content": "hello"}}]}
        ).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = OpenAiClient()
        text, usage = client.invoke(messages=[{"role": "user", "content": "test"}])

        assert text == "hello"
        assert usage.input_tokens == 0
        assert usage.output_tokens == 0


class TestRetryLogic:
    @patch("hypothesis_engine.openai_client.time.sleep")
    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_retries_on_500(
        self, mock_urlopen: MagicMock, mock_sleep: MagicMock
    ) -> None:
        error_500 = urllib.error.HTTPError(
            url="http://test", code=500, msg="Server Error", hdrs=None, fp=BytesIO(b"")  # type: ignore[arg-type]
        )
        mock_resp = MagicMock()
        mock_resp.read.return_value = _make_openai_response("success")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [error_500, mock_resp]

        client = OpenAiClient(max_retries=3)
        text, usage = client.invoke(messages=[{"role": "user", "content": "test"}])

        assert text == "success"
        assert mock_urlopen.call_count == 2
        mock_sleep.assert_called_once_with(1.0)

    @patch("hypothesis_engine.openai_client.time.sleep")
    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_raises_immediately_on_4xx(
        self, mock_urlopen: MagicMock, mock_sleep: MagicMock
    ) -> None:
        error_401 = urllib.error.HTTPError(
            url="http://test", code=401, msg="Unauthorized", hdrs=None, fp=BytesIO(b"")  # type: ignore[arg-type]
        )
        mock_urlopen.side_effect = error_401

        client = OpenAiClient(max_retries=3)
        with pytest.raises(RuntimeError, match="HTTP 401"):
            client.invoke(messages=[{"role": "user", "content": "test"}])

        assert mock_urlopen.call_count == 1
        mock_sleep.assert_not_called()

    @patch("hypothesis_engine.openai_client.time.sleep")
    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_raises_after_all_retries_exhausted_on_500(
        self, mock_urlopen: MagicMock, mock_sleep: MagicMock
    ) -> None:
        error_500 = urllib.error.HTTPError(
            url="http://test", code=500, msg="Server Error", hdrs=None, fp=BytesIO(b"")  # type: ignore[arg-type]
        )
        mock_urlopen.side_effect = error_500

        client = OpenAiClient(max_retries=3)
        with pytest.raises(RuntimeError, match="HTTP 500"):
            client.invoke(messages=[{"role": "user", "content": "test"}])

        assert mock_urlopen.call_count == 3
        assert mock_sleep.call_count == 2

    @patch("hypothesis_engine.openai_client.time.sleep")
    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_exponential_backoff_delays(
        self, mock_urlopen: MagicMock, mock_sleep: MagicMock
    ) -> None:
        error_503 = urllib.error.HTTPError(
            url="http://test", code=503, msg="Service Unavailable", hdrs=None, fp=BytesIO(b"")  # type: ignore[arg-type]
        )
        mock_urlopen.side_effect = error_503

        client = OpenAiClient(max_retries=3)
        with pytest.raises(RuntimeError):
            client.invoke(messages=[{"role": "user", "content": "test"}])

        delays = [call.args[0] for call in mock_sleep.call_args_list]
        assert delays == [1.0, 2.0]

    @patch("hypothesis_engine.openai_client.time.sleep")
    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_retries_on_429_and_succeeds(
        self, mock_urlopen: MagicMock, mock_sleep: MagicMock
    ) -> None:
        error_429 = urllib.error.HTTPError(
            url="http://test", code=429, msg="Too Many Requests", hdrs=None, fp=BytesIO(b"")  # type: ignore[arg-type]
        )
        mock_resp = MagicMock()
        mock_resp.read.return_value = _make_openai_response("ok")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [error_429, error_429, mock_resp]

        client = OpenAiClient(max_retries=3)
        text, _ = client.invoke(messages=[{"role": "user", "content": "test"}])

        assert text == "ok"
        assert mock_urlopen.call_count == 3
        delays = [call.args[0] for call in mock_sleep.call_args_list]
        assert delays == [1.0, 2.0]

    @patch("hypothesis_engine.openai_client.time.sleep")
    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_raises_after_all_retries_exhausted_on_429(
        self, mock_urlopen: MagicMock, mock_sleep: MagicMock
    ) -> None:
        error_429 = urllib.error.HTTPError(
            url="http://test", code=429, msg="Too Many Requests", hdrs=None, fp=BytesIO(b"")  # type: ignore[arg-type]
        )
        mock_urlopen.side_effect = error_429

        client = OpenAiClient(max_retries=3)
        with pytest.raises(RuntimeError, match="HTTP 429"):
            client.invoke(messages=[{"role": "user", "content": "test"}])

        assert mock_urlopen.call_count == 3
        assert mock_sleep.call_count == 2

    @patch("hypothesis_engine.openai_client.time.sleep")
    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_raises_immediately_on_400(
        self, mock_urlopen: MagicMock, mock_sleep: MagicMock
    ) -> None:
        error_400 = urllib.error.HTTPError(
            url="http://test", code=400, msg="Bad Request", hdrs=None, fp=BytesIO(b"")  # type: ignore[arg-type]
        )
        mock_urlopen.side_effect = error_400

        client = OpenAiClient(max_retries=3)
        with pytest.raises(RuntimeError, match="HTTP 400"):
            client.invoke(messages=[{"role": "user", "content": "test"}])

        assert mock_urlopen.call_count == 1
        mock_sleep.assert_not_called()

    @patch("hypothesis_engine.openai_client.time.sleep")
    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_generic_exception_retries_then_succeeds(
        self, mock_urlopen: MagicMock, mock_sleep: MagicMock
    ) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = _make_openai_response("recovered")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [OSError("connection reset"), OSError("connection reset"), mock_resp]

        client = OpenAiClient(max_retries=3)
        text, _ = client.invoke(messages=[{"role": "user", "content": "test"}])

        assert text == "recovered"
        assert mock_urlopen.call_count == 3
        delays = [call.args[0] for call in mock_sleep.call_args_list]
        assert delays == [1.0, 2.0]

    @patch("hypothesis_engine.openai_client.time.sleep")
    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_generic_exception_exhausts_retries(
        self, mock_urlopen: MagicMock, mock_sleep: MagicMock
    ) -> None:
        mock_urlopen.side_effect = OSError("connection refused")

        client = OpenAiClient(max_retries=3)
        with pytest.raises(RuntimeError, match="Failed after.*retries"):
            client.invoke(messages=[{"role": "user", "content": "test"}])

        assert mock_urlopen.call_count == 3
        assert mock_sleep.call_count == 2


class TestInvokeStructured:
    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_returns_content_and_usage(self, mock_urlopen: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = _make_openai_response(
            text='{"key": "value"}', prompt_tokens=50, completion_tokens=30
        )
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        schema = {"type": "object", "properties": {"key": {"type": "string"}}}
        client = OpenAiClient(model="gpt-4o")
        text, usage = client.invoke_structured(
            messages=[{"role": "user", "content": "generate"}],
            output_schema=schema,
        )

        assert text == '{"key": "value"}'
        assert isinstance(usage, TokenUsage)
        assert usage.input_tokens == 50
        assert usage.output_tokens == 30

    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_request_payload_includes_response_format(
        self, mock_urlopen: MagicMock
    ) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = _make_openai_response(text="{}")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        schema = {"type": "object", "properties": {"x": {"type": "integer"}}}
        client = OpenAiClient(model="gpt-4o-mini")
        client.invoke_structured(
            messages=[{"role": "user", "content": "go"}],
            output_schema=schema,
        )

        req = mock_urlopen.call_args[0][0]
        sent_body = json.loads(req.data)
        assert sent_body["model"] == "gpt-4o-mini"
        assert sent_body["response_format"]["type"] == "json_schema"
        assert sent_body["response_format"]["json_schema"]["name"] == "structured_output"
        assert sent_body["response_format"]["json_schema"]["schema"] == schema
        assert sent_body["response_format"]["json_schema"]["strict"] is True

    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_system_message_included_when_provided(
        self, mock_urlopen: MagicMock
    ) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = _make_openai_response(text="{}")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = OpenAiClient()
        client.invoke_structured(
            messages=[{"role": "user", "content": "go"}],
            output_schema={"type": "object"},
            system="be precise",
        )

        req = mock_urlopen.call_args[0][0]
        sent_body = json.loads(req.data)
        assert sent_body["messages"][0] == {"role": "system", "content": "be precise"}
        assert sent_body["messages"][1] == {"role": "user", "content": "go"}

    @patch("hypothesis_engine.openai_client.urllib.request.urlopen")
    def test_falls_back_to_invoke_on_failure(self, mock_urlopen: MagicMock) -> None:
        fallback_response = _make_openai_response(text="fallback text")
        mock_resp = MagicMock()
        mock_resp.read.return_value = fallback_response
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [OSError("network error"), mock_resp]

        client = OpenAiClient(max_retries=1)
        with pytest.warns(RuntimeWarning, match="invoke_structured failed"):
            text, usage = client.invoke_structured(
                messages=[{"role": "user", "content": "go"}],
                output_schema={"type": "object"},
            )

        assert text == "fallback text"
        assert mock_urlopen.call_count == 2
