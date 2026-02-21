from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from hypothesis_engine.bedrock_client import LlmBackend, TokenUsage


class OpenAiClient(LlmBackend):
    def __init__(
        self,
        api_key: str = "",
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o",
        max_retries: int = 3,
        timeout_seconds: int = 120,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._max_retries = max_retries
        self._timeout_seconds = timeout_seconds

    def invoke(
        self,
        messages: list[dict[str, str]],
        system: str = "",
        max_tokens: int = 4096,
    ) -> tuple[str, TokenUsage]:
        request_messages: list[dict[str, str]] = []
        if system:
            request_messages.append({"role": "system", "content": system})
        request_messages.extend(messages)

        body = json.dumps(
            {
                "model": self._model,
                "messages": request_messages,
                "max_tokens": max_tokens,
            }
        ).encode()

        headers = {
            "Content-Type": "application/json",
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        url = f"{self._base_url}/chat/completions"
        return self._invoke_with_retry(url, body, headers)

    def invoke_structured(
        self,
        messages: list[dict[str, str]],
        output_schema: dict,
        system: str = "",
        max_tokens: int = 4096,
    ) -> tuple[str, TokenUsage]:
        """Use OpenAI's native json_schema response_format for structured output.

        Sends a response_format block with type=json_schema and strict=True, which
        causes the API to enforce schema conformance at the model level rather than
        relying on a schema-hint message. Falls back to plain invoke() with a
        RuntimeWarning if the structured request fails.
        """
        request_messages: list[dict[str, str]] = []
        if system:
            request_messages.append({"role": "system", "content": system})
        request_messages.extend(messages)

        body = json.dumps(
            {
                "model": self._model,
                "messages": request_messages,
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "structured_output",
                        "schema": output_schema,
                        "strict": True,
                    },
                },
                "max_tokens": max_tokens,
            }
        ).encode()

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        url = f"{self._base_url}/chat/completions"
        try:
            return self._invoke_with_retry(url, body, headers)
        except Exception as e:
            import warnings

            warnings.warn(
                f"invoke_structured failed, falling back to invoke(): {e}",
                RuntimeWarning,
                stacklevel=2,
            )
            return self.invoke(messages, system=system, max_tokens=max_tokens)

    def _invoke_with_retry(
        self,
        url: str,
        body: bytes,
        headers: dict[str, str],
    ) -> tuple[str, TokenUsage]:
        delays = [1.0, 2.0, 4.0]
        last_error: Exception | None = None

        for attempt in range(self._max_retries):
            try:
                req = urllib.request.Request(
                    url, data=body, headers=headers, method="POST"
                )
                with urllib.request.urlopen(req, timeout=self._timeout_seconds) as resp:
                    response_body = json.loads(resp.read())

                text = response_body["choices"][0]["message"]["content"]
                raw_usage = response_body.get("usage", {})
                usage = TokenUsage(
                    input_tokens=raw_usage.get("prompt_tokens", 0),
                    output_tokens=raw_usage.get("completion_tokens", 0),
                )
                return (text, usage)
            except urllib.error.HTTPError as e:
                last_error = e
                retryable = e.code == 429 or 500 <= e.code < 600
                if retryable and attempt < self._max_retries - 1:
                    delay = delays[min(attempt, len(delays) - 1)]
                    time.sleep(delay)
                    continue
                raise RuntimeError(
                    f"HTTP {e.code}: {e.reason}"
                ) from e
            except Exception as e:
                last_error = e
                if attempt < self._max_retries - 1:
                    delay = delays[min(attempt, len(delays) - 1)]
                    time.sleep(delay)
                    continue

        raise RuntimeError(
            f"Failed after {self._max_retries} retries: {last_error}"
        ) from last_error
