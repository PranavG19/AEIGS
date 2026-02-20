from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from typing import Any

import boto3
import botocore.config
from pydantic import BaseModel


class TokenUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0


class LlmBackend(ABC):
    @abstractmethod
    def invoke(
        self,
        messages: list[dict[str, str]],
        system: str = "",
        max_tokens: int = 4096,
    ) -> tuple[str, TokenUsage]: ...

    def invoke_structured(
        self,
        messages: list[dict[str, str]],
        output_schema: dict,
        system: str = "",
        max_tokens: int = 4096,
    ) -> tuple[str, TokenUsage]:
        """Fall back to plain invoke() with the schema appended as a user message.

        Subclasses should override this with native structured output support.
        The schema hint instructs the model to return valid JSON matching the
        provided schema, but conformance is not enforced at the API level.
        """
        schema_hint = json.dumps(output_schema, indent=2)
        schema_message: dict[str, str] = {
            "role": "user",
            "content": f"Output must be valid JSON matching this schema:\n{schema_hint}",
        }
        augmented_messages = list(messages) + [schema_message]
        return self.invoke(augmented_messages, system=system, max_tokens=max_tokens)


class BedrockClient(LlmBackend):
    def __init__(
        self,
        model_id: str = "global.anthropic.claude-sonnet-4-6",
        aws_profile: str | None = None,
        max_retries: int = 3,
        timeout_seconds: int = 120,
    ) -> None:
        self._model_id = model_id
        self._aws_profile = aws_profile
        self._max_retries = max_retries
        self._timeout_seconds = timeout_seconds
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            if self._aws_profile is None:
                session = boto3.Session()
            else:
                session = boto3.Session(profile_name=self._aws_profile)
            config = botocore.config.Config(
                read_timeout=self._timeout_seconds,
                connect_timeout=min(self._timeout_seconds, 30),
            )
            self._client = session.client(
                "bedrock-runtime",
                region_name="us-east-1",
                config=config,
            )
        return self._client

    def invoke(
        self,
        messages: list[dict[str, str]],
        system: str,
        max_tokens: int = 4096,
    ) -> tuple[str, TokenUsage]:
        body = json.dumps(
            {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "system": system,
                "messages": messages,
            }
        )
        return self._invoke_with_retry(body)

    def invoke_structured(
        self,
        messages: list[dict[str, str]],
        output_schema: dict,
        system: str = "",
        max_tokens: int = 4096,
    ) -> tuple[str, TokenUsage]:
        """Use Bedrock tool_use to force structured JSON output.

        Builds a single-tool definition whose input_schema is the caller-supplied
        schema, then sets tool_choice to force the model to call that tool.
        The tool_use block in the response contains the structured result as a dict.

        Falls back to plain invoke() if the API does not return a tool_use block
        (e.g. the model prefaced the call with a text block, or if the API call
        itself raises an exception).
        """
        tool = {
            "name": "structured_output",
            "description": "Return the result as structured JSON.",
            "input_schema": output_schema,
        }
        body = json.dumps(
            {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "system": system,
                "messages": messages,
                "tools": [tool],
                "tool_choice": {"type": "tool", "name": "structured_output"},
            }
        )
        try:
            client = self._get_client()
            response = client.invoke_model(
                modelId=self._model_id,
                contentType="application/json",
                accept="application/json",
                body=body,
            )
            response_body = json.loads(response["body"].read())
            raw_usage = response_body.get("usage", {})
            usage = TokenUsage(
                input_tokens=raw_usage.get("input_tokens", 0),
                output_tokens=raw_usage.get("output_tokens", 0),
            )
            for block in response_body.get("content", []):
                if block.get("type") == "tool_use":
                    return (json.dumps(block["input"]), usage)
        except Exception:
            pass
        return self.invoke(messages, system=system, max_tokens=max_tokens)

    def _invoke_with_retry(self, body: str) -> tuple[str, TokenUsage]:
        client = self._get_client()
        delays = [1.0, 2.0, 4.0]

        last_error: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                response = client.invoke_model(
                    modelId=self._model_id,
                    contentType="application/json",
                    accept="application/json",
                    body=body,
                )
                response_body = json.loads(response["body"].read())
                text = str(response_body.get("content", [{}])[0].get("text", ""))
                raw_usage = response_body.get("usage", {})
                usage = TokenUsage(
                    input_tokens=raw_usage.get("input_tokens", 0),
                    output_tokens=raw_usage.get("output_tokens", 0),
                )
                return (text, usage)
            except Exception as e:
                last_error = e
                if attempt < self._max_retries - 1:
                    delay = delays[min(attempt, len(delays) - 1)]
                    time.sleep(delay)

        raise RuntimeError(
            f"Failed after {self._max_retries} retries: {last_error}"
        ) from last_error
