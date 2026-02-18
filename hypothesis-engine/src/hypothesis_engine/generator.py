from __future__ import annotations

import json
import time
from typing import Any

import boto3
from pydantic import BaseModel, Field


class ScanContext(BaseModel):
    technology_stack: list[str] = Field(default_factory=list)
    high_centrality_nodes: list[dict[str, Any]] = Field(default_factory=list)
    findings_summary: list[str] = Field(default_factory=list)
    high_risk_functions: list[dict[str, str]] = Field(default_factory=list)
    authorization_matrix_summary: str = ""
    known_vulnerable_dependencies: list[str] = Field(default_factory=list)


class Hypothesis(BaseModel):
    condition: str
    vulnerability_class: str
    reasoning: str
    test_approach: str
    confidence: float = Field(ge=0.0, le=1.0)


class GenerationResult(BaseModel):
    hypotheses: list[Hypothesis]
    model_id: str
    generation_time_ms: float


SYSTEM_PROMPT = (
    "You are a security researcher analyzing a web application for vulnerabilities. "
    "Generate hypotheses about potential vulnerabilities based on the provided context. "
    "Each hypothesis must follow this exact JSON format:\n"
    '{"condition": "IF ...", "vulnerability_class": "...", '
    '"reasoning": "BECAUSE ...", "test_approach": "CAN BE TESTED BY ...", '
    '"confidence": 0.0-1.0}\n'
    "Return a JSON array of hypothesis objects. Be specific and actionable."
)


def build_user_prompt(context: ScanContext) -> str:
    parts: list[str] = []

    if context.technology_stack:
        parts.append(f"Technology stack: {', '.join(context.technology_stack)}")

    if context.high_centrality_nodes:
        node_summaries = [
            f"  - {n.get('label', 'unknown')} (type={n.get('type', 'unknown')})"
            for n in context.high_centrality_nodes[:50]
        ]
        parts.append("High-centrality nodes:\n" + "\n".join(node_summaries))

    if context.findings_summary:
        parts.append("Findings so far:\n" + "\n".join(f"  - {f}" for f in context.findings_summary))

    if context.high_risk_functions:
        func_summaries = [
            f"  - {f.get('name', '?')} in {f.get('file', '?')}"
            for f in context.high_risk_functions
        ]
        parts.append("High-risk functions:\n" + "\n".join(func_summaries))

    if context.authorization_matrix_summary:
        parts.append(f"Authorization matrix:\n{context.authorization_matrix_summary}")

    if context.known_vulnerable_dependencies:
        parts.append(
            "Known vulnerable dependencies:\n"
            + "\n".join(f"  - {d}" for d in context.known_vulnerable_dependencies)
        )

    return "\n\n".join(parts) if parts else "No context available. Generate general hypotheses."


def parse_hypotheses_from_response(response_text: str) -> list[Hypothesis]:
    cleaned = response_text.strip()

    start = cleaned.find("[")
    end = cleaned.rfind("]")
    if start == -1 or end == -1:
        return []

    json_str = cleaned[start : end + 1]

    try:
        raw_list = json.loads(json_str)
    except json.JSONDecodeError:
        return []

    hypotheses: list[Hypothesis] = []
    for item in raw_list:
        if not isinstance(item, dict):
            continue
        try:
            hypothesis = Hypothesis(
                condition=item.get("condition", ""),
                vulnerability_class=item.get("vulnerability_class", ""),
                reasoning=item.get("reasoning", ""),
                test_approach=item.get("test_approach", ""),
                confidence=float(item.get("confidence", 0.5)),
            )
            if hypothesis.condition and hypothesis.vulnerability_class:
                hypotheses.append(hypothesis)
        except (ValueError, TypeError):
            continue

    return hypotheses


class HypothesisGenerator:
    def __init__(
        self,
        model_id: str = "global.anthropic.claude-sonnet-4-6",
        aws_profile: str = "ziya",
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
            session = boto3.Session(profile_name=self._aws_profile)
            self._client = session.client(
                "bedrock-runtime",
                region_name="us-east-1",
            )
        return self._client

    def generate(self, context: ScanContext, max_hypotheses: int = 20) -> GenerationResult:
        user_prompt = build_user_prompt(context)
        start_time = time.monotonic()

        body = json.dumps(
            {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 4096,
                "system": SYSTEM_PROMPT,
                "messages": [
                    {
                        "role": "user",
                        "content": f"Generate up to {max_hypotheses} vulnerability hypotheses "
                        f"for this application:\n\n{user_prompt}",
                    }
                ],
            }
        )

        response_text = self._invoke_with_retry(body)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        hypotheses = parse_hypotheses_from_response(response_text)
        hypotheses = hypotheses[:max_hypotheses]

        return GenerationResult(
            hypotheses=hypotheses,
            model_id=self._model_id,
            generation_time_ms=elapsed_ms,
        )

    def _invoke_with_retry(self, body: str) -> str:
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
                return str(response_body.get("content", [{}])[0].get("text", ""))
            except Exception as e:
                last_error = e
                if attempt < self._max_retries - 1:
                    delay = delays[min(attempt, len(delays) - 1)]
                    time.sleep(delay)

        raise RuntimeError(
            f"Failed after {self._max_retries} retries: {last_error}"
        ) from last_error
