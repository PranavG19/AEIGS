from __future__ import annotations

import json
import time
from typing import Any

from pydantic import BaseModel, Field

from hypothesis_engine.bedrock_client import BedrockClient, LlmBackend
from hypothesis_engine.openai_client import OpenAiClient


class ScanContext(BaseModel):
    technology_stack: list[str] = Field(default_factory=list)
    high_centrality_nodes: list[dict[str, Any]] = Field(default_factory=list)
    findings_summary: list[str] = Field(default_factory=list)
    high_risk_functions: list[dict[str, str]] = Field(default_factory=list)
    authorization_matrix_summary: str = ""
    known_vulnerable_dependencies: list[str] = Field(default_factory=list)
    feedback_summary: list[dict[str, object]] = Field(default_factory=list)


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
    reasoning_trace: str = ""
    input_tokens: int = 0
    output_tokens: int = 0


SYSTEM_PROMPT = (
    "You are a security researcher analyzing a web application for vulnerabilities. "
    "First, analyze the context and reason about potential vulnerabilities step by step. "
    "Then output your hypotheses as a JSON array.\n\n"
    "Each hypothesis must follow this exact JSON format:\n"
    '{"condition": "IF ...", "vulnerability_class": "...", '
    '"reasoning": "BECAUSE ...", "test_approach": "CAN BE TESTED BY ...", '
    '"confidence": 0.0-1.0}\n'
    "Return your reasoning as plain text first, followed by the JSON array. "
    "Be specific and actionable."
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

    if context.feedback_summary:
        feedback_lines = [
            f"  - {fb.get('condition', '?')}: {fb.get('outcome', '?')} "
            f"(anomaly_score: {fb.get('anomaly_score', 0.0)})"
            for fb in context.feedback_summary
        ]
        parts.append("## Prior Round Feedback\n" + "\n".join(feedback_lines))

    return "\n\n".join(parts) if parts else "No context available. Generate general hypotheses."


def parse_hypotheses_from_response(
    response_text: str,
) -> tuple[str, list[Hypothesis]]:
    cleaned = response_text.strip()

    start = cleaned.find("[")
    end = cleaned.rfind("]")
    if start == -1 or end == -1:
        return ("", [])

    reasoning_trace = cleaned[:start].strip()
    json_str = cleaned[start : end + 1]

    try:
        raw_list = json.loads(json_str)
    except json.JSONDecodeError:
        return (reasoning_trace, [])

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

    return (reasoning_trace, hypotheses)


def create_backend(backend_type: str, **kwargs: Any) -> LlmBackend:
    if backend_type == "bedrock":
        return BedrockClient(**kwargs)
    elif backend_type in ("openai", "ollama"):
        if backend_type == "ollama":
            kwargs.setdefault("base_url", "http://localhost:11434/v1")
        return OpenAiClient(**kwargs)
    else:
        raise ValueError(f"Unknown backend type: {backend_type}")


class HypothesisGenerator:
    def __init__(
        self,
        model_id: str = "global.anthropic.claude-sonnet-4-6",
        aws_profile: str | None = None,
        max_retries: int = 3,
        timeout_seconds: int = 120,
        client: LlmBackend | None = None,
    ) -> None:
        if client is not None:
            self._client = client
        else:
            self._client = BedrockClient(
                model_id=model_id,
                aws_profile=aws_profile,
                max_retries=max_retries,
                timeout_seconds=timeout_seconds,
            )
        self._model_id = model_id

    def invoke(
        self,
        messages: list[dict[str, str]],
        system: str = "",
        max_tokens: int = 4096,
    ) -> tuple[str, Any]:
        return self._client.invoke(messages=messages, system=system, max_tokens=max_tokens)

    def generate(self, context: ScanContext, max_hypotheses: int = 20) -> GenerationResult:
        user_prompt = build_user_prompt(context)
        start_time = time.monotonic()

        messages = [
            {
                "role": "user",
                "content": f"Generate up to {max_hypotheses} vulnerability hypotheses "
                f"for this application:\n\n{user_prompt}",
            }
        ]

        response_text, usage = self.invoke(
            messages=messages,
            system=SYSTEM_PROMPT,
            max_tokens=8192,
        )
        elapsed_ms = (time.monotonic() - start_time) * 1000

        reasoning_trace, hypotheses = parse_hypotheses_from_response(response_text)
        hypotheses = hypotheses[:max_hypotheses]

        return GenerationResult(
            hypotheses=hypotheses,
            model_id=self._model_id,
            generation_time_ms=elapsed_ms,
            reasoning_trace=reasoning_trace,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
        )
