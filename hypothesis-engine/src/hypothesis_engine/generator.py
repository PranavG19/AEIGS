from __future__ import annotations

import json
import time
from typing import Any

from pydantic import BaseModel, Field

from hypothesis_engine.bedrock_client import BedrockClient, LlmBackend, TokenUsage
from hypothesis_engine.openai_client import OpenAiClient


class ScanContext(BaseModel):
    technology_stack: list[str] = Field(default_factory=list)
    high_centrality_nodes: list[dict[str, Any]] = Field(default_factory=list)
    findings_summary: list[str] = Field(default_factory=list)
    high_risk_functions: list[dict[str, str]] = Field(default_factory=list)
    authorization_matrix_summary: str = ""
    known_vulnerable_dependencies: list[str] = Field(default_factory=list)
    feedback_summary: str = ""
    graph_nodes: list[dict[str, Any]] = Field(default_factory=list)
    graph_edges: list[dict[str, Any]] = Field(default_factory=list)
    defense_posture: dict[str, Any] = Field(default_factory=dict)
    attack_paths: list[dict[str, Any]] = Field(default_factory=list)


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
    "When graph topology is provided, reason about multi-step attack chains: "
    "identify which nodes are reachable from public endpoints and which paths "
    "lack defensive controls. "
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

    if context.graph_nodes:
        node_lines = []
        for n in context.graph_nodes[:50]:
            label = n.get("label", "unknown")
            ntype = n.get("type", "unknown")
            protected = n.get("protected_by", [])
            if protected:
                node_lines.append(f"  - {label} (type={ntype}, protected_by={', '.join(protected)})")
            else:
                node_lines.append(f"  - {label} (type={ntype})")
        parts.append("Graph nodes:\n" + "\n".join(node_lines))

    if context.graph_edges:
        edge_lines = [
            f"  - {e.get('source_id', '?')} --[{e.get('label', '?')}]--> {e.get('target_id', '?')} (weight={e.get('weight', '?')})"
            for e in context.graph_edges[:100]
        ]
        parts.append("Graph edges:\n" + "\n".join(edge_lines))

    if context.defense_posture:
        dp = context.defense_posture
        defense_lines = []
        if dp.get("has_waf") is not None:
            defense_lines.append(f"  WAF present: {dp['has_waf']}")
        if dp.get("waf_vendor"):
            defense_lines.append(f"  WAF vendor: {dp['waf_vendor']}")
        if dp.get("bot_detection_present") is not None:
            defense_lines.append(f"  Bot detection: {dp['bot_detection_present']}")
        if dp.get("rate_limit_rps") is not None:
            defense_lines.append(f"  Rate limit: {dp['rate_limit_rps']} rps")
        if defense_lines:
            parts.append("Defense posture:\n" + "\n".join(defense_lines))

    if context.attack_paths:
        path_lines = []
        for p in context.attack_paths[:10]:
            path_nodes = " -> ".join(p.get("path", []))
            weight = p.get("total_weight", "?")
            unprotected = p.get("unprotected_hops", "?")
            path_lines.append(f"  - {path_nodes} (weight={weight}, unprotected_hops={unprotected})")
        parts.append("Known attack paths:\n" + "\n".join(path_lines))

    if context.feedback_summary:
        # feedback_summary is produced by build_feedback_summary() — safe fields only:
        #   SAFE: vulnerability_class (enum name, from our system)
        #   SAFE: outcome (HypothesisOutcome enum value, from our system)
        #   SAFE: anomaly_score (float, from our oracle)
        #   UNSAFE (excluded): anomaly_details — may contain raw target response content;
        #     including it would allow a malicious server to inject instructions into
        #     subsequent LLM prompts.
        parts.append("## Prior Round Feedback\n" + context.feedback_summary)

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
    ) -> tuple[str, TokenUsage]:
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

        schema = {"type": "array", "items": Hypothesis.model_json_schema()}
        reasoning_trace = ""
        hypotheses: list[Hypothesis] = []
        usage = None

        try:
            json_text, usage = self._client.invoke_structured(
                messages=messages,
                output_schema=schema,
                system=SYSTEM_PROMPT,
                max_tokens=8192,
            )
            raw_list = json.loads(json_text)
            hypotheses = [Hypothesis.model_validate(h) for h in raw_list]
        except Exception:
            raw_text, usage = self.invoke(
                messages=messages,
                system=SYSTEM_PROMPT,
                max_tokens=8192,
            )
            reasoning_trace, hypotheses = parse_hypotheses_from_response(raw_text)

        elapsed_ms = (time.monotonic() - start_time) * 1000
        hypotheses = hypotheses[:max_hypotheses]

        return GenerationResult(
            hypotheses=hypotheses,
            model_id=self._model_id,
            generation_time_ms=elapsed_ms,
            reasoning_trace=reasoning_trace,
            input_tokens=usage.input_tokens if usage is not None else 0,
            output_tokens=usage.output_tokens if usage is not None else 0,
        )
