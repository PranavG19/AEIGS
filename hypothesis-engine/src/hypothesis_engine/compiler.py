from __future__ import annotations

import json
import time

from pydantic import BaseModel, Field

from hypothesis_engine.bedrock_client import LlmBackend
from hypothesis_engine.generator import Hypothesis


class TestParameter(BaseModel):
    name: str
    value: str
    location: str = "body"


class ExpectedAnomaly(BaseModel):
    anomaly_type: str
    description: str


class TestSpecification(BaseModel):
    hypothesis_condition: str
    target_endpoint: str
    http_method: str = "GET"
    parameters: list[TestParameter] = Field(default_factory=list)
    payload_patterns: list[str] = Field(default_factory=list)
    expected_anomalies: list[ExpectedAnomaly] = Field(default_factory=list)
    priority: float = Field(ge=0.0, le=1.0, default=0.5)


class CompilationResult(BaseModel):
    specifications: list[TestSpecification]
    compilation_time_ms: float
    failed_compilations: int
    input_tokens: int = 0
    output_tokens: int = 0


COMPILER_SYSTEM_PROMPT = (
    "You are a security test specification compiler. "
    "Convert vulnerability hypotheses into concrete test specifications. "
    "Each specification must be a JSON object with these fields:\n"
    '{"target_endpoint": "/path", "http_method": "GET|POST|PUT|DELETE", '
    '"parameters": [{"name": "param", "value": "payload", "location": "body|query|header"}], '
    '"payload_patterns": ["pattern1", "pattern2"], '
    '"expected_anomalies": [{"anomaly_type": "status-code|timing|content|reflection", '
    '"description": "what to look for"}], '
    '"priority": 0.0-1.0}\n'
    "Return a JSON array. Be concrete and specific with real payloads."
)


def build_compilation_prompt(hypothesis: Hypothesis) -> str:
    return (
        f"Convert this vulnerability hypothesis into a test specification:\n\n"
        f"Condition: {hypothesis.condition}\n"
        f"Vulnerability class: {hypothesis.vulnerability_class}\n"
        f"Reasoning: {hypothesis.reasoning}\n"
        f"Test approach: {hypothesis.test_approach}\n"
        f"Confidence: {hypothesis.confidence}\n\n"
        f"Generate exactly one test specification as a JSON array with one element."
    )


def parse_test_specifications(response_text: str, hypothesis: Hypothesis) -> list[TestSpecification]:
    cleaned = response_text.strip()

    start = cleaned.find("[")
    end = cleaned.rfind("]")
    if start == -1 or end == -1:
        start_obj = cleaned.find("{")
        end_obj = cleaned.rfind("}")
        if start_obj == -1 or end_obj == -1:
            return []
        json_str = "[" + cleaned[start_obj : end_obj + 1] + "]"
    else:
        json_str = cleaned[start : end + 1]

    try:
        raw_list = json.loads(json_str)
    except json.JSONDecodeError:
        return []

    specs: list[TestSpecification] = []
    for item in raw_list:
        if not isinstance(item, dict):
            continue
        try:
            parameters = [
                TestParameter(
                    name=p.get("name", ""),
                    value=p.get("value", ""),
                    location=p.get("location", "body"),
                )
                for p in item.get("parameters", [])
                if isinstance(p, dict)
            ]

            expected_anomalies = [
                ExpectedAnomaly(
                    anomaly_type=a.get("anomaly_type", ""),
                    description=a.get("description", ""),
                )
                for a in item.get("expected_anomalies", [])
                if isinstance(a, dict)
            ]

            spec = TestSpecification(
                hypothesis_condition=hypothesis.condition,
                target_endpoint=item.get("target_endpoint", "/"),
                http_method=item.get("http_method", "GET"),
                parameters=parameters,
                payload_patterns=item.get("payload_patterns", []),
                expected_anomalies=expected_anomalies,
                priority=float(item.get("priority", hypothesis.confidence)),
            )
            specs.append(spec)
        except (ValueError, TypeError):
            continue

    return specs


class HypothesisCompiler:
    def __init__(self, client: LlmBackend) -> None:
        self._client = client

    def compile_hypothesis(self, hypothesis: Hypothesis) -> list[TestSpecification]:
        prompt = build_compilation_prompt(hypothesis)
        messages = [{"role": "user", "content": prompt}]
        response_text, _usage = self._client.invoke(
            messages=messages,
            system=COMPILER_SYSTEM_PROMPT,
            max_tokens=2048,
        )
        return parse_test_specifications(response_text, hypothesis)

    def _compile_one_with_usage(
        self, hypothesis: Hypothesis
    ) -> tuple[list[TestSpecification], int, int]:
        prompt = build_compilation_prompt(hypothesis)
        messages = [{"role": "user", "content": prompt}]
        response_text, usage = self._client.invoke(
            messages=messages,
            system=COMPILER_SYSTEM_PROMPT,
            max_tokens=2048,
        )
        specs = parse_test_specifications(response_text, hypothesis)
        return specs, usage.input_tokens, usage.output_tokens

    def compile_batch(self, hypotheses: list[Hypothesis]) -> CompilationResult:
        start_time = time.monotonic()
        all_specs: list[TestSpecification] = []
        failed = 0
        total_input_tokens = 0
        total_output_tokens = 0

        for hypothesis in hypotheses:
            try:
                specs, in_tok, out_tok = self._compile_one_with_usage(hypothesis)
                all_specs.extend(specs)
                total_input_tokens += in_tok
                total_output_tokens += out_tok
            except Exception:
                failed += 1

        elapsed_ms = (time.monotonic() - start_time) * 1000

        return CompilationResult(
            specifications=all_specs,
            compilation_time_ms=elapsed_ms,
            failed_compilations=failed,
            input_tokens=total_input_tokens,
            output_tokens=total_output_tokens,
        )
