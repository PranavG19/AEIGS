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
    "<role>\n"
    "You are a security test specification compiler.\n"
    "</role>\n\n"
    "<task>\n"
    "Convert vulnerability hypotheses into concrete, executable test specifications.\n"
    "Each specification must contain real payloads and precise detection criteria.\n"
    "</task>\n\n"
    "<output_format>\n"
    "Return a JSON array inside <test_specs> tags. Each object must have these fields:\n"
    '{"target_endpoint": "/path",\n'
    ' "http_method": "GET|POST|PUT|DELETE",\n'
    ' "parameters": [{"name": "param", "value": "payload", "location": "body|query|header"}],\n'
    ' "payload_patterns": ["pattern1", "pattern2"],\n'
    ' "expected_anomalies": [{"anomaly_type": "status-code|timing|content|reflection",\n'
    '  "description": "what to look for"}],\n'
    ' "priority": 0.0-1.0}\n'
    "</output_format>\n\n"
    "<example>\n"
    "Hypothesis: IF /api/search accepts query parameter q that reaches SQL query\n"
    "Test specification:\n"
    '[{"target_endpoint": "/api/search",\n'
    '  "http_method": "GET",\n'
    '  "parameters": [{"name": "q", "value": "\\\' OR 1=1--", "location": "query"}],\n'
    '  "payload_patterns": ["\\\' OR 1=1--", "\\\' AND 1=0--", "\\\'; DROP TABLE--"],\n'
    '  "expected_anomalies": [{"anomaly_type": "content", "description": "Tautology returns more rows than contradiction"},\n'
    '   {"anomaly_type": "status-code", "description": "500 Internal Server Error on malformed SQL"}],\n'
    '  "priority": 0.85}]\n'
    "</example>\n\n"
    "<constraints>\n"
    "- Use real, specific payloads — not placeholders like 'malicious input'.\n"
    "- The target_endpoint must be a concrete path, not a description.\n"
    "- Each specification must have at least one parameter and one expected anomaly.\n"
    "- Priority should match the hypothesis confidence score.\n"
    "</constraints>"
)


def build_compilation_prompt(hypothesis: Hypothesis) -> str:
    return (
        "<hypothesis>\n"
        f"  <condition>{hypothesis.condition}</condition>\n"
        f"  <vulnerability_class>{hypothesis.vulnerability_class}</vulnerability_class>\n"
        f"  <reasoning>{hypothesis.reasoning}</reasoning>\n"
        f"  <test_approach>{hypothesis.test_approach}</test_approach>\n"
        f"  <confidence>{hypothesis.confidence}</confidence>\n"
        "</hypothesis>\n\n"
        "Generate exactly one test specification as a JSON array with one element inside <test_specs> tags."
    )


def parse_test_specifications(response_text: str, hypothesis: Hypothesis) -> list[TestSpecification]:
    cleaned = response_text.strip()

    # Try XML tag-based extraction first
    tag_start = cleaned.find("<test_specs>")
    tag_end = cleaned.find("</test_specs>")
    if tag_start != -1 and tag_end != -1:
        json_str = cleaned[tag_start + len("<test_specs>"):tag_end].strip()
    else:
        # Fallback to bracket-based extraction
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
