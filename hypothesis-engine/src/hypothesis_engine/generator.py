from __future__ import annotations

import json
import time
import warnings
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
    class_confirmation_rates: dict[str, float] = Field(default_factory=dict)


class Hypothesis(BaseModel):
    condition: str
    vulnerability_class: str
    reasoning: str
    test_approach: str
    confidence: float = Field(ge=0.0, le=1.0)
    insufficient_data: bool = False


class GenerationResult(BaseModel):
    hypotheses: list[Hypothesis]
    model_id: str
    generation_time_ms: float
    reasoning_trace: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    parsing_method: str = "unknown"
    latency_ms: float = 0.0


SYSTEM_PROMPT = (
    "<role>\n"
    "You are a security vulnerability researcher analyzing a web application.\n"
    "</role>\n\n"
    "<task>\n"
    "Generate vulnerability hypotheses based on the provided application context.\n"
    "For each hypothesis, reason about WHY the vulnerability likely exists given\n"
    "the architecture, then specify HOW to test for it.\n"
    "</task>\n\n"
    "<instructions>\n"
    "1. Analyze the application topology in <graph_topology> to identify attack paths.\n"
    "2. Cross-reference with <defense_posture> to find unprotected paths.\n"
    "3. Consider <prior_feedback> to avoid repeating refuted hypotheses.\n"
    "4. Use <thinking> tags to show your step-by-step reasoning before outputting hypotheses.\n"
    "5. Output hypotheses as a JSON array inside <hypotheses> tags.\n"
    "</instructions>\n\n"
    "<valid_vulnerability_classes>\n"
    "SQL Injection, Cross-Site Scripting, Command Injection, Path Traversal,\n"
    "Server-Side Request Forgery, Insecure Deserialization, Broken Authentication,\n"
    "Broken Authorization, Security Misconfiguration, Sensitive Data Exposure,\n"
    "Server-Side Template Injection, Header Injection, Open Redirect,\n"
    "CRLF Injection, Known Vulnerable Dependency, Insufficient Input Validation\n"
    "</valid_vulnerability_classes>\n\n"
    "<confidence_rubric>\n"
    "0.9-1.0: Strong structural evidence — unvalidated input flows directly to dangerous sink\n"
    "0.7-0.8: Moderate evidence — input reaches sink but validation status is unclear\n"
    "0.4-0.6: Speculative — architecture suggests possibility but data flow is unconfirmed\n"
    "0.1-0.3: Low confidence — technology stack association only, no structural evidence\n"
    "</confidence_rubric>\n\n"
    "<examples>\n"
    "Example 1 (high confidence — structural evidence):\n"
    '{"condition": "IF endpoint /api/search accepts query parameter q that is concatenated into a SQL query in searchHandler",\n'
    ' "vulnerability_class": "SQL Injection",\n'
    ' "reasoning": "BECAUSE the graph shows Endpoint(/api/search) --[Calls]--> Function(searchHandler) --[Reads]--> DataStore(users_db) with no parameterized query usage detected and the endpoint is not ProtectedBy any Defense node",\n'
    " \"test_approach\": \"CAN BE TESTED BY sending tautology payload \\' OR 1=1-- in q parameter and comparing row count against contradiction payload \\' AND 1=0--\",\n"
    ' "confidence": 0.85}\n\n'
    "Example 2 (moderate confidence — partial evidence):\n"
    '{"condition": "IF endpoint /api/render accepts template parameter that is passed to the Jinja2 engine",\n'
    ' "vulnerability_class": "Server-Side Template Injection",\n'
    ' "reasoning": "BECAUSE the technology stack includes Flask/Jinja2 and the endpoint Calls a Function(render_template) but it is unclear whether user input reaches the template context directly",\n'
    ' "test_approach": "CAN BE TESTED BY sending {{7*7}} in the template parameter and checking if response contains 49",\n'
    ' "confidence": 0.55}\n\n'
    "Example 3 (low confidence, insufficient data):\n"
    '{"condition": "IF the Express.js application uses cookie-based sessions",\n'
    ' "vulnerability_class": "Broken Authentication",\n'
    ' "reasoning": "BECAUSE Express.js applications commonly use express-session with default settings that may lack secure cookie flags, but no session configuration was observed in the scan context",\n'
    ' "test_approach": "CAN BE TESTED BY examining Set-Cookie headers for missing Secure, HttpOnly, and SameSite attributes",\n'
    ' "confidence": 0.2,\n'
    ' "insufficient_data": true}\n'
    "</examples>\n\n"
    "<constraints>\n"
    "- Only use vulnerability classes from <valid_vulnerability_classes>. Do NOT invent new classes.\n"
    "- Do NOT assign confidence above 0.7 without structural evidence from the graph topology.\n"
    "- Do NOT repeat hypotheses for vulnerability classes marked as refuted in <prior_feedback>.\n"
    "- If graph topology data is missing, cap all confidence scores at 0.4 and set insufficient_data to true.\n"
    "- Each hypothesis must reference specific endpoints, functions, or data stores from the provided context.\n"
    "</constraints>\n\n"
    "<output_format>\n"
    "First, output your reasoning inside <thinking> tags.\n"
    "Then, output a JSON array inside <hypotheses> tags.\n"
    "Each hypothesis must have these fields:\n"
    '{"condition": "IF ...", "vulnerability_class": "one of the valid classes",\n'
    ' "reasoning": "BECAUSE ...", "test_approach": "CAN BE TESTED BY ...",\n'
    ' "confidence": 0.0-1.0, "insufficient_data": false}\n'
    "</output_format>"
)


def build_user_prompt(context: ScanContext) -> str:
    parts: list[str] = ["<application_context>"]

    if context.technology_stack:
        parts.append(f"<technology_stack>\n{', '.join(context.technology_stack)}\n</technology_stack>")

    if context.high_centrality_nodes:
        node_summaries = [
            f"  - {n.get('label', 'unknown')} (type={n.get('type', 'unknown')})"
            for n in context.high_centrality_nodes[:50]
        ]
        parts.append("<high_centrality_nodes>\n" + "\n".join(node_summaries) + "\n</high_centrality_nodes>")

    if context.findings_summary:
        parts.append("<findings_summary>\n" + "\n".join(f"  - {f}" for f in context.findings_summary) + "\n</findings_summary>")

    if context.high_risk_functions:
        func_summaries = [
            f"  - {f.get('name', '?')} in {f.get('file', '?')}"
            for f in context.high_risk_functions
        ]
        parts.append("<high_risk_functions>\n" + "\n".join(func_summaries) + "\n</high_risk_functions>")

    if context.authorization_matrix_summary:
        parts.append(f"<authorization_matrix>\n{context.authorization_matrix_summary}\n</authorization_matrix>")

    if context.known_vulnerable_dependencies:
        parts.append(
            "<known_vulnerable_dependencies>\n"
            + "\n".join(f"  - {d}" for d in context.known_vulnerable_dependencies)
            + "\n</known_vulnerable_dependencies>"
        )

    if context.graph_nodes or context.graph_edges:
        parts.append("<graph_topology>")
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
            parts.append("<nodes>\n" + "\n".join(node_lines) + "\n</nodes>")

        if context.graph_edges:
            edge_lines = [
                f"  - {e.get('source_id', '?')} --[{e.get('label', '?')}]--> {e.get('target_id', '?')} (weight={e.get('weight', '?')})"
                for e in context.graph_edges[:100]
            ]
            parts.append("<edges>\n" + "\n".join(edge_lines) + "\n</edges>")
        parts.append("</graph_topology>")

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
            parts.append("<defense_posture>\n" + "\n".join(defense_lines) + "\n</defense_posture>")

    if context.attack_paths:
        path_lines = []
        for p in context.attack_paths[:10]:
            path_nodes = " -> ".join(p.get("path", []))
            weight = p.get("total_weight", "?")
            unprotected = p.get("unprotected_hops", "?")
            path_lines.append(f"  - {path_nodes} (weight={weight}, unprotected_hops={unprotected})")
        parts.append("<attack_paths>\n" + "\n".join(path_lines) + "\n</attack_paths>")

    if context.feedback_summary:
        parts.append("<prior_feedback>\n" + context.feedback_summary + "</prior_feedback>")

    if context.class_confirmation_rates:
        rate_lines = [
            f"  {cls}: {rate * 100:.0f}%"
            for cls, rate in sorted(context.class_confirmation_rates.items())
        ]
        parts.append("<prior_performance>\n" + "\n".join(rate_lines) + "\n</prior_performance>")

    parts.append("</application_context>")

    return "\n\n".join(parts) if len(parts) > 2 else "No context available. Generate general hypotheses."


def parse_hypotheses_from_response(
    response_text: str,
) -> tuple[str, list[Hypothesis], str]:
    cleaned = response_text.strip()
    parsing_method = "failed"

    reasoning_trace = ""
    think_start = cleaned.find("<thinking>")
    think_end = cleaned.find("</thinking>")
    if think_start != -1 and think_end != -1:
        reasoning_trace = cleaned[think_start + len("<thinking>"):think_end].strip()

    hyp_start = cleaned.find("<hypotheses>")
    hyp_end = cleaned.find("</hypotheses>")
    if hyp_start != -1 and hyp_end != -1:
        json_str = cleaned[hyp_start + len("<hypotheses>"):hyp_end].strip()
        parsing_method = "xml_tags"
    else:
        start = cleaned.find("[")
        end = cleaned.rfind("]")
        if start == -1 or end == -1:
            single_start = cleaned.find("{")
            single_end = cleaned.rfind("}")
            if single_start != -1 and single_end != -1:
                json_str = "[" + cleaned[single_start : single_end + 1] + "]"
                parsing_method = "single_object_wrapped"
            else:
                return (reasoning_trace, [], parsing_method)
        else:
            if not reasoning_trace:
                reasoning_trace = cleaned[:start].strip()
            json_str = cleaned[start : end + 1]
            parsing_method = "bracket_json"

    try:
        raw_list = json.loads(json_str)
    except json.JSONDecodeError:
        parsing_method = "failed"
        return (reasoning_trace, [], parsing_method)

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
                insufficient_data=bool(item.get("insufficient_data", False)),
            )
            if hypothesis.condition and hypothesis.vulnerability_class:
                hypotheses.append(hypothesis)
        except (ValueError, TypeError):
            continue

    if parsing_method != "xml_tags" and hypotheses:
        warnings.warn(
            f"LLM response required {parsing_method} parsing fallback",
            RuntimeWarning,
            stacklevel=2,
        )

    return (reasoning_trace, hypotheses, parsing_method)


def _consistency_key(h: Hypothesis) -> tuple[str, str]:
    """Extract a matching key for self-consistency comparison.

    Matches hypotheses by vulnerability_class and the first path-like
    token in the condition (e.g., '/api/search' from 'IF endpoint /api/search ...').
    """
    endpoint = ""
    for token in h.condition.split():
        if token.startswith("/"):
            endpoint = token.rstrip(".,;:")
            break
    return (h.vulnerability_class, endpoint)


def _median(values: list[float]) -> float:
    """Return the median of a non-empty list of floats."""
    s = sorted(values)
    n = len(s)
    if n % 2 == 1:
        return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) / 2


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
        parsing_method = "structured"

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
            reasoning_trace, hypotheses, parsing_method = parse_hypotheses_from_response(raw_text)

        elapsed_ms = (time.monotonic() - start_time) * 1000
        hypotheses = hypotheses[:max_hypotheses]

        return GenerationResult(
            hypotheses=hypotheses,
            model_id=self._model_id,
            generation_time_ms=elapsed_ms,
            reasoning_trace=reasoning_trace,
            input_tokens=usage.input_tokens if usage is not None else 0,
            output_tokens=usage.output_tokens if usage is not None else 0,
            parsing_method=parsing_method,
            latency_ms=usage.latency_ms if usage is not None else 0.0,
        )

    def generate_with_consistency(
        self,
        context: ScanContext,
        max_hypotheses: int = 20,
        num_rounds: int = 3,
        agreement_threshold: int = 2,
    ) -> GenerationResult:
        """Generate hypotheses with self-consistency filtering.

        Runs N independent generation rounds and keeps only hypotheses that
        appear in at least `agreement_threshold` rounds (matched by
        vulnerability_class + endpoint substring in condition). This provides
        semantic entropy-based confidence without requiring logprobs.

        Opt-in via this method; the default `generate` method is unchanged.
        """
        all_results: list[GenerationResult] = []
        total_input_tokens = 0
        total_output_tokens = 0
        total_time_ms = 0.0

        for _ in range(num_rounds):
            result = self.generate(context, max_hypotheses=max_hypotheses)
            all_results.append(result)
            total_input_tokens += result.input_tokens
            total_output_tokens += result.output_tokens
            total_time_ms += result.generation_time_ms

        occurrence_counts: dict[tuple[str, str], int] = {}
        hypothesis_map: dict[tuple[str, str], Hypothesis] = {}
        confidence_scores: dict[tuple[str, str], list[float]] = {}

        for result in all_results:
            seen_this_round: set[tuple[str, str]] = set()
            for h in result.hypotheses:
                key = _consistency_key(h)
                if key not in seen_this_round:
                    seen_this_round.add(key)
                    occurrence_counts[key] = occurrence_counts.get(key, 0) + 1
                    confidence_scores.setdefault(key, []).append(h.confidence)
                    hypothesis_map[key] = h

        consistent = []
        for key, count in occurrence_counts.items():
            if count >= agreement_threshold:
                h = hypothesis_map[key].model_copy()
                h.confidence = _median(confidence_scores[key])
                consistent.append(h)
        consistent.sort(key=lambda h: h.confidence, reverse=True)

        # Combine reasoning traces
        traces = [r.reasoning_trace for r in all_results if r.reasoning_trace]
        combined_trace = "\n---\n".join(traces) if traces else ""

        return GenerationResult(
            hypotheses=consistent[:max_hypotheses],
            model_id=self._model_id,
            generation_time_ms=total_time_ms,
            reasoning_trace=combined_trace,
            input_tokens=total_input_tokens,
            output_tokens=total_output_tokens,
        )
