from __future__ import annotations

import json
import time
import warnings
from pathlib import Path

from pydantic import BaseModel, Field

from hypothesis_engine.bedrock_client import BedrockClient


class EvasionContext(BaseModel):
    vulnerability_class: str
    blocked_payload: str
    defense_type: str
    defense_vendor: str
    response_code: int
    response_snippet: str
    previously_attempted_evasions: list[str] = Field(default_factory=list)


class EvasionPayload(BaseModel):
    payload: str
    strategy: str
    confidence: float = Field(ge=0.0, le=1.0)


class EvasionResult(BaseModel):
    evasions: list[EvasionPayload]
    model_id: str
    generation_time_ms: float


SYSTEM_PROMPT = (
    "You are a WAF bypass researcher specializing in web application firewall evasion. "
    "Your task is to generate payloads that bypass a specific defense mechanism. "
    "Given a blocked payload, the defense type, and previously failed attempts, "
    "generate alternative payloads using encoding tricks, structural transformations, "
    "and protocol-level bypasses.\n\n"
    "Vulnerability class: {vulnerability_class}\n"
    "Defense type: {defense_type} ({defense_vendor})\n\n"
    "{bypass_examples_section}"
    "Previously failed evasion attempts (DO NOT repeat these):\n{failed_attempts}\n\n"
    "Return a JSON array of objects with these exact fields:\n"
    '[{{"payload": "...", "strategy": "human-readable description", "confidence": 0.0-1.0}}]\n'
    "Generate diverse evasion strategies. Do not repeat the blocked payload or failed attempts."
)


class EvasionHypothesisGenerator(BedrockClient):
    def __init__(
        self,
        model_id: str = "global.anthropic.claude-sonnet-4-6",
        aws_profile: str = "ziya",
        max_retries: int = 3,
        timeout_seconds: int = 120,
    ) -> None:
        super().__init__(
            model_id=model_id,
            aws_profile=aws_profile,
            max_retries=max_retries,
            timeout_seconds=timeout_seconds,
        )
        self._bypass_examples = self._load_bypass_examples()

    def _load_bypass_examples(self) -> dict:
        import hypothesis_engine.evasion_mode as _self_module

        corpus_path = Path(_self_module.__file__).parent / "bypass_examples.json"
        if corpus_path.exists():
            return json.loads(corpus_path.read_text())
        warnings.warn(
            "bypass_examples.json not found — using generic payloads",
            RuntimeWarning,
            stacklevel=2,
        )
        return {}

    def _get_relevant_examples(self, vulnerability_class: str) -> list[dict]:
        normalized = vulnerability_class.lower().replace(" ", "_")
        for key in self._bypass_examples:
            if key == normalized or normalized.startswith(key):
                return self._bypass_examples[key]
        return []

    def _build_system_prompt(self, context: EvasionContext) -> str:
        examples = self._get_relevant_examples(context.vulnerability_class)
        if examples:
            example_lines = [
                f"  - {e['payload']} ({e['technique']})" for e in examples[:10]
            ]
            bypass_examples_section = (
                "Known bypass examples for reference:\n"
                + "\n".join(example_lines)
                + "\n\n"
            )
        else:
            bypass_examples_section = ""

        failed = "\n".join(
            f"  - {a}" for a in context.previously_attempted_evasions
        ) if context.previously_attempted_evasions else "  (none)"

        return SYSTEM_PROMPT.format(
            vulnerability_class=context.vulnerability_class,
            defense_type=context.defense_type,
            defense_vendor=context.defense_vendor,
            bypass_examples_section=bypass_examples_section,
            failed_attempts=failed,
        )

    def generate_evasions(
        self, context: EvasionContext, max_evasions: int = 10
    ) -> EvasionResult:
        system = self._build_system_prompt(context)
        user_message = (
            f"Blocked payload: {context.blocked_payload}\n"
            f"HTTP response code: {context.response_code}\n"
            f"Response snippet: {context.response_snippet[:500]}\n\n"
            f"Generate up to {max_evasions} evasion payloads."
        )

        start_time = time.monotonic()
        response_text, _usage = self.invoke(
            messages=[{"role": "user", "content": user_message}],
            system=system,
            max_tokens=4096,
        )
        elapsed_ms = (time.monotonic() - start_time) * 1000

        evasions = self._parse_evasions(response_text, max_evasions)

        return EvasionResult(
            evasions=evasions,
            model_id=self._model_id,
            generation_time_ms=elapsed_ms,
        )

    def _parse_evasions(
        self, response: str, max_evasions: int
    ) -> list[EvasionPayload]:
        cleaned = response.strip()

        start = cleaned.find("[")
        end = cleaned.rfind("]")
        if start == -1 or end == -1:
            return []

        json_str = cleaned[start : end + 1]

        try:
            raw_list = json.loads(json_str)
        except json.JSONDecodeError:
            return []

        evasions: list[EvasionPayload] = []
        for item in raw_list:
            if not isinstance(item, dict):
                continue
            try:
                evasion = EvasionPayload(
                    payload=item.get("payload", ""),
                    strategy=item.get("strategy", ""),
                    confidence=float(item.get("confidence", 0.5)),
                )
                if evasion.payload and evasion.strategy:
                    evasions.append(evasion)
            except (ValueError, TypeError):
                continue

        return evasions[:max_evasions]
