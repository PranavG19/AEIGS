from __future__ import annotations

import json
import time
import warnings
from pathlib import Path

from pydantic import BaseModel, Field

from hypothesis_engine.bedrock_client import LlmBackend


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
    input_tokens: int = 0
    output_tokens: int = 0


SYSTEM_PROMPT = (
    "<role>\n"
    "You are a WAF bypass researcher specializing in web application firewall evasion.\n"
    "</role>\n\n"
    "<task>\n"
    "Generate payloads that bypass a specific defense mechanism.\n"
    "Given a blocked payload, the defense type, and previously failed attempts,\n"
    "generate alternative payloads using encoding tricks, structural transformations,\n"
    "and protocol-level bypasses.\n"
    "</task>\n\n"
    "<evasion_context>\n"
    "  <vulnerability_class>{vulnerability_class}</vulnerability_class>\n"
    "  <defense_type>{defense_type}</defense_type>\n"
    "  <defense_vendor>{defense_vendor}</defense_vendor>\n"
    "</evasion_context>\n\n"
    "{bypass_examples_section}"
    "<failed_attempts>\n"
    "{failed_attempts}\n"
    "</failed_attempts>\n\n"
    "<output_format>\n"
    "Return a JSON array of objects inside <evasion_payloads> tags with these fields:\n"
    '[{{"payload": "...", "strategy": "human-readable description", "confidence": 0.0-1.0}}]\n'
    "</output_format>\n\n"
    "<constraints>\n"
    "- Generate diverse evasion strategies — do not repeat the blocked payload or failed attempts.\n"
    "- Each payload must be syntactically valid for the vulnerability class.\n"
    "- Confidence should reflect the likelihood of bypassing this specific defense vendor.\n"
    "- Prefer encoding-based bypasses over structural changes when the defense is signature-based.\n"
    "</constraints>"
)


class EvasionHypothesisGenerator:
    def __init__(
        self,
        client: LlmBackend,
        model_id: str = "global.anthropic.claude-sonnet-4-6",
    ) -> None:
        self._client = client
        self._model_id = model_id
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
                "<bypass_examples>\n"
                + "\n".join(example_lines)
                + "\n</bypass_examples>\n\n"
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
        # ACCEPTED RISK: response_snippet contains raw target response content.
        # This is necessary for evasion mode to understand WAF blocking behavior.
        # A malicious server could embed prompt injection in responses.
        # Mitigated by: [:500] truncation, evasion mode being opt-in.
        user_message = (
            "<blocked_request>\n"
            f"  <payload>{context.blocked_payload}</payload>\n"
            f"  <response_code>{context.response_code}</response_code>\n"
            f"  <response_snippet>{context.response_snippet[:500]}</response_snippet>\n"
            "</blocked_request>\n\n"
            f"Generate up to {max_evasions} evasion payloads inside <evasion_payloads> tags."
        )

        start_time = time.monotonic()
        response_text, usage = self._client.invoke(
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
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
        )

    def _parse_evasions(
        self, response: str, max_evasions: int
    ) -> list[EvasionPayload]:
        cleaned = response.strip()

        # Try XML tag-based extraction first
        tag_start = cleaned.find("<evasion_payloads>")
        tag_end = cleaned.find("</evasion_payloads>")
        if tag_start != -1 and tag_end != -1:
            json_str = cleaned[tag_start + len("<evasion_payloads>"):tag_end].strip()
        else:
            # Fallback to bracket-based extraction
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
