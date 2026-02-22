from __future__ import annotations

import json
from pathlib import Path

import pytest

from hypothesis_engine.generator import (
    SYSTEM_PROMPT,
    Hypothesis,
    ScanContext,
    build_user_prompt,
    parse_hypotheses_from_response,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text())


class TestSystemPromptStructure:
    def test_contains_xml_role_tag(self) -> None:
        assert "<role>" in SYSTEM_PROMPT
        assert "</role>" in SYSTEM_PROMPT

    def test_contains_valid_vulnerability_classes(self) -> None:
        assert "<valid_vulnerability_classes>" in SYSTEM_PROMPT
        assert "SQL Injection" in SYSTEM_PROMPT
        assert "Cross-Site Scripting" in SYSTEM_PROMPT
        assert "Command Injection" in SYSTEM_PROMPT

    def test_contains_confidence_rubric(self) -> None:
        assert "<confidence_rubric>" in SYSTEM_PROMPT
        assert "0.9-1.0" in SYSTEM_PROMPT
        assert "0.1-0.3" in SYSTEM_PROMPT

    def test_contains_examples(self) -> None:
        assert "<examples>" in SYSTEM_PROMPT
        assert "</examples>" in SYSTEM_PROMPT

    def test_contains_constraints(self) -> None:
        assert "<constraints>" in SYSTEM_PROMPT
        assert "</constraints>" in SYSTEM_PROMPT

    def test_contains_output_format(self) -> None:
        assert "<output_format>" in SYSTEM_PROMPT
        assert "<thinking>" in SYSTEM_PROMPT
        assert "<hypotheses>" in SYSTEM_PROMPT

    def test_all_16_vulnerability_classes_present(self) -> None:
        classes = [
            "SQL Injection", "Cross-Site Scripting", "Command Injection",
            "Path Traversal", "Server-Side Request Forgery", "Insecure Deserialization",
            "Broken Authentication", "Broken Authorization", "Security Misconfiguration",
            "Sensitive Data Exposure", "Server-Side Template Injection", "Header Injection",
            "Open Redirect", "CRLF Injection", "Known Vulnerable Dependency",
            "Insufficient Input Validation",
        ]
        for cls in classes:
            assert cls in SYSTEM_PROMPT, f"Missing vulnerability class: {cls}"


class TestUserPromptStructure:
    @pytest.mark.parametrize("fixture_name", ["express_app.json", "flask_app.json", "graphql_app.json"])
    def test_user_prompt_contains_xml_tags(self, fixture_name: str) -> None:
        fixture = load_fixture(fixture_name)
        ctx = ScanContext(**fixture["scan_context"])
        prompt = build_user_prompt(ctx)
        assert "<application_context>" in prompt
        assert "</application_context>" in prompt
        assert "<technology_stack>" in prompt

    @pytest.mark.parametrize("fixture_name", ["express_app.json", "flask_app.json", "graphql_app.json"])
    def test_user_prompt_contains_graph_topology(self, fixture_name: str) -> None:
        fixture = load_fixture(fixture_name)
        ctx = ScanContext(**fixture["scan_context"])
        prompt = build_user_prompt(ctx)
        assert "<graph_topology>" in prompt
        assert "<nodes>" in prompt
        assert "<edges>" in prompt

    @pytest.mark.parametrize("fixture_name", ["express_app.json", "flask_app.json", "graphql_app.json"])
    def test_user_prompt_contains_defense_posture(self, fixture_name: str) -> None:
        fixture = load_fixture(fixture_name)
        ctx = ScanContext(**fixture["scan_context"])
        prompt = build_user_prompt(ctx)
        assert "<defense_posture>" in prompt


class TestParsingRobustness:
    def test_parse_xml_tagged_response(self) -> None:
        response = (
            '<thinking>\nAnalyzing the application...\n</thinking>\n'
            '<hypotheses>\n'
            '[{"condition": "IF /api/search", "vulnerability_class": "SQL Injection", '
            '"reasoning": "test", "test_approach": "test", "confidence": 0.8}]\n'
            '</hypotheses>'
        )
        trace, hypotheses, _method = parse_hypotheses_from_response(response)
        assert trace == "Analyzing the application..."
        assert len(hypotheses) == 1
        assert hypotheses[0].vulnerability_class == "SQL Injection"

    def test_parse_fallback_bracket_response(self) -> None:
        response = (
            'Here is my analysis:\n\n'
            '[{"condition": "IF /api/test", "vulnerability_class": "XSS", '
            '"reasoning": "test", "test_approach": "test", "confidence": 0.5}]'
        )
        trace, hypotheses, _method = parse_hypotheses_from_response(response)
        assert len(hypotheses) == 1
        assert trace == "Here is my analysis:"

    def test_parse_empty_response(self) -> None:
        trace, hypotheses, _method = parse_hypotheses_from_response("")
        assert len(hypotheses) == 0

    def test_parse_malformed_json(self) -> None:
        response = '<hypotheses>\n{not valid json}\n</hypotheses>'
        trace, hypotheses, _method = parse_hypotheses_from_response(response)
        assert len(hypotheses) == 0

    def test_golden_hypotheses_round_trip(self) -> None:
        fixture = load_fixture("express_app.json")
        golden = fixture["golden_hypotheses"]
        json_str = json.dumps(golden)
        response = f"<thinking>\nGolden test\n</thinking>\n<hypotheses>\n{json_str}\n</hypotheses>"
        trace, hypotheses, _method = parse_hypotheses_from_response(response)
        assert len(hypotheses) == len(golden)
        for h, g in zip(hypotheses, golden):
            assert h.vulnerability_class == g["vulnerability_class"]
