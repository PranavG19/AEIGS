from hypothesis_engine.generator import (
    Hypothesis,
    ScanContext,
    build_user_prompt,
    parse_hypotheses_from_response,
)


class TestScanContext:
    def test_empty_context_has_defaults(self) -> None:
        ctx = ScanContext()
        assert ctx.technology_stack == []
        assert ctx.high_centrality_nodes == []
        assert ctx.findings_summary == []

    def test_context_with_stack(self) -> None:
        ctx = ScanContext(technology_stack=["Express", "PostgreSQL"])
        assert len(ctx.technology_stack) == 2


class TestBuildUserPrompt:
    def test_empty_context_returns_fallback(self) -> None:
        ctx = ScanContext()
        prompt = build_user_prompt(ctx)
        assert "No context available" in prompt

    def test_tech_stack_included(self) -> None:
        ctx = ScanContext(technology_stack=["Django", "MySQL"])
        prompt = build_user_prompt(ctx)
        assert "Django" in prompt
        assert "MySQL" in prompt

    def test_findings_included(self) -> None:
        ctx = ScanContext(findings_summary=["SQLi in /login", "XSS in /search"])
        prompt = build_user_prompt(ctx)
        assert "SQLi in /login" in prompt

    def test_high_risk_functions_included(self) -> None:
        ctx = ScanContext(
            high_risk_functions=[{"name": "query_user", "file": "db.py"}]
        )
        prompt = build_user_prompt(ctx)
        assert "query_user" in prompt

    def test_auth_matrix_included(self) -> None:
        ctx = ScanContext(authorization_matrix_summary="GET /admin: user=403, admin=200")
        prompt = build_user_prompt(ctx)
        assert "/admin" in prompt

    def test_vulnerable_deps_included(self) -> None:
        ctx = ScanContext(known_vulnerable_dependencies=["lodash@4.17.20 (CVE-2021-23337)"])
        prompt = build_user_prompt(ctx)
        assert "lodash" in prompt

    def test_centrality_nodes_included(self) -> None:
        ctx = ScanContext(
            high_centrality_nodes=[{"label": "auth_endpoint", "type": "Endpoint"}]
        )
        prompt = build_user_prompt(ctx)
        assert "auth_endpoint" in prompt


class TestParseHypotheses:
    def test_parse_valid_json_array(self) -> None:
        response = """Here are the hypotheses:
[
  {
    "condition": "IF login uses string concat",
    "vulnerability_class": "SQL Injection",
    "reasoning": "BECAUSE no parameterized queries",
    "test_approach": "CAN BE TESTED BY sending payloads",
    "confidence": 0.8
  }
]"""
        results = parse_hypotheses_from_response(response)
        assert len(results) == 1
        assert results[0].vulnerability_class == "SQL Injection"
        assert results[0].confidence == 0.8

    def test_parse_multiple_hypotheses(self) -> None:
        response = """[
  {"condition": "IF a", "vulnerability_class": "XSS", "reasoning": "r", "test_approach": "t", "confidence": 0.7},
  {"condition": "IF b", "vulnerability_class": "SQLi", "reasoning": "r", "test_approach": "t", "confidence": 0.6}
]"""
        results = parse_hypotheses_from_response(response)
        assert len(results) == 2

    def test_parse_empty_response(self) -> None:
        results = parse_hypotheses_from_response("")
        assert results == []

    def test_parse_invalid_json(self) -> None:
        results = parse_hypotheses_from_response("not json at all")
        assert results == []

    def test_parse_skips_invalid_items(self) -> None:
        response = '[{"condition": "IF x", "vulnerability_class": "XSS", "reasoning": "r", "test_approach": "t", "confidence": 0.5}, "not_an_object"]'
        results = parse_hypotheses_from_response(response)
        assert len(results) == 1

    def test_parse_skips_empty_condition(self) -> None:
        response = '[{"condition": "", "vulnerability_class": "XSS", "reasoning": "r", "test_approach": "t", "confidence": 0.5}]'
        results = parse_hypotheses_from_response(response)
        assert len(results) == 0

    def test_parse_default_confidence(self) -> None:
        response = '[{"condition": "IF x", "vulnerability_class": "XSS", "reasoning": "r", "test_approach": "t"}]'
        results = parse_hypotheses_from_response(response)
        assert len(results) == 1
        assert results[0].confidence == 0.5

    def test_parse_with_surrounding_text(self) -> None:
        response = 'Here are my findings:\n[{"condition": "IF x", "vulnerability_class": "XSS", "reasoning": "r", "test_approach": "t", "confidence": 0.9}]\nEnd of analysis.'
        results = parse_hypotheses_from_response(response)
        assert len(results) == 1


class TestHypothesisModel:
    def test_hypothesis_creation(self) -> None:
        h = Hypothesis(
            condition="IF login endpoint",
            vulnerability_class="SQL Injection",
            reasoning="no parameterized queries",
            test_approach="send payloads",
            confidence=0.8,
        )
        assert h.condition == "IF login endpoint"
        assert h.confidence == 0.8

    def test_confidence_bounds(self) -> None:
        import pytest

        with pytest.raises(Exception):
            Hypothesis(
                condition="x",
                vulnerability_class="y",
                reasoning="r",
                test_approach="t",
                confidence=1.5,
            )

    def test_confidence_lower_bound(self) -> None:
        import pytest

        with pytest.raises(Exception):
            Hypothesis(
                condition="x",
                vulnerability_class="y",
                reasoning="r",
                test_approach="t",
                confidence=-0.1,
            )
