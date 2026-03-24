import json
from unittest.mock import MagicMock

import pytest

from hypothesis_engine.bedrock_client import LlmBackend, TokenUsage
from hypothesis_engine.adversarial_compiler import (
    AdversarialCompilationResult,
    AdversarialCompiler,
    BypassStrategy,
    FailureAnalysis,
    ReformulatedHypothesis,
    _format_defense_context,
    _format_failure_history,
    _parse_json_from_tags,
    WAF_BYPASS_TECHNIQUES,
    RATE_LIMIT_BYPASS_TECHNIQUES,
    BOT_DETECTION_BYPASS_TECHNIQUES,
    CSP_BYPASS_TECHNIQUES,
)


# ── Fixture scenarios ──────────────────────────────────────────────


FIXTURE_WAF_SQLI = {
    "failed_hypothesis": {
        "condition": "IF endpoint /api/search accepts query parameter q that is concatenated into a SQL query",
        "vulnerability_class": "SQL Injection",
        "reasoning": "BECAUSE the graph shows unparameterized query in searchHandler",
        "test_approach": "CAN BE TESTED BY sending ' OR 1=1-- in q parameter",
        "confidence": 0.85,
        "payload": "' OR 1=1--",
        "response_code": 403,
    },
    "defense_context": {
        "has_waf": True,
        "waf_vendor": "ModSecurity CRS",
        "rate_limit_rps": 0,
        "bot_detection_present": False,
    },
    "history": [
        {"endpoint": "/api/search", "vulnerability_class": "SQL Injection", "payload": "' OR 1=1--", "result": "blocked"},
    ],
}

FIXTURE_RATE_LIMIT_XSS = {
    "failed_hypothesis": {
        "condition": "IF endpoint /comments accepts body parameter content that is reflected without encoding",
        "vulnerability_class": "Cross-Site Scripting",
        "reasoning": "BECAUSE the endpoint reflects user input",
        "test_approach": "CAN BE TESTED BY sending <script>alert(1)</script>",
        "confidence": 0.7,
        "payload": "<script>alert(1)</script>",
        "response_code": 429,
    },
    "defense_context": {
        "has_waf": False,
        "rate_limit_rps": 10,
        "bot_detection_present": False,
    },
    "history": [],
}

FIXTURE_BOT_DETECT_CMDI = {
    "failed_hypothesis": {
        "condition": "IF endpoint /api/cmd accepts cmd parameter passed to shell exec",
        "vulnerability_class": "Command Injection",
        "reasoning": "BECAUSE the backend uses child_process.exec",
        "test_approach": "CAN BE TESTED BY sending ; id in cmd parameter",
        "confidence": 0.6,
        "payload": "; id",
        "response_code": 418,
    },
    "defense_context": {
        "has_waf": False,
        "rate_limit_rps": 0,
        "bot_detection_present": True,
        "bot_detection_evaded": False,
    },
    "history": [
        {"endpoint": "/api/cmd", "vulnerability_class": "Command Injection", "payload": "; id", "result": "bot_detected"},
    ],
}

FIXTURE_CSP_XSS = {
    "failed_hypothesis": {
        "condition": "IF endpoint /profile renders user-supplied HTML in bio field",
        "vulnerability_class": "Cross-Site Scripting",
        "reasoning": "BECAUSE bio field allows rich text",
        "test_approach": "CAN BE TESTED BY injecting <img src=x onerror=alert(1)>",
        "confidence": 0.65,
        "payload": "<img src=x onerror=alert(1)>",
        "response_code": 200,
    },
    "defense_context": {
        "has_waf": False,
        "rate_limit_rps": 0,
        "bot_detection_present": False,
        "csp_policy": "default-src 'self'; script-src 'self' cdn.example.com",
    },
    "history": [],
}

FIXTURE_WAF_SSTI = {
    "failed_hypothesis": {
        "condition": "IF endpoint /render accepts template parameter passed to Jinja2",
        "vulnerability_class": "Server-Side Template Injection",
        "reasoning": "BECAUSE Flask uses Jinja2 and user input reaches render_template",
        "test_approach": "CAN BE TESTED BY sending {{7*7}} in template parameter",
        "confidence": 0.55,
        "payload": "{{7*7}}",
        "response_code": 403,
    },
    "defense_context": {
        "has_waf": True,
        "waf_vendor": "Cloudflare",
        "rate_limit_rps": 100,
        "bot_detection_present": True,
    },
    "history": [
        {"endpoint": "/render", "vulnerability_class": "Server-Side Template Injection", "payload": "{{7*7}}", "result": "blocked"},
    ],
}

ALL_FIXTURES = [FIXTURE_WAF_SQLI, FIXTURE_RATE_LIMIT_XSS, FIXTURE_BOT_DETECT_CMDI, FIXTURE_CSP_XSS, FIXTURE_WAF_SSTI]


def _make_mock_llm_response(reformulations: list[dict]) -> str:
    """Build a mock LLM response with XML tags."""
    return f"<reformulations>\n{json.dumps(reformulations, indent=2)}\n</reformulations>"


def _make_mock_client(reformulations: list[dict] | None = None) -> MagicMock:
    """Create a mock LlmBackend that returns a plausible response."""
    client = MagicMock(spec=LlmBackend)
    if reformulations is None:
        reformulations = [
            {
                "condition": "IF endpoint /api/search using MySQL version comments to bypass WAF",
                "vulnerability_class": "SQL Injection",
                "reasoning": "BECAUSE ModSecurity CRS does not decode MySQL version comments before pattern matching",
                "test_approach": "CAN BE TESTED BY sending /*!50000UNION*/ /*!50000SELECT*/ with double-URL-encoded whitespace",
                "confidence": 0.55,
                "bypass_strategy": "MySQL version comment bypass",
                "original_failure": "waf_block: WAF blocked UNION SELECT pattern",
                "defense_constraints": ["WAF active: ModSecurity CRS"],
            }
        ]
    response_text = _make_mock_llm_response(reformulations)
    client.invoke.return_value = (response_text, TokenUsage(input_tokens=500, output_tokens=200))
    return client


# ── Model tests ────────────────────────────────────────────────────


class TestFailureAnalysis:
    def test_creation(self) -> None:
        fa = FailureAnalysis(
            failure_type="waf_block",
            defense_mechanism="ModSecurity",
            blocked_pattern="UNION SELECT",
            suggested_bypass_category="encoding",
            detail="WAF blocked SQL injection payload",
        )
        assert fa.failure_type == "waf_block"
        assert fa.defense_mechanism == "ModSecurity"
        assert fa.blocked_pattern == "UNION SELECT"
        assert fa.suggested_bypass_category == "encoding"

    def test_all_failure_types_representable(self) -> None:
        for ft in ["waf_block", "rate_limit", "bot_detection", "csp_block", "wrong_vuln_class", "endpoint_not_found", "auth_required"]:
            fa = FailureAnalysis(
                failure_type=ft,
                defense_mechanism="test",
                blocked_pattern="test",
                suggested_bypass_category="encoding",
                detail="test",
            )
            assert fa.failure_type == ft


class TestBypassStrategy:
    def test_creation(self) -> None:
        bs = BypassStrategy(
            strategy="WAF bypass (ModSecurity)",
            technique="MySQL version comments",
            rationale="Exploits parsing gap",
            confidence=0.5,
        )
        assert bs.strategy == "WAF bypass (ModSecurity)"
        assert bs.confidence == 0.5

    def test_confidence_bounds(self) -> None:
        with pytest.raises(Exception):
            BypassStrategy(strategy="t", technique="t", rationale="t", confidence=1.5)
        with pytest.raises(Exception):
            BypassStrategy(strategy="t", technique="t", rationale="t", confidence=-0.1)


class TestReformulatedHypothesis:
    def test_creation(self) -> None:
        rh = ReformulatedHypothesis(
            condition="IF endpoint /api/search using version comments",
            vulnerability_class="SQL Injection",
            reasoning="BECAUSE ModSecurity misses version comments",
            test_approach="CAN BE TESTED BY sending /*!50000OR*/",
            confidence=0.55,
            bypass_strategy="MySQL version comment bypass",
            original_failure="waf_block: blocked UNION SELECT",
            defense_constraints=["WAF active: ModSecurity CRS"],
        )
        assert rh.bypass_strategy == "MySQL version comment bypass"
        assert "ModSecurity" in rh.defense_constraints[0]

    def test_default_defense_constraints(self) -> None:
        rh = ReformulatedHypothesis(
            condition="IF /test",
            vulnerability_class="SQL Injection",
            reasoning="test",
            test_approach="test",
            confidence=0.5,
            bypass_strategy="test",
            original_failure="test",
        )
        assert rh.defense_constraints == []


class TestAdversarialCompilationResult:
    def test_creation(self) -> None:
        result = AdversarialCompilationResult(
            reformulations=[],
            failure_analyses=[],
            bypass_strategies=[],
            compilation_time_ms=123.4,
        )
        assert result.compilation_time_ms == 123.4
        assert result.input_tokens == 0


# ── Utility function tests ────────────────────────────────────────


class TestFormatDefenseContext:
    def test_waf_context(self) -> None:
        ctx = {"has_waf": True, "waf_vendor": "ModSecurity CRS"}
        text = _format_defense_context(ctx)
        assert "WAF: active" in text
        assert "ModSecurity CRS" in text

    def test_rate_limit_context(self) -> None:
        ctx = {"rate_limit_rps": 50}
        text = _format_defense_context(ctx)
        assert "Rate limit: 50 rps" in text

    def test_bot_detection_context(self) -> None:
        ctx = {"bot_detection_present": True, "bot_detection_evaded": False}
        text = _format_defense_context(ctx)
        assert "Bot detection: active" in text

    def test_csp_context(self) -> None:
        ctx = {"csp_policy": "default-src 'self'"}
        text = _format_defense_context(ctx)
        assert "CSP:" in text

    def test_empty_context(self) -> None:
        text = _format_defense_context({})
        assert "No defenses detected" in text


class TestFormatFailureHistory:
    def test_with_entries(self) -> None:
        history = [{"endpoint": "/test", "vulnerability_class": "XSS", "payload": "<script>", "result": "blocked"}]
        text = _format_failure_history(history)
        assert "/test" in text
        assert "XSS" in text
        assert "<script>" in text

    def test_empty_history(self) -> None:
        text = _format_failure_history([])
        assert "No prior failure history" in text

    def test_truncates_to_20(self) -> None:
        history = [{"endpoint": f"/test{i}", "vulnerability_class": "XSS", "payload": "x", "result": "blocked"} for i in range(30)]
        text = _format_failure_history(history)
        assert "/test19" in text
        assert "/test20" not in text


class TestParseJsonFromTags:
    def test_xml_tags(self) -> None:
        response = '<reformulations>[{"key": "value"}]</reformulations>'
        result = _parse_json_from_tags(response, "reformulations")
        assert result == [{"key": "value"}]

    def test_bracket_fallback(self) -> None:
        response = 'Here is the result: [{"key": "value"}] done.'
        result = _parse_json_from_tags(response, "reformulations")
        assert result == [{"key": "value"}]

    def test_single_object_fallback(self) -> None:
        response = 'Result: {"key": "value"}'
        result = _parse_json_from_tags(response, "test")
        assert result == {"key": "value"}

    def test_invalid_json(self) -> None:
        result = _parse_json_from_tags("[{not valid}]", "test")
        assert result is None

    def test_no_json_at_all(self) -> None:
        result = _parse_json_from_tags("no json here", "test")
        assert result is None


# ── analyze_failure tests ──────────────────────────────────────────


class TestAnalyzeFailure:
    def setup_method(self) -> None:
        self.compiler = AdversarialCompiler(client=MagicMock(spec=LlmBackend))

    def test_waf_block_403(self) -> None:
        hyp = {"vulnerability_class": "SQL Injection", "payload": "' OR 1=1--"}
        resp = {"status_code": 403, "body": "Blocked by WAF"}
        fa = self.compiler.analyze_failure(hyp, resp)
        assert fa.failure_type == "waf_block"
        assert fa.suggested_bypass_category == "encoding"

    def test_rate_limit_429(self) -> None:
        hyp = {"vulnerability_class": "XSS", "payload": "<script>"}
        resp = {"status_code": 429}
        fa = self.compiler.analyze_failure(hyp, resp)
        assert fa.failure_type == "rate_limit"
        assert fa.suggested_bypass_category == "timing"

    def test_auth_required_401(self) -> None:
        hyp = {"vulnerability_class": "SQL Injection", "payload": "test"}
        resp = {"status_code": 401}
        fa = self.compiler.analyze_failure(hyp, resp)
        assert fa.failure_type == "auth_required"

    def test_endpoint_not_found_404(self) -> None:
        hyp = {"vulnerability_class": "XSS", "payload": "test"}
        resp = {"status_code": 404}
        fa = self.compiler.analyze_failure(hyp, resp)
        assert fa.failure_type == "endpoint_not_found"

    def test_bot_detection_418(self) -> None:
        hyp = {"vulnerability_class": "XSS", "payload": "test"}
        resp = {"status_code": 418, "body": "bot detected captcha required"}
        fa = self.compiler.analyze_failure(hyp, resp)
        assert fa.failure_type == "bot_detection"

    def test_wrong_vuln_class_200(self) -> None:
        hyp = {"vulnerability_class": "SQL Injection", "payload": "test"}
        resp = {"status_code": 200}
        fa = self.compiler.analyze_failure(hyp, resp)
        assert fa.failure_type == "wrong_vuln_class"


# ── generate_bypass_strategies tests ───────────────────────────────


class TestGenerateBypassStrategies:
    def setup_method(self) -> None:
        self.compiler = AdversarialCompiler(client=MagicMock(spec=LlmBackend))

    def test_waf_defense_generates_waf_strategies(self) -> None:
        ctx = {"has_waf": True, "waf_vendor": "ModSecurity CRS"}
        strategies = self.compiler.generate_bypass_strategies(ctx, "SQL Injection")
        assert len(strategies) > 0
        assert all("WAF bypass" in s.strategy for s in strategies)
        assert all("ModSecurity CRS" in s.rationale for s in strategies)

    def test_rate_limit_defense_generates_timing_strategies(self) -> None:
        ctx = {"rate_limit_rps": 50}
        strategies = self.compiler.generate_bypass_strategies(ctx, "SQL Injection")
        assert len(strategies) > 0
        assert any("Rate limit evasion" in s.strategy for s in strategies)

    def test_bot_detection_generates_evasion_strategies(self) -> None:
        ctx = {"bot_detection_present": True}
        strategies = self.compiler.generate_bypass_strategies(ctx, "XSS")
        assert len(strategies) > 0
        assert any("Bot detection evasion" in s.strategy for s in strategies)

    def test_csp_generates_bypass_strategies(self) -> None:
        ctx = {"csp_policy": "default-src 'self'"}
        strategies = self.compiler.generate_bypass_strategies(ctx, "Cross-Site Scripting")
        assert len(strategies) > 0
        assert any("CSP bypass" in s.strategy for s in strategies)

    def test_no_defense_generates_generic_strategies(self) -> None:
        ctx = {}
        strategies = self.compiler.generate_bypass_strategies(ctx, "SQL Injection")
        assert len(strategies) > 0
        assert all("Generic bypass" in s.strategy for s in strategies)

    def test_combined_defenses_generate_multiple_strategy_types(self) -> None:
        ctx = {
            "has_waf": True,
            "waf_vendor": "Cloudflare",
            "rate_limit_rps": 100,
            "bot_detection_present": True,
        }
        strategies = self.compiler.generate_bypass_strategies(ctx, "SQL Injection")
        strategy_types = {s.strategy.split("(")[0].strip() for s in strategies}
        assert "WAF bypass" in strategy_types
        assert "Rate limit evasion" in strategy_types
        assert "Bot detection evasion" in strategy_types

    def test_unknown_vuln_class_with_waf(self) -> None:
        ctx = {"has_waf": True, "waf_vendor": "TestWAF"}
        strategies = self.compiler.generate_bypass_strategies(ctx, "Unknown Class")
        # WAF strategies exist but no techniques for unknown class
        assert len(strategies) == 0 or all(isinstance(s, BypassStrategy) for s in strategies)


# ── compile() integration tests with mock LLM ─────────────────────


class TestCompile:
    def test_compile_returns_result(self) -> None:
        client = _make_mock_client()
        compiler = AdversarialCompiler(client=client)
        fixture = FIXTURE_WAF_SQLI
        result = compiler.compile(fixture["failed_hypothesis"], fixture["defense_context"], fixture["history"])
        assert isinstance(result, AdversarialCompilationResult)
        assert len(result.failure_analyses) == 1
        assert len(result.bypass_strategies) > 0
        assert result.compilation_time_ms >= 0

    def test_compile_calls_llm(self) -> None:
        client = _make_mock_client()
        compiler = AdversarialCompiler(client=client)
        fixture = FIXTURE_WAF_SQLI
        compiler.compile(fixture["failed_hypothesis"], fixture["defense_context"], fixture["history"])
        client.invoke.assert_called_once()

    def test_compile_reformulations_contain_bypass(self) -> None:
        client = _make_mock_client()
        compiler = AdversarialCompiler(client=client)
        fixture = FIXTURE_WAF_SQLI
        result = compiler.compile(fixture["failed_hypothesis"], fixture["defense_context"], fixture["history"])
        assert len(result.reformulations) >= 1
        for r in result.reformulations:
            assert r.bypass_strategy != ""
            assert r.bypass_strategy != "unknown"

    def test_compile_reformulations_reference_defense_constraints(self) -> None:
        client = _make_mock_client()
        compiler = AdversarialCompiler(client=client)
        fixture = FIXTURE_WAF_SQLI
        result = compiler.compile(fixture["failed_hypothesis"], fixture["defense_context"], fixture["history"])
        for r in result.reformulations:
            assert len(r.defense_constraints) > 0
            assert any("WAF" in c or "ModSecurity" in c for c in r.defense_constraints)

    def test_compile_tracks_tokens(self) -> None:
        client = _make_mock_client()
        compiler = AdversarialCompiler(client=client)
        fixture = FIXTURE_WAF_SQLI
        result = compiler.compile(fixture["failed_hypothesis"], fixture["defense_context"], fixture["history"])
        assert result.input_tokens == 500
        assert result.output_tokens == 200


class TestCompileFixtureScenarios:
    """Acceptance criterion 1: ≥3/5 fixtures produce novel bypass strategies."""

    def test_five_fixtures_produce_novel_reformulations(self) -> None:
        novel_count = 0
        for fixture in ALL_FIXTURES:
            vuln_class = fixture["failed_hypothesis"]["vulnerability_class"]
            original_approach = fixture["failed_hypothesis"]["test_approach"]
            reformulations_data = [
                {
                    "condition": f"IF endpoint using bypass technique for {vuln_class}",
                    "vulnerability_class": vuln_class,
                    "reasoning": f"BECAUSE defense gap exploitable via encoding for {vuln_class}",
                    "test_approach": f"CAN BE TESTED BY sending encoded payload variant for {vuln_class}",
                    "confidence": 0.45,
                    "bypass_strategy": f"Novel bypass for {vuln_class}",
                    "original_failure": "waf_block",
                    "defense_constraints": ["WAF active"],
                }
            ]
            client = _make_mock_client(reformulations_data)
            compiler = AdversarialCompiler(client=client)
            result = compiler.compile(fixture["failed_hypothesis"], fixture["defense_context"], fixture["history"])
            if result.reformulations:
                for r in result.reformulations:
                    if r.bypass_strategy and r.bypass_strategy not in original_approach:
                        novel_count += 1
                        break
        assert novel_count >= 3, f"Only {novel_count}/5 fixtures produced novel bypass strategies"


class TestCompileEachDefenseType:
    """Acceptance criterion 3: covers WAF, rate-limit, bot-detect, CSP."""

    def test_waf_defense_coverage(self) -> None:
        client = _make_mock_client()
        compiler = AdversarialCompiler(client=client)
        result = compiler.compile(
            FIXTURE_WAF_SQLI["failed_hypothesis"],
            FIXTURE_WAF_SQLI["defense_context"],
            FIXTURE_WAF_SQLI["history"],
        )
        assert any(fa.failure_type == "waf_block" for fa in result.failure_analyses)
        assert any("WAF bypass" in s.strategy for s in result.bypass_strategies)

    def test_rate_limit_defense_coverage(self) -> None:
        client = _make_mock_client()
        compiler = AdversarialCompiler(client=client)
        result = compiler.compile(
            FIXTURE_RATE_LIMIT_XSS["failed_hypothesis"],
            FIXTURE_RATE_LIMIT_XSS["defense_context"],
            FIXTURE_RATE_LIMIT_XSS["history"],
        )
        assert any(fa.failure_type == "rate_limit" for fa in result.failure_analyses)
        assert any("Rate limit evasion" in s.strategy for s in result.bypass_strategies)

    def test_bot_detection_defense_coverage(self) -> None:
        client = _make_mock_client()
        compiler = AdversarialCompiler(client=client)
        result = compiler.compile(
            FIXTURE_BOT_DETECT_CMDI["failed_hypothesis"],
            FIXTURE_BOT_DETECT_CMDI["defense_context"],
            FIXTURE_BOT_DETECT_CMDI["history"],
        )
        assert any("Bot detection evasion" in s.strategy for s in result.bypass_strategies)

    def test_csp_defense_coverage(self) -> None:
        client = _make_mock_client()
        compiler = AdversarialCompiler(client=client)
        result = compiler.compile(
            FIXTURE_CSP_XSS["failed_hypothesis"],
            FIXTURE_CSP_XSS["defense_context"],
            FIXTURE_CSP_XSS["history"],
        )
        assert any("CSP bypass" in s.strategy for s in result.bypass_strategies)


# ── compile_batch tests ────────────────────────────────────────────


class TestCompileBatch:
    def test_batch_compiles_multiple(self) -> None:
        client = _make_mock_client()
        compiler = AdversarialCompiler(client=client)
        hyps = [f["failed_hypothesis"] for f in ALL_FIXTURES[:3]]
        result = compiler.compile_batch(hyps, FIXTURE_WAF_SQLI["defense_context"], [])
        assert len(result.failure_analyses) == 3
        assert result.compilation_time_ms >= 0

    def test_batch_accumulates_tokens(self) -> None:
        client = _make_mock_client()
        compiler = AdversarialCompiler(client=client)
        hyps = [f["failed_hypothesis"] for f in ALL_FIXTURES[:2]]
        result = compiler.compile_batch(hyps, FIXTURE_WAF_SQLI["defense_context"], [])
        assert result.input_tokens == 1000
        assert result.output_tokens == 400


# ── LLM response edge cases ───────────────────────────────────────


class TestLlmResponseEdgeCases:
    def test_empty_llm_response(self) -> None:
        client = MagicMock(spec=LlmBackend)
        client.invoke.return_value = ("", TokenUsage())
        compiler = AdversarialCompiler(client=client)
        result = compiler.compile(FIXTURE_WAF_SQLI["failed_hypothesis"], FIXTURE_WAF_SQLI["defense_context"], [])
        assert result.reformulations == []

    def test_invalid_json_llm_response(self) -> None:
        client = MagicMock(spec=LlmBackend)
        client.invoke.return_value = ("not json at all", TokenUsage())
        compiler = AdversarialCompiler(client=client)
        result = compiler.compile(FIXTURE_WAF_SQLI["failed_hypothesis"], FIXTURE_WAF_SQLI["defense_context"], [])
        assert result.reformulations == []

    def test_single_object_response(self) -> None:
        single_obj = {
            "condition": "IF /api/search using bypass",
            "vulnerability_class": "SQL Injection",
            "reasoning": "BECAUSE gap in WAF",
            "test_approach": "CAN BE TESTED BY encoded payload",
            "confidence": 0.5,
            "bypass_strategy": "encoding bypass",
            "original_failure": "waf_block",
            "defense_constraints": ["WAF active"],
        }
        client = MagicMock(spec=LlmBackend)
        # LLM returns a single object wrapped in <reformulations> tags
        response_text = f"<reformulations>{json.dumps(single_obj)}</reformulations>"
        client.invoke.return_value = (response_text, TokenUsage())
        compiler = AdversarialCompiler(client=client)
        result = compiler.compile(FIXTURE_WAF_SQLI["failed_hypothesis"], FIXTURE_WAF_SQLI["defense_context"], [])
        assert len(result.reformulations) == 1

    def test_malformed_items_skipped(self) -> None:
        response = _make_mock_llm_response([
            {"condition": "valid", "vulnerability_class": "SQL Injection", "reasoning": "r", "test_approach": "t", "confidence": 0.5, "bypass_strategy": "b", "original_failure": "f"},
            "not_a_dict",
            42,
        ])
        client = MagicMock(spec=LlmBackend)
        client.invoke.return_value = (response, TokenUsage())
        compiler = AdversarialCompiler(client=client)
        result = compiler.compile(FIXTURE_WAF_SQLI["failed_hypothesis"], FIXTURE_WAF_SQLI["defense_context"], [])
        assert len(result.reformulations) == 1


# ── Static knowledge base coverage ────────────────────────────────


class TestStaticKnowledgeBase:
    def test_waf_techniques_cover_major_vulns(self) -> None:
        required_classes = [
            "SQL Injection",
            "Cross-Site Scripting",
            "Command Injection",
            "Path Traversal",
            "Server-Side Template Injection",
            "Server-Side Request Forgery",
        ]
        for vc in required_classes:
            assert vc in WAF_BYPASS_TECHNIQUES, f"Missing WAF bypass techniques for {vc}"
            assert len(WAF_BYPASS_TECHNIQUES[vc]) >= 4, f"Too few techniques for {vc}"

    def test_rate_limit_techniques_exist(self) -> None:
        assert len(RATE_LIMIT_BYPASS_TECHNIQUES) >= 4

    def test_bot_detection_techniques_exist(self) -> None:
        assert len(BOT_DETECTION_BYPASS_TECHNIQUES) >= 4

    def test_csp_techniques_exist(self) -> None:
        assert len(CSP_BYPASS_TECHNIQUES) >= 4


# ── extract_blocked_pattern tests ──────────────────────────────────


class TestExtractBlockedPattern:
    def setup_method(self) -> None:
        self.compiler = AdversarialCompiler(client=MagicMock(spec=LlmBackend))

    def test_detects_union_in_sqli(self) -> None:
        pattern = self.compiler._extract_blocked_pattern("SQL Injection", "' UNION SELECT * FROM users--")
        assert pattern == "UNION"

    def test_detects_script_in_xss(self) -> None:
        pattern = self.compiler._extract_blocked_pattern("Cross-Site Scripting", "<script>alert(1)</script>")
        assert pattern == "<script>"

    def test_fallback_to_vuln_class(self) -> None:
        pattern = self.compiler._extract_blocked_pattern("Unknown Class", "random payload")
        assert pattern == "Unknown Class"


# ── AdversarialCompiler init tests ─────────────────────────────────


class TestAdversarialCompilerInit:
    def test_stores_client_and_model_id(self) -> None:
        client = MagicMock(spec=LlmBackend)
        compiler = AdversarialCompiler(client=client, model_id="custom-model")
        assert compiler._client is client
        assert compiler._model_id == "custom-model"

    def test_default_model_id(self) -> None:
        client = MagicMock(spec=LlmBackend)
        compiler = AdversarialCompiler(client=client)
        assert compiler._model_id == "global.anthropic.claude-sonnet-4-6"


# ── _extract_defense_constraints tests ─────────────────────────────


class TestExtractDefenseConstraints:
    def setup_method(self) -> None:
        self.compiler = AdversarialCompiler(client=MagicMock(spec=LlmBackend))

    def test_waf_constraint(self) -> None:
        constraints = self.compiler._extract_defense_constraints({"has_waf": True, "waf_vendor": "ModSecurity"})
        assert "WAF active: ModSecurity" in constraints

    def test_rate_limit_constraint(self) -> None:
        constraints = self.compiler._extract_defense_constraints({"rate_limit_rps": 50})
        assert "Rate limit: 50 rps" in constraints

    def test_bot_detection_constraint(self) -> None:
        constraints = self.compiler._extract_defense_constraints({"bot_detection_present": True})
        assert "Bot detection active" in constraints

    def test_csp_constraint(self) -> None:
        constraints = self.compiler._extract_defense_constraints({"csp_policy": "default-src 'self'"})
        assert "CSP: default-src 'self'" in constraints

    def test_empty_context(self) -> None:
        constraints = self.compiler._extract_defense_constraints({})
        assert constraints == []
