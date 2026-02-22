from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from hypothesis_engine.ipc_types import (
    CompiledPayloadsResponse,
    DefenseContextIpc,
    ErrorResponse,
    EvasionGenerateRequest,
    EvasionPayloadsResponse,
    GenerateHypothesesRequest,
    HypothesisIpc,
    HypothesesResponse,
    ReadyResponse,
    ScanContextIpc,
    ShutdownRequest,
    parse_bridge_request,
    parse_bridge_response,
)


class TestScanContextIpc:
    def test_roundtrip(self) -> None:
        ctx = ScanContextIpc(
            technology_stack=["express", "postgresql"],
            findings_summary=["SQLi in /login"],
            high_centrality_nodes=["/api/users"],
            defense_posture={"has_waf": True, "waf_vendor": "ModSecurity"},
            class_confirmation_rates={"SQL Injection": 0.75},
            model_id="claude-sonnet-4-6",
        )
        serialized = ctx.model_dump()
        roundtripped = ScanContextIpc.model_validate(serialized)
        assert roundtripped.technology_stack == ["express", "postgresql"]
        assert roundtripped.class_confirmation_rates["SQL Injection"] == 0.75
        assert roundtripped.model_id == "claude-sonnet-4-6"

    def test_json_roundtrip(self) -> None:
        ctx = ScanContextIpc(
            technology_stack=["flask"],
            findings_summary=[],
            high_centrality_nodes=[],
            defense_posture={},
        )
        json_str = ctx.model_dump_json()
        roundtripped = ScanContextIpc.model_validate_json(json_str)
        assert roundtripped.technology_stack == ["flask"]
        assert roundtripped.class_confirmation_rates == {}
        assert roundtripped.model_id is None

    def test_defaults_optional_fields(self) -> None:
        ctx = ScanContextIpc.model_validate({
            "technology_stack": [],
            "findings_summary": [],
            "high_centrality_nodes": [],
            "defense_posture": {},
        })
        assert ctx.class_confirmation_rates == {}
        assert ctx.model_id is None

    def test_cross_language_fixture(self) -> None:
        fixture = json.loads(SCAN_CONTEXT_FIXTURE)
        ctx = ScanContextIpc.model_validate(fixture)
        assert ctx.technology_stack == ["express", "postgresql"]
        assert ctx.class_confirmation_rates["SQL Injection"] == 0.75
        assert ctx.model_id == "claude-sonnet-4-6"


class TestHypothesisIpc:
    def test_roundtrip(self) -> None:
        h = HypothesisIpc(
            vulnerability_class="SqlInjection",
            description="blind sqli in /users",
            confidence=0.9,
            test_specification="' OR 1=1--",
        )
        serialized = h.model_dump()
        roundtripped = HypothesisIpc.model_validate(serialized)
        assert roundtripped.vulnerability_class == "SqlInjection"
        assert roundtripped.confidence == 0.9
        assert roundtripped.test_specification == "' OR 1=1--"

    def test_null_test_specification(self) -> None:
        h = HypothesisIpc.model_validate({
            "vulnerability_class": "XSS",
            "description": "reflected xss",
            "confidence": 0.7,
            "test_specification": None,
        })
        assert h.test_specification is None

    def test_missing_test_specification_defaults_none(self) -> None:
        h = HypothesisIpc.model_validate({
            "vulnerability_class": "XSS",
            "description": "reflected xss",
            "confidence": 0.7,
        })
        assert h.test_specification is None

    def test_rejects_missing_required_field(self) -> None:
        with pytest.raises(ValidationError):
            HypothesisIpc.model_validate({
                "vulnerability_class": "XSS",
                "confidence": 0.7,
            })


class TestDefenseContextIpc:
    def test_roundtrip(self) -> None:
        dc = DefenseContextIpc(
            has_waf=True,
            waf_vendor="ModSecurity",
            rate_limit_rps=10.0,
            bot_detection_present=False,
        )
        serialized = dc.model_dump()
        roundtripped = DefenseContextIpc.model_validate(serialized)
        assert roundtripped.has_waf is True
        assert roundtripped.waf_vendor == "ModSecurity"
        assert roundtripped.rate_limit_rps == 10.0
        assert roundtripped.bot_detection_present is False

    def test_optional_fields_default_none(self) -> None:
        dc = DefenseContextIpc.model_validate({
            "has_waf": False,
            "bot_detection_present": False,
        })
        assert dc.waf_vendor is None
        assert dc.rate_limit_rps is None


class TestBridgeRequest:
    def test_parse_generate_hypotheses(self) -> None:
        data = {
            "type": "GenerateHypotheses",
            "request_id": 1,
            "scan_context": {
                "technology_stack": ["express"],
                "findings_summary": [],
                "high_centrality_nodes": [],
                "defense_posture": {},
            },
            "vulnerability_class": "SqlInjection",
            "feedback_summary": "prior feedback",
        }
        req = parse_bridge_request(data)
        assert isinstance(req, GenerateHypothesesRequest)
        assert req.request_id == 1
        assert req.vulnerability_class == "SqlInjection"
        assert req.scan_context.technology_stack == ["express"]
        assert req.feedback_summary == "prior feedback"

    def test_parse_compile_payloads(self) -> None:
        data = {
            "type": "CompilePayloads",
            "request_id": 42,
            "hypotheses": [{
                "vulnerability_class": "XSS",
                "description": "reflected XSS",
                "confidence": 0.85,
                "test_specification": None,
            }],
        }
        req = parse_bridge_request(data)
        assert isinstance(req, GenerateHypothesesRequest) is False
        assert req.request_id == 42
        assert len(req.hypotheses) == 1

    def test_parse_evasion_generate(self) -> None:
        data = {
            "type": "EvasionGenerate",
            "request_id": 7,
            "defense_context": {
                "has_waf": True,
                "waf_vendor": "ModSecurity",
                "rate_limit_rps": 10.0,
                "bot_detection_present": False,
            },
        }
        req = parse_bridge_request(data)
        assert isinstance(req, EvasionGenerateRequest)
        assert req.defense_context.has_waf is True

    def test_parse_shutdown(self) -> None:
        req = parse_bridge_request({"type": "Shutdown"})
        assert isinstance(req, ShutdownRequest)

    def test_rejects_unknown_type(self) -> None:
        with pytest.raises(ValidationError):
            parse_bridge_request({"type": "UnknownType", "request_id": 1})

    def test_cross_language_fixture(self) -> None:
        fixture = json.loads(BRIDGE_REQUEST_FIXTURE)
        req = parse_bridge_request(fixture)
        assert isinstance(req, GenerateHypothesesRequest)
        assert req.vulnerability_class == "SqlInjection"


class TestBridgeResponse:
    def test_parse_ready(self) -> None:
        resp = parse_bridge_response({"type": "Ready"})
        assert isinstance(resp, ReadyResponse)

    def test_parse_hypotheses(self) -> None:
        data = {
            "type": "Hypotheses",
            "request_id": 1,
            "hypotheses": [{
                "vulnerability_class": "SqlInjection",
                "description": "blind sqli",
                "confidence": 0.9,
                "test_specification": None,
            }],
            "reasoning_trace": "analyzed endpoints",
            "input_tokens": 500,
            "output_tokens": 120,
        }
        resp = parse_bridge_response(data)
        assert isinstance(resp, HypothesesResponse)
        assert resp.request_id == 1
        assert len(resp.hypotheses) == 1
        assert resp.reasoning_trace == "analyzed endpoints"

    def test_parse_compiled_payloads(self) -> None:
        data = {
            "type": "CompiledPayloads",
            "request_id": 2,
            "payloads": ["payload1", "payload2"],
            "input_tokens": 200,
            "output_tokens": 80,
        }
        resp = parse_bridge_response(data)
        assert isinstance(resp, CompiledPayloadsResponse)
        assert resp.payloads == ["payload1", "payload2"]

    def test_parse_evasion_payloads(self) -> None:
        data = {
            "type": "EvasionPayloads",
            "request_id": 3,
            "payloads": ["evasion1"],
            "input_tokens": 300,
            "output_tokens": 60,
        }
        resp = parse_bridge_response(data)
        assert isinstance(resp, EvasionPayloadsResponse)
        assert resp.payloads == ["evasion1"]

    def test_parse_error(self) -> None:
        data = {
            "type": "Error",
            "request_id": 99,
            "message": "backend timeout",
        }
        resp = parse_bridge_response(data)
        assert isinstance(resp, ErrorResponse)
        assert resp.message == "backend timeout"

    def test_rejects_unknown_type(self) -> None:
        with pytest.raises(ValidationError):
            parse_bridge_response({"type": "Unknown", "request_id": 1})

    def test_cross_language_fixture(self) -> None:
        fixture = json.loads(BRIDGE_RESPONSE_FIXTURE)
        resp = parse_bridge_response(fixture)
        assert isinstance(resp, HypothesesResponse)
        assert resp.hypotheses[0].vulnerability_class == "SqlInjection"


class TestResponseConstruction:
    def test_ready_response_serializes(self) -> None:
        resp = ReadyResponse()
        data = resp.model_dump()
        assert data["type"] == "Ready"

    def test_hypotheses_response_serializes(self) -> None:
        resp = HypothesesResponse(
            request_id=1,
            hypotheses=[
                HypothesisIpc(
                    vulnerability_class="SqlInjection",
                    description="test",
                    confidence=0.9,
                )
            ],
            reasoning_trace="trace",
            input_tokens=100,
            output_tokens=50,
        )
        data = resp.model_dump()
        assert data["type"] == "Hypotheses"
        assert data["request_id"] == 1
        assert len(data["hypotheses"]) == 1

    def test_error_response_serializes(self) -> None:
        resp = ErrorResponse(request_id=1, message="failure")
        data = resp.model_dump()
        assert data["type"] == "Error"
        assert data["message"] == "failure"

    def test_compiled_payloads_response_serializes(self) -> None:
        resp = CompiledPayloadsResponse(
            request_id=2,
            payloads=["p1", "p2"],
            input_tokens=200,
            output_tokens=80,
        )
        data = resp.model_dump()
        assert data["type"] == "CompiledPayloads"
        assert data["payloads"] == ["p1", "p2"]


SCAN_CONTEXT_FIXTURE = """{
    "technology_stack": ["express", "postgresql"],
    "findings_summary": ["SQLi in /login"],
    "high_centrality_nodes": ["/api/users"],
    "defense_posture": {"has_waf": true, "waf_vendor": "ModSecurity"},
    "class_confirmation_rates": {"SQL Injection": 0.75},
    "model_id": "claude-sonnet-4-6"
}"""

BRIDGE_REQUEST_FIXTURE = """{
    "type": "GenerateHypotheses",
    "request_id": 1,
    "scan_context": {
        "technology_stack": ["express"],
        "findings_summary": [],
        "high_centrality_nodes": [],
        "defense_posture": {}
    },
    "vulnerability_class": "SqlInjection",
    "feedback_summary": null
}"""

BRIDGE_RESPONSE_FIXTURE = """{
    "type": "Hypotheses",
    "request_id": 1,
    "hypotheses": [{
        "vulnerability_class": "SqlInjection",
        "description": "blind sqli in /users",
        "confidence": 0.9,
        "test_specification": "' OR 1=1--"
    }],
    "reasoning_trace": "analyzed endpoints",
    "input_tokens": 500,
    "output_tokens": 120
}"""
