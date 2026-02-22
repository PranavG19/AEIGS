from __future__ import annotations

import json
import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from hypothesis_engine.bedrock_client import LlmBackend, TokenUsage
from hypothesis_engine.bridge import (
    Bridge,
    _build_evasion_context,
    _build_hypotheses,
    _build_scan_context,
    _hypothesis_to_ipc,
    main,
    read_frame,
    send_frame,
)
from hypothesis_engine.compiler import CompilationResult, TestSpecification
from hypothesis_engine.evasion_mode import EvasionPayload, EvasionResult
from hypothesis_engine.generator import (
    GenerationResult,
    Hypothesis,
    ScanContext,
)
from hypothesis_engine.ipc_types import (
    CompilePayloadsRequest,
    DefenseContextIpc,
    EvasionGenerateRequest,
    GenerateHypothesesRequest,
    HypothesisIpc,
    ScanContextIpc,
)


def _make_frame(data: dict) -> bytes:
    payload = json.dumps(data).encode("utf-8")
    return struct.pack("<I", len(payload)) + payload


class FakeSocket:
    """In-memory socket substitute for testing framing functions."""

    def __init__(self, data: bytes = b"") -> None:
        self._recv_buf = bytearray(data)
        self._send_buf = bytearray()

    def recv(self, n: int) -> bytes:
        chunk = bytes(self._recv_buf[:n])
        self._recv_buf = self._recv_buf[n:]
        return chunk

    def sendall(self, data: bytes) -> None:
        self._send_buf.extend(data)

    def sent_data(self) -> bytes:
        return bytes(self._send_buf)


class TestReadFrame:
    def test_parses_length_prefixed_json(self) -> None:
        msg = {"type": "Ready"}
        raw = _make_frame(msg)
        sock = FakeSocket(raw)
        result = read_frame(sock)
        assert result == msg

    def test_handles_empty_payload(self) -> None:
        sock = FakeSocket(struct.pack("<I", 0))
        result = read_frame(sock)
        assert result == {}

    def test_rejects_oversized_frame(self) -> None:
        sock = FakeSocket(struct.pack("<I", 128 * 1024 * 1024))
        with pytest.raises(ValueError, match="exceeds maximum"):
            read_frame(sock)

    def test_connection_closed_during_length(self) -> None:
        sock = FakeSocket(b"\x04\x00")
        with pytest.raises(ConnectionError, match="connection closed"):
            read_frame(sock)

    def test_connection_closed_during_payload(self) -> None:
        length = struct.pack("<I", 100)
        sock = FakeSocket(length + b"short")
        with pytest.raises(ConnectionError, match="connection closed"):
            read_frame(sock)


class TestSendFrame:
    def test_writes_length_prefixed_json(self) -> None:
        msg = {"type": "Ready"}
        sock = FakeSocket()
        send_frame(sock, msg)
        raw = sock.sent_data()
        length = struct.unpack("<I", raw[:4])[0]
        payload = json.loads(raw[4 : 4 + length])
        assert payload == msg

    def test_roundtrip(self) -> None:
        msg = {"type": "Hypotheses", "request_id": 42, "data": [1, 2, 3]}
        sock = FakeSocket()
        send_frame(sock, msg)
        read_sock = FakeSocket(sock.sent_data())
        result = read_frame(read_sock)
        assert result == msg


def _make_generate_request(
    scan_context: ScanContextIpc | None = None,
    feedback_summary: str | None = None,
) -> GenerateHypothesesRequest:
    sc = scan_context or ScanContextIpc(
        technology_stack=[],
        findings_summary=[],
        high_centrality_nodes=[],
        defense_posture={},
    )
    return GenerateHypothesesRequest(
        type="GenerateHypotheses",
        request_id=1,
        scan_context=sc,
        vulnerability_class="SqlInjection",
        feedback_summary=feedback_summary,
    )


class TestBuildScanContext:
    def test_maps_ipc_fields_to_scan_context(self) -> None:
        req = _make_generate_request(
            scan_context=ScanContextIpc(
                technology_stack=["Express", "PostgreSQL"],
                findings_summary=["SQLi in /login"],
                high_centrality_nodes=["auth_endpoint"],
                defense_posture={"has_waf": True},
            ),
            feedback_summary="round 1 results",
        )
        ctx = _build_scan_context(req)
        assert ctx.technology_stack == ["Express", "PostgreSQL"]
        assert ctx.findings_summary == ["SQLi in /login"]
        assert ctx.high_centrality_nodes == [{"label": "auth_endpoint"}]
        assert ctx.defense_posture == {"has_waf": True}
        assert ctx.feedback_summary == "round 1 results"

    def test_empty_request_uses_defaults(self) -> None:
        req = _make_generate_request()
        ctx = _build_scan_context(req)
        assert ctx.technology_stack == []
        assert ctx.feedback_summary == ""

    def test_null_feedback_becomes_empty_string(self) -> None:
        req = _make_generate_request(feedback_summary=None)
        ctx = _build_scan_context(req)
        assert ctx.feedback_summary == ""


class TestBuildHypotheses:
    def test_maps_ipc_fields_to_hypothesis(self) -> None:
        ipc_list = [
            HypothesisIpc(
                vulnerability_class="SqlInjection",
                description="IF login uses string concat",
                confidence=0.8,
                test_specification="send payloads to /login",
            )
        ]
        result = _build_hypotheses(ipc_list)
        assert len(result) == 1
        h = result[0]
        assert h.vulnerability_class == "SqlInjection"
        assert h.condition == "IF login uses string concat"
        assert h.reasoning == "IF login uses string concat"
        assert h.test_approach == "send payloads to /login"
        assert h.confidence == 0.8

    def test_missing_test_specification_defaults_to_empty(self) -> None:
        ipc_list = [
            HypothesisIpc(
                vulnerability_class="XSS",
                description="reflected input",
                confidence=0.5,
            )
        ]
        result = _build_hypotheses(ipc_list)
        assert result[0].test_approach == ""

    def test_null_test_specification_defaults_to_empty(self) -> None:
        ipc_list = [
            HypothesisIpc(
                vulnerability_class="XSS",
                description="reflected input",
                confidence=0.5,
                test_specification=None,
            )
        ]
        result = _build_hypotheses(ipc_list)
        assert result[0].test_approach == ""


class TestBuildEvasionContext:
    def test_maps_defense_context_with_waf(self) -> None:
        req = EvasionGenerateRequest(
            type="EvasionGenerate",
            request_id=1,
            defense_context=DefenseContextIpc(
                has_waf=True,
                waf_vendor="ModSecurity",
                rate_limit_rps=10.0,
                bot_detection_present=True,
            ),
        )
        ctx = _build_evasion_context(req)
        assert ctx.defense_type == "waf"
        assert ctx.defense_vendor == "ModSecurity"

    def test_no_waf_sets_unknown_defense_type(self) -> None:
        req = EvasionGenerateRequest(
            type="EvasionGenerate",
            request_id=1,
            defense_context=DefenseContextIpc(
                has_waf=False,
                bot_detection_present=False,
            ),
        )
        ctx = _build_evasion_context(req)
        assert ctx.defense_type == "unknown"
        assert ctx.defense_vendor == "unknown"

    def test_null_waf_vendor_defaults_to_unknown(self) -> None:
        req = EvasionGenerateRequest(
            type="EvasionGenerate",
            request_id=1,
            defense_context=DefenseContextIpc(
                has_waf=True,
                waf_vendor=None,
                bot_detection_present=False,
            ),
        )
        ctx = _build_evasion_context(req)
        assert ctx.defense_vendor == "unknown"


class TestHypothesisToIpc:
    def test_converts_hypothesis_to_model(self) -> None:
        h = Hypothesis(
            condition="IF /login accepts SQL metacharacters",
            vulnerability_class="SqlInjection",
            reasoning="string concatenation detected",
            test_approach="send payloads",
            confidence=0.9,
        )
        result = _hypothesis_to_ipc(h)
        assert result.vulnerability_class == "SqlInjection"
        assert result.description == "IF /login accepts SQL metacharacters"
        assert result.confidence == 0.9
        assert result.test_specification == "send payloads"


class TestBridgeDispatch:
    def setup_method(self) -> None:
        self.bridge = Bridge()

    @patch.object(Bridge, "handle_generate_hypotheses")
    def test_dispatches_generate_hypotheses(self, mock_handler: MagicMock) -> None:
        mock_handler.return_value = {
            "type": "Hypotheses",
            "request_id": 1,
            "hypotheses": [],
            "reasoning_trace": "",
            "input_tokens": 0,
            "output_tokens": 0,
        }
        request = {
            "type": "GenerateHypotheses",
            "request_id": 1,
            "scan_context": {
                "technology_stack": [],
                "findings_summary": [],
                "high_centrality_nodes": [],
                "defense_posture": {},
            },
            "vulnerability_class": "SqlInjection",
        }
        result = self.bridge.dispatch(request)
        mock_handler.assert_called_once()
        assert isinstance(mock_handler.call_args[0][0], GenerateHypothesesRequest)
        assert result["type"] == "Hypotheses"

    @patch.object(Bridge, "handle_compile_payloads")
    def test_dispatches_compile_payloads(self, mock_handler: MagicMock) -> None:
        mock_handler.return_value = {
            "type": "CompiledPayloads",
            "request_id": 2,
            "payloads": [],
            "input_tokens": 0,
            "output_tokens": 0,
        }
        request = {
            "type": "CompilePayloads",
            "request_id": 2,
            "hypotheses": [],
        }
        result = self.bridge.dispatch(request)
        mock_handler.assert_called_once()
        assert isinstance(mock_handler.call_args[0][0], CompilePayloadsRequest)
        assert result["type"] == "CompiledPayloads"

    @patch.object(Bridge, "handle_evasion_generate")
    def test_dispatches_evasion_generate(self, mock_handler: MagicMock) -> None:
        mock_handler.return_value = {
            "type": "EvasionPayloads",
            "request_id": 3,
            "payloads": [],
            "input_tokens": 0,
            "output_tokens": 0,
        }
        request = {
            "type": "EvasionGenerate",
            "request_id": 3,
            "defense_context": {
                "has_waf": False,
                "bot_detection_present": False,
            },
        }
        result = self.bridge.dispatch(request)
        mock_handler.assert_called_once()
        assert isinstance(mock_handler.call_args[0][0], EvasionGenerateRequest)
        assert result["type"] == "EvasionPayloads"

    def test_unknown_type_returns_error(self) -> None:
        request = {"type": "UnknownAction", "request_id": 99}
        result = self.bridge.dispatch(request)
        assert result["type"] == "Error"
        assert result["request_id"] == 99
        assert "invalid request" in result["message"]

    def test_exception_returns_error(self) -> None:
        with patch.object(
            Bridge, "handle_generate_hypotheses", side_effect=RuntimeError("boom")
        ):
            request = {
                "type": "GenerateHypotheses",
                "request_id": 7,
                "scan_context": {
                    "technology_stack": [],
                    "findings_summary": [],
                    "high_centrality_nodes": [],
                    "defense_posture": {},
                },
                "vulnerability_class": "SqlInjection",
            }
            result = self.bridge.dispatch(request)
            assert result["type"] == "Error"
            assert result["request_id"] == 7
            assert "boom" in result["message"]

    def test_shutdown_returns_none(self) -> None:
        result = self.bridge.dispatch({"type": "Shutdown"})
        assert result is None


class TestBridgeHandleGenerateHypotheses:
    def test_calls_generator_and_returns_hypotheses(self) -> None:
        bridge = Bridge()
        mock_backend = MagicMock(spec=LlmBackend)
        bridge._backend = mock_backend

        mock_generator = MagicMock()
        mock_generator.generate.return_value = GenerationResult(
            hypotheses=[
                Hypothesis(
                    condition="IF /login is vulnerable",
                    vulnerability_class="SqlInjection",
                    reasoning="string concat",
                    test_approach="send payloads",
                    confidence=0.8,
                )
            ],
            model_id="test-model",
            generation_time_ms=100.0,
            reasoning_trace="analyzed the endpoint",
            input_tokens=500,
            output_tokens=120,
        )
        bridge._generator = mock_generator

        req = GenerateHypothesesRequest(
            type="GenerateHypotheses",
            request_id=1,
            scan_context=ScanContextIpc(
                technology_stack=["Express"],
                findings_summary=[],
                high_centrality_nodes=[],
                defense_posture={},
            ),
            vulnerability_class="SqlInjection",
            feedback_summary="prior results",
        )
        result = bridge.handle_generate_hypotheses(req)

        assert result["type"] == "Hypotheses"
        assert result["request_id"] == 1
        assert len(result["hypotheses"]) == 1
        assert result["hypotheses"][0]["vulnerability_class"] == "SqlInjection"
        assert result["reasoning_trace"] == "analyzed the endpoint"
        assert result["input_tokens"] == 500
        assert result["output_tokens"] == 120


class TestBridgeHandleCompilePayloads:
    def test_calls_compiler_and_returns_payloads(self) -> None:
        bridge = Bridge()
        mock_backend = MagicMock(spec=LlmBackend)
        bridge._backend = mock_backend

        mock_compiler = MagicMock()
        mock_compiler.compile_batch.return_value = CompilationResult(
            specifications=[
                TestSpecification(
                    hypothesis_condition="IF login",
                    target_endpoint="/login",
                    http_method="POST",
                    payload_patterns=["' OR 1=1--", "admin' --"],
                )
            ],
            compilation_time_ms=50.0,
            failed_compilations=0,
            input_tokens=200,
            output_tokens=100,
        )
        bridge._compiler = mock_compiler

        req = CompilePayloadsRequest(
            type="CompilePayloads",
            request_id=2,
            hypotheses=[
                HypothesisIpc(
                    vulnerability_class="SqlInjection",
                    description="IF login is vulnerable",
                    confidence=0.8,
                    test_specification="send SQL payloads",
                )
            ],
        )
        result = bridge.handle_compile_payloads(req)

        assert result["type"] == "CompiledPayloads"
        assert result["request_id"] == 2
        assert result["payloads"] == ["' OR 1=1--", "admin' --"]
        assert result["input_tokens"] == 200
        assert result["output_tokens"] == 100


class TestBridgeHandleEvasionGenerate:
    def test_calls_evasion_generator_and_returns_payloads(self) -> None:
        bridge = Bridge()
        mock_backend = MagicMock(spec=LlmBackend)
        bridge._backend = mock_backend

        mock_evasion = MagicMock()
        mock_evasion.generate_evasions.return_value = EvasionResult(
            evasions=[
                EvasionPayload(
                    payload="' /*!50000OR*/ 1=1--",
                    strategy="version comment bypass",
                    confidence=0.7,
                )
            ],
            model_id="test-model",
            generation_time_ms=80.0,
            input_tokens=300,
            output_tokens=150,
        )
        bridge._evasion_generator = mock_evasion

        req = EvasionGenerateRequest(
            type="EvasionGenerate",
            request_id=3,
            defense_context=DefenseContextIpc(
                has_waf=True,
                waf_vendor="ModSecurity",
                rate_limit_rps=10.0,
                bot_detection_present=False,
            ),
        )
        result = bridge.handle_evasion_generate(req)

        assert result["type"] == "EvasionPayloads"
        assert result["request_id"] == 3
        assert result["payloads"] == ["' /*!50000OR*/ 1=1--"]
        assert result["input_tokens"] == 300
        assert result["output_tokens"] == 150


def _short_sock_path(suffix: str) -> str:
    """Return a short /tmp socket path to stay within macOS 104-byte limit."""
    import os
    import tempfile

    fd, path = tempfile.mkstemp(suffix=suffix, dir="/tmp")
    os.close(fd)
    os.unlink(path)
    return path


class TestMainSendsReadyHandshake:
    def test_sends_ready_then_handles_shutdown(self) -> None:
        sock_path = _short_sock_path(".sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(sock_path)
        server.listen(1)

        import threading

        received_frames: list[dict] = []

        def client_thread() -> None:
            main(sock_path)

        t = threading.Thread(target=client_thread, daemon=True)
        t.start()

        conn, _ = server.accept()
        try:
            ready = read_frame(conn)
            received_frames.append(ready)

            shutdown_msg = {"type": "Shutdown"}
            send_frame(conn, shutdown_msg)
        finally:
            conn.close()
            server.close()

        t.join(timeout=5)
        assert received_frames[0] == {"type": "Ready"}


class TestShutdownBreaksLoop:
    def test_loop_exits_on_shutdown(self) -> None:
        sock_path = _short_sock_path(".sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(sock_path)
        server.listen(1)

        import threading

        exited = threading.Event()

        def client_thread() -> None:
            main(sock_path)
            exited.set()

        t = threading.Thread(target=client_thread, daemon=True)
        t.start()

        conn, _ = server.accept()
        try:
            read_frame(conn)
            send_frame(conn, {"type": "Shutdown"})
        finally:
            conn.close()
            server.close()

        assert exited.wait(timeout=5)
