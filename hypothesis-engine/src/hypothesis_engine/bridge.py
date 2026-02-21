from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
from typing import Any

from hypothesis_engine.compiler import HypothesisCompiler
from hypothesis_engine.evasion_mode import EvasionContext, EvasionHypothesisGenerator
from hypothesis_engine.generator import (
    Hypothesis,
    HypothesisGenerator,
    ScanContext,
    create_backend,
)

MAX_FRAME_SIZE = 64 * 1024 * 1024


def recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from sock, raising ConnectionError on premature close."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(
                f"connection closed after {len(buf)} of {n} bytes"
            )
        buf.extend(chunk)
    return bytes(buf)


def read_frame(sock: socket.socket) -> dict:
    """Read a length-prefixed JSON frame from a Unix domain socket."""
    length_bytes = recv_exactly(sock, 4)
    length = struct.unpack("<I", length_bytes)[0]
    if length > MAX_FRAME_SIZE:
        raise ValueError(
            f"frame size {length} exceeds maximum {MAX_FRAME_SIZE}"
        )
    if length == 0:
        return {}
    payload = recv_exactly(sock, length)
    return json.loads(payload)


def send_frame(sock: socket.socket, msg: dict) -> None:
    """Write a length-prefixed JSON frame to a Unix domain socket."""
    payload = json.dumps(msg).encode("utf-8")
    length = len(payload)
    sock.sendall(struct.pack("<I", length))
    sock.sendall(payload)


def _build_scan_context(request: dict) -> ScanContext:
    """Map IPC scan_context fields to the Python ScanContext model."""
    sc = request.get("scan_context", {})
    return ScanContext(
        technology_stack=sc.get("technology_stack", []),
        findings_summary=sc.get("findings_summary", []),
        high_centrality_nodes=[
            {"label": n} if isinstance(n, str) else n
            for n in sc.get("high_centrality_nodes", [])
        ],
        defense_posture=sc.get("defense_posture", {}),
        feedback_summary=request.get("feedback_summary", "") or "",
    )


def _build_hypotheses(raw_list: list[dict[str, Any]]) -> list[Hypothesis]:
    """Map IPC HypothesisJson dicts to Python Hypothesis models."""
    result: list[Hypothesis] = []
    for h in raw_list:
        result.append(
            Hypothesis(
                condition=h.get("description", ""),
                vulnerability_class=h.get("vulnerability_class", ""),
                reasoning=h.get("description", ""),
                test_approach=h.get("test_specification", "") or "",
                confidence=h.get("confidence", 0.5),
            )
        )
    return result


def _build_evasion_context(defense_context: dict) -> EvasionContext:
    """Map IPC DefenseContextJson to the Python EvasionContext model."""
    has_waf = defense_context.get("has_waf", False)
    return EvasionContext(
        vulnerability_class="",
        blocked_payload="",
        defense_type="waf" if has_waf else "unknown",
        defense_vendor=defense_context.get("waf_vendor") or "unknown",
        response_code=0,
        response_snippet="",
    )


def _hypothesis_to_ipc(h: Hypothesis) -> dict:
    """Convert a Python Hypothesis to an IPC HypothesisJson dict."""
    return {
        "vulnerability_class": h.vulnerability_class,
        "description": h.condition,
        "confidence": h.confidence,
        "test_specification": h.test_approach or None,
    }


class Bridge:
    """Persistent IPC bridge dispatching requests to hypothesis-engine components."""

    def __init__(self) -> None:
        self._backend = None
        self._generator: HypothesisGenerator | None = None
        self._compiler: HypothesisCompiler | None = None
        self._evasion_generator: EvasionHypothesisGenerator | None = None

    def _ensure_backend(self) -> None:
        if self._backend is None:
            self._backend = create_backend("bedrock")

    def _get_generator(self) -> HypothesisGenerator:
        self._ensure_backend()
        if self._generator is None:
            self._generator = HypothesisGenerator(client=self._backend)
        return self._generator

    def _get_compiler(self) -> HypothesisCompiler:
        self._ensure_backend()
        if self._compiler is None:
            self._compiler = HypothesisCompiler(client=self._backend)
        return self._compiler

    def _get_evasion_generator(self) -> EvasionHypothesisGenerator:
        self._ensure_backend()
        if self._evasion_generator is None:
            self._evasion_generator = EvasionHypothesisGenerator(
                client=self._backend
            )
        return self._evasion_generator

    def handle_generate_hypotheses(self, request: dict) -> dict:
        """Handle a GenerateHypotheses request."""
        request_id = request["request_id"]
        context = _build_scan_context(request)
        generator = self._get_generator()
        result = generator.generate(context)
        return {
            "type": "Hypotheses",
            "request_id": request_id,
            "hypotheses": [_hypothesis_to_ipc(h) for h in result.hypotheses],
            "reasoning_trace": result.reasoning_trace,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
        }

    def handle_compile_payloads(self, request: dict) -> dict:
        """Handle a CompilePayloads request."""
        request_id = request["request_id"]
        hypotheses = _build_hypotheses(request.get("hypotheses", []))
        compiler = self._get_compiler()
        result = compiler.compile_batch(hypotheses)
        payloads: list[str] = []
        for spec in result.specifications:
            payloads.extend(spec.payload_patterns)
        return {
            "type": "CompiledPayloads",
            "request_id": request_id,
            "payloads": payloads,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
        }

    def handle_evasion_generate(self, request: dict) -> dict:
        """Handle an EvasionGenerate request."""
        request_id = request["request_id"]
        context = _build_evasion_context(request.get("defense_context", {}))
        evasion_gen = self._get_evasion_generator()
        result = evasion_gen.generate_evasions(context)
        payloads = [e.payload for e in result.evasions]
        return {
            "type": "EvasionPayloads",
            "request_id": request_id,
            "payloads": payloads,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
        }

    def dispatch(self, request: dict) -> dict | None:
        """Dispatch a single request, returning a response dict or None for shutdown."""
        msg_type = request.get("type")
        request_id = request.get("request_id", 0)

        if msg_type == "Shutdown":
            return None

        try:
            if msg_type == "GenerateHypotheses":
                return self.handle_generate_hypotheses(request)
            elif msg_type == "CompilePayloads":
                return self.handle_compile_payloads(request)
            elif msg_type == "EvasionGenerate":
                return self.handle_evasion_generate(request)
            else:
                return {
                    "type": "Error",
                    "request_id": request_id,
                    "message": f"unknown request type: {msg_type}",
                }
        except Exception as exc:
            return {
                "type": "Error",
                "request_id": request_id,
                "message": str(exc),
            }


def main(socket_path: str) -> None:
    """Connect to the Unix socket, send Ready, and enter the request loop."""
    bridge = Bridge()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(socket_path)
        send_frame(sock, {"type": "Ready"})

        while True:
            request = read_frame(sock)
            response = bridge.dispatch(request)
            if response is None:
                break
            send_frame(sock, response)
    finally:
        sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Hypothesis engine IPC bridge"
    )
    parser.add_argument(
        "--socket", required=True, help="Path to Unix domain socket"
    )
    args = parser.parse_args()
    main(args.socket)
