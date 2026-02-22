from __future__ import annotations

import argparse
import json
import socket
import struct

from hypothesis_engine.compiler import HypothesisCompiler
from hypothesis_engine.evasion_mode import EvasionContext, EvasionHypothesisGenerator
from hypothesis_engine.generator import (
    Hypothesis,
    HypothesisGenerator,
    ScanContext,
    create_backend,
)
from hypothesis_engine.ipc_types import (
    CompiledPayloadsResponse,
    CompilePayloadsRequest,
    ErrorResponse,
    EvasionGenerateRequest,
    EvasionPayloadsResponse,
    GenerateHypothesesRequest,
    HypothesisIpc,
    HypothesesResponse,
    ReadyResponse,
    ShutdownRequest,
    parse_bridge_request,
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


def _build_scan_context(req: GenerateHypothesesRequest) -> ScanContext:
    """Map validated IPC request to the Python ScanContext model."""
    sc = req.scan_context
    return ScanContext(
        technology_stack=sc.technology_stack,
        findings_summary=sc.findings_summary,
        high_centrality_nodes=[
            {"label": n} if isinstance(n, str) else n
            for n in sc.high_centrality_nodes
        ],
        defense_posture=sc.defense_posture,
        feedback_summary=req.feedback_summary or "",
    )


def _build_hypotheses(ipc_list: list[HypothesisIpc]) -> list[Hypothesis]:
    """Map validated IPC HypothesisIpc models to Python Hypothesis models."""
    return [
        Hypothesis(
            condition=h.description,
            vulnerability_class=h.vulnerability_class,
            reasoning=h.description,
            test_approach=h.test_specification or "",
            confidence=h.confidence,
        )
        for h in ipc_list
    ]


def _build_evasion_context(req: EvasionGenerateRequest) -> EvasionContext:
    """Map validated IPC request to the Python EvasionContext model."""
    dc = req.defense_context
    return EvasionContext(
        vulnerability_class="",
        blocked_payload="",
        defense_type="waf" if dc.has_waf else "unknown",
        defense_vendor=dc.waf_vendor or "unknown",
        response_code=0,
        response_snippet="",
    )


def _hypothesis_to_ipc(h: Hypothesis) -> HypothesisIpc:
    """Convert a Python Hypothesis to an IPC HypothesisIpc model."""
    return HypothesisIpc(
        vulnerability_class=h.vulnerability_class,
        description=h.condition,
        confidence=h.confidence,
        test_specification=h.test_approach or None,
    )


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

    def handle_generate_hypotheses(
        self, req: GenerateHypothesesRequest
    ) -> dict:
        """Handle a GenerateHypotheses request."""
        context = _build_scan_context(req)
        generator = self._get_generator()
        result = generator.generate(context)
        resp = HypothesesResponse(
            request_id=req.request_id,
            hypotheses=[_hypothesis_to_ipc(h) for h in result.hypotheses],
            reasoning_trace=result.reasoning_trace,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
        )
        return resp.model_dump()

    def handle_compile_payloads(self, req: CompilePayloadsRequest) -> dict:
        """Handle a CompilePayloads request."""
        hypotheses = _build_hypotheses(req.hypotheses)
        compiler = self._get_compiler()
        result = compiler.compile_batch(hypotheses)
        payloads: list[str] = []
        for spec in result.specifications:
            payloads.extend(spec.payload_patterns)
        resp = CompiledPayloadsResponse(
            request_id=req.request_id,
            payloads=payloads,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
        )
        return resp.model_dump()

    def handle_evasion_generate(self, req: EvasionGenerateRequest) -> dict:
        """Handle an EvasionGenerate request."""
        context = _build_evasion_context(req)
        evasion_gen = self._get_evasion_generator()
        result = evasion_gen.generate_evasions(context)
        payloads = [e.payload for e in result.evasions]
        resp = EvasionPayloadsResponse(
            request_id=req.request_id,
            payloads=payloads,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
        )
        return resp.model_dump()

    def dispatch(self, raw_request: dict) -> dict | None:
        """Dispatch a single request, returning a response dict or None for shutdown."""
        request_id = raw_request.get("request_id", 0)

        try:
            req = parse_bridge_request(raw_request)
        except Exception as exc:
            return ErrorResponse(
                request_id=request_id,
                message=f"invalid request: {exc}",
            ).model_dump()

        if isinstance(req, ShutdownRequest):
            return None

        try:
            if isinstance(req, GenerateHypothesesRequest):
                return self.handle_generate_hypotheses(req)
            elif isinstance(req, CompilePayloadsRequest):
                return self.handle_compile_payloads(req)
            elif isinstance(req, EvasionGenerateRequest):
                return self.handle_evasion_generate(req)
            else:
                return ErrorResponse(
                    request_id=request_id,
                    message=f"unknown request type: {type(req).__name__}",
                ).model_dump()
        except Exception as exc:
            return ErrorResponse(
                request_id=request_id,
                message=str(exc),
            ).model_dump()


def main(socket_path: str) -> None:
    """Connect to the Unix socket, send Ready, and enter the request loop."""
    bridge = Bridge()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(socket_path)
        send_frame(sock, ReadyResponse().model_dump())

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
