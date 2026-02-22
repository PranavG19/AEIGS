from __future__ import annotations

from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, Field


class ScanContextIpc(BaseModel):
    """Scan context for IPC transport. Must match Rust ScanContextIpc exactly."""

    technology_stack: list[str] = Field(default_factory=list)
    findings_summary: list[str] = Field(default_factory=list)
    high_centrality_nodes: list[str] = Field(default_factory=list)
    defense_posture: dict[str, Any] = Field(default_factory=dict)
    class_confirmation_rates: dict[str, float] = Field(default_factory=dict)
    model_id: str | None = None


class HypothesisIpc(BaseModel):
    """Hypothesis for IPC transport. Must match Rust HypothesisIpc exactly."""

    vulnerability_class: str
    description: str
    confidence: float
    test_specification: str | None = None


class DefenseContextIpc(BaseModel):
    """Defense context for IPC transport. Must match Rust DefenseContextIpc exactly."""

    has_waf: bool
    waf_vendor: str | None = None
    rate_limit_rps: float | None = None
    bot_detection_present: bool


class GenerateHypothesesRequest(BaseModel):
    """GenerateHypotheses variant of BridgeRequest."""

    type: Literal["GenerateHypotheses"]
    request_id: int
    scan_context: ScanContextIpc
    vulnerability_class: str
    feedback_summary: str | None = None


class CompilePayloadsRequest(BaseModel):
    """CompilePayloads variant of BridgeRequest."""

    type: Literal["CompilePayloads"]
    request_id: int
    hypotheses: list[HypothesisIpc]


class EvasionGenerateRequest(BaseModel):
    """EvasionGenerate variant of BridgeRequest."""

    type: Literal["EvasionGenerate"]
    request_id: int
    defense_context: DefenseContextIpc


class ShutdownRequest(BaseModel):
    """Shutdown variant of BridgeRequest."""

    type: Literal["Shutdown"]


BridgeRequest = Annotated[
    Union[
        GenerateHypothesesRequest,
        CompilePayloadsRequest,
        EvasionGenerateRequest,
        ShutdownRequest,
    ],
    Field(discriminator="type"),
]


class ReadyResponse(BaseModel):
    """Ready variant of BridgeResponse."""

    type: Literal["Ready"] = "Ready"


class HypothesesResponse(BaseModel):
    """Hypotheses variant of BridgeResponse."""

    type: Literal["Hypotheses"] = "Hypotheses"
    request_id: int
    hypotheses: list[HypothesisIpc]
    reasoning_trace: str
    input_tokens: int = 0
    output_tokens: int = 0


class CompiledPayloadsResponse(BaseModel):
    """CompiledPayloads variant of BridgeResponse."""

    type: Literal["CompiledPayloads"] = "CompiledPayloads"
    request_id: int
    payloads: list[str]
    input_tokens: int = 0
    output_tokens: int = 0


class EvasionPayloadsResponse(BaseModel):
    """EvasionPayloads variant of BridgeResponse."""

    type: Literal["EvasionPayloads"] = "EvasionPayloads"
    request_id: int
    payloads: list[str]
    input_tokens: int = 0
    output_tokens: int = 0


class ErrorResponse(BaseModel):
    """Error variant of BridgeResponse."""

    type: Literal["Error"] = "Error"
    request_id: int
    message: str


BridgeResponse = Annotated[
    Union[
        ReadyResponse,
        HypothesesResponse,
        CompiledPayloadsResponse,
        EvasionPayloadsResponse,
        ErrorResponse,
    ],
    Field(discriminator="type"),
]


def parse_bridge_request(data: dict[str, Any]) -> (
    GenerateHypothesesRequest
    | CompilePayloadsRequest
    | EvasionGenerateRequest
    | ShutdownRequest
):
    """Parse a raw dict into a typed BridgeRequest variant."""
    from pydantic import TypeAdapter

    adapter = TypeAdapter(BridgeRequest)
    return adapter.validate_python(data)


def parse_bridge_response(data: dict[str, Any]) -> (
    ReadyResponse
    | HypothesesResponse
    | CompiledPayloadsResponse
    | EvasionPayloadsResponse
    | ErrorResponse
):
    """Parse a raw dict into a typed BridgeResponse variant."""
    from pydantic import TypeAdapter

    adapter = TypeAdapter(BridgeResponse)
    return adapter.validate_python(data)
