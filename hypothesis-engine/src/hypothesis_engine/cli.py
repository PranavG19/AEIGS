from __future__ import annotations

import json
import sys

from hypothesis_engine.compiler import HypothesisCompiler
from hypothesis_engine.generator import Hypothesis, HypothesisGenerator, ScanContext, create_backend


def handle_request(request: dict) -> dict:
    action = request.get("action")

    if action == "generate":
        return _handle_generate(request)
    elif action == "compile":
        return _handle_compile(request)
    else:
        return {"error": f"Unknown action: {action}"}


def _handle_generate(request: dict) -> dict:
    try:
        backend = create_backend(request["backend"], **request.get("backend_kwargs", {}))
        generator = HypothesisGenerator(client=backend)
        context = ScanContext(**request["context"])
        result = generator.generate(context)
        return {
            "hypotheses": [h.model_dump() for h in result.hypotheses],
            "model_id": result.model_id,
            "reasoning_trace": result.reasoning_trace,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
        }
    except Exception as e:
        return {"error": str(e)}


def _handle_compile(request: dict) -> dict:
    try:
        backend = create_backend(request["backend"], **request.get("backend_kwargs", {}))
        compiler = HypothesisCompiler(client=backend)
        hypotheses = [Hypothesis(**h) for h in request["hypotheses"]]
        result = compiler.compile_batch(hypotheses)
        return {
            "specifications": [s.model_dump() for s in result.specifications],
            "compilation_time_ms": result.compilation_time_ms,
            "failed_compilations": result.failed_compilations,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
        }
    except Exception as e:
        return {"error": str(e)}


def main() -> None:
    request = json.loads(sys.stdin.read())
    response = handle_request(request)
    sys.stdout.write(json.dumps(response))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
