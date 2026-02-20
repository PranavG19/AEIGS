from __future__ import annotations

import re

from hypothesis_engine.generator import Hypothesis

HEDGING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\bmight\b",
        r"\bpossibly\b",
        r"\bperhaps\b",
        r"\bcould be\b",
        r"\buncertain\b",
        r"\bnot sure\b",
        r"\bunclear\b",
        r"\bpotentially\b",
        r"\bmay have\b",
        r"\bseems like\b",
        r"\bappears to\b",
    ]
]

CONFIDENCE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\bconfirms\b",
        r"\bclearly\b",
        r"\bdefinitely\b",
        r"\bstrong evidence\b",
        r"\bindicates\b",
        r"\bdemonstrates\b",
    ]
]


def extract_uncertainty_score(reasoning_trace: str) -> float:
    hedging_count = sum(
        1 for pattern in HEDGING_PATTERNS if pattern.search(reasoning_trace)
    )
    confidence_count = sum(
        1 for pattern in CONFIDENCE_PATTERNS if pattern.search(reasoning_trace)
    )

    if hedging_count == 0 and confidence_count == 0:
        return 0.5

    score = 1.0 - (hedging_count / (hedging_count + confidence_count))
    return max(0.0, min(1.0, score))


def adjust_confidence(hypothesis: Hypothesis, uncertainty_score: float) -> Hypothesis:
    new_confidence = hypothesis.confidence * uncertainty_score

    if hypothesis.insufficient_data:
        new_confidence = min(new_confidence, 0.2)

    new_confidence = max(0.0, min(1.0, new_confidence))

    return hypothesis.model_copy(update={"confidence": new_confidence})


def prioritize_hypotheses(hypotheses: list[Hypothesis]) -> list[Hypothesis]:
    sufficient = [h for h in hypotheses if not h.insufficient_data]
    insufficient = [h for h in hypotheses if h.insufficient_data]

    sufficient.sort(key=lambda h: h.confidence, reverse=True)
    insufficient.sort(key=lambda h: h.confidence, reverse=True)

    return sufficient + insufficient
