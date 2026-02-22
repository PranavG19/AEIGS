from __future__ import annotations

import re

from hypothesis_engine.generator import Hypothesis

STRUCTURAL_EVIDENCE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"input\s+flows?\s+(?:directly\s+)?to",
        r"(?:no|without|lacks?|missing)\s+(?:validation|sanitization|escaping|parameteriz)",
        r"concatenat(?:ed?|es|ing)\s+(?:into|with|to)\s+(?:sql|query|command|template)",
        r"(?:reads?|writes?|calls?)\s+.*(?:datastore|database|sink)",
        r"unprotected\s+(?:endpoint|path|node|entry)",
        r"(?:graph|topology)\s+shows?",
        r"(?:no|without|lacks?)\s+(?:defense|waf|protection|authentication)",
        r"(?:direct|unfiltered)\s+(?:access|path|route)",
    ]
]

SPECULATIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"(?:commonly|typically|often|usually)\s+(?:vulnerable|susceptible|affected)",
        r"technology\s+stack\s+(?:suggests?|indicates?|implies?)",
        r"(?:default|common)\s+(?:configuration|settings?|setup)",
        r"(?:no\s+evidence|insufficient\s+data|unclear|unknown)",
        r"(?:might|could|may)\s+(?:be|have|allow|enable)\s+(?:vulnerable|exploitable)",
        r"(?:without\s+(?:seeing|observing|confirming|verifying))",
    ]
]


def extract_uncertainty_score(reasoning_trace: str) -> float:
    """Analyze reasoning trace for structural evidence vs speculation.

    Returns a score in [0.0, 1.0] where:
    - Higher values indicate structural evidence (concrete data flow, graph analysis)
    - Lower values indicate speculation (technology assumptions, common patterns)
    - 0.5 is the neutral baseline when no patterns are detected
    """
    structural_count = sum(
        1 for pattern in STRUCTURAL_EVIDENCE_PATTERNS if pattern.search(reasoning_trace)
    )
    speculative_count = sum(
        1 for pattern in SPECULATIVE_PATTERNS if pattern.search(reasoning_trace)
    )

    if structural_count == 0 and speculative_count == 0:
        return 0.5

    score = structural_count / (structural_count + speculative_count)
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
