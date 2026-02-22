from __future__ import annotations

import json
from pathlib import Path

import pytest

from hypothesis_engine.generator import Hypothesis, ScanContext

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text())


def compute_hypothesis_metrics(
    hypotheses: list[Hypothesis],
    ground_truth: list[dict[str, str]],
) -> dict[str, float]:
    """Compute precision, recall, F1 for hypotheses against ground truth.

    Matching: hypothesis.vulnerability_class must match ground_truth entry's
    vulnerability_class, and ground_truth entry's endpoint must appear as a
    substring in hypothesis.condition.
    """
    gt_set = {(g["endpoint"], g["vulnerability_class"]) for g in ground_truth}
    matched_gt: set[tuple[str, str]] = set()
    true_positives = 0

    for h in hypotheses:
        for endpoint, vuln_class in gt_set:
            if h.vulnerability_class == vuln_class and endpoint in h.condition:
                if (endpoint, vuln_class) not in matched_gt:
                    true_positives += 1
                    matched_gt.add((endpoint, vuln_class))
                break

    precision = true_positives / len(hypotheses) if hypotheses else 0.0
    recall = true_positives / len(gt_set) if gt_set else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {"precision": precision, "recall": recall, "f1": f1, "true_positives": true_positives}


class TestEvaluationMetrics:
    def test_perfect_match(self) -> None:
        hypotheses = [
            Hypothesis(
                condition="IF endpoint /api/search is injectable",
                vulnerability_class="SQL Injection",
                reasoning="test", test_approach="test", confidence=0.8,
            )
        ]
        gt = [{"endpoint": "/api/search", "vulnerability_class": "SQL Injection"}]
        metrics = compute_hypothesis_metrics(hypotheses, gt)
        assert metrics["precision"] == 1.0
        assert metrics["recall"] == 1.0
        assert metrics["f1"] == 1.0

    def test_false_positive(self) -> None:
        hypotheses = [
            Hypothesis(
                condition="IF endpoint /api/search is injectable",
                vulnerability_class="SQL Injection",
                reasoning="test", test_approach="test", confidence=0.8,
            ),
            Hypothesis(
                condition="IF endpoint /api/users has XSS",
                vulnerability_class="Cross-Site Scripting",
                reasoning="test", test_approach="test", confidence=0.5,
            ),
        ]
        gt = [{"endpoint": "/api/search", "vulnerability_class": "SQL Injection"}]
        metrics = compute_hypothesis_metrics(hypotheses, gt)
        assert metrics["precision"] == 0.5
        assert metrics["recall"] == 1.0

    def test_false_negative(self) -> None:
        hypotheses = [
            Hypothesis(
                condition="IF endpoint /api/search is injectable",
                vulnerability_class="SQL Injection",
                reasoning="test", test_approach="test", confidence=0.8,
            )
        ]
        gt = [
            {"endpoint": "/api/search", "vulnerability_class": "SQL Injection"},
            {"endpoint": "/render", "vulnerability_class": "Cross-Site Scripting"},
        ]
        metrics = compute_hypothesis_metrics(hypotheses, gt)
        assert metrics["precision"] == 1.0
        assert metrics["recall"] == 0.5

    def test_empty_hypotheses(self) -> None:
        metrics = compute_hypothesis_metrics([], [{"endpoint": "/x", "vulnerability_class": "XSS"}])
        assert metrics["precision"] == 0.0
        assert metrics["recall"] == 0.0
        assert metrics["f1"] == 0.0

    def test_empty_ground_truth(self) -> None:
        hypotheses = [
            Hypothesis(
                condition="IF endpoint /x is vulnerable",
                vulnerability_class="XSS",
                reasoning="test", test_approach="test", confidence=0.5,
            )
        ]
        metrics = compute_hypothesis_metrics(hypotheses, [])
        assert metrics["precision"] == 0.0
        assert metrics["recall"] == 0.0


class TestGoldenHypothesesAgainstGroundTruth:
    @pytest.mark.parametrize("fixture_name", ["express_app.json", "flask_app.json", "graphql_app.json"])
    def test_golden_hypotheses_have_nonzero_recall(self, fixture_name: str) -> None:
        fixture = load_fixture(fixture_name)
        golden = [
            Hypothesis(**h) for h in fixture["golden_hypotheses"]
        ]
        metrics = compute_hypothesis_metrics(golden, fixture["ground_truth"])
        assert metrics["recall"] > 0.0, (
            f"{fixture['app_name']}: golden hypotheses should cover at least some ground truth"
        )
        assert metrics["precision"] > 0.0, (
            f"{fixture['app_name']}: golden hypotheses should not be all false positives"
        )

    @pytest.mark.parametrize("fixture_name", ["express_app.json", "flask_app.json", "graphql_app.json"])
    def test_golden_hypotheses_have_valid_classes(self, fixture_name: str) -> None:
        valid_classes = {
            "SQL Injection", "Cross-Site Scripting", "Command Injection",
            "Path Traversal", "Server-Side Request Forgery", "Insecure Deserialization",
            "Broken Authentication", "Broken Authorization", "Security Misconfiguration",
            "Sensitive Data Exposure", "Server-Side Template Injection", "Header Injection",
            "Open Redirect", "CRLF Injection", "Known Vulnerable Dependency",
            "Insufficient Input Validation",
        }
        fixture = load_fixture(fixture_name)
        for h in fixture["golden_hypotheses"]:
            assert h["vulnerability_class"] in valid_classes, (
                f"Invalid class: {h['vulnerability_class']}"
            )

    @pytest.mark.parametrize("fixture_name", ["express_app.json", "flask_app.json", "graphql_app.json"])
    def test_scan_context_loads_as_model(self, fixture_name: str) -> None:
        fixture = load_fixture(fixture_name)
        ctx = ScanContext(**fixture["scan_context"])
        assert len(ctx.technology_stack) > 0
        assert len(ctx.graph_nodes) > 0
