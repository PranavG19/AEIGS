from __future__ import annotations

import json
from pathlib import Path

import pytest

from hypothesis_engine.generator import Hypothesis, ScanContext

FIXTURES_DIR = Path(__file__).parent / "fixtures"

fixture_files = sorted(p.name for p in FIXTURES_DIR.glob("*.json"))


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text())


# Static-only baseline: vulnerability classes discoverable without LLM
# These are found by static analysis (dependency scanning, route enumeration)
# Each set must be a subset of the corresponding fixture's ground_truth classes
STATIC_BASELINE: dict[str, set[str]] = {
    "express-vuln-app": {
        "Security Misconfiguration",  # from exposed admin/config endpoint
    },
    "flask-vuln-app": {
        "Security Misconfiguration",  # from exposed /config endpoint
    },
    "graphql-vuln-app": set(),  # no known vulnerable deps, single /graphql endpoint
    "spring-boot-app": set(),  # no known vulnerable deps or obvious misconfigs
    "django-app": {
        "Security Misconfiguration",  # from exposed /admin/settings/ endpoint
    },
    "rails-app": set(),  # no known vulnerable deps
    "fastapi-app": set(),  # no known vulnerable deps
    "nextjs-app": set(),  # no known vulnerable deps, no obvious misconfigs
    "php-laravel-app": {
        "Security Misconfiguration",  # from exposed /api/admin/env endpoint
    },
    "go-gin-app": set(),  # no known vulnerable deps
    "express-waf-app": set(),  # WAF obscures static signals
    "flask-ratelimit-app": set(),  # rate limiter does not reveal vuln classes statically
    "graphql-auth-app": set(),  # no known vulnerable deps, auth issues require dynamic testing
    "microservices-app": set(),  # SSRF and authz require dynamic testing
    "aspnet-app": {
        "Known Vulnerable Dependency",  # Newtonsoft.Json 11.0.2 (CVE-2024-21907)
    },
}


def _fixture_params() -> list[tuple[str, str]]:
    result = []
    for name in fixture_files:
        fixture = load_fixture(name)
        app_name = fixture["app_name"]
        if app_name in STATIC_BASELINE:
            result.append((name, app_name))
    return result


fixture_params = _fixture_params()


def compute_recall(
    hypotheses: list[Hypothesis],
    ground_truth: list[dict[str, str]],
) -> float:
    gt_classes = {g["vulnerability_class"] for g in ground_truth}
    found_classes = {h.vulnerability_class for h in hypotheses}
    matched = gt_classes & found_classes
    return len(matched) / len(gt_classes) if gt_classes else 0.0


class TestStaticOnlyBaseline:
    @pytest.mark.parametrize("fixture_name,app_name", fixture_params)
    def test_static_baseline_is_subset_of_ground_truth(
        self, fixture_name: str, app_name: str
    ) -> None:
        fixture = load_fixture(fixture_name)
        gt_classes = {g["vulnerability_class"] for g in fixture["ground_truth"]}
        baseline = STATIC_BASELINE[app_name]
        assert baseline.issubset(gt_classes), (
            f"Static baseline contains classes not in ground truth: {baseline - gt_classes}"
        )


class TestLlmDelta:
    @pytest.mark.parametrize("fixture_name,app_name", fixture_params)
    def test_golden_hypotheses_exceed_static_baseline(
        self, fixture_name: str, app_name: str
    ) -> None:
        """Golden hypotheses (LLM proxy) should find more classes than static-only."""
        fixture = load_fixture(fixture_name)
        gt = fixture["ground_truth"]
        golden = [Hypothesis(**h) for h in fixture["golden_hypotheses"]]

        golden_classes = {h.vulnerability_class for h in golden}
        baseline_classes = STATIC_BASELINE[app_name]

        # LLM should find strictly more classes than static alone
        llm_exclusive = golden_classes - baseline_classes
        assert len(llm_exclusive) > 0, (
            f"{app_name}: LLM hypotheses should discover classes beyond static baseline. "
            f"Golden classes: {golden_classes}, Baseline: {baseline_classes}"
        )

    @pytest.mark.parametrize("fixture_name,app_name", fixture_params)
    def test_golden_recall_exceeds_static_recall(
        self, fixture_name: str, app_name: str
    ) -> None:
        fixture = load_fixture(fixture_name)
        gt = fixture["ground_truth"]
        golden = [Hypothesis(**h) for h in fixture["golden_hypotheses"]]

        golden_recall = compute_recall(golden, gt)
        static_hypotheses = [
            Hypothesis(
                condition=f"IF dependency is vulnerable",
                vulnerability_class=cls,
                reasoning="static", test_approach="static", confidence=0.9,
            )
            for cls in STATIC_BASELINE[app_name]
        ]
        static_recall = compute_recall(static_hypotheses, gt)

        assert golden_recall > static_recall, (
            f"{app_name}: Golden recall ({golden_recall:.2f}) should exceed "
            f"static recall ({static_recall:.2f})"
        )


class TestDeltaDocumentation:
    def test_all_fixture_apps_have_static_baseline(self) -> None:
        for fixture_name in fixture_files:
            fixture = load_fixture(fixture_name)
            assert fixture["app_name"] in STATIC_BASELINE, (
                f"Missing static baseline for {fixture['app_name']}"
            )
