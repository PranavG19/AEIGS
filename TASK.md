# WORKER TASK — Adversarial Prompt Compiler

## status: DONE

## feature
Meta-reasoning layer that takes failed hypotheses + defense context and generates adversarial reformulations.

## crate
hypothesis-engine (Python)

## files
- hypothesis-engine/src/hypothesis_engine/adversarial_compiler.py
- hypothesis-engine/tests/test_adversarial_compiler.py

## what-it-does
Instead of "try SQLi on /login", it produces: "the WAF blocks UNION SELECT but the backend is
MySQL 8 which supports VALUES ROW() — generate a payload using VALUES ROW() syntax with
double-URL-encoded whitespace."

Compiles defense fingerprints + failure history into constraint-satisfying prompt mutations.
Teaches the LLM to think like a bypass researcher, not a payload dictionary.

## architecture
```python
class AdversarialCompiler:
    def compile(self, failed_hypothesis: dict, defense_context: dict, history: list[dict]) -> list[dict]:
        """Takes a failed hypothesis and defense context, returns reformulated hypotheses
        with specific bypass strategies derived from the defense constraints."""
        pass

    def analyze_failure(self, hypothesis: dict, response: dict) -> dict:
        """Determines WHY a hypothesis failed — WAF block, rate limit, wrong vuln class, etc."""
        pass

    def generate_bypass_strategies(self, defense_context: dict, vuln_class: str) -> list[str]:
        """Given a defense profile, generate specific bypass strategies for a vuln class."""
        pass
```

## acceptance-criteria
1. Given 5 fixture scenarios (failed hypothesis + defense context), generate reformulated hypotheses where ≥3/5 contain novel bypass strategies not in the original
2. Verify reformulations reference specific defense constraints from the context
3. Covers each defense type: WAF, rate-limit, bot-detect, CSP
4. Works with existing LlmBackend (bedrock/openai/ollama)
5. 20+ tests
6. Follows existing hypothesis-engine patterns (see generator.py, compiler.py)

## test-command
cd hypothesis-engine && uv run pytest tests/test_adversarial_compiler.py -v

## patterns-to-follow
- Read existing hypothesis-engine/src/hypothesis_engine/ for patterns
- Use existing types: ScanContextIpc, HypothesisIpc, DefenseContextIpc
- XML prompt structure: <role>/<task>/<constraints>/<output_format>
- Tests use fixtures from hypothesis-engine/tests/fixtures/

## do-not
- Do NOT modify existing Python files (generator.py, compiler.py, etc.)
- Do NOT add new pip dependencies without checking pyproject.toml
- Do NOT call real LLM APIs in tests — mock the LlmBackend
