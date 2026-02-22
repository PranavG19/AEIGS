# Phase 3: Capability Gap Closure — Low-Level Design

**Date:** 2026-02-21
**Status:** Draft
**Scope:** 8 capability gaps identified in competitive analysis (excludes CI/CD)

## Gap Inventory

| # | Gap | Current State | Target State |
|---|-----|--------------|--------------|
| 1 | No browser engine / crawler | OpenAPI + source-code route discovery only | Headless Chromium crawler discovers routes, forms, JS-rendered content |
| 2 | No authenticated scanning | `AuthFlow` types exist in enumeration crate, not wired to pipeline | Pipeline executes auth flows, injects session tokens into all fuzz requests |
| 3 | Localhost-only targeting | 3-layer localhost enforcement, no remote option | Ed25519-attested remote targets via `--scope-attestation` flag |
| 4 | Low detection rate (19% recall) | Generic anomaly oracle + LLM hypothesis generation | Vuln-specific confirmation signatures + expanded payload corpus |
| 5 | No JavaScript / DOM analysis | Reflection detection is string-matching on raw HTML body | Headless browser executes response, checks DOM for injected elements |
| 6 | Payload-agnostic fuzzer | Same oracle for all 16 vuln classes | Per-class confirmation functions with class-specific evidence patterns |
| 7 | No distributed scanning | Types + partitioning exist, no network transport | TCP-based coordinator/worker protocol with heartbeat and result streaming |
| 8 | Subprocess-based Python/Rust IPC | `std::process::Command` + stdout JSON | Length-prefixed IPC over Unix domain socket with bidirectional streaming |

---

## Gap 1: Headless Browser Crawler

### Design

New crate: `crates/crawler/` — wraps headless Chromium via `chromiumoxide` (CDP protocol).

```
Crawler
  ├── browser_pool: Vec<BrowserTab>        // pre-launched tabs, reused
  ├── visited: HashSet<NormalizedUrl>       // dedup
  ├── queue: VecDeque<CrawlTask>           // BFS frontier
  ├── max_depth: u32                       // default 3
  ├── max_pages: u32                       // default 500
  └── scope_regex: Regex                   // restrict crawl to target domain
```

```
struct CrawlResult {
    discovered_endpoints: Vec<DiscoveredEndpoint>,
    forms: Vec<DiscoveredForm>,
    js_sources: Vec<String>,                 // URLs of <script src="...">
    dom_event_handlers: Vec<DomEventHandler>, // onclick, onsubmit, etc.
}

struct DiscoveredEndpoint {
    url: String,
    method: String,             // from form method or "GET" for links
    parameters: Vec<Parameter>, // form inputs, query params
    source: DiscoverySource,    // Link, Form, JavaScript, ApiCall
}

enum DiscoverySource {
    Link,
    Form,
    JavaScript,     // extracted from XHR/fetch intercepted via CDP
    ApiCall,        // runtime network intercept
    OpenApiSpec,
    SourceCode,
}
```

**Pseudocode:**

```
fn crawl(target_url, config) -> CrawlResult:
    validate_target(target_url, scope_attestation)
    browser = launch_headless_chromium()
    queue = [CrawlTask { url: target_url, depth: 0 }]
    visited = {}
    result = CrawlResult::empty()

    while queue is not empty AND result.endpoints.len() < max_pages:
        task = queue.pop_front()
        if task.url in visited OR task.depth > max_depth:
            continue
        visited.insert(normalize(task.url))

        // Enable CDP network interception to capture XHR/fetch calls
        enable_network_intercept(browser)

        page = browser.navigate(task.url)
        wait_for_idle(page, timeout=5s)  // networkIdle event

        // Extract links, forms, and JS event handlers from rendered DOM
        links = extract_links(page.dom())
        forms = extract_forms(page.dom())
        handlers = extract_event_handlers(page.dom())
        intercepted_apis = collect_intercepted_requests()

        result.forms.extend(forms)
        result.dom_event_handlers.extend(handlers)

        for link in links:
            if in_scope(link, scope_regex):
                queue.push(CrawlTask { url: link, depth: task.depth + 1 })
                result.discovered_endpoints.push(endpoint_from_link(link))

        for api_call in intercepted_apis:
            result.discovered_endpoints.push(endpoint_from_api_call(api_call))

        // Collect <script src> for Gap 5 JS analysis
        result.js_sources.extend(extract_script_sources(page.dom()))

    browser.close()
    return result
```

**Pipeline Integration:**

```
// In orchestrator pipeline.rs, add new phase between recon and fingerprint:
fn run_crawl_phase(ctx, config) -> Vec<OperationLogEntry>:
    crawler = Crawler::new(config)
    crawl_result = crawler.crawl(ctx.target_url)

    ops = []
    for endpoint in crawl_result.discovered_endpoints:
        ops.push(AddNode { type: Endpoint, properties: { path, method, discovery_source } })

    for form in crawl_result.forms:
        ops.push(AddNode { type: Endpoint, properties: { path, method: form.method } })
        // Add edges from form to its parameters
        for param in form.inputs:
            ops.push(AddNode { type: Parameter, properties: { name, type, location } })

    ctx.graph.apply_operations(&ops)
    return ops
```

### Integration Tests

```
#[test] crawler_discovers_all_express_app_endpoints
    // Launch express-vuln-app Docker container
    // Run crawler against http://localhost:3000
    // Assert: discovers >= 14 of 17 known endpoints (some need auth)
    // Assert: each endpoint has correct HTTP method
    // Assert: form parameters extracted for POST endpoints

#[test] crawler_respects_max_depth
    // Create a simple chain: page1 -> page2 -> page3 -> page4
    // Set max_depth=2
    // Assert: page4 NOT discovered

#[test] crawler_respects_scope_regex
    // Page links to external domain
    // Assert: external links NOT followed

#[test] crawler_captures_xhr_fetch_calls
    // Express endpoint that triggers XHR from client JS
    // Assert: intercepted API endpoint appears in discovered_endpoints
    // Assert: discovery_source == ApiCall

#[test] crawler_handles_js_rendered_content
    // Page that renders links via JavaScript (not in initial HTML)
    // Assert: JS-rendered links discovered after wait_for_idle

#[test] crawler_deduplicates_urls
    // Multiple pages link to same endpoint
    // Assert: endpoint appears exactly once

#[test] crawler_extracts_form_parameters
    // HTML form with text, select, checkbox inputs
    // Assert: all input names + types captured in DiscoveredForm

#[test] crawler_integrates_with_pipeline_graph
    // Run crawl phase, then verify graph contains Endpoint nodes
    // with discovery_source property set

#[test] crawler_timeout_does_not_hang
    // Target that serves slowly (sleep 30s)
    // Assert: crawl completes within max_timeout, partial results returned
```

---

## Gap 2: Authenticated Scanning

### Design

Wire existing `AuthFlow` / `AuthFlowStep` / `AuthFlowState` from `enumeration::auth_flow` into the pipeline. New struct `AuthenticatedSession` holds the resolved tokens/cookies.

```
struct AuthenticatedSession {
    variables: HashMap<String, String>,  // extracted tokens, session IDs
    cookies: Vec<(String, String)>,       // name=value pairs to inject
    headers: Vec<(String, String)>,       // Authorization: Bearer xyz, etc.
    is_valid: bool,
}
```

**Pseudocode:**

```
fn execute_auth_flow(flow: AuthFlow, transport: &mut EvasionTransport, inputs: HashMap<String, String>) -> Result<AuthenticatedSession>:
    state = AuthFlowState { variables: inputs, completed_steps: [], is_authenticated: false }

    for step in flow.steps:
        // Render body template with current variables
        body = render_template(step.body_template, &state.variables)
        request = build_request(step.endpoint, step.method, body)

        response = transport.send(&request).await
        if response.status_code != step.expected_status:
            return Err(StepFailed { step.step_id, expected, actual })

        // Extract values from response
        for extraction in step.extract_from_response:
            value = match extraction.source:
                Header(name) => response.headers.get(name)
                JsonPath(path) => json_path_extract(response.body, path)
                Cookie(name) => extract_cookie(response.headers, name)
                StatusCode => response.status_code.to_string()
            state.variables.insert(extraction.variable_name, value)

        state.completed_steps.push(step.step_id)

    state.is_authenticated = true
    return Ok(build_authenticated_session(state))

fn inject_auth_into_request(request: &mut FuzzRequest, session: &AuthenticatedSession):
    for (name, value) in &session.headers:
        request.headers.push((name.clone(), value.clone()))
    for (name, value) in &session.cookies:
        request.headers.push(("Cookie".to_string(), format!("{name}={value}")))
```

**Pipeline Integration:**

```
// In phase_fuzz.rs, before fuzzing loop:
fn run_fuzz(ctx, ...) -> FuzzPhaseResult:
    authenticated_session = if ctx.auth_flow.is_some():
        let flow = ctx.auth_flow.unwrap()
        Some(execute_auth_flow(flow, &mut transport, ctx.auth_inputs).await?)
    else:
        None

    for target in scheduler:
        request = build_fuzz_request(target)
        if let Some(session) = &authenticated_session:
            inject_auth_into_request(&mut request, session)

        // Re-authenticate if session expired (401 response)
        response = transport.send(&request).await
        if response.status_code == 401 && authenticated_session.is_some():
            authenticated_session = Some(execute_auth_flow(...).await?)
            inject_auth_into_request(&mut request, authenticated_session.unwrap())
            response = transport.send(&request).await

        anomalies = oracle.analyze_response(...)
```

**CLI Flags:**

```
--auth-flow <path.json>     Path to auth flow definition JSON
--auth-input <key=value>    Auth flow input variables (repeatable)
```

### Integration Tests

```
#[test] auth_flow_login_and_fuzz_express_app
    // Express app with /api/login endpoint returning JWT
    // Auth flow: POST /api/login { username, password } -> extract token from JSON
    // Fuzz authenticated endpoints with injected Bearer token
    // Assert: fuzz results include findings from auth-protected endpoints

#[test] auth_flow_cookie_session
    // Express app with session cookie auth
    // Auth flow: POST /login -> extract Set-Cookie -> inject into subsequent requests
    // Assert: fuzz requests carry session cookie

#[test] auth_flow_re_authenticates_on_401
    // Short-lived session that expires after 5 requests
    // Assert: pipeline re-executes auth flow when 401 received
    // Assert: scanning continues after re-authentication

#[test] auth_flow_missing_variable_fails_gracefully
    // Auth flow requires "csrf_token" but extraction fails
    // Assert: error is AuthFlowError::ExtractionFailed
    // Assert: pipeline logs warning and continues without auth

#[test] auth_flow_detects_session_fixation
    // Server that returns same session ID regardless of credentials
    // Assert: AuthFlowVulnerability::SessionFixation flagged
    // Assert: finding added to knowledge graph

#[test] auth_flow_variables_persist_across_steps
    // Multi-step auth: step 1 extracts CSRF token, step 2 uses it in body
    // Assert: template {{csrf_token}} correctly rendered in step 2

#[test] auth_flow_integrates_with_evasion_transport
    // Auth flow requests go through EvasionTransport
    // Assert: persona headers applied to auth requests
    // Assert: timing jitter applied between auth steps
```

---

## Gap 3: Remote Target via Scope Attestation

### Design

Modify the 3-layer target validation to accept remote targets when a valid Ed25519-signed `SignedScopeAttestation` is provided.

```
// New function in target_validation.rs:
fn validate_target(url: &str, attestation: Option<&SignedScopeAttestation>) -> Result<(), TargetValidationError>:
    // Always allow localhost
    if validate_target_is_localhost(url).is_ok():
        return Ok(())

    // Remote requires valid attestation
    match attestation:
        Some(att) =>
            verify_attestation(att, url)?  // checks Ed25519 sig, expiry, target match
            return Ok(())
        None =>
            return Err(NonLocalhostTarget { host })
```

**Transport Layer Changes:**

```
// EvasionTransport gains attestation field:
struct EvasionTransport {
    ...existing fields...
    scope_attestation: Option<SignedScopeAttestation>,
}

// In send():
fn send(&mut self, request: &FuzzRequest) -> Result<FuzzResponse>:
    validate_target(&request.endpoint, self.scope_attestation.as_ref())?
    ...rest of existing logic...
```

**CLI:**

```
--scope-attestation <path>  Path to signed scope attestation JSON
--target <url>              Target URL (localhost or attested remote)
```

**Attestation Generation Tool:**

```
// New binary: aegis-attest (or subcommand: aegis attest)
fn generate_attestation(target, authorized_by, valid_days, key_path) -> SignedScopeAttestation:
    key = load_or_generate_signing_key(key_path)
    document = ScopeDocument {
        target,
        authorized_by,
        valid_until: today + valid_days,
        scope_id: uuid(),
    }
    return sign_scope_document(&document, &key)
```

### Integration Tests

```
#[test] remote_target_rejected_without_attestation
    // Set target to http://example.com (non-localhost)
    // No attestation provided
    // Assert: TargetValidationError::NonLocalhostTarget

#[test] remote_target_accepted_with_valid_attestation
    // Generate Ed25519 keypair
    // Sign attestation for http://example.com
    // validate_target(url, Some(attestation))
    // Assert: Ok(())

#[test] remote_target_rejected_with_expired_attestation
    // Sign attestation with valid_until = yesterday
    // Assert: AttestationError::Expired

#[test] remote_target_rejected_with_wrong_target
    // Sign attestation for http://example.com
    // Validate against http://other.com
    // Assert: AttestationError::TargetMismatch

#[test] remote_target_rejected_with_tampered_signature
    // Valid attestation, then flip a byte in signature_hex
    // Assert: AttestationError::InvalidSignature

#[test] localhost_always_accepted_without_attestation
    // validate_target("http://localhost:3000", None)
    // Assert: Ok(())

#[test] transport_enforces_attestation_on_remote
    // Build EvasionTransport with attestation for example.com
    // send() to example.com -> network call attempted (not rejected by validation)
    // Build EvasionTransport WITHOUT attestation
    // send() to example.com -> TransportError::TargetNotAllowed

#[test] fuzz_executor_enforces_attestation_on_remote
    // Verify third validation layer (fuzzing executor) also checks attestation

#[test] pipeline_loads_attestation_from_cli_flag
    // --scope-attestation /tmp/test.json --target http://remote:8080
    // Assert: attestation loaded and passed to transport + executor

#[test] attestation_generation_roundtrip
    // Generate keypair -> sign document -> save JSON -> load -> verify
    // Assert: full roundtrip succeeds

#[test] attestation_url_normalization
    // Sign for "HTTP://Example.COM:80/path/"
    // Verify against "http://example.com/path"
    // Assert: Ok(()) (trailing slash, case, default port all normalized)
```

---

## Gap 4: Detection Rate Improvement (19% -> 60%+ recall)

### Design

Three-pronged approach:

**A. Expanded payload templates** — Triple the template count per vuln class with diverse encoding variants.

```
// Add to mutator.rs build_default_templates():

// SqlInjection: add blind, error-based, UNION, stacked, second-order
"1' AND (SELECT SLEEP(5))--"
"1 AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--"
"' OR ''='"
"-1 UNION SELECT username,password FROM users--"
"1; EXEC xp_cmdshell('id')--"

// CrossSiteScripting: add event handler, DOM, mutation XSS
"<details open ontoggle=alert(1)>"
"<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>"
"\"><svg/onload=fetch('//attacker')>"
"'-alert(1)-'"
"<iframe srcdoc='<script>alert(1)</script>'>"

// CommandInjection: add out-of-band, encoding variants
"$(sleep 5)"
"| sleep 5 #"
";ping -c 5 127.0.0.1"
"`sleep 5`"
"\nid\n"
"a]b[$(id)"

// PathTraversal: add null byte, double encoding, Windows
"..%252f..%252f..%252fetc/passwd"
"..%c0%afetc/passwd"
"..\\..\\..\\etc\\passwd"
"....//....//etc/passwd"
"/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

// SSTI: add Jinja2, Twig, Freemarker, Velocity
"{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
"#{T(java.lang.Runtime).getRuntime().exec('id')}"
"<#assign ex = 'freemarker.template.utility.Execute'?new()>${ex('id')}"
"${class.forName('java.lang.Runtime').getRuntime().exec('id')}"

// InsecureDeserialization: add Node.js, Python pickle, Java
'{"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id\")}()"}'
"cos\nsystem\n(S'id'\ntR."  // Python pickle
"aced0005..."  // Java serialized object header
```

**B. Vulnerability-specific confirmation signatures** (Gap 6 primary fix):

```
// New module: fuzzing/src/confirmation.rs
struct ConfirmationSignature {
    vuln_class: VulnerabilityClass,
    name: &'static str,
    check: fn(response: &FuzzResponse, payload: &str) -> Option<ConfirmationEvidence>,
}

struct ConfirmationEvidence {
    evidence_type: EvidenceType,
    confidence: f64,
    description: String,
}

enum EvidenceType {
    SqlErrorMessage,         // DB error in response body
    TimeBasedDelay,          // response_time > baseline * threshold
    ReflectedPayload,        // payload echoed in specific context
    StatusCodeChange,        // 200->500 or similar
    InformationDisclosure,   // stack traces, internal paths
    BehaviorDifference,      // different response for true vs false condition
    TemplateEvaluation,      // {{7*7}} -> 49 in response
    CommandOutput,           // OS command output patterns
    PathContents,            // file contents in response
    RedirectToExternal,      // Location header to attacker domain
    DeserializationMarker,   // serialized object execution evidence
}
```

See Gap 6 for full pseudocode.

**C. LLM-guided payload generation feedback loop:**

```
// Tighter integration with hypothesis-engine
fn generate_targeted_payloads(ctx, endpoint, vuln_class, previous_results) -> Vec<TaggedPayload>:
    // Feed oracle results back to LLM
    feedback = ScanContext {
        endpoint,
        vuln_class,
        previous_payloads: previous_results.payloads_tried,
        anomalies_found: previous_results.anomalies,
        waf_detected: ctx.defense_profile.waf_vendor,
        technology_stack: infer_tech_stack(previous_results),
    }

    hypotheses = hypothesis_engine.generate(feedback)
    payloads = hypothesis_engine.compile(hypotheses)

    // Merge with static payloads, dedup
    all_payloads = merge_unique(static_payloads, llm_payloads)
    return all_payloads
```

### Integration Tests

```
#[test] expanded_sqli_templates_detect_express_sqli
    // Express app with known SQLi at /api/users?id=
    // Run mutator.generate_payloads(SqlInjection, 50)
    // Send each against endpoint
    // Assert: at least one triggers oracle anomaly (error message or timing)

#[test] expanded_xss_templates_detect_express_xss
    // Express app with reflected XSS at /api/search?q=
    // Assert: at least one XSS payload reflected in response

#[test] ssti_templates_detect_flask_ssti
    // Flask app with SSTI at /template?name=
    // Assert: {{7*7}} or variant produces "49" in response body

#[test] time_based_sqli_detection
    // Endpoint vulnerable to SLEEP-based SQLi
    // Baseline: ~50ms, Payload with SLEEP(2): ~2000ms
    // Assert: TimingAnomaly detected with score > 0.8

#[test] combined_recall_on_express_ground_truth
    // Full pipeline scan of express-vuln-app
    // Assert: true_positives >= 10 (was 3, target 10+ out of 16)
    // Assert: recall >= 0.50 (stretch: 0.60)

#[test] combined_recall_on_flask_ground_truth
    // Full pipeline scan of flask-vuln-app
    // Assert: true_positives >= 5 (out of 7)

#[test] false_positive_rate_bounded
    // Scan an app with NO vulnerabilities (healthy express app)
    // Assert: findings_count <= 2 (ideally 0)

#[test] llm_feedback_improves_second_iteration
    // Run with --max-iterations 2
    // Assert: iteration 2 finds >= 1 new finding that iteration 1 missed
    // Assert: refuted_tracker prevents re-testing failed hypotheses
```

---

## Gap 5: JavaScript / DOM Analysis

### Design

Reuse the headless browser from Gap 1. After fuzzing sends a payload that shows ReflectionDetected in the raw response, verify it actually executes in the DOM.

```
// New module: crawler/src/dom_verifier.rs
struct DomVerificationResult {
    payload: String,
    endpoint: String,
    dom_executed: bool,         // did the payload fire in-browser?
    evidence: DomEvidence,
    confidence_boost: f64,      // added to existing confidence score
}

enum DomEvidence {
    AlertFired,                 // window.alert intercepted
    DomMutation,               // new <script> or event handler in DOM
    CookieAccess,              // document.cookie accessed
    NavigationAttempt,         // window.location changed
    FetchToExternal,           // fetch() to non-origin domain
    NoExecution,               // payload present in DOM but did not execute
}
```

**Pseudocode:**

```
fn verify_xss_in_dom(browser, endpoint, method, payload, auth_session) -> DomVerificationResult:
    // Instrument browser to catch JS execution
    page = browser.new_page()

    // Override window.alert to signal execution
    page.evaluate("window.__aegis_xss_fired = false; window.alert = function() { window.__aegis_xss_fired = true; }")

    // Also intercept other dangerous sinks
    page.evaluate("""
        window.__aegis_nav_attempt = false;
        Object.defineProperty(window, 'location', {
            set: function(v) { window.__aegis_nav_attempt = true; }
        });
    """)

    // Navigate to the endpoint with payload injected
    url = inject_payload_into_url(endpoint, payload, method)
    if auth_session:
        inject_cookies(page, auth_session.cookies)
    page.navigate(url)
    wait_for_idle(page, timeout=3s)

    // Check execution markers
    xss_fired = page.evaluate("window.__aegis_xss_fired")
    nav_attempt = page.evaluate("window.__aegis_nav_attempt")

    // Check DOM for injected elements
    dom_mutation = page.evaluate("""
        document.querySelectorAll('script:not([src])').length > 0 ||
        document.querySelectorAll('[onerror],[onload],[onclick]').length > 0
    """)

    evidence = if xss_fired: AlertFired
               elif nav_attempt: NavigationAttempt
               elif dom_mutation: DomMutation
               else: NoExecution

    return DomVerificationResult {
        payload, endpoint,
        dom_executed: evidence != NoExecution,
        evidence,
        confidence_boost: if dom_executed { 0.3 } else { -0.2 },
    }
```

**Pipeline Integration:**

```
// After fuzz phase, before report phase:
fn run_dom_verification_phase(ctx, fuzz_results) -> Vec<OperationLogEntry>:
    xss_findings = fuzz_results.findings.filter(|f| f.class == CrossSiteScripting)

    browser = launch_headless_chromium()
    ops = []

    for finding in xss_findings:
        result = verify_xss_in_dom(browser, finding.endpoint, finding.payload, ctx.auth_session)
        if result.dom_executed:
            // Upgrade evidence level
            ops.push(UpdateFinding {
                finding_id: finding.id,
                evidence_level: EvidenceLevel::Confirmed,
                confidence_score: finding.confidence + result.confidence_boost,
                description_suffix: format!("DOM verified: {}", result.evidence),
            })
        else:
            // Downgrade confidence
            ops.push(UpdateFinding {
                finding_id: finding.id,
                confidence_score: (finding.confidence - 0.2).max(0.0),
                description_suffix: "Reflected but not DOM-executable",
            })

    browser.close()
    return ops
```

### Integration Tests

```
#[test] dom_verifier_confirms_reflected_xss
    // Express endpoint that reflects <script>alert(1)</script> in HTML
    // Assert: dom_executed == true, evidence == AlertFired

#[test] dom_verifier_rejects_html_encoded_reflection
    // Express endpoint that HTML-encodes the payload (&lt;script&gt;)
    // Assert: dom_executed == false, evidence == NoExecution

#[test] dom_verifier_detects_event_handler_xss
    // Payload: <img src=x onerror=alert(1)>
    // Assert: dom_executed == true, evidence == DomMutation or AlertFired

#[test] dom_verifier_detects_dom_based_xss
    // Endpoint reads URL fragment and writes to innerHTML
    // Assert: dom_executed == true

#[test] dom_verifier_works_with_authenticated_session
    // XSS behind auth wall
    // Inject session cookies into browser page
    // Assert: page loads authenticated content, XSS verified

#[test] dom_verifier_timeout_on_slow_page
    // Page that never finishes loading
    // Assert: returns NoExecution within timeout, does not hang

#[test] dom_verification_upgrades_evidence_in_graph
    // Run fuzz phase -> dom verification phase
    // Check finding in graph: evidence_level should be Confirmed
    // Check confidence_score increased

#[test] dom_verification_downgrades_false_positive
    // Finding with reflected payload that is HTML-encoded
    // After dom verification: confidence decreased
    // Assert: in final SARIF, confidence_score < original
```

---

## Gap 6: Vulnerability-Specific Oracle Signatures

### Design

Replace the one-size-fits-all oracle with per-class confirmation functions that understand what each vuln class looks like when exploited.

```
// New: fuzzing/src/confirmation.rs

type ConfirmFn = fn(&FuzzResponse, &FuzzResponse, &str, &BaselineProfile) -> Option<ConfirmationEvidence>;

fn build_confirmation_registry() -> HashMap<VulnerabilityClass, Vec<ConfirmFn>>:
    registry = HashMap::new()

    registry.insert(SqlInjection, vec![
        confirm_sql_error_message,
        confirm_sql_time_delay,
        confirm_sql_boolean_diff,
        confirm_sql_union_column_count,
    ])

    registry.insert(CrossSiteScripting, vec![
        confirm_xss_reflection_in_html_context,
        confirm_xss_reflection_in_attribute,
        confirm_xss_reflection_in_js_context,
    ])

    registry.insert(CommandInjection, vec![
        confirm_cmd_output_patterns,
        confirm_cmd_time_delay,
    ])

    registry.insert(PathTraversal, vec![
        confirm_path_traversal_file_contents,
    ])

    registry.insert(ServerSideTemplateInjection, vec![
        confirm_ssti_evaluation,
    ])

    registry.insert(OpenRedirect, vec![
        confirm_redirect_to_payload_domain,
    ])

    registry.insert(InsecureDeserialization, vec![
        confirm_deserialization_error_pattern,
    ])

    registry.insert(ServerSideRequestForgery, vec![
        confirm_ssrf_internal_content,
    ])

    return registry
```

**Per-class confirmation pseudocode:**

```
fn confirm_sql_error_message(treatment, control, payload, baseline) -> Option<ConfirmationEvidence>:
    sql_error_patterns = [
        r"SQL syntax.*MySQL",
        r"ORA-\d{5}",
        r"PostgreSQL.*ERROR",
        r"SQLSTATE\[\w+\]",
        r"sqlite3\.OperationalError",
        r"Microsoft OLE DB Provider",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
    ]
    for pattern in sql_error_patterns:
        if regex_match(pattern, treatment.body) AND NOT regex_match(pattern, control.body):
            return Some(ConfirmationEvidence {
                evidence_type: SqlErrorMessage,
                confidence: 0.95,
                description: format!("SQL error pattern: {pattern}"),
            })
    return None

fn confirm_sql_time_delay(treatment, control, payload, baseline) -> Option<ConfirmationEvidence>:
    if NOT contains_time_keyword(payload):
        return None
    treatment_ms = treatment.response_time.as_millis()
    control_ms = control.response_time.as_millis()
    // Payload contained SLEEP(N) or pg_sleep(N)
    expected_delay_ms = extract_sleep_seconds(payload) * 1000
    if treatment_ms > control_ms + (expected_delay_ms * 0.8):
        return Some(ConfirmationEvidence {
            evidence_type: TimeBasedDelay,
            confidence: 0.90,
            description: format!("Time delay: {treatment_ms}ms vs control {control_ms}ms"),
        })
    return None

fn confirm_sql_boolean_diff(treatment, control, payload, baseline) -> Option<ConfirmationEvidence>:
    // For boolean-based blind SQLi: ' AND 1=1 vs ' AND 1=2
    // This needs TWO treatment requests
    // Caller must send both and pass them as treatment (true-condition) vs control (false-condition)
    if treatment.body != control.body AND treatment.status_code == control.status_code:
        similarity = simhash_similarity(simhash(treatment.body), simhash(control.body))
        if similarity < 0.85:  // bodies are meaningfully different
            return Some(ConfirmationEvidence {
                evidence_type: BehaviorDifference,
                confidence: 0.85,
                description: format!("Boolean blind SQLi: body similarity {similarity:.2}"),
            })
    return None

fn confirm_xss_reflection_in_html_context(treatment, control, payload, baseline) -> Option<ConfirmationEvidence>:
    // Check if payload appears in HTML body context (not inside attribute or script tag)
    if payload.len() >= 4 AND treatment.body.contains(payload):
        // Verify it's not HTML-encoded
        encoded = html_encode(payload)  // &lt;script&gt;
        if NOT treatment.body.contains(&encoded) OR treatment.body.contains(payload):
            // Check if the reflection is in a "dangerous" context
            if is_in_html_body_context(treatment.body, payload):
                return Some(ConfirmationEvidence {
                    evidence_type: ReflectedPayload,
                    confidence: 0.90,
                    description: "XSS payload reflected in HTML body context unencoded",
                })
    return None

fn confirm_ssti_evaluation(treatment, control, payload, baseline) -> Option<ConfirmationEvidence>:
    // Look for mathematical evaluation: {{7*7}} -> 49, {{7*'7'}} -> 7777777
    eval_markers = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("{{7*'7'}}", "7777777"),
        ("<%= 7*7 %>", "49"),
        ("#{7*7}", "49"),
    ]
    for (template, expected_result) in eval_markers:
        if payload.contains(template) OR payload == template:
            if treatment.body.contains(expected_result) AND NOT control.body.contains(expected_result):
                return Some(ConfirmationEvidence {
                    evidence_type: TemplateEvaluation,
                    confidence: 0.95,
                    description: format!("SSTI evaluation: {template} -> {expected_result}"),
                })
    return None

fn confirm_cmd_output_patterns(treatment, control, payload, baseline) -> Option<ConfirmationEvidence>:
    // Look for OS command output patterns
    cmd_output_patterns = [
        r"uid=\d+\(.*?\)\s+gid=\d+",     // id command output
        r"root:.*:0:0:",                     // /etc/passwd format
        r"total \d+\n.*rwx",                // ls -la output
        r"Windows IP Configuration",         // ipconfig output
        r"PRETTY_NAME=",                     // /etc/os-release
    ]
    for pattern in cmd_output_patterns:
        if regex_match(pattern, treatment.body) AND NOT regex_match(pattern, control.body):
            return Some(ConfirmationEvidence {
                evidence_type: CommandOutput,
                confidence: 0.95,
                description: format!("Command output pattern: {pattern}"),
            })
    return None

fn confirm_path_traversal_file_contents(treatment, control, payload, baseline) -> Option<ConfirmationEvidence>:
    file_content_patterns = [
        r"root:.*:0:0:",                     // /etc/passwd
        r"\[boot loader\]",                  // Windows boot.ini
        r"\[extensions\]",                   // Windows win.ini
        r"<!DOCTYPE.*html",                  // reading another page
    ]
    for pattern in file_content_patterns:
        if regex_match(pattern, treatment.body) AND NOT regex_match(pattern, control.body):
            return Some(ConfirmationEvidence {
                evidence_type: PathContents,
                confidence: 0.92,
                description: format!("File content pattern: {pattern}"),
            })
    return None

fn confirm_redirect_to_payload_domain(treatment, control, payload, baseline) -> Option<ConfirmationEvidence>:
    // Check Location header for redirect to attacker-controlled domain
    location = treatment.headers.find("location")
    if location.is_some():
        loc = location.unwrap()
        if loc.contains("evil.com") OR loc.starts_with("//") OR loc.starts_with(payload):
            return Some(ConfirmationEvidence {
                evidence_type: RedirectToExternal,
                confidence: 0.90,
                description: format!("Redirect to: {loc}"),
            })
    // Also check 3xx status codes
    if treatment.status_code >= 300 AND treatment.status_code < 400:
        if control.status_code < 300 OR control.status_code >= 400:
            return Some(ConfirmationEvidence {
                evidence_type: RedirectToExternal,
                confidence: 0.80,
                description: "Status changed to redirect",
            })
    return None
```

**Oracle Integration:**

```
// Modified oracle.analyze_response_with_control():
fn analyze_response_with_control(
    &self,
    treatment: &FuzzResponse,
    control: &FuzzResponse,
    payload: &str,
    endpoint: &str,
    method: &str,
    vuln_class: Option<VulnerabilityClass>,  // NEW parameter
) -> Vec<Anomaly>:
    // Existing generic anomaly detection
    anomalies = existing_generic_analysis(treatment, control, payload, endpoint, method)

    // NEW: class-specific confirmation
    if let Some(class) = vuln_class:
        if let Some(confirmers) = self.confirmation_registry.get(&class):
            let baseline = self.baselines.get(&(endpoint, method))
            for confirm_fn in confirmers:
                if let Some(evidence) = confirm_fn(treatment, control, payload, baseline):
                    anomalies.push(Anomaly {
                        request_id: treatment.request_id,
                        anomaly_type: AnomalyType::ContentAnomaly,
                        score: evidence.confidence,
                        description: format!("[{}] {}", class, evidence.description),
                    })

    return anomalies
```

### Integration Tests

```
#[test] sqli_error_confirmation_detects_mysql_error
    // Response body contains "You have an error in your SQL syntax; check the manual"
    // Control response has no such error
    // Assert: confirm_sql_error_message returns confidence 0.95

#[test] sqli_time_delay_confirmation
    // Payload: "1'; SELECT pg_sleep(2)--"
    // Treatment: 2100ms, Control: 50ms
    // Assert: confirm_sql_time_delay returns confidence 0.90

#[test] sqli_boolean_blind_confirmation
    // ' AND 1=1 returns normal page, ' AND 1=2 returns different page
    // Assert: confirm_sql_boolean_diff returns confidence 0.85

#[test] xss_reflection_confirmed_unencoded
    // Payload reflected as-is in HTML body
    // Assert: confirm_xss_reflection returns confidence 0.90

#[test] xss_reflection_rejected_when_encoded
    // Payload HTML-encoded in response
    // Assert: confirm_xss_reflection returns None

#[test] ssti_evaluation_confirmed
    // Send "{{7*7}}", response contains "49"
    // Assert: confirm_ssti_evaluation returns confidence 0.95

#[test] cmd_injection_output_confirmed
    // Response contains "uid=1000(www-data) gid=1000"
    // Assert: confirm_cmd_output_patterns returns confidence 0.95

#[test] path_traversal_etc_passwd_confirmed
    // Response contains "root:x:0:0:root:/root:/bin/bash"
    // Assert: confirm_path_traversal_file_contents returns confidence 0.92

#[test] open_redirect_confirmed_via_location_header
    // Response has Location: //evil.com
    // Assert: confirm_redirect_to_payload_domain returns confidence 0.90

#[test] class_specific_oracle_integrates_with_generic
    // Both generic anomaly AND class-specific confirmation fire
    // Assert: anomaly list contains both, highest confidence wins

#[test] confirmation_reduces_false_positives
    // Generic oracle flags a status code change
    // But class-specific check finds no vuln evidence
    // Assert: overall finding confidence is lower than pure generic

#[test] confirmation_registry_covers_all_exploitable_classes
    // Assert: registry has entries for at least:
    // SqlInjection, XSS, CmdInj, PathTraversal, SSTI, OpenRedirect, SSRF, InsecureDeser
    // (8 of 16 classes — remaining 8 are config/info-based, not confirmable via payload)
```

---

## Gap 7: Distributed Scanning (Network Transport)

### Design

Build TCP-based coordinator/worker protocol on top of existing `DistributedConfig`, `CoordinatorState`, and `WorkAssignment` types.

```
// New module: orchestrator/src/distributed_transport.rs

enum DistributedMessage {
    // Coordinator -> Worker
    AssignWork(WorkAssignment),
    Pause,
    Resume,
    Shutdown,

    // Worker -> Coordinator
    Register { worker_id: WorkerId, role: WorkerRole },
    Heartbeat { worker_id: WorkerId, status: WorkerStatus },
    FindingsBatch { worker_id: WorkerId, findings: Vec<OperationLogEntry> },
    WorkComplete { worker_id: WorkerId },
    Error { worker_id: WorkerId, message: String },
}
```

**Wire Protocol:**

```
// Reuse IpcFrame from protocol crate (length-prefixed JSON):
[4 bytes: length LE u32][JSON payload]

// Messages are DistributedMessage serialized to JSON
// TLS with mutual authentication using scope attestation keys
```

**Coordinator Pseudocode:**

```
fn run_coordinator(config: DistributedConfig, endpoints: Vec<String>, bind_addr: SocketAddr):
    listener = TcpListener::bind(bind_addr).await
    state = CoordinatorState::new(&config)
    graph = KnowledgeGraph::new()

    // Accept worker connections
    loop:
        match listener.accept().await:
            (stream, addr) =>
                spawn(handle_worker_connection(stream, &mut state, &graph))

fn handle_worker_connection(stream, state, graph):
    loop:
        msg = read_ipc_frame(stream).await
        match msg:
            Register { worker_id, role } =>
                state.register_worker(worker_id, role)
                assignments = state.assign_work(endpoints, strategy)
                send(stream, AssignWork(assignment_for_this_worker))

            Heartbeat { worker_id, status } =>
                state.update_worker_status(worker_id, ...)

            FindingsBatch { worker_id, findings } =>
                graph.apply_operations(&findings)
                state.collected_findings += findings.len()

            WorkComplete { worker_id } =>
                state.update_worker_status(worker_id, Completed, ...)
                if state.all_complete():
                    run_report_phase(graph)
                    broadcast(Shutdown)
```

**Worker Pseudocode:**

```
fn run_worker(coordinator_addr: SocketAddr, worker_id: WorkerId):
    stream = TcpStream::connect(coordinator_addr).await
    send(stream, Register { worker_id, role: FuzzWorker })

    loop:
        msg = read_ipc_frame(stream).await
        match msg:
            AssignWork(assignment) =>
                // Run fuzz phase for assigned endpoints only
                findings = run_local_fuzz(assignment.endpoints)
                send(stream, FindingsBatch { worker_id, findings })
                send(stream, WorkComplete { worker_id })

            Pause => pause_fuzzing()
            Resume => resume_fuzzing()
            Shutdown => break

    // Periodic heartbeat in background task
    spawn(heartbeat_loop(stream, worker_id, interval=5s))
```

**CLI:**

```
aegis scan --distributed --coordinator 0.0.0.0:9090 --workers 3
aegis worker --coordinator 10.0.0.1:9090 --worker-id worker-1
```

### Integration Tests

```
#[test] coordinator_accepts_worker_registration
    // Start coordinator on localhost:0 (random port)
    // Connect worker, send Register message
    // Assert: coordinator state has 1 registered worker

#[test] coordinator_assigns_work_to_workers
    // Register 3 workers with 12 endpoints
    // Assert: each worker gets 4 endpoints (round-robin)

#[test] worker_sends_findings_to_coordinator
    // Worker completes fuzz, sends FindingsBatch
    // Assert: coordinator graph contains the findings

#[test] coordinator_detects_failed_worker
    // Worker stops sending heartbeats
    // After timeout: detect_failed_workers returns that worker
    // Assert: rebalance redistributes its endpoints

#[test] coordinator_rebalances_on_failure
    // 3 workers, worker-2 fails
    // Assert: worker-2's endpoints reassigned to worker-1 and worker-3

#[test] distributed_scan_produces_same_results_as_local
    // Same target, same config
    // Run local scan -> findings_local
    // Run distributed scan (1 coordinator + 2 workers, same machine)
    // Assert: findings_distributed >= findings_local * 0.9
    // (Slight variance OK due to timing/nondeterminism)

#[test] coordinator_shutdown_after_completion
    // All workers send WorkComplete
    // Assert: coordinator produces report and sends Shutdown

#[test] wire_protocol_roundtrip
    // Encode DistributedMessage -> IpcFrame -> bytes -> decode
    // Assert: decoded == original for all message variants

#[test] coordinator_handles_concurrent_worker_messages
    // 5 workers sending heartbeats + findings simultaneously
    // Assert: no data corruption, all findings collected

#[test] tls_mutual_auth_rejects_unauthorized_worker
    // Worker connects without valid TLS cert
    // Assert: connection rejected
```

---

## Gap 8: Structured Python/Rust IPC via Unix Domain Socket

### Design

Replace `std::process::Command` + stdout JSON with persistent bidirectional IPC over Unix domain sockets. Rust side spawns Python process once, communicates via framed JSON messages.

```
// New module: orchestrator/src/hypothesis_bridge.rs

struct HypothesisBridge {
    child: Child,               // spawned Python process
    socket: UnixStream,         // bidirectional IPC
    request_counter: u64,
}

enum BridgeRequest {
    GenerateHypotheses {
        request_id: u64,
        scan_context: ScanContextJson,
        vulnerability_class: String,
        feedback_summary: Option<String>,
    },
    CompilePayloads {
        request_id: u64,
        hypotheses: Vec<HypothesisJson>,
    },
    EvasionGenerate {
        request_id: u64,
        defense_context: DefenseContextJson,
    },
    Shutdown,
}

enum BridgeResponse {
    Hypotheses {
        request_id: u64,
        hypotheses: Vec<HypothesisJson>,
        reasoning_trace: String,
        input_tokens: u64,
        output_tokens: u64,
    },
    CompiledPayloads {
        request_id: u64,
        payloads: Vec<String>,
        input_tokens: u64,
        output_tokens: u64,
    },
    Error {
        request_id: u64,
        message: String,
    },
}
```

**Rust Side Pseudocode:**

```
fn start_hypothesis_bridge(python_path: &str) -> HypothesisBridge:
    socket_path = format!("/tmp/aegis-hypothesis-{}.sock", std::process::id())
    listener = UnixListener::bind(socket_path)

    child = Command::new(python_path)
        .args(["-m", "hypothesis_engine.bridge", "--socket", socket_path])
        .spawn()

    // Wait for Python to connect
    stream = listener.accept(timeout=10s)

    // Verify handshake
    msg = read_ipc_frame(stream)
    assert(msg == BridgeResponse::Ready)

    return HypothesisBridge { child, socket: stream, request_counter: 0 }

fn generate_hypotheses(&mut self, ctx, vuln_class, feedback) -> Result<Vec<Hypothesis>>:
    self.request_counter += 1
    request = BridgeRequest::GenerateHypotheses {
        request_id: self.request_counter,
        scan_context: serialize_context(ctx),
        vulnerability_class: format!("{:?}", vuln_class),
        feedback_summary: feedback,
    }

    write_ipc_frame(self.socket, &request)
    response = read_ipc_frame(self.socket, timeout=120s)

    match response:
        BridgeResponse::Hypotheses { hypotheses, tokens, ... } =>
            return Ok(deserialize_hypotheses(hypotheses))
        BridgeResponse::Error { message, ... } =>
            return Err(BridgeError::PythonError(message))
```

**Python Side Pseudocode:**

```python
# hypothesis_engine/bridge.py
import socket, json, struct

def main(socket_path: str):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(socket_path)

    # Send ready handshake
    send_frame(sock, {"type": "Ready"})

    generator = HypothesisGenerator(create_backend())
    compiler = HypothesisCompiler(create_backend())

    while True:
        request = read_frame(sock)
        if request["type"] == "Shutdown":
            break

        try:
            if request["type"] == "GenerateHypotheses":
                result, token_usage = generator.generate(
                    scan_context=request["scan_context"],
                    vulnerability_class=request["vulnerability_class"],
                    feedback=request.get("feedback_summary"),
                )
                send_frame(sock, {
                    "type": "Hypotheses",
                    "request_id": request["request_id"],
                    "hypotheses": [h.dict() for h in result],
                    "reasoning_trace": result.reasoning_trace,
                    "input_tokens": token_usage.input_tokens,
                    "output_tokens": token_usage.output_tokens,
                })

            elif request["type"] == "CompilePayloads":
                payloads = compiler.compile(request["hypotheses"])
                send_frame(sock, {
                    "type": "CompiledPayloads",
                    "request_id": request["request_id"],
                    "payloads": payloads,
                    ...
                })

        except Exception as e:
            send_frame(sock, {
                "type": "Error",
                "request_id": request["request_id"],
                "message": str(e),
            })

def read_frame(sock) -> dict:
    length_bytes = sock.recv(4)
    length = struct.unpack('<I', length_bytes)[0]
    data = sock.recv(length)
    return json.loads(data)

def send_frame(sock, msg: dict):
    payload = json.dumps(msg).encode()
    sock.sendall(struct.pack('<I', len(payload)) + payload)
```

### Integration Tests

```
#[test] bridge_starts_and_handshakes
    // Start HypothesisBridge
    // Assert: Python process spawned, Ready handshake received

#[test] bridge_generates_hypotheses_via_socket
    // Send GenerateHypotheses request
    // Assert: response contains hypotheses array
    // Assert: token counts are non-zero

#[test] bridge_compiles_payloads_via_socket
    // Send CompilePayloads request
    // Assert: response contains compiled payload strings

#[test] bridge_handles_python_error_gracefully
    // Send malformed request that causes Python exception
    // Assert: BridgeResponse::Error returned with message
    // Assert: bridge still functional (not crashed)

#[test] bridge_handles_python_crash
    // Kill Python child process
    // Assert: next request returns error (not hang)
    // Assert: bridge detects process exit

#[test] bridge_respects_timeout
    // Python side sleeps for 300s before responding
    // Rust side has 120s timeout
    // Assert: timeout error returned, bridge recoverable

#[test] bridge_shutdown_clean
    // Send Shutdown request
    // Assert: Python process exits cleanly
    // Assert: socket file cleaned up

#[test] bridge_concurrent_requests_serialized
    // Two generate_hypotheses calls in rapid succession
    // Assert: responses arrive in order, no interleaving

#[test] bridge_request_response_id_matching
    // Send multiple requests
    // Assert: each response has matching request_id

#[test] bridge_integrates_with_pipeline
    // Full pipeline with --no-llm=false
    // Assert: hypothesis generation uses bridge (not subprocess)
    // Assert: token counts propagated to ScanMetrics
```

---

## Test Gaps from Previous Phases

These tests address weaknesses identified during Phase 1 and Phase 2 work.

### SARIF Extraction Robustness

```
#[test] sarif_extraction_handles_missing_vulnerability_class
    // SARIF result with endpoint but no vulnerabilityClass
    // Assert: extraction skips this result without panic

#[test] sarif_extraction_handles_debug_vs_display_format
    // SARIF emitter uses format!("{:?}", vc) -> "SqlInjection"
    // Ground truth uses the same Debug format
    // Assert: extraction matches both Debug ("SqlInjection") and Display ("SQL Injection")

#[test] sarif_extraction_with_empty_results_array
    // SARIF with runs[0].results = []
    // Assert: extracted findings is empty HashSet, no error
```

### Ground Truth Comparison Edge Cases

```
#[test] ground_truth_comparison_case_insensitive_endpoint
    // Ground truth: "/API/users", SARIF: "/api/users"
    // Assert: matched (case-insensitive comparison on path)

#[test] ground_truth_comparison_trailing_slash
    // Ground truth: "/api/users/", SARIF: "/api/users"
    // Assert: matched (trailing slash normalized)

#[test] ground_truth_comparison_with_query_params
    // Ground truth: "/api/search", SARIF: "/api/search?q=test"
    // Assert: matched (query params stripped for comparison)
```

### Counterfactual Oracle Robustness

```
#[test] counterfactual_eliminates_flaky_endpoint_false_positives
    // Non-deterministic endpoint that returns 500 randomly
    // Both control AND treatment get 500
    // Assert: no anomaly reported (counterfactual filters it)

#[test] counterfactual_preserves_reflection_regardless_of_control
    // Control has no reflection, treatment has payload reflected
    // Assert: ReflectionDetected anomaly survives counterfactual filter
```

### Knowledge Graph Concurrency

```
#[test] concurrent_apply_operations_no_data_loss
    // 10 threads each applying 100 operations simultaneously
    // Assert: graph contains all 1000 nodes/edges/findings
    // Assert: no GraphError returned

#[test] concurrent_read_during_write
    // Reader thread queries graph continuously
    // Writer thread applies operations continuously
    // Assert: reader never sees partial state
    // Assert: no deadlock within 10 seconds
```

### Pipeline Checkpoint Resume

```
#[test] checkpoint_resume_skips_completed_phases
    // Run scan through fuzz phase, save checkpoint
    // Resume from checkpoint
    // Assert: recon and fingerprint phases NOT re-run
    // Assert: fuzz phase re-run (was in-progress when checkpointed)

#[test] checkpoint_deleted_on_successful_completion
    // Full scan completes normally
    // Assert: checkpoint file does not exist

#[test] checkpoint_preserves_graph_state
    // Run recon, save checkpoint
    // Load checkpoint, check graph
    // Assert: recon-discovered nodes present in loaded graph
```

### Evasion Transport

```
#[test] persona_rotation_produces_different_headers
    // Transport with rotation_interval=1
    // Send 3 requests
    // Assert: User-Agent header changes between requests

#[test] timing_jitter_varies_between_requests
    // Send 20 requests, measure inter-request timing
    // Assert: standard deviation of delays > 0 (not constant)

#[test] transport_rejects_non_localhost_without_attestation
    // send() to http://example.com
    // Assert: TransportError::TargetNotAllowed
```

### Benchmark Evaluation

```
#[test] benchmark_f1_is_zero_when_no_findings
    // 0 true positives, 0 false positives, N false negatives
    // Assert: precision = 0.0, recall = 0.0, f1 = 0.0

#[test] benchmark_perfect_score
    // All ground truth matched, no false positives
    // Assert: precision = 1.0, recall = 1.0, f1 = 1.0

#[test] benchmark_per_class_metrics
    // Mix of SQLi and XSS findings, some correct some not
    // Assert: per-class precision/recall computed independently
```

---

## Dependency Graph

```
Gap 1 (Crawler) ← independent, needed by Gap 5
Gap 2 (Auth Scanning) ← independent
Gap 3 (Remote Targets) ← independent, needed by Gap 7
Gap 4 (Detection Rate) ← depends on Gap 6 (class-specific signatures)
Gap 5 (DOM Analysis) ← depends on Gap 1 (browser engine)
Gap 6 (Vuln Signatures) ← independent, highest impact
Gap 7 (Distributed) ← depends on Gap 3 (remote targets useful), Gap 8 (IPC pattern)
Gap 8 (Python IPC) ← independent
```

**Recommended implementation order:**

1. Gap 6 (Vuln-Specific Signatures) — highest recall impact, no dependencies
2. Gap 3 (Remote Targets) — small change, unblocks Gap 7
3. Gap 8 (Python IPC) — foundational improvement
4. Gap 2 (Auth Scanning) — wiring existing types
5. Gap 4 (Detection Rate) — builds on Gap 6
6. Gap 1 (Crawler) — new crate
7. Gap 5 (DOM Analysis) — builds on Gap 1
8. Gap 7 (Distributed) — most complex, do last

---

## Success Criteria

| Metric | Current | Target |
|--------|---------|--------|
| Express E2E recall | 19% (3/16) | >= 60% (10/16) |
| Flask E2E recall | ~57% (4/7) | >= 85% (6/7) |
| False positive rate | ~85% (17/20) | <= 40% |
| GraphQL E2E recall | untested | >= 50% (4/8) |
| Docker integration tests | 34 | >= 75 |
| Rust unit tests | 2,377 | >= 3,000 |
| Endpoint discovery (crawler) | OpenAPI/source only | >= 80% of routes via crawling |
| Auth-protected finding detection | 0 | >= 3 per auth-protected app |
