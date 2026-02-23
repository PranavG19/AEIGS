# AEGIS Security Assessment SOP

AEGIS is an adversarial vulnerability discovery framework that performs automated security testing against web applications. It combines static source code analysis, dependency auditing, HTTP fuzzing with counterfactual anomaly detection, LLM-powered hypothesis generation, and attack graph synthesis to discover vulnerabilities. This SOP provides step-by-step instructions for an LLM agent to operate AEGIS for a complete security assessment.

## Parameters

| Parameter | Required | Default | Values | Description |
|---|---|---|---|---|
| `target_url` | yes | -- | URL string | The base URL of the application to scan |
| `authorization` | yes | -- | `localhost` \| `authorized` \| `attestation:<path>` | How you are authorized to scan the target |
| `intensity` | yes | -- | `quick` \| `thorough` \| `paranoid` | Scan depth preset |
| `source_access` | no | `none` | `none` \| path to source directory | Path to application source code for static analysis |
| `llm_backend` | no | `none` | `none` \| `bedrock` \| `openai` \| `ollama` | LLM backend for hypothesis generation |
| `auth_credentials` | no | -- | JSON file path or key=value pairs | Authentication flow for scanning protected endpoints |
| `report_audience` | no | `developer` | `developer` \| `security` \| `executive` | Report format/audience |
| `business_context` | no | -- | JSON file path | Excluded endpoints, critical assets, known issues |
| `exploit_tools` | no | -- | List of tool names | External tools available for post-scan validation |

### Parameter Details

**authorization values:**
- `localhost` -- Target is on localhost/127.0.0.1. No extra flags needed (AEGIS enforces localhost-only by default).
- `authorized` -- You have written authorization to scan a remote target. Pass `--i-am-authorized`. Authorization is recorded in the audit trail.
- `attestation:<path>` -- You have an Ed25519-signed scope attestation file. Pass `--scope-attestation <path>`.

**intensity presets:**
- `quick` -- 1 iteration, no LLM, default stealth. Fast surface-level scan.
- `thorough` -- 3 iterations, LLM enabled, convergence threshold 2. Standard assessment.
- `paranoid` -- 5 iterations, LLM enabled, convergence threshold 3, paranoid stealth. Maximum coverage.

**report_audience formats:**
- `developer` -- SARIF 2.1.0 JSON with CWE IDs and inline fix suggestions. IDE-compatible.
- `security` -- SARIF enriched with MITRE ATT&CK technique IDs, attack chains, and defense gap analysis.
- `executive` -- Summary JSON with severity counts, risk rating, top 5 remediation priorities, and defense posture.

## Prerequisites

### Required

- **Rust toolchain**: nightly, edition 2024
- **Python 3.12+** with `uv` package manager
- **Built binary**: The orchestrator must be compiled before use

```bash
cargo build -p aegis-orchestrator --release
```

The binary is located at `./target/release/aegis-orchestrator`.

### Optional

- **Docker or Colima**: Required only for running fixture app integration tests
- **AWS Bedrock credentials**: Required if `llm_backend` is `bedrock` (default credentials chain: env vars, `~/.aws/credentials`, instance profile)
- **OpenAI API key**: Required if `llm_backend` is `openai` (set `OPENAI_API_KEY` env var)
- **ollama**: Required if `llm_backend` is `ollama` (must be running at `http://localhost:11434`)
- **jq**: For parsing SARIF output on the command line
- **External tools**: sqlmap, nuclei, nmap, subfinder, interactsh-client (for post-scan exploitation)

## Steps

### Step 1: Validate Environment

Verify all required components are available before starting.

```bash
# Verify the binary exists and runs
./target/release/aegis-orchestrator --help

# If the binary does not exist, build it
cargo build -p aegis-orchestrator --release
```

If `llm_backend` is not `none`, verify credentials:

```bash
# For bedrock:
aws sts get-caller-identity

# For openai:
test -n "$OPENAI_API_KEY" && echo "OpenAI key set" || echo "ERROR: OPENAI_API_KEY not set"

# For ollama:
curl -s http://localhost:11434/api/tags | head -c 200
```

If `exploit_tools` are specified, verify they are installed:

```bash
which sqlmap nuclei nmap subfinder interactsh-client 2>/dev/null
```

### Step 2: Pre-Scan Reconnaissance

This step is optional but recommended when `source_access` is provided. It parses lock files, discovers dependencies, and populates the vulnerability database.

**Update the vulnerability database from source dependencies:**

```bash
./target/release/aegis-orchestrator update-db \
  --source-dir <source_access_path> \
  --db-path ~/.aegis/vuln.db
```

This parses lock files (Cargo.lock, package-lock.json, poetry.lock, Gemfile.lock, go.sum, requirements.txt) in the source directory, queries the OSV API for known vulnerabilities, and writes results to the SQLite database at `~/.aegis/vuln.db`.

**Run standalone reconnaissance (optional, for preview):**

```bash
./target/release/aegis-orchestrator recon --source-dir <source_access_path>
```

This prints the number of graph operations discovered (dependencies, files, vulnerability matches) without running a full scan. Useful for verifying source access is working before committing to a full scan.

### Step 3: Prepare Authentication (if needed)

If the target requires authentication, create an auth flow JSON file.

**Auth flow file format** (`auth-flow.json`):

```json
{
  "name": "login-flow",
  "steps": [
    {
      "step_id": "login",
      "endpoint": "http://target:3000/api/login",
      "method": "POST",
      "body_template": "{\"username\": \"{{username}}\", \"password\": \"{{password}}\"}",
      "extract_from_response": [
        {
          "variable_name": "auth_token",
          "source": {"JsonPath": "$.token"}
        }
      ],
      "expected_status": 200
    }
  ],
  "required_inputs": ["username", "password"]
}
```

Extraction sources can be:
- `{"JsonPath": "$.path.to.field"}` -- Extract from JSON response body
- `{"Header": "Authorization"}` -- Extract from response header
- `{"Cookie": "session_id"}` -- Extract from Set-Cookie header
- `"StatusCode"` -- Extract the HTTP status code

### Step 4: Prepare Business Context (if needed)

If certain endpoints should be excluded or prioritized, create a business context JSON file.

**Business context file format** (`context.json`):

```json
{
  "excluded_endpoints": ["/health", "/metrics", "/api/internal/debug"],
  "critical_assets": ["/api/payments", "/api/users/admin"],
  "pii_endpoints": ["/api/users/profile", "/api/users/export"],
  "known_issues": [
    {
      "endpoint": "/api/legacy/search",
      "vulnerability_class": "SqlInjection"
    }
  ]
}
```

Known issues are annotated with SARIF suppressions rather than removed, preserving the audit trail while allowing downstream tooling to filter them.

### Step 5: Create Scope Attestation (if authorization is attestation-based)

For engagements requiring cryptographic proof of authorization:

```bash
./target/release/aegis-orchestrator attest \
  --target <target_url> \
  --authorized-by "Client Name <email@example.com>" \
  --valid-days 30 \
  --key signing-key.bin \
  --output scope-attestation.json
```

This generates an Ed25519 signing key (if `signing-key.bin` does not exist) and writes a signed scope attestation document. The scan will verify the signature, target match, and expiry before proceeding.

### Step 6: Execute Scan

Build the scan command from the input parameters. The command structure is:

```bash
./target/release/aegis-orchestrator \
  --target <target_url> \
  --preset <intensity> \
  -o findings.sarif \
  -f <report_audience> \
  --graph-db scan.json \
  --history-db scan-history.db \
  [authorization flags] \
  [source flags] \
  [llm flags] \
  [auth flags] \
  [scope flags] \
  [advanced flags]
```

**Authorization flags** (choose one based on `authorization` parameter):
- `localhost`: no flag needed (default behavior)
- `authorized`: add `--i-am-authorized`
- `attestation:<path>`: add `--scope-attestation <path>`

**Source flags** (if `source_access` is not `none`):
- `--source-dir <path>`
- `--vuln-db ~/.aegis/vuln.db` (if you ran `update-db` in Step 2)

**LLM flags:**
- If `llm_backend` is `none`: add `--no-llm`
- If `llm_backend` is `bedrock`, `openai`, or `ollama`: do not add `--no-llm` (LLM is enabled by default when a preset enables it; `thorough` and `paranoid` presets enable LLM)

**Auth flags** (if `auth_credentials` is provided):
- `--auth-flow auth-flow.json`
- `--auth-input username=admin --auth-input password=secret`

**Scope flags** (if `business_context` is provided):
- `--context-file context.json`

**Endpoint filtering:**
- `--include-endpoints /api/v1 /api/v2` (scan only these path prefixes)
- `--exclude-endpoints /health /metrics` (skip these paths)

**Advanced flags (optional):**
- `--verbose` or `-v`: Enable tracing output for debugging
- `--telemetry`: Write aggregate scan metrics to a JSON sidecar file
- `--stealth-level default|aggressive|paranoid`: Override preset stealth (default/aggressive/paranoid)
- `--persona chrome|firefox|safari|mobile|googlebot`: HTTP persona for evasion
- `--max-rps <n>`: Rate limit outgoing requests per second
- `--max-iterations <n>`: Override preset iteration count
- `--convergence-threshold <n>`: Stop after N consecutive rounds with zero new findings
- `--resume`: Resume a previously interrupted scan (requires `--graph-db`)
- `--interactive`: Enable interactive scan control (pause/resume/status/quit via stdin)
- `--no-audit`: Disable audit logging (not recommended for client engagements)
- `--export-graph dot|d3json`: Export attack graph visualization
- `--skip-fingerprint`: Skip HTTP defense fingerprinting phase
- `--skip-crawl`: Skip browser crawling phase
- `--skip-evasion`: Disable evasion transport layer
- `--accept-self-signed`: Accept self-signed TLS certificates on localhost targets

#### Complete Example Commands

**Quick localhost scan, no LLM:**

```bash
./target/release/aegis-orchestrator \
  --target http://localhost:3000 \
  --preset quick \
  -o findings.sarif \
  -f developer \
  --graph-db scan.json \
  --history-db scan-history.db
```

**Thorough scan of authorized remote target with LLM and source code:**

```bash
./target/release/aegis-orchestrator \
  --target https://staging.example.com \
  --preset thorough \
  --i-am-authorized \
  --source-dir ./client-app \
  --vuln-db ~/.aegis/vuln.db \
  -o findings.sarif \
  -f security \
  --graph-db scan.json \
  --history-db scan-history.db \
  --telemetry
```

**Paranoid scan with attestation, authentication, and business context:**

```bash
./target/release/aegis-orchestrator \
  --target https://app.client.com \
  --preset paranoid \
  --scope-attestation scope-attestation.json \
  --source-dir ./client-app \
  --vuln-db ~/.aegis/vuln.db \
  --auth-flow auth-flow.json \
  --auth-input username=admin \
  --auth-input password='$CLIENT_PASSWORD' \
  --context-file context.json \
  -o findings.sarif \
  -f security \
  --graph-db scan.json \
  --history-db scan-history.db \
  --export-graph dot \
  --telemetry
```

### Step 7: Interpret Results

The scan produces a SARIF 2.1.0 JSON file (for `developer` and `security` formats) or a summary JSON file (for `executive` format).

**Count findings by severity:**

```bash
jq '[.runs[0].results[] | .level] | group_by(.) | map({level: .[0], count: length})' findings.sarif
```

**List all findings with rule ID, message, and severity:**

```bash
jq '.runs[0].results[] | {ruleId: .ruleId, message: .message.text, level}' findings.sarif
```

**Extract findings with CWE IDs:**

```bash
jq '.runs[0].results[] | {
  ruleId: .ruleId,
  message: .message.text,
  level,
  cwe: (.taxa // [] | map(.id) | join(", "))
}' findings.sarif
```

**Count findings by vulnerability class (security format):**

```bash
jq '.runs[0].properties.securityAnalysis.findingCorrelations' findings.sarif
```

**Parse executive format:**

```bash
jq '{
  total: .total_findings,
  critical: .severity_counts.critical,
  high: .severity_counts.high,
  medium: .severity_counts.medium,
  low: .severity_counts.low,
  risk: .risk_summary,
  top_priorities: [.top_remediation_priorities[] | {rule: .rule_id, severity: .severity_rating, fix: .remediation}]
}' findings.sarif
```

**Interpret severity ratings** (based on composite score):
- Critical: composite >= 70.0
- High: composite >= 40.0
- Medium: composite >= 20.0
- Low: composite < 20.0

**Check for WAF bypass findings (security format):**

```bash
jq '.runs[0].properties.securityAnalysis.defenseGaps' findings.sarif
```

### Step 8: Post-Scan Exploitation (if exploit_tools available)

For each confirmed finding, use external tools to gather proof-of-impact evidence. This step converts scanner findings into demonstrable exploits for the client report.

**SQL Injection (sqlmap):**

```bash
# Extract SQLi findings
SQLI_ENDPOINTS=$(jq -r '.runs[0].results[] | select(.ruleId | test("sql"; "i")) | .locations[0].physicalLocation.artifactLocation.uri' findings.sarif)

# For each endpoint, run sqlmap
for endpoint in $SQLI_ENDPOINTS; do
  sqlmap -u "${endpoint}" --batch --level=3 --risk=2 --output-dir=./sqlmap-results/
done
```

**Known CVEs (nuclei):**

```bash
# Run nuclei with technology-specific templates
nuclei -u <target_url> -t cves/ -o nuclei-results.txt

# Or target specific technologies
nuclei -u <target_url> -tags express,nodejs -o nuclei-results.txt
```

**Network reconnaissance (nmap):**

```bash
# Service version detection on the target
nmap -sV -p- <target_host> -oN nmap-results.txt
```

**Subdomain enumeration (subfinder):**

```bash
subfinder -d <target_domain> -o subdomains.txt
```

**Out-of-band interaction testing (interactsh-client):**

```bash
# Start interactsh listener for SSRF/blind injection verification
interactsh-client -o interactions.txt &
INTERACT_URL=$(interactsh-client -json 2>/dev/null | jq -r '.url')
# Use $INTERACT_URL as payload in manual SSRF tests
```

### Step 9: Iterative Deepening (optional)

If the initial scan found few results or you need higher confidence:

**Re-run with increased intensity:**

```bash
# The --graph-db flag preserves previous findings
# Only new findings are added; duplicates are deduplicated
./target/release/aegis-orchestrator \
  --target <target_url> \
  --preset paranoid \
  --i-am-authorized \
  --graph-db scan.json \
  --history-db scan-history.db \
  -o findings-deep.sarif \
  -f security
```

**Resume an interrupted scan:**

If a scan was interrupted (Ctrl+C, network failure), resume from the last checkpoint:

```bash
./target/release/aegis-orchestrator \
  --target <target_url> \
  --preset thorough \
  --i-am-authorized \
  --graph-db scan.json \
  --history-db scan-history.db \
  --resume \
  -o findings.sarif \
  -f developer
```

The `--resume` flag requires `--graph-db`. The scanner loads the checkpoint file saved alongside the graph database, skips completed phases, and continues from where it stopped. The checkpoint file is deleted on successful scan completion.

**Focus on specific endpoints:**

```bash
./target/release/aegis-orchestrator \
  --target <target_url> \
  --preset thorough \
  --i-am-authorized \
  --include-endpoints /api/payments /api/admin \
  --graph-db scan.json \
  --history-db scan-history.db \
  -o findings-focused.sarif \
  -f developer
```

**Diff-mode reporting:**

When `--graph-db` points to a database from a previous scan, the output summary reports `new_findings_count` and `previously_known_count`. This enables differential reporting between assessment iterations.

### Step 10: Generate Final Report

The scan output is already in a client-deliverable format. Choose the appropriate format for your audience:

**For developers** (`-f developer`):
- SARIF 2.1.0 JSON importable into VS Code, GitHub Code Scanning, Azure DevOps
- Each finding includes CWE ID, location (endpoint + parameter), and remediation guidance
- Known issues from `context.json` are annotated with SARIF suppressions

**For security teams** (`-f security`):
- SARIF with additional `properties.securityAnalysis` block containing:
  - `attackChains`: Each finding mapped to MITRE ATT&CK technique IDs
  - `defenseGaps`: Defenses detected vs defenses bypassed
  - `findingCorrelations`: Findings grouped by vulnerability class

**For executives** (`-f executive`):
- Summary JSON with:
  - `severity_counts`: {critical, high, medium, low}
  - `risk_summary`: Overall risk rating (Critical/High/Medium/Low)
  - `top_remediation_priorities`: Top 5 findings with plain-English remediation
  - `defense_posture_summary`: WAF, rate limiting, bot detection status
  - `scan_metadata`: Target, duration, phases completed

**Export attack graph visualization:**

```bash
# DOT format (render with Graphviz)
./target/release/aegis-orchestrator \
  --target <target_url> \
  --preset thorough \
  --i-am-authorized \
  --graph-db scan.json \
  --export-graph dot \
  -o findings.sarif -f security

# Convert to PNG
dot -Tpng scan.dot -o attack-graph.png
```

**Verify audit log integrity:**

The scan output includes an audit log integrity check. If the scan was run with audit logging (the default), the output will print:

```
Audit log integrity: verified
```

If this says `FAILED`, the audit trail has been tampered with or corrupted.

## Troubleshooting

### Target unreachable

```
Scan failed: config: target must be localhost, got: example.com
```

AEGIS enforces localhost-only by default. For remote targets, add `--i-am-authorized` or provide a `--scope-attestation` file. Verify the target URL is reachable:

```bash
curl -s -o /dev/null -w "%{http_code}" <target_url>
```

### No findings

Possible causes and remediations:
- **Target is behind a WAF**: Try `--stealth-level paranoid` or `--preset paranoid`
- **Scan too shallow**: Increase intensity from `quick` to `thorough` or `paranoid`
- **Endpoints not discovered**: Provide source code via `--source-dir` for route parsing, or check if the target has an OpenAPI spec
- **LLM not enabled**: The `quick` preset disables LLM. Use `--preset thorough` for LLM-powered hypothesis generation
- **Endpoints filtered out**: Check `--include-endpoints` / `--exclude-endpoints` flags
- **Rate limited**: The scanner auto-detects rate limits but may back off too aggressively. Check with `--verbose`

### LLM errors

```
hypothesis bridge: subprocess failed
```

- **Bedrock**: Verify AWS credentials with `aws sts get-caller-identity`. Ensure the model `global.anthropic.claude-sonnet-4-6` is enabled in your Bedrock account.
- **OpenAI**: Verify `OPENAI_API_KEY` is set and valid.
- **ollama**: Verify ollama is running at `http://localhost:11434` and has a model pulled.
- **Fallback**: Use `--no-llm` to proceed with static-only fuzzing (no hypothesis generation). The scanner still performs route discovery, dependency auditing, and payload mutation.

### Build failures

```bash
# Clean and rebuild
cargo clean -p aegis-orchestrator
cargo build -p aegis-orchestrator --release
```

If Rust nightly features fail, ensure you are on the correct toolchain:

```bash
rustup override set nightly
```

### Rate limited by target

The scanner automatically detects rate limits and adjusts its request rate. If you see rate limit warnings in `--verbose` output:

- Use `--stealth-level paranoid` for maximum stealth (timing jitter, persona rotation, session management)
- Set an explicit rate cap: `--max-rps 5`
- Use `--persona googlebot` to mimic a search engine crawler

### Checkpoint/resume issues

```
WARNING: --resume requires --graph-db
```

The `--resume` flag only works when `--graph-db` is provided. The checkpoint file is saved as `<graph-db-path>.checkpoint.json`. If this file is corrupted, delete it and re-run the scan from scratch.

### Audit log errors

```
Scan failed: audit log: ...
```

By default, AEGIS requires audit logging and fails if the log cannot be created. If you do not need audit logging:

```bash
./target/release/aegis-orchestrator --target <url> --preset quick --no-audit -o findings.sarif
```

This is not recommended for client engagements.

## Vulnerability Classes Reference

AEGIS detects 34 vulnerability classes. Each class maps to a CWE ID and MITRE ATT&CK technique.

| Vulnerability Class | CWE | ATT&CK | Description |
|---|---|---|---|
| SQL Injection | CWE-89 | T1190 | SQL code injection via unsanitized input |
| Cross-Site Scripting | CWE-79 | T1189 | Script injection in rendered HTML |
| Command Injection | CWE-78 | T1059 | OS command execution via user input |
| Path Traversal | CWE-22 | T1083 | File access outside intended directory |
| Server-Side Request Forgery | CWE-918 | T1090 | Internal network requests via user input |
| Insecure Deserialization | CWE-502 | T1190 | Code execution via crafted serialized objects |
| Broken Authentication | CWE-287 | T1078 | Authentication bypass or weak credentials |
| Broken Authorization | CWE-863 | T1548 | Privilege escalation or access control bypass |
| Security Misconfiguration | CWE-16 | T1574 | Insecure default settings or exposed admin interfaces |
| Sensitive Data Exposure | CWE-200 | T1005 | Unprotected PII, credentials, or internal data |
| Server-Side Template Injection | CWE-1336 | T1221 | Code execution via template engine abuse |
| Header Injection | CWE-113 | T1071 | HTTP header manipulation via CR/LF injection |
| Open Redirect | CWE-601 | T1204 | Unvalidated redirect to attacker-controlled URL |
| CRLF Injection | CWE-93 | T1071 | Response splitting via CR/LF in input |
| Known Vulnerable Dependency | CWE-1395 | T1195 | Third-party library with published CVE |
| Insufficient Input Validation | CWE-20 | T1190 | Missing or weak input validation |
| NoSQL Injection | CWE-943 | T1190 | NoSQL query manipulation via user input |
| XML External Entity | CWE-611 | T1190 | XXE attacks via crafted XML input |
| Cross-Origin Misconfiguration | CWE-942 | T1189 | Permissive CORS or cross-origin policies |
| Missing Security Header | CWE-693 | T1574 | Absent X-Frame-Options, CSP, HSTS, etc. |
| JWT Vulnerability | CWE-347 | T1078 | JWT algorithm confusion, weak signing, or token forgery |
| HTTP Request Smuggling | CWE-444 | T1071 | Request desynchronization via ambiguous Content-Length/Transfer-Encoding |
| Race Condition | CWE-362 | T1190 | Time-of-check/time-of-use exploits |
| Subdomain Takeover | CWE-284 | T1584 | Dangling DNS records pointing to unclaimed services |
| Prototype Pollution | CWE-1321 | T1190 | JavaScript prototype chain modification |
| GraphQL Abuse | CWE-20 | T1190 | Introspection leaks, query batching, depth attacks |
| Cloud Misconfiguration | CWE-16 | T1574 | Exposed cloud metadata, permissive bucket policies |
| Clickjacking | CWE-1021 | T1189 | UI redress via iframe embedding |
| Cache Poisoning | CWE-349 | T1557 | Cache key manipulation to serve malicious content |
| Host Header Injection | CWE-644 | T1071 | Host header abuse for password reset poisoning, etc. |
| Insecure Direct Object Reference | CWE-639 | T1548 | Direct access to objects via predictable IDs |
| Information Disclosure | CWE-200 | T1005 | Stack traces, debug info, or internal paths exposed |
| Weak Cryptography | CWE-327 | T1600 | Use of broken or risky cryptographic algorithms |
| Mass Assignment | CWE-915 | T1190 | Unprotected object property binding from user input |

## Scan Pipeline Phases

The scanner executes phases in this order:

1. **Recon** -- Source code analysis: route parsing, lock file parsing, dependency enumeration, known CVE matching against vuln DB
2. **Crawl** -- Browser-based endpoint discovery (skippable with `--skip-crawl`)
3. **Fingerprint** -- HTTP defense profiling: WAF detection, rate limit probing, bot detection analysis (skippable with `--skip-fingerprint`)
4. **Fuzz** (iterative) -- Payload mutation and delivery with counterfactual anomaly detection. Priority-scheduled via novelty scoring. LLM hypotheses injected when available.
5. **DOM Verify** -- Client-side verification of reflected findings
6. **Analyze** -- Attack graph construction (petgraph DiGraph), path analysis, centrality ranking, mitigation impact estimation
7. **Report** -- SARIF/executive JSON emission with CWE, ATT&CK, defense context, and remediation guidance

When `--max-iterations` > 1, the fuzz-analyze loop repeats. The `--convergence-threshold` stops iteration early when N consecutive rounds discover zero new findings.

## Example Workflows

### Quick scan of a localhost development app

Scenario: Developer wants a fast check of their local Express.js app.

```bash
# Build
cargo build -p aegis-orchestrator --release

# Scan
./target/release/aegis-orchestrator \
  --target http://localhost:3000 \
  --preset quick \
  -o findings.sarif \
  -f developer

# Review
jq '.runs[0].results | length' findings.sarif
jq '.runs[0].results[] | {ruleId, message: .message.text, level}' findings.sarif
```

### Full assessment of a client website

Scenario: Freelance pentester with written authorization to scan `https://staging.client.com`. Source code provided. AWS Bedrock credentials available.

```bash
# Step 1: Build
cargo build -p aegis-orchestrator --release

# Step 2: Update vulnerability database from client source
./target/release/aegis-orchestrator update-db \
  --source-dir ./client-source \
  --db-path ~/.aegis/vuln.db

# Step 3: Create auth flow (if the app requires login)
cat > auth-flow.json << 'EOF'
{
  "name": "client-login",
  "steps": [
    {
      "step_id": "login",
      "endpoint": "https://staging.client.com/api/auth/login",
      "method": "POST",
      "body_template": "{\"email\": \"{{email}}\", \"password\": \"{{password}}\"}",
      "extract_from_response": [
        {"variable_name": "token", "source": {"JsonPath": "$.access_token"}}
      ],
      "expected_status": 200
    }
  ],
  "required_inputs": ["email", "password"]
}
EOF

# Step 4: Run thorough scan
./target/release/aegis-orchestrator \
  --target https://staging.client.com \
  --preset thorough \
  --i-am-authorized \
  --source-dir ./client-source \
  --vuln-db ~/.aegis/vuln.db \
  --auth-flow auth-flow.json \
  --auth-input email=test@example.com \
  --auth-input password=TestPass123 \
  -o findings.sarif \
  -f security \
  --graph-db scan.json \
  --history-db scan-history.db \
  --export-graph dot \
  --telemetry

# Step 5: Review findings
jq '[.runs[0].results[] | .level] | group_by(.) | map({level: .[0], count: length})' findings.sarif
jq '.runs[0].properties.securityAnalysis.defenseGaps' findings.sarif

# Step 6: Run sqlmap against confirmed SQLi findings
SQLI=$(jq -r '.runs[0].results[] | select(.ruleId | test("sql"; "i")) | .locations[0].physicalLocation.artifactLocation.uri' findings.sarif)
for url in $SQLI; do
  sqlmap -u "$url" --batch --level=3 --risk=2 --output-dir=./sqlmap-out/
done

# Step 7: Deep scan on high-priority endpoints
./target/release/aegis-orchestrator \
  --target https://staging.client.com \
  --preset paranoid \
  --i-am-authorized \
  --include-endpoints /api/payments /api/admin \
  --graph-db scan.json \
  --history-db scan-history.db \
  -o findings-deep.sarif \
  -f security

# Step 8: Generate executive summary for client
./target/release/aegis-orchestrator \
  --target https://staging.client.com \
  --preset quick \
  --i-am-authorized \
  --graph-db scan.json \
  -o executive-report.json \
  -f executive
```

### Dependency-only audit (no network scanning)

Scenario: Audit a project's dependencies for known CVEs without any network requests.

```bash
# Update vuln DB
./target/release/aegis-orchestrator update-db \
  --source-dir ./project-source \
  --db-path ~/.aegis/vuln.db

# Run recon-only scan (quick preset, no HTTP scanning needed)
./target/release/aegis-orchestrator \
  --target http://localhost:1 \
  --preset quick \
  --source-dir ./project-source \
  --vuln-db ~/.aegis/vuln.db \
  --skip-fingerprint \
  --skip-crawl \
  --no-audit \
  -o dep-audit.sarif \
  -f developer

# Check for Known Vulnerable Dependency findings
jq '.runs[0].results[] | select(.ruleId | test("dependency"; "i"))' dep-audit.sarif
```

### Scan with cryptographic scope attestation

Scenario: Enterprise engagement requiring formal proof of authorization with Ed25519-signed scope documents.

```bash
# Generate attestation (auto-generates signing key if it doesn't exist)
./target/release/aegis-orchestrator attest \
  --target https://app.enterprise.com \
  --authorized-by "Security Team Lead <secops@enterprise.com>" \
  --valid-days 14 \
  --key engagement-key.bin \
  --output scope-attestation.json

# Run scan with attestation
./target/release/aegis-orchestrator \
  --target https://app.enterprise.com \
  --preset thorough \
  --scope-attestation scope-attestation.json \
  --graph-db scan.json \
  --history-db scan-history.db \
  -o findings.sarif \
  -f security \
  --telemetry
```

## CLI Reference Summary

### Subcommands

| Subcommand | Description |
|---|---|
| *(default)* | Run a scan against the target URL |
| `recon` | Standalone source code reconnaissance |
| `attest` | Generate Ed25519-signed scope attestation |
| `update-db` | Populate vulnerability database from OSV API |

### Common Scan Flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--target <url>` | | (required) | Target URL to scan |
| `--preset <name>` | `-p` | (none) | Preset: quick, thorough, paranoid, benchmark |
| `--output <path>` | `-o` | `aegis-report.sarif` | Output report file path |
| `--report-format <fmt>` | `-f` | `developer` | Report format: developer, security, executive |
| `--source-dir <path>` | | (none) | Path to application source code |
| `--verbose` | `-v` | false | Enable debug tracing |

### Authorization Flags

| Flag | Default | Description |
|---|---|---|
| `--i-am-authorized` | false | Assert authorization for non-localhost targets |
| `--scope-attestation <path>` | (none) | Ed25519-signed scope document |
| `--signed-config <path>` | (none) | Signed scan configuration for tamper detection |
| `--no-audit` | false | Disable mandatory audit logging |

### Tuning Flags

| Flag | Default | Description |
|---|---|---|
| `--max-iterations <n>` | 1 | Maximum fuzz-analyze iterations |
| `--convergence-threshold <n>` | 2 | Stop after N rounds with zero new findings |
| `--stealth-level <level>` | `default` | Stealth mode: default, aggressive, paranoid |
| `--persona <name>` | `chrome` | HTTP persona: chrome, firefox, safari, mobile, googlebot |
| `--max-rps <n>` | (none) | Rate limit requests per second |
| `--include-endpoints <paths>` | (none) | Only scan these endpoint prefixes |
| `--exclude-endpoints <paths>` | (none) | Skip these endpoint prefixes |
| `--skip-fingerprint` | false | Skip defense fingerprinting phase |
| `--skip-crawl` | false | Skip browser crawling phase |
| `--skip-evasion` | false | Disable evasion transport |
| `--stealth` | false | Enable stealth mode |
| `--paranoia-sweep` | false | Enable paranoia sweep |

### Advanced Flags

| Flag | Default | Description |
|---|---|---|
| `--graph-db <path>` | (none) | Persistent graph database for incremental scanning |
| `--history-db <path>` | (none) | SQLite scan history for adaptive payload selection |
| `--vuln-db <path>` | (none; falls back to `~/.aegis/vuln.db` if it exists) | Vulnerability database path |
| `--export-graph <fmt>` | (none) | Export attack graph: dot, d3json |
| `--context-file <path>` | (none) | Business context JSON |
| `--auth-flow <path>` | (none) | Authentication flow JSON |
| `--auth-input <k=v>` | (none) | Auth flow template variables (repeatable) |
| `--no-llm` | false | Disable LLM hypothesis generation |
| `--bypass-corpus <path>` | (none) | Custom bypass payload corpus |
| `--python-cmd <cmd>` | `python3` | Python interpreter for hypothesis engine |
| `--resume` | false | Resume from checkpoint (requires --graph-db) |
| `--interactive` | false | Enable interactive scan control |
| `--telemetry` | false | Write aggregate metrics sidecar |
| `--accept-self-signed` | false | Accept self-signed TLS on localhost |
| `--persona-catalog <path>` | (none) | Custom persona catalog JSON |

### Distributed Scanning Flags

For multi-worker distributed scans. Coordinator partitions work across workers via heartbeat-based coordination.

| Flag | Default | Description |
|---|---|---|
| `--distributed` | false | Enable coordinator mode |
| `--coordinator-addr <host:port>` | `127.0.0.1:9100` | Coordinator bind address |
| `--workers <n>` | 1 | Number of workers to wait for before starting |
| `--worker-connect <host:port>` | (none) | Connect to coordinator as a worker |
| `--worker-id <id>` | `worker-0` | Worker identifier |

### Recon Subcommand

```
aegis-orchestrator recon --source-dir <path>
```

### Attest Subcommand

```
aegis-orchestrator attest \
  --target <url> \
  --authorized-by <string> \
  --valid-days <n> \
  --key <path> \
  [--output <path>]           # default: scope-attestation.json
```

### Update-DB Subcommand

```
aegis-orchestrator update-db \
  --source-dir <path> \
  [--db-path <path>]          # default: ~/.aegis/vuln.db
  [--full-refresh]            # clear and re-populate
```
