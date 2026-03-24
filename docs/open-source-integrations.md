# Open-Source Integration Plan

Zero reinvention. Every item below replaces or augments something AEGIS already does — using the exact
`ToolWrapper` trait pattern from `crates/exploiter/src/wrapper.rs`.

---

## Ground Truth from Source Reading

### Existing wrapper pattern (subfinder_wrapper.rs — 87 lines)
```rust
impl ToolWrapper for XWrapper {
    fn name(&self) -> &str { "toolname" }
    fn is_available(&self) -> bool { check_tool_installed("toolname") }
    fn build_command(&self, context: &ExploitContext) -> Command { /* Command::new + args */ }
    fn parse_output(&self, stdout: &str, _stderr: &str) -> Vec<ExploitResult> { /* JSON lines */ }
    fn timeout(&self) -> Duration { Duration::from_secs(N) }
    fn supported_classes(&self) -> &[VulnerabilityClass] { &CLASSES }
}
```
Every new wrapper below is ~80–120 lines following this exact shape.

### Current weaknesses being replaced
| Module | Current state | Problem |
|---|---|---|
| `discovery/brute_forcer.rs` | Custom threaded BFS, 260 lines | `default_wordlist.txt` embedded static list |
| `discovery/wordlist.rs` | `include_str!` compile-time embed | No runtime wordlist override |
| `crawler/crawler.rs` | Custom BFS, 192 lines | No JS crawling, no headless fallback in prod |
| `discovery/param_discoverer.rs` | 67 hardcoded params | Fixed list, no heuristic discovery |
| `exploiter/subfinder_wrapper.rs` | Subfinder only | Limited data sources (~20) |
| `passive-recon/filesystem_walker.rs` | Path walk only | No credential/secret detection |

---

## Section 1 — Data Upgrades (zero code, immediate impact)

### 1A. SecLists
**Repo:** `github.com/danielmiessler/SecLists`  
**Install:** `git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/seclists`

Key paths replacing current embedded wordlists:
```
Discovery/Web-Content/raft-large-directories.txt    # 62,284 paths  (vs current ~2013)
Discovery/Web-Content/burp-parameter-names.txt      # 6,453 params  (vs current 67)
Discovery/Web-Content/raft-large-files.txt          # 37,478 files
Fuzzing/SQLi/Generic-SQLi.txt                       # feeds fuzzing MutationOrigin::BypassCorpus
Fuzzing/XSS/XSS-Bypass-Strings.txt
```

**Code change — `crates/discovery/src/wordlist.rs`:**  
Add alongside existing `default_wordlist()`:
```rust
pub fn load_wordlist_from_path(path: &Path) -> Vec<String> { /* reuse parse_wordlist */ }
pub fn seclists_directories(base: &Path) -> Vec<String>  // loads raft-large-directories.txt
pub fn seclists_params(base: &Path) -> Vec<String>       // loads burp-parameter-names.txt
```

**Code change — `crates/orchestrator/src/scan_config.rs`:**  
Add `seclists_path: Option<PathBuf>` + `--seclists-path <dir>` CLI flag.  
Pass into `DirectoryBruster` and `param_discoverer`. Falls back to embedded list if unset.

---

### 1B. PayloadsAllTheThings — bypass corpus
**Repo:** `github.com/swisskyrepo/PayloadsAllTheThings`  
**Install:** `git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git /opt/patt`

Directory → `VulnerabilityClass` mapping:
```
SQL Injection/       → SqlInjection
XSS Injection/       → CrossSiteScripting
Command Injection/   → CommandInjection
Path Traversal/      → PathTraversal
SSTI/                → ServerSideTemplateInjection
...
```

**Code change — `hypothesis-engine/src/generator.py`:**  
Extend `bypass_examples.json` loader to also scan `PAYLOADS_ALL_THE_THINGS_PATH` env var.
Extract payloads from `*.md` files per directory. Feeds `MutationOrigin::BypassCorpus`.

**Code change — `crates/orchestrator/src/update_db.rs`:**  
Add `--update-wordlists` flag: `git -C <seclists_path> pull` + `git -C <patt_path> pull`.

---

## Section 2 — New Wrappers in `crates/exploiter/src/`

All wrappers: implement `ToolWrapper`, register in `selector.rs`, tested with `MockFuzzTransport`.

---

### 2A. `feroxbuster_wrapper.rs`
**Repo:** `github.com/epi052/feroxbuster`  
**Replaces:** `DirectoryBruster` for remote targets under `--i-am-authorized`  
**Augments:** discovery phase with recursive scanning and auto-tune

**Exact CLI (from README):**
```bash
feroxbuster -u <url> -w <wordlist> --json --silent --no-state \
  -t 50 --timeout 10 --depth 3 -x php,html,js,json \
  --filter-status 404 --auto-tune
```
Pass `-H "Cookie: ..."` from `ExploitContext.auth_cookie` when set.

**JSON output line structure (from docs):**
```json
{"type":"response","url":"http://...","status":200,"content_length":1234,
 "words":42,"lines":10,"method":"GET"}
```

**Parse:** filter `"type":"response"`, map to `ExploitResult` with evidence = `"{status} {url}"`.

**`supported_classes`:** `InformationDisclosure`, `SecurityMisconfiguration`, `SensitiveDataExposure`

**Wiring:** Call from `phase_fingerprint.rs` (discovery pass) after httpx prunes dead endpoints.

---

### 2B. `httpx_wrapper.rs`
**Repo:** `github.com/projectdiscovery/httpx`  
**Role:** Liveness + tech-stack gate before fuzzing. Prunes dead endpoints from fuzz queue.

**Exact CLI (from README):**
```bash
httpx -l <targets_file> -json -silent -sc -title -td -cdn -retries 2 \
  -timeout 10 -threads 50 -no-color
```
Or single target: `echo <url> | httpx -json -silent -sc -td`

**JSON output line structure:**
```json
{"url":"https://...","status_code":200,"title":"Admin","tech":["PHP","nginx"],
 "cdn":"cloudflare","content_length":4321}
```

**Parse:** emit `ExploitResult` per live endpoint; attach `tech` array to evidence string.  
Return tech info as `extracted_data` for `DefenseContext` enrichment in orchestrator.

**`supported_classes`:** `SecurityMisconfiguration`, `InformationDisclosure`

**Wiring (`phase_fingerprint.rs`):**
```rust
// After endpoint discovery, before fuzzing:
let live_endpoints = run_httpx_probe(&discovered_endpoints).await?;
// Update DefenseContext with detected tech stack
// Feed only live_endpoints to fuzz scheduler
```

---

### 2C. `gau_wrapper.rs`
**Repo:** `github.com/lc/gau`  
**Role:** Passive URL harvest (Wayback, CommonCrawl, OTX, URLScan) → seeds discovery phase

**Exact CLI (from README):**
```bash
gau --json --blacklist png,jpg,gif,css,woff,ttf,svg --threads 5 \
    --providers wayback,commoncrawl,otx,urlscan <domain>
```
Extract domain from `ExploitContext.target_url` via existing `extract_domain()` in `subfinder_wrapper.rs`.

**Output:** One URL per line (plain text default). With `--json`:
```json
{"url":"https://example.com/old-api/...","statuscode":200,"mime_type":"text/html"}
```

**Parse:** collect discovered URLs → emit as `ExploitResult` per URL with `evidence = "historical: {url}"`.

**`supported_classes`:** `InformationDisclosure`

**Wiring (`phase_recon.rs`):** Run concurrently with `subfinder` via `tokio::join!`. Feed URLs as seeds into crawler queue and fuzz scheduler.

---

### 2D. `dalfox_wrapper.rs`
**Repo:** `github.com/hahwul/dalfox`  
**Role:** XSS-specific confirmatory scanner on endpoints flagged by fuzzer

**Exact CLI (from README + key flags):**
```bash
dalfox url <url> --format json --silence --no-color --timeout 30
# With blind XSS callback (from --dalfox-blind-xss ScanConfig option):
dalfox url <url> -b <callback_url> --format json --silence
# Pipe mode for bulk:
cat endpoints.txt | dalfox pipe --format json --silence
```

**JSON output:**
```json
{"type":"VULN","data":"<script>alert(1)</script>","param":"q",
 "evidence":"GET /?q=<script>...","cwe":"CWE-79","severity":"HIGH"}
```

**Parse:** filter `"type":"VULN"`, map to `ExploitResult`. Set `severity_upgrade = 8.0`.

**`supported_classes`:** `CrossSiteScripting`

**New `ScanConfig` field:** `dalfox_blind_xss: Option<String>` / `--dalfox-blind-xss <url>`

**Wiring (`phase_fuzz.rs`):** After fuzzer marks finding as `CrossSiteScripting` candidate, run dalfox on that specific endpoint+param for DOM confirmation. Complements `dom_verifier.rs`.

---

### 2E. `trufflehog_wrapper.rs`
**Repo:** `github.com/trufflesecurity/trufflehog`  
**Role:** 800+ detector secret scanning on filesystem paths and git repos

**Exact CLI (from README):**
```bash
# Filesystem
trufflehog filesystem <path> --json --results=verified,unknown --no-update
# Git repo
trufflehog git <url> --json --results=verified,unknown --no-update
```

**JSON output:**
```json
{"DetectorName":"AWS","DecoderName":"PLAIN","Verified":true,
 "Raw":"AKIAYVP4CIP...","SourceMetadata":{"Data":{"Filesystem":{"file":"...","line":4}}}}
```

**Parse:** emit `ExploitResult` per finding. `evidence = "{DetectorName}: {Raw_truncated} ({Verified})"`.  
`severity_upgrade = 9.5` for verified, `5.0` for unknown.

**`supported_classes`:** `SensitiveDataExposure`, `InformationDisclosure`

**Wiring (`phase_recon.rs`):** Run alongside `filesystem_walker.rs` in `tokio::join!`.  
`ExploitContext.endpoint` = path to scan. Gate: only runs when filesystem access is in scope.

---

### 2F. `amass_wrapper.rs`
**Repo:** `github.com/owasp-amass/amass`  
**Role:** Deep subdomain enum (60+ data sources) augmenting subfinder's ~20

**Exact CLI (from README + docs):**
```bash
amass enum -d <domain> -passive -json <outfile> -timeout 10
# Active (requires --i-am-authorized):
amass enum -d <domain> -active -json <outfile>
```
Use temp file for `-json` output; read + delete on completion.

**JSON output:**
```json
{"name":"sub.example.com","domain":"example.com","addresses":[{"ip":"1.2.3.4"}],
 "tag":"cert","source":"CertSpotter"}
```

**Parse:** one `ExploitResult` per subdomain. Evidence = `"{name} via {source}"`.

**`supported_classes`:** `SubdomainTakeover`, `InformationDisclosure`

**New `ScanConfig` field:** `amass_passive: bool` (default `true`) / `--amass-active`

**Wiring:** Run in `phase_recon.rs` alongside `subfinder`. Both feed subdomain list into knowledge graph.

---

## Section 3 — Crawler Enhancement

### 3A. `katana_wrapper.rs` in `crates/crawler/src/`
**Repo:** `github.com/projectdiscovery/katana`  
**Role:** Replaces custom BFS crawler for JS-rendered pages when katana is installed

**Exact CLI (from README):**
```bash
katana -u <url> -d 3 -jc -kf all -aff -silent -j -rl 50 \
  -timeout 10 -cs <scope_regex> -t 10
# Headless mode (when --headless-crawl set):
katana -u <url> -d 3 -jc -headless -system-chrome -j -silent
```

**JSON output (from README):**
```json
{"timestamp":"...","request":{"method":"GET","endpoint":"https://..."},
 "response":{"status_code":200,"technologies":["PHP","nginx"]}}
```

**Parse → `CrawlResult`:** Map `endpoint` to `DiscoveredEndpoint`, extract `technologies` for `DefenseContext`.

**Feature gate:** `feature = "katana"` in `crates/crawler/Cargo.toml`. The existing `Crawler` remains the
default; katana is preferred when feature is enabled and binary is present.

**Scope enforcement:** pass `-cs "localhost|127\\.0\\.0\\.1"` when not under `--i-am-authorized`.

**New `ScanConfig` field:** `headless_crawl: bool` / `--headless-crawl`

---

## Section 4 — `update-db` Extension

**File:** `crates/orchestrator/src/update_db.rs`

Add alongside existing OSV DB update:
```
--update-wordlists    git pull SecLists + PayloadsAllTheThings
--update-tools        go install / brew install for all wrapped tools
```

New `UpdateDbArgs` fields: `update_wordlists: bool`, `update_tools: bool`

`run_doctor()` in `doctor.rs`: add checks for feroxbuster, httpx, gau, dalfox, trufflehog, amass, katana.
Each emits `CheckStatus::Missing` with install command as the fix hint.

---

## Implementation Order (impact × effort)

| Priority | Task | Files touched | Effort |
|---|---|---|---|
| 1 | SecLists wordlist path support | `wordlist.rs`, `scan_config.rs` | ~40 lines |
| 2 | PayloadsAllTheThings corpus loader | `hypothesis-engine/generator.py` | ~30 lines |
| 3 | `httpx_wrapper.rs` | new file + `selector.rs` + `phase_fingerprint.rs` | ~100 lines |
| 4 | `gau_wrapper.rs` | new file + `selector.rs` + `phase_recon.rs` | ~80 lines |
| 5 | `feroxbuster_wrapper.rs` | new file + `selector.rs` + `phase_fingerprint.rs` | ~110 lines |
| 6 | `trufflehog_wrapper.rs` | new file + `selector.rs` + `phase_recon.rs` | ~90 lines |
| 7 | `dalfox_wrapper.rs` | new file + `selector.rs` + `phase_fuzz.rs` + `scan_config.rs` | ~100 lines |
| 8 | `amass_wrapper.rs` | new file + `selector.rs` + `phase_recon.rs` + `scan_config.rs` | ~100 lines |
| 9 | `katana_wrapper.rs` | new file in `crates/crawler/`, `Cargo.toml` feature gate | ~120 lines |
| 10 | `update-db --update-wordlists/--update-tools` | `update_db.rs`, `doctor.rs` | ~60 lines |

**Total new code: ~830 lines across 10 wrapper/config files.**  
**Total code deleted or superseded: ~0** (all additions are opt-in via tool availability + config flags).

---

## Convention Notes (from CLAUDE.md)

- Each wrapper file: one public type. Functions ≤40 lines. Builder `with_*` for config variants.
- Test files adjacent: `feroxbuster_wrapper_test.rs` with `MockFuzzTransport`.
- JSON parsing structs are private (`struct FeroxbusterLine`, etc.) — one per file, no sharing.
- `check_tool_installed(name)` in `checker.rs` handles `is_available()` for all new wrappers.
- `extract_domain()` in `subfinder_wrapper.rs` is reusable for gau + amass — move to `wrapper.rs` or `util.rs`.
- Commit format: `[exploiter] add feroxbuster wrapper`, `[discovery] add seclists wordlist support`, etc.
