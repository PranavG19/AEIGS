<!-- metadata: crate=aegis-discovery, purpose=HTTP endpoint discovery via directory brute-force + JS analysis + sitemap parsing + backup scanning + vhost enumeration + parameter probing + tech fingerprinting, type=library, internal_deps=[aegis-protocol], external_deps=[reqwest (blocking), regex, url] -->

# aegis-discovery

## Purpose

Discovers HTTP endpoints, parameters, virtual hosts, technology stack information, and sensitive file exposures on localhost targets through multiple passive and active enumeration techniques.

## Crate Type

Library

## Dependencies on Workspace Crates

- `aegis-protocol` — `validate_target_is_localhost`, `NodeType`, `GraphOperation`, `OperationLogEntry`, `ModuleIdentifier`

## External Dependencies

- `reqwest` (blocking) — HTTP probing for all active discovery modules
- `regex` — JS pattern matching (7 patterns), sitemap XML parsing, HTML pattern detection
- `url` — URL parsing and normalization

## Module Structure

| Module | Description |
|---|---|
| `brute_forcer` | Directory brute-forcing with concurrent threads, baseline-404 detection, interesting path flagging |
| `js_extractor` | Extracts endpoints from JavaScript source using 7 regex patterns (fetch, axios, XMLHttpRequest, route definitions, full URLs, API path literals) |
| `tech_fingerprinter` | Identifies technology stack from HTTP headers, HTML content, cookies, path probes, and CDN SRI attributes |
| `param_discoverer` | Probes 67 common parameter names against an endpoint and detects behavioral changes (status code, body size, content) |
| `vhost_discoverer` | Enumerates virtual hosts by setting `Host` headers with 31 common prefixes and comparing responses against baseline |
| `backup_scanner` | Probes 40+ sensitive paths and generates backup file variants from known paths (.bak, .old, .orig, ~, .swp, etc.) |
| `sitemap_parser` | Fetches and parses `robots.txt` and `sitemap.xml`, converting results to graph operations |
| `graph_ops` | Converts discovery results into `OperationLogEntry` instances for the knowledge graph |
| `wordlist` | Loads the default 2,013-entry wordlist from an embedded text file |

## Public API Summary

### `brute_forcer`

```rust
pub struct DiscoveredPath { pub path: String, pub status_code: u16,
                             pub content_length: usize, pub content_type: Option<String>,
                             pub interesting: bool }

pub enum BruteForceError { InvalidBaseUrl(String), NonLocalhostTarget(String), HttpError(String) }

pub struct DirectoryBruster { /* private */ }

impl DirectoryBruster {
    pub fn new(base_url: &str, wordlist: Vec<String>) -> Result<Self, BruteForceError>
    pub fn with_default_wordlist(base_url: &str) -> Result<Self, BruteForceError>
    pub fn with_extensions(self, extensions: Vec<String>) -> Self
    pub fn with_concurrency(self, concurrency: usize) -> Self   // clamped to >=1
    pub fn with_filter_codes(self, codes: HashSet<u16>) -> Self // default: {404}
    pub fn detect_baseline_404(&mut self) -> Option<usize>
    pub fn run(&self) -> Vec<DiscoveredPath>  // concurrent, sorted by path
}
```

### `js_extractor`

```rust
pub struct ExtractedEndpoint { pub url: String, pub method: Option<String>,
                                pub source_pattern: String }

pub struct JsEndpointExtractor { /* private */ }

impl JsEndpointExtractor {
    pub fn new(base_url: &str) -> Self
    /// Extracts endpoints from JS content using 7 patterns. Cross-origin URLs filtered out.
    pub fn extract_from_js(&self, js_content: &str) -> Vec<ExtractedEndpoint>
}
```

### `tech_fingerprinter`

```rust
pub enum TechCategory { WebServer, Framework, Cms, ProgrammingLanguage, JavaScript, Cdn, Analytics, Security }

pub struct DetectedTech { pub name: String, pub version: Option<String>,
                           pub category: TechCategory, pub confidence: f64, pub evidence: String }

pub struct TechFingerprint { pub technologies: Vec<DetectedTech> }

pub struct TechFingerprinter { /* private */ }

impl TechFingerprinter {
    pub fn new() -> Result<Self, FingerprintError>
    /// Fingerprints via headers + HTML body + path probes. Deduplicates by name (highest confidence wins).
    pub fn fingerprint(&self, target: &str) -> Result<TechFingerprint, FingerprintError>
}

/// Fingerprint from response headers only (no HTTP call). Useful for testing.
pub fn fingerprint_from_headers(headers: &[(String, String)]) -> Vec<DetectedTech>
pub fn fingerprint_from_html(body: &str) -> Vec<DetectedTech>
```

### `param_discoverer`

```rust
pub const COMMON_PARAMS: &[&str]  // 67 parameter names

pub enum ParamEvidence { StatusCodeChange(u16, u16), BodySizeChange(usize, usize), ContentChange }

pub struct DiscoveredParam { pub endpoint: String, pub param_name: String,
                              pub evidence: ParamEvidence }

pub struct ParamDiscoverer { /* private */ }

impl ParamDiscoverer {
    pub fn new() -> Result<Self, ParamDiscoverError>
    pub fn discover_params(&self, endpoint: &str) -> Result<Vec<DiscoveredParam>, ParamDiscoverError>
}
```

### `vhost_discoverer`

```rust
pub const VHOST_PREFIXES: &[&str]  // 31 prefixes (admin, api, dev, staging, etc.)

pub struct DiscoveredVhost { pub hostname: String, pub status_code: u16,
                              pub content_length: usize, pub evidence: String }

pub struct VhostDiscoverer { /* private */ }

impl VhostDiscoverer {
    pub fn new() -> Result<Self, VhostError>
    pub fn discover_vhosts(&self, target_url: &str, target_domain: &str)
        -> Result<Vec<DiscoveredVhost>, VhostError>
}
```

### `backup_scanner`

```rust
pub const SENSITIVE_PATHS: &[&str]  // 40 paths (.env, .git/config, web.config, etc.)

pub enum BackupType { EnvironmentFile, SourceControl, BackupFile, ConfigurationFile,
                      DatabaseDump, SourceMap, IdeFile, DebugEndpoint }

pub struct BackupFinding { pub path: String, pub status_code: u16, pub content_length: usize,
                            pub finding_type: BackupType, pub severity: f64 }

pub struct BackupScanner { /* private */ }

impl BackupScanner {
    pub fn new() -> Result<Self, BackupScanError>
    /// Probes SENSITIVE_PATHS + backup variants of known_paths. Sorted by severity descending.
    pub fn scan(&self, target_url: &str, known_paths: &[String])
        -> Result<Vec<BackupFinding>, BackupScanError>
}

pub fn generate_backup_variants(known_paths: &[String]) -> Vec<String>
pub fn classify_path(path: &str) -> BackupType
```

### `sitemap_parser`

```rust
pub struct RobotsResult { pub disallowed_paths: Vec<String>, pub sitemap_urls: Vec<String>,
                           pub allowed_paths: Vec<String> }
pub struct SitemapResult { pub urls: Vec<String> }

pub fn parse_robots_txt(content: &str) -> RobotsResult
pub fn parse_sitemap_xml(content: &str) -> SitemapResult
/// Fetches /robots.txt and /sitemap.xml from localhost target.
pub fn fetch_and_parse(target_url: &str) -> Result<(RobotsResult, SitemapResult), SitemapError>
pub fn sitemap_results_to_operations(robots: &RobotsResult, sitemap: &SitemapResult,
    start_sequence: u64) -> Vec<OperationLogEntry>
```

### `graph_ops`

```rust
pub fn discovered_paths_to_operations(paths: &[DiscoveredPath], start_sequence: u64) -> Vec<OperationLogEntry>
pub fn extracted_endpoints_to_operations(endpoints: &[ExtractedEndpoint], start_sequence: u64) -> Vec<OperationLogEntry>
pub fn backup_findings_to_operations(findings: &[BackupFinding], start_sequence: u64) -> Vec<OperationLogEntry>
pub fn discovered_params_to_operations(params: &[DiscoveredParam], start_sequence: u64) -> Vec<OperationLogEntry>
pub fn vhost_findings_to_operations(findings: &[DiscoveredVhost], start_sequence: u64) -> Vec<OperationLogEntry>
```

### `wordlist`

```rust
/// Loads the default 2,013-entry wordlist from the embedded default_wordlist.txt file.
pub fn default_wordlist() -> Vec<String>
/// Parses any wordlist content (strips blank lines and # comments).
pub fn parse_wordlist(content: &str) -> Vec<String>
```

## Key Implementation Notes

- **Localhost enforcement at every entry point**: Every public method that makes HTTP requests validates the target via `aegis_protocol::target_validation::validate_target_is_localhost`. Non-localhost targets return `NonLocalhostTarget` errors rather than making requests.

- **Baseline-404 false positive suppression**: `DirectoryBruster` and `BackupScanner` both use a shared baseline-404 detection pattern. A probe request is sent to a randomized nonexistent path (`BASELINE_404_PROBE = "aegis-nonexistent-path-4f7a8b2c-d1e3"`) and the response size is recorded. Paths whose response sizes are within `BODY_SIZE_TOLERANCE = 64` bytes of the baseline are filtered (brute_forcer.rs:225-230).

- **Concurrent brute-forcing via `std::thread`**: `DirectoryBruster::run` uses OS threads (not async) with `std::sync::mpsc`. Candidates are split into chunks of `wordlist.len() / concurrency` (brute_forcer.rs:132). The default concurrency is 20.

- **JS extraction patterns**: 7 patterns are compiled once in `build_patterns()` (js_extractor.rs:88-162): `fetch(...)`, `axios.method(...)`, `$.ajax({url:...})`, `xhr.open(METHOD, url)`, `router/app.method(path)`, full absolute URLs, and `/api/` path literals. Cross-origin URLs are filtered by comparing parsed host against `base_host`.

- **Virtual host baseline comparison**: Uses a djb2-style hash (`simple_hash`) of the response body for cheap equality checking, plus body size within `BODY_SIZE_TOLERANCE = 64` bytes, and status code comparison (vhost_discoverer.rs:173-186).

- **Param discovery threshold**: Body size difference threshold is 10% (`BODY_SIZE_DIFF_THRESHOLD = 0.10`) using `max(baseline, probe)` as the denominator to avoid division by zero on empty bodies (param_discoverer.rs:160-167).

- **`discovered_params_to_operations` emits `NodeType::Config`**: Parameters are stored as `Config` nodes (not `Endpoint` nodes) in the knowledge graph (graph_ops.rs:152-160).

- **Sitemap URL reconstruction**: The `robots.txt` parser uses a special `reconstruct_url_after_directive` function for `Sitemap:` lines because URLs contain colons — splitting on `:` would truncate the URL. The directive length is used to skip past the colon correctly (sitemap_parser.rs:89-94).

## Usage Context

Used by the orchestrator's `phase_fingerprint` and `phase_recon` phases. The graph_ops converters are called after each discovery pass to build `OperationLogEntry` batches that are applied to the `KnowledgeGraph`. The `TechFingerprinter` results feed into the `DefenseContext` for subsequent fuzzing phases. `BackupScanner` results feed directly into `SensitiveDataExposure` and `InformationDisclosure` findings.
