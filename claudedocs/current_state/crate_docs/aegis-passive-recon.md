<!-- metadata:
  crate: aegis-passive-recon
  purpose: Static analysis of the target's source tree: lock file parsing, vulnerability DB lookup, and filesystem classification
  public_api: ParsedDependency, Ecosystem, ParseError, detect_ecosystem(), parse_lock_file(), parse_lock_file_content(),
              VulnerabilityRecord, VulnerabilityMatch, VulnDatabaseError, VulnDatabase,
              version_in_range(),
              FileClassification, ClassifiedFile, WalkerError, WalkResult,
              walk_directory(), classify_file()
  modules: dependency_parser, vuln_database, filesystem_walker
  dependencies: aegis-protocol, aegis-knowledge-graph, serde, serde_json, tracing,
                rusqlite (bundled), semver, cargo-lock
-->

# aegis-passive-recon

## Purpose

`aegis-passive-recon` performs non-network reconnaissance by statically analyzing the target
application's source directory. It parses dependency lock files from five ecosystems, matches
parsed dependencies against a SQLite vulnerability database (populated via the `update-db`
subcommand from the OSV API), and classifies filesystem entries by type (lock files, env files,
Dockerfiles, Kubernetes manifests, etc.). This phase runs concurrently with HTTP fingerprinting
at scan start, since it requires no network access. Findings from this phase (known vulnerable
dependencies) appear in the knowledge graph as `Dependency` nodes with `KnownVulnerableDependency`
findings linked to them.

## Crate Type

Library

## Dependencies on Workspace Crates

- `aegis-protocol` — `VulnerabilityClass`, `ModuleIdentifier`, `OperationLogEntry`
- `aegis-knowledge-graph` — `GraphStore` trait for operation application

## External Dependencies

| Dependency | Version | Role |
|---|---|---|
| serde | 1 | Derives on lock file structs |
| serde_json | 1 | `package-lock.json` deserialization |
| tracing | 0.1 | Diagnostic spans |
| rusqlite | 0.32 (bundled) | SQLite vulnerability database; bundled C library, zero external dep |
| semver | 1 | Semantic version comparison for vulnerability range checks |
| cargo-lock | 10 | Cargo.lock parsing (handles all format versions; filters to default registry) |

## Module Structure

| Module | Responsibility |
|---|---|
| `dependency_parser` | Lock file detection, parsing for 5 ecosystems, `Ecosystem` enum with OSV name mapping |
| `vuln_database` | `VulnDatabase` SQLite wrapper, `VulnerabilityRecord`, `VulnerabilityMatch`, `version_in_range()` |
| `filesystem_walker` | Recursive directory walk with skip list, `classify_file()`, `FileClassification` enum |

## Public API Summary

### dependency_parser

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDependency {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ecosystem {
    Npm, Cargo, PyPi, Go, RubyGems,
}
impl Display for Ecosystem { ... }  // "npm", "cargo", "pypi", "go", "rubygems"
impl Ecosystem {
    pub fn osv_name(&self) -> &'static str;
    // Returns: "npm", "crates.io", "PyPI", "Go", "RubyGems"
    // Used as the ecosystem identifier in OSV API queries.

    pub fn from_osv_name(name: &str) -> Option<Self>;
}

pub enum ParseError {
    IoError(std::io::Error),
    JsonError(serde_json::Error),
    UnsupportedFormat(String),   // filename not recognized
    MalformedContent(String),    // cargo-lock parse failure
}

// Detect ecosystem from filename (not path)
pub fn detect_ecosystem(filename: &str) -> Option<Ecosystem>;
// Supported: "package-lock.json", "yarn.lock", "pnpm-lock.yaml" -> Npm
//            "Cargo.lock" -> Cargo
//            "requirements.txt", "Pipfile.lock", "poetry.lock" -> PyPi
//            "go.sum" -> Go
//            "Gemfile.lock" -> RubyGems

// Parse a lock file at the given path
pub fn parse_lock_file(path: &Path) -> Result<Vec<ParsedDependency>, ParseError>;

// Parse lock file content from a string (for testing without filesystem access)
pub fn parse_lock_file_content(filename: &str, content: &str) -> Result<Vec<ParsedDependency>, ParseError>;
// filename is matched by basename only (e.g. "Cargo.lock", "package-lock.json")
```

**Supported formats and parser notes:**
- `package-lock.json` — Prefers npm v3 `packages` map (strips `node_modules/` prefix), falls back to v1/v2 `dependencies` map. Skips the root entry (empty path key).
- `Cargo.lock` — Uses the `cargo-lock` crate for multi-format version support. Filters to `is_default_registry()` only to avoid scanning private/git dependencies.
- `requirements.txt` — Line-by-line; skips comments (`#`), blank lines, and options (`-r`, `-c`). Parses `name==version`, `>=`, `<=`, `~=`, `!=`, `>`, `<`. Takes only the first version component before any comma.
- `go.sum` — Whitespace-split; deduplicates `(module, version)` pairs. Strips `v` prefix and `/go.mod` suffix from version strings.
- `Gemfile.lock` — Tracks indent level: enters `specs:` section, records the first-seen indent as the gem-line level, skips deeper indents (sub-dependencies). Parses `name (version)` format.

### vuln_database

```rust
#[derive(Debug, Clone)]
pub struct VulnerabilityRecord {
    pub cve_id: String,
    pub package_name: String,
    pub ecosystem: String,
    pub vulnerable_version_start: String,
    pub vulnerable_version_end: String,
    pub severity: f64,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct VulnerabilityMatch {
    pub dependency: ParsedDependency,
    pub cve_id: String,
    pub severity: f64,
    pub description: String,
}

pub enum VulnDatabaseError {
    SqliteError(rusqlite::Error),
    SemverError(String),
}
impl From<rusqlite::Error> for VulnDatabaseError { ... }

pub struct VulnDatabase { connection: Connection }
impl VulnDatabase {
    // Open or create database file; runs schema migration
    pub fn open(path: &Path) -> Result<Self, VulnDatabaseError>;
    // In-memory database; used in tests
    pub fn open_in_memory() -> Result<Self, VulnDatabaseError>;

    // Insert a single record; returns last_insert_rowid
    pub fn insert_vulnerability(&self, record: &VulnerabilityRecord) -> Result<i64, VulnDatabaseError>;

    // INSERT OR IGNORE; returns true if a new row was inserted
    pub fn upsert_vulnerability(&self, record: &VulnerabilityRecord) -> Result<bool, VulnDatabaseError>;

    // INSERT OR IGNORE in a transaction; returns count of newly inserted rows
    pub fn insert_batch(&self, records: &[VulnerabilityRecord]) -> Result<usize, VulnDatabaseError>;

    // Query vulnerabilities for a specific package+ecosystem
    pub fn find_vulnerabilities_for_package(
        &self,
        package_name: &str,
        ecosystem: &str,
    ) -> Result<Vec<VulnerabilityRecord>, VulnDatabaseError>;

    // Check a single dependency; filters by version_in_range
    pub fn check_dependency(&self, dep: &ParsedDependency) -> Result<Vec<VulnerabilityMatch>, VulnDatabaseError>;

    // Check all dependencies; aggregates results
    pub fn check_all_dependencies(&self, deps: &[ParsedDependency]) -> Result<Vec<VulnerabilityMatch>, VulnDatabaseError>;

    // Update metadata tracking
    pub fn get_last_updated(&self, ecosystem: &str) -> Result<Option<u64>, VulnDatabaseError>;
    pub fn set_last_updated(&self, ecosystem: &str, timestamp_ms: u64) -> Result<(), VulnDatabaseError>;

    // Delete all vulnerabilities for an ecosystem (used in --full-refresh)
    pub fn clear_ecosystem(&self, ecosystem: &str) -> Result<u64, VulnDatabaseError>;

    // Row count
    pub fn vulnerability_count(&self) -> Result<u64, VulnDatabaseError>;
}

// Check if a version string falls within [start, end] (both inclusive).
// Prefers semver semantics; falls back to lexicographic comparison for non-semver strings.
// The sentinel "999999.0.0" represents "not yet fixed" (no fixed version in OSV).
pub fn version_in_range(version: &str, start: &str, end: &str) -> bool;
```

**Schema:**
```sql
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    package_name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    vulnerable_version_start TEXT NOT NULL,
    vulnerable_version_end TEXT NOT NULL,
    severity REAL NOT NULL DEFAULT 0.0,
    description TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX idx_vuln_unique ON vulnerabilities(cve_id, package_name, ecosystem, vulnerable_version_start, vulnerable_version_end);
CREATE TABLE update_metadata (ecosystem TEXT PRIMARY KEY, last_updated_unix_ms INTEGER NOT NULL);
```

### filesystem_walker

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileClassification {
    LockFile, ConfigFile, SourceCode, Dockerfile, KubernetesManifest,
    TerraformFile, EnvFile, WebServerConfig, Unknown,
}
impl Display for FileClassification { ... }

#[derive(Debug, Clone)]
pub struct ClassifiedFile {
    pub path: PathBuf,
    pub classification: FileClassification,
    pub size_bytes: u64,
}

pub enum WalkerError {
    IoError(std::io::Error),
    RootNotFound(PathBuf),
}

pub struct WalkResult {
    pub files: Vec<ClassifiedFile>,
    pub total_size_bytes: u64,
    pub classification_counts: HashMap<FileClassification, usize>,
}

// Recursively walk a directory, classify all files, return summary
pub fn walk_directory(root: &Path) -> Result<WalkResult, WalkerError>;

// Classify a single file path by filename and extension
pub fn classify_file(path: &Path) -> FileClassification;
```

**Skipped directories:** `node_modules`, `.git`, `__pycache__`, `target`, `.venv`, `venv`,
`.tox`, `dist`, `build`, `.next`

**Classification rules (in priority order):**
1. Lock files (filename exact match: `package-lock.json`, `Cargo.lock`, etc.) → `LockFile`
2. Env files (`.env`, `.env.*`, `env`, `.envrc`) → `EnvFile`
3. Dockerfiles (`Dockerfile`, `Dockerfile.*`, `docker-compose.yml/yaml`) → `Dockerfile`
4. Web server configs (`nginx.conf`, `httpd.conf`, `apache2.conf`, `.htaccess`) → `WebServerConfig`
5. Extension: `tf`, `tfvars` → `TerraformFile`
6. Extension: source languages (rs, py, js, ts, jsx, tsx, go, java, rb, cpp, c, h, hpp, cs, swift, kt, scala, php) → `SourceCode`
7. YAML/YML: filename contains `docker-compose` → `Dockerfile`; parent dir is `k8s/kubernetes/manifests/deploy`, or filename contains `deployment/service/ingress/pod` → `KubernetesManifest`; otherwise → `ConfigFile`
8. Extension: `json`, `toml`, `ini`, `cfg`, `conf`, `properties`, `xml` → `ConfigFile`
9. Default → `Unknown`

## Error Types

- `ParseError` — IoError, JsonError, UnsupportedFormat, MalformedContent
- `VulnDatabaseError` — SqliteError (with `From<rusqlite::Error>`), SemverError
- `WalkerError` — IoError (with `From<io::Error>`), RootNotFound

All implement `std::error::Error` and `Display`.

## Key Implementation Notes

**Cargo.lock filtering prevents private registry scanning.** `parse_cargo_lock` uses
`cargo-lock`'s `is_default_registry()` check to exclude packages from git sources, path
dependencies, and private registries. Only crates published to crates.io are queried against the
vulnerability database.

**Gemfile.lock indent tracking is required for correctness.** The lock file has a hierarchical
structure where top-level gems are followed by their sub-dependencies at deeper indentation levels.
The parser records the first-seen indent level after entering a `specs:` block and skips all lines
with different (deeper) indentation. Without this, sub-dependency versions would be incorrectly
reported as top-level dependency versions.

**Version comparison falls back gracefully for non-semver strings.** `version_in_range` first
attempts semver parsing for both the package version and range bounds. If either fails to parse as
semver (e.g., Ruby gem versions like `r2022a`, or Python pre-release strings), it falls back to
lexicographic `str::cmp`. This fallback correctly orders most version schemes that aren't semver
but is not guaranteed accurate for all possible formats.

**OSV sentinel version.** The `update_db` module (in the orchestrator) uses `"999999.0.0"` as
`vulnerable_version_end` when an OSV record has an `introduced` event with no corresponding `fixed`
or `last_affected` event. This means any version above the start is considered vulnerable. The
`version_in_range` function treats this correctly since `"999999.0.0"` parses as valid semver and
will be greater than any real package version.

**SQLite uses `unchecked_transaction` for batch inserts.** `insert_batch` wraps all inserts in a
single transaction for performance. `unchecked_transaction` is used because the connection is not
`Send` and the transaction is committed synchronously before the function returns. All
inserts use `INSERT OR IGNORE` with the unique index, providing idempotent batch loading.

**`VulnDatabase` defaults to `~/.aegis/vuln.db`.** The three-argument `vuln_lookup` function in
the orchestrator accepts `Option<&Path>` for the database path; when `None` is passed, it falls
back to `~/.aegis/vuln.db` if that file exists, and returns an empty result (no findings) if it
does not. The `--vuln-db` CLI flag overrides this default.

## Usage Context

The passive recon phase (`phase_recon.rs` in the orchestrator) calls `walk_directory` on the
`--source-dir` path (if provided), then calls `parse_lock_file` on each discovered lock file.
The resulting `ParsedDependency` list is passed to `VulnDatabase::check_all_dependencies`, and each
`VulnerabilityMatch` is converted to an `AddNode` + `AddFinding` operation batch applied to the
knowledge graph. This phase runs in the first scan iteration, concurrently with HTTP fingerprinting
via `tokio::join!`. The `update-db` subcommand in the orchestrator populates the SQLite database
by querying the OSV batch API with the actual dependency list from the source directory.
