# Interactive Proxy TUI — Design Document

**Date:** 2026-02-23
**Status:** Approved
**Scope:** Full Burp Suite Repeater/Intruder parity via ratatui TUI

## Problem

AEGIS has a proxy crate (~1,800 LOC, 43 tests) with recording proxy, repeater, 4-mode intruder, and knowledge graph sync. But it's a library with no user-facing interface. A freelance pentester can't use it interactively — there's no way to browse captured traffic, edit and resend requests, or run intruder attacks without writing Rust code.

Burp Suite Pro provides Repeater (edit-and-resend with diff), Intruder (4 attack modes with payload processing, grep, and live results), and a proxy log with search/filter/scope. AEGIS needs equivalent functionality accessible via terminal.

## Decision: TUI over Web UI

- **ratatui TUI** — Rust-native, no browser dependency, fits CLI identity
- Separate binary via `aegis proxy` subcommand
- Can import knowledge graph from prior scans for pre-populated attack surface

## Architecture

### Crate Structure

```
crates/
├── proxy/                    # ENHANCED — add persistence, payloads, grep, scope
│   ├── persistence.rs        # SQLite storage layer (~300 LOC)
│   ├── scope.rs              # URL scope rules — include/exclude (~150 LOC)
│   ├── session.rs            # Cookie jar + session tracking (~200 LOC)
│   ├── payload.rs            # Payload sources, processors, encoding (~400 LOC)
│   ├── grep.rs               # Response grep-match/extract (~150 LOC)
│   ├── diff.rs               # Request/response diff engine (~200 LOC)
│   ├── modification.rs       # Proxy match-and-replace rules (~100 LOC)
│   └── (existing modules enhanced)
│
├── proxy-tui/                # NEW — ratatui TUI application (~2,500-3,000 LOC)
│   ├── main.rs               # Binary entry, clap args
│   ├── app.rs                # App state machine, event loop
│   ├── views/
│   │   ├── proxy_log.rs      # Exchange list with filter/search
│   │   ├── request_editor.rs # Editable request pane
│   │   ├── response.rs       # Response viewer with syntax highlight
│   │   ├── intruder.rs       # Position marking, payload config, results
│   │   ├── repeater.rs       # Edit-send-compare workflow
│   │   ├── scope.rs          # Scope rule editor
│   │   ├── payloads.rs       # Payload list manager
│   │   └── comparer.rs       # Side-by-side diff view
│   ├── widgets/
│   │   ├── hex_view.rs       # Hex/raw/pretty toggle
│   │   ├── diff_view.rs      # Side-by-side diff rendering
│   │   ├── table.rs          # Sortable, filterable table
│   │   └── status_bar.rs     # Proxy status, counts, scope
│   └── keybinds.rs           # Vim-style keybindings
```

### Dependencies

- `proxy-tui` depends on: `aegis-proxy`, `ratatui`, `crossterm`, `clap`
- `proxy` adds: `rusqlite` (already workspace dep), `regex` (for scope/grep)
- No new external crate families beyond ratatui + crossterm

### Entry Point

```
aegis proxy [--listen ADDR] [--import-graph PATH] [--db PATH]
```

Wired as subcommand in orchestrator `main.rs` (same pattern as `recon`, `attest`, `update-db`).

## Data Model

SQLite at `~/.aegis/proxy.db` (or `--db <path>`):

```sql
CREATE TABLE exchanges (
    id              INTEGER PRIMARY KEY,
    method          TEXT NOT NULL,
    url             TEXT NOT NULL,
    request_headers TEXT NOT NULL,      -- JSON array of [key, value]
    request_body    BLOB,
    response_status INTEGER NOT NULL,
    response_headers TEXT NOT NULL,     -- JSON array of [key, value]
    response_body   BLOB,
    timestamp_ms    INTEGER NOT NULL,
    duration_ms     INTEGER NOT NULL,
    in_scope        INTEGER NOT NULL DEFAULT 1,
    tags            TEXT DEFAULT '[]'
);
CREATE INDEX idx_exchanges_url ON exchanges(url);
CREATE INDEX idx_exchanges_timestamp ON exchanges(timestamp_ms);
CREATE INDEX idx_exchanges_status ON exchanges(response_status);

CREATE TABLE scope_rules (
    id         INTEGER PRIMARY KEY,
    pattern    TEXT NOT NULL,
    is_include INTEGER NOT NULL,
    priority   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE saved_requests (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    method      TEXT NOT NULL,
    url         TEXT NOT NULL,
    headers     TEXT NOT NULL,
    body        BLOB,
    notes       TEXT DEFAULT '',
    created_at  INTEGER NOT NULL,
    exchange_id INTEGER,
    FOREIGN KEY (exchange_id) REFERENCES exchanges(id)
);

CREATE TABLE intruder_runs (
    id             INTEGER PRIMARY KEY,
    name           TEXT DEFAULT '',
    mode           TEXT NOT NULL,
    template_json  TEXT NOT NULL,
    positions_json TEXT NOT NULL,
    concurrency    INTEGER NOT NULL DEFAULT 10,
    started_at     INTEGER NOT NULL,
    completed_at   INTEGER,
    total_requests INTEGER DEFAULT 0
);

CREATE TABLE intruder_results (
    id            INTEGER PRIMARY KEY,
    run_id        INTEGER NOT NULL,
    payload_json  TEXT NOT NULL,
    status_code   INTEGER NOT NULL,
    body_length   INTEGER NOT NULL,
    duration_ms   INTEGER NOT NULL,
    response_body BLOB,
    grep_matches  TEXT DEFAULT '[]',
    FOREIGN KEY (run_id) REFERENCES intruder_runs(id)
);
CREATE INDEX idx_intruder_results_run ON intruder_results(run_id);

CREATE TABLE payload_lists (
    id      INTEGER PRIMARY KEY,
    name    TEXT NOT NULL UNIQUE,
    source  TEXT NOT NULL,
    entries TEXT NOT NULL
);

CREATE TABLE cookies (
    id        INTEGER PRIMARY KEY,
    domain    TEXT NOT NULL,
    name      TEXT NOT NULL,
    value     TEXT NOT NULL,
    path      TEXT DEFAULT '/',
    expires   INTEGER,
    secure    INTEGER DEFAULT 0,
    http_only INTEGER DEFAULT 0
);

CREATE TABLE modification_rules (
    id           INTEGER PRIMARY KEY,
    enabled      INTEGER NOT NULL DEFAULT 1,
    match_target TEXT NOT NULL,
    match_pattern TEXT NOT NULL,
    replace_with TEXT NOT NULL
);
```

Headers stored as JSON arrays (matches existing `Vec<(String, String)>`). Bodies as BLOB (binary-safe). In-memory write-through cache for TUI responsiveness.

## Payload Pipeline

Three-layer pipeline replacing current `Vec<Vec<String>>`:

### Sources

```rust
pub enum PayloadSource {
    SimpleList(Vec<String>),
    FromFile(PathBuf),
    SavedList(String),               // name in payload_lists table
    NumberRange { start: i64, end: i64, step: i64 },
    BruteForce { charset: String, min_length: usize, max_length: usize },
    NullPayloads(usize),
    DateRange { start: String, end: String, format: String },
    ExtractFromResponse { grep_pattern: String },
}
```

### Processors (applied in order)

```rust
pub enum PayloadProcessor {
    AddPrefix(String),
    AddSuffix(String),
    RegexReplace { pattern: String, replacement: String },
    Substring { start: usize, length: Option<usize> },
    ChangeCase(CaseMode),
    Reverse,
    SkipIf(String),
    MatchOnly(String),
}
```

### Encoding (applied last)

```rust
pub enum PayloadEncoding {
    None,
    UrlEncode,
    DoubleUrlEncode,
    HtmlEncode,
    Base64Encode,
    Base64Decode,
    Hex,
    Sha256,
    Md5,
    Chain(Vec<PayloadEncoding>),
}
```

### Composition

```rust
pub struct PayloadPipeline {
    pub source: PayloadSource,
    pub processors: Vec<PayloadProcessor>,
    pub encoding: PayloadEncoding,
}
```

Backwards compatible: `PayloadSource::SimpleList` with empty processors and `PayloadEncoding::None` equals current behavior.

## Response Analysis

### Grep-Match

```rust
pub struct GrepMatch {
    pub pattern: String,
    pub search_in: SearchTarget,  // Body, Headers, Both
    pub negate: bool,
}
```

### Grep-Extract

```rust
pub struct GrepExtract {
    pub pattern: String,
    pub group: usize,
    pub search_in: SearchTarget,
}
```

Results stored per intruder result in `grep_matches` JSON column. Displayed as columns in TUI results table.

## Diff Engine

```rust
pub struct DiffResult {
    pub status_changed: bool,
    pub header_diffs: Vec<HeaderDiff>,
    pub body_diff: Vec<DiffChunk>,
    pub body_length_delta: i64,
    pub duration_delta_ms: i64,
}

pub enum DiffChunk {
    Equal(String),
    Added(String),
    Removed(String),
}
```

LCS-based line diff (~60 lines, no external crate). Word diff variant splits lines on whitespace before diffing. Hex diff compares raw bytes.

## Session Management

```rust
pub struct SessionJar {
    cookies: HashMap<String, Vec<Cookie>>,
    auto_update: bool,
}
```

- Auto-updates from `Set-Cookie` response headers when enabled
- Injects cookies into Repeater/Intruder requests unless manually overridden
- Session tokens highlighted in proxy log (heuristic: `session*`, `token*`, `auth*`, `sid*`, `jwt*`)
- Persisted to SQLite `cookies` table

## Scope Engine

```rust
pub struct ScopeEngine {
    rules: Vec<ScopeRule>,
    compiled: Vec<(Regex, bool)>,
}
```

Evaluation: include rules first (if any), then exclude rules. Out-of-scope exchanges still recorded but dimmed in TUI and excluded from Repeater/Intruder by default. `--import-graph` auto-generates include rules from knowledge graph endpoints.

## Proxy Modification Rules

Match-and-replace applied to traffic passing through proxy:

```rust
pub struct ModificationRule {
    pub match_target: MatchTarget,   // RequestHeader, RequestBody, ResponseHeader, ResponseBody
    pub match_pattern: String,       // regex
    pub replace_with: String,        // supports $1 capture groups
}
```

Common uses: strip security headers, inject forwarding headers, modify User-Agent.

## TUI Layout

6 tabs: `[1:Proxy] [2:Repeater] [3:Intruder] [4:Scope] [5:Payloads] [6:Comparer]`

### Tab 1: Proxy Log
- Sortable exchange table (method, URL, status, length, time, tags)
- Split-pane request/response viewer
- Filter by regex on URL, method, status, body
- Actions: repeat, send-to-intruder, save, tag

### Tab 2: Repeater
- Editable request pane (method, URL, headers, body)
- Response viewer with timing
- Request history navigation
- Diff view (current vs original or vs previous)
- Copy-as-curl

### Tab 3: Intruder
- Config sub-view: template editor, position marking, mode selection, payload pipeline config, grep rules
- Results sub-view: live-updating sortable table with payload, status, length, time, grep matches
- Attack stats: match count, timing percentiles, error count
- Pause/resume/stop controls

### Tab 4: Scope
- Include/exclude rule list with regex patterns
- Toggle, add, delete, edit rules
- Import from knowledge graph

### Tab 5: Payload Lists
- Named payload list manager
- Preview entries
- Import from file, generate from range/brute-force

### Tab 6: Comparer
- Side-by-side request/response comparison
- Three diff modes: Word, Line, Hex
- Jump between differences
- Synchronized scrolling

### Keybindings
- Vim-style navigation (j/k/h/l, /, gg/G)
- Number keys for tab switching
- Single-letter shortcuts for actions (shown in status bar)
- `?` for help overlay
- `q` to quit

## Size Estimate

| Component | LOC |
|-----------|-----|
| proxy crate enhancements | ~1,500 |
| proxy-tui crate | ~2,500-3,000 |
| Test files | ~1,500 |
| **Total** | **~5,000-5,500** |

## Key Differentiator vs. Burp

Knowledge graph integration. `aegis proxy --import-graph scan.db` pre-populates the proxy with discovered endpoints, known vulnerabilities, and defense context from a prior automated scan. Manual testing is informed by automated findings. Burp has no equivalent.
