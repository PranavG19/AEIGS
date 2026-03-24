# Interactive Proxy TUI — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a ratatui-based interactive proxy TUI with full Burp Suite Repeater/Intruder parity, backed by SQLite persistence.

**Architecture:** Enhance the existing `aegis-proxy` crate with persistence, payload pipeline, grep, diff, scope, and session modules. Create a new `aegis-proxy-tui` crate with ratatui views for 6 tabs (Proxy, Repeater, Intruder, Scope, Payloads, Comparer). Entry point via `aegis proxy` subcommand.

**Tech Stack:** Rust 2024, ratatui + crossterm (TUI), rusqlite (persistence), regex (grep/scope), existing hyper/reqwest proxy infrastructure.

**Design doc:** `docs/plans/2026-02-23-interactive-proxy-tui-design.md`

**HARD REQUIREMENTS:**
- Every task MUST include wiring verification — confirm the module integrates end-to-end with adjacent modules, not just unit tests
- Every task MUST achieve 95%+ test coverage including integration tests
- After EVERY feature, run `cargo test -p aegis-proxy` and `cargo clippy -p aegis-proxy -- -D warnings` to confirm zero regressions
- Follow existing crate conventions: one public type per file, `#[path]` adjacent test files, `lib.rs` only re-exports, builder pattern with `with_*` methods

---

## Phase 1: Proxy Crate Enhancements

### Task 1: SQLite Persistence Layer

**Files:**
- Create: `crates/proxy/src/persistence.rs`
- Create: `crates/proxy/src/persistence_test.rs`
- Modify: `crates/proxy/src/lib.rs` (add module + re-export)
- Modify: `crates/proxy/Cargo.toml` (add rusqlite dep)

**Step 1: Add rusqlite dependency**

In `crates/proxy/Cargo.toml`, add to `[dependencies]`:
```toml
rusqlite = { workspace = true }
```

**Step 2: Write the failing tests**

Create `crates/proxy/src/persistence_test.rs`:

```rust
use super::*;
use crate::types::RecordedExchange;
use tempfile::NamedTempFile;

fn sample_exchange(id: u64) -> RecordedExchange {
    RecordedExchange {
        id,
        request_method: "GET".to_string(),
        request_url: format!("http://localhost:3000/api/users/{id}"),
        request_headers: vec![("host".to_string(), "localhost:3000".to_string())],
        request_body: vec![],
        response_status: 200,
        response_headers: vec![("content-type".to_string(), "application/json".to_string())],
        response_body: b"{\"id\":1}".to_vec(),
        timestamp_ms: 1700000000000 + id,
        duration_ms: 42,
    }
}

#[test]
fn open_creates_schema() {
    let tmp = NamedTempFile::new().unwrap();
    let db = ProxyDb::open(tmp.path()).unwrap();
    // Verify tables exist by inserting and querying
    let ex = sample_exchange(1);
    db.insert_exchange(&ex).unwrap();
    let fetched = db.exchange_by_id(1).unwrap();
    assert!(fetched.is_some());
}

#[test]
fn insert_and_query_exchange() {
    let tmp = NamedTempFile::new().unwrap();
    let db = ProxyDb::open(tmp.path()).unwrap();
    let ex = sample_exchange(1);
    db.insert_exchange(&ex).unwrap();
    let fetched = db.exchange_by_id(1).unwrap().unwrap();
    assert_eq!(fetched.request_method, "GET");
    assert_eq!(fetched.response_status, 200);
    assert_eq!(fetched.request_body, Vec::<u8>::new());
    assert_eq!(fetched.response_body, b"{\"id\":1}");
}

#[test]
fn list_exchanges_returns_all() {
    let tmp = NamedTempFile::new().unwrap();
    let db = ProxyDb::open(tmp.path()).unwrap();
    for i in 1..=5 {
        db.insert_exchange(&sample_exchange(i)).unwrap();
    }
    let all = db.list_exchanges(None, None).unwrap();
    assert_eq!(all.len(), 5);
}

#[test]
fn list_exchanges_with_limit_and_offset() {
    let tmp = NamedTempFile::new().unwrap();
    let db = ProxyDb::open(tmp.path()).unwrap();
    for i in 1..=10 {
        db.insert_exchange(&sample_exchange(i)).unwrap();
    }
    let page = db.list_exchanges(Some(3), Some(2)).unwrap();
    assert_eq!(page.len(), 3);
    assert_eq!(page[0].id, 3); // offset 2 skips first 2
}

#[test]
fn filter_exchanges_by_method() {
    let tmp = NamedTempFile::new().unwrap();
    let db = ProxyDb::open(tmp.path()).unwrap();
    db.insert_exchange(&sample_exchange(1)).unwrap();
    let mut post_ex = sample_exchange(2);
    post_ex.request_method = "POST".to_string();
    db.insert_exchange(&post_ex).unwrap();
    let filtered = db.filter_exchanges("method = 'POST'").unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].id, 2);
}

#[test]
fn search_exchanges_by_url_pattern() {
    let tmp = NamedTempFile::new().unwrap();
    let db = ProxyDb::open(tmp.path()).unwrap();
    db.insert_exchange(&sample_exchange(1)).unwrap();
    let mut other = sample_exchange(2);
    other.request_url = "http://localhost:3000/admin/settings".to_string();
    db.insert_exchange(&other).unwrap();
    let results = db.search_exchanges_by_url("/admin/").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, 2);
}

#[test]
fn delete_exchange() {
    let tmp = NamedTempFile::new().unwrap();
    let db = ProxyDb::open(tmp.path()).unwrap();
    db.insert_exchange(&sample_exchange(1)).unwrap();
    db.delete_exchange(1).unwrap();
    assert!(db.exchange_by_id(1).unwrap().is_none());
}

#[test]
fn clear_all_exchanges() {
    let tmp = NamedTempFile::new().unwrap();
    let db = ProxyDb::open(tmp.path()).unwrap();
    for i in 1..=5 {
        db.insert_exchange(&sample_exchange(i)).unwrap();
    }
    db.clear_exchanges().unwrap();
    let all = db.list_exchanges(None, None).unwrap();
    assert_eq!(all.len(), 0);
}

#[test]
fn exchange_count() {
    let tmp = NamedTempFile::new().unwrap();
    let db = ProxyDb::open(tmp.path()).unwrap();
    assert_eq!(db.exchange_count().unwrap(), 0);
    db.insert_exchange(&sample_exchange(1)).unwrap();
    db.insert_exchange(&sample_exchange(2)).unwrap();
    assert_eq!(db.exchange_count().unwrap(), 2);
}

#[test]
fn binary_body_round_trips() {
    let tmp = NamedTempFile::new().unwrap();
    let db = ProxyDb::open(tmp.path()).unwrap();
    let mut ex = sample_exchange(1);
    ex.request_body = vec![0x00, 0xFF, 0xDE, 0xAD];
    ex.response_body = vec![0xBE, 0xEF, 0x00, 0x01];
    db.insert_exchange(&ex).unwrap();
    let fetched = db.exchange_by_id(1).unwrap().unwrap();
    assert_eq!(fetched.request_body, vec![0x00, 0xFF, 0xDE, 0xAD]);
    assert_eq!(fetched.response_body, vec![0xBE, 0xEF, 0x00, 0x01]);
}

// --- Saved Requests ---

#[test]
fn save_and_load_request() {
    let tmp = NamedTempFile::new().unwrap();
    let db = ProxyDb::open(tmp.path()).unwrap();
    let saved = SavedRequest {
        id: 0, // auto-assigned
        name: "test auth bypass".to_string(),
        method: "PUT".to_string(),
        url: "http://localhost:3000/api/users/1".to_string(),
        headers: vec![("host".to_string(), "localhost".to_string())],
        body: b"{\"role\":\"admin\"}".to_vec(),
        notes: "testing IDOR".to_string(),
        created_at: 1700000000000,
        exchange_id: None,
    };
    let id = db.insert_saved_request(&saved).unwrap();
    let fetched = db.saved_request_by_id(id).unwrap().unwrap();
    assert_eq!(fetched.name, "test auth bypass");
    assert_eq!(fetched.notes, "testing IDOR");
}

#[test]
fn list_saved_requests() {
    let tmp = NamedTempFile::new().unwrap();
    let db = ProxyDb::open(tmp.path()).unwrap();
    for i in 1..=3 {
        let saved = SavedRequest {
            id: 0,
            name: format!("request_{i}"),
            method: "GET".to_string(),
            url: format!("http://localhost/{i}"),
            headers: vec![],
            body: vec![],
            notes: String::new(),
            created_at: 1700000000000 + i,
            exchange_id: None,
        };
        db.insert_saved_request(&saved).unwrap();
    }
    let all = db.list_saved_requests().unwrap();
    assert_eq!(all.len(), 3);
}

// --- Intruder Runs ---

#[test]
fn insert_and_query_intruder_run() {
    let tmp = NamedTempFile::new().unwrap();
    let db = ProxyDb::open(tmp.path()).unwrap();
    let run = IntruderRunRecord {
        id: 0,
        name: "auth brute".to_string(),
        mode: "Sniper".to_string(),
        template_json: "{}".to_string(),
        positions_json: "[]".to_string(),
        concurrency: 10,
        started_at: 1700000000000,
        completed_at: None,
        total_requests: 0,
    };
    let run_id = db.insert_intruder_run(&run).unwrap();
    let fetched = db.intruder_run_by_id(run_id).unwrap().unwrap();
    assert_eq!(fetched.name, "auth brute");
    assert_eq!(fetched.mode, "Sniper");
}

#[test]
fn insert_and_query_intruder_results() {
    let tmp = NamedTempFile::new().unwrap();
    let db = ProxyDb::open(tmp.path()).unwrap();
    let run = IntruderRunRecord {
        id: 0,
        name: "test".to_string(),
        mode: "BatteringRam".to_string(),
        template_json: "{}".to_string(),
        positions_json: "[]".to_string(),
        concurrency: 5,
        started_at: 1700000000000,
        completed_at: None,
        total_requests: 0,
    };
    let run_id = db.insert_intruder_run(&run).unwrap();
    let result = IntruderResultRecord {
        id: 0,
        run_id,
        payload_json: "[\"admin\"]".to_string(),
        status_code: 200,
        body_length: 891,
        duration_ms: 14,
        response_body: b"success".to_vec(),
        grep_matches: "[]".to_string(),
    };
    db.insert_intruder_result(&result).unwrap();
    let results = db.intruder_results_for_run(run_id).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status_code, 200);
    assert_eq!(results[0].response_body, b"success");
}

// --- Payload Lists ---

#[test]
fn insert_and_query_payload_list() {
    let tmp = NamedTempFile::new().unwrap();
    let db = ProxyDb::open(tmp.path()).unwrap();
    let list = PayloadListRecord {
        id: 0,
        name: "sqli-basic".to_string(),
        source: "manual".to_string(),
        entries: "[\"' OR 1=1--\",\"admin\"]".to_string(),
    };
    db.insert_payload_list(&list).unwrap();
    let fetched = db.payload_list_by_name("sqli-basic").unwrap().unwrap();
    assert_eq!(fetched.source, "manual");
    assert!(fetched.entries.contains("OR 1=1"));
}

#[test]
fn list_payload_lists() {
    let tmp = NamedTempFile::new().unwrap();
    let db = ProxyDb::open(tmp.path()).unwrap();
    for name in &["list-a", "list-b"] {
        let list = PayloadListRecord {
            id: 0,
            name: name.to_string(),
            source: "manual".to_string(),
            entries: "[]".to_string(),
        };
        db.insert_payload_list(&list).unwrap();
    }
    let all = db.list_payload_lists().unwrap();
    assert_eq!(all.len(), 2);
}

// --- Wiring: ProxyDb re-opens existing data ---

#[test]
fn reopen_preserves_data() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();
    {
        let db = ProxyDb::open(&path).unwrap();
        db.insert_exchange(&sample_exchange(1)).unwrap();
    }
    // Reopen
    let db = ProxyDb::open(&path).unwrap();
    let fetched = db.exchange_by_id(1).unwrap();
    assert!(fetched.is_some());
}
```

**Step 3: Run tests to verify they fail**

Run: `cargo test -p aegis-proxy --lib -- persistence_test -v 2>&1 | tail -5`
Expected: compilation errors (module doesn't exist yet)

**Step 4: Implement persistence.rs**

Create `crates/proxy/src/persistence.rs`:

```rust
use std::path::Path;

use rusqlite::{Connection, params};

use crate::types::RecordedExchange;

/// Record types for SQLite-backed storage.

#[derive(Debug, Clone)]
pub struct SavedRequest {
    pub id: i64,
    pub name: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub notes: String,
    pub created_at: u64,
    pub exchange_id: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct IntruderRunRecord {
    pub id: i64,
    pub name: String,
    pub mode: String,
    pub template_json: String,
    pub positions_json: String,
    pub concurrency: usize,
    pub started_at: u64,
    pub completed_at: Option<u64>,
    pub total_requests: u64,
}

#[derive(Debug, Clone)]
pub struct IntruderResultRecord {
    pub id: i64,
    pub run_id: i64,
    pub payload_json: String,
    pub status_code: u16,
    pub body_length: usize,
    pub duration_ms: u64,
    pub response_body: Vec<u8>,
    pub grep_matches: String,
}

#[derive(Debug, Clone)]
pub struct PayloadListRecord {
    pub id: i64,
    pub name: String,
    pub source: String,
    pub entries: String,
}

/// SQLite-backed persistent storage for proxy data.
pub struct ProxyDb {
    conn: Connection,
}

impl ProxyDb {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let db = Self { conn };
        db.create_schema()?;
        Ok(db)
    }

    fn create_schema(&self) -> Result<(), rusqlite::Error> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS exchanges (
                id              INTEGER PRIMARY KEY,
                method          TEXT NOT NULL,
                url             TEXT NOT NULL,
                request_headers TEXT NOT NULL,
                request_body    BLOB,
                response_status INTEGER NOT NULL,
                response_headers TEXT NOT NULL,
                response_body   BLOB,
                timestamp_ms    INTEGER NOT NULL,
                duration_ms     INTEGER NOT NULL,
                in_scope        INTEGER NOT NULL DEFAULT 1,
                tags            TEXT DEFAULT '[]'
            );
            CREATE INDEX IF NOT EXISTS idx_exchanges_url ON exchanges(url);
            CREATE INDEX IF NOT EXISTS idx_exchanges_timestamp ON exchanges(timestamp_ms);

            CREATE TABLE IF NOT EXISTS scope_rules (
                id         INTEGER PRIMARY KEY,
                pattern    TEXT NOT NULL,
                is_include INTEGER NOT NULL,
                priority   INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS saved_requests (
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

            CREATE TABLE IF NOT EXISTS intruder_runs (
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

            CREATE TABLE IF NOT EXISTS intruder_results (
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
            CREATE INDEX IF NOT EXISTS idx_intruder_results_run ON intruder_results(run_id);

            CREATE TABLE IF NOT EXISTS payload_lists (
                id      INTEGER PRIMARY KEY,
                name    TEXT NOT NULL UNIQUE,
                source  TEXT NOT NULL,
                entries TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cookies (
                id        INTEGER PRIMARY KEY,
                domain    TEXT NOT NULL,
                name      TEXT NOT NULL,
                value     TEXT NOT NULL,
                path      TEXT DEFAULT '/',
                expires   INTEGER,
                secure    INTEGER DEFAULT 0,
                http_only INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS modification_rules (
                id            INTEGER PRIMARY KEY,
                enabled       INTEGER NOT NULL DEFAULT 1,
                match_target  TEXT NOT NULL,
                match_pattern TEXT NOT NULL,
                replace_with  TEXT NOT NULL
            );"
        )
    }

    // --- Exchanges ---

    pub fn insert_exchange(&self, ex: &RecordedExchange) -> Result<(), rusqlite::Error> {
        let headers_json = serde_json::to_string(&ex.request_headers).unwrap_or_default();
        let resp_headers_json = serde_json::to_string(&ex.response_headers).unwrap_or_default();
        self.conn.execute(
            "INSERT INTO exchanges (id, method, url, request_headers, request_body,
             response_status, response_headers, response_body, timestamp_ms, duration_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                ex.id as i64,
                ex.request_method,
                ex.request_url,
                headers_json,
                ex.request_body,
                ex.response_status as i64,
                resp_headers_json,
                ex.response_body,
                ex.timestamp_ms as i64,
                ex.duration_ms as i64,
            ],
        )?;
        Ok(())
    }

    pub fn exchange_by_id(&self, id: u64) -> Result<Option<RecordedExchange>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, method, url, request_headers, request_body,
             response_status, response_headers, response_body, timestamp_ms, duration_ms
             FROM exchanges WHERE id = ?1"
        )?;
        let mut rows = stmt.query_map(params![id as i64], |row| {
            Ok(row_to_exchange(row))
        })?;
        match rows.next() {
            Some(Ok(ex)) => Ok(Some(ex)),
            _ => Ok(None),
        }
    }

    pub fn list_exchanges(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<RecordedExchange>, rusqlite::Error> {
        let sql = format!(
            "SELECT id, method, url, request_headers, request_body,
             response_status, response_headers, response_body, timestamp_ms, duration_ms
             FROM exchanges ORDER BY id ASC LIMIT {} OFFSET {}",
            limit.unwrap_or(10_000),
            offset.unwrap_or(0)
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| Ok(row_to_exchange(row)))?;
        rows.collect()
    }

    pub fn filter_exchanges(&self, where_clause: &str) -> Result<Vec<RecordedExchange>, rusqlite::Error> {
        let sql = format!(
            "SELECT id, method, url, request_headers, request_body,
             response_status, response_headers, response_body, timestamp_ms, duration_ms
             FROM exchanges WHERE {where_clause} ORDER BY id ASC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| Ok(row_to_exchange(row)))?;
        rows.collect()
    }

    pub fn search_exchanges_by_url(&self, pattern: &str) -> Result<Vec<RecordedExchange>, rusqlite::Error> {
        let like_pattern = format!("%{pattern}%");
        let mut stmt = self.conn.prepare(
            "SELECT id, method, url, request_headers, request_body,
             response_status, response_headers, response_body, timestamp_ms, duration_ms
             FROM exchanges WHERE url LIKE ?1 ORDER BY id ASC"
        )?;
        let rows = stmt.query_map(params![like_pattern], |row| Ok(row_to_exchange(row)))?;
        rows.collect()
    }

    pub fn delete_exchange(&self, id: u64) -> Result<(), rusqlite::Error> {
        self.conn.execute("DELETE FROM exchanges WHERE id = ?1", params![id as i64])?;
        Ok(())
    }

    pub fn clear_exchanges(&self) -> Result<(), rusqlite::Error> {
        self.conn.execute("DELETE FROM exchanges", [])?;
        Ok(())
    }

    pub fn exchange_count(&self) -> Result<u64, rusqlite::Error> {
        let count: i64 = self.conn.query_row("SELECT COUNT(*) FROM exchanges", [], |r| r.get(0))?;
        Ok(count as u64)
    }

    // --- Saved Requests ---

    pub fn insert_saved_request(&self, req: &SavedRequest) -> Result<i64, rusqlite::Error> {
        let headers_json = serde_json::to_string(&req.headers).unwrap_or_default();
        self.conn.execute(
            "INSERT INTO saved_requests (name, method, url, headers, body, notes, created_at, exchange_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                req.name, req.method, req.url, headers_json, req.body,
                req.notes, req.created_at as i64, req.exchange_id.map(|e| e as i64),
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn saved_request_by_id(&self, id: i64) -> Result<Option<SavedRequest>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, method, url, headers, body, notes, created_at, exchange_id
             FROM saved_requests WHERE id = ?1"
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            let headers_json: String = row.get(4)?;
            let headers: Vec<(String, String)> = serde_json::from_str(&headers_json).unwrap_or_default();
            Ok(SavedRequest {
                id: row.get(0)?,
                name: row.get(1)?,
                method: row.get(2)?,
                url: row.get(3)?,
                headers,
                body: row.get(5)?,
                notes: row.get(6)?,
                created_at: row.get::<_, i64>(7)? as u64,
                exchange_id: row.get::<_, Option<i64>>(8)?.map(|v| v as u64),
            })
        })?;
        match rows.next() {
            Some(Ok(req)) => Ok(Some(req)),
            _ => Ok(None),
        }
    }

    pub fn list_saved_requests(&self) -> Result<Vec<SavedRequest>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, method, url, headers, body, notes, created_at, exchange_id
             FROM saved_requests ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            let headers_json: String = row.get(4)?;
            let headers: Vec<(String, String)> = serde_json::from_str(&headers_json).unwrap_or_default();
            Ok(SavedRequest {
                id: row.get(0)?,
                name: row.get(1)?,
                method: row.get(2)?,
                url: row.get(3)?,
                headers,
                body: row.get(5)?,
                notes: row.get(6)?,
                created_at: row.get::<_, i64>(7)? as u64,
                exchange_id: row.get::<_, Option<i64>>(8)?.map(|v| v as u64),
            })
        })?;
        rows.collect()
    }

    // --- Intruder Runs ---

    pub fn insert_intruder_run(&self, run: &IntruderRunRecord) -> Result<i64, rusqlite::Error> {
        self.conn.execute(
            "INSERT INTO intruder_runs (name, mode, template_json, positions_json, concurrency, started_at, completed_at, total_requests)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                run.name, run.mode, run.template_json, run.positions_json,
                run.concurrency as i64, run.started_at as i64,
                run.completed_at.map(|c| c as i64), run.total_requests as i64,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn intruder_run_by_id(&self, id: i64) -> Result<Option<IntruderRunRecord>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, mode, template_json, positions_json, concurrency, started_at, completed_at, total_requests
             FROM intruder_runs WHERE id = ?1"
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(IntruderRunRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                mode: row.get(2)?,
                template_json: row.get(3)?,
                positions_json: row.get(4)?,
                concurrency: row.get::<_, i64>(5)? as usize,
                started_at: row.get::<_, i64>(6)? as u64,
                completed_at: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
                total_requests: row.get::<_, i64>(8)? as u64,
            })
        })?;
        match rows.next() {
            Some(Ok(run)) => Ok(Some(run)),
            _ => Ok(None),
        }
    }

    pub fn update_intruder_run_completed(&self, id: i64, completed_at: u64, total: u64) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "UPDATE intruder_runs SET completed_at = ?1, total_requests = ?2 WHERE id = ?3",
            params![completed_at as i64, total as i64, id],
        )?;
        Ok(())
    }

    // --- Intruder Results ---

    pub fn insert_intruder_result(&self, result: &IntruderResultRecord) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT INTO intruder_results (run_id, payload_json, status_code, body_length, duration_ms, response_body, grep_matches)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                result.run_id, result.payload_json, result.status_code as i64,
                result.body_length as i64, result.duration_ms as i64,
                result.response_body, result.grep_matches,
            ],
        )?;
        Ok(())
    }

    pub fn intruder_results_for_run(&self, run_id: i64) -> Result<Vec<IntruderResultRecord>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, run_id, payload_json, status_code, body_length, duration_ms, response_body, grep_matches
             FROM intruder_results WHERE run_id = ?1 ORDER BY id ASC"
        )?;
        let rows = stmt.query_map(params![run_id], |row| {
            Ok(IntruderResultRecord {
                id: row.get(0)?,
                run_id: row.get(1)?,
                payload_json: row.get(2)?,
                status_code: row.get::<_, i64>(3)? as u16,
                body_length: row.get::<_, i64>(4)? as usize,
                duration_ms: row.get::<_, i64>(5)? as u64,
                response_body: row.get(6)?,
                grep_matches: row.get(7)?,
            })
        })?;
        rows.collect()
    }

    // --- Payload Lists ---

    pub fn insert_payload_list(&self, list: &PayloadListRecord) -> Result<i64, rusqlite::Error> {
        self.conn.execute(
            "INSERT INTO payload_lists (name, source, entries) VALUES (?1, ?2, ?3)",
            params![list.name, list.source, list.entries],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn payload_list_by_name(&self, name: &str) -> Result<Option<PayloadListRecord>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, source, entries FROM payload_lists WHERE name = ?1"
        )?;
        let mut rows = stmt.query_map(params![name], |row| {
            Ok(PayloadListRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                source: row.get(2)?,
                entries: row.get(3)?,
            })
        })?;
        match rows.next() {
            Some(Ok(list)) => Ok(Some(list)),
            _ => Ok(None),
        }
    }

    pub fn list_payload_lists(&self) -> Result<Vec<PayloadListRecord>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, source, entries FROM payload_lists ORDER BY name ASC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PayloadListRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                source: row.get(2)?,
                entries: row.get(3)?,
            })
        })?;
        rows.collect()
    }
}

fn row_to_exchange(row: &rusqlite::Row<'_>) -> RecordedExchange {
    let req_headers_json: String = row.get(3).unwrap_or_default();
    let resp_headers_json: String = row.get(6).unwrap_or_default();
    RecordedExchange {
        id: row.get::<_, i64>(0).unwrap_or(0) as u64,
        request_method: row.get(1).unwrap_or_default(),
        request_url: row.get(2).unwrap_or_default(),
        request_headers: serde_json::from_str(&req_headers_json).unwrap_or_default(),
        request_body: row.get(4).unwrap_or_default(),
        response_status: row.get::<_, i64>(5).unwrap_or(0) as u16,
        response_headers: serde_json::from_str(&resp_headers_json).unwrap_or_default(),
        response_body: row.get(7).unwrap_or_default(),
        timestamp_ms: row.get::<_, i64>(8).unwrap_or(0) as u64,
        duration_ms: row.get::<_, i64>(9).unwrap_or(0) as u64,
    }
}

#[cfg(test)]
#[path = "persistence_test.rs"]
mod persistence_test;
```

**Step 5: Register module in lib.rs**

Add to `crates/proxy/src/lib.rs`:
```rust
mod persistence;
pub use persistence::*;
```

Also add `tempfile` to `[dev-dependencies]` in `crates/proxy/Cargo.toml`:
```toml
tempfile = { workspace = true }
```

**Step 6: Run tests to verify they pass**

Run: `cargo test -p aegis-proxy --lib -- persistence_test -v`
Expected: all 16 tests pass

**Step 7: Run full crate tests + clippy**

Run: `cargo test -p aegis-proxy && cargo clippy -p aegis-proxy -- -D warnings`
Expected: all 43 existing + 16 new tests pass, zero clippy warnings

**Step 8: Commit**

```bash
git add crates/proxy/src/persistence.rs crates/proxy/src/persistence_test.rs crates/proxy/src/lib.rs crates/proxy/Cargo.toml
git commit -m "[proxy] add SQLite persistence layer with ProxyDb"
```

---

### Task 2: Diff Engine

**Files:**
- Create: `crates/proxy/src/diff.rs`
- Create: `crates/proxy/src/diff_test.rs`
- Modify: `crates/proxy/src/lib.rs` (add module)

**Step 1: Write the failing tests**

Create `crates/proxy/src/diff_test.rs` with tests for:
- `compute_line_diff` on identical strings returns all `Equal` chunks
- `compute_line_diff` on completely different strings returns `Removed` + `Added`
- `compute_line_diff` detects inserted/removed lines in middle
- `compute_word_diff` highlights changed words within a line
- `compare_responses` detects status change, header diffs, body diffs, length delta, timing delta
- `compare_responses` with identical responses shows no diffs
- `HeaderDiff::Added`, `HeaderDiff::Removed`, `HeaderDiff::Changed` variants

**Step 2: Implement diff.rs**

LCS-based line diff algorithm (~80 lines). Types: `DiffChunk` (Equal/Added/Removed), `HeaderDiff` (Added/Removed/Changed), `DiffResult`, `WordDiff`. Functions: `compute_line_diff(left, right) -> Vec<DiffChunk>`, `compute_word_diff(left, right) -> Vec<WordDiff>`, `compare_responses(original: &RepeaterResult, current: &RepeaterResult) -> DiffResult`.

**Step 3: Run tests, verify pass. Clippy + full suite. Commit.**

```bash
git commit -m "[proxy] add diff engine for request/response comparison"
```

---

### Task 3: Grep Engine

**Files:**
- Create: `crates/proxy/src/grep.rs`
- Create: `crates/proxy/src/grep_test.rs`
- Modify: `crates/proxy/src/lib.rs`
- Modify: `crates/proxy/Cargo.toml` (add `regex` dep)

**Step 1: Write tests for:**
- `GrepMatch` finds pattern in body, headers, both
- `GrepMatch` with `negate=true` flags when NOT matched
- `GrepExtract` extracts capture group from body
- `GrepExtract` extracts from headers
- `apply_grep_matches` returns list of matched pattern strings
- `apply_grep_extracts` returns extracted values
- Invalid regex returns error (not panic)

**Step 2: Implement grep.rs**

Types: `SearchTarget` (Body/Headers/Both), `GrepMatch`, `GrepExtract`. Functions: `apply_grep_matches(matches, status, headers, body) -> Vec<String>`, `apply_grep_extracts(extracts, headers, body) -> Vec<String>`.

Add `regex = { workspace = true }` to `crates/proxy/Cargo.toml`.

**Step 3: Run tests, clippy, full suite. Commit.**

```bash
git commit -m "[proxy] add grep-match and grep-extract for response analysis"
```

---

### Task 4: Scope Engine

**Files:**
- Create: `crates/proxy/src/scope.rs`
- Create: `crates/proxy/src/scope_test.rs`
- Modify: `crates/proxy/src/lib.rs`

**Step 1: Write tests for:**
- No rules = everything in scope
- Include rule matches URL = in scope
- Include rule doesn't match = out of scope
- Exclude rule removes from scope
- Include + exclude interaction (include first, then exclude)
- `add_rule`, `remove_rule`, `toggle_rule`
- Regex compilation error returns error
- Priority ordering

**Step 2: Implement scope.rs**

Types: `ScopeRule { id, pattern, is_include, enabled }`, `ScopeEngine`. Functions: `ScopeEngine::new()`, `add_rule()`, `remove_rule()`, `is_in_scope(url) -> bool`. Compiles regex on `add_rule`; caches `Vec<(Regex, bool)>`.

**Step 3: Run tests, clippy, full suite. Commit.**

```bash
git commit -m "[proxy] add URL scope engine with include/exclude regex rules"
```

---

### Task 5: Payload Pipeline

**Files:**
- Create: `crates/proxy/src/payload.rs`
- Create: `crates/proxy/src/payload_test.rs`
- Modify: `crates/proxy/src/lib.rs`

**Step 1: Write tests for each payload source:**
- `SimpleList` generates exact items
- `NumberRange { 1, 5, 1 }` generates `["1","2","3","4","5"]`
- `NullPayloads(3)` generates 3 empty strings
- `BruteForce { "ab", 1, 2 }` generates `["a","b","aa","ab","ba","bb"]`
- `FromFile` reads one-per-line (use tempfile)
- `DateRange` generates date strings in format

**Write tests for each processor:**
- `AddPrefix("x")` on "y" = "xy"
- `AddSuffix("!")` on "y" = "y!"
- `Reverse` on "abc" = "cba"
- `ChangeCase(Upper)` on "abc" = "ABC"
- `SkipIf("bad")` filters out "bad" but keeps "good"
- `MatchOnly("good")` keeps only "good"
- `Substring { 1, Some(2) }` on "abcde" = "bc"
- `RegexReplace { "\\d+", "N" }` on "abc123" = "abcN"

**Write tests for each encoding:**
- `UrlEncode` on `"a b&c"` = `"a%20b%26c"`
- `Base64Encode` on "hello" = "aGVsbG8="
- `Hex` on "AB" = "4142"
- `Sha256` on "test" = known hash
- `Chain([UrlEncode, Base64Encode])` applies in order

**Write pipeline integration test:**
- `PayloadPipeline { source: NumberRange(1,3,1), processors: [AddPrefix("id=")], encoding: UrlEncode }` generates `["id%3D1", "id%3D2", "id%3D3"]`

**Step 2: Implement payload.rs**

Types: `PayloadSource`, `PayloadProcessor`, `PayloadEncoding`, `CaseMode`, `PayloadPipeline`. Functions: `PayloadPipeline::generate() -> Result<Vec<String>, PayloadError>`. Each source has a `generate()` method. Processors applied via `fold`. Encoding applied last.

**Step 3: Run tests, clippy, full suite. Commit.**

```bash
git commit -m "[proxy] add payload pipeline with sources, processors, and encoding"
```

---

### Task 6: Session Management

**Files:**
- Create: `crates/proxy/src/session.rs`
- Create: `crates/proxy/src/session_test.rs`
- Modify: `crates/proxy/src/lib.rs`

**Step 1: Write tests for:**
- `SessionJar::new()` is empty
- `update_from_response` parses `Set-Cookie` headers
- `cookies_for_url` returns matching cookies by domain/path
- `inject_cookies` adds Cookie header to request headers
- `is_session_cookie` detects session/token/auth/sid/jwt patterns
- Expired cookies are excluded from injection
- `clear()` empties the jar

**Step 2: Implement session.rs**

Types: `Cookie { name, value, domain, path, expires, secure, http_only }`, `SessionJar { cookies: HashMap<String, Vec<Cookie>>, auto_update: bool }`. Functions: `update_from_response(url, headers)`, `cookies_for_url(url) -> Vec<&Cookie>`, `inject_cookies(url, headers) -> Vec<(String, String)>`, `is_session_cookie(name) -> bool`.

**Step 3: Run tests, clippy, full suite. Commit.**

```bash
git commit -m "[proxy] add session jar with cookie tracking and injection"
```

---

### Task 7: Modification Rules

**Files:**
- Create: `crates/proxy/src/modification.rs`
- Create: `crates/proxy/src/modification_test.rs`
- Modify: `crates/proxy/src/lib.rs`

**Step 1: Write tests for:**
- `apply_rules` modifies matching request header
- `apply_rules` modifies response header
- `apply_rules` modifies request body with regex capture group
- Disabled rule is skipped
- Non-matching rule leaves content unchanged
- Multiple rules applied in order

**Step 2: Implement modification.rs**

Types: `MatchTarget` (RequestHeader/RequestBody/ResponseHeader/ResponseBody), `ModificationRule { id, enabled, match_target, match_pattern, replace_with }`, `ModificationEngine`. Functions: `apply_to_request(rules, method, url, headers, body)`, `apply_to_response(rules, status, headers, body)`.

**Step 3: Run tests, clippy, full suite. Commit.**

```bash
git commit -m "[proxy] add match-and-replace modification rules for proxy traffic"
```

---

### Task 8: Wire Persistence Into Proxy

**Files:**
- Modify: `crates/proxy/src/proxy.rs` (add optional ProxyDb write-through)
- Modify: `crates/proxy/src/types.rs` (add `in_scope` and `tags` fields to RecordedExchange)
- Modify: `crates/proxy/src/proxy_test.rs` (add wiring tests)

**Step 1: Write wiring tests:**
- Start proxy with `ProxyDb` → send request → verify exchange in SQLite
- Start proxy with `ScopeEngine` → send in-scope and out-of-scope requests → verify `in_scope` field
- Proxy without persistence (existing behavior) still works

**Step 2: Enhance `ProxyConfig`**

Add optional fields:
```rust
pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub max_log_size: usize,
    pub db_path: Option<PathBuf>,      // NEW
    pub scope: Option<ScopeEngine>,    // NEW
}
```

**Step 3: Modify `handle_request` to write through to ProxyDb when configured**

The `start_proxy` function creates an `Option<Arc<Mutex<ProxyDb>>>` from `config.db_path`, passes it into `accept_loop`. `append_exchange` writes to both in-memory log and SQLite.

**Step 4: Add `in_scope` and `tags` to `RecordedExchange`**

```rust
pub struct RecordedExchange {
    // ... existing fields ...
    pub in_scope: bool,        // NEW, default true
    pub tags: Vec<String>,     // NEW, default empty
}
```

Update all existing test code that constructs `RecordedExchange` to include the new fields.

**Step 5: Run ALL tests (entire crate), verify zero regressions. Clippy. Commit.**

```bash
git commit -m "[proxy] wire SQLite persistence and scope into recording proxy"
```

---

### Task 9: Wire Payload Pipeline Into Intruder

**Files:**
- Modify: `crates/proxy/src/intruder.rs` (accept PayloadPipeline, add grep)
- Modify: `crates/proxy/src/intruder_test.rs` (add pipeline + grep tests)

**Step 1: Write wiring tests:**
- `IntruderConfig` with `PayloadPipeline` source generates correct payloads (NumberRange + UrlEncode)
- `IntruderConfig` with `GrepMatch` populates `grep_matches` in results
- `IntruderConfig` with `GrepExtract` populates extracted values
- Backwards compat: existing `Vec<Vec<String>>` still works (via `PayloadSource::SimpleList`)

**Step 2: Add `PipelineIntruderConfig` alongside existing `IntruderConfig`**

```rust
pub struct PipelineIntruderConfig {
    pub template: ModifiedRequest,
    pub positions: Vec<String>,
    pub pipelines: Vec<PayloadPipeline>,  // one per position
    pub mode: AttackMode,
    pub concurrency: usize,
    pub grep_matches: Vec<GrepMatch>,
    pub grep_extracts: Vec<GrepExtract>,
}
```

Add `run_pipeline_intruder(config: PipelineIntruderConfig) -> Vec<PipelineIntruderResult>` that generates payloads from pipelines, runs attack, applies grep to each response.

**Step 3: Add `PipelineIntruderResult` with grep fields:**

```rust
pub struct PipelineIntruderResult {
    pub payload: Vec<String>,
    pub status_code: u16,
    pub body_length: usize,
    pub duration_ms: u64,
    pub response_body: Vec<u8>,
    pub grep_matches: Vec<String>,
    pub grep_extracts: Vec<String>,
}
```

**Step 4: Run all tests, clippy, full suite. Commit.**

```bash
git commit -m "[proxy] wire payload pipeline and grep into intruder attack engine"
```

---

### Task 10: Phase 1 Integration Test

**Files:**
- Create: `crates/proxy/tests/integration.rs`

**Step 1: Write end-to-end integration test**

This test verifies the FULL wiring: proxy → persistence → scope → intruder → grep → graph sync.

```rust
// Start proxy with persistence and scope
// Send requests through proxy (via reqwest pointed at proxy addr)
// Verify exchanges in SQLite
// Select an exchange, send to repeater, get diff
// Run intruder with payload pipeline + grep
// Verify intruder results in SQLite with grep matches
// Sync exchanges to knowledge graph
// Verify graph operations
```

**Step 2: Run integration test**

Run: `cargo test -p aegis-proxy --test integration -v`
Expected: full pipeline passes end to end

**Step 3: Run full workspace test + clippy to confirm zero cross-crate regressions**

Run: `cargo test --workspace && cargo clippy --workspace -- -D warnings`

**Step 4: Commit**

```bash
git commit -m "[proxy] add end-to-end integration test for persistence + scope + intruder pipeline"
```

---

## Phase 2: TUI Crate Setup

### Task 11: Create proxy-tui Crate Skeleton

**Files:**
- Create: `crates/proxy-tui/Cargo.toml`
- Create: `crates/proxy-tui/src/lib.rs`
- Create: `crates/proxy-tui/src/main.rs`
- Modify: `Cargo.toml` (workspace members)

**Step 1: Create Cargo.toml**

```toml
[package]
name = "aegis-proxy-tui"
version.workspace = true
edition.workspace = true
license.workspace = true

[[bin]]
name = "aegis-proxy-tui"
path = "src/main.rs"

[dependencies]
aegis-proxy = { path = "../proxy" }
aegis-protocol = { path = "../protocol" }
ratatui = "0.29"
crossterm = "0.28"
clap = { workspace = true }
tokio = { workspace = true }
serde_json = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
```

**Step 2: Add to workspace**

Add `"crates/proxy-tui"` to `[workspace] members` in root `Cargo.toml`.

**Step 3: Create minimal main.rs with clap**

```rust
use clap::Parser;

#[derive(Parser)]
#[command(name = "aegis-proxy-tui", about = "Interactive proxy with TUI")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,
    #[arg(long)]
    import_graph: Option<String>,
    #[arg(long)]
    db: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    println!("AEGIS Proxy TUI — listening on {}", args.listen);
    Ok(())
}
```

**Step 4: Verify it compiles and runs**

Run: `cargo build -p aegis-proxy-tui && cargo run -p aegis-proxy-tui -- --help`
Expected: help text printed, exit 0

**Step 5: Commit**

```bash
git commit -m "[proxy-tui] create crate skeleton with clap CLI"
```

---

### Task 12: App State Machine & Event Loop

**Files:**
- Create: `crates/proxy-tui/src/app.rs`
- Create: `crates/proxy-tui/src/app_test.rs`
- Create: `crates/proxy-tui/src/keybinds.rs`
- Create: `crates/proxy-tui/src/keybinds_test.rs`
- Modify: `crates/proxy-tui/src/lib.rs`
- Modify: `crates/proxy-tui/src/main.rs`

**Step 1: Write tests for app state transitions:**
- Tab switching: 1-6 keys change active tab
- `q` sets `should_quit = true`
- `?` toggles help overlay
- State starts on Tab 1 (Proxy)

**Step 2: Implement app.rs**

Types:
```rust
pub enum Tab { Proxy, Repeater, Intruder, Scope, Payloads, Comparer }

pub struct App {
    pub active_tab: Tab,
    pub should_quit: bool,
    pub show_help: bool,
    // ... per-tab state added in later tasks
}
```

Functions: `App::new()`, `App::handle_key(KeyEvent)`, `App::render(frame)`.

**Step 3: Implement keybinds.rs**

Map `KeyCode` + `KeyModifiers` to `Action` enum. Vim-style: j/k for up/down, `/` for search, etc.

**Step 4: Wire into main.rs**

Set up crossterm terminal, ratatui event loop, render `App`.

**Step 5: Verify TUI launches and responds to tab keys**

Run: `cargo run -p aegis-proxy-tui` — TUI should display, tab keys switch, `q` quits.

**Step 6: Run tests, clippy. Commit.**

```bash
git commit -m "[proxy-tui] add app state machine, event loop, and keybindings"
```

---

### Task 13: Reusable Table Widget

**Files:**
- Create: `crates/proxy-tui/src/widgets/mod.rs`
- Create: `crates/proxy-tui/src/widgets/table.rs`
- Create: `crates/proxy-tui/src/widgets/table_test.rs`

**Step 1: Write tests for:**
- Sort by column (ascending, descending)
- Filter rows by predicate
- Selection cursor wraps at boundaries
- Column width calculation from data

**Step 2: Implement sortable/filterable table widget**

Generic over row data. Supports: column definitions, sort by column index, filter closure, selection tracking. Renders via `ratatui::widgets::Table`.

**Step 3: Tests, clippy, commit.**

```bash
git commit -m "[proxy-tui] add reusable sortable/filterable table widget"
```

---

### Tasks 14-16: Additional Widgets (status_bar, hex_view, diff_view)

Same TDD pattern: tests first, implement, verify wiring with ratatui rendering, commit each.

```bash
git commit -m "[proxy-tui] add status bar widget"
git commit -m "[proxy-tui] add hex/raw/pretty body viewer widget"
git commit -m "[proxy-tui] add side-by-side diff view widget"
```

---

## Phase 3: TUI Views

### Task 17: Proxy Log View

**Files:**
- Create: `crates/proxy-tui/src/views/mod.rs`
- Create: `crates/proxy-tui/src/views/proxy_log.rs`
- Create: `crates/proxy-tui/src/views/proxy_log_test.rs`

**Step 1: Write tests for:**
- Renders exchange list from ProxyDb
- Filter by URL regex narrows displayed rows
- Selection sends exchange to repeater state
- Tags are displayed and editable

**Step 2: Implement proxy_log.rs**

Uses the table widget. Loads exchanges from `ProxyDb`. Split pane shows selected exchange's request/response. Keybinds: `r` → send to repeater, `i` → send to intruder, `s` → save, `t` → tag, `/` → filter.

**WIRING VERIFICATION:** Start proxy with ProxyDb, send real HTTP requests, verify they appear in the TUI view backed by SQLite data.

**Step 3: Tests, clippy, full suite. Commit.**

```bash
git commit -m "[proxy-tui] add proxy log view with filter, search, and split pane"
```

---

### Task 18: Request Editor View

**Files:**
- Create: `crates/proxy-tui/src/views/request_editor.rs`
- Create: `crates/proxy-tui/src/views/request_editor_test.rs`

**Step 1: Write tests for:**
- Loads ModifiedRequest into editable fields
- Editing URL/method/headers/body updates internal state
- `Enter` triggers send and populates response
- `c` copies as curl command

**Step 2: Implement. WIRING: verify edits actually modify the request sent by Repeater.**

```bash
git commit -m "[proxy-tui] add request editor view with editable fields"
```

---

### Task 19: Response View

**Files:**
- Create: `crates/proxy-tui/src/views/response.rs`
- Create: `crates/proxy-tui/src/views/response_test.rs`

**Step 1: Tests for:** status/headers/body display, hex toggle, body search.

```bash
git commit -m "[proxy-tui] add response viewer with hex/raw/pretty modes"
```

---

### Task 20: Repeater View

**Files:**
- Create: `crates/proxy-tui/src/views/repeater.rs`
- Create: `crates/proxy-tui/src/views/repeater_test.rs`

**Step 1: Write tests for:**
- Edit request → send → response displayed
- History navigation (left/right arrows)
- Diff view compares current vs original
- Diff view compares current vs previous

**WIRING VERIFICATION:** Load exchange from ProxyDb → edit in request editor → send via Repeater → diff with original → all connected end-to-end.

```bash
git commit -m "[proxy-tui] add repeater view with history and diff"
```

---

### Task 21: Intruder View

**Files:**
- Create: `crates/proxy-tui/src/views/intruder.rs`
- Create: `crates/proxy-tui/src/views/intruder_test.rs`

**Step 1: Write tests for:**
- Position marking with `Space` key
- Mode selection with `m` key
- Payload pipeline configuration
- Attack launch starts background task
- Results table updates as results arrive
- Grep match/extract columns populated
- Stats computed (match count, timing percentiles)
- Pause/resume/stop controls

**WIRING VERIFICATION:**
- Load exchange from proxy log → mark positions → configure payload pipeline → run attack → results flow into table AND into ProxyDb (intruder_runs + intruder_results tables) → grep matches visible.
- This is the most critical wiring test: proxy → intruder → payload pipeline → grep → persistence.

```bash
git commit -m "[proxy-tui] add intruder view with config, live results, and grep"
```

---

### Task 22: Scope View

**Files:**
- Create: `crates/proxy-tui/src/views/scope.rs`
- Create: `crates/proxy-tui/src/views/scope_test.rs`

**Step 1: Tests for:** add/remove/toggle rules, import from graph.

**WIRING:** Change scope rules → verify proxy log view dims out-of-scope exchanges.

```bash
git commit -m "[proxy-tui] add scope rule editor view"
```

---

### Task 23: Payload List Manager View

**Files:**
- Create: `crates/proxy-tui/src/views/payloads.rs`
- Create: `crates/proxy-tui/src/views/payloads_test.rs`

**Step 1: Tests for:** list/add/delete payload lists, import from file, preview entries.

**WIRING:** Create payload list → use it in intruder config → verify payloads generated from SQLite-stored list.

```bash
git commit -m "[proxy-tui] add payload list manager view"
```

---

### Task 24: Comparer View

**Files:**
- Create: `crates/proxy-tui/src/views/comparer.rs`
- Create: `crates/proxy-tui/src/views/comparer_test.rs`

**Step 1: Tests for:**
- Select two exchanges → side-by-side display
- Word/Line/Hex diff mode switching
- Next/prev diff navigation
- Synced scrolling

**WIRING:** Select exchanges from proxy log or intruder results → compare in comparer view → diff engine produces correct output.

```bash
git commit -m "[proxy-tui] add comparer view with word/line/hex diff modes"
```

---

## Phase 4: Final Wiring & Integration

### Task 25: Wire Subcommand Into Orchestrator

**Files:**
- Modify: `crates/orchestrator/src/main.rs` (add `proxy` subcommand dispatch)
- Modify: `crates/orchestrator/Cargo.toml` (add aegis-proxy-tui dep, optional feature)

**Step 1: Add subcommand dispatch**

Same pattern as `recon`, `attest`, `update-db`:
```rust
if args.len() > 1 && args[1] == "proxy" {
    // Launch TUI
}
```

**Step 2: Verify `aegis proxy --help` works from the main binary.**

```bash
git commit -m "[orchestrator] wire aegis proxy subcommand to TUI binary"
```

---

### Task 26: Knowledge Graph Import

**Files:**
- Create: `crates/proxy-tui/src/graph_import.rs`
- Create: `crates/proxy-tui/src/graph_import_test.rs`

**Step 1: Write tests for:**
- Load graph DB → extract endpoints → generate scope rules
- Load graph DB → extract endpoints → pre-populate saved requests

**Step 2: Implement `--import-graph` flag**

Read `KnowledgeGraph::load_from_file()`, iterate `nodes_by_type(Endpoint)`, create `ScopeRule` for each path, insert `SavedRequest` for each endpoint.

**WIRING:** `aegis scan --target X --graph-db scan.db` → `aegis proxy --import-graph scan.db` → scope rules + saved requests populated from scan data.

```bash
git commit -m "[proxy-tui] add knowledge graph import for pre-populated scope and requests"
```

---

### Task 27: Full Integration Test Suite

**Files:**
- Create: `crates/proxy-tui/tests/integration.rs`

**Step 1: Write comprehensive integration tests:**

1. **Proxy → SQLite → TUI load:** Start proxy, send requests, verify SQLite, verify TUI data model loads them
2. **Repeater round-trip:** Load exchange → modify → send → diff → verify all fields
3. **Intruder pipeline end-to-end:** Configure pipeline → run → grep → results in SQLite → verify
4. **Scope filtering:** Add scope rules → proxy captures → verify in_scope field → verify TUI filters
5. **Session jar:** Send login request → receive Set-Cookie → subsequent requests include cookie
6. **Graph import:** Load scan DB → verify scope rules and saved requests created
7. **Persistence survival:** Write data → drop ProxyDb → reopen → data intact

**Step 2: Run full workspace test suite**

```bash
cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all --check
```

All gates must pass.

**Step 3: Commit**

```bash
git commit -m "[proxy-tui] add comprehensive integration test suite verifying full wiring"
```

---

### Task 28: Final Wiring Verification

**Checklist — every item must be verified with a passing test:**

- [ ] `ProxyDb` opens, creates schema, round-trips all exchange fields including binary bodies
- [ ] Proxy write-through: exchanges appear in both memory and SQLite
- [ ] Scope engine: in-scope exchanges marked correctly in SQLite
- [ ] Session jar: cookies extracted from responses, injected into subsequent requests
- [ ] Modification rules: match-and-replace applied to proxy traffic
- [ ] Payload pipeline: sources generate, processors transform, encodings apply, in order
- [ ] Intruder with pipeline: payloads from pipeline fed into attack modes correctly
- [ ] Grep-match: patterns found in response body/headers, results stored per intruder result
- [ ] Grep-extract: capture groups extracted, stored per intruder result
- [ ] Diff engine: line/word/hex diffs computed correctly between two responses
- [ ] Graph sync: proxy exchanges → knowledge graph operations (existing, unchanged)
- [ ] Graph import: scan DB endpoints → scope rules + saved requests
- [ ] TUI event loop: tab switching, keybinds, rendering all work
- [ ] TUI proxy log: loads from ProxyDb, filter works, send-to-repeater works
- [ ] TUI repeater: edit-send-diff cycle works end to end
- [ ] TUI intruder: config → run → live results → grep display → SQLite storage
- [ ] TUI comparer: select two items → diff displayed correctly
- [ ] TUI scope: add/remove rules → proxy behavior changes
- [ ] TUI payloads: create list → use in intruder → correct payloads generated
- [ ] `aegis proxy` subcommand launches TUI from main binary
- [ ] All existing 43 proxy tests still pass (zero regressions)
- [ ] `cargo clippy --workspace -- -D warnings` = zero warnings
- [ ] `cargo fmt --all --check` = clean

Run: `cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all --check`

```bash
git commit -m "[proxy] final wiring verification — all integration tests pass"
```

---

## Summary

| Phase | Tasks | New Files | LOC Estimate |
|-------|-------|-----------|-------------|
| Phase 1: Proxy Enhancements | 1-10 | 14 source + 7 test | ~2,500 |
| Phase 2: TUI Setup | 11-16 | 10 source + 5 test | ~1,200 |
| Phase 3: TUI Views | 17-24 | 16 source + 8 test | ~2,500 |
| Phase 4: Wiring | 25-28 | 4 source + 2 test | ~500 |
| **Total** | **28 tasks** | **44 source + 22 test** | **~6,700** |

Each task follows TDD: write failing test → implement → verify pass → wiring check → clippy → commit.
