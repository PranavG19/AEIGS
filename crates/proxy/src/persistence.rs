use std::path::Path;

use rusqlite::{Connection, params};

use crate::types::RecordedExchange;

/// A bookmarked request saved for manual testing or replay.
#[derive(Debug, Clone)]
pub struct SavedRequest {
    pub id: i64,
    pub name: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub notes: String,
    pub created_at: i64,
    pub exchange_id: Option<i64>,
}

/// Metadata for an intruder attack run.
#[derive(Debug, Clone)]
pub struct IntruderRunRecord {
    pub id: i64,
    pub name: String,
    pub mode: String,
    pub template_json: String,
    pub positions_json: String,
    pub concurrency: u32,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub total_requests: Option<u32>,
}

/// A single result row from an intruder request.
#[derive(Debug, Clone)]
pub struct IntruderResultRecord {
    pub id: i64,
    pub run_id: i64,
    pub payload_json: String,
    pub status_code: u16,
    pub body_length: u32,
    pub duration_ms: u64,
    pub response_body: Vec<u8>,
    pub grep_matches: String,
}

/// A named, reusable payload list.
#[derive(Debug, Clone)]
pub struct PayloadListRecord {
    pub id: i64,
    pub name: String,
    pub source: String,
    pub entries: String,
}

/// Structured filter for querying exchanges without raw SQL.
#[derive(Debug, Clone)]
pub enum ExchangeFilter {
    Method(String),
    StatusCode(u16),
    UrlContains(String),
    StatusRange { min: u16, max: u16 },
}

/// Error type for proxy database operations.
#[derive(Debug, thiserror::Error)]
pub enum ProxyDbError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// SQLite-backed persistence for proxy exchanges, saved requests,
/// intruder runs/results, and payload lists.
///
/// Headers are stored as JSON arrays of `[key, value]` pairs.
/// Bodies are stored as BLOBs for binary safety.
/// WAL journal mode is enabled for concurrent read performance.
pub struct ProxyDb {
    conn: Connection,
}

impl ProxyDb {
    /// Opens or creates a proxy database at the given path.
    ///
    /// Creates all tables and indexes if they do not exist.
    pub fn open(path: &Path) -> Result<Self, ProxyDbError> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.initialize()?;
        Ok(db)
    }

    /// Opens an in-memory database for testing.
    pub fn open_in_memory() -> Result<Self, ProxyDbError> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.initialize()?;
        Ok(db)
    }

    fn initialize(&self) -> Result<(), ProxyDbError> {
        self.conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        self.conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        self.create_schema()?;
        Ok(())
    }

    fn create_schema(&self) -> Result<(), ProxyDbError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS exchanges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                request_headers TEXT NOT NULL,
                request_body BLOB NOT NULL,
                response_status INTEGER NOT NULL,
                response_headers TEXT NOT NULL,
                response_body BLOB NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                in_scope INTEGER DEFAULT 1,
                tags TEXT DEFAULT '[]'
            );
            CREATE INDEX IF NOT EXISTS idx_exchanges_url ON exchanges(url);
            CREATE INDEX IF NOT EXISTS idx_exchanges_timestamp ON exchanges(timestamp_ms);

            CREATE TABLE IF NOT EXISTS scope_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT NOT NULL,
                is_include INTEGER NOT NULL,
                priority INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS saved_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                headers TEXT NOT NULL,
                body BLOB NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                exchange_id INTEGER,
                FOREIGN KEY (exchange_id) REFERENCES exchanges(id)
            );

            CREATE TABLE IF NOT EXISTS intruder_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                mode TEXT NOT NULL,
                template_json TEXT NOT NULL,
                positions_json TEXT NOT NULL,
                concurrency INTEGER NOT NULL,
                started_at INTEGER NOT NULL,
                completed_at INTEGER,
                total_requests INTEGER
            );

            CREATE TABLE IF NOT EXISTS intruder_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                body_length INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                response_body BLOB NOT NULL,
                grep_matches TEXT DEFAULT '[]',
                FOREIGN KEY (run_id) REFERENCES intruder_runs(id)
            );
            CREATE INDEX IF NOT EXISTS idx_intruder_results_run
                ON intruder_results(run_id);

            CREATE TABLE IF NOT EXISTS payload_lists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                source TEXT NOT NULL,
                entries TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cookies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                name TEXT NOT NULL,
                value TEXT NOT NULL,
                path TEXT NOT NULL DEFAULT '/',
                expires INTEGER,
                secure INTEGER NOT NULL DEFAULT 0,
                http_only INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS modification_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                enabled INTEGER NOT NULL DEFAULT 1,
                match_target TEXT NOT NULL,
                match_pattern TEXT NOT NULL,
                replace_with TEXT NOT NULL
            );",
        )?;
        Ok(())
    }

    /// Inserts a recorded exchange and returns the row ID.
    pub fn insert_exchange(&self, ex: &RecordedExchange) -> Result<i64, ProxyDbError> {
        let req_headers = serialize_headers(&ex.request_headers)?;
        let resp_headers = serialize_headers(&ex.response_headers)?;
        self.conn.execute(
            "INSERT INTO exchanges
                (method, url, request_headers, request_body,
                 response_status, response_headers, response_body,
                 timestamp_ms, duration_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                ex.request_method,
                ex.request_url,
                req_headers,
                ex.request_body,
                ex.response_status as i64,
                resp_headers,
                ex.response_body,
                ex.timestamp_ms as i64,
                ex.duration_ms as i64,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Retrieves a single exchange by its row ID.
    pub fn exchange_by_id(&self, id: i64) -> Result<Option<RecordedExchange>, ProxyDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, method, url, request_headers, request_body,
                    response_status, response_headers, response_body,
                    timestamp_ms, duration_ms
             FROM exchanges WHERE id = ?1",
        )?;
        let nested_rows: Vec<Result<RecordedExchange, ProxyDbError>> = stmt
            .query_map(params![id], row_to_exchange)?
            .collect::<Result<Vec<_>, _>>()?;
        match nested_rows.into_iter().next() {
            Some(inner) => Ok(Some(inner?)),
            None => Ok(None),
        }
    }

    /// Lists exchanges ordered by timestamp descending with pagination.
    pub fn list_exchanges(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<RecordedExchange>, ProxyDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, method, url, request_headers, request_body,
                    response_status, response_headers, response_body,
                    timestamp_ms, duration_ms
             FROM exchanges ORDER BY timestamp_ms DESC LIMIT ?1 OFFSET ?2",
        )?;
        collect_exchange_rows(&mut stmt, params![limit, offset])
    }

    /// Filters exchanges using structured filter predicates.
    ///
    /// Builds parameterized WHERE clauses internally to prevent SQL injection.
    /// Multiple filters are combined with AND.
    pub fn filter_exchanges(
        &self,
        filters: &[ExchangeFilter],
    ) -> Result<Vec<RecordedExchange>, ProxyDbError> {
        let mut conditions = Vec::new();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1usize;

        for filter in filters {
            match filter {
                ExchangeFilter::Method(m) => {
                    conditions.push(format!("method = ?{idx}"));
                    param_values.push(Box::new(m.clone()));
                    idx += 1;
                }
                ExchangeFilter::StatusCode(code) => {
                    conditions.push(format!("response_status = ?{idx}"));
                    param_values.push(Box::new(i64::from(*code)));
                    idx += 1;
                }
                ExchangeFilter::UrlContains(pattern) => {
                    conditions.push(format!("url LIKE ?{idx}"));
                    param_values.push(Box::new(format!("%{pattern}%")));
                    idx += 1;
                }
                ExchangeFilter::StatusRange { min, max } => {
                    conditions.push(format!(
                        "response_status >= ?{} AND response_status <= ?{}",
                        idx,
                        idx + 1
                    ));
                    param_values.push(Box::new(i64::from(*min)));
                    param_values.push(Box::new(i64::from(*max)));
                    idx += 2;
                }
            }
        }

        let where_clause = if conditions.is_empty() {
            "1=1".to_string()
        } else {
            conditions.join(" AND ")
        };

        let sql = format!(
            "SELECT id, method, url, request_headers, request_body,
                    response_status, response_headers, response_body,
                    timestamp_ms, duration_ms
             FROM exchanges WHERE {where_clause} ORDER BY timestamp_ms DESC"
        );

        let mut stmt = self.conn.prepare(&sql)?;
        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|b| b.as_ref()).collect();
        let nested_rows: Vec<Result<RecordedExchange, ProxyDbError>> = stmt
            .query_map(params_ref.as_slice(), row_to_exchange)?
            .collect::<Result<Vec<_>, _>>()?;
        nested_rows.into_iter().collect()
    }

    /// Searches exchanges by URL pattern using SQL LIKE.
    pub fn search_exchanges_by_url(
        &self,
        pattern: &str,
    ) -> Result<Vec<RecordedExchange>, ProxyDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, method, url, request_headers, request_body,
                    response_status, response_headers, response_body,
                    timestamp_ms, duration_ms
             FROM exchanges WHERE url LIKE ?1 ORDER BY timestamp_ms DESC",
        )?;
        collect_exchange_rows(&mut stmt, params![pattern])
    }

    /// Deletes an exchange by ID. Returns true if a row was deleted.
    pub fn delete_exchange(&self, id: i64) -> Result<bool, ProxyDbError> {
        let count = self
            .conn
            .execute("DELETE FROM exchanges WHERE id = ?1", params![id])?;
        Ok(count > 0)
    }

    /// Deletes all exchanges.
    pub fn clear_exchanges(&self) -> Result<(), ProxyDbError> {
        self.conn.execute("DELETE FROM exchanges", [])?;
        Ok(())
    }

    /// Returns the total number of stored exchanges.
    pub fn exchange_count(&self) -> Result<u64, ProxyDbError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM exchanges", [], |row| row.get(0))?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Inserts a saved request and returns the row ID.
    pub fn insert_saved_request(&self, req: &SavedRequest) -> Result<i64, ProxyDbError> {
        let headers = serialize_headers(&req.headers)?;
        self.conn.execute(
            "INSERT INTO saved_requests
                (name, method, url, headers, body, notes, created_at, exchange_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                req.name,
                req.method,
                req.url,
                headers,
                req.body,
                req.notes,
                req.created_at,
                req.exchange_id,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Retrieves a saved request by its row ID.
    pub fn saved_request_by_id(&self, id: i64) -> Result<Option<SavedRequest>, ProxyDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, method, url, headers, body, notes, created_at, exchange_id
             FROM saved_requests WHERE id = ?1",
        )?;
        let nested_rows: Vec<Result<SavedRequest, ProxyDbError>> = stmt
            .query_map(params![id], row_to_saved_request)?
            .collect::<Result<Vec<_>, _>>()?;
        match nested_rows.into_iter().next() {
            Some(inner) => Ok(Some(inner?)),
            None => Ok(None),
        }
    }

    /// Lists all saved requests ordered by creation time descending.
    pub fn list_saved_requests(&self) -> Result<Vec<SavedRequest>, ProxyDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, method, url, headers, body, notes, created_at, exchange_id
             FROM saved_requests ORDER BY created_at DESC",
        )?;
        let nested_rows: Vec<Result<SavedRequest, ProxyDbError>> = stmt
            .query_map([], row_to_saved_request)?
            .collect::<Result<Vec<_>, _>>()?;
        nested_rows.into_iter().collect()
    }

    /// Inserts an intruder run record and returns the row ID.
    pub fn insert_intruder_run(&self, run: &IntruderRunRecord) -> Result<i64, ProxyDbError> {
        self.conn.execute(
            "INSERT INTO intruder_runs
                (name, mode, template_json, positions_json, concurrency,
                 started_at, completed_at, total_requests)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                run.name,
                run.mode,
                run.template_json,
                run.positions_json,
                run.concurrency,
                run.started_at,
                run.completed_at,
                run.total_requests,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Retrieves an intruder run by its row ID.
    pub fn intruder_run_by_id(&self, id: i64) -> Result<Option<IntruderRunRecord>, ProxyDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, mode, template_json, positions_json, concurrency,
                    started_at, completed_at, total_requests
             FROM intruder_runs WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], row_to_intruder_run)?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Updates an intruder run with completion timestamp and total request count.
    ///
    /// Returns `true` if the run was found and updated, `false` if no row matched.
    pub fn update_intruder_run_completed(
        &self,
        id: i64,
        completed_at: i64,
        total_requests: u32,
    ) -> Result<bool, ProxyDbError> {
        let rows = self.conn.execute(
            "UPDATE intruder_runs SET completed_at = ?1, total_requests = ?2 WHERE id = ?3",
            params![completed_at, total_requests, id],
        )?;
        Ok(rows > 0)
    }

    /// Inserts a single intruder result row.
    pub fn insert_intruder_result(
        &self,
        result: &IntruderResultRecord,
    ) -> Result<i64, ProxyDbError> {
        self.conn.execute(
            "INSERT INTO intruder_results
                (run_id, payload_json, status_code, body_length,
                 duration_ms, response_body, grep_matches)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                result.run_id,
                result.payload_json,
                result.status_code as i64,
                result.body_length as i64,
                result.duration_ms as i64,
                result.response_body,
                result.grep_matches,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Retrieves all intruder results for a given run ID.
    pub fn intruder_results_for_run(
        &self,
        run_id: i64,
    ) -> Result<Vec<IntruderResultRecord>, ProxyDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, run_id, payload_json, status_code, body_length,
                    duration_ms, response_body, grep_matches
             FROM intruder_results WHERE run_id = ?1 ORDER BY id",
        )?;
        let rows = stmt
            .query_map(params![run_id], row_to_intruder_result)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Inserts a named payload list and returns the row ID.
    ///
    /// The name must be unique; duplicate names produce a database error.
    pub fn insert_payload_list(&self, pl: &PayloadListRecord) -> Result<i64, ProxyDbError> {
        self.conn.execute(
            "INSERT INTO payload_lists (name, source, entries) VALUES (?1, ?2, ?3)",
            params![pl.name, pl.source, pl.entries],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Retrieves a payload list by its unique name.
    pub fn payload_list_by_name(
        &self,
        name: &str,
    ) -> Result<Option<PayloadListRecord>, ProxyDbError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, source, entries FROM payload_lists WHERE name = ?1")?;
        let mut rows = stmt.query_map(params![name], row_to_payload_list)?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Lists all payload lists ordered by name.
    pub fn list_payload_lists(&self) -> Result<Vec<PayloadListRecord>, ProxyDbError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, source, entries FROM payload_lists ORDER BY name")?;
        let rows = stmt
            .query_map([], row_to_payload_list)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

fn collect_exchange_rows(
    stmt: &mut rusqlite::Statement,
    params: impl rusqlite::Params,
) -> Result<Vec<RecordedExchange>, ProxyDbError> {
    let nested: Vec<Result<RecordedExchange, ProxyDbError>> = stmt
        .query_map(params, row_to_exchange)?
        .collect::<Result<Vec<_>, _>>()?;
    nested.into_iter().collect()
}

fn row_to_exchange(
    row: &rusqlite::Row,
) -> rusqlite::Result<Result<RecordedExchange, ProxyDbError>> {
    let id: i64 = row.get(0)?;
    let method: String = row.get(1)?;
    let url: String = row.get(2)?;
    let req_headers_json: String = row.get(3)?;
    let req_body: Vec<u8> = row.get(4)?;
    let status: i64 = row.get(5)?;
    let resp_headers_json: String = row.get(6)?;
    let resp_body: Vec<u8> = row.get(7)?;
    let timestamp: i64 = row.get(8)?;
    let duration: i64 = row.get(9)?;

    let req_headers = match deserialize_headers(&req_headers_json) {
        Ok(h) => h,
        Err(e) => return Ok(Err(e)),
    };
    let resp_headers = match deserialize_headers(&resp_headers_json) {
        Ok(h) => h,
        Err(e) => return Ok(Err(e)),
    };

    Ok(Ok(RecordedExchange {
        id: u64::try_from(id).unwrap_or(0),
        request_method: method,
        request_url: url,
        request_headers: req_headers,
        request_body: req_body,
        response_status: u16::try_from(status).unwrap_or(0),
        response_headers: resp_headers,
        response_body: resp_body,
        timestamp_ms: u64::try_from(timestamp).unwrap_or(0),
        duration_ms: u64::try_from(duration).unwrap_or(0),
    }))
}

fn row_to_saved_request(
    row: &rusqlite::Row,
) -> rusqlite::Result<Result<SavedRequest, ProxyDbError>> {
    let id: i64 = row.get(0)?;
    let name: String = row.get(1)?;
    let method: String = row.get(2)?;
    let url: String = row.get(3)?;
    let headers_json: String = row.get(4)?;
    let body: Vec<u8> = row.get(5)?;
    let notes: String = row.get(6)?;
    let created_at: i64 = row.get(7)?;
    let exchange_id: Option<i64> = row.get(8)?;

    let headers = match deserialize_headers(&headers_json) {
        Ok(h) => h,
        Err(e) => return Ok(Err(e)),
    };

    Ok(Ok(SavedRequest {
        id,
        name,
        method,
        url,
        headers,
        body,
        notes,
        created_at,
        exchange_id,
    }))
}

fn row_to_intruder_run(row: &rusqlite::Row) -> rusqlite::Result<IntruderRunRecord> {
    let id: i64 = row.get(0)?;
    let name: String = row.get(1)?;
    let mode: String = row.get(2)?;
    let template_json: String = row.get(3)?;
    let positions_json: String = row.get(4)?;
    let concurrency: i64 = row.get(5)?;
    let started_at: i64 = row.get(6)?;
    let completed_at: Option<i64> = row.get(7)?;
    let total_requests: Option<i64> = row.get(8)?;

    Ok(IntruderRunRecord {
        id,
        name,
        mode,
        template_json,
        positions_json,
        concurrency: u32::try_from(concurrency).unwrap_or(0),
        started_at,
        completed_at,
        total_requests: total_requests.map(|v| u32::try_from(v).unwrap_or(0)),
    })
}

fn row_to_intruder_result(row: &rusqlite::Row) -> rusqlite::Result<IntruderResultRecord> {
    let id: i64 = row.get(0)?;
    let run_id: i64 = row.get(1)?;
    let payload_json: String = row.get(2)?;
    let status_code: i64 = row.get(3)?;
    let body_length: i64 = row.get(4)?;
    let duration_ms: i64 = row.get(5)?;
    let response_body: Vec<u8> = row.get(6)?;
    let grep_matches: String = row.get(7)?;

    Ok(IntruderResultRecord {
        id,
        run_id,
        payload_json,
        status_code: u16::try_from(status_code).unwrap_or(0),
        body_length: u32::try_from(body_length).unwrap_or(0),
        duration_ms: u64::try_from(duration_ms).unwrap_or(0),
        response_body,
        grep_matches,
    })
}

fn row_to_payload_list(row: &rusqlite::Row) -> rusqlite::Result<PayloadListRecord> {
    let id: i64 = row.get(0)?;
    let name: String = row.get(1)?;
    let source: String = row.get(2)?;
    let entries: String = row.get(3)?;

    Ok(PayloadListRecord {
        id,
        name,
        source,
        entries,
    })
}

fn serialize_headers(headers: &[(String, String)]) -> Result<String, ProxyDbError> {
    let pairs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    Ok(serde_json::to_string(&pairs)?)
}

fn deserialize_headers(json: &str) -> Result<Vec<(String, String)>, ProxyDbError> {
    Ok(serde_json::from_str(json)?)
}

#[cfg(test)]
#[path = "persistence_test.rs"]
mod persistence_test;
