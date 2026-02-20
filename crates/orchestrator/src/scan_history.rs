use aegis_protocol::finding::VulnerabilityClass;
use rusqlite::{Connection, params};
use std::path::Path;

/// A scan history entry for insertion into the database.
///
/// Records the outcome of a single payload against an endpoint, enabling
/// adaptive payload selection and endpoint similarity analysis across scans.
pub struct ScanHistoryEntry {
    pub endpoint_pattern: String,
    pub vulnerability_class: VulnerabilityClass,
    pub payload: String,
    pub anomaly_score: f64,
    pub is_true_positive: bool,
    pub timestamp_unix_ms: u64,
    pub target_app_hash: String,
}

/// A scan history record retrieved from the database, including its row ID.
#[derive(Debug, Clone)]
pub struct ScanHistoryRecord {
    pub id: i64,
    pub endpoint_pattern: String,
    pub vulnerability_class: VulnerabilityClass,
    pub payload: String,
    pub anomaly_score: f64,
    pub is_true_positive: bool,
    pub timestamp_unix_ms: u64,
    pub target_app_hash: String,
}

#[derive(Debug)]
pub enum ScanHistoryError {
    DatabaseError(String),
    QueryError(String),
}

impl std::fmt::Display for ScanHistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DatabaseError(msg) => write!(f, "database error: {msg}"),
            Self::QueryError(msg) => write!(f, "query error: {msg}"),
        }
    }
}

impl std::error::Error for ScanHistoryError {}

impl From<rusqlite::Error> for ScanHistoryError {
    fn from(e: rusqlite::Error) -> Self {
        Self::DatabaseError(e.to_string())
    }
}

/// SQLite-backed persistent storage for scan findings.
///
/// Stores per-payload outcomes to enable adaptive payload selection and
/// endpoint similarity analysis across scans. Thread-safety is left to
/// the caller; the database connection is not internally synchronized.
pub struct ScanHistoryDb {
    connection: Connection,
}

impl ScanHistoryDb {
    /// Opens or creates a scan history database at the given path.
    ///
    /// Creates the `scan_history` table and indexes if they do not exist.
    pub fn open(path: &Path) -> Result<Self, ScanHistoryError> {
        let connection = Connection::open(path)?;
        let db = Self { connection };
        db.initialize_schema()?;
        Ok(db)
    }

    /// Opens an in-memory scan history database for testing.
    pub fn open_in_memory() -> Result<Self, ScanHistoryError> {
        let connection = Connection::open_in_memory()?;
        let db = Self { connection };
        db.initialize_schema()?;
        Ok(db)
    }

    fn initialize_schema(&self) -> Result<(), ScanHistoryError> {
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_pattern TEXT NOT NULL,
                vulnerability_class TEXT NOT NULL,
                payload TEXT NOT NULL,
                anomaly_score REAL NOT NULL,
                is_true_positive INTEGER NOT NULL,
                timestamp_unix_ms INTEGER NOT NULL,
                target_app_hash TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scan_history_endpoint
                ON scan_history(endpoint_pattern);
            CREATE INDEX IF NOT EXISTS idx_scan_history_vuln_class
                ON scan_history(vulnerability_class);
            CREATE INDEX IF NOT EXISTS idx_scan_history_app_hash
                ON scan_history(target_app_hash);",
        )?;
        Ok(())
    }

    /// Inserts a single scan history entry and returns its row ID.
    pub fn insert(&self, entry: &ScanHistoryEntry) -> Result<i64, ScanHistoryError> {
        self.connection.execute(
            "INSERT INTO scan_history
                (endpoint_pattern, vulnerability_class, payload, anomaly_score,
                 is_true_positive, timestamp_unix_ms, target_app_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry.endpoint_pattern,
                entry.vulnerability_class.to_string(),
                entry.payload,
                entry.anomaly_score,
                entry.is_true_positive as i32,
                entry.timestamp_unix_ms as i64,
                entry.target_app_hash,
            ],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    /// Inserts multiple entries in a single transaction. Returns the count inserted.
    pub fn insert_batch(&self, entries: &[ScanHistoryEntry]) -> Result<usize, ScanHistoryError> {
        let tx = self.connection.unchecked_transaction()?;
        let mut count = 0usize;
        for entry in entries {
            tx.execute(
                "INSERT INTO scan_history
                    (endpoint_pattern, vulnerability_class, payload, anomaly_score,
                     is_true_positive, timestamp_unix_ms, target_app_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    entry.endpoint_pattern,
                    entry.vulnerability_class.to_string(),
                    entry.payload,
                    entry.anomaly_score,
                    entry.is_true_positive as i32,
                    entry.timestamp_unix_ms as i64,
                    entry.target_app_hash,
                ],
            )?;
            count += 1;
        }
        tx.commit()?;
        Ok(count)
    }

    /// Queries all records matching an endpoint pattern (exact match).
    pub fn query_by_endpoint(
        &self,
        pattern: &str,
    ) -> Result<Vec<ScanHistoryRecord>, ScanHistoryError> {
        let mut stmt = self.connection.prepare(
            "SELECT id, endpoint_pattern, vulnerability_class, payload, anomaly_score,
                    is_true_positive, timestamp_unix_ms, target_app_hash
             FROM scan_history
             WHERE endpoint_pattern = ?1",
        )?;
        let records = stmt
            .query_map(params![pattern], row_to_record)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Queries all records matching a vulnerability class.
    pub fn query_by_class(
        &self,
        class: VulnerabilityClass,
    ) -> Result<Vec<ScanHistoryRecord>, ScanHistoryError> {
        let mut stmt = self.connection.prepare(
            "SELECT id, endpoint_pattern, vulnerability_class, payload, anomaly_score,
                    is_true_positive, timestamp_unix_ms, target_app_hash
             FROM scan_history
             WHERE vulnerability_class = ?1",
        )?;
        let records = stmt
            .query_map(params![class.to_string()], row_to_record)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Returns the fraction of records for a class that are true positives.
    ///
    /// Returns 0.0 if no records exist for the class.
    pub fn success_rate_by_class(
        &self,
        class: VulnerabilityClass,
    ) -> Result<f64, ScanHistoryError> {
        let (total, positives): (i64, i64) = self.connection.query_row(
            "SELECT COUNT(*), COALESCE(SUM(is_true_positive), 0)
             FROM scan_history
             WHERE vulnerability_class = ?1",
            params![class.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if total == 0 {
            return Ok(0.0);
        }
        Ok(positives as f64 / total as f64)
    }

    /// Returns the total number of records in the database.
    pub fn total_records(&self) -> Result<u64, ScanHistoryError> {
        let count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM scan_history", [], |row| row.get(0))?;
        Ok(count as u64)
    }
}

fn row_to_record(row: &rusqlite::Row) -> rusqlite::Result<ScanHistoryRecord> {
    let class_str: String = row.get(2)?;
    let vulnerability_class = parse_vulnerability_class(&class_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let is_true_positive_int: i32 = row.get(5)?;
    let timestamp: i64 = row.get(6)?;
    Ok(ScanHistoryRecord {
        id: row.get(0)?,
        endpoint_pattern: row.get(1)?,
        vulnerability_class,
        payload: row.get(3)?,
        anomaly_score: row.get(4)?,
        is_true_positive: is_true_positive_int != 0,
        timestamp_unix_ms: timestamp as u64,
        target_app_hash: row.get(7)?,
    })
}

/// Parses a Display-formatted vulnerability class string back into the enum.
fn parse_vulnerability_class(s: &str) -> Result<VulnerabilityClass, ParseVulnClassError> {
    match s {
        "SQL Injection" => Ok(VulnerabilityClass::SqlInjection),
        "Cross-Site Scripting" => Ok(VulnerabilityClass::CrossSiteScripting),
        "Command Injection" => Ok(VulnerabilityClass::CommandInjection),
        "Path Traversal" => Ok(VulnerabilityClass::PathTraversal),
        "Server-Side Request Forgery" => Ok(VulnerabilityClass::ServerSideRequestForgery),
        "Insecure Deserialization" => Ok(VulnerabilityClass::InsecureDeserialization),
        "Broken Authentication" => Ok(VulnerabilityClass::BrokenAuthentication),
        "Broken Authorization" => Ok(VulnerabilityClass::BrokenAuthorization),
        "Security Misconfiguration" => Ok(VulnerabilityClass::SecurityMisconfiguration),
        "Sensitive Data Exposure" => Ok(VulnerabilityClass::SensitiveDataExposure),
        "Server-Side Template Injection" => Ok(VulnerabilityClass::ServerSideTemplateInjection),
        "Header Injection" => Ok(VulnerabilityClass::HeaderInjection),
        "Open Redirect" => Ok(VulnerabilityClass::OpenRedirect),
        "CRLF Injection" => Ok(VulnerabilityClass::CrlfInjection),
        "Known Vulnerable Dependency" => Ok(VulnerabilityClass::KnownVulnerableDependency),
        "Insufficient Input Validation" => Ok(VulnerabilityClass::InsufficientInputValidation),
        _ => Err(ParseVulnClassError(s.to_string())),
    }
}

#[derive(Debug)]
struct ParseVulnClassError(String);

impl std::fmt::Display for ParseVulnClassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown vulnerability class: {}", self.0)
    }
}

impl std::error::Error for ParseVulnClassError {}
