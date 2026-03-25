use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Persisted scan state in SQLite.
#[derive(Debug)]
pub struct ScanPersistence {
    conn: Connection,
}

/// A checkpoint representing scan progress at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentCheckpoint {
    pub scan_id: String,
    pub target: String,
    pub phase: String,
    pub iteration: u32,
    pub total_findings: u64,
    pub total_operations: u64,
    pub timestamp_ms: u64,
    pub completed_endpoints: Vec<String>,
}

/// A persisted finding for diff comparisons.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedFinding {
    pub scan_id: String,
    pub finding_id: u64,
    pub vulnerability_class: String,
    pub endpoint: String,
    pub severity: f64,
    pub confidence: f64,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

/// Represents what changed between two scans.
#[derive(Debug, Clone)]
pub struct ScanDiff {
    pub new_findings: Vec<PersistedFinding>,
    pub resolved_findings: Vec<PersistedFinding>,
    pub unchanged_findings: Vec<PersistedFinding>,
    pub new_endpoints: Vec<String>,
    pub removed_endpoints: Vec<String>,
}

/// Error type for persistence operations.
#[derive(Debug)]
pub enum PersistenceError {
    Database(String),
    NotFound(String),
    Serialization(String),
}

impl std::fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(msg) => write!(f, "database error: {msg}"),
            Self::NotFound(msg) => write!(f, "not found: {msg}"),
            Self::Serialization(msg) => write!(f, "serialization error: {msg}"),
        }
    }
}

impl std::error::Error for PersistenceError {}

impl From<rusqlite::Error> for PersistenceError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(e.to_string())
    }
}

impl ScanPersistence {
    /// Open or create a scan persistence database at the given path.
    pub fn open(path: &Path) -> Result<Self, PersistenceError> {
        let conn = Connection::open(path)?;
        let persistence = Self { conn };
        persistence.init_schema()?;
        Ok(persistence)
    }

    /// Create an in-memory database (for testing).
    pub fn in_memory() -> Result<Self, PersistenceError> {
        let conn = Connection::open_in_memory()?;
        let persistence = Self { conn };
        persistence.init_schema()?;
        Ok(persistence)
    }

    fn init_schema(&self) -> Result<(), PersistenceError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS checkpoints (
                scan_id TEXT NOT NULL,
                target TEXT NOT NULL,
                phase TEXT NOT NULL,
                iteration INTEGER NOT NULL,
                total_findings INTEGER NOT NULL,
                total_operations INTEGER NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                completed_endpoints TEXT NOT NULL DEFAULT '[]',
                PRIMARY KEY (scan_id)
            );
            CREATE TABLE IF NOT EXISTS findings (
                scan_id TEXT NOT NULL,
                finding_id INTEGER NOT NULL,
                vulnerability_class TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                severity REAL NOT NULL,
                confidence REAL NOT NULL,
                first_seen_ms INTEGER NOT NULL,
                last_seen_ms INTEGER NOT NULL,
                PRIMARY KEY (scan_id, finding_id)
            );
            CREATE TABLE IF NOT EXISTS endpoints (
                scan_id TEXT NOT NULL,
                url TEXT NOT NULL,
                method TEXT NOT NULL DEFAULT 'GET',
                last_scanned_ms INTEGER NOT NULL,
                PRIMARY KEY (scan_id, url)
            );
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);",
        )?;
        Ok(())
    }

    /// Save a checkpoint for the given scan.
    pub fn save_checkpoint(
        &self,
        checkpoint: &PersistentCheckpoint,
    ) -> Result<(), PersistenceError> {
        let endpoints_json = serde_json::to_string(&checkpoint.completed_endpoints)
            .map_err(|e| PersistenceError::Serialization(e.to_string()))?;
        self.conn.execute(
            "INSERT OR REPLACE INTO checkpoints
             (scan_id, target, phase, iteration, total_findings, total_operations, timestamp_ms, completed_endpoints)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                checkpoint.scan_id,
                checkpoint.target,
                checkpoint.phase,
                checkpoint.iteration,
                checkpoint.total_findings as i64,
                checkpoint.total_operations as i64,
                checkpoint.timestamp_ms as i64,
                endpoints_json,
            ],
        )?;
        Ok(())
    }

    /// Load the latest checkpoint for a scan.
    pub fn load_checkpoint(
        &self,
        scan_id: &str,
    ) -> Result<Option<PersistentCheckpoint>, PersistenceError> {
        let mut stmt = self.conn.prepare(
            "SELECT scan_id, target, phase, iteration, total_findings, total_operations, timestamp_ms, completed_endpoints
             FROM checkpoints WHERE scan_id = ?1",
        )?;
        let result = stmt.query_row(params![scan_id], |row| {
            let endpoints_json: String = row.get(7)?;
            Ok(PersistentCheckpoint {
                scan_id: row.get(0)?,
                target: row.get(1)?,
                phase: row.get(2)?,
                iteration: row.get(3)?,
                total_findings: row.get::<_, i64>(4)? as u64,
                total_operations: row.get::<_, i64>(5)? as u64,
                timestamp_ms: row.get::<_, i64>(6)? as u64,
                completed_endpoints: serde_json::from_str(&endpoints_json).unwrap_or_default(),
            })
        });
        match result {
            Ok(cp) => Ok(Some(cp)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(PersistenceError::Database(e.to_string())),
        }
    }

    /// Delete a checkpoint (after successful completion).
    pub fn delete_checkpoint(&self, scan_id: &str) -> Result<(), PersistenceError> {
        self.conn.execute(
            "DELETE FROM checkpoints WHERE scan_id = ?1",
            params![scan_id],
        )?;
        Ok(())
    }

    /// Save a finding for the current scan.
    pub fn save_finding(&self, finding: &PersistedFinding) -> Result<(), PersistenceError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO findings
             (scan_id, finding_id, vulnerability_class, endpoint, severity, confidence, first_seen_ms, last_seen_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                finding.scan_id,
                finding.finding_id as i64,
                finding.vulnerability_class,
                finding.endpoint,
                finding.severity,
                finding.confidence,
                finding.first_seen_ms as i64,
                finding.last_seen_ms as i64,
            ],
        )?;
        Ok(())
    }

    /// Load all findings for a scan.
    pub fn load_findings(&self, scan_id: &str) -> Result<Vec<PersistedFinding>, PersistenceError> {
        let mut stmt = self.conn.prepare(
            "SELECT scan_id, finding_id, vulnerability_class, endpoint, severity, confidence, first_seen_ms, last_seen_ms
             FROM findings WHERE scan_id = ?1",
        )?;
        let findings = stmt
            .query_map(params![scan_id], |row| {
                Ok(PersistedFinding {
                    scan_id: row.get(0)?,
                    finding_id: row.get::<_, i64>(1)? as u64,
                    vulnerability_class: row.get(2)?,
                    endpoint: row.get(3)?,
                    severity: row.get(4)?,
                    confidence: row.get(5)?,
                    first_seen_ms: row.get::<_, i64>(6)? as u64,
                    last_seen_ms: row.get::<_, i64>(7)? as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(findings)
    }

    /// Save a scanned endpoint.
    pub fn save_endpoint(
        &self,
        scan_id: &str,
        url: &str,
        method: &str,
        timestamp_ms: u64,
    ) -> Result<(), PersistenceError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO endpoints (scan_id, url, method, last_scanned_ms) VALUES (?1, ?2, ?3, ?4)",
            params![scan_id, url, method, timestamp_ms as i64],
        )?;
        Ok(())
    }

    /// Load all endpoints for a scan.
    pub fn load_endpoints(
        &self,
        scan_id: &str,
    ) -> Result<Vec<(String, String, u64)>, PersistenceError> {
        let mut stmt = self
            .conn
            .prepare("SELECT url, method, last_scanned_ms FROM endpoints WHERE scan_id = ?1")?;
        let eps = stmt
            .query_map(params![scan_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)? as u64,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(eps)
    }

    /// Compute diff between two scans.
    pub fn diff_scans(
        &self,
        old_scan_id: &str,
        new_scan_id: &str,
    ) -> Result<ScanDiff, PersistenceError> {
        let old_findings = self.load_findings(old_scan_id)?;
        let new_findings = self.load_findings(new_scan_id)?;

        let old_keys: std::collections::HashSet<String> = old_findings
            .iter()
            .map(|f| format!("{}:{}", f.vulnerability_class, f.endpoint))
            .collect();
        let new_keys: std::collections::HashSet<String> = new_findings
            .iter()
            .map(|f| format!("{}:{}", f.vulnerability_class, f.endpoint))
            .collect();

        let new_finding_list: Vec<PersistedFinding> = new_findings
            .iter()
            .filter(|f| !old_keys.contains(&format!("{}:{}", f.vulnerability_class, f.endpoint)))
            .cloned()
            .collect();

        let resolved: Vec<PersistedFinding> = old_findings
            .iter()
            .filter(|f| !new_keys.contains(&format!("{}:{}", f.vulnerability_class, f.endpoint)))
            .cloned()
            .collect();

        let unchanged: Vec<PersistedFinding> = new_findings
            .iter()
            .filter(|f| old_keys.contains(&format!("{}:{}", f.vulnerability_class, f.endpoint)))
            .cloned()
            .collect();

        let old_eps = self.load_endpoints(old_scan_id)?;
        let new_eps = self.load_endpoints(new_scan_id)?;
        let old_ep_set: std::collections::HashSet<String> =
            old_eps.iter().map(|(u, _, _)| u.clone()).collect();
        let new_ep_set: std::collections::HashSet<String> =
            new_eps.iter().map(|(u, _, _)| u.clone()).collect();

        let new_endpoints: Vec<String> = new_ep_set.difference(&old_ep_set).cloned().collect();
        let removed_endpoints: Vec<String> = old_ep_set.difference(&new_ep_set).cloned().collect();

        Ok(ScanDiff {
            new_findings: new_finding_list,
            resolved_findings: resolved,
            unchanged_findings: unchanged,
            new_endpoints,
            removed_endpoints,
        })
    }

    /// Get endpoints that haven't been scanned since the given timestamp.
    pub fn stale_endpoints(
        &self,
        scan_id: &str,
        since_ms: u64,
    ) -> Result<Vec<String>, PersistenceError> {
        let mut stmt = self
            .conn
            .prepare("SELECT url FROM endpoints WHERE scan_id = ?1 AND last_scanned_ms < ?2")?;
        let eps = stmt
            .query_map(params![scan_id, since_ms as i64], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(eps)
    }
}
