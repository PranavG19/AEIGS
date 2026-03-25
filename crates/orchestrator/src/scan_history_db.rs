use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Error type for scan history database operations.
#[derive(Debug)]
pub enum ScanHistoryDbError {
    Database(String),
    Query(String),
}

impl std::fmt::Display for ScanHistoryDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(msg) => write!(f, "database error: {msg}"),
            Self::Query(msg) => write!(f, "query error: {msg}"),
        }
    }
}

impl std::error::Error for ScanHistoryDbError {}

impl From<rusqlite::Error> for ScanHistoryDbError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(e.to_string())
    }
}

/// A complete scan result stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredScanResult {
    pub scan_id: String,
    pub target_url: String,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub total_findings: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub info_count: u32,
    pub scan_mode: String,
    pub duration_ms: u64,
}

/// A single finding record linked to a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFinding {
    pub finding_id: String,
    pub scan_id: String,
    pub endpoint: String,
    pub vulnerability_class: String,
    pub severity: String,
    pub score: f64,
    pub title: String,
    pub fingerprint: String,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub resolved_at_ms: Option<u64>,
}

/// A trend data point for findings over time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTrendPoint {
    pub scan_id: String,
    pub timestamp_ms: u64,
    pub total_findings: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
}

/// Per-endpoint history summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointHistory {
    pub endpoint: String,
    pub total_findings_ever: u32,
    pub active_findings: u32,
    pub resolved_findings: u32,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

/// Per-vulnerability-class history summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnClassHistory {
    pub vulnerability_class: String,
    pub total_occurrences: u32,
    pub active_count: u32,
    pub resolved_count: u32,
    pub average_score: f64,
}

/// Retention policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub max_scans: Option<u32>,
    pub max_age_days: Option<u32>,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_scans: Some(1000),
            max_age_days: Some(365),
        }
    }
}

/// Persistent SQLite-backed scan history database.
///
/// Stores complete scan results, individual findings, and provides
/// query methods for trend analysis, per-endpoint, and per-class history.
pub struct PersistentScanHistoryDb {
    conn: Connection,
}

impl PersistentScanHistoryDb {
    /// Opens or creates the database at the given path.
    pub fn open(path: &Path) -> Result<Self, ScanHistoryDbError> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.initialize_schema()?;
        Ok(db)
    }

    /// Opens an in-memory database for testing.
    pub fn open_in_memory() -> Result<Self, ScanHistoryDbError> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.initialize_schema()?;
        Ok(db)
    }

    fn initialize_schema(&self) -> Result<(), ScanHistoryDbError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                started_at_ms INTEGER NOT NULL,
                completed_at_ms INTEGER NOT NULL,
                total_findings INTEGER NOT NULL,
                critical_count INTEGER NOT NULL DEFAULT 0,
                high_count INTEGER NOT NULL DEFAULT 0,
                medium_count INTEGER NOT NULL DEFAULT 0,
                low_count INTEGER NOT NULL DEFAULT 0,
                info_count INTEGER NOT NULL DEFAULT 0,
                scan_mode TEXT NOT NULL DEFAULT 'full',
                duration_ms INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url);
            CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(started_at_ms);

            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                vulnerability_class TEXT NOT NULL,
                severity TEXT NOT NULL,
                score REAL NOT NULL,
                title TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                first_seen_ms INTEGER NOT NULL,
                last_seen_ms INTEGER NOT NULL,
                resolved_at_ms INTEGER,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_endpoint ON findings(endpoint);
            CREATE INDEX IF NOT EXISTS idx_findings_class ON findings(vulnerability_class);
            CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);",
        )?;
        Ok(())
    }

    /// Stores a complete scan result.
    pub fn store_scan(&self, scan: &StoredScanResult) -> Result<(), ScanHistoryDbError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO scans
                (scan_id, target_url, started_at_ms, completed_at_ms, total_findings,
                 critical_count, high_count, medium_count, low_count, info_count,
                 scan_mode, duration_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                scan.scan_id,
                scan.target_url,
                scan.started_at_ms as i64,
                scan.completed_at_ms as i64,
                scan.total_findings as i64,
                scan.critical_count as i64,
                scan.high_count as i64,
                scan.medium_count as i64,
                scan.low_count as i64,
                scan.info_count as i64,
                scan.scan_mode,
                scan.duration_ms as i64,
            ],
        )?;
        Ok(())
    }

    /// Stores a finding record.
    pub fn store_finding(&self, finding: &StoredFinding) -> Result<(), ScanHistoryDbError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO findings
                (finding_id, scan_id, endpoint, vulnerability_class, severity,
                 score, title, fingerprint, first_seen_ms, last_seen_ms, resolved_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                finding.finding_id,
                finding.scan_id,
                finding.endpoint,
                finding.vulnerability_class,
                finding.severity,
                finding.score,
                finding.title,
                finding.fingerprint,
                finding.first_seen_ms as i64,
                finding.last_seen_ms as i64,
                finding.resolved_at_ms.map(|t| t as i64),
            ],
        )?;
        Ok(())
    }

    /// Stores multiple findings in a transaction.
    pub fn store_findings_batch(
        &self,
        findings: &[StoredFinding],
    ) -> Result<usize, ScanHistoryDbError> {
        let tx = self.conn.unchecked_transaction()?;
        let mut count = 0usize;
        for finding in findings {
            tx.execute(
                "INSERT OR REPLACE INTO findings
                    (finding_id, scan_id, endpoint, vulnerability_class, severity,
                     score, title, fingerprint, first_seen_ms, last_seen_ms, resolved_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    finding.finding_id,
                    finding.scan_id,
                    finding.endpoint,
                    finding.vulnerability_class,
                    finding.severity,
                    finding.score,
                    finding.title,
                    finding.fingerprint,
                    finding.first_seen_ms as i64,
                    finding.last_seen_ms as i64,
                    finding.resolved_at_ms.map(|t| t as i64),
                ],
            )?;
            count += 1;
        }
        tx.commit()?;
        Ok(count)
    }

    /// Returns all stored scans ordered by start time (newest first).
    pub fn list_scans(&self, limit: u32) -> Result<Vec<StoredScanResult>, ScanHistoryDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT scan_id, target_url, started_at_ms, completed_at_ms, total_findings,
                    critical_count, high_count, medium_count, low_count, info_count,
                    scan_mode, duration_ms
             FROM scans ORDER BY started_at_ms DESC LIMIT ?1",
        )?;
        let results = stmt
            .query_map(params![limit as i64], |row| {
                Ok(StoredScanResult {
                    scan_id: row.get(0)?,
                    target_url: row.get(1)?,
                    started_at_ms: row.get::<_, i64>(2)? as u64,
                    completed_at_ms: row.get::<_, i64>(3)? as u64,
                    total_findings: row.get::<_, i64>(4)? as u32,
                    critical_count: row.get::<_, i64>(5)? as u32,
                    high_count: row.get::<_, i64>(6)? as u32,
                    medium_count: row.get::<_, i64>(7)? as u32,
                    low_count: row.get::<_, i64>(8)? as u32,
                    info_count: row.get::<_, i64>(9)? as u32,
                    scan_mode: row.get(10)?,
                    duration_ms: row.get::<_, i64>(11)? as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(results)
    }

    /// Queries findings for a specific scan.
    pub fn findings_for_scan(
        &self,
        scan_id: &str,
    ) -> Result<Vec<StoredFinding>, ScanHistoryDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT finding_id, scan_id, endpoint, vulnerability_class, severity,
                    score, title, fingerprint, first_seen_ms, last_seen_ms, resolved_at_ms
             FROM findings WHERE scan_id = ?1",
        )?;
        let results = stmt
            .query_map(params![scan_id], row_to_finding)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(results)
    }

    /// Returns trend data points for all scans of a target, ordered by time.
    pub fn trend_for_target(
        &self,
        target_url: &str,
    ) -> Result<Vec<ScanTrendPoint>, ScanHistoryDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT scan_id, started_at_ms, total_findings, critical_count,
                    high_count, medium_count, low_count
             FROM scans WHERE target_url = ?1 ORDER BY started_at_ms ASC",
        )?;
        let results = stmt
            .query_map(params![target_url], |row| {
                Ok(ScanTrendPoint {
                    scan_id: row.get(0)?,
                    timestamp_ms: row.get::<_, i64>(1)? as u64,
                    total_findings: row.get::<_, i64>(2)? as u32,
                    critical_count: row.get::<_, i64>(3)? as u32,
                    high_count: row.get::<_, i64>(4)? as u32,
                    medium_count: row.get::<_, i64>(5)? as u32,
                    low_count: row.get::<_, i64>(6)? as u32,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(results)
    }

    /// Returns per-endpoint history summaries.
    pub fn endpoint_history(&self) -> Result<Vec<EndpointHistory>, ScanHistoryDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT endpoint,
                    COUNT(*) as total,
                    SUM(CASE WHEN resolved_at_ms IS NULL THEN 1 ELSE 0 END) as active,
                    SUM(CASE WHEN resolved_at_ms IS NOT NULL THEN 1 ELSE 0 END) as resolved,
                    MIN(first_seen_ms) as first_seen,
                    MAX(last_seen_ms) as last_seen
             FROM findings GROUP BY endpoint ORDER BY total DESC",
        )?;
        let results = stmt
            .query_map([], |row| {
                Ok(EndpointHistory {
                    endpoint: row.get(0)?,
                    total_findings_ever: row.get::<_, i64>(1)? as u32,
                    active_findings: row.get::<_, i64>(2)? as u32,
                    resolved_findings: row.get::<_, i64>(3)? as u32,
                    first_seen_ms: row.get::<_, i64>(4)? as u64,
                    last_seen_ms: row.get::<_, i64>(5)? as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(results)
    }

    /// Returns per-vulnerability-class history summaries.
    pub fn vuln_class_history(&self) -> Result<Vec<VulnClassHistory>, ScanHistoryDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT vulnerability_class,
                    COUNT(*) as total,
                    SUM(CASE WHEN resolved_at_ms IS NULL THEN 1 ELSE 0 END) as active,
                    SUM(CASE WHEN resolved_at_ms IS NOT NULL THEN 1 ELSE 0 END) as resolved,
                    AVG(score) as avg_score
             FROM findings GROUP BY vulnerability_class ORDER BY total DESC",
        )?;
        let results = stmt
            .query_map([], |row| {
                Ok(VulnClassHistory {
                    vulnerability_class: row.get(0)?,
                    total_occurrences: row.get::<_, i64>(1)? as u32,
                    active_count: row.get::<_, i64>(2)? as u32,
                    resolved_count: row.get::<_, i64>(3)? as u32,
                    average_score: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(results)
    }

    /// Queries historical findings for a specific endpoint.
    pub fn findings_for_endpoint(
        &self,
        endpoint: &str,
    ) -> Result<Vec<StoredFinding>, ScanHistoryDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT finding_id, scan_id, endpoint, vulnerability_class, severity,
                    score, title, fingerprint, first_seen_ms, last_seen_ms, resolved_at_ms
             FROM findings WHERE endpoint = ?1 ORDER BY last_seen_ms DESC",
        )?;
        let results = stmt
            .query_map(params![endpoint], row_to_finding)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(results)
    }

    /// Queries historical findings for a specific vulnerability class.
    pub fn findings_for_class(
        &self,
        vuln_class: &str,
    ) -> Result<Vec<StoredFinding>, ScanHistoryDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT finding_id, scan_id, endpoint, vulnerability_class, severity,
                    score, title, fingerprint, first_seen_ms, last_seen_ms, resolved_at_ms
             FROM findings WHERE vulnerability_class = ?1 ORDER BY last_seen_ms DESC",
        )?;
        let results = stmt
            .query_map(params![vuln_class], row_to_finding)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(results)
    }

    /// Applies a retention policy, deleting old scans and their findings.
    /// Returns the number of scans deleted.
    pub fn apply_retention(
        &self,
        policy: &RetentionPolicy,
        current_timestamp_ms: u64,
    ) -> Result<usize, ScanHistoryDbError> {
        let mut deleted = 0usize;

        if let Some(max_age_days) = policy.max_age_days {
            let cutoff_ms = current_timestamp_ms.saturating_sub(max_age_days as u64 * 86_400_000);
            let old_scans: Vec<String> = {
                let mut stmt = self
                    .conn
                    .prepare("SELECT scan_id FROM scans WHERE started_at_ms < ?1")?;
                stmt.query_map(params![cutoff_ms as i64], |row| row.get(0))?
                    .collect::<Result<Vec<_>, _>>()?
            };
            for scan_id in &old_scans {
                self.conn
                    .execute("DELETE FROM findings WHERE scan_id = ?1", params![scan_id])?;
                self.conn
                    .execute("DELETE FROM scans WHERE scan_id = ?1", params![scan_id])?;
                deleted += 1;
            }
        }

        if let Some(max_scans) = policy.max_scans {
            let excess_scans: Vec<String> = {
                let mut stmt = self.conn.prepare(
                    "SELECT scan_id FROM scans ORDER BY started_at_ms DESC LIMIT -1 OFFSET ?1",
                )?;
                stmt.query_map(params![max_scans as i64], |row| row.get(0))?
                    .collect::<Result<Vec<_>, _>>()?
            };
            for scan_id in &excess_scans {
                self.conn
                    .execute("DELETE FROM findings WHERE scan_id = ?1", params![scan_id])?;
                self.conn
                    .execute("DELETE FROM scans WHERE scan_id = ?1", params![scan_id])?;
                deleted += 1;
            }
        }

        Ok(deleted)
    }

    /// Returns the total count of stored scans.
    pub fn total_scans(&self) -> Result<u64, ScanHistoryDbError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// Returns the total count of stored findings.
    pub fn total_findings(&self) -> Result<u64, ScanHistoryDbError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0))?;
        Ok(count as u64)
    }
}

fn row_to_finding(row: &rusqlite::Row) -> rusqlite::Result<StoredFinding> {
    let resolved: Option<i64> = row.get(10)?;
    Ok(StoredFinding {
        finding_id: row.get(0)?,
        scan_id: row.get(1)?,
        endpoint: row.get(2)?,
        vulnerability_class: row.get(3)?,
        severity: row.get(4)?,
        score: row.get(5)?,
        title: row.get(6)?,
        fingerprint: row.get(7)?,
        first_seen_ms: row.get::<_, i64>(8)? as u64,
        last_seen_ms: row.get::<_, i64>(9)? as u64,
        resolved_at_ms: resolved.map(|v| v as u64),
    })
}
