use crate::dependency_parser::ParsedDependency;
use rusqlite::{Connection, params};
use std::path::Path;

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

#[derive(Debug)]
pub enum VulnDatabaseError {
    SqliteError(rusqlite::Error),
    SemverError(String),
}

impl std::fmt::Display for VulnDatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SqliteError(e) => write!(f, "sqlite error: {e}"),
            Self::SemverError(msg) => write!(f, "semver error: {msg}"),
        }
    }
}

impl std::error::Error for VulnDatabaseError {}

impl From<rusqlite::Error> for VulnDatabaseError {
    fn from(e: rusqlite::Error) -> Self {
        Self::SqliteError(e)
    }
}

pub struct VulnDatabase {
    connection: Connection,
}

impl VulnDatabase {
    pub fn open(path: &Path) -> Result<Self, VulnDatabaseError> {
        let connection = Connection::open(path)?;
        let db = Self { connection };
        db.initialize_schema()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self, VulnDatabaseError> {
        let connection = Connection::open_in_memory()?;
        let db = Self { connection };
        db.initialize_schema()?;
        Ok(db)
    }

    fn initialize_schema(&self) -> Result<(), VulnDatabaseError> {
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                package_name TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                vulnerable_version_start TEXT NOT NULL,
                vulnerable_version_end TEXT NOT NULL,
                severity REAL NOT NULL DEFAULT 0.0,
                description TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_vuln_package
                ON vulnerabilities(package_name, ecosystem);
            CREATE INDEX IF NOT EXISTS idx_vuln_cve
                ON vulnerabilities(cve_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_unique
                ON vulnerabilities(cve_id, package_name, ecosystem,
                    vulnerable_version_start, vulnerable_version_end);
            CREATE TABLE IF NOT EXISTS update_metadata (
                ecosystem TEXT PRIMARY KEY,
                last_updated_unix_ms INTEGER NOT NULL
            );",
        )?;
        Ok(())
    }

    pub fn insert_vulnerability(
        &self,
        record: &VulnerabilityRecord,
    ) -> Result<i64, VulnDatabaseError> {
        self.connection.execute(
            "INSERT INTO vulnerabilities
                (cve_id, package_name, ecosystem, vulnerable_version_start,
                 vulnerable_version_end, severity, description)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.cve_id,
                record.package_name,
                record.ecosystem,
                record.vulnerable_version_start,
                record.vulnerable_version_end,
                record.severity,
                record.description,
            ],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    pub fn find_vulnerabilities_for_package(
        &self,
        package_name: &str,
        ecosystem: &str,
    ) -> Result<Vec<VulnerabilityRecord>, VulnDatabaseError> {
        let mut stmt = self.connection.prepare(
            "SELECT cve_id, package_name, ecosystem, vulnerable_version_start,
                    vulnerable_version_end, severity, description
             FROM vulnerabilities
             WHERE package_name = ?1 AND ecosystem = ?2",
        )?;

        let records = stmt
            .query_map(params![package_name, ecosystem], |row| {
                Ok(VulnerabilityRecord {
                    cve_id: row.get(0)?,
                    package_name: row.get(1)?,
                    ecosystem: row.get(2)?,
                    vulnerable_version_start: row.get(3)?,
                    vulnerable_version_end: row.get(4)?,
                    severity: row.get(5)?,
                    description: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(records)
    }

    pub fn check_dependency(
        &self,
        dep: &ParsedDependency,
    ) -> Result<Vec<VulnerabilityMatch>, VulnDatabaseError> {
        let ecosystem_str = dep.ecosystem.to_string();
        let records = self.find_vulnerabilities_for_package(&dep.name, &ecosystem_str)?;

        let mut matches = Vec::new();
        for record in records {
            if version_in_range(
                &dep.version,
                &record.vulnerable_version_start,
                &record.vulnerable_version_end,
            ) {
                matches.push(VulnerabilityMatch {
                    dependency: dep.clone(),
                    cve_id: record.cve_id,
                    severity: record.severity,
                    description: record.description,
                });
            }
        }

        Ok(matches)
    }

    pub fn check_all_dependencies(
        &self,
        deps: &[ParsedDependency],
    ) -> Result<Vec<VulnerabilityMatch>, VulnDatabaseError> {
        let mut all_matches = Vec::new();
        for dep in deps {
            let dep_matches = self.check_dependency(dep)?;
            all_matches.extend(dep_matches);
        }
        Ok(all_matches)
    }

    pub fn upsert_vulnerability(
        &self,
        record: &VulnerabilityRecord,
    ) -> Result<bool, VulnDatabaseError> {
        let changed = self.connection.execute(
            "INSERT OR IGNORE INTO vulnerabilities
                (cve_id, package_name, ecosystem, vulnerable_version_start,
                 vulnerable_version_end, severity, description)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.cve_id,
                record.package_name,
                record.ecosystem,
                record.vulnerable_version_start,
                record.vulnerable_version_end,
                record.severity,
                record.description,
            ],
        )?;
        Ok(changed > 0)
    }

    pub fn insert_batch(
        &self,
        records: &[VulnerabilityRecord],
    ) -> Result<usize, VulnDatabaseError> {
        let tx = self.connection.unchecked_transaction()?;
        let mut inserted = 0usize;
        for record in records {
            let changed = tx.execute(
                "INSERT OR IGNORE INTO vulnerabilities
                    (cve_id, package_name, ecosystem, vulnerable_version_start,
                     vulnerable_version_end, severity, description)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    record.cve_id,
                    record.package_name,
                    record.ecosystem,
                    record.vulnerable_version_start,
                    record.vulnerable_version_end,
                    record.severity,
                    record.description,
                ],
            )?;
            if changed > 0 {
                inserted += 1;
            }
        }
        tx.commit()?;
        Ok(inserted)
    }

    pub fn get_last_updated(&self, ecosystem: &str) -> Result<Option<u64>, VulnDatabaseError> {
        let mut stmt = self
            .connection
            .prepare("SELECT last_updated_unix_ms FROM update_metadata WHERE ecosystem = ?1")?;
        let mut rows = stmt.query_map(params![ecosystem], |row| row.get::<_, i64>(0))?;
        match rows.next() {
            Some(Ok(ts)) => Ok(Some(ts as u64)),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    pub fn set_last_updated(
        &self,
        ecosystem: &str,
        timestamp_ms: u64,
    ) -> Result<(), VulnDatabaseError> {
        self.connection.execute(
            "INSERT OR REPLACE INTO update_metadata (ecosystem, last_updated_unix_ms)
             VALUES (?1, ?2)",
            params![ecosystem, timestamp_ms as i64],
        )?;
        Ok(())
    }

    pub fn clear_ecosystem(&self, ecosystem: &str) -> Result<u64, VulnDatabaseError> {
        let deleted = self.connection.execute(
            "DELETE FROM vulnerabilities WHERE ecosystem = ?1",
            params![ecosystem],
        )?;
        Ok(deleted as u64)
    }

    pub fn vulnerability_count(&self) -> Result<u64, VulnDatabaseError> {
        let count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM vulnerabilities", [], |row| row.get(0))?;
        Ok(count as u64)
    }
}

pub fn version_in_range(version: &str, start: &str, end: &str) -> bool {
    match (
        semver::Version::parse(version),
        semver::Version::parse(start),
        semver::Version::parse(end),
    ) {
        (Ok(v), Ok(s), Ok(e)) => v >= s && v <= e,
        _ => {
            compare_versions(version, start) != std::cmp::Ordering::Less
                && compare_versions(version, end) != std::cmp::Ordering::Greater
        }
    }
}

/// Compare two version strings, preferring semver semantics when both parse.
/// Falls back to lexicographic comparison for non-semver strings (e.g. "r2022a").
/// Lexicographic correctly orders pre-release suffixes ("beta" < "rc1") whereas
/// the old numeric-split approach silently dropped them, causing false negatives.
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    match (semver::Version::parse(a), semver::Version::parse(b)) {
        (Ok(av), Ok(bv)) => av.cmp(&bv),
        _ => a.cmp(b),
    }
}
