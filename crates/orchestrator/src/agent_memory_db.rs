use std::path::Path;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

/// Half-life for memory decay in milliseconds (7 days).
const DECAY_HALF_LIFE_MS: f64 = 7.0 * 24.0 * 3600.0 * 1000.0;

/// SQLite-backed persistent memory database for the LLM agent.
///
/// Stores four categories of cross-session intelligence:
/// 1. Successful techniques per tech stack (what worked)
/// 2. Failed attempts (what to avoid repeating)
/// 3. WAF bypass strategies that worked (evasion knowledge)
/// 4. Target similarity profiles (find similar targets for knowledge transfer)
///
/// Old memories decay over time via an exponential decay function applied
/// at query time, so stale techniques from months ago carry less weight
/// than recent discoveries.
pub struct AgentMemoryDb {
    conn: Connection,
}

/// Error type for memory database operations.
#[derive(Debug)]
pub enum MemoryDbError {
    Database(String),
    Serialization(String),
}

impl std::fmt::Display for MemoryDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(msg) => write!(f, "memory db error: {msg}"),
            Self::Serialization(msg) => write!(f, "memory db serialization error: {msg}"),
        }
    }
}

impl std::error::Error for MemoryDbError {}

impl From<rusqlite::Error> for MemoryDbError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(e.to_string())
    }
}

impl From<serde_json::Error> for MemoryDbError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

/// A recorded technique (success or failure) with full context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueMemory {
    pub id: Option<i64>,
    pub vulnerability_class: String,
    pub endpoint_pattern: String,
    pub payload_type: String,
    pub evasion_technique: Option<String>,
    pub success: bool,
    pub tech_stack: Vec<String>,
    pub defense_stack: Vec<String>,
    pub confidence: f64,
    pub session_id: String,
    pub target_url: String,
    pub timestamp_ms: u64,
}

/// A recorded WAF bypass strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafBypassMemory {
    pub id: Option<i64>,
    pub waf_vendor: String,
    pub bypass_technique: String,
    pub payload_mutation: String,
    pub vulnerability_class: String,
    pub success: bool,
    pub session_id: String,
    pub timestamp_ms: u64,
}

/// A target profile for similarity matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetProfile {
    pub id: Option<i64>,
    pub target_url: String,
    pub tech_stack_json: String,
    pub total_findings: u32,
    pub highest_severity: f64,
    pub session_id: String,
    pub timestamp_ms: u64,
}

/// Aggregated success rate with decay-weighted scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecayedSuccessRate {
    pub vulnerability_class: String,
    pub raw_success_rate: f64,
    pub decayed_score: f64,
    pub total_attempts: u64,
    pub successes: u64,
    pub mean_age_ms: u64,
}

/// Cross-session learnings for a specific tech stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackLearnings {
    pub tech_stack: Vec<String>,
    pub top_vulnerability_classes: Vec<(String, f64)>,
    pub known_bypasses: Vec<String>,
    pub total_sessions: u64,
}

impl AgentMemoryDb {
    /// Open or create a memory database at the given path.
    pub fn open(path: &Path) -> Result<Self, MemoryDbError> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.initialize_schema()?;
        Ok(db)
    }

    /// Open an in-memory database for testing.
    pub fn open_in_memory() -> Result<Self, MemoryDbError> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.initialize_schema()?;
        Ok(db)
    }

    fn initialize_schema(&self) -> Result<(), MemoryDbError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS techniques (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_class TEXT NOT NULL,
                endpoint_pattern TEXT NOT NULL,
                payload_type TEXT NOT NULL,
                evasion_technique TEXT,
                success INTEGER NOT NULL,
                tech_stack_json TEXT NOT NULL DEFAULT '[]',
                defense_stack_json TEXT NOT NULL DEFAULT '[]',
                confidence REAL NOT NULL DEFAULT 0.0,
                session_id TEXT NOT NULL,
                target_url TEXT NOT NULL DEFAULT '',
                timestamp_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS waf_bypasses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                waf_vendor TEXT NOT NULL,
                bypass_technique TEXT NOT NULL,
                payload_mutation TEXT NOT NULL,
                vulnerability_class TEXT NOT NULL DEFAULT '',
                success INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS target_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                tech_stack_json TEXT NOT NULL DEFAULT '[]',
                total_findings INTEGER NOT NULL DEFAULT 0,
                highest_severity REAL NOT NULL DEFAULT 0.0,
                session_id TEXT NOT NULL UNIQUE,
                timestamp_ms INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_tech_class ON techniques(vulnerability_class);
            CREATE INDEX IF NOT EXISTS idx_tech_stack ON techniques(tech_stack_json);
            CREATE INDEX IF NOT EXISTS idx_tech_target ON techniques(target_url);
            CREATE INDEX IF NOT EXISTS idx_tech_success ON techniques(success);
            CREATE INDEX IF NOT EXISTS idx_bypass_vendor ON waf_bypasses(waf_vendor);
            CREATE INDEX IF NOT EXISTS idx_bypass_success ON waf_bypasses(success);
            CREATE INDEX IF NOT EXISTS idx_profile_url ON target_profiles(target_url);
            CREATE INDEX IF NOT EXISTS idx_profile_stack ON target_profiles(tech_stack_json);",
        )?;
        Ok(())
    }

    /// Store a technique outcome (success or failure).
    pub fn store_technique(&self, mem: &TechniqueMemory) -> Result<i64, MemoryDbError> {
        let tech_json = serde_json::to_string(&mem.tech_stack)?;
        let defense_json = serde_json::to_string(&mem.defense_stack)?;
        self.conn.execute(
            "INSERT INTO techniques
                (vulnerability_class, endpoint_pattern, payload_type, evasion_technique,
                 success, tech_stack_json, defense_stack_json, confidence,
                 session_id, target_url, timestamp_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                mem.vulnerability_class,
                mem.endpoint_pattern,
                mem.payload_type,
                mem.evasion_technique,
                mem.success as i32,
                tech_json,
                defense_json,
                mem.confidence,
                mem.session_id,
                mem.target_url,
                mem.timestamp_ms as i64,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Store a WAF bypass strategy.
    pub fn store_bypass(&self, mem: &WafBypassMemory) -> Result<i64, MemoryDbError> {
        self.conn.execute(
            "INSERT INTO waf_bypasses
                (waf_vendor, bypass_technique, payload_mutation, vulnerability_class,
                 success, session_id, timestamp_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                mem.waf_vendor,
                mem.bypass_technique,
                mem.payload_mutation,
                mem.vulnerability_class,
                mem.success as i32,
                mem.session_id,
                mem.timestamp_ms as i64,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Store a target profile for cross-session similarity matching.
    pub fn store_target_profile(&self, profile: &TargetProfile) -> Result<i64, MemoryDbError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO target_profiles
                (target_url, tech_stack_json, total_findings, highest_severity,
                 session_id, timestamp_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                profile.target_url,
                profile.tech_stack_json,
                profile.total_findings as i32,
                profile.highest_severity,
                profile.session_id,
                profile.timestamp_ms as i64,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Query successful techniques for a vulnerability class, weighted by decay.
    pub fn successful_techniques_for_class(
        &self,
        vulnerability_class: &str,
        now_ms: u64,
    ) -> Result<Vec<(TechniqueMemory, f64)>, MemoryDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, vulnerability_class, endpoint_pattern, payload_type,
                    evasion_technique, success, tech_stack_json, defense_stack_json,
                    confidence, session_id, target_url, timestamp_ms
             FROM techniques
             WHERE vulnerability_class = ?1 AND success = 1
             ORDER BY timestamp_ms DESC
             LIMIT 100",
        )?;
        let rows = stmt
            .query_map(params![vulnerability_class], |row| {
                let ts: i64 = row.get(11)?;
                Ok((
                    TechniqueMemory {
                        id: Some(row.get(0)?),
                        vulnerability_class: row.get(1)?,
                        endpoint_pattern: row.get(2)?,
                        payload_type: row.get(3)?,
                        evasion_technique: row.get(4)?,
                        success: {
                            let v: i32 = row.get(5)?;
                            v != 0
                        },
                        tech_stack: serde_json::from_str(
                            &row.get::<_, String>(6).unwrap_or_default(),
                        )
                        .unwrap_or_default(),
                        defense_stack: serde_json::from_str(
                            &row.get::<_, String>(7).unwrap_or_default(),
                        )
                        .unwrap_or_default(),
                        confidence: row.get(8)?,
                        session_id: row.get(9)?,
                        target_url: row.get(10)?,
                        timestamp_ms: ts as u64,
                    },
                    ts as u64,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows
            .into_iter()
            .map(|(mem, ts)| {
                let decay = compute_decay(now_ms, ts);
                (mem, decay)
            })
            .collect())
    }

    /// Query failed techniques for a vulnerability class (so the agent avoids repeating).
    pub fn failed_techniques_for_class(
        &self,
        vulnerability_class: &str,
    ) -> Result<Vec<TechniqueMemory>, MemoryDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, vulnerability_class, endpoint_pattern, payload_type,
                    evasion_technique, success, tech_stack_json, defense_stack_json,
                    confidence, session_id, target_url, timestamp_ms
             FROM techniques
             WHERE vulnerability_class = ?1 AND success = 0
             ORDER BY timestamp_ms DESC
             LIMIT 200",
        )?;
        let rows = stmt
            .query_map(params![vulnerability_class], |row| {
                let ts: i64 = row.get(11)?;
                Ok(TechniqueMemory {
                    id: Some(row.get(0)?),
                    vulnerability_class: row.get(1)?,
                    endpoint_pattern: row.get(2)?,
                    payload_type: row.get(3)?,
                    evasion_technique: row.get(4)?,
                    success: false,
                    tech_stack: serde_json::from_str(
                        &row.get::<_, String>(6).unwrap_or_default(),
                    )
                    .unwrap_or_default(),
                    defense_stack: serde_json::from_str(
                        &row.get::<_, String>(7).unwrap_or_default(),
                    )
                    .unwrap_or_default(),
                    confidence: row.get(8)?,
                    session_id: row.get(9)?,
                    target_url: row.get(10)?,
                    timestamp_ms: ts as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Query successful WAF bypass strategies for a vendor.
    pub fn successful_bypasses_for_vendor(
        &self,
        waf_vendor: &str,
    ) -> Result<Vec<WafBypassMemory>, MemoryDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, waf_vendor, bypass_technique, payload_mutation,
                    vulnerability_class, success, session_id, timestamp_ms
             FROM waf_bypasses
             WHERE waf_vendor = ?1 AND success = 1
             ORDER BY timestamp_ms DESC
             LIMIT 50",
        )?;
        let rows = stmt
            .query_map(params![waf_vendor], |row| {
                let ts: i64 = row.get(7)?;
                Ok(WafBypassMemory {
                    id: Some(row.get(0)?),
                    waf_vendor: row.get(1)?,
                    bypass_technique: row.get(2)?,
                    payload_mutation: row.get(3)?,
                    vulnerability_class: row.get(4)?,
                    success: true,
                    session_id: row.get(6)?,
                    timestamp_ms: ts as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Load learnings from previous scans of similar targets (same tech stack).
    pub fn load_learnings_for_stack(
        &self,
        tech_stack: &[String],
    ) -> Result<StackLearnings, MemoryDbError> {
        let tech_json = serde_json::to_string(tech_stack)?;

        let total_sessions: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM target_profiles WHERE tech_stack_json = ?1",
            params![tech_json],
            |row| row.get(0),
        )?;

        let mut class_stmt = self.conn.prepare(
            "SELECT vulnerability_class, CAST(SUM(success) AS REAL) / COUNT(*) AS rate
             FROM techniques
             WHERE tech_stack_json = ?1 AND success = 1
             GROUP BY vulnerability_class
             HAVING COUNT(*) >= 2
             ORDER BY rate DESC
             LIMIT 10",
        )?;
        let top_classes: Vec<(String, f64)> = class_stmt
            .query_map(params![tech_json], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut bypass_stmt = self.conn.prepare(
            "SELECT DISTINCT bypass_technique FROM waf_bypasses
             WHERE success = 1 AND session_id IN (
                 SELECT session_id FROM target_profiles WHERE tech_stack_json = ?1
             )
             LIMIT 20",
        )?;
        let bypasses: Vec<String> = bypass_stmt
            .query_map(params![tech_json], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(StackLearnings {
            tech_stack: tech_stack.to_vec(),
            top_vulnerability_classes: top_classes,
            known_bypasses: bypasses,
            total_sessions: total_sessions as u64,
        })
    }

    /// Compute decay-weighted success rate for a vulnerability class.
    pub fn decayed_success_rate(
        &self,
        vulnerability_class: &str,
        now_ms: u64,
    ) -> Result<DecayedSuccessRate, MemoryDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT success, timestamp_ms FROM techniques
             WHERE vulnerability_class = ?1",
        )?;
        let rows: Vec<(bool, u64)> = stmt
            .query_map(params![vulnerability_class], |row| {
                let success: i32 = row.get(0)?;
                let ts: i64 = row.get(1)?;
                Ok((success != 0, ts as u64))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        if rows.is_empty() {
            return Ok(DecayedSuccessRate {
                vulnerability_class: vulnerability_class.to_string(),
                raw_success_rate: 0.0,
                decayed_score: 0.0,
                total_attempts: 0,
                successes: 0,
                mean_age_ms: 0,
            });
        }

        let total = rows.len() as u64;
        let successes = rows.iter().filter(|(s, _)| *s).count() as u64;
        let raw_rate = successes as f64 / total as f64;

        let mut weighted_success = 0.0_f64;
        let mut total_weight = 0.0_f64;
        let mut age_sum = 0u64;

        for (success, ts) in &rows {
            let decay = compute_decay(now_ms, *ts);
            total_weight += decay;
            if *success {
                weighted_success += decay;
            }
            age_sum += now_ms.saturating_sub(*ts);
        }

        let decayed_score = if total_weight > 0.0 {
            weighted_success / total_weight
        } else {
            0.0
        };

        let mean_age = age_sum / total;

        Ok(DecayedSuccessRate {
            vulnerability_class: vulnerability_class.to_string(),
            raw_success_rate: raw_rate,
            decayed_score,
            total_attempts: total,
            successes,
            mean_age_ms: mean_age,
        })
    }

    /// Total technique records in the database.
    pub fn total_techniques(&self) -> Result<u64, MemoryDbError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM techniques", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// Total bypass records in the database.
    pub fn total_bypasses(&self) -> Result<u64, MemoryDbError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM waf_bypasses", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// Total target profiles in the database.
    pub fn total_profiles(&self) -> Result<u64, MemoryDbError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM target_profiles",
            [],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Purge memories older than the given threshold (in milliseconds).
    pub fn purge_older_than(&self, threshold_ms: u64) -> Result<u64, MemoryDbError> {
        let threshold = threshold_ms as i64;
        let mut total = 0u64;
        total += self.conn.execute(
            "DELETE FROM techniques WHERE timestamp_ms < ?1",
            params![threshold],
        )? as u64;
        total += self.conn.execute(
            "DELETE FROM waf_bypasses WHERE timestamp_ms < ?1",
            params![threshold],
        )? as u64;
        Ok(total)
    }
}

/// Compute exponential decay factor for a memory record.
///
/// Returns a value in (0, 1] where 1.0 is "just recorded" and values
/// approach 0.0 as the record ages. Uses a 7-day half-life.
pub fn compute_decay(now_ms: u64, record_ms: u64) -> f64 {
    let age_ms = now_ms.saturating_sub(record_ms) as f64;
    (-age_ms * (2.0_f64.ln()) / DECAY_HALF_LIFE_MS).exp()
}

#[cfg(test)]
#[path = "agent_memory_db_test.rs"]
mod agent_memory_db_test;
