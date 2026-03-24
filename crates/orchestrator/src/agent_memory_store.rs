use std::collections::HashMap;
use std::path::Path;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::agent_loop::{
    AgentMemory, EndpointBehavior, IterationSummary, TechniqueRecord, WafBypassRecord,
};

/// Persistent cross-session memory store for the autonomous agent.
///
/// Backs `AgentMemory` with SQLite so the agent learns across scan sessions.
/// Stores: technique outcomes, WAF bypass patterns, tech-stack correlations,
/// endpoint behaviors, and per-session summaries. Queries expose aggregate
/// success rates and correlation lookups so the Brain can reason about what
/// worked historically against similar targets.
///
/// Schema is append-only — we never delete historical data because even
/// failures carry signal ("don't retry this against ModSecurity").
pub struct AgentMemoryStore {
    conn: Connection,
}

/// Error type for memory store operations.
#[derive(Debug)]
pub enum MemoryStoreError {
    Database(String),
    Serialization(String),
}

impl std::fmt::Display for MemoryStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(msg) => write!(f, "memory store database error: {msg}"),
            Self::Serialization(msg) => write!(f, "memory store serialization error: {msg}"),
        }
    }
}

impl std::error::Error for MemoryStoreError {}

impl From<rusqlite::Error> for MemoryStoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(e.to_string())
    }
}

impl From<serde_json::Error> for MemoryStoreError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

/// A technique outcome record enriched with tech-stack context.
///
/// The key insight: "XSS via polyglot payload worked against Express+EJS
/// behind Cloudflare" is far more useful than "XSS worked somewhere."
/// This struct captures that full context for cross-session correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueOutcome {
    pub vulnerability_class: String,
    pub endpoint_pattern: String,
    pub payload_type: String,
    pub evasion_used: Option<String>,
    pub success: bool,
    pub tech_stack: Vec<String>,
    pub defense_stack: Vec<String>,
    pub confidence: f64,
    pub session_id: String,
    pub timestamp_ms: u64,
}

/// Aggregated success rate for a vulnerability class against a specific
/// tech-stack or defense configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassSuccessRate {
    pub vulnerability_class: String,
    pub total_attempts: u64,
    pub successes: u64,
    pub rate: f64,
}

/// A WAF bypass record with full context for cross-session reuse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredBypass {
    pub id: i64,
    pub defense_type: String,
    pub defense_vendor: Option<String>,
    pub bypass_technique: String,
    pub payload_mutation: String,
    pub success: bool,
    pub tech_stack_json: String,
    pub session_id: String,
    pub timestamp_ms: u64,
}

/// Tech-stack correlation: "when we see this stack, these classes succeed."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechStackCorrelation {
    pub tech_stack_key: String,
    pub vulnerability_class: String,
    pub success_rate: f64,
    pub sample_count: u64,
}

/// Session summary for historical trend analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub target_url: String,
    pub tech_stack_json: String,
    pub total_findings: u32,
    pub total_actions: u32,
    pub iterations: u32,
    pub effectiveness: f64,
    pub duration_ms: u64,
    pub timestamp_ms: u64,
}

impl AgentMemoryStore {
    /// Opens or creates a memory store at the given filesystem path.
    pub fn open(path: &Path) -> Result<Self, MemoryStoreError> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.initialize_schema()?;
        Ok(store)
    }

    /// Opens an in-memory store for testing.
    pub fn open_in_memory() -> Result<Self, MemoryStoreError> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.initialize_schema()?;
        Ok(store)
    }

    fn initialize_schema(&self) -> Result<(), MemoryStoreError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS technique_outcomes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_class TEXT NOT NULL,
                endpoint_pattern TEXT NOT NULL,
                payload_type TEXT NOT NULL,
                evasion_used TEXT,
                success INTEGER NOT NULL,
                tech_stack_json TEXT NOT NULL DEFAULT '[]',
                defense_stack_json TEXT NOT NULL DEFAULT '[]',
                confidence REAL NOT NULL DEFAULT 0.0,
                session_id TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS waf_bypasses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                defense_type TEXT NOT NULL,
                defense_vendor TEXT,
                bypass_technique TEXT NOT NULL,
                payload_mutation TEXT NOT NULL,
                success INTEGER NOT NULL,
                tech_stack_json TEXT NOT NULL DEFAULT '[]',
                session_id TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS endpoint_behaviors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_pattern TEXT NOT NULL,
                typical_response_code INTEGER NOT NULL,
                typical_response_time_ms INTEGER NOT NULL,
                content_type TEXT NOT NULL,
                parameters_json TEXT NOT NULL DEFAULT '[]',
                auth_type TEXT,
                response_varies INTEGER NOT NULL DEFAULT 0,
                timing_variance_ms REAL NOT NULL DEFAULT 0.0,
                session_id TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS session_summaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL UNIQUE,
                target_url TEXT NOT NULL,
                tech_stack_json TEXT NOT NULL DEFAULT '[]',
                total_findings INTEGER NOT NULL DEFAULT 0,
                total_actions INTEGER NOT NULL DEFAULT 0,
                iterations INTEGER NOT NULL DEFAULT 0,
                effectiveness REAL NOT NULL DEFAULT 0.0,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                timestamp_ms INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_technique_vuln_class
                ON technique_outcomes(vulnerability_class);
            CREATE INDEX IF NOT EXISTS idx_technique_session
                ON technique_outcomes(session_id);
            CREATE INDEX IF NOT EXISTS idx_technique_tech_stack
                ON technique_outcomes(tech_stack_json);
            CREATE INDEX IF NOT EXISTS idx_bypass_defense
                ON waf_bypasses(defense_type);
            CREATE INDEX IF NOT EXISTS idx_bypass_vendor
                ON waf_bypasses(defense_vendor);
            CREATE INDEX IF NOT EXISTS idx_endpoint_pattern
                ON endpoint_behaviors(endpoint_pattern);
            CREATE INDEX IF NOT EXISTS idx_session_target
                ON session_summaries(target_url);",
        )?;
        Ok(())
    }

    /// Records a technique outcome (success or failure) with full context.
    pub fn record_technique(
        &self,
        outcome: &TechniqueOutcome,
    ) -> Result<i64, MemoryStoreError> {
        let tech_json = serde_json::to_string(&outcome.tech_stack)?;
        let defense_json = serde_json::to_string(&outcome.defense_stack)?;
        self.conn.execute(
            "INSERT INTO technique_outcomes
                (vulnerability_class, endpoint_pattern, payload_type, evasion_used,
                 success, tech_stack_json, defense_stack_json, confidence,
                 session_id, timestamp_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                outcome.vulnerability_class,
                outcome.endpoint_pattern,
                outcome.payload_type,
                outcome.evasion_used,
                outcome.success as i32,
                tech_json,
                defense_json,
                outcome.confidence,
                outcome.session_id,
                outcome.timestamp_ms as i64,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Records a WAF bypass attempt with defense context.
    pub fn record_bypass(
        &self,
        defense_type: &str,
        defense_vendor: Option<&str>,
        bypass_technique: &str,
        payload_mutation: &str,
        success: bool,
        tech_stack: &[String],
        session_id: &str,
        timestamp_ms: u64,
    ) -> Result<i64, MemoryStoreError> {
        let tech_json = serde_json::to_string(tech_stack)?;
        self.conn.execute(
            "INSERT INTO waf_bypasses
                (defense_type, defense_vendor, bypass_technique, payload_mutation,
                 success, tech_stack_json, session_id, timestamp_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                defense_type,
                defense_vendor,
                bypass_technique,
                payload_mutation,
                success as i32,
                tech_json,
                session_id,
                timestamp_ms as i64,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Records endpoint behavior observation.
    pub fn record_endpoint_behavior(
        &self,
        endpoint_pattern: &str,
        behavior: &EndpointBehavior,
        session_id: &str,
        timestamp_ms: u64,
    ) -> Result<i64, MemoryStoreError> {
        let params_json = serde_json::to_string(&behavior.parameters_discovered)?;
        self.conn.execute(
            "INSERT INTO endpoint_behaviors
                (endpoint_pattern, typical_response_code, typical_response_time_ms,
                 content_type, parameters_json, auth_type, response_varies,
                 timing_variance_ms, session_id, timestamp_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                endpoint_pattern,
                behavior.typical_response_code as i32,
                behavior.typical_response_time_ms as i64,
                behavior.content_type,
                params_json,
                behavior.auth_type,
                behavior.response_varies_with_input as i32,
                behavior.timing_variance_ms,
                session_id,
                timestamp_ms as i64,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Saves a session summary for historical trend tracking.
    pub fn save_session_summary(
        &self,
        summary: &SessionSummary,
    ) -> Result<i64, MemoryStoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO session_summaries
                (session_id, target_url, tech_stack_json, total_findings,
                 total_actions, iterations, effectiveness, duration_ms, timestamp_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                summary.session_id,
                summary.target_url,
                summary.tech_stack_json,
                summary.total_findings as i32,
                summary.total_actions as i32,
                summary.iterations as i32,
                summary.effectiveness,
                summary.duration_ms as i64,
                summary.timestamp_ms as i64,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Returns the global success rate for a vulnerability class across all sessions.
    pub fn success_rate_for_class(
        &self,
        vulnerability_class: &str,
    ) -> Result<ClassSuccessRate, MemoryStoreError> {
        let (total, successes): (i64, i64) = self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(success), 0)
             FROM technique_outcomes
             WHERE vulnerability_class = ?1",
            params![vulnerability_class],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let rate = if total == 0 {
            0.0
        } else {
            successes as f64 / total as f64
        };
        Ok(ClassSuccessRate {
            vulnerability_class: vulnerability_class.to_string(),
            total_attempts: total as u64,
            successes: successes as u64,
            rate,
        })
    }

    /// Returns success rates for all vulnerability classes that have data.
    pub fn all_class_success_rates(
        &self,
    ) -> Result<Vec<ClassSuccessRate>, MemoryStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT vulnerability_class, COUNT(*), COALESCE(SUM(success), 0)
             FROM technique_outcomes
             GROUP BY vulnerability_class
             ORDER BY vulnerability_class",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let class: String = row.get(0)?;
                let total: i64 = row.get(1)?;
                let successes: i64 = row.get(2)?;
                Ok((class, total, successes))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .map(|(class, total, successes)| {
                let rate = if total == 0 {
                    0.0
                } else {
                    successes as f64 / total as f64
                };
                ClassSuccessRate {
                    vulnerability_class: class,
                    total_attempts: total as u64,
                    successes: successes as u64,
                    rate,
                }
            })
            .collect())
    }

    /// Finds successful bypass techniques for a specific defense type/vendor.
    ///
    /// The agent uses this to short-circuit evasion: "Cloudflare? Last time
    /// unicode normalization + double-encoding worked. Start there."
    pub fn successful_bypasses_for(
        &self,
        defense_type: &str,
        defense_vendor: Option<&str>,
    ) -> Result<Vec<StoredBypass>, MemoryStoreError> {
        let (sql, values): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match defense_vendor {
            Some(vendor) => (
                "SELECT id, defense_type, defense_vendor, bypass_technique, payload_mutation,
                        success, tech_stack_json, session_id, timestamp_ms
                 FROM waf_bypasses
                 WHERE defense_type = ?1 AND defense_vendor = ?2 AND success = 1
                 ORDER BY timestamp_ms DESC",
                vec![
                    Box::new(defense_type.to_string()) as Box<dyn rusqlite::types::ToSql>,
                    Box::new(vendor.to_string()),
                ],
            ),
            None => (
                "SELECT id, defense_type, defense_vendor, bypass_technique, payload_mutation,
                        success, tech_stack_json, session_id, timestamp_ms
                 FROM waf_bypasses
                 WHERE defense_type = ?1 AND success = 1
                 ORDER BY timestamp_ms DESC",
                vec![Box::new(defense_type.to_string()) as Box<dyn rusqlite::types::ToSql>],
            ),
        };
        let mut stmt = self.conn.prepare(sql)?;
        let params_slice: Vec<&dyn rusqlite::types::ToSql> =
            values.iter().map(|v| v.as_ref()).collect();
        let rows = stmt
            .query_map(params_slice.as_slice(), |row| {
                Ok(StoredBypass {
                    id: row.get(0)?,
                    defense_type: row.get(1)?,
                    defense_vendor: row.get(2)?,
                    bypass_technique: row.get(3)?,
                    payload_mutation: row.get(4)?,
                    success: {
                        let v: i32 = row.get(5)?;
                        v != 0
                    },
                    tech_stack_json: row.get(6)?,
                    session_id: row.get(7)?,
                    timestamp_ms: {
                        let v: i64 = row.get(8)?;
                        v as u64
                    },
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Returns tech-stack → vulnerability class correlations.
    ///
    /// Groups technique outcomes by tech_stack_json and vulnerability_class,
    /// computing success rates. The agent uses this for: "Last time I saw
    /// Express+EJS, SSTI had a 67% success rate — prioritize that."
    pub fn tech_stack_correlations(
        &self,
    ) -> Result<Vec<TechStackCorrelation>, MemoryStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT tech_stack_json, vulnerability_class, COUNT(*), COALESCE(SUM(success), 0)
             FROM technique_outcomes
             GROUP BY tech_stack_json, vulnerability_class
             HAVING COUNT(*) >= 2
             ORDER BY CAST(COALESCE(SUM(success), 0) AS REAL) / COUNT(*) DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let tech: String = row.get(0)?;
                let class: String = row.get(1)?;
                let total: i64 = row.get(2)?;
                let successes: i64 = row.get(3)?;
                Ok((tech, class, total, successes))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .map(|(tech, class, total, successes)| TechStackCorrelation {
                tech_stack_key: tech,
                vulnerability_class: class,
                success_rate: if total == 0 {
                    0.0
                } else {
                    successes as f64 / total as f64
                },
                sample_count: total as u64,
            })
            .collect())
    }

    /// Returns success rate for a specific vulnerability class against a
    /// specific tech stack (JSON-serialized).
    pub fn success_rate_for_stack(
        &self,
        tech_stack_json: &str,
        vulnerability_class: &str,
    ) -> Result<Option<f64>, MemoryStoreError> {
        let result: Result<(i64, i64), _> = self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(success), 0)
             FROM technique_outcomes
             WHERE tech_stack_json = ?1 AND vulnerability_class = ?2",
            params![tech_stack_json, vulnerability_class],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );
        match result {
            Ok((total, successes)) if total > 0 => {
                Ok(Some(successes as f64 / total as f64))
            }
            Ok(_) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Persists an in-memory `AgentMemory` to the store at end of scan.
    ///
    /// Bulk-inserts all technique records, bypass records, and endpoint
    /// behaviors from the current session. Uses a transaction for atomicity.
    pub fn persist_agent_memory(
        &self,
        memory: &AgentMemory,
        session_id: &str,
        target_url: &str,
        tech_stack: &[String],
        duration_ms: u64,
    ) -> Result<u64, MemoryStoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let mut count = 0u64;
        let timestamp = current_timestamp_ms();
        let tech_json = serde_json::to_string(tech_stack)?;

        for technique in &memory.successful_techniques {
            tx.execute(
                "INSERT INTO technique_outcomes
                    (vulnerability_class, endpoint_pattern, payload_type, evasion_used,
                     success, tech_stack_json, defense_stack_json, confidence,
                     session_id, timestamp_ms)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, '[]', 0.0, ?6, ?7)",
                params![
                    technique.vulnerability_class,
                    technique.endpoint,
                    technique.payload_type,
                    technique.evasion_used,
                    tech_json,
                    session_id,
                    timestamp as i64,
                ],
            )?;
            count += 1;
        }

        for technique in &memory.failed_techniques {
            tx.execute(
                "INSERT INTO technique_outcomes
                    (vulnerability_class, endpoint_pattern, payload_type, evasion_used,
                     success, tech_stack_json, defense_stack_json, confidence,
                     session_id, timestamp_ms)
                 VALUES (?1, ?2, ?3, ?4, 0, ?5, '[]', 0.0, ?6, ?7)",
                params![
                    technique.vulnerability_class,
                    technique.endpoint,
                    technique.payload_type,
                    technique.evasion_used,
                    tech_json,
                    session_id,
                    timestamp as i64,
                ],
            )?;
            count += 1;
        }

        for bypass in &memory.waf_bypass_patterns {
            tx.execute(
                "INSERT INTO waf_bypasses
                    (defense_type, defense_vendor, bypass_technique, payload_mutation,
                     success, tech_stack_json, session_id, timestamp_ms)
                 VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    bypass.defense_type,
                    bypass.bypass_technique,
                    bypass.payload_mutation,
                    bypass.successful as i32,
                    tech_json,
                    session_id,
                    timestamp as i64,
                ],
            )?;
            count += 1;
        }

        for (endpoint, behavior) in &memory.endpoint_behaviors {
            let params_json = serde_json::to_string(&behavior.parameters_discovered)?;
            tx.execute(
                "INSERT INTO endpoint_behaviors
                    (endpoint_pattern, typical_response_code, typical_response_time_ms,
                     content_type, parameters_json, auth_type, response_varies,
                     timing_variance_ms, session_id, timestamp_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    endpoint,
                    behavior.typical_response_code as i32,
                    behavior.typical_response_time_ms as i64,
                    behavior.content_type,
                    params_json,
                    behavior.auth_type,
                    behavior.response_varies_with_input as i32,
                    behavior.timing_variance_ms,
                    session_id,
                    timestamp as i64,
                ],
            )?;
            count += 1;
        }

        let total_findings: u32 = memory.iteration_summaries.iter().map(|s| s.new_findings).sum();
        tx.execute(
            "INSERT OR REPLACE INTO session_summaries
                (session_id, target_url, tech_stack_json, total_findings,
                 total_actions, iterations, effectiveness, duration_ms, timestamp_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                session_id,
                target_url,
                tech_json,
                total_findings as i32,
                memory.total_actions_taken as i32,
                memory.iteration_summaries.len() as i32,
                if memory.hypotheses_generated == 0 {
                    0.0
                } else {
                    memory.hypotheses_confirmed as f64 / memory.hypotheses_generated as f64
                },
                duration_ms as i64,
                timestamp as i64,
            ],
        )?;
        count += 1;

        tx.commit()?;
        Ok(count)
    }

    /// Hydrates an `AgentMemory` from historical data for a target.
    ///
    /// Pre-loads relevant technique outcomes and bypass patterns so the
    /// agent starts a new scan with institutional knowledge rather than
    /// from scratch. Filters by tech stack similarity when available.
    pub fn hydrate_memory_for_target(
        &self,
        target_url: &str,
        tech_stack: &[String],
    ) -> Result<AgentMemory, MemoryStoreError> {
        let mut memory = AgentMemory::default();
        let tech_json = serde_json::to_string(tech_stack)?;

        let mut stmt = self.conn.prepare(
            "SELECT vulnerability_class, endpoint_pattern, payload_type, evasion_used, success
             FROM technique_outcomes
             WHERE session_id IN (
                 SELECT session_id FROM session_summaries WHERE target_url = ?1
             )
             OR tech_stack_json = ?2
             ORDER BY timestamp_ms DESC
             LIMIT 500",
        )?;
        let rows = stmt
            .query_map(params![target_url, tech_json], |row| {
                let vuln: String = row.get(0)?;
                let endpoint: String = row.get(1)?;
                let payload: String = row.get(2)?;
                let evasion: Option<String> = row.get(3)?;
                let success: i32 = row.get(4)?;
                Ok((vuln, endpoint, payload, evasion, success != 0))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        for (vuln, endpoint, payload, evasion, success) in rows {
            let record = TechniqueRecord {
                vulnerability_class: vuln,
                endpoint,
                payload_type: payload,
                evasion_used: evasion,
                iteration: 0,
            };
            if success {
                memory.record_success(record);
            } else {
                memory.record_failure(record);
            }
        }

        let mut bypass_stmt = self.conn.prepare(
            "SELECT defense_type, bypass_technique, payload_mutation, success
             FROM waf_bypasses
             WHERE session_id IN (
                 SELECT session_id FROM session_summaries WHERE target_url = ?1
             )
             OR tech_stack_json = ?2
             ORDER BY timestamp_ms DESC
             LIMIT 200",
        )?;
        let bypass_rows = bypass_stmt
            .query_map(params![target_url, tech_json], |row| {
                let defense: String = row.get(0)?;
                let technique: String = row.get(1)?;
                let mutation: String = row.get(2)?;
                let success: i32 = row.get(3)?;
                Ok((defense, technique, mutation, success != 0))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        for (defense, technique, mutation, success) in bypass_rows {
            memory.record_waf_bypass(WafBypassRecord {
                defense_type: defense,
                bypass_technique: technique,
                payload_mutation: mutation,
                successful: success,
                iteration: 0,
            });
        }

        Ok(memory)
    }

    /// Builds a context string suitable for injection into an LLM prompt.
    ///
    /// Summarizes cross-session knowledge: top techniques, WAF bypasses,
    /// tech-stack correlations. Formatted as structured text the Brain can
    /// reason about when planning its next moves.
    pub fn build_llm_context(
        &self,
        tech_stack: &[String],
        defense_type: Option<&str>,
    ) -> Result<String, MemoryStoreError> {
        let mut ctx = String::from("<cross_session_memory>\n");

        let rates = self.all_class_success_rates()?;
        if !rates.is_empty() {
            ctx.push_str("  <historical_success_rates>\n");
            for rate in &rates {
                ctx.push_str(&format!(
                    "    {}: {:.0}% ({}/{} attempts)\n",
                    rate.vulnerability_class,
                    rate.rate * 100.0,
                    rate.successes,
                    rate.total_attempts,
                ));
            }
            ctx.push_str("  </historical_success_rates>\n");
        }

        if !tech_stack.is_empty() {
            let tech_json = serde_json::to_string(tech_stack)?;
            let correlations = self.tech_stack_correlations()?;
            let relevant: Vec<_> = correlations
                .iter()
                .filter(|c| c.tech_stack_key == tech_json)
                .collect();
            if !relevant.is_empty() {
                ctx.push_str("  <tech_stack_correlations>\n");
                for corr in relevant {
                    ctx.push_str(&format!(
                        "    Against this tech stack, {} has {:.0}% success rate ({} samples)\n",
                        corr.vulnerability_class,
                        corr.success_rate * 100.0,
                        corr.sample_count,
                    ));
                }
                ctx.push_str("  </tech_stack_correlations>\n");
            }
        }

        if let Some(dt) = defense_type {
            let bypasses = self.successful_bypasses_for(dt, None)?;
            if !bypasses.is_empty() {
                ctx.push_str("  <known_bypasses>\n");
                for bypass in bypasses.iter().take(10) {
                    ctx.push_str(&format!(
                        "    {} via {} (mutation: {})\n",
                        bypass.defense_type, bypass.bypass_technique, bypass.payload_mutation,
                    ));
                }
                ctx.push_str("  </known_bypasses>\n");
            }
        }

        ctx.push_str("</cross_session_memory>");
        Ok(ctx)
    }

    /// Returns the total number of technique outcome records.
    pub fn total_technique_records(&self) -> Result<u64, MemoryStoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM technique_outcomes",
            [],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Returns the total number of WAF bypass records.
    pub fn total_bypass_records(&self) -> Result<u64, MemoryStoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM waf_bypasses",
            [],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Returns the total number of session summaries.
    pub fn total_sessions(&self) -> Result<u64, MemoryStoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM session_summaries",
            [],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Returns all session summaries, most recent first.
    pub fn all_sessions(&self) -> Result<Vec<SessionSummary>, MemoryStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT session_id, target_url, tech_stack_json, total_findings,
                    total_actions, iterations, effectiveness, duration_ms, timestamp_ms
             FROM session_summaries
             ORDER BY timestamp_ms DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(SessionSummary {
                    session_id: row.get(0)?,
                    target_url: row.get(1)?,
                    tech_stack_json: row.get(2)?,
                    total_findings: {
                        let v: i32 = row.get(3)?;
                        v as u32
                    },
                    total_actions: {
                        let v: i32 = row.get(4)?;
                        v as u32
                    },
                    iterations: {
                        let v: i32 = row.get(5)?;
                        v as u32
                    },
                    effectiveness: row.get(6)?,
                    duration_ms: {
                        let v: i64 = row.get(7)?;
                        v as u64
                    },
                    timestamp_ms: {
                        let v: i64 = row.get(8)?;
                        v as u64
                    },
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Returns the most effective technique for a vulnerability class.
    ///
    /// Ranks by success count descending. Returns the payload_type and
    /// evasion combination that has worked the most historically.
    pub fn best_technique_for_class(
        &self,
        vulnerability_class: &str,
    ) -> Result<Option<(String, Option<String>)>, MemoryStoreError> {
        let result: Result<(String, Option<String>), _> = self.conn.query_row(
            "SELECT payload_type, evasion_used
             FROM technique_outcomes
             WHERE vulnerability_class = ?1 AND success = 1
             GROUP BY payload_type, evasion_used
             ORDER BY COUNT(*) DESC
             LIMIT 1",
            params![vulnerability_class],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );
        match result {
            Ok(pair) => Ok(Some(pair)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
#[path = "agent_memory_store_test.rs"]
mod agent_memory_store_test;
