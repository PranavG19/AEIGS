use super::*;

fn now_ms() -> u64 {
    1700000000000
}

fn make_technique(class: &str, payload: &str, success: bool) -> TechniqueMemory {
    TechniqueMemory {
        id: None,
        vulnerability_class: class.to_string(),
        endpoint_pattern: "/api/test".to_string(),
        payload_type: payload.to_string(),
        evasion_technique: None,
        success,
        tech_stack: vec!["Express".to_string(), "Node.js".to_string()],
        defense_stack: vec![],
        confidence: 0.8,
        session_id: "session-001".to_string(),
        target_url: "http://127.0.0.1:3000".to_string(),
        timestamp_ms: now_ms(),
    }
}

fn make_bypass(vendor: &str, technique: &str, success: bool) -> WafBypassMemory {
    WafBypassMemory {
        id: None,
        waf_vendor: vendor.to_string(),
        bypass_technique: technique.to_string(),
        payload_mutation: "double-encoding".to_string(),
        vulnerability_class: "SQL Injection".to_string(),
        success,
        session_id: "session-001".to_string(),
        timestamp_ms: now_ms(),
    }
}

fn make_profile(url: &str, session: &str, findings: u32) -> TargetProfile {
    TargetProfile {
        id: None,
        target_url: url.to_string(),
        tech_stack_json: serde_json::to_string(&vec!["Express", "Node.js"]).unwrap(),
        total_findings: findings,
        highest_severity: 9.8,
        session_id: session.to_string(),
        timestamp_ms: now_ms(),
    }
}

#[test]
fn open_in_memory_creates_schema() {
    let db = AgentMemoryDb::open_in_memory().unwrap();
    assert_eq!(db.total_techniques().unwrap(), 0);
    assert_eq!(db.total_bypasses().unwrap(), 0);
    assert_eq!(db.total_profiles().unwrap(), 0);
}

#[test]
fn store_and_retrieve_technique() {
    let db = AgentMemoryDb::open_in_memory().unwrap();
    let tech = make_technique("SQL Injection", "union-based", true);
    let id = db.store_technique(&tech).unwrap();
    assert!(id > 0);
    assert_eq!(db.total_techniques().unwrap(), 1);
}

#[test]
fn successful_techniques_returns_only_successes() {
    let db = AgentMemoryDb::open_in_memory().unwrap();
    db.store_technique(&make_technique("SQL Injection", "union", true))
        .unwrap();
    db.store_technique(&make_technique("SQL Injection", "blind", false))
        .unwrap();
    db.store_technique(&make_technique("XSS", "reflected", true))
        .unwrap();

    let results = db
        .successful_techniques_for_class("SQL Injection", now_ms())
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0.payload_type, "union");
    assert!(results[0].1 > 0.9); // very recent, decay near 1.0
}

#[test]
fn failed_techniques_returns_only_failures() {
    let db = AgentMemoryDb::open_in_memory().unwrap();
    db.store_technique(&make_technique("SQL Injection", "union", true))
        .unwrap();
    db.store_technique(&make_technique("SQL Injection", "blind", false))
        .unwrap();

    let results = db.failed_techniques_for_class("SQL Injection").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].payload_type, "blind");
    assert!(!results[0].success);
}

#[test]
fn store_and_retrieve_bypass() {
    let db = AgentMemoryDb::open_in_memory().unwrap();
    db.store_bypass(&make_bypass("Cloudflare", "unicode-normalization", true))
        .unwrap();
    db.store_bypass(&make_bypass("Cloudflare", "chunked-encoding", false))
        .unwrap();
    db.store_bypass(&make_bypass("ModSecurity", "double-encoding", true))
        .unwrap();

    let cf_bypasses = db.successful_bypasses_for_vendor("Cloudflare").unwrap();
    assert_eq!(cf_bypasses.len(), 1);
    assert_eq!(cf_bypasses[0].bypass_technique, "unicode-normalization");

    let ms_bypasses = db.successful_bypasses_for_vendor("ModSecurity").unwrap();
    assert_eq!(ms_bypasses.len(), 1);
}

#[test]
fn store_target_profile() {
    let db = AgentMemoryDb::open_in_memory().unwrap();
    db.store_target_profile(&make_profile("http://127.0.0.1:3000", "sess-001", 5))
        .unwrap();
    assert_eq!(db.total_profiles().unwrap(), 1);
}

#[test]
fn load_learnings_for_matching_stack() {
    let db = AgentMemoryDb::open_in_memory().unwrap();
    let stack = vec!["Express".to_string(), "Node.js".to_string()];

    // Store enough technique outcomes for aggregation
    for _ in 0..3 {
        db.store_technique(&make_technique("SQL Injection", "union", true))
            .unwrap();
    }
    for _ in 0..2 {
        db.store_technique(&make_technique("SQL Injection", "blind", false))
            .unwrap();
    }
    db.store_technique(&make_technique("XSS", "reflected", true))
        .unwrap();

    db.store_target_profile(&make_profile("http://127.0.0.1:3000", "sess-001", 3))
        .unwrap();

    let learnings = db.load_learnings_for_stack(&stack).unwrap();
    assert_eq!(learnings.total_sessions, 1);
    assert!(!learnings.top_vulnerability_classes.is_empty());
}

#[test]
fn decayed_success_rate_recent_records() {
    let db = AgentMemoryDb::open_in_memory().unwrap();
    db.store_technique(&make_technique("XSS", "reflected", true))
        .unwrap();
    db.store_technique(&make_technique("XSS", "stored", false))
        .unwrap();

    let rate = db.decayed_success_rate("XSS", now_ms()).unwrap();
    assert_eq!(rate.total_attempts, 2);
    assert_eq!(rate.successes, 1);
    assert!((rate.raw_success_rate - 0.5).abs() < 0.01);
    // Recent records, so decayed_score should be close to raw
    assert!((rate.decayed_score - 0.5).abs() < 0.1);
}

#[test]
fn decayed_success_rate_empty_class() {
    let db = AgentMemoryDb::open_in_memory().unwrap();
    let rate = db.decayed_success_rate("SSRF", now_ms()).unwrap();
    assert_eq!(rate.total_attempts, 0);
    assert_eq!(rate.decayed_score, 0.0);
}

#[test]
fn decay_old_records_have_lower_weight() {
    let db = AgentMemoryDb::open_in_memory().unwrap();
    let now = now_ms();
    let seven_days_ago = now - (7 * 24 * 3600 * 1000);
    let thirty_days_ago = now - (30 * 24 * 3600 * 1000);

    // Recent success
    let mut recent = make_technique("SSTI", "polyglot", true);
    recent.timestamp_ms = now;
    db.store_technique(&recent).unwrap();

    // Old success
    let mut old = make_technique("SSTI", "jinja2", true);
    old.timestamp_ms = seven_days_ago;
    db.store_technique(&old).unwrap();

    // Very old failure
    let mut very_old = make_technique("SSTI", "freemarker", false);
    very_old.timestamp_ms = thirty_days_ago;
    db.store_technique(&very_old).unwrap();

    let results = db.successful_techniques_for_class("SSTI", now).unwrap();

    assert_eq!(results.len(), 2);
    // Most recent should have highest decay weight
    let (recent_mem, recent_decay) = &results[0];
    let (old_mem, old_decay) = &results[1];
    assert_eq!(recent_mem.payload_type, "polyglot");
    assert!(recent_decay > old_decay);
    assert!(*recent_decay > 0.99);
    assert!(*old_decay < 0.6); // ~7 day half-life means ~0.5 at 7 days
}

#[test]
fn compute_decay_at_zero_age_is_one() {
    let now = 1700000000000u64;
    assert!((compute_decay(now, now) - 1.0).abs() < 0.001);
}

#[test]
fn compute_decay_at_half_life_is_half() {
    let now = 1700000000000u64;
    let half_life_ago = now - DECAY_HALF_LIFE_MS as u64;
    let decay = compute_decay(now, half_life_ago);
    assert!(
        (decay - 0.5).abs() < 0.01,
        "decay at half-life should be ~0.5, got {decay}"
    );
}

#[test]
fn compute_decay_very_old_approaches_zero() {
    let now = 1700000000000u64;
    let year_ago = now - (365 * 24 * 3600 * 1000);
    let decay = compute_decay(now, year_ago);
    assert!(
        decay < 0.001,
        "year-old memory should have near-zero weight"
    );
}

#[test]
fn purge_removes_old_records() {
    let db = AgentMemoryDb::open_in_memory().unwrap();
    let now = now_ms();
    let old_ts = now - (90 * 24 * 3600 * 1000);

    let mut old_tech = make_technique("XSS", "old", true);
    old_tech.timestamp_ms = old_ts;
    db.store_technique(&old_tech).unwrap();

    let mut new_tech = make_technique("XSS", "new", true);
    new_tech.timestamp_ms = now;
    db.store_technique(&new_tech).unwrap();

    let mut old_bypass = make_bypass("CF", "old-bypass", true);
    old_bypass.timestamp_ms = old_ts;
    db.store_bypass(&old_bypass).unwrap();

    assert_eq!(db.total_techniques().unwrap(), 2);
    assert_eq!(db.total_bypasses().unwrap(), 1);

    let cutoff = now - (30 * 24 * 3600 * 1000);
    let purged = db.purge_older_than(cutoff).unwrap();
    assert_eq!(purged, 2); // 1 technique + 1 bypass

    assert_eq!(db.total_techniques().unwrap(), 1);
    assert_eq!(db.total_bypasses().unwrap(), 0);
}

#[test]
fn technique_memory_serde_roundtrip() {
    let mem = make_technique("SQL Injection", "union", true);
    let json = serde_json::to_string(&mem).unwrap();
    let parsed: TechniqueMemory = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.vulnerability_class, "SQL Injection");
    assert!(parsed.success);
}

#[test]
fn waf_bypass_memory_serde_roundtrip() {
    let mem = make_bypass("Cloudflare", "unicode", true);
    let json = serde_json::to_string(&mem).unwrap();
    let parsed: WafBypassMemory = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.waf_vendor, "Cloudflare");
}

#[test]
fn memory_db_error_display() {
    let err = MemoryDbError::Database("test error".to_string());
    assert!(err.to_string().contains("test error"));

    let err = MemoryDbError::Serialization("bad json".to_string());
    assert!(err.to_string().contains("bad json"));
}

#[test]
fn open_file_based_db() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("memory.db");
    let db = AgentMemoryDb::open(&db_path).unwrap();
    db.store_technique(&make_technique("XSS", "reflected", true))
        .unwrap();
    assert_eq!(db.total_techniques().unwrap(), 1);

    // Reopen and verify persistence
    drop(db);
    let db2 = AgentMemoryDb::open(&db_path).unwrap();
    assert_eq!(db2.total_techniques().unwrap(), 1);
}
