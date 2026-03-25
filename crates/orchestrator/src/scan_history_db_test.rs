#[cfg(test)]
mod tests {
    use crate::scan_history_db::{
        EndpointHistory, PersistentScanHistoryDb, RetentionPolicy, StoredFinding, StoredScanResult,
        VulnClassHistory,
    };

    fn sample_scan(id: &str, target: &str, ts: u64, findings: u32) -> StoredScanResult {
        StoredScanResult {
            scan_id: id.to_string(),
            target_url: target.to_string(),
            started_at_ms: ts,
            completed_at_ms: ts + 60_000,
            total_findings: findings,
            critical_count: 1,
            high_count: 2,
            medium_count: findings.saturating_sub(3),
            low_count: 0,
            info_count: 0,
            scan_mode: "full".to_string(),
            duration_ms: 60_000,
        }
    }

    fn sample_finding(id: &str, scan_id: &str, endpoint: &str, class: &str) -> StoredFinding {
        StoredFinding {
            finding_id: id.to_string(),
            scan_id: scan_id.to_string(),
            endpoint: endpoint.to_string(),
            vulnerability_class: class.to_string(),
            severity: "high".to_string(),
            score: 8.5,
            title: format!("{class} in {endpoint}"),
            fingerprint: format!("{endpoint}:{class}"),
            first_seen_ms: 1_000_000,
            last_seen_ms: 2_000_000,
            resolved_at_ms: None,
        }
    }

    #[test]
    fn open_in_memory_creates_tables() {
        let db = PersistentScanHistoryDb::open_in_memory().unwrap();
        assert_eq!(db.total_scans().unwrap(), 0);
        assert_eq!(db.total_findings().unwrap(), 0);
    }

    #[test]
    fn store_and_list_scans() {
        let db = PersistentScanHistoryDb::open_in_memory().unwrap();
        db.store_scan(&sample_scan("s1", "http://example.com", 1000, 5))
            .unwrap();
        db.store_scan(&sample_scan("s2", "http://example.com", 2000, 3))
            .unwrap();

        let scans = db.list_scans(10).unwrap();
        assert_eq!(scans.len(), 2);
        assert_eq!(scans[0].scan_id, "s2"); // newest first
        assert_eq!(scans[1].scan_id, "s1");
    }

    #[test]
    fn store_and_query_findings_for_scan() {
        let db = PersistentScanHistoryDb::open_in_memory().unwrap();
        db.store_scan(&sample_scan("s1", "http://example.com", 1000, 2))
            .unwrap();
        db.store_finding(&sample_finding("f1", "s1", "/api/users", "SQL Injection"))
            .unwrap();
        db.store_finding(&sample_finding("f2", "s1", "/api/admin", "XSS"))
            .unwrap();

        let findings = db.findings_for_scan("s1").unwrap();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn store_findings_batch() {
        let db = PersistentScanHistoryDb::open_in_memory().unwrap();
        db.store_scan(&sample_scan("s1", "http://example.com", 1000, 3))
            .unwrap();
        let findings = vec![
            sample_finding("f1", "s1", "/api/a", "SQLi"),
            sample_finding("f2", "s1", "/api/b", "XSS"),
            sample_finding("f3", "s1", "/api/c", "CMDi"),
        ];
        let count = db.store_findings_batch(&findings).unwrap();
        assert_eq!(count, 3);
        assert_eq!(db.total_findings().unwrap(), 3);
    }

    #[test]
    fn trend_for_target() {
        let db = PersistentScanHistoryDb::open_in_memory().unwrap();
        db.store_scan(&sample_scan("s1", "http://example.com", 1000, 10))
            .unwrap();
        db.store_scan(&sample_scan("s2", "http://example.com", 2000, 7))
            .unwrap();
        db.store_scan(&sample_scan("s3", "http://example.com", 3000, 3))
            .unwrap();
        db.store_scan(&sample_scan("other", "http://other.com", 1500, 5))
            .unwrap();

        let trend = db.trend_for_target("http://example.com").unwrap();
        assert_eq!(trend.len(), 3);
        assert_eq!(trend[0].total_findings, 10);
        assert_eq!(trend[1].total_findings, 7);
        assert_eq!(trend[2].total_findings, 3);
    }

    #[test]
    fn endpoint_history_aggregation() {
        let db = PersistentScanHistoryDb::open_in_memory().unwrap();
        db.store_scan(&sample_scan("s1", "http://example.com", 1000, 3))
            .unwrap();
        db.store_finding(&sample_finding("f1", "s1", "/api/users", "SQLi"))
            .unwrap();
        db.store_finding(&sample_finding("f2", "s1", "/api/users", "XSS"))
            .unwrap();
        db.store_finding(&sample_finding("f3", "s1", "/api/admin", "CMDi"))
            .unwrap();

        let history = db.endpoint_history().unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].endpoint, "/api/users"); // most findings
        assert_eq!(history[0].total_findings_ever, 2);
        assert_eq!(history[1].endpoint, "/api/admin");
    }

    #[test]
    fn vuln_class_history_aggregation() {
        let db = PersistentScanHistoryDb::open_in_memory().unwrap();
        db.store_scan(&sample_scan("s1", "http://example.com", 1000, 3))
            .unwrap();
        db.store_finding(&sample_finding("f1", "s1", "/a", "SQL Injection"))
            .unwrap();
        db.store_finding(&sample_finding("f2", "s1", "/b", "SQL Injection"))
            .unwrap();
        db.store_finding(&sample_finding("f3", "s1", "/c", "XSS"))
            .unwrap();

        let history = db.vuln_class_history().unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].vulnerability_class, "SQL Injection");
        assert_eq!(history[0].total_occurrences, 2);
    }

    #[test]
    fn findings_for_endpoint_query() {
        let db = PersistentScanHistoryDb::open_in_memory().unwrap();
        db.store_scan(&sample_scan("s1", "http://example.com", 1000, 2))
            .unwrap();
        db.store_finding(&sample_finding("f1", "s1", "/api/users", "SQLi"))
            .unwrap();
        db.store_finding(&sample_finding("f2", "s1", "/api/admin", "XSS"))
            .unwrap();

        let findings = db.findings_for_endpoint("/api/users").unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].endpoint, "/api/users");
    }

    #[test]
    fn findings_for_class_query() {
        let db = PersistentScanHistoryDb::open_in_memory().unwrap();
        db.store_scan(&sample_scan("s1", "http://example.com", 1000, 2))
            .unwrap();
        db.store_finding(&sample_finding("f1", "s1", "/a", "SQL Injection"))
            .unwrap();
        db.store_finding(&sample_finding("f2", "s1", "/b", "XSS"))
            .unwrap();

        let findings = db.findings_for_class("SQL Injection").unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].vulnerability_class, "SQL Injection");
    }

    #[test]
    fn retention_policy_max_age() {
        let db = PersistentScanHistoryDb::open_in_memory().unwrap();
        let now = 100_000_000_000u64;
        let old_ts = now - 400 * 86_400_000; // 400 days ago
        db.store_scan(&sample_scan("old", "http://example.com", old_ts, 1))
            .unwrap();
        db.store_scan(&sample_scan("recent", "http://example.com", now - 1000, 1))
            .unwrap();
        db.store_finding(&sample_finding("f-old", "old", "/a", "SQLi"))
            .unwrap();
        db.store_finding(&sample_finding("f-recent", "recent", "/b", "XSS"))
            .unwrap();

        let policy = RetentionPolicy {
            max_scans: None,
            max_age_days: Some(365),
        };
        let deleted = db.apply_retention(&policy, now).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(db.total_scans().unwrap(), 1);
        assert_eq!(db.total_findings().unwrap(), 1);
    }

    #[test]
    fn retention_policy_max_scans() {
        let db = PersistentScanHistoryDb::open_in_memory().unwrap();
        for i in 0..5 {
            db.store_scan(&sample_scan(
                &format!("s{i}"),
                "http://example.com",
                (i as u64 + 1) * 1000,
                1,
            ))
            .unwrap();
        }
        assert_eq!(db.total_scans().unwrap(), 5);

        let policy = RetentionPolicy {
            max_scans: Some(3),
            max_age_days: None,
        };
        let deleted = db.apply_retention(&policy, 100_000).unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(db.total_scans().unwrap(), 3);
    }

    #[test]
    fn resolved_findings_tracked() {
        let db = PersistentScanHistoryDb::open_in_memory().unwrap();
        db.store_scan(&sample_scan("s1", "http://example.com", 1000, 1))
            .unwrap();
        let mut finding = sample_finding("f1", "s1", "/api", "SQLi");
        finding.resolved_at_ms = Some(5_000_000);
        db.store_finding(&finding).unwrap();

        let results = db.findings_for_scan("s1").unwrap();
        assert_eq!(results[0].resolved_at_ms, Some(5_000_000));

        let history = db.endpoint_history().unwrap();
        assert_eq!(history[0].resolved_findings, 1);
        assert_eq!(history[0].active_findings, 0);
    }

    #[test]
    fn list_scans_respects_limit() {
        let db = PersistentScanHistoryDb::open_in_memory().unwrap();
        for i in 0..10 {
            db.store_scan(&sample_scan(
                &format!("s{i}"),
                "http://example.com",
                (i as u64) * 1000,
                1,
            ))
            .unwrap();
        }
        let scans = db.list_scans(3).unwrap();
        assert_eq!(scans.len(), 3);
    }

    #[test]
    fn scan_upsert_replaces() {
        let db = PersistentScanHistoryDb::open_in_memory().unwrap();
        db.store_scan(&sample_scan("s1", "http://example.com", 1000, 5))
            .unwrap();
        db.store_scan(&sample_scan("s1", "http://example.com", 1000, 10))
            .unwrap();
        assert_eq!(db.total_scans().unwrap(), 1);
        let scans = db.list_scans(10).unwrap();
        assert_eq!(scans[0].total_findings, 10);
    }

    #[test]
    fn default_retention_policy() {
        let policy = RetentionPolicy::default();
        assert_eq!(policy.max_scans, Some(1000));
        assert_eq!(policy.max_age_days, Some(365));
    }
}
