#[cfg(test)]
mod tests {
    use crate::scan_persistence::*;

    fn test_checkpoint(scan_id: &str) -> PersistentCheckpoint {
        PersistentCheckpoint {
            scan_id: scan_id.to_string(),
            target: "http://localhost:8080".to_string(),
            phase: "fuzz".to_string(),
            iteration: 2,
            total_findings: 5,
            total_operations: 100,
            timestamp_ms: 1700000000000,
            completed_endpoints: vec!["/api/users".to_string(), "/api/login".to_string()],
        }
    }

    fn test_finding(scan_id: &str, id: u64, endpoint: &str) -> PersistedFinding {
        PersistedFinding {
            scan_id: scan_id.to_string(),
            finding_id: id,
            vulnerability_class: "SqlInjection".to_string(),
            endpoint: endpoint.to_string(),
            severity: 8.0,
            confidence: 0.85,
            first_seen_ms: 1700000000000,
            last_seen_ms: 1700000000000,
        }
    }

    #[test]
    fn open_in_memory() {
        let db = ScanPersistence::in_memory();
        assert!(db.is_ok());
    }

    #[test]
    fn save_and_load_checkpoint() {
        let db = ScanPersistence::in_memory().unwrap();
        let cp = test_checkpoint("scan-001");
        db.save_checkpoint(&cp).unwrap();

        let loaded = db.load_checkpoint("scan-001").unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.scan_id, "scan-001");
        assert_eq!(loaded.phase, "fuzz");
        assert_eq!(loaded.iteration, 2);
        assert_eq!(loaded.total_findings, 5);
        assert_eq!(loaded.completed_endpoints.len(), 2);
    }

    #[test]
    fn load_nonexistent_checkpoint_returns_none() {
        let db = ScanPersistence::in_memory().unwrap();
        let loaded = db.load_checkpoint("no-such-scan").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn delete_checkpoint() {
        let db = ScanPersistence::in_memory().unwrap();
        db.save_checkpoint(&test_checkpoint("scan-001")).unwrap();
        db.delete_checkpoint("scan-001").unwrap();
        assert!(db.load_checkpoint("scan-001").unwrap().is_none());
    }

    #[test]
    fn save_and_load_findings() {
        let db = ScanPersistence::in_memory().unwrap();
        db.save_finding(&test_finding("scan-001", 1, "/api/users"))
            .unwrap();
        db.save_finding(&test_finding("scan-001", 2, "/api/login"))
            .unwrap();
        let findings = db.load_findings("scan-001").unwrap();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn save_and_load_endpoints() {
        let db = ScanPersistence::in_memory().unwrap();
        db.save_endpoint("scan-001", "/api/users", "GET", 1700000000000)
            .unwrap();
        db.save_endpoint("scan-001", "/api/login", "POST", 1700000000000)
            .unwrap();
        let eps = db.load_endpoints("scan-001").unwrap();
        assert_eq!(eps.len(), 2);
    }

    #[test]
    fn diff_scans_new_findings() {
        let db = ScanPersistence::in_memory().unwrap();
        db.save_finding(&test_finding("scan-001", 1, "/api/users"))
            .unwrap();
        db.save_finding(&test_finding("scan-002", 1, "/api/users"))
            .unwrap();
        db.save_finding(&test_finding("scan-002", 2, "/api/admin"))
            .unwrap();

        let diff = db.diff_scans("scan-001", "scan-002").unwrap();
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.unchanged_findings.len(), 1);
        assert!(diff.resolved_findings.is_empty());
    }

    #[test]
    fn diff_scans_resolved_findings() {
        let db = ScanPersistence::in_memory().unwrap();
        db.save_finding(&test_finding("scan-001", 1, "/api/users"))
            .unwrap();
        db.save_finding(&test_finding("scan-001", 2, "/api/old"))
            .unwrap();
        db.save_finding(&test_finding("scan-002", 1, "/api/users"))
            .unwrap();

        let diff = db.diff_scans("scan-001", "scan-002").unwrap();
        assert_eq!(diff.resolved_findings.len(), 1);
        assert_eq!(diff.resolved_findings[0].endpoint, "/api/old");
    }

    #[test]
    fn diff_scans_endpoint_changes() {
        let db = ScanPersistence::in_memory().unwrap();
        db.save_endpoint("scan-001", "/api/users", "GET", 100)
            .unwrap();
        db.save_endpoint("scan-001", "/api/old", "GET", 100)
            .unwrap();
        db.save_endpoint("scan-002", "/api/users", "GET", 200)
            .unwrap();
        db.save_endpoint("scan-002", "/api/new", "GET", 200)
            .unwrap();

        let diff = db.diff_scans("scan-001", "scan-002").unwrap();
        assert!(diff.new_endpoints.contains(&"/api/new".to_string()));
        assert!(diff.removed_endpoints.contains(&"/api/old".to_string()));
    }

    #[test]
    fn stale_endpoints() {
        let db = ScanPersistence::in_memory().unwrap();
        db.save_endpoint("scan-001", "/old", "GET", 100).unwrap();
        db.save_endpoint("scan-001", "/new", "GET", 500).unwrap();
        let stale = db.stale_endpoints("scan-001", 300).unwrap();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0], "/old");
    }

    #[test]
    fn checkpoint_upsert() {
        let db = ScanPersistence::in_memory().unwrap();
        let mut cp = test_checkpoint("scan-001");
        db.save_checkpoint(&cp).unwrap();
        cp.iteration = 5;
        cp.total_findings = 20;
        db.save_checkpoint(&cp).unwrap();
        let loaded = db.load_checkpoint("scan-001").unwrap().unwrap();
        assert_eq!(loaded.iteration, 5);
        assert_eq!(loaded.total_findings, 20);
    }
}
