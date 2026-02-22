#[cfg(test)]
mod tests {
    use aegis_protocol::finding::VulnerabilityClass;

    use crate::scan_history::{ScanHistoryDb, ScanHistoryEntry};

    fn sample_entry(endpoint: &str, class: VulnerabilityClass, is_tp: bool) -> ScanHistoryEntry {
        ScanHistoryEntry {
            endpoint_pattern: endpoint.to_string(),
            vulnerability_class: class,
            payload: "' OR 1=1 --".to_string(),
            anomaly_score: 0.85,
            is_true_positive: is_tp,
            timestamp_unix_ms: 1_700_000_000_000,
            target_app_hash: "abc123".to_string(),
        }
    }

    #[test]
    fn open_in_memory_creates_table() {
        let db = ScanHistoryDb::open_in_memory().unwrap();
        assert_eq!(db.total_records().unwrap(), 0);
    }

    #[test]
    fn insert_and_retrieve_single_record() {
        let db = ScanHistoryDb::open_in_memory().unwrap();
        let entry = sample_entry("/api/users", VulnerabilityClass::SqlInjection, true);
        let row_id = db.insert(&entry).unwrap();
        assert_eq!(row_id, 1);

        let records = db.query_by_endpoint("/api/users").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, 1);
        assert_eq!(records[0].endpoint_pattern, "/api/users");
        assert_eq!(
            records[0].vulnerability_class,
            VulnerabilityClass::SqlInjection
        );
        assert!(records[0].is_true_positive);
        assert_eq!(records[0].anomaly_score, 0.85);
        assert_eq!(records[0].timestamp_unix_ms, 1_700_000_000_000);
        assert_eq!(records[0].target_app_hash, "abc123");
    }

    #[test]
    fn insert_batch_and_count() {
        let db = ScanHistoryDb::open_in_memory().unwrap();
        let entries = vec![
            sample_entry("/api/a", VulnerabilityClass::SqlInjection, true),
            sample_entry("/api/b", VulnerabilityClass::CrossSiteScripting, false),
            sample_entry("/api/c", VulnerabilityClass::CommandInjection, true),
        ];
        let count = db.insert_batch(&entries).unwrap();
        assert_eq!(count, 3);
        assert_eq!(db.total_records().unwrap(), 3);
    }

    #[test]
    fn query_by_endpoint_pattern() {
        let db = ScanHistoryDb::open_in_memory().unwrap();
        db.insert(&sample_entry(
            "/api/users",
            VulnerabilityClass::SqlInjection,
            true,
        ))
        .unwrap();
        db.insert(&sample_entry(
            "/api/users",
            VulnerabilityClass::CrossSiteScripting,
            false,
        ))
        .unwrap();
        db.insert(&sample_entry(
            "/api/admin",
            VulnerabilityClass::SqlInjection,
            true,
        ))
        .unwrap();

        let users = db.query_by_endpoint("/api/users").unwrap();
        assert_eq!(users.len(), 2);

        let admin = db.query_by_endpoint("/api/admin").unwrap();
        assert_eq!(admin.len(), 1);

        let none = db.query_by_endpoint("/api/nonexistent").unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn query_by_vulnerability_class() {
        let db = ScanHistoryDb::open_in_memory().unwrap();
        db.insert(&sample_entry("/a", VulnerabilityClass::SqlInjection, true))
            .unwrap();
        db.insert(&sample_entry("/b", VulnerabilityClass::SqlInjection, false))
            .unwrap();
        db.insert(&sample_entry("/c", VulnerabilityClass::PathTraversal, true))
            .unwrap();

        let sqli = db.query_by_class(VulnerabilityClass::SqlInjection).unwrap();
        assert_eq!(sqli.len(), 2);

        let pt = db
            .query_by_class(VulnerabilityClass::PathTraversal)
            .unwrap();
        assert_eq!(pt.len(), 1);
    }

    #[test]
    fn success_rate_mixed_tp_and_fp() {
        let db = ScanHistoryDb::open_in_memory().unwrap();
        db.insert(&sample_entry("/a", VulnerabilityClass::SqlInjection, true))
            .unwrap();
        db.insert(&sample_entry("/b", VulnerabilityClass::SqlInjection, true))
            .unwrap();
        db.insert(&sample_entry("/c", VulnerabilityClass::SqlInjection, false))
            .unwrap();
        db.insert(&sample_entry("/d", VulnerabilityClass::SqlInjection, false))
            .unwrap();

        let rate = db
            .success_rate_by_class(VulnerabilityClass::SqlInjection)
            .unwrap();
        assert!((rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn success_rate_no_records_returns_zero() {
        let db = ScanHistoryDb::open_in_memory().unwrap();
        let rate = db
            .success_rate_by_class(VulnerabilityClass::CommandInjection)
            .unwrap();
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn total_records_count() {
        let db = ScanHistoryDb::open_in_memory().unwrap();
        assert_eq!(db.total_records().unwrap(), 0);
        db.insert(&sample_entry("/a", VulnerabilityClass::SqlInjection, true))
            .unwrap();
        assert_eq!(db.total_records().unwrap(), 1);
        db.insert(&sample_entry(
            "/b",
            VulnerabilityClass::CrossSiteScripting,
            false,
        ))
        .unwrap();
        assert_eq!(db.total_records().unwrap(), 2);
    }

    #[test]
    fn multiple_inserts_produce_unique_ids() {
        let db = ScanHistoryDb::open_in_memory().unwrap();
        let id1 = db
            .insert(&sample_entry("/a", VulnerabilityClass::SqlInjection, true))
            .unwrap();
        let id2 = db
            .insert(&sample_entry("/b", VulnerabilityClass::SqlInjection, true))
            .unwrap();
        let id3 = db
            .insert(&sample_entry("/c", VulnerabilityClass::SqlInjection, true))
            .unwrap();
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[test]
    fn all_vulnerability_classes_round_trip() {
        let db = ScanHistoryDb::open_in_memory().unwrap();
        let classes = [
            VulnerabilityClass::SqlInjection,
            VulnerabilityClass::CrossSiteScripting,
            VulnerabilityClass::CommandInjection,
            VulnerabilityClass::PathTraversal,
            VulnerabilityClass::ServerSideRequestForgery,
            VulnerabilityClass::InsecureDeserialization,
            VulnerabilityClass::BrokenAuthentication,
            VulnerabilityClass::BrokenAuthorization,
            VulnerabilityClass::SecurityMisconfiguration,
            VulnerabilityClass::SensitiveDataExposure,
            VulnerabilityClass::ServerSideTemplateInjection,
            VulnerabilityClass::HeaderInjection,
            VulnerabilityClass::OpenRedirect,
            VulnerabilityClass::CrlfInjection,
            VulnerabilityClass::KnownVulnerableDependency,
            VulnerabilityClass::InsufficientInputValidation,
        ];
        for class in classes {
            db.insert(&sample_entry("/rt", class, true)).unwrap();
        }
        let records = db.query_by_endpoint("/rt").unwrap();
        assert_eq!(records.len(), 16);
        for (record, expected) in records.iter().zip(classes.iter()) {
            assert_eq!(record.vulnerability_class, *expected);
        }
    }

    #[test]
    fn error_display_is_descriptive() {
        use crate::scan_history::ScanHistoryError;

        let err = ScanHistoryError::DatabaseError("connection failed".to_string());
        assert!(err.to_string().contains("database error"));
        assert!(err.to_string().contains("connection failed"));

        let err = ScanHistoryError::QueryError("bad query".to_string());
        assert!(err.to_string().contains("query error"));
        assert!(err.to_string().contains("bad query"));
    }

    fn entry_with_payload(
        endpoint: &str,
        class: VulnerabilityClass,
        payload: &str,
        is_tp: bool,
    ) -> ScanHistoryEntry {
        ScanHistoryEntry {
            endpoint_pattern: endpoint.to_string(),
            vulnerability_class: class,
            payload: payload.to_string(),
            anomaly_score: 0.85,
            is_true_positive: is_tp,
            timestamp_unix_ms: 1_700_000_000_000,
            target_app_hash: "abc123".to_string(),
        }
    }

    #[test]
    fn payload_stats_for_aggregates_correctly() {
        let db = ScanHistoryDb::open_in_memory().unwrap();
        let ep = "/api/users";
        let class = VulnerabilityClass::SqlInjection;
        db.insert(&entry_with_payload(ep, class, "' OR 1=1--", true))
            .unwrap();
        db.insert(&entry_with_payload(ep, class, "' OR 1=1--", false))
            .unwrap();
        db.insert(&entry_with_payload(ep, class, "' OR 1=1--", true))
            .unwrap();
        db.insert(&entry_with_payload(
            ep,
            class,
            "1 UNION SELECT null--",
            true,
        ))
        .unwrap();
        db.insert(&entry_with_payload(
            ep,
            class,
            "1 UNION SELECT null--",
            false,
        ))
        .unwrap();

        let stats = db.payload_stats_for(ep, class).unwrap();
        assert_eq!(stats.len(), 2);

        let or_payload = stats.iter().find(|s| s.payload == "' OR 1=1--").unwrap();
        assert_eq!(or_payload.attempts, 3);
        assert_eq!(or_payload.successes, 2);

        let union_payload = stats
            .iter()
            .find(|s| s.payload == "1 UNION SELECT null--")
            .unwrap();
        assert_eq!(union_payload.attempts, 2);
        assert_eq!(union_payload.successes, 1);
    }

    #[test]
    fn payload_stats_for_empty_returns_empty() {
        let db = ScanHistoryDb::open_in_memory().unwrap();
        let stats = db
            .payload_stats_for("/api/nonexistent", VulnerabilityClass::SqlInjection)
            .unwrap();
        assert!(stats.is_empty());
    }

    #[test]
    fn payload_stats_for_filters_by_class_and_endpoint() {
        let db = ScanHistoryDb::open_in_memory().unwrap();
        db.insert(&entry_with_payload(
            "/api/users",
            VulnerabilityClass::SqlInjection,
            "sqli-payload",
            true,
        ))
        .unwrap();
        db.insert(&entry_with_payload(
            "/api/users",
            VulnerabilityClass::CrossSiteScripting,
            "xss-payload",
            true,
        ))
        .unwrap();
        db.insert(&entry_with_payload(
            "/api/admin",
            VulnerabilityClass::SqlInjection,
            "admin-sqli",
            true,
        ))
        .unwrap();

        let stats = db
            .payload_stats_for("/api/users", VulnerabilityClass::SqlInjection)
            .unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].payload, "sqli-payload");
        assert_eq!(stats[0].attempts, 1);
        assert_eq!(stats[0].successes, 1);
    }

    #[test]
    fn open_file_based_database() {
        let dir = std::env::temp_dir().join("aegis-scan-history-test");
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join(format!("test-{}.db", std::process::id()));

        {
            let db = ScanHistoryDb::open(&db_path).unwrap();
            db.insert(&sample_entry(
                "/api/a",
                VulnerabilityClass::SqlInjection,
                true,
            ))
            .unwrap();
            assert_eq!(db.total_records().unwrap(), 1);
        }

        {
            let db = ScanHistoryDb::open(&db_path).unwrap();
            assert_eq!(db.total_records().unwrap(), 1);
        }

        std::fs::remove_file(&db_path).ok();
    }

    #[test]
    fn success_rates_all_classes_returns_all_with_records() {
        let db = ScanHistoryDb::open_in_memory().unwrap();
        db.insert(&sample_entry("/a", VulnerabilityClass::SqlInjection, true))
            .unwrap();
        db.insert(&sample_entry("/b", VulnerabilityClass::SqlInjection, false))
            .unwrap();
        db.insert(&sample_entry("/c", VulnerabilityClass::PathTraversal, true))
            .unwrap();

        let rates = db.success_rates_all_classes().unwrap();
        assert_eq!(rates.len(), 2);
        assert!((rates["SQL Injection"] - 0.5).abs() < f64::EPSILON);
        assert!((rates["Path Traversal"] - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn success_rates_all_classes_empty_db_returns_empty() {
        let db = ScanHistoryDb::open_in_memory().unwrap();
        let rates = db.success_rates_all_classes().unwrap();
        assert!(rates.is_empty());
    }

    #[test]
    fn success_rates_all_classes_omits_zero_total() {
        let db = ScanHistoryDb::open_in_memory().unwrap();
        db.insert(&sample_entry(
            "/a",
            VulnerabilityClass::CrossSiteScripting,
            true,
        ))
        .unwrap();
        let rates = db.success_rates_all_classes().unwrap();
        assert_eq!(rates.len(), 1);
        assert!(rates.contains_key("Cross-Site Scripting"));
        assert!(!rates.contains_key("SQL Injection"));
    }
}
