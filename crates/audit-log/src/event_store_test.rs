#[cfg(test)]
mod tests {
    use crate::event_store::{
        EventQuery, EventStoreError, ScanSnapshot, classify_event, compute_scan_timeline,
        diff_snapshots, filter_entries, replay_from_entries,
    };
    use aegis_protocol::audit::{AuditEntry, AuditEventType};
    use aegis_protocol::finding::VulnerabilityClass;
    use aegis_protocol::operation::ModuleIdentifier;

    fn make_entry(seq: u64, timestamp_ms: u64, event: AuditEventType) -> AuditEntry {
        AuditEntry {
            sequence_number: seq,
            previous_hash: [0u8; 32],
            timestamp_unix_ms: timestamp_ms,
            event,
            payload_cbor: Vec::new(),
            hmac: [0u8; 32],
        }
    }

    #[test]
    fn replay_scan_started_sets_target() {
        let entries = vec![make_entry(
            0,
            1000,
            AuditEventType::ScanStarted {
                target_description: "http://localhost:8080".to_string(),
            },
        )];

        let snapshot = replay_from_entries(&entries);
        assert_eq!(
            snapshot.target_description.as_deref(),
            Some("http://localhost:8080")
        );
    }

    #[test]
    fn replay_module_started_adds_module() {
        let entries = vec![make_entry(
            0,
            1000,
            AuditEventType::ModuleStarted {
                module: ModuleIdentifier::Fuzzing,
            },
        )];

        let snapshot = replay_from_entries(&entries);
        assert_eq!(snapshot.active_modules, vec!["Fuzzing"]);
    }

    #[test]
    fn replay_finding_recorded_adds_finding() {
        let entries = vec![make_entry(
            0,
            1000,
            AuditEventType::FindingRecorded {
                finding_id: 42,
                vulnerability_class: VulnerabilityClass::SqlInjection,
            },
        )];

        let snapshot = replay_from_entries(&entries);
        assert_eq!(snapshot.findings.len(), 1);
        assert_eq!(snapshot.findings[0].finding_id, 42);
        assert_eq!(snapshot.findings[0].vulnerability_class, "SQL Injection");
    }

    #[test]
    fn replay_scan_completed_marks_complete() {
        let entries = vec![make_entry(
            0,
            1000,
            AuditEventType::ScanCompleted { total_findings: 7 },
        )];

        let snapshot = replay_from_entries(&entries);
        assert!(snapshot.is_complete);
        assert_eq!(snapshot.total_findings, Some(7));
    }

    #[test]
    fn replay_key_event_adds_event() {
        let entries = vec![make_entry(
            0,
            1000,
            AuditEventType::KeyEvent {
                description: "HMAC key rotated".to_string(),
            },
        )];

        let snapshot = replay_from_entries(&entries);
        assert_eq!(snapshot.key_events, vec!["HMAC key rotated"]);
    }

    #[test]
    fn replay_config_change_records_change() {
        let entries = vec![make_entry(
            0,
            1000,
            AuditEventType::ConfigChange {
                key: "max_rps".to_string(),
                old_value: "100".to_string(),
                new_value: "200".to_string(),
            },
        )];

        let snapshot = replay_from_entries(&entries);
        assert_eq!(snapshot.config_changes.len(), 1);
        assert_eq!(snapshot.config_changes[0].key, "max_rps");
        assert_eq!(snapshot.config_changes[0].old_value, "100");
        assert_eq!(snapshot.config_changes[0].new_value, "200");
    }

    #[test]
    fn replay_empty_entries_returns_empty_snapshot() {
        let snapshot = replay_from_entries(&[]);
        assert!(snapshot.target_description.is_none());
        assert!(snapshot.active_modules.is_empty());
        assert!(snapshot.findings.is_empty());
        assert!(snapshot.total_findings.is_none());
        assert!(snapshot.config_changes.is_empty());
        assert!(snapshot.key_events.is_empty());
        assert!(!snapshot.is_complete);
        assert_eq!(snapshot.last_sequence, 0);
        assert_eq!(snapshot.last_timestamp_ms, 0);
    }

    #[test]
    fn replay_tracks_last_sequence() {
        let entries = vec![
            make_entry(
                0,
                1000,
                AuditEventType::ScanStarted {
                    target_description: "app".to_string(),
                },
            ),
            make_entry(
                1,
                2000,
                AuditEventType::ModuleStarted {
                    module: ModuleIdentifier::PassiveRecon,
                },
            ),
            make_entry(2, 3000, AuditEventType::ScanCompleted { total_findings: 0 }),
        ];

        let snapshot = replay_from_entries(&entries);
        assert_eq!(snapshot.last_sequence, 2);
    }

    #[test]
    fn replay_tracks_last_timestamp() {
        let entries = vec![
            make_entry(
                0,
                1000,
                AuditEventType::ScanStarted {
                    target_description: "app".to_string(),
                },
            ),
            make_entry(1, 5000, AuditEventType::ScanCompleted { total_findings: 0 }),
        ];

        let snapshot = replay_from_entries(&entries);
        assert_eq!(snapshot.last_timestamp_ms, 5000);
    }

    #[test]
    fn filter_entries_by_event_type() {
        let entries = vec![
            make_entry(
                0,
                1000,
                AuditEventType::ScanStarted {
                    target_description: "app".to_string(),
                },
            ),
            make_entry(
                1,
                2000,
                AuditEventType::ModuleStarted {
                    module: ModuleIdentifier::Fuzzing,
                },
            ),
            make_entry(2, 3000, AuditEventType::ScanCompleted { total_findings: 0 }),
        ];

        let query = EventQuery {
            event_types: Some(vec!["ModuleStarted".to_string()]),
            ..Default::default()
        };

        let result = filter_entries(&entries, &query).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].sequence_number, 1);
    }

    #[test]
    fn filter_entries_by_sequence_range() {
        let entries = vec![
            make_entry(
                0,
                1000,
                AuditEventType::ScanStarted {
                    target_description: "app".to_string(),
                },
            ),
            make_entry(
                1,
                2000,
                AuditEventType::ModuleStarted {
                    module: ModuleIdentifier::Fuzzing,
                },
            ),
            make_entry(
                2,
                3000,
                AuditEventType::KeyEvent {
                    description: "midpoint".to_string(),
                },
            ),
            make_entry(3, 4000, AuditEventType::ScanCompleted { total_findings: 0 }),
        ];

        let query = EventQuery {
            after_sequence: Some(0),
            before_sequence: Some(3),
            ..Default::default()
        };

        let result = filter_entries(&entries, &query).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].sequence_number, 1);
        assert_eq!(result[1].sequence_number, 2);
    }

    #[test]
    fn filter_entries_by_timestamp_range() {
        let entries = vec![
            make_entry(
                0,
                1000,
                AuditEventType::ScanStarted {
                    target_description: "app".to_string(),
                },
            ),
            make_entry(
                1,
                2000,
                AuditEventType::KeyEvent {
                    description: "a".to_string(),
                },
            ),
            make_entry(
                2,
                3000,
                AuditEventType::KeyEvent {
                    description: "b".to_string(),
                },
            ),
            make_entry(3, 4000, AuditEventType::ScanCompleted { total_findings: 0 }),
        ];

        let query = EventQuery {
            after_timestamp_ms: Some(1500),
            before_timestamp_ms: Some(3500),
            ..Default::default()
        };

        let result = filter_entries(&entries, &query).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].timestamp_unix_ms, 2000);
        assert_eq!(result[1].timestamp_unix_ms, 3000);
    }

    #[test]
    fn filter_entries_invalid_sequence_range_returns_error() {
        let entries = vec![make_entry(
            0,
            1000,
            AuditEventType::ScanStarted {
                target_description: "app".to_string(),
            },
        )];

        let query = EventQuery {
            after_sequence: Some(5),
            before_sequence: Some(3),
            ..Default::default()
        };

        let result = filter_entries(&entries, &query);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("after_sequence"));
    }

    #[test]
    fn filter_entries_invalid_timestamp_range_returns_error() {
        let entries = vec![make_entry(
            0,
            1000,
            AuditEventType::ScanStarted {
                target_description: "app".to_string(),
            },
        )];

        let query = EventQuery {
            after_timestamp_ms: Some(5000),
            before_timestamp_ms: Some(3000),
            ..Default::default()
        };

        let result = filter_entries(&entries, &query);
        assert!(result.is_err());
    }

    #[test]
    fn filter_entries_no_filters_returns_all() {
        let entries = vec![
            make_entry(
                0,
                1000,
                AuditEventType::ScanStarted {
                    target_description: "app".to_string(),
                },
            ),
            make_entry(1, 2000, AuditEventType::ScanCompleted { total_findings: 0 }),
        ];

        let query = EventQuery::default();
        let result = filter_entries(&entries, &query).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn classify_event_scan_started() {
        let event = AuditEventType::ScanStarted {
            target_description: "x".to_string(),
        };
        assert_eq!(classify_event(&event), "ScanStarted");
    }

    #[test]
    fn classify_event_module_started() {
        let event = AuditEventType::ModuleStarted {
            module: ModuleIdentifier::Enumeration,
        };
        assert_eq!(classify_event(&event), "ModuleStarted");
    }

    #[test]
    fn classify_event_finding_recorded() {
        let event = AuditEventType::FindingRecorded {
            finding_id: 1,
            vulnerability_class: VulnerabilityClass::SqlInjection,
        };
        assert_eq!(classify_event(&event), "FindingRecorded");
    }

    #[test]
    fn classify_event_scan_completed() {
        let event = AuditEventType::ScanCompleted { total_findings: 0 };
        assert_eq!(classify_event(&event), "ScanCompleted");
    }

    #[test]
    fn classify_event_key_event() {
        let event = AuditEventType::KeyEvent {
            description: "x".to_string(),
        };
        assert_eq!(classify_event(&event), "KeyEvent");
    }

    #[test]
    fn classify_event_config_change() {
        let event = AuditEventType::ConfigChange {
            key: "k".to_string(),
            old_value: "a".to_string(),
            new_value: "b".to_string(),
        };
        assert_eq!(classify_event(&event), "ConfigChange");
    }

    #[test]
    fn compute_scan_timeline_produces_ordered_entries() {
        let entries = vec![
            make_entry(
                0,
                1000,
                AuditEventType::ScanStarted {
                    target_description: "app".to_string(),
                },
            ),
            make_entry(
                1,
                2000,
                AuditEventType::ModuleStarted {
                    module: ModuleIdentifier::Fuzzing,
                },
            ),
            make_entry(2, 3000, AuditEventType::ScanCompleted { total_findings: 5 }),
        ];

        let timeline = compute_scan_timeline(&entries);
        assert_eq!(timeline.len(), 3);
        assert_eq!(timeline[0].0, 1000);
        assert!(timeline[0].1.contains("Scan started"));
        assert_eq!(timeline[1].0, 2000);
        assert!(timeline[1].1.contains("Module started"));
        assert_eq!(timeline[2].0, 3000);
        assert!(timeline[2].1.contains("Scan completed"));
    }

    #[test]
    fn compute_scan_timeline_empty_returns_empty() {
        let timeline = compute_scan_timeline(&[]);
        assert!(timeline.is_empty());
    }

    #[test]
    fn diff_snapshots_finds_new_findings() {
        let before = ScanSnapshot {
            target_description: Some("app".to_string()),
            active_modules: vec!["Fuzzing".to_string()],
            findings: vec![],
            total_findings: None,
            config_changes: vec![],
            key_events: vec![],
            last_sequence: 1,
            last_timestamp_ms: 1000,
            is_complete: false,
        };

        let entries = vec![
            make_entry(
                0,
                1000,
                AuditEventType::ScanStarted {
                    target_description: "app".to_string(),
                },
            ),
            make_entry(
                1,
                2000,
                AuditEventType::ModuleStarted {
                    module: ModuleIdentifier::Fuzzing,
                },
            ),
            make_entry(
                2,
                3000,
                AuditEventType::FindingRecorded {
                    finding_id: 1,
                    vulnerability_class: VulnerabilityClass::SqlInjection,
                },
            ),
        ];

        let after = replay_from_entries(&entries);
        let diff = diff_snapshots(&before, &after);
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.new_findings[0].finding_id, 1);
    }

    #[test]
    fn diff_snapshots_finds_new_modules() {
        let before = ScanSnapshot {
            target_description: Some("app".to_string()),
            active_modules: vec!["PassiveRecon".to_string()],
            findings: vec![],
            total_findings: None,
            config_changes: vec![],
            key_events: vec![],
            last_sequence: 0,
            last_timestamp_ms: 1000,
            is_complete: false,
        };

        let after = ScanSnapshot {
            active_modules: vec!["PassiveRecon".to_string(), "Fuzzing".to_string()],
            ..before.clone()
        };

        let diff = diff_snapshots(&before, &after);
        assert_eq!(diff.new_modules, vec!["Fuzzing"]);
    }

    #[test]
    fn diff_snapshots_finds_new_config_changes() {
        use crate::event_store::ConfigChangeRecord;

        let before = ScanSnapshot {
            target_description: None,
            active_modules: vec![],
            findings: vec![],
            total_findings: None,
            config_changes: vec![ConfigChangeRecord {
                key: "a".to_string(),
                old_value: "1".to_string(),
                new_value: "2".to_string(),
                sequence_number: 0,
                timestamp_ms: 1000,
            }],
            key_events: vec![],
            last_sequence: 0,
            last_timestamp_ms: 1000,
            is_complete: false,
        };

        let mut after = before.clone();
        after.config_changes.push(ConfigChangeRecord {
            key: "b".to_string(),
            old_value: "3".to_string(),
            new_value: "4".to_string(),
            sequence_number: 1,
            timestamp_ms: 2000,
        });

        let diff = diff_snapshots(&before, &after);
        assert_eq!(diff.new_config_changes.len(), 1);
        assert_eq!(diff.new_config_changes[0].key, "b");
    }

    #[test]
    fn diff_snapshots_identical_returns_empty_diff() {
        let snapshot = ScanSnapshot {
            target_description: Some("app".to_string()),
            active_modules: vec!["Fuzzing".to_string()],
            findings: vec![],
            total_findings: Some(0),
            config_changes: vec![],
            key_events: vec!["event".to_string()],
            last_sequence: 2,
            last_timestamp_ms: 3000,
            is_complete: true,
        };

        let diff = diff_snapshots(&snapshot, &snapshot);
        assert!(diff.new_findings.is_empty());
        assert!(diff.new_modules.is_empty());
        assert!(diff.new_config_changes.is_empty());
        assert!(diff.new_key_events.is_empty());
    }

    #[test]
    fn event_store_error_display_messages() {
        let verification = EventStoreError::VerificationFailed("bad hash".to_string());
        assert!(verification.to_string().contains("verification failed"));
        assert!(verification.to_string().contains("bad hash"));

        let deser = EventStoreError::DeserializationFailed("corrupt".to_string());
        assert!(deser.to_string().contains("deserialization failed"));

        let query = EventStoreError::InvalidQuery("bad range".to_string());
        assert!(query.to_string().contains("invalid query"));

        let io = EventStoreError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"));
        assert!(io.to_string().contains("io error"));
    }

    #[test]
    fn scan_snapshot_serialization_roundtrip() {
        let snapshot = ScanSnapshot {
            target_description: Some("http://localhost:8080".to_string()),
            active_modules: vec!["Fuzzing".to_string(), "PassiveRecon".to_string()],
            findings: vec![crate::event_store::FindingRecord {
                finding_id: 42,
                vulnerability_class: "SQL Injection".to_string(),
                sequence_number: 3,
                timestamp_ms: 5000,
            }],
            total_findings: Some(1),
            config_changes: vec![crate::event_store::ConfigChangeRecord {
                key: "max_rps".to_string(),
                old_value: "100".to_string(),
                new_value: "200".to_string(),
                sequence_number: 2,
                timestamp_ms: 4000,
            }],
            key_events: vec!["key rotated".to_string()],
            last_sequence: 5,
            last_timestamp_ms: 10000,
            is_complete: true,
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        let deserialized: ScanSnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.target_description, snapshot.target_description);
        assert_eq!(deserialized.active_modules, snapshot.active_modules);
        assert_eq!(deserialized.findings.len(), 1);
        assert_eq!(deserialized.findings[0].finding_id, 42);
        assert_eq!(deserialized.total_findings, Some(1));
        assert!(deserialized.is_complete);
        assert_eq!(deserialized.last_sequence, 5);
    }

    #[test]
    fn finding_record_fields_populated_correctly() {
        let entries = vec![make_entry(
            7,
            9999,
            AuditEventType::FindingRecorded {
                finding_id: 99,
                vulnerability_class: VulnerabilityClass::CrossSiteScripting,
            },
        )];

        let snapshot = replay_from_entries(&entries);
        let finding = &snapshot.findings[0];
        assert_eq!(finding.finding_id, 99);
        assert_eq!(finding.vulnerability_class, "Cross-Site Scripting");
        assert_eq!(finding.sequence_number, 7);
        assert_eq!(finding.timestamp_ms, 9999);
    }

    #[test]
    fn event_query_default_is_unfiltered() {
        let query = EventQuery::default();
        assert!(query.event_types.is_none());
        assert!(query.after_sequence.is_none());
        assert!(query.before_sequence.is_none());
        assert!(query.after_timestamp_ms.is_none());
        assert!(query.before_timestamp_ms.is_none());
    }

    #[test]
    fn replay_full_scan_lifecycle() {
        let entries = vec![
            make_entry(
                0,
                1000,
                AuditEventType::ScanStarted {
                    target_description: "http://localhost:3000".to_string(),
                },
            ),
            make_entry(
                1,
                1100,
                AuditEventType::ModuleStarted {
                    module: ModuleIdentifier::PassiveRecon,
                },
            ),
            make_entry(
                2,
                1200,
                AuditEventType::ModuleStarted {
                    module: ModuleIdentifier::Fuzzing,
                },
            ),
            make_entry(
                3,
                2000,
                AuditEventType::ConfigChange {
                    key: "stealth_mode".to_string(),
                    old_value: "default".to_string(),
                    new_value: "paranoid".to_string(),
                },
            ),
            make_entry(
                4,
                3000,
                AuditEventType::FindingRecorded {
                    finding_id: 1,
                    vulnerability_class: VulnerabilityClass::SqlInjection,
                },
            ),
            make_entry(
                5,
                3500,
                AuditEventType::FindingRecorded {
                    finding_id: 2,
                    vulnerability_class: VulnerabilityClass::CrossSiteScripting,
                },
            ),
            make_entry(
                6,
                4000,
                AuditEventType::KeyEvent {
                    description: "WAF detected".to_string(),
                },
            ),
            make_entry(7, 5000, AuditEventType::ScanCompleted { total_findings: 2 }),
        ];

        let snapshot = replay_from_entries(&entries);
        assert_eq!(
            snapshot.target_description.as_deref(),
            Some("http://localhost:3000")
        );
        assert_eq!(snapshot.active_modules.len(), 2);
        assert_eq!(snapshot.findings.len(), 2);
        assert_eq!(snapshot.total_findings, Some(2));
        assert_eq!(snapshot.config_changes.len(), 1);
        assert_eq!(snapshot.key_events, vec!["WAF detected"]);
        assert_eq!(snapshot.last_sequence, 7);
        assert_eq!(snapshot.last_timestamp_ms, 5000);
        assert!(snapshot.is_complete);
    }

    #[test]
    fn diff_snapshots_finds_new_key_events() {
        let before = ScanSnapshot {
            target_description: None,
            active_modules: vec![],
            findings: vec![],
            total_findings: None,
            config_changes: vec![],
            key_events: vec!["first".to_string()],
            last_sequence: 0,
            last_timestamp_ms: 1000,
            is_complete: false,
        };

        let mut after = before.clone();
        after.key_events.push("second".to_string());

        let diff = diff_snapshots(&before, &after);
        assert_eq!(diff.new_key_events, vec!["second"]);
    }

    #[test]
    fn filter_entries_with_multiple_event_types() {
        let entries = vec![
            make_entry(
                0,
                1000,
                AuditEventType::ScanStarted {
                    target_description: "app".to_string(),
                },
            ),
            make_entry(
                1,
                2000,
                AuditEventType::ModuleStarted {
                    module: ModuleIdentifier::Fuzzing,
                },
            ),
            make_entry(
                2,
                3000,
                AuditEventType::FindingRecorded {
                    finding_id: 1,
                    vulnerability_class: VulnerabilityClass::SqlInjection,
                },
            ),
            make_entry(3, 4000, AuditEventType::ScanCompleted { total_findings: 1 }),
        ];

        let query = EventQuery {
            event_types: Some(vec!["ScanStarted".to_string(), "ScanCompleted".to_string()]),
            ..Default::default()
        };

        let result = filter_entries(&entries, &query).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].sequence_number, 0);
        assert_eq!(result[1].sequence_number, 3);
    }

    #[test]
    fn compute_scan_timeline_describes_finding_events() {
        let entries = vec![make_entry(
            0,
            1000,
            AuditEventType::FindingRecorded {
                finding_id: 5,
                vulnerability_class: VulnerabilityClass::CommandInjection,
            },
        )];

        let timeline = compute_scan_timeline(&entries);
        assert_eq!(timeline.len(), 1);
        assert!(timeline[0].1.contains("Finding #5"));
        assert!(timeline[0].1.contains("Command Injection"));
    }

    #[test]
    fn compute_scan_timeline_describes_config_change() {
        let entries = vec![make_entry(
            0,
            1000,
            AuditEventType::ConfigChange {
                key: "max_rps".to_string(),
                old_value: "100".to_string(),
                new_value: "200".to_string(),
            },
        )];

        let timeline = compute_scan_timeline(&entries);
        assert!(timeline[0].1.contains("Config changed"));
        assert!(timeline[0].1.contains("max_rps"));
    }

    #[test]
    fn filter_entries_equal_sequence_range_returns_error() {
        let entries = vec![make_entry(
            0,
            1000,
            AuditEventType::ScanStarted {
                target_description: "app".to_string(),
            },
        )];

        let query = EventQuery {
            after_sequence: Some(5),
            before_sequence: Some(5),
            ..Default::default()
        };

        assert!(filter_entries(&entries, &query).is_err());
    }
}
