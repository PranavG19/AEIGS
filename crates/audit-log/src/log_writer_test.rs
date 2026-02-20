#[cfg(test)]
mod tests {
    use crate::hash_chain::{compute_next_hash, genesis_hash};
    use crate::hmac_signer::HmacSigner;
    use crate::log_writer::{AuditLogWriter, AuditWriter, serialize_event};
    use aegis_protocol::audit::AuditEventType;
    use aegis_protocol::finding::VulnerabilityClass;
    use aegis_protocol::operation::ModuleIdentifier;
    use std::fs;

    fn temp_log_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("aegis-test-logs");
        fs::create_dir_all(&dir).unwrap();
        dir.join(format!("{name}-{}.log", std::process::id()))
    }

    #[test]
    fn write_single_event() {
        let path = temp_log_path("single");
        let mut writer = AuditLogWriter::create(&path, b"test-key").unwrap();

        let entry = writer
            .append_event_full(AuditEventType::ScanStarted {
                target_description: "test-app".to_string(),
            })
            .unwrap();

        assert_eq!(entry.sequence_number, 0);
        assert_eq!(entry.previous_hash, genesis_hash());
        assert!(!entry.payload_cbor.is_empty());
        assert_eq!(writer.sequence_number(), 1);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn write_multiple_events_increments_sequence() {
        let path = temp_log_path("multi");
        let mut writer = AuditLogWriter::create(&path, b"test-key").unwrap();

        let entry1 = writer
            .append_event_full(AuditEventType::ScanStarted {
                target_description: "app1".to_string(),
            })
            .unwrap();

        let entry2 = writer
            .append_event_full(AuditEventType::ModuleStarted {
                module: ModuleIdentifier::PassiveRecon,
            })
            .unwrap();

        assert_eq!(entry1.sequence_number, 0);
        assert_eq!(entry2.sequence_number, 1);
        assert_ne!(entry1.previous_hash, entry2.previous_hash);
        assert_eq!(writer.sequence_number(), 2);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn hash_chain_links_correctly() {
        let path = temp_log_path("chain-link");
        let mut writer = AuditLogWriter::create(&path, b"test-key").unwrap();

        let entry1 = writer
            .append_event_full(AuditEventType::ScanStarted {
                target_description: "app".to_string(),
            })
            .unwrap();

        let entry2 = writer
            .append_event_full(AuditEventType::ScanCompleted { total_findings: 5 })
            .unwrap();

        let expected_hash = compute_next_hash(&entry1.previous_hash, &entry1.payload_cbor);
        assert_eq!(entry2.previous_hash, expected_hash);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn hmac_verifies_against_payload() {
        let path = temp_log_path("hmac-verify");
        let key = b"test-hmac-key";
        let mut writer = AuditLogWriter::create(&path, key).unwrap();

        let entry = writer
            .append_event_full(AuditEventType::KeyEvent {
                description: "test event".to_string(),
            })
            .unwrap();

        let signer = HmacSigner::new(key);
        assert!(signer.verify(&entry.payload_cbor, &entry.hmac));

        fs::remove_file(&path).ok();
    }

    #[test]
    fn file_grows_with_writes() {
        let path = temp_log_path("file-grows");
        let mut writer = AuditLogWriter::create(&path, b"key").unwrap();

        writer
            .append_event_full(AuditEventType::ScanStarted {
                target_description: "app".to_string(),
            })
            .unwrap();

        let size1 = fs::metadata(&path).unwrap().len();
        assert!(size1 > 0);

        writer
            .append_event_full(AuditEventType::ScanCompleted { total_findings: 0 })
            .unwrap();

        let size2 = fs::metadata(&path).unwrap().len();
        assert!(size2 > size1);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn all_event_types_serialize() {
        let events = vec![
            AuditEventType::ScanStarted {
                target_description: "test".to_string(),
            },
            AuditEventType::ModuleStarted {
                module: ModuleIdentifier::Fuzzing,
            },
            AuditEventType::FindingRecorded {
                finding_id: 42,
                vulnerability_class: VulnerabilityClass::SqlInjection,
            },
            AuditEventType::ScanCompleted { total_findings: 10 },
            AuditEventType::KeyEvent {
                description: "key rotated".to_string(),
            },
            AuditEventType::ConfigChange {
                key: "max_rps".to_string(),
                old_value: "100".to_string(),
                new_value: "200".to_string(),
            },
        ];

        let path = temp_log_path("all-types");
        let mut writer = AuditLogWriter::create(&path, b"key").unwrap();

        for event in events {
            writer.append_event_full(event).unwrap();
        }

        assert_eq!(writer.sequence_number(), 6);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn serialize_event_produces_valid_cbor() {
        let event = AuditEventType::ScanStarted {
            target_description: "test".to_string(),
        };

        let cbor_bytes = serialize_event(&event).unwrap();
        assert!(!cbor_bytes.is_empty());

        let deserialized: AuditEventType = ciborium::from_reader(&cbor_bytes[..]).unwrap();
        match deserialized {
            AuditEventType::ScanStarted { target_description } => {
                assert_eq!(target_description, "test");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn error_display_is_descriptive() {
        use crate::log_writer::LogWriterError;

        let io_err = LogWriterError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(io_err.to_string().contains("io error"));

        let ser_err = LogWriterError::SerializationError("bad data".to_string());
        assert!(ser_err.to_string().contains("serialization error"));

        let creation_err = LogWriterError::LogCreationFailed("permission denied".to_string());
        assert!(
            creation_err
                .to_string()
                .contains("audit log creation failed")
        );
    }

    #[test]
    fn create_with_invalid_path_returns_error() {
        let result = AuditLogWriter::create(
            std::path::Path::new("/nonexistent/dir/that/does/not/exist/audit.log"),
            b"test-key",
        );
        assert!(result.is_err());
    }

    #[test]
    fn noop_writer_accepts_events_silently() {
        use crate::log_writer::{AuditWriter, NoOpAuditLogWriter};

        let mut writer = NoOpAuditLogWriter::new();
        let result = writer.append_event(AuditEventType::ScanStarted {
            target_description: "test".to_string(),
        });
        assert!(result.is_ok());
        assert_eq!(writer.sequence_number(), 0);
    }

    #[test]
    fn noop_writer_default_trait() {
        use crate::log_writer::{AuditWriter, NoOpAuditLogWriter};

        let writer = NoOpAuditLogWriter::default();
        assert_eq!(writer.sequence_number(), 0);
    }

    /// Verify that ciborium produces deterministic CBOR output for the same input.
    ///
    /// The hash chain computes SHA3-256 over CBOR bytes, so non-deterministic
    /// serialization would produce different hashes for identical logical events,
    /// making the audit log non-reproducible. RFC 8949 Section 4.2 specifies
    /// deterministic encoding rules; this test confirms ciborium satisfies them
    /// for our AuditEventType enum.
    #[test]
    fn cbor_serialization_is_deterministic() {
        let iterations = 1000;

        let scan_started = AuditEventType::ScanStarted {
            target_description: "http://localhost:8080/api".to_string(),
        };
        let reference_bytes = serialize_event(&scan_started).unwrap();
        for i in 0..iterations {
            let event = AuditEventType::ScanStarted {
                target_description: "http://localhost:8080/api".to_string(),
            };
            let bytes = serialize_event(&event).unwrap();
            assert_eq!(
                bytes, reference_bytes,
                "ScanStarted serialization diverged on iteration {i}"
            );
        }

        let module_started = AuditEventType::ModuleStarted {
            module: ModuleIdentifier::Fuzzing,
        };
        let reference_bytes = serialize_event(&module_started).unwrap();
        for i in 0..iterations {
            let event = AuditEventType::ModuleStarted {
                module: ModuleIdentifier::Fuzzing,
            };
            let bytes = serialize_event(&event).unwrap();
            assert_eq!(
                bytes, reference_bytes,
                "ModuleStarted serialization diverged on iteration {i}"
            );
        }

        let config_change = AuditEventType::ConfigChange {
            key: "max_rps".to_string(),
            old_value: "100".to_string(),
            new_value: "200".to_string(),
        };
        let reference_bytes = serialize_event(&config_change).unwrap();
        for i in 0..iterations {
            let event = AuditEventType::ConfigChange {
                key: "max_rps".to_string(),
                old_value: "100".to_string(),
                new_value: "200".to_string(),
            };
            let bytes = serialize_event(&event).unwrap();
            assert_eq!(
                bytes, reference_bytes,
                "ConfigChange serialization diverged on iteration {i}"
            );
        }
    }
}
