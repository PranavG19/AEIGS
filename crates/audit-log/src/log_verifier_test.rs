#[cfg(test)]
mod tests {
    use crate::log_verifier::{VerifierError, verify_log, verify_log_bytes};
    use crate::log_writer::AuditLogWriter;
    use aegis_protocol::audit::AuditEventType;
    use std::fs;

    fn temp_log_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("aegis-verifier-tests");
        fs::create_dir_all(&dir).unwrap();
        dir.join(format!("{name}-{}.log", std::process::id()))
    }

    fn write_test_log(path: &std::path::Path, key: &[u8], count: usize) {
        let mut writer = AuditLogWriter::create(path, key).unwrap();
        for i in 0..count {
            writer
                .append_event_full(AuditEventType::KeyEvent {
                    description: format!("event-{i}"),
                })
                .unwrap();
        }
    }

    #[test]
    fn verify_valid_log_passes() {
        let path = temp_log_path("valid");
        let key = b"verify-key";
        write_test_log(&path, key, 5);

        let report = verify_log(&path, key).unwrap();
        assert_eq!(report.entries_checked, 5);
        assert!(!report.tamper_detected);
        assert!(report.hash_chain_valid);
        assert!(report.hmac_valid);
        assert!(report.first_invalid_entry.is_none());

        fs::remove_file(&path).ok();
    }

    #[test]
    fn verify_tampered_entry_detected() {
        let path = temp_log_path("tampered");
        let key = b"verify-key";
        write_test_log(&path, key, 5);

        let mut data = fs::read(&path).unwrap();

        let tamper_offset = 8 + 32 + 4 + 2;
        if tamper_offset < data.len() {
            data[tamper_offset] ^= 0xFF;
        }
        fs::write(&path, &data).unwrap();

        let report = verify_log(&path, key).unwrap();
        assert!(report.tamper_detected);
        assert!(report.first_invalid_entry.is_some());

        fs::remove_file(&path).ok();
    }

    #[test]
    fn verify_wrong_key_detected() {
        let path = temp_log_path("wrong-key");
        write_test_log(&path, b"correct-key", 3);

        let report = verify_log(&path, b"wrong-key").unwrap();
        assert!(report.tamper_detected);
        assert!(!report.hmac_valid);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn verify_empty_log_passes() {
        let path = temp_log_path("empty");
        fs::write(&path, []).unwrap();

        let report = verify_log(&path, b"key").unwrap();
        assert_eq!(report.entries_checked, 0);
        assert!(!report.tamper_detected);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn verify_truncated_header_returns_error() {
        let result = verify_log_bytes(&[0u8; 10], b"key");
        assert!(result.is_err());
    }

    #[test]
    fn verify_truncated_payload_returns_error() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(&100u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 10]);

        let result = verify_log_bytes(&data, b"key");
        assert!(result.is_err());
    }

    #[test]
    fn write_then_verify_roundtrip() {
        let path = temp_log_path("roundtrip");
        let key = b"roundtrip-key";

        let mut writer = AuditLogWriter::create(&path, key).unwrap();
        writer
            .append_event_full(AuditEventType::ScanStarted {
                target_description: "test-app".to_string(),
            })
            .unwrap();
        writer
            .append_event_full(AuditEventType::ScanCompleted { total_findings: 42 })
            .unwrap();

        let report = verify_log(&path, key).unwrap();
        assert_eq!(report.entries_checked, 2);
        assert!(!report.tamper_detected);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn error_display_is_descriptive() {
        let io_err = VerifierError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
        assert!(io_err.to_string().contains("io error"));

        let fmt_err = VerifierError::InvalidFormat("bad format".to_string());
        assert!(fmt_err.to_string().contains("invalid format"));
    }

    #[test]
    fn verify_nonexistent_file_returns_error() {
        let result = verify_log(std::path::Path::new("/nonexistent/path"), b"key");
        assert!(result.is_err());
    }
}
