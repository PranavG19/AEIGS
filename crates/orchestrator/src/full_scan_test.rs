#[cfg(test)]
mod tests {
    use crate::full_scan::{ScanError, full_scan};
    use crate::scan_config::ScanConfig;
    use clap::Parser;

    fn test_config(target: &str) -> ScanConfig {
        ScanConfig::try_parse_from([
            "aegis",
            "--target",
            target,
            "--no-llm",
            "--skip-crawl",
            "--skip-fingerprint",
            "--max-iterations",
            "1",
            "--no-audit",
            "--output",
            "/tmp/test-fullscan.sarif",
        ])
        .unwrap()
    }

    #[test]
    fn rejects_non_localhost_target() {
        let config = test_config("http://evil.com");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(full_scan("http://evil.com", &config));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ScanError::InvalidTarget(_)));
    }

    #[test]
    fn accepts_localhost_target() {
        let config = test_config("http://127.0.0.1:9999");
        let rt = tokio::runtime::Runtime::new().unwrap();
        // Will fail at fuzz phase since nothing is listening, but should
        // get past validation and recon.
        let result = rt.block_on(full_scan("http://127.0.0.1:9999", &config));
        match result {
            Ok(report) => {
                assert!(report.phases_completed >= 1);
            }
            Err(ScanError::InvalidTarget(_)) => panic!("should accept localhost"),
            Err(_) => {} // other errors are acceptable
        }
    }

    #[test]
    fn scan_report_fields_populated() {
        let config = test_config("http://localhost:19876");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(full_scan("http://localhost:19876", &config));
        match result {
            Ok(report) => {
                assert!(report.scan_duration_ms > 0);
                assert!(!report.sarif_path.is_empty());
            }
            Err(_) => {} // acceptable if no server is running
        }
    }

    #[test]
    fn authorized_flag_bypasses_localhost_check() {
        let mut config = test_config("http://evil.com");
        config.audit.i_am_authorized = true;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(full_scan("http://evil.com", &config));
        match result {
            Err(ScanError::InvalidTarget(_)) => {
                panic!("i_am_authorized should bypass localhost check")
            }
            _ => {} // any other result is acceptable
        }
    }
}
