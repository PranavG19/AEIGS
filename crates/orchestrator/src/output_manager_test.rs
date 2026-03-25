use std::collections::HashMap;

use crate::output_manager::{ExportFormat, OutputManager, StoredFinding};

fn make_finding(id: u64, scan_id: &str) -> StoredFinding {
    StoredFinding {
        id,
        scan_id: scan_id.to_string(),
        vulnerability_class: "SqlInjection".to_string(),
        endpoint: format!("/api/endpoint_{}", id),
        severity: 8.5,
        confidence: 0.9,
        evidence: format!("payload caused error on endpoint_{}", id),
    }
}

#[test]
fn init_scan_creates_directory_structure() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mgr = OutputManager::new(tmp.path());

    let scan_dir = mgr.init_scan("scan-001", "http://127.0.0.1:3000").unwrap();
    assert!(scan_dir.exists());
    assert!(scan_dir.join("evidence").exists());
    assert!(scan_dir.join("reports").exists());
}

#[test]
fn store_and_retrieve_findings() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mgr = OutputManager::new(tmp.path());
    mgr.init_scan("scan-001", "http://127.0.0.1:3000").unwrap();

    let findings = vec![make_finding(1, "scan-001"), make_finding(2, "scan-001")];

    let path = mgr.store_findings("scan-001", &findings).unwrap();
    assert!(path.exists());

    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("SqlInjection"));
    assert!(content.contains("endpoint_1"));

    let entry = mgr.get_scan("scan-001").unwrap();
    assert_eq!(entry.findings_count, 2);
}

#[test]
fn store_evidence_file() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mgr = OutputManager::new(tmp.path());
    mgr.init_scan("scan-001", "http://127.0.0.1:3000").unwrap();

    let data = b"screenshot binary data here";
    let path = mgr
        .store_evidence("scan-001", "screenshot_001.png", data)
        .unwrap();

    assert!(path.exists());
    assert_eq!(std::fs::read(&path).unwrap(), data);

    let entry = mgr.get_scan("scan-001").unwrap();
    assert_eq!(entry.evidence_files.len(), 1);
    assert_eq!(entry.evidence_files[0], "screenshot_001.png");
}

#[test]
fn export_sarif_format() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mgr = OutputManager::new(tmp.path());
    mgr.init_scan("scan-001", "http://127.0.0.1:3000").unwrap();

    let sarif_content = r#"{"version":"2.1.0","runs":[]}"#;
    let path = mgr
        .export("scan-001", ExportFormat::Sarif, sarif_content)
        .unwrap();

    assert!(path.exists());
    assert!(path.to_string_lossy().contains("sarif.json"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), sarif_content);
}

#[test]
fn export_multiple_formats() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mgr = OutputManager::new(tmp.path());
    mgr.init_scan("scan-001", "http://127.0.0.1:3000").unwrap();

    mgr.export("scan-001", ExportFormat::Json, "{}").unwrap();
    mgr.export("scan-001", ExportFormat::Csv, "col1,col2\n")
        .unwrap();
    mgr.export("scan-001", ExportFormat::Html, "<html></html>")
        .unwrap();

    let entry = mgr.get_scan("scan-001").unwrap();
    assert_eq!(entry.report_paths.len(), 3);
}

#[test]
fn save_and_read_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mgr = OutputManager::new(tmp.path());
    mgr.init_scan("scan-001", "http://127.0.0.1:3000").unwrap();

    let path = mgr.save_metadata("scan-001").unwrap();
    assert!(path.exists());

    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("scan-001"));
    assert!(content.contains("127.0.0.1"));
}

#[test]
fn list_scans_sorted_by_recency() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mgr = OutputManager::new(tmp.path());

    mgr.init_scan("scan-old", "http://127.0.0.1:3000").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    mgr.init_scan("scan-new", "http://127.0.0.1:3001").unwrap();

    let scans = mgr.list_scans();
    assert_eq!(scans.len(), 2);
    assert_eq!(scans[0].scan_id, "scan-new");
    assert_eq!(scans[1].scan_id, "scan-old");
}

#[test]
fn delete_scan_removes_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mgr = OutputManager::new(tmp.path());
    mgr.init_scan("scan-001", "http://127.0.0.1:3000").unwrap();

    let scan_dir = tmp.path().join("scan-001");
    assert!(scan_dir.exists());

    mgr.delete_scan("scan-001").unwrap();
    assert!(!scan_dir.exists());
    assert!(mgr.get_scan("scan-001").is_none());
}

#[test]
fn cleanup_old_scans_respects_retention_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mgr = OutputManager::new(tmp.path()).with_max_retained(2);

    for i in 0..4 {
        let id = format!("scan-{:03}", i);
        mgr.init_scan(&id, "http://127.0.0.1:3000").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let removed = mgr.cleanup_old_scans().unwrap();
    assert_eq!(removed, 2);
    assert_eq!(mgr.list_scans().len(), 2);
}

#[test]
fn total_disk_usage_accounts_for_all_files() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mgr = OutputManager::new(tmp.path());
    mgr.init_scan("scan-001", "http://127.0.0.1:3000").unwrap();

    let data = vec![0u8; 1024];
    mgr.store_evidence("scan-001", "big_file.bin", &data)
        .unwrap();

    let usage = mgr.total_disk_usage();
    assert!(
        usage >= 1024,
        "usage should be at least 1024, got {}",
        usage
    );
}

#[test]
fn error_on_nonexistent_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mgr = OutputManager::new(tmp.path());

    let result = mgr.store_findings("nonexistent", &[]);
    assert!(result.is_err());
}

#[test]
fn export_format_extensions() {
    assert_eq!(ExportFormat::Sarif.extension(), "sarif.json");
    assert_eq!(ExportFormat::Json.extension(), "json");
    assert_eq!(ExportFormat::Csv.extension(), "csv");
    assert_eq!(ExportFormat::Html.extension(), "html");
}

#[test]
fn all_formats_returns_four() {
    assert_eq!(ExportFormat::all().len(), 4);
}

#[test]
fn multiple_evidence_files() {
    let tmp = tempfile::tempdir().unwrap();
    let mut mgr = OutputManager::new(tmp.path());
    mgr.init_scan("scan-001", "http://127.0.0.1:3000").unwrap();

    mgr.store_evidence("scan-001", "payload_1.txt", b"payload1")
        .unwrap();
    mgr.store_evidence("scan-001", "payload_2.txt", b"payload2")
        .unwrap();
    mgr.store_evidence("scan-001", "screenshot.png", b"\x89PNG")
        .unwrap();

    let entry = mgr.get_scan("scan-001").unwrap();
    assert_eq!(entry.evidence_files.len(), 3);
}
