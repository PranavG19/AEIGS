use aegis_audit_log::event_store::{
    EventQuery, compute_scan_timeline, diff_snapshots, filter_entries, replay_from_entries,
};
use aegis_audit_log::hash_chain::{HashChain, genesis_hash, verify_chain};
use aegis_audit_log::hmac_signer::HmacSigner;
use aegis_audit_log::log_verifier::verify_log;
use aegis_audit_log::log_writer::{AuditLogWriter, AuditWriter, NoOpAuditLogWriter};
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

fn make_scan_entries() -> Vec<AuditEntry> {
    vec![
        make_entry(
            0,
            1000,
            AuditEventType::ScanStarted {
                target_description: "http://localhost:3000".to_string(),
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
    ]
}

#[test]
fn write_read_verify_100_entries() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit.cbor");
    let hmac_key = b"integration-test-key-100";

    let mut writer = AuditLogWriter::create(&log_path, hmac_key).unwrap();

    for i in 0..100 {
        writer
            .append_event(AuditEventType::KeyEvent {
                description: format!("event-{i}"),
            })
            .unwrap();
    }

    assert_eq!(writer.sequence_number(), 100);

    let report = verify_log(&log_path, hmac_key).unwrap();
    assert_eq!(report.entries_checked, 100);
    assert!(!report.tamper_detected);
    assert!(report.hash_chain_valid);
    assert!(report.hmac_valid);
}

#[test]
fn write_verify_detects_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit-tamper.cbor");
    let hmac_key = b"tamper-test-key";

    let mut writer = AuditLogWriter::create(&log_path, hmac_key).unwrap();
    for i in 0..5 {
        writer
            .append_event(AuditEventType::KeyEvent {
                description: format!("event-{i}"),
            })
            .unwrap();
    }

    let mut data = std::fs::read(&log_path).unwrap();
    let middle = data.len() / 2;
    data[middle] ^= 0xFF;
    std::fs::write(&log_path, &data).unwrap();

    let report = verify_log(&log_path, hmac_key).unwrap();
    assert!(
        report.tamper_detected,
        "corrupted byte should cause tamper detection"
    );
}

#[test]
fn hmac_verification_correct_key() {
    let signer = HmacSigner::new(b"correct-key");
    let data = b"some audit payload";
    let mac = signer.sign(data);

    assert!(signer.verify(data, &mac), "correct key should verify");
}

#[test]
fn hmac_verification_wrong_key() {
    let signer_a = HmacSigner::new(b"key-A");
    let signer_b = HmacSigner::new(b"key-B");
    let data = b"some audit payload";
    let mac = signer_a.sign(data);

    assert!(
        !signer_b.verify(data, &mac),
        "wrong key should fail verification"
    );
}

#[test]
fn hmac_key_derivation_from_passphrase() {
    let signer1 = HmacSigner::with_derived_key(b"my-passphrase");
    let signer2 = HmacSigner::with_derived_key(b"my-passphrase");

    let data = b"test payload";
    let mac1 = signer1.sign(data);
    let mac2 = signer2.sign(data);

    assert_eq!(mac1, mac2, "same passphrase must derive same key");
}

#[test]
fn hmac_key_save_load_file() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("hmac.key");

    let original = HmacSigner::new(b"secret-key-material");
    original.save_key_to_file(&key_path).unwrap();

    let loaded = HmacSigner::with_key_file(&key_path).unwrap();

    let data = b"verify roundtrip";
    let mac_original = original.sign(data);
    let mac_loaded = loaded.sign(data);
    assert_eq!(mac_original, mac_loaded, "save/load must preserve key");
}

#[test]
fn noop_writer_discards_events() {
    let mut noop = NoOpAuditLogWriter::new();
    let result = noop.append_event(AuditEventType::ScanStarted {
        target_description: "should be dropped".to_string(),
    });

    assert!(result.is_ok());
    assert_eq!(noop.sequence_number(), 1);
}

#[test]
fn event_store_replay_reconstructs_scan() {
    let entries = make_scan_entries();
    let snapshot = replay_from_entries(&entries);

    assert_eq!(
        snapshot.target_description.as_deref(),
        Some("http://localhost:3000")
    );
    assert!(!snapshot.active_modules.is_empty());
    assert_eq!(snapshot.findings.len(), 1);
    assert_eq!(snapshot.findings[0].finding_id, 1);
    assert_eq!(snapshot.total_findings, Some(1));
    assert!(snapshot.is_complete);
}

#[test]
fn event_store_filter_by_type() {
    let entries = make_scan_entries();
    let query = EventQuery {
        event_types: Some(vec!["FindingRecorded".to_string()]),
        ..Default::default()
    };

    let filtered = filter_entries(&entries, &query).unwrap();
    assert_eq!(filtered.len(), 1);
    assert!(matches!(
        filtered[0].event,
        AuditEventType::FindingRecorded { .. }
    ));
}

#[test]
fn event_store_filter_by_sequence_range() {
    let mut entries = Vec::new();
    for i in 0..10 {
        entries.push(make_entry(
            i,
            (i + 1) * 1000,
            AuditEventType::KeyEvent {
                description: format!("event-{i}"),
            },
        ));
    }

    let query = EventQuery {
        after_sequence: Some(3),
        before_sequence: Some(7),
        ..Default::default()
    };

    let filtered = filter_entries(&entries, &query).unwrap();
    let seqs: Vec<u64> = filtered.iter().map(|e| e.sequence_number).collect();
    assert_eq!(seqs, vec![4, 5, 6]);
}

#[test]
fn event_store_filter_by_timestamp_range() {
    let mut entries = Vec::new();
    for i in 0..10 {
        entries.push(make_entry(
            i,
            (i + 1) * 100,
            AuditEventType::KeyEvent {
                description: format!("event-{i}"),
            },
        ));
    }

    let query = EventQuery {
        after_timestamp_ms: Some(300),
        before_timestamp_ms: Some(700),
        ..Default::default()
    };

    let filtered = filter_entries(&entries, &query).unwrap();
    for entry in &filtered {
        assert!(entry.timestamp_unix_ms > 300);
        assert!(entry.timestamp_unix_ms < 700);
    }
    assert!(!filtered.is_empty());
}

#[test]
fn event_store_diff_snapshots() {
    let entries_before = vec![
        make_entry(
            0,
            1000,
            AuditEventType::ScanStarted {
                target_description: "localhost".to_string(),
            },
        ),
        make_entry(
            1,
            2000,
            AuditEventType::FindingRecorded {
                finding_id: 1,
                vulnerability_class: VulnerabilityClass::SqlInjection,
            },
        ),
        make_entry(
            2,
            3000,
            AuditEventType::FindingRecorded {
                finding_id: 2,
                vulnerability_class: VulnerabilityClass::CrossSiteScripting,
            },
        ),
    ];

    let mut entries_after = entries_before.clone();
    entries_after.push(make_entry(
        3,
        4000,
        AuditEventType::FindingRecorded {
            finding_id: 3,
            vulnerability_class: VulnerabilityClass::CommandInjection,
        },
    ));
    entries_after.push(make_entry(
        4,
        5000,
        AuditEventType::FindingRecorded {
            finding_id: 4,
            vulnerability_class: VulnerabilityClass::PathTraversal,
        },
    ));
    entries_after.push(make_entry(
        5,
        6000,
        AuditEventType::FindingRecorded {
            finding_id: 5,
            vulnerability_class: VulnerabilityClass::OpenRedirect,
        },
    ));

    let snap_before = replay_from_entries(&entries_before);
    let snap_after = replay_from_entries(&entries_after);
    let diff = diff_snapshots(&snap_before, &snap_after);

    assert_eq!(
        diff.new_findings.len(),
        3,
        "diff should show 3 new findings"
    );
}

#[test]
fn event_store_timeline() {
    let entries = vec![
        make_entry(
            0,
            1000,
            AuditEventType::ScanStarted {
                target_description: "localhost".to_string(),
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
        make_entry(
            3,
            4000,
            AuditEventType::KeyEvent {
                description: "rate limit detected".to_string(),
            },
        ),
        make_entry(4, 5000, AuditEventType::ScanCompleted { total_findings: 1 }),
    ];

    let timeline = compute_scan_timeline(&entries);
    assert_eq!(timeline.len(), 5);
    for (ts, desc) in &timeline {
        assert!(*ts > 0, "timestamps should be positive");
        assert!(!desc.is_empty(), "descriptions should not be empty");
    }
}

#[test]
fn event_store_config_change_tracked() {
    let entries = vec![
        make_entry(
            0,
            1000,
            AuditEventType::ScanStarted {
                target_description: "localhost".to_string(),
            },
        ),
        make_entry(
            1,
            2000,
            AuditEventType::ConfigChange {
                key: "max_iterations".to_string(),
                old_value: "1".to_string(),
                new_value: "5".to_string(),
            },
        ),
    ];

    let snapshot = replay_from_entries(&entries);
    assert_eq!(snapshot.config_changes.len(), 1);
    let change = &snapshot.config_changes[0];
    assert_eq!(change.key, "max_iterations");
    assert_eq!(change.old_value, "1");
    assert_eq!(change.new_value, "5");
}

#[test]
fn genesis_hash_deterministic() {
    let h1 = genesis_hash();
    let h2 = genesis_hash();
    assert_eq!(h1, h2, "genesis hash must be deterministic");
}

#[test]
fn hash_chain_sequential() {
    let mut chain1 = HashChain::new();
    let mut chain2 = HashChain::new();

    let inputs: Vec<&[u8]> = vec![b"first", b"second", b"third"];
    let mut hashes1 = Vec::new();
    let mut hashes2 = Vec::new();

    for input in &inputs {
        hashes1.push(chain1.append(input));
        hashes2.push(chain2.append(input));
    }

    assert_eq!(
        hashes1, hashes2,
        "same inputs must produce same hash sequence"
    );

    let chain_entries: Vec<([u8; 32], Vec<u8>)> = hashes1
        .iter()
        .zip(inputs.iter())
        .map(|(hash, data)| (*hash, data.to_vec()))
        .collect();
    assert!(
        verify_chain(&chain_entries),
        "chain built from sequential appends must verify"
    );
}
