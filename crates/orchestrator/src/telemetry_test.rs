use crate::telemetry::{
    TelemetryCollector, TelemetryConfig, TelemetryError, TelemetryEventType, TelemetryPayload,
    default_telemetry_config, generate_session_id, sanitize_error_category,
};

fn enabled_config() -> TelemetryConfig {
    TelemetryConfig {
        enabled: true,
        endpoint: None,
        include_timing: true,
        include_counts: true,
        include_llm_usage: true,
        session_id: "test-session-abc123".to_string(),
    }
}

fn disabled_config() -> TelemetryConfig {
    TelemetryConfig {
        enabled: false,
        endpoint: None,
        include_timing: true,
        include_counts: true,
        include_llm_usage: true,
        session_id: "disabled-session".to_string(),
    }
}

#[test]
fn default_config_is_disabled() {
    let config = default_telemetry_config();
    assert!(!config.enabled);
    assert!(config.endpoint.is_none());
    assert!(config.include_timing);
    assert!(config.include_counts);
    assert!(!config.include_llm_usage);
}

#[test]
fn collector_not_enabled_records_nothing() {
    let mut collector = TelemetryCollector::new(disabled_config());
    collector.record_scan_start(11, true, "default");
    collector.record_scan_end(5, 10);
    collector.record_scan_error("config");
    collector.record_phase_complete("recon", 100, 5);
    collector.record_llm_usage(3, 1000, 500);
    assert_eq!(collector.event_count(), 0);
    assert!(collector.events().is_empty());
}

#[test]
fn record_scan_start_when_enabled() {
    let mut collector = TelemetryCollector::new(enabled_config());
    collector.record_scan_start(11, true, "paranoid");
    assert_eq!(collector.event_count(), 1);
    let event = &collector.events()[0];
    assert_eq!(event.event_type, TelemetryEventType::ScanStarted);
    assert_eq!(event.session_id, "test-session-abc123");
    match &event.payload {
        TelemetryPayload::ScanStart {
            crate_count,
            has_llm,
            stealth_preset,
        } => {
            assert_eq!(*crate_count, 11);
            assert!(*has_llm);
            assert_eq!(stealth_preset, "paranoid");
        }
        _ => panic!("expected ScanStart payload"),
    }
}

#[test]
fn record_scan_end_calculates_duration() {
    let mut collector = TelemetryCollector::new(enabled_config());
    collector.record_scan_end(7, 42);
    assert_eq!(collector.event_count(), 1);
    let event = &collector.events()[0];
    assert_eq!(event.event_type, TelemetryEventType::ScanCompleted);
    match &event.payload {
        TelemetryPayload::ScanEnd {
            total_findings,
            total_endpoints,
            duration_ms,
        } => {
            assert_eq!(*total_findings, 7);
            assert_eq!(*total_endpoints, 42);
            assert!(*duration_ms < 5000);
        }
        _ => panic!("expected ScanEnd payload"),
    }
}

#[test]
fn record_scan_error_creates_failed_event() {
    let mut collector = TelemetryCollector::new(enabled_config());
    collector.record_scan_error("config: invalid target");
    assert_eq!(collector.event_count(), 1);
    let event = &collector.events()[0];
    assert_eq!(event.event_type, TelemetryEventType::ScanFailed);
    match &event.payload {
        TelemetryPayload::ScanError { error_category } => {
            assert_eq!(error_category, "config");
        }
        _ => panic!("expected ScanError payload"),
    }
}

#[test]
fn record_phase_complete_when_timing_enabled() {
    let mut collector = TelemetryCollector::new(enabled_config());
    collector.record_phase_complete("recon", 250, 15);
    assert_eq!(collector.event_count(), 1);
    let event = &collector.events()[0];
    assert_eq!(event.event_type, TelemetryEventType::PhaseCompleted);
    match &event.payload {
        TelemetryPayload::PhaseComplete {
            phase_name,
            duration_ms,
            item_count,
        } => {
            assert_eq!(phase_name, "recon");
            assert_eq!(*duration_ms, 250);
            assert_eq!(*item_count, 15);
        }
        _ => panic!("expected PhaseComplete payload"),
    }
}

#[test]
fn record_phase_complete_when_timing_disabled_skips() {
    let config = TelemetryConfig {
        enabled: true,
        include_timing: false,
        ..enabled_config()
    };
    let mut collector = TelemetryCollector::new(config);
    collector.record_phase_complete("recon", 250, 15);
    assert_eq!(collector.event_count(), 0);
}

#[test]
fn record_llm_usage_when_enabled() {
    let mut collector = TelemetryCollector::new(enabled_config());
    collector.record_llm_usage(5, 2000, 800);
    assert_eq!(collector.event_count(), 1);
    match &collector.events()[0].payload {
        TelemetryPayload::LlmUsage {
            total_calls,
            total_input_tokens,
            total_output_tokens,
        } => {
            assert_eq!(*total_calls, 5);
            assert_eq!(*total_input_tokens, 2000);
            assert_eq!(*total_output_tokens, 800);
        }
        _ => panic!("expected LlmUsage payload"),
    }
}

#[test]
fn record_llm_usage_when_llm_tracking_disabled_skips() {
    let config = TelemetryConfig {
        enabled: true,
        include_llm_usage: false,
        ..enabled_config()
    };
    let mut collector = TelemetryCollector::new(config);
    collector.record_llm_usage(5, 2000, 800);
    assert_eq!(collector.event_count(), 0);
}

#[test]
fn event_count_tracks_correctly() {
    let mut collector = TelemetryCollector::new(enabled_config());
    assert_eq!(collector.event_count(), 0);
    collector.record_scan_start(11, false, "default");
    assert_eq!(collector.event_count(), 1);
    collector.record_phase_complete("recon", 100, 3);
    assert_eq!(collector.event_count(), 2);
    collector.record_phase_complete("fuzz", 500, 20);
    assert_eq!(collector.event_count(), 3);
    collector.record_scan_end(4, 10);
    assert_eq!(collector.event_count(), 4);
}

#[test]
fn export_json_produces_valid_json() {
    let mut collector = TelemetryCollector::new(enabled_config());
    collector.record_scan_start(11, true, "default");
    collector.record_scan_end(3, 8);
    let json = collector.export_json().unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.len(), 2);
}

#[test]
fn export_json_with_no_events_returns_empty_array() {
    let collector = TelemetryCollector::new(enabled_config());
    let json = collector.export_json().unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
    assert!(parsed.is_empty());
}

#[test]
fn export_to_file_writes_valid_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("telemetry.json");
    let mut collector = TelemetryCollector::new(enabled_config());
    collector.record_scan_start(5, false, "aggressive");
    collector.export_to_file(&path).unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&contents).unwrap();
    assert_eq!(parsed.len(), 1);
}

#[test]
fn generate_session_id_returns_32_hex_chars() {
    let id = generate_session_id();
    assert_eq!(id.len(), 32);
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn generate_session_id_produces_unique_values() {
    let id1 = generate_session_id();
    let id2 = generate_session_id();
    assert_ne!(id1, id2);
}

#[test]
fn sanitize_error_category_extracts_first_word_before_colon() {
    assert_eq!(sanitize_error_category("config: invalid target"), "config");
    assert_eq!(
        sanitize_error_category("audit log: failed to create"),
        "audit log"
    );
}

#[test]
fn sanitize_error_category_truncates_long_messages() {
    let long = "a".repeat(100);
    let result = sanitize_error_category(&long);
    assert_eq!(result.len(), 50);
}

#[test]
fn sanitize_error_category_handles_empty_string() {
    assert_eq!(sanitize_error_category(""), "unknown");
}

#[test]
fn telemetry_event_type_equality() {
    assert_eq!(
        TelemetryEventType::ScanStarted,
        TelemetryEventType::ScanStarted
    );
    assert_eq!(
        TelemetryEventType::ScanCompleted,
        TelemetryEventType::ScanCompleted
    );
    assert_eq!(
        TelemetryEventType::ScanFailed,
        TelemetryEventType::ScanFailed
    );
    assert_eq!(
        TelemetryEventType::PhaseCompleted,
        TelemetryEventType::PhaseCompleted
    );
    assert_ne!(
        TelemetryEventType::ScanStarted,
        TelemetryEventType::ScanFailed
    );
}

#[test]
fn telemetry_payload_serialization_roundtrip() {
    let payload = TelemetryPayload::ScanStart {
        crate_count: 11,
        has_llm: true,
        stealth_preset: "default".to_string(),
    };
    let json = serde_json::to_string(&payload).unwrap();
    let deserialized: TelemetryPayload = serde_json::from_str(&json).unwrap();
    match deserialized {
        TelemetryPayload::ScanStart {
            crate_count,
            has_llm,
            stealth_preset,
        } => {
            assert_eq!(crate_count, 11);
            assert!(has_llm);
            assert_eq!(stealth_preset, "default");
        }
        _ => panic!("deserialization produced wrong variant"),
    }
}

#[test]
fn telemetry_error_display_not_enabled() {
    let err = TelemetryError::NotEnabled;
    assert_eq!(format!("{err}"), "telemetry is not enabled");
}

#[test]
fn telemetry_error_display_serialization_failed() {
    let err = TelemetryError::SerializationFailed("bad data".to_string());
    assert_eq!(format!("{err}"), "telemetry serialization failed: bad data");
}

#[test]
fn telemetry_error_display_export_failed() {
    let err = TelemetryError::ExportFailed("disk full".to_string());
    assert_eq!(format!("{err}"), "telemetry export failed: disk full");
}

#[test]
fn telemetry_error_is_std_error() {
    let err = TelemetryError::NotEnabled;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn not_enabled_error_returned_when_disabled() {
    let collector = TelemetryCollector::new(disabled_config());
    let result = collector.export_json();
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TelemetryError::NotEnabled));
}

#[test]
fn session_id_is_preserved_across_events() {
    let mut collector = TelemetryCollector::new(enabled_config());
    collector.record_scan_start(5, false, "default");
    collector.record_phase_complete("recon", 100, 3);
    collector.record_scan_end(2, 5);
    for event in collector.events() {
        assert_eq!(event.session_id, "test-session-abc123");
    }
}

#[test]
fn all_event_types_covered() {
    let mut collector = TelemetryCollector::new(enabled_config());
    collector.record_scan_start(11, true, "default");
    collector.record_phase_complete("recon", 100, 5);
    collector.record_llm_usage(2, 500, 200);
    collector.record_scan_error("fuzz");
    collector.record_scan_end(3, 8);

    let types: Vec<TelemetryEventType> = collector.events().iter().map(|e| e.event_type).collect();
    assert!(types.contains(&TelemetryEventType::ScanStarted));
    assert!(types.contains(&TelemetryEventType::ScanCompleted));
    assert!(types.contains(&TelemetryEventType::ScanFailed));
    assert!(types.contains(&TelemetryEventType::PhaseCompleted));
}

#[test]
fn timestamps_are_monotonically_nondecreasing() {
    let mut collector = TelemetryCollector::new(enabled_config());
    collector.record_scan_start(1, false, "default");
    collector.record_phase_complete("recon", 10, 1);
    collector.record_scan_end(0, 0);
    let timestamps: Vec<u64> = collector.events().iter().map(|e| e.timestamp_ms).collect();
    for window in timestamps.windows(2) {
        assert!(window[0] <= window[1]);
    }
}

#[test]
fn is_enabled_reflects_config() {
    let enabled = TelemetryCollector::new(enabled_config());
    assert!(enabled.is_enabled());
    let disabled = TelemetryCollector::new(disabled_config());
    assert!(!disabled.is_enabled());
}

#[test]
fn export_to_file_returns_not_enabled_when_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("telemetry.json");
    let collector = TelemetryCollector::new(disabled_config());
    let result = collector.export_to_file(&path);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TelemetryError::NotEnabled));
}

#[test]
fn export_to_file_returns_export_failed_for_bad_path() {
    let mut collector = TelemetryCollector::new(enabled_config());
    collector.record_scan_start(1, false, "default");
    let bad_path = std::path::Path::new("/nonexistent/deep/dir/telemetry.json");
    let result = collector.export_to_file(bad_path);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TelemetryError::ExportFailed(_)
    ));
}

#[test]
fn telemetry_config_debug_format() {
    let config = default_telemetry_config();
    let dbg = format!("{config:?}");
    assert!(dbg.contains("TelemetryConfig"));
    assert!(dbg.contains("enabled: false"));
}

#[test]
fn telemetry_config_clone() {
    let config = enabled_config();
    let cloned = config.clone();
    assert_eq!(cloned.enabled, config.enabled);
    assert_eq!(cloned.session_id, config.session_id);
    assert_eq!(cloned.include_llm_usage, config.include_llm_usage);
}

#[test]
fn telemetry_event_clone() {
    let mut collector = TelemetryCollector::new(enabled_config());
    collector.record_scan_start(5, false, "default");
    let event = collector.events()[0].clone();
    assert_eq!(event.event_type, TelemetryEventType::ScanStarted);
    assert_eq!(event.session_id, "test-session-abc123");
}

#[test]
fn sanitize_error_category_no_colon_returns_whole_string() {
    assert_eq!(sanitize_error_category("timeout"), "timeout");
}

#[test]
fn sanitize_error_category_trims_whitespace() {
    assert_eq!(sanitize_error_category("  config : details"), "config");
}

#[test]
fn default_config_session_id_is_valid_hex() {
    let config = default_telemetry_config();
    assert_eq!(config.session_id.len(), 32);
    assert!(config.session_id.chars().all(|c| c.is_ascii_hexdigit()));
}
