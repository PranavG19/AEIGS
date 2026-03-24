use crate::h2_protocol_attacks::*;
use crate::stealth_config::StealthConfig;

// ─── Frame header structure validation ──────────────────────────────

#[test]
fn continuation_flood_produces_valid_frame_headers() {
    let config = H2AttackConfig::default().with_frame_count(50);
    let payload = generate_continuation_flood(&config);
    assert!(payload.validate_frame_headers());
}

#[test]
fn rapid_reset_produces_valid_frame_headers() {
    let config = H2AttackConfig::default().with_frame_count(20);
    let payload = generate_rapid_reset(&config);
    assert!(payload.validate_frame_headers());
}

#[test]
fn settings_flood_produces_valid_frame_headers() {
    let config = H2AttackConfig::default().with_frame_count(30);
    let payload = generate_settings_flood(&config);
    assert!(payload.validate_frame_headers());
}

#[test]
fn ping_flood_produces_valid_frame_headers() {
    let config = H2AttackConfig::default().with_frame_count(40);
    let payload = generate_ping_flood(&config);
    assert!(payload.validate_frame_headers());
}

#[test]
fn empty_frames_produces_valid_frame_headers() {
    let config = H2AttackConfig::default().with_frame_count(25);
    let payload = generate_empty_frames(&config);
    assert!(payload.validate_frame_headers());
}

#[test]
fn hpack_bombing_produces_valid_frame_headers() {
    let config = H2AttackConfig::default().with_frame_count(15);
    let payload = generate_hpack_bombing(&config);
    assert!(payload.validate_frame_headers());
}

// ─── Continuation flood specifics ───────────────────────────────────

#[test]
fn continuation_flood_first_frame_is_headers() {
    let config = H2AttackConfig::default().with_frame_count(10);
    let payload = generate_continuation_flood(&config);
    assert_eq!(parse_frame_type(&payload.frames[0]), Some(0x1));
}

#[test]
fn continuation_flood_no_end_headers_flag() {
    let config = H2AttackConfig::default().with_frame_count(5);
    let payload = generate_continuation_flood(&config);
    for frame in &payload.frames {
        let flags = parse_frame_flags(frame).unwrap();
        assert_eq!(flags & 0x4, 0, "END_HEADERS must not be set");
    }
}

#[test]
fn continuation_flood_all_same_stream() {
    let config = H2AttackConfig::default()
        .with_frame_count(8)
        .with_stream_id_start(7);
    let payload = generate_continuation_flood(&config);
    for frame in &payload.frames {
        assert_eq!(parse_stream_id(frame), Some(7));
    }
}

#[test]
fn continuation_flood_rest_are_continuation_type() {
    let config = H2AttackConfig::default().with_frame_count(10);
    let payload = generate_continuation_flood(&config);
    for frame in payload.frames.iter().skip(1) {
        assert_eq!(parse_frame_type(frame), Some(0x9));
    }
}

// ─── Rapid reset specifics ──────────────────────────────────────────

#[test]
fn rapid_reset_alternates_headers_and_rst() {
    let config = H2AttackConfig::default().with_frame_count(5);
    let payload = generate_rapid_reset(&config);
    assert!(payload.frames.len() >= 2);
    assert_eq!(payload.frames.len() % 2, 0, "Must have HEADERS+RST pairs");
    for pair in payload.frames.chunks(2) {
        assert_eq!(parse_frame_type(&pair[0]), Some(0x1));
        assert_eq!(parse_frame_type(&pair[1]), Some(0x3));
    }
}

#[test]
fn rapid_reset_uses_odd_stream_ids() {
    let config = H2AttackConfig::default().with_frame_count(3);
    let payload = generate_rapid_reset(&config);
    for pair in payload.frames.chunks(2) {
        let sid = parse_stream_id(&pair[0]).unwrap();
        assert_eq!(sid % 2, 1, "H2 client streams must be odd");
        assert_eq!(parse_stream_id(&pair[1]), Some(sid));
    }
}

#[test]
fn rapid_reset_rst_contains_cancel_error_code() {
    let config = H2AttackConfig::default().with_frame_count(2);
    let payload = generate_rapid_reset(&config);
    for pair in payload.frames.chunks(2) {
        let rst = &pair[1];
        let error_code = u32::from_be_bytes([rst[9], rst[10], rst[11], rst[12]]);
        assert_eq!(error_code, 0x8, "RST_STREAM should carry CANCEL (0x8)");
    }
}

// ─── Settings flood specifics ───────────────────────────────────────

#[test]
fn settings_flood_uses_stream_zero() {
    let config = H2AttackConfig::default().with_frame_count(5);
    let payload = generate_settings_flood(&config);
    for frame in &payload.frames {
        assert_eq!(parse_stream_id(frame), Some(0));
    }
}

#[test]
fn settings_flood_payload_is_multiple_of_six() {
    let config = H2AttackConfig::default().with_frame_count(3);
    let payload = generate_settings_flood(&config);
    for frame in &payload.frames {
        let plen = parse_payload_length(frame).unwrap();
        assert_eq!(plen % 6, 0, "SETTINGS params are 6 bytes each");
    }
}

// ─── Ping flood specifics ───────────────────────────────────────────

#[test]
fn ping_flood_each_frame_has_8_byte_payload() {
    let config = H2AttackConfig::default().with_frame_count(10);
    let payload = generate_ping_flood(&config);
    for frame in &payload.frames {
        assert_eq!(parse_payload_length(frame), Some(8));
    }
}

#[test]
fn ping_flood_stream_id_is_zero() {
    let config = H2AttackConfig::default().with_frame_count(5);
    let payload = generate_ping_flood(&config);
    for frame in &payload.frames {
        assert_eq!(parse_stream_id(frame), Some(0));
    }
}

#[test]
fn ping_flood_no_ack_flag() {
    let config = H2AttackConfig::default().with_frame_count(5);
    let payload = generate_ping_flood(&config);
    for frame in &payload.frames {
        let flags = parse_frame_flags(frame).unwrap();
        assert_eq!(flags & 0x1, 0, "PING frames should not have ACK set");
    }
}

// ─── Empty frames specifics ─────────────────────────────────────────

#[test]
fn empty_frames_data_frames_have_zero_payload() {
    let config = H2AttackConfig::default().with_frame_count(10);
    let payload = generate_empty_frames(&config);
    for frame in payload.frames.iter().skip(1) {
        assert_eq!(parse_payload_length(frame), Some(0));
        assert_eq!(frame.len(), 9);
    }
}

#[test]
fn empty_frames_first_frame_is_headers() {
    let config = H2AttackConfig::default().with_frame_count(5);
    let payload = generate_empty_frames(&config);
    assert_eq!(parse_frame_type(&payload.frames[0]), Some(0x1));
}

// ─── HPACK bombing specifics ────────────────────────────────────────

#[test]
fn hpack_bombing_last_frame_has_end_headers() {
    let config = H2AttackConfig::default().with_frame_count(5);
    let payload = generate_hpack_bombing(&config);
    let last = payload.frames.last().unwrap();
    let flags = parse_frame_flags(last).unwrap();
    assert_ne!(flags & 0x4, 0, "Last frame should have END_HEADERS");
}

#[test]
fn hpack_bombing_payload_exceeds_minimum_size() {
    let config = H2AttackConfig::default()
        .with_frame_count(3)
        .with_payload_size(512);
    let payload = generate_hpack_bombing(&config);
    for frame in &payload.frames {
        assert!(frame.len() > 9, "Frames must have non-trivial payload");
    }
}

// ─── Config and stealth integration ─────────────────────────────────

#[test]
fn stealth_paranoid_reduces_frame_count() {
    let base = H2AttackConfig::default().with_frame_count(1000);
    let stealth = H2AttackConfig::default()
        .with_frame_count(1000)
        .with_stealth(StealthConfig::paranoid());

    let base_payload = generate_ping_flood(&base);
    let stealth_payload = generate_ping_flood(&stealth);

    assert!(
        stealth_payload.frames.len() < base_payload.frames.len(),
        "Paranoid stealth should generate fewer frames"
    );
}

#[test]
fn stealth_aggressive_partial_reduction() {
    let config = H2AttackConfig::default()
        .with_frame_count(100)
        .with_stealth(StealthConfig::aggressive());
    let payload = generate_settings_flood(&config);
    assert_eq!(payload.frames.len(), 60);
}

#[test]
fn stealth_paranoid_10_percent() {
    let config = H2AttackConfig::default()
        .with_frame_count(100)
        .with_stealth(StealthConfig::paranoid());
    let payload = generate_settings_flood(&config);
    assert_eq!(payload.frames.len(), 10);
}

#[test]
fn stealth_default_40_percent() {
    let config = H2AttackConfig::default()
        .with_frame_count(100)
        .with_stealth(StealthConfig::default());
    let payload = generate_settings_flood(&config);
    assert_eq!(payload.frames.len(), 40);
}

#[test]
fn inter_frame_delay_zero_without_stealth() {
    let config = H2AttackConfig::default();
    let payload = generate_ping_flood(&config);
    assert_eq!(payload.inter_frame_delay_us, 0);
}

#[test]
fn inter_frame_delay_nonzero_with_stealth() {
    let config = H2AttackConfig::default().with_stealth(StealthConfig::default());
    let payload = generate_ping_flood(&config);
    assert!(payload.inter_frame_delay_us > 0);
}

// ─── generate_all_attacks & dispatch ────────────────────────────────

#[test]
fn generate_all_produces_six_attack_types() {
    let config = H2AttackConfig::default().with_frame_count(5);
    let attacks = generate_all_attacks(&config);
    assert_eq!(attacks.len(), 6);
    let types: Vec<_> = attacks.iter().map(|a| a.attack_type).collect();
    assert!(types.contains(&H2AttackType::ContinuationFlood));
    assert!(types.contains(&H2AttackType::RapidReset));
    assert!(types.contains(&H2AttackType::SettingsFlood));
    assert!(types.contains(&H2AttackType::PingFlood));
    assert!(types.contains(&H2AttackType::EmptyFrames));
    assert!(types.contains(&H2AttackType::HpackBombing));
}

#[test]
fn generate_attack_dispatches_correctly() {
    let config = H2AttackConfig::default().with_frame_count(3);
    for at in all_attack_types() {
        let payload = generate_attack(at, &config);
        assert_eq!(payload.attack_type, at);
    }
}

#[test]
fn all_attack_types_returns_six() {
    assert_eq!(all_attack_types().len(), 6);
}

// ─── Total bytes accounting ─────────────────────────────────────────

#[test]
fn total_bytes_matches_actual_frame_sum() {
    let config = H2AttackConfig::default().with_frame_count(10);
    for at in all_attack_types() {
        let payload = generate_attack(at, &config);
        let actual: usize = payload.frames.iter().map(|f| f.len()).sum();
        assert_eq!(payload.total_bytes, actual, "Mismatch for {:?}", at);
    }
}

// ─── Display / description ──────────────────────────────────────────

#[test]
fn attack_type_display_is_human_readable() {
    assert_eq!(
        format!("{}", H2AttackType::ContinuationFlood),
        "CONTINUATION Flood"
    );
    assert_eq!(
        format!("{}", H2AttackType::RapidReset),
        "Rapid Reset (CVE-2023-44487)"
    );
}

// ─── Config builder chain ───────────────────────────────────────────

#[test]
fn config_builder_chain_works() {
    let config = H2AttackConfig::default()
        .with_frame_count(500)
        .with_stream_id_start(3)
        .with_concurrency(20)
        .with_payload_size(1024);
    assert_eq!(config.frame_count, 500);
    assert_eq!(config.stream_id_start, 3);
    assert_eq!(config.concurrency, 20);
    assert_eq!(config.payload_size, 1024);
}

// ─── Edge case: minimal frame count ─────────────────────────────────

#[test]
fn frame_count_one_still_generates_valid_payload() {
    let config = H2AttackConfig::default().with_frame_count(1);
    for at in all_attack_types() {
        let payload = generate_attack(at, &config);
        assert!(!payload.frames.is_empty());
        assert!(payload.validate_frame_headers());
    }
}

#[test]
fn parse_helpers_return_none_for_short_buffer() {
    let short = vec![0u8; 3];
    assert_eq!(parse_frame_type(&short), None);
    assert_eq!(parse_stream_id(&short), None);
    assert_eq!(parse_frame_flags(&short), None);
    assert_eq!(parse_payload_length(&short), None);
}
