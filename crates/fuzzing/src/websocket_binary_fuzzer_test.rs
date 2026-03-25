use crate::websocket_binary_fuzzer::*;

#[test]
fn all_seven_attack_types_generated() {
    let config = WsBinaryFuzzConfig::default();
    let attacks = generate_all_ws_attacks(&config);
    assert_eq!(attacks.len(), 7);

    let types: Vec<WsFrameAttackType> = attacks.iter().map(|a| a.attack_type).collect();
    assert!(types.contains(&WsFrameAttackType::MalformedFrame));
    assert!(types.contains(&WsFrameAttackType::ControlFrameAbuse));
    assert!(types.contains(&WsFrameAttackType::MaskingAttack));
    assert!(types.contains(&WsFrameAttackType::ExtensionAbuse));
    assert!(types.contains(&WsFrameAttackType::BinaryProtocolFuzz));
    assert!(types.contains(&WsFrameAttackType::FrameInjection));
    assert!(types.contains(&WsFrameAttackType::UpgradeSmuggling));
}

#[test]
fn all_ws_attack_types_returns_seven() {
    let types = all_ws_attack_types();
    assert_eq!(types.len(), 7);
}

#[test]
fn malformed_frames_contain_reserved_opcodes() {
    let config = WsBinaryFuzzConfig::default();
    let payload = generate_malformed_frames(&config);
    assert_eq!(payload.attack_type, WsFrameAttackType::MalformedFrame);
    assert!(payload.frames.len() >= 5);

    for frame in &payload.frames[..5] {
        if let Some(opcode) = parse_ws_opcode(frame) {
            assert!(
                (0x3..=0x7).contains(&opcode) || opcode == 0x0F || opcode == 0x1 || opcode == 0x0,
                "unexpected opcode: {opcode:#x}"
            );
        }
    }
}

#[test]
fn malformed_frames_include_orphan_continuation() {
    let config = WsBinaryFuzzConfig::default();
    let payload = generate_malformed_frames(&config);

    let has_orphan = payload
        .frames
        .iter()
        .any(|f| parse_ws_opcode(f) == Some(0x0) && parse_ws_fin(f) == Some(true));
    assert!(has_orphan, "should contain orphan continuation frame");
}

#[test]
fn malformed_frames_include_truncated() {
    let config = WsBinaryFuzzConfig::default();
    let payload = generate_malformed_frames(&config);

    let has_truncated = payload.frames.iter().any(|f| f.len() == 4);
    assert!(has_truncated, "should contain a truncated frame");
}

#[test]
fn control_frame_abuse_generates_ping_flood() {
    let config = WsBinaryFuzzConfig::default().with_frame_count(50);
    let payload = generate_control_frame_abuse(&config);
    assert_eq!(payload.attack_type, WsFrameAttackType::ControlFrameAbuse);

    let ping_count = payload
        .frames
        .iter()
        .filter(|f| parse_ws_opcode(f) == Some(0x9))
        .count();
    assert!(
        ping_count >= 50,
        "expected at least 50 pings, got {ping_count}"
    );
}

#[test]
fn control_frame_abuse_oversized_close() {
    let config = WsBinaryFuzzConfig::default();
    let payload = generate_control_frame_abuse(&config);

    let close_frames: Vec<&Vec<u8>> = payload
        .frames
        .iter()
        .filter(|f| parse_ws_opcode(f) == Some(0x8))
        .collect();
    assert!(!close_frames.is_empty());

    let oversized = close_frames.iter().any(|f| {
        parse_ws_payload_length(f).map_or(false, |len| len > CONTROL_FRAME_MAX_PAYLOAD as u64)
    });
    assert!(oversized, "should contain oversized close frame");
}

const CONTROL_FRAME_MAX_PAYLOAD: usize = 125;

#[test]
fn masking_attacks_include_unmasked_frames() {
    let config = WsBinaryFuzzConfig::default();
    let payload = generate_masking_attacks(&config);
    assert_eq!(payload.attack_type, WsFrameAttackType::MaskingAttack);

    let unmasked_count = payload
        .frames
        .iter()
        .filter(|f| parse_ws_masked(f) == Some(false))
        .count();
    assert!(unmasked_count >= 2, "need at least 2 unmasked frames");
}

#[test]
fn masking_attacks_zero_key() {
    let config = WsBinaryFuzzConfig::default();
    let payload = generate_masking_attacks(&config);

    let has_zero_mask = payload.frames.iter().any(|f| {
        if parse_ws_masked(f) != Some(true) || f.len() < 6 {
            return false;
        }
        f[2] == 0 && f[3] == 0 && f[4] == 0 && f[5] == 0
    });
    assert!(has_zero_mask, "should contain frame with zero masking key");
}

#[test]
fn extension_abuse_sets_rsv_bits() {
    let config = WsBinaryFuzzConfig::default();
    let payload = generate_extension_abuse(&config);
    assert_eq!(payload.attack_type, WsFrameAttackType::ExtensionAbuse);

    let rsv_frames: Vec<u8> = payload
        .frames
        .iter()
        .filter_map(|f| parse_ws_rsv(f))
        .filter(|rsv| *rsv != 0)
        .collect();
    assert!(
        rsv_frames.len() >= 4,
        "need RSV1, RSV2, RSV3, and all-RSV frames"
    );
}

#[test]
fn extension_abuse_deflate_bomb_present() {
    let config = WsBinaryFuzzConfig::default();
    let payload = generate_extension_abuse(&config);

    let has_rsv1_binary = payload
        .frames
        .iter()
        .any(|f| parse_ws_rsv(f) == Some(0x40) && parse_ws_opcode(f) == Some(0x2));
    assert!(
        has_rsv1_binary,
        "should have RSV1 + binary frame for deflate bomb"
    );
}

#[test]
fn binary_protocol_fuzz_grpc_web_payload() {
    let config = WsBinaryFuzzConfig::default();
    let payload = generate_binary_protocol_fuzz(&config);
    assert_eq!(payload.attack_type, WsFrameAttackType::BinaryProtocolFuzz);

    let has_grpc = payload
        .frames
        .iter()
        .any(|f| f.len() > 10 && parse_ws_opcode(f) == Some(0x2));
    assert!(has_grpc, "should contain gRPC-Web binary frame");
}

#[test]
fn binary_protocol_fuzz_wasm_header() {
    let config = WsBinaryFuzzConfig::default();
    let payload = generate_binary_protocol_fuzz(&config);

    let wasm_magic = b"\x00asm";
    let has_wasm = payload.frames.iter().any(|f| {
        let header_len = if parse_ws_masked(f) == Some(true) {
            6
        } else {
            2
        };
        if f.len() <= header_len {
            return false;
        }
        let data = &f[header_len..];
        if parse_ws_masked(f) == Some(true) && f.len() >= 6 {
            let key = [f[2], f[3], f[4], f[5]];
            let unmasked: Vec<u8> = data
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key[i % 4])
                .collect();
            unmasked.len() >= 4 && &unmasked[..4] == wasm_magic
        } else {
            data.len() >= 4 && &data[..4] == wasm_magic
        }
    });
    assert!(has_wasm, "should contain WASM magic header payload");
}

#[test]
fn binary_protocol_fuzz_boundary_sizes() {
    let config = WsBinaryFuzzConfig::default();
    let payload = generate_binary_protocol_fuzz(&config);

    let has_empty = payload
        .frames
        .iter()
        .any(|f| parse_ws_payload_length(f) == Some(0) && parse_ws_opcode(f) == Some(0x2));
    assert!(has_empty, "should contain zero-length binary frame");
}

#[test]
fn frame_injection_crlf_smuggling() {
    let config = WsBinaryFuzzConfig::default();
    let payload = generate_frame_injection(&config);
    assert_eq!(payload.attack_type, WsFrameAttackType::FrameInjection);
    assert!(!payload.frames.is_empty());
}

#[test]
fn frame_injection_interleaved_frames() {
    let config = WsBinaryFuzzConfig::default().with_frame_count(10);
    let payload = generate_frame_injection(&config);

    assert!(payload.frames.len() >= 10, "should have interleaved frames");
}

#[test]
fn frame_injection_invalid_utf8() {
    let config = WsBinaryFuzzConfig::default();
    let payload = generate_frame_injection(&config);

    let has_invalid_utf8 = payload.frames.iter().any(|f| {
        if parse_ws_opcode(f) != Some(0x1) {
            return false;
        }
        let header_len = if parse_ws_masked(f) == Some(true) {
            6
        } else {
            2
        };
        if f.len() <= header_len {
            return false;
        }
        let data = &f[header_len..];
        std::str::from_utf8(data).is_err()
    });
    assert!(
        has_invalid_utf8,
        "should contain invalid UTF-8 in text frame"
    );
}

#[test]
fn upgrade_smuggling_request_variants() {
    let config = WsBinaryFuzzConfig::default();
    let payload = generate_upgrade_smuggling(&config);
    assert_eq!(payload.attack_type, WsFrameAttackType::UpgradeSmuggling);
    assert!(payload.frames.len() >= 5);

    let has_admin = payload
        .frames
        .iter()
        .any(|f| String::from_utf8_lossy(f).contains("/admin"));
    assert!(has_admin, "should contain /admin path injection");
}

#[test]
fn upgrade_smuggling_h2c_upgrade() {
    let config = WsBinaryFuzzConfig::default();
    let payload = generate_upgrade_smuggling(&config);

    let has_h2c = payload
        .frames
        .iter()
        .any(|f| String::from_utf8_lossy(f).contains("h2c"));
    assert!(has_h2c, "should contain h2c upgrade attempt");
}

#[test]
fn config_builder_pattern() {
    let config = WsBinaryFuzzConfig::default()
        .with_frame_count(50)
        .with_max_payload_size(1024)
        .with_masking(false)
        .with_masking_key([0x11, 0x22, 0x33, 0x44]);

    assert_eq!(config.frame_count, 50);
    assert_eq!(config.max_payload_size, 1024);
    assert!(!config.use_masking);
    assert_eq!(config.masking_key, [0x11, 0x22, 0x33, 0x44]);
}

#[test]
fn ws_attack_payload_validate_frame_headers() {
    let config = WsBinaryFuzzConfig::default();
    let payload = generate_malformed_frames(&config);

    let valid_count = payload.frames.iter().filter(|f| f.len() >= 2).count();
    assert!(
        valid_count >= payload.frames.len() - 1,
        "most frames should have valid headers"
    );
}

#[test]
fn generate_ws_attack_dispatch() {
    let config = WsBinaryFuzzConfig::default();
    for attack_type in all_ws_attack_types() {
        let payload = generate_ws_attack(attack_type, &config);
        assert_eq!(payload.attack_type, attack_type);
        assert!(!payload.frames.is_empty());
        assert!(payload.total_bytes > 0);
        assert!(!payload.description.is_empty());
    }
}

#[test]
fn score_ws_attack_ranges() {
    for attack_type in all_ws_attack_types() {
        let score = score_ws_attack(&attack_type);
        assert!(
            (0.0..=1.0).contains(&score),
            "score for {attack_type} should be in [0,1]: {score}"
        );
    }
}

#[test]
fn score_ws_attack_ordering() {
    assert!(
        score_ws_attack(&WsFrameAttackType::UpgradeSmuggling)
            > score_ws_attack(&WsFrameAttackType::FrameInjection)
    );
    assert!(
        score_ws_attack(&WsFrameAttackType::FrameInjection)
            > score_ws_attack(&WsFrameAttackType::BinaryProtocolFuzz)
    );
}

#[test]
fn ws_upgrade_headers_no_extensions() {
    let headers = ws_upgrade_headers_with_extensions(&[]);
    assert_eq!(headers.len(), 4);
    assert!(
        headers
            .iter()
            .any(|(k, v)| k == "Upgrade" && v == "websocket")
    );
    assert!(headers.iter().any(|(k, _)| k == "Sec-WebSocket-Key"));
}

#[test]
fn ws_upgrade_headers_with_deflate() {
    let headers = ws_upgrade_headers_with_extensions(&["permessage-deflate"]);
    assert_eq!(headers.len(), 5);
    let ext = headers
        .iter()
        .find(|(k, _)| k == "Sec-WebSocket-Extensions");
    assert!(ext.is_some());
    assert_eq!(ext.unwrap().1, "permessage-deflate");
}

#[test]
fn parse_ws_opcode_valid() {
    let frame = vec![0x81, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F];
    assert_eq!(parse_ws_opcode(&frame), Some(0x1));
}

#[test]
fn parse_ws_opcode_too_short() {
    assert_eq!(parse_ws_opcode(&[]), None);
    assert_eq!(parse_ws_opcode(&[0x81]), None);
}

#[test]
fn parse_ws_fin_set() {
    let frame = vec![0x81, 0x00];
    assert_eq!(parse_ws_fin(&frame), Some(true));
}

#[test]
fn parse_ws_fin_unset() {
    let frame = vec![0x01, 0x00];
    assert_eq!(parse_ws_fin(&frame), Some(false));
}

#[test]
fn parse_ws_masked_true() {
    let frame = vec![0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D];
    assert_eq!(parse_ws_masked(&frame), Some(true));
}

#[test]
fn parse_ws_masked_false() {
    let frame = vec![0x81, 0x05];
    assert_eq!(parse_ws_masked(&frame), Some(false));
}

#[test]
fn parse_ws_payload_length_small() {
    let frame = vec![0x81, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F];
    assert_eq!(parse_ws_payload_length(&frame), Some(5));
}

#[test]
fn parse_ws_payload_length_medium() {
    let frame = vec![0x81, 126, 0x01, 0x00];
    assert_eq!(parse_ws_payload_length(&frame), Some(256));
}

#[test]
fn parse_ws_payload_length_large() {
    let frame = vec![0x81, 127, 0, 0, 0, 0, 0, 1, 0, 0];
    assert_eq!(parse_ws_payload_length(&frame), Some(65536));
}

#[test]
fn attack_type_display() {
    assert_eq!(
        format!("{}", WsFrameAttackType::MalformedFrame),
        "Malformed WebSocket Frame"
    );
    assert_eq!(
        format!("{}", WsFrameAttackType::UpgradeSmuggling),
        "Upgrade Smuggling"
    );
}

#[test]
fn default_config_values() {
    let config = WsBinaryFuzzConfig::default();
    assert_eq!(config.frame_count, 100);
    assert_eq!(config.max_payload_size, 65536);
    assert!(config.use_masking);
    assert_eq!(config.masking_key, [0x37, 0xFA, 0x21, 0x3D]);
}

#[test]
fn total_bytes_consistent() {
    let config = WsBinaryFuzzConfig::default().with_frame_count(10);
    for attack_type in all_ws_attack_types() {
        let payload = generate_ws_attack(attack_type, &config);
        let computed: usize = payload.frames.iter().map(|f| f.len()).sum();
        assert_eq!(
            payload.total_bytes, computed,
            "total_bytes mismatch for {attack_type}"
        );
    }
}

#[test]
fn parse_ws_rsv_bits() {
    let frame = vec![0x41, 0x00];
    assert_eq!(parse_ws_rsv(&frame), Some(0x40));

    let frame2 = vec![0x81, 0x00];
    assert_eq!(parse_ws_rsv(&frame2), Some(0x00));
}
