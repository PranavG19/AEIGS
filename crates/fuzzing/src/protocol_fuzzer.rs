use rand::Rng;

/// Layer of the network stack being fuzzed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolLayer {
    Http1,
    Http2,
    WebSocket,
    Tls,
}

/// A single fuzzed protocol message ready for transmission.
#[derive(Debug, Clone)]
pub struct FuzzedMessage {
    pub layer: ProtocolLayer,
    pub raw_bytes: Vec<u8>,
    pub description: String,
    pub mutation_applied: ProtocolMutation,
}

/// The specific mutation applied to produce a fuzzed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolMutation {
    MalformedRequestLine,
    InvalidVersion,
    ChunkedEncodingAbuse,
    HeaderLineFolding,
    ContentLengthConflict,
    NullByteInjection,
    OversizedHeader,
    InvalidFrameType,
    FrameOrderViolation,
    HpackBomb,
    StreamIdCollision,
    SettingsFlood,
    WindowUpdateOverflow,
    FragmentAbuse,
    ControlFramePayload,
    MaskedServerFrame,
    ReservedOpcodeUse,
    PingFlood,
    VersionConfusion,
    MalformedRecord,
    TruncatedHandshake,
    RecordOverflow,
    CipherSuiteMismatch,
}

/// Grammar-aware protocol fuzzer that generates valid-ish protocol messages
/// designed to probe parser edge cases in HTTP/1.1, HTTP/2, WebSocket, and TLS.
pub struct ProtocolFuzzer {
    layers: Vec<ProtocolLayer>,
    max_payload_size: usize,
}

impl ProtocolFuzzer {
    pub fn new() -> Self {
        Self {
            layers: vec![
                ProtocolLayer::Http1,
                ProtocolLayer::Http2,
                ProtocolLayer::WebSocket,
                ProtocolLayer::Tls,
            ],
            max_payload_size: 65536,
        }
    }

    pub fn with_layers(mut self, layers: Vec<ProtocolLayer>) -> Self {
        self.layers = layers;
        self
    }

    pub fn with_max_payload_size(mut self, size: usize) -> Self {
        self.max_payload_size = size;
        self
    }

    /// Generate a batch of fuzzed messages across all configured layers.
    pub fn generate_batch(&self, count_per_layer: usize) -> Vec<FuzzedMessage> {
        let mut messages = Vec::new();
        for layer in &self.layers {
            let generators = generators_for_layer(*layer);
            for (idx, generator) in generators.iter().enumerate() {
                if idx >= count_per_layer {
                    break;
                }
                messages.push(generator(self.max_payload_size));
            }
        }
        messages
    }

    /// Generate fuzzed messages for a specific protocol layer.
    pub fn generate_for_layer(&self, layer: ProtocolLayer, count: usize) -> Vec<FuzzedMessage> {
        let generators = generators_for_layer(layer);
        generators
            .iter()
            .take(count)
            .map(|generator| generator(self.max_payload_size))
            .collect()
    }

    pub fn configured_layers(&self) -> &[ProtocolLayer] {
        &self.layers
    }
}

impl Default for ProtocolFuzzer {
    fn default() -> Self {
        Self::new()
    }
}

type MessageGenerator = fn(usize) -> FuzzedMessage;

fn generators_for_layer(layer: ProtocolLayer) -> Vec<MessageGenerator> {
    match layer {
        ProtocolLayer::Http1 => vec![
            gen_malformed_request_line,
            gen_invalid_http_version,
            gen_chunked_encoding_abuse,
            gen_header_line_folding,
            gen_content_length_conflict,
            gen_null_byte_injection,
            gen_oversized_header,
        ],
        ProtocolLayer::Http2 => vec![
            gen_invalid_frame_type,
            gen_frame_order_violation,
            gen_hpack_bomb,
            gen_stream_id_collision,
            gen_settings_flood,
            gen_window_update_overflow,
        ],
        ProtocolLayer::WebSocket => vec![
            gen_fragment_abuse,
            gen_control_frame_payload,
            gen_masked_server_frame,
            gen_reserved_opcode,
            gen_ping_flood,
        ],
        ProtocolLayer::Tls => vec![
            gen_version_confusion,
            gen_malformed_tls_record,
            gen_truncated_handshake,
            gen_record_overflow,
            gen_cipher_suite_mismatch,
        ],
    }
}

fn gen_malformed_request_line(_max_size: usize) -> FuzzedMessage {
    let payloads = [
        "G\x00ET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET  /  HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET / HTTP/1.1 extra\r\nHost: localhost\r\n\r\n",
        " GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET\t/\tHTTP/1.1\r\nHost: localhost\r\n\r\n",
        "\r\nGET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ];
    let mut rng = rand::rng();
    let chosen = payloads[rng.random_range(0..payloads.len())];
    FuzzedMessage {
        layer: ProtocolLayer::Http1,
        raw_bytes: chosen.as_bytes().to_vec(),
        description: "Malformed HTTP/1.1 request line with illegal characters or spacing"
            .to_string(),
        mutation_applied: ProtocolMutation::MalformedRequestLine,
    }
}

fn gen_invalid_http_version(_max_size: usize) -> FuzzedMessage {
    let payloads = [
        "GET / HTTP/0.9\r\nHost: localhost\r\n\r\n",
        "GET / HTTP/2.0\r\nHost: localhost\r\n\r\n",
        "GET / HTTP/1.2\r\nHost: localhost\r\n\r\n",
        "GET / HTTP/3.0\r\nHost: localhost\r\n\r\n",
        "GET / HTTP/9.9\r\nHost: localhost\r\n\r\n",
        "GET / HTTP/1.10\r\nHost: localhost\r\n\r\n",
    ];
    let mut rng = rand::rng();
    let chosen = payloads[rng.random_range(0..payloads.len())];
    FuzzedMessage {
        layer: ProtocolLayer::Http1,
        raw_bytes: chosen.as_bytes().to_vec(),
        description: "HTTP request with invalid or unusual version number".to_string(),
        mutation_applied: ProtocolMutation::InvalidVersion,
    }
}

fn gen_chunked_encoding_abuse(_max_size: usize) -> FuzzedMessage {
    let payload = concat!(
        "POST /api/data HTTP/1.1\r\n",
        "Host: localhost\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "ffffffff\r\n",
        "A\r\n",
        "0\r\n",
        "\r\n",
    );
    FuzzedMessage {
        layer: ProtocolLayer::Http1,
        raw_bytes: payload.as_bytes().to_vec(),
        description: "Chunked transfer encoding with oversized chunk declaration".to_string(),
        mutation_applied: ProtocolMutation::ChunkedEncodingAbuse,
    }
}

fn gen_header_line_folding(_max_size: usize) -> FuzzedMessage {
    let payload = concat!(
        "GET / HTTP/1.1\r\n",
        "Host: localhost\r\n",
        "X-Custom: value\r\n",
        " continuation-of-header\r\n",
        "\tcontinuation-with-tab\r\n",
        "\r\n",
    );
    FuzzedMessage {
        layer: ProtocolLayer::Http1,
        raw_bytes: payload.as_bytes().to_vec(),
        description: "HTTP/1.1 header line folding (deprecated in RFC 7230)".to_string(),
        mutation_applied: ProtocolMutation::HeaderLineFolding,
    }
}

fn gen_content_length_conflict(_max_size: usize) -> FuzzedMessage {
    let payload = concat!(
        "POST /api/data HTTP/1.1\r\n",
        "Host: localhost\r\n",
        "Content-Length: 5\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "0\r\n",
        "\r\n",
    );
    FuzzedMessage {
        layer: ProtocolLayer::Http1,
        raw_bytes: payload.as_bytes().to_vec(),
        description: "Conflicting Content-Length and Transfer-Encoding headers (CL.TE smuggling)"
            .to_string(),
        mutation_applied: ProtocolMutation::ContentLengthConflict,
    }
}

fn gen_null_byte_injection(_max_size: usize) -> FuzzedMessage {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"GET /path");
    payload.push(0x00);
    payload.extend_from_slice(b".txt HTTP/1.1\r\nHost: localhost\r\n\r\n");
    FuzzedMessage {
        layer: ProtocolLayer::Http1,
        raw_bytes: payload,
        description: "Null byte injected into request path".to_string(),
        mutation_applied: ProtocolMutation::NullByteInjection,
    }
}

fn gen_oversized_header(max_size: usize) -> FuzzedMessage {
    let header_size = max_size.min(32768);
    let mut payload = Vec::new();
    payload.extend_from_slice(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Large: ");
    payload.extend(std::iter::repeat(b'A').take(header_size));
    payload.extend_from_slice(b"\r\n\r\n");
    FuzzedMessage {
        layer: ProtocolLayer::Http1,
        raw_bytes: payload,
        description: "HTTP header exceeding typical server limits".to_string(),
        mutation_applied: ProtocolMutation::OversizedHeader,
    }
}

fn gen_invalid_frame_type(_max_size: usize) -> FuzzedMessage {
    let mut frame = Vec::new();
    frame.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    frame.extend_from_slice(&[0, 0, 0]);
    frame.push(0xFF);
    frame.push(0x00);
    frame.extend_from_slice(&[0, 0, 0, 1]);
    FuzzedMessage {
        layer: ProtocolLayer::Http2,
        raw_bytes: frame,
        description: "HTTP/2 frame with invalid frame type 0xFF".to_string(),
        mutation_applied: ProtocolMutation::InvalidFrameType,
    }
}

fn gen_frame_order_violation(_max_size: usize) -> FuzzedMessage {
    let mut frames = Vec::new();
    frames.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    frames.extend_from_slice(&[0, 0, 5]);
    frames.push(0x01);
    frames.push(0x04);
    frames.extend_from_slice(&[0, 0, 0, 1]);
    frames.extend_from_slice(b"hello");
    frames.extend_from_slice(&[0, 0, 0]);
    frames.push(0x04);
    frames.push(0x00);
    frames.extend_from_slice(&[0, 0, 0, 0]);
    FuzzedMessage {
        layer: ProtocolLayer::Http2,
        raw_bytes: frames,
        description: "HTTP/2 HEADERS frame sent before SETTINGS, violating connection preface"
            .to_string(),
        mutation_applied: ProtocolMutation::FrameOrderViolation,
    }
}

fn gen_hpack_bomb(_max_size: usize) -> FuzzedMessage {
    let mut frame = Vec::new();
    frame.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    let hpack_data: Vec<u8> = (0..256)
        .flat_map(|_| vec![0x00, 0x85, 0xf2, 0xb2, 0x4a, 0x84, 0xff])
        .collect();
    let len = hpack_data.len();
    frame.push(((len >> 16) & 0xFF) as u8);
    frame.push(((len >> 8) & 0xFF) as u8);
    frame.push((len & 0xFF) as u8);
    frame.push(0x01);
    frame.push(0x04);
    frame.extend_from_slice(&[0, 0, 0, 1]);
    frame.extend_from_slice(&hpack_data);
    FuzzedMessage {
        layer: ProtocolLayer::Http2,
        raw_bytes: frame,
        description: "HPACK bomb: large compressed headers that expand significantly".to_string(),
        mutation_applied: ProtocolMutation::HpackBomb,
    }
}

fn gen_stream_id_collision(_max_size: usize) -> FuzzedMessage {
    let mut frames = Vec::new();
    frames.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    for _ in 0..2 {
        frames.extend_from_slice(&[0, 0, 5]);
        frames.push(0x01);
        frames.push(0x04);
        frames.extend_from_slice(&[0, 0, 0, 1]);
        frames.extend_from_slice(b"hello");
    }
    FuzzedMessage {
        layer: ProtocolLayer::Http2,
        raw_bytes: frames,
        description: "Two HTTP/2 HEADERS frames reusing same stream ID 1".to_string(),
        mutation_applied: ProtocolMutation::StreamIdCollision,
    }
}

fn gen_settings_flood(_max_size: usize) -> FuzzedMessage {
    let mut frames = Vec::new();
    frames.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    for _ in 0..1000 {
        frames.extend_from_slice(&[0, 0, 6]);
        frames.push(0x04);
        frames.push(0x00);
        frames.extend_from_slice(&[0, 0, 0, 0]);
        frames.extend_from_slice(&[0x00, 0x03, 0x00, 0x00, 0x00, 0x64]);
    }
    FuzzedMessage {
        layer: ProtocolLayer::Http2,
        raw_bytes: frames,
        description: "SETTINGS frame flood: 1000 rapid SETTINGS frames".to_string(),
        mutation_applied: ProtocolMutation::SettingsFlood,
    }
}

fn gen_window_update_overflow(_max_size: usize) -> FuzzedMessage {
    let mut frame = Vec::new();
    frame.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    frame.extend_from_slice(&[0, 0, 4]);
    frame.push(0x08);
    frame.push(0x00);
    frame.extend_from_slice(&[0, 0, 0, 0]);
    frame.extend_from_slice(&[0x7F, 0xFF, 0xFF, 0xFF]);
    FuzzedMessage {
        layer: ProtocolLayer::Http2,
        raw_bytes: frame,
        description: "WINDOW_UPDATE with maximum increment to overflow flow control window"
            .to_string(),
        mutation_applied: ProtocolMutation::WindowUpdateOverflow,
    }
}

fn gen_fragment_abuse(_max_size: usize) -> FuzzedMessage {
    let mut frames = Vec::new();
    frames.push(0x01);
    frames.extend_from_slice(&[0, 3]);
    frames.push(0x80);
    frames.extend_from_slice(b"hel");
    frames.push(0x80);
    frames.extend_from_slice(&[0, 2]);
    frames.push(0x80);
    frames.extend_from_slice(b"lo");
    FuzzedMessage {
        layer: ProtocolLayer::WebSocket,
        raw_bytes: frames,
        description: "WebSocket message split into tiny fragments to probe reassembly".to_string(),
        mutation_applied: ProtocolMutation::FragmentAbuse,
    }
}

fn gen_control_frame_payload(_max_size: usize) -> FuzzedMessage {
    let mut frame = Vec::new();
    frame.push(0x89);
    frame.push(126);
    let payload_len: u16 = 200;
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend(std::iter::repeat(b'P').take(200));
    FuzzedMessage {
        layer: ProtocolLayer::WebSocket,
        raw_bytes: frame,
        description: "WebSocket ping frame with oversized payload (>125 bytes violates RFC 6455)"
            .to_string(),
        mutation_applied: ProtocolMutation::ControlFramePayload,
    }
}

fn gen_masked_server_frame(_max_size: usize) -> FuzzedMessage {
    let payload = b"server data";
    let mut frame = Vec::new();
    frame.push(0x81);
    frame.push(0x80 | payload.len() as u8);
    let mask: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];
    frame.extend_from_slice(&mask);
    for (i, byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask[i % 4]);
    }
    FuzzedMessage {
        layer: ProtocolLayer::WebSocket,
        raw_bytes: frame,
        description: "Server-to-client WebSocket frame with masking bit set (illegal per spec)"
            .to_string(),
        mutation_applied: ProtocolMutation::MaskedServerFrame,
    }
}

fn gen_reserved_opcode(_max_size: usize) -> FuzzedMessage {
    let mut frame = Vec::new();
    frame.push(0x80 | 0x0B);
    frame.push(0x05);
    frame.extend_from_slice(b"hello");
    FuzzedMessage {
        layer: ProtocolLayer::WebSocket,
        raw_bytes: frame,
        description: "WebSocket frame using reserved opcode 0x0B".to_string(),
        mutation_applied: ProtocolMutation::ReservedOpcodeUse,
    }
}

fn gen_ping_flood(_max_size: usize) -> FuzzedMessage {
    let mut frames = Vec::new();
    for i in 0..500u16 {
        frames.push(0x89);
        frames.push(0x02);
        frames.extend_from_slice(&i.to_be_bytes());
    }
    FuzzedMessage {
        layer: ProtocolLayer::WebSocket,
        raw_bytes: frames,
        description: "500 rapid WebSocket ping frames to trigger pong amplification".to_string(),
        mutation_applied: ProtocolMutation::PingFlood,
    }
}

fn gen_version_confusion(_max_size: usize) -> FuzzedMessage {
    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x04, 0x01]);
    let payload = [0x01, 0x00, 0x00, 0x05, 0x04, 0x01];
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(&payload);
    FuzzedMessage {
        layer: ProtocolLayer::Tls,
        raw_bytes: record,
        description: "TLS record claiming version 4.1 (nonexistent)".to_string(),
        mutation_applied: ProtocolMutation::VersionConfusion,
    }
}

fn gen_malformed_tls_record(_max_size: usize) -> FuzzedMessage {
    let mut record = Vec::new();
    record.push(0xFF);
    record.extend_from_slice(&[0x03, 0x03]);
    let payload = [0x00; 10];
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(&payload);
    FuzzedMessage {
        layer: ProtocolLayer::Tls,
        raw_bytes: record,
        description: "TLS record with invalid content type 0xFF".to_string(),
        mutation_applied: ProtocolMutation::MalformedRecord,
    }
}

fn gen_truncated_handshake(_max_size: usize) -> FuzzedMessage {
    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x03]);
    record.extend_from_slice(&[0x00, 0x20]);
    record.push(0x01);
    record.extend_from_slice(&[0x00, 0x00, 0x1C]);
    record.extend_from_slice(&[0x03, 0x03]);
    record.extend_from_slice(&[0x00; 5]);
    FuzzedMessage {
        layer: ProtocolLayer::Tls,
        raw_bytes: record,
        description: "TLS ClientHello truncated mid-handshake (declared 32 bytes, sent 11)"
            .to_string(),
        mutation_applied: ProtocolMutation::TruncatedHandshake,
    }
}

fn gen_record_overflow(_max_size: usize) -> FuzzedMessage {
    let mut record = Vec::new();
    record.push(0x17);
    record.extend_from_slice(&[0x03, 0x03]);
    record.extend_from_slice(&[0xFF, 0xFF]);
    let payload_size = _max_size.min(16384);
    record.extend(std::iter::repeat(b'X').take(payload_size));
    FuzzedMessage {
        layer: ProtocolLayer::Tls,
        raw_bytes: record,
        description: "TLS application data record claiming 65535 bytes (exceeds 2^14 limit)"
            .to_string(),
        mutation_applied: ProtocolMutation::RecordOverflow,
    }
}

fn gen_cipher_suite_mismatch(_max_size: usize) -> FuzzedMessage {
    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x03]);
    let mut hello = Vec::new();
    hello.push(0x01);
    hello.extend_from_slice(&[0x00, 0x00, 0x00]);
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&[0x00; 32]);
    hello.push(0x00);
    hello.extend_from_slice(&[0x00, 0x04]);
    hello.extend_from_slice(&[0x00, 0xFF, 0x00, 0xFE]);
    hello.extend_from_slice(&[0x01, 0x00]);
    hello.extend_from_slice(&[0x00, 0x00]);
    let hello_len = hello.len();
    hello[2] = ((hello_len - 4) >> 8) as u8;
    hello[3] = ((hello_len - 4) & 0xFF) as u8;
    record.extend_from_slice(&(hello_len as u16).to_be_bytes());
    record.extend_from_slice(&hello);
    FuzzedMessage {
        layer: ProtocolLayer::Tls,
        raw_bytes: record,
        description: "TLS ClientHello with non-existent cipher suites 0x00FF and 0x00FE"
            .to_string(),
        mutation_applied: ProtocolMutation::CipherSuiteMismatch,
    }
}
