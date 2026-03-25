use crate::protocol_fuzzer::{FuzzedMessage, ProtocolFuzzer, ProtocolLayer, ProtocolMutation};

#[test]
fn default_generates_all_layers() {
    let fuzzer = ProtocolFuzzer::new();
    assert_eq!(fuzzer.configured_layers().len(), 4);
}

#[test]
fn generate_batch_produces_messages_for_all_layers() {
    let fuzzer = ProtocolFuzzer::new();
    let batch = fuzzer.generate_batch(3);
    assert!(!batch.is_empty());
    let layers: Vec<ProtocolLayer> = batch.iter().map(|m| m.layer).collect();
    assert!(layers.contains(&ProtocolLayer::Http1));
    assert!(layers.contains(&ProtocolLayer::Http2));
    assert!(layers.contains(&ProtocolLayer::WebSocket));
    assert!(layers.contains(&ProtocolLayer::Tls));
}

#[test]
fn generate_for_http1_only() {
    let fuzzer = ProtocolFuzzer::new().with_layers(vec![ProtocolLayer::Http1]);
    let messages = fuzzer.generate_for_layer(ProtocolLayer::Http1, 10);
    assert!(!messages.is_empty());
    for msg in &messages {
        assert_eq!(msg.layer, ProtocolLayer::Http1);
        assert!(!msg.raw_bytes.is_empty());
        assert!(!msg.description.is_empty());
    }
}

#[test]
fn http1_malformed_request_line() {
    let fuzzer = ProtocolFuzzer::new();
    let messages = fuzzer.generate_for_layer(ProtocolLayer::Http1, 1);
    assert!(!messages.is_empty());
    let msg = &messages[0];
    assert_eq!(msg.mutation_applied, ProtocolMutation::MalformedRequestLine);
    assert!(msg.raw_bytes.len() > 5);
}

#[test]
fn http1_all_mutations_covered() {
    let fuzzer = ProtocolFuzzer::new();
    let messages = fuzzer.generate_for_layer(ProtocolLayer::Http1, 20);
    let mutations: Vec<ProtocolMutation> = messages.iter().map(|m| m.mutation_applied).collect();
    assert!(mutations.contains(&ProtocolMutation::MalformedRequestLine));
    assert!(mutations.contains(&ProtocolMutation::InvalidVersion));
    assert!(mutations.contains(&ProtocolMutation::ChunkedEncodingAbuse));
    assert!(mutations.contains(&ProtocolMutation::HeaderLineFolding));
    assert!(mutations.contains(&ProtocolMutation::ContentLengthConflict));
    assert!(mutations.contains(&ProtocolMutation::NullByteInjection));
    assert!(mutations.contains(&ProtocolMutation::OversizedHeader));
}

#[test]
fn http2_all_mutations_covered() {
    let fuzzer = ProtocolFuzzer::new();
    let messages = fuzzer.generate_for_layer(ProtocolLayer::Http2, 20);
    let mutations: Vec<ProtocolMutation> = messages.iter().map(|m| m.mutation_applied).collect();
    assert!(mutations.contains(&ProtocolMutation::InvalidFrameType));
    assert!(mutations.contains(&ProtocolMutation::FrameOrderViolation));
    assert!(mutations.contains(&ProtocolMutation::HpackBomb));
    assert!(mutations.contains(&ProtocolMutation::StreamIdCollision));
    assert!(mutations.contains(&ProtocolMutation::SettingsFlood));
    assert!(mutations.contains(&ProtocolMutation::WindowUpdateOverflow));
}

#[test]
fn websocket_all_mutations_covered() {
    let fuzzer = ProtocolFuzzer::new();
    let messages = fuzzer.generate_for_layer(ProtocolLayer::WebSocket, 20);
    let mutations: Vec<ProtocolMutation> = messages.iter().map(|m| m.mutation_applied).collect();
    assert!(mutations.contains(&ProtocolMutation::FragmentAbuse));
    assert!(mutations.contains(&ProtocolMutation::ControlFramePayload));
    assert!(mutations.contains(&ProtocolMutation::MaskedServerFrame));
    assert!(mutations.contains(&ProtocolMutation::ReservedOpcodeUse));
    assert!(mutations.contains(&ProtocolMutation::PingFlood));
}

#[test]
fn tls_all_mutations_covered() {
    let fuzzer = ProtocolFuzzer::new();
    let messages = fuzzer.generate_for_layer(ProtocolLayer::Tls, 20);
    let mutations: Vec<ProtocolMutation> = messages.iter().map(|m| m.mutation_applied).collect();
    assert!(mutations.contains(&ProtocolMutation::VersionConfusion));
    assert!(mutations.contains(&ProtocolMutation::MalformedRecord));
    assert!(mutations.contains(&ProtocolMutation::TruncatedHandshake));
    assert!(mutations.contains(&ProtocolMutation::RecordOverflow));
    assert!(mutations.contains(&ProtocolMutation::CipherSuiteMismatch));
}

#[test]
fn max_payload_size_respected_for_oversized_header() {
    let fuzzer = ProtocolFuzzer::new().with_max_payload_size(1024);
    let messages = fuzzer.generate_for_layer(ProtocolLayer::Http1, 20);
    for msg in &messages {
        if msg.mutation_applied == ProtocolMutation::OversizedHeader {
            assert!(msg.raw_bytes.len() < 2048);
        }
    }
}

#[test]
fn batch_count_limits_per_layer() {
    let fuzzer = ProtocolFuzzer::new();
    let batch = fuzzer.generate_batch(2);
    let http1_count = batch
        .iter()
        .filter(|m| m.layer == ProtocolLayer::Http1)
        .count();
    assert!(http1_count <= 2);
}

#[test]
fn chunked_encoding_abuse_contains_transfer_encoding() {
    let fuzzer = ProtocolFuzzer::new();
    let messages = fuzzer.generate_for_layer(ProtocolLayer::Http1, 10);
    let chunked = messages
        .iter()
        .find(|m| m.mutation_applied == ProtocolMutation::ChunkedEncodingAbuse)
        .unwrap();
    let text = String::from_utf8_lossy(&chunked.raw_bytes);
    assert!(text.contains("Transfer-Encoding: chunked"));
}

#[test]
fn content_length_conflict_has_both_headers() {
    let fuzzer = ProtocolFuzzer::new();
    let messages = fuzzer.generate_for_layer(ProtocolLayer::Http1, 10);
    let conflict = messages
        .iter()
        .find(|m| m.mutation_applied == ProtocolMutation::ContentLengthConflict)
        .unwrap();
    let text = String::from_utf8_lossy(&conflict.raw_bytes);
    assert!(text.contains("Content-Length:"));
    assert!(text.contains("Transfer-Encoding:"));
}

#[test]
fn settings_flood_has_many_frames() {
    let fuzzer = ProtocolFuzzer::new();
    let messages = fuzzer.generate_for_layer(ProtocolLayer::Http2, 10);
    let flood = messages
        .iter()
        .find(|m| m.mutation_applied == ProtocolMutation::SettingsFlood)
        .unwrap();
    assert!(flood.raw_bytes.len() > 5000);
}

#[test]
fn ping_flood_generates_many_frames() {
    let fuzzer = ProtocolFuzzer::new();
    let messages = fuzzer.generate_for_layer(ProtocolLayer::WebSocket, 10);
    let flood = messages
        .iter()
        .find(|m| m.mutation_applied == ProtocolMutation::PingFlood)
        .unwrap();
    assert!(flood.raw_bytes.len() > 500);
}

#[test]
fn tls_version_confusion_has_bogus_version() {
    let fuzzer = ProtocolFuzzer::new();
    let messages = fuzzer.generate_for_layer(ProtocolLayer::Tls, 10);
    let confusion = messages
        .iter()
        .find(|m| m.mutation_applied == ProtocolMutation::VersionConfusion)
        .unwrap();
    assert_eq!(confusion.raw_bytes[1], 0x04);
    assert_eq!(confusion.raw_bytes[2], 0x01);
}

#[test]
fn default_trait_works() {
    let fuzzer = ProtocolFuzzer::default();
    assert_eq!(fuzzer.configured_layers().len(), 4);
}

#[test]
fn each_message_has_nonempty_description() {
    let fuzzer = ProtocolFuzzer::new();
    let batch = fuzzer.generate_batch(10);
    for msg in &batch {
        assert!(!msg.description.is_empty());
    }
}

#[test]
fn each_message_has_nonempty_bytes() {
    let fuzzer = ProtocolFuzzer::new();
    let batch = fuzzer.generate_batch(10);
    for msg in &batch {
        assert!(!msg.raw_bytes.is_empty());
    }
}
