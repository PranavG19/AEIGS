use crate::hpack_bomb_v2::*;

// ─── Config builder ─────────────────────────────────────────────────

#[test]
fn config_builder_chain_works() {
    let config = HpackBombConfig::default()
        .with_target_expansion_ratio(200)
        .with_max_frame_size(32768)
        .with_dynamic_table_size(8192);
    assert_eq!(config.target_expansion_ratio, 200);
    assert_eq!(config.max_frame_size, 32768);
    assert_eq!(config.dynamic_table_size, 8192);
}

#[test]
fn config_default_values() {
    let config = HpackBombConfig::default();
    assert_eq!(config.target_expansion_ratio, 100);
    assert_eq!(config.max_frame_size, 16_384);
    assert_eq!(config.dynamic_table_size, 4096);
}

// ─── Huffman bomb ───────────────────────────────────────────────────

#[test]
fn huffman_bomb_expansion_ratio_exceeds_threshold() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let target = 100_000;
    let compressed = bomb.generate_huffman_bomb(target);
    let ratio = bomb.calculate_expansion_ratio(&compressed, target);
    assert!(
        ratio > 1.0,
        "Huffman bomb must expand: compressed={}, target={}, ratio={}",
        compressed.len(),
        target,
        ratio
    );
}

#[test]
fn huffman_bomb_compressed_smaller_than_target() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let target = 50_000;
    let compressed = bomb.generate_huffman_bomb(target);
    assert!(
        compressed.len() < target,
        "Compressed ({}) must be smaller than decompressed target ({})",
        compressed.len(),
        target
    );
}

#[test]
fn huffman_bomb_nonempty_output() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let compressed = bomb.generate_huffman_bomb(1024);
    assert!(!compressed.is_empty());
}

#[test]
fn huffman_bomb_starts_with_incremental_indexing() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let compressed = bomb.generate_huffman_bomb(256);
    assert_eq!(
        compressed[0], 0x40,
        "First byte must be 0x40 (literal with incremental indexing)"
    );
}

// ─── Table exhaustion ───────────────────────────────────────────────

#[test]
fn table_exhaustion_fills_to_limit() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let table_size = 4096;
    let blocks = bomb.generate_table_exhaustion(table_size);
    assert!(!blocks.is_empty(), "Must produce at least one block");

    let mut total_entry_size = 0usize;
    for (i, block) in blocks.iter().enumerate() {
        assert_eq!(block[0], 0x40, "Block {} must use incremental indexing", i);
        total_entry_size += estimate_entry_size_from_block(block);
    }
    assert!(
        total_entry_size >= table_size,
        "Total entry size ({}) must fill the table ({})",
        total_entry_size,
        table_size
    );
}

#[test]
fn table_exhaustion_each_block_is_valid_hpack() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let blocks = bomb.generate_table_exhaustion(2048);
    for block in &blocks {
        assert!(!block.is_empty());
        assert_eq!(block[0], 0x40);
    }
}

#[test]
fn table_exhaustion_larger_table() {
    let bomb = HpackBombV2::new(HpackBombConfig::default().with_dynamic_table_size(16384));
    let blocks = bomb.generate_table_exhaustion(16384);
    assert!(
        blocks.len() > 1,
        "Large table should require multiple entries"
    );
}

// ─── Header list overflow ───────────────────────────────────────────

#[test]
fn header_list_overflow_exceeds_configured_max() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let max_size = 8192;
    let payload = bomb.generate_header_list_overflow(max_size);
    assert!(payload.len() > 10, "Overflow payload must be substantial");
    let decompressed_estimate = estimate_decompressed_size_from_block(&payload);
    assert!(
        decompressed_estimate > max_size,
        "Decompressed size ({}) must exceed max_size ({})",
        decompressed_estimate,
        max_size
    );
}

#[test]
fn header_list_overflow_starts_with_incremental_indexing() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let payload = bomb.generate_header_list_overflow(4096);
    assert_eq!(payload[0], 0x40);
}

// ─── CONTINUATION bomb ──────────────────────────────────────────────

#[test]
fn continuation_bomb_correct_fragment_count() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let fragments = 10;
    let frames = bomb.generate_continuation_bomb(fragments);
    assert_eq!(frames.len() as u32, fragments);
}

#[test]
fn continuation_bomb_first_frame_is_headers() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let frames = bomb.generate_continuation_bomb(5);
    assert_eq!(
        parse_frame_type(&frames[0]),
        Some(0x1),
        "First frame must be HEADERS"
    );
}

#[test]
fn continuation_bomb_middle_frames_are_continuation() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let frames = bomb.generate_continuation_bomb(8);
    for frame in frames.iter().skip(1) {
        assert_eq!(
            parse_frame_type(frame),
            Some(0x9),
            "Middle/last frames must be CONTINUATION"
        );
    }
}

#[test]
fn continuation_bomb_only_last_has_end_headers() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let frames = bomb.generate_continuation_bomb(6);

    let first_flags = parse_frame_flags(&frames[0]).unwrap();
    assert_eq!(
        first_flags & 0x4,
        0,
        "First HEADERS must NOT have END_HEADERS"
    );

    for frame in frames.iter().skip(1).take(frames.len() - 2) {
        let flags = parse_frame_flags(frame).unwrap();
        assert_eq!(
            flags & 0x4,
            0,
            "Middle CONTINUATION must NOT have END_HEADERS"
        );
    }

    let last_flags = parse_frame_flags(frames.last().unwrap()).unwrap();
    assert_ne!(
        last_flags & 0x4,
        0,
        "Last CONTINUATION must have END_HEADERS"
    );
}

#[test]
fn continuation_bomb_all_same_stream_id() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let frames = bomb.generate_continuation_bomb(4);
    let expected_sid = parse_stream_id(&frames[0]).unwrap();
    for frame in &frames {
        assert_eq!(parse_stream_id(frame), Some(expected_sid));
    }
}

#[test]
fn continuation_bomb_valid_frame_headers() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let frames = bomb.generate_continuation_bomb(5);
    for frame in &frames {
        assert!(
            validate_frame_header(frame),
            "Frame must have valid H2 header"
        );
    }
}

#[test]
fn continuation_bomb_minimum_one_fragment() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let frames = bomb.generate_continuation_bomb(0);
    assert!(
        !frames.is_empty(),
        "Must produce at least one frame even with fragments=0"
    );
}

// ─── Expansion ratio calculation ────────────────────────────────────

#[test]
fn expansion_ratio_calculation() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let compressed = vec![0u8; 100];
    let ratio = bomb.calculate_expansion_ratio(&compressed, 10000);
    assert!((ratio - 100.0).abs() < 0.01);
}

#[test]
fn expansion_ratio_zero_for_empty_compressed() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let ratio = bomb.calculate_expansion_ratio(&[], 1000);
    assert_eq!(ratio, 0.0);
}

#[test]
fn expansion_ratio_one_to_one() {
    let bomb = HpackBombV2::new(HpackBombConfig::default());
    let compressed = vec![0u8; 500];
    let ratio = bomb.calculate_expansion_ratio(&compressed, 500);
    assert!((ratio - 1.0).abs() < 0.01);
}

// ─── DynamicTableEntry ──────────────────────────────────────────────

#[test]
fn dynamic_table_entry_size_per_rfc() {
    let entry = DynamicTableEntry::new("content-type", "text/html");
    assert_eq!(entry.size, 32 + "content-type".len() + "text/html".len());
    assert_eq!(entry.size, 32 + 12 + 9);
}

#[test]
fn dynamic_table_entry_empty_values() {
    let entry = DynamicTableEntry::new("", "");
    assert_eq!(entry.size, 32);
}

// ─── ContinuationFragment fields ────────────────────────────────────

#[test]
fn continuation_fragment_fields() {
    let frag = ContinuationFragment {
        stream_id: 5,
        payload: vec![0xAA, 0xBB],
        is_final: true,
    };
    assert_eq!(frag.stream_id, 5);
    assert_eq!(frag.payload.len(), 2);
    assert!(frag.is_final);
}

// ─── HpackBombResult ────────────────────────────────────────────────

#[test]
fn hpack_bomb_result_fields() {
    let result = HpackBombResult {
        compressed_size: 100,
        decompressed_size: 100_000,
        expansion_ratio: 1000.0,
        frame_count: 5,
    };
    assert_eq!(result.compressed_size, 100);
    assert_eq!(result.decompressed_size, 100_000);
    assert!((result.expansion_ratio - 1000.0).abs() < f64::EPSILON);
    assert_eq!(result.frame_count, 5);
}

// ─── Parse helpers on generated frames ──────────────────────────────

#[test]
fn parse_helpers_return_none_for_short_buffer() {
    let short = vec![0u8; 3];
    assert_eq!(parse_frame_type(&short), None);
    assert_eq!(parse_frame_flags(&short), None);
    assert_eq!(parse_stream_id(&short), None);
    assert_eq!(parse_payload_length(&short), None);
}

// ─── Test helpers ───────────────────────────────────────────────────

/// Estimate the HPACK dynamic table entry size from a raw block starting with 0x40.
fn estimate_entry_size_from_block(block: &[u8]) -> usize {
    if block.is_empty() || block[0] != 0x40 {
        return 0;
    }
    let mut pos = 1;
    let (name_len, consumed) = decode_int(block, pos);
    pos += consumed;
    pos += name_len;
    let (value_len, consumed) = decode_int(block, pos);
    pos += consumed;
    let _ = pos;
    32 + name_len + value_len
}

/// Estimate decompressed size from a raw header block.
fn estimate_decompressed_size_from_block(block: &[u8]) -> usize {
    if block.is_empty() || block[0] != 0x40 {
        return 0;
    }
    let mut pos = 1;
    let (name_len, consumed) = decode_int(block, pos);
    pos += consumed;
    pos += name_len;
    let (value_len, consumed) = decode_int(block, pos);
    pos += consumed;
    let _ = pos;
    32 + name_len + value_len
}

fn decode_int(data: &[u8], start: usize) -> (usize, usize) {
    if start >= data.len() {
        return (0, 0);
    }
    let first = (data[start] & 0x7F) as usize;
    if first < 127 {
        return (first, 1);
    }
    let mut value = 127usize;
    let mut m = 0u32;
    let mut i = start + 1;
    while i < data.len() {
        let b = data[i] as usize;
        value += (b & 0x7F) << m;
        m += 7;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
    }
    (value, i - start)
}
