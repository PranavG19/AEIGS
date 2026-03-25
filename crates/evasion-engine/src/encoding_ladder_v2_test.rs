use super::encoding_ladder_v2::*;

#[test]
fn test_supported_encoding_count() {
    let ladder = EncodingLadderV2::new();
    assert_eq!(ladder.supported_encoding_count(), 14);
}

#[test]
fn test_single_url_encoding() {
    let ladder = EncodingLadderV2::new();
    let result = ladder.encode_single("<script>alert(1)</script>", EncodingType::Url);
    assert!(result.contains("%3C"));
    assert!(result.contains("%3E"));
    assert!(!result.contains('<'));
}

#[test]
fn test_double_url_encoding() {
    let ladder = EncodingLadderV2::new();
    let result = ladder.encode_single("<", EncodingType::DoubleUrl);
    assert!(result.contains("%25"));
}

#[test]
fn test_unicode_encoding() {
    let ladder = EncodingLadderV2::new();
    let result = ladder.encode_single("a", EncodingType::Unicode);
    assert_eq!(result, "\\u0061");
}

#[test]
fn test_overlong_utf8_encoding() {
    let ladder = EncodingLadderV2::new();
    let result = ladder.encode_single("<", EncodingType::OverlongUtf8);
    assert!(result.starts_with('%'));
    assert!(result.len() > 3);
}

#[test]
fn test_html_entity_encoding() {
    let ladder = EncodingLadderV2::new();
    let result = ladder.encode_single("<script>", EncodingType::HtmlEntity);
    assert!(result.contains("&lt;"));
    assert!(result.contains("&gt;"));
}

#[test]
fn test_html_entity_hex_encoding() {
    let ladder = EncodingLadderV2::new();
    let result = ladder.encode_single("A", EncodingType::HtmlEntityHex);
    assert_eq!(result, "&#x41;");
}

#[test]
fn test_base64_encoding() {
    let ladder = EncodingLadderV2::new();
    let result = ladder.encode_single("hello", EncodingType::Base64);
    assert_eq!(result, "aGVsbG8=");
}

#[test]
fn test_hex_encoding() {
    let ladder = EncodingLadderV2::new();
    let result = ladder.encode_single("AB", EncodingType::Hex);
    assert!(result.contains("0x41"));
    assert!(result.contains("0x42"));
}

#[test]
fn test_octal_encoding() {
    let ladder = EncodingLadderV2::new();
    let result = ladder.encode_single("A", EncodingType::Octal);
    assert_eq!(result, "\\101");
}

#[test]
fn test_js_unicode_encoding() {
    let ladder = EncodingLadderV2::new();
    let result = ladder.encode_single("a", EncodingType::JsUnicode);
    assert_eq!(result, "\\u0061");
}

#[test]
fn test_js_octal_encoding() {
    let ladder = EncodingLadderV2::new();
    let result = ladder.encode_single("A", EncodingType::JsOctal);
    assert_eq!(result, "\\101");
}

#[test]
fn test_css_escape_encoding() {
    let ladder = EncodingLadderV2::new();
    let result = ladder.encode_single("A", EncodingType::CssEscape);
    assert_eq!(result, "\\000041");
}

#[test]
fn test_xml_entity_encoding() {
    let ladder = EncodingLadderV2::new();
    let result = ladder.encode_single("<tag>", EncodingType::XmlEntity);
    assert!(result.contains("&lt;"));
    assert!(result.contains("&gt;"));
}

#[test]
fn test_decimal_entity_encoding() {
    let ladder = EncodingLadderV2::new();
    let result = ladder.encode_single("A", EncodingType::DecimalEntity);
    assert_eq!(result, "&#65;");
}

#[test]
fn test_context_url_parameter() {
    let ladder = EncodingLadderV2::new();
    let results = ladder.encode_for_context("test", EncodingContext::UrlParameter);
    assert!(!results.is_empty());
    for r in &results {
        assert_eq!(r.context, EncodingContext::UrlParameter);
        assert_eq!(r.depth, 1);
        assert_eq!(r.original, "test");
    }
}

#[test]
fn test_context_html_body() {
    let ladder = EncodingLadderV2::new();
    let results = ladder.encode_for_context("<script>", EncodingContext::HtmlBody);
    assert!(!results.is_empty());
    let has_html_entity = results
        .iter()
        .any(|r| r.chain.contains(&EncodingType::HtmlEntity));
    assert!(has_html_entity);
}

#[test]
fn test_context_javascript() {
    let ladder = EncodingLadderV2::new();
    let results = ladder.encode_for_context("alert(1)", EncodingContext::JavaScriptString);
    assert!(!results.is_empty());
    let has_js = results
        .iter()
        .any(|r| r.chain.contains(&EncodingType::JsUnicode));
    assert!(has_js);
}

#[test]
fn test_encoding_chain_generates_multi_depth() {
    let ladder = EncodingLadderV2::new().with_max_depth(2);
    let results = ladder.encode_chain("test", EncodingContext::UrlParameter);
    let depth_1: Vec<_> = results.iter().filter(|r| r.depth == 1).collect();
    let depth_2: Vec<_> = results.iter().filter(|r| r.depth == 2).collect();
    assert!(!depth_1.is_empty());
    assert!(!depth_2.is_empty());
}

#[test]
fn test_encoding_chain_no_same_consecutive() {
    let ladder = EncodingLadderV2::new().with_max_depth(3);
    let results = ladder.encode_chain("test", EncodingContext::UrlParameter);
    for r in &results {
        for window in r.chain.windows(2) {
            assert_ne!(window[0], window[1], "Same encoding repeated consecutively");
        }
    }
}

#[test]
fn test_encoding_chain_depth_3() {
    let ladder = EncodingLadderV2::new().with_max_depth(3);
    let results = ladder.encode_chain("x", EncodingContext::HtmlBody);
    let depth_3: Vec<_> = results.iter().filter(|r| r.depth == 3).collect();
    assert!(!depth_3.is_empty());
    for r in &depth_3 {
        assert_eq!(r.chain.len(), 3);
    }
}

#[test]
fn test_permutations() {
    let ladder = EncodingLadderV2::new();
    let encodings = vec![EncodingType::Url, EncodingType::Base64, EncodingType::Hex];
    let results = ladder.permutations("test", &encodings, 2);
    assert!(!results.is_empty());
    let depth_2: Vec<_> = results.iter().filter(|r| r.depth == 2).collect();
    assert!(!depth_2.is_empty());
}

#[test]
fn test_with_max_depth_clamped() {
    let ladder = EncodingLadderV2::new().with_max_depth(10);
    let results = ladder.encode_chain("x", EncodingContext::HttpHeader);
    let max_depth = results.iter().map(|r| r.depth).max().unwrap_or(0);
    assert!(max_depth <= 5);
}

#[test]
fn test_encodings_for_context() {
    let ladder = EncodingLadderV2::new();
    let url_encs = ladder.encodings_for_context(EncodingContext::UrlParameter);
    assert!(url_encs.contains(&EncodingType::Url));
    assert!(url_encs.contains(&EncodingType::DoubleUrl));

    let html_encs = ladder.encodings_for_context(EncodingContext::HtmlBody);
    assert!(html_encs.contains(&EncodingType::HtmlEntity));

    let js_encs = ladder.encodings_for_context(EncodingContext::JavaScriptString);
    assert!(js_encs.contains(&EncodingType::JsUnicode));
}

#[test]
fn test_display_encoding_types() {
    let types = vec![
        EncodingType::Url,
        EncodingType::DoubleUrl,
        EncodingType::Unicode,
        EncodingType::OverlongUtf8,
        EncodingType::HtmlEntity,
        EncodingType::HtmlEntityHex,
        EncodingType::Base64,
        EncodingType::Hex,
        EncodingType::Octal,
        EncodingType::JsUnicode,
        EncodingType::JsOctal,
        EncodingType::CssEscape,
        EncodingType::XmlEntity,
        EncodingType::DecimalEntity,
    ];
    for t in types {
        let s = format!("{}", t);
        assert!(!s.is_empty());
    }
}

#[test]
fn test_display_encoding_contexts() {
    let contexts = vec![
        EncodingContext::UrlParameter,
        EncodingContext::HtmlBody,
        EncodingContext::HtmlAttribute,
        EncodingContext::JavaScriptString,
        EncodingContext::CssValue,
        EncodingContext::XmlContent,
        EncodingContext::JsonValue,
        EncodingContext::HttpHeader,
    ];
    for c in contexts {
        let s = format!("{}", c);
        assert!(!s.is_empty());
    }
}

#[test]
fn test_empty_payload() {
    let ladder = EncodingLadderV2::new();
    let result = ladder.encode_single("", EncodingType::Url);
    assert!(result.is_empty());
}

#[test]
fn test_chain_preserves_original() {
    let ladder = EncodingLadderV2::new().with_max_depth(2);
    let results = ladder.encode_chain("<script>", EncodingContext::HtmlBody);
    for r in &results {
        assert_eq!(r.original, "<script>");
    }
}

#[test]
fn test_all_contexts_have_encodings() {
    let ladder = EncodingLadderV2::new();
    let contexts = vec![
        EncodingContext::UrlParameter,
        EncodingContext::HtmlBody,
        EncodingContext::HtmlAttribute,
        EncodingContext::JavaScriptString,
        EncodingContext::CssValue,
        EncodingContext::XmlContent,
        EncodingContext::JsonValue,
        EncodingContext::HttpHeader,
    ];
    for ctx in contexts {
        let encs = ladder.encodings_for_context(ctx);
        assert!(!encs.is_empty(), "Context {} has no encodings", ctx);
    }
}
