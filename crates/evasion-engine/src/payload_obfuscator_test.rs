use super::*;

#[test]
fn url_encode_special_chars() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("<script>", ObfuscationTransform::UrlEncode);
    assert_eq!(result.obfuscated, "%3Cscript%3E");
    assert_eq!(result.original, "<script>");
}

#[test]
fn url_encode_preserves_alphanumeric() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("abc123", ObfuscationTransform::UrlEncode);
    assert_eq!(result.obfuscated, "abc123");
}

#[test]
fn double_url_encode_encodes_percent() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("<", ObfuscationTransform::DoubleUrlEncode);
    assert_eq!(result.obfuscated, "%253C");
}

#[test]
fn triple_url_encode_deep_nesting() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("<", ObfuscationTransform::TripleUrlEncode);
    assert_eq!(result.obfuscated, "%25253C");
}

#[test]
fn unicode_fullwidth_transforms_ascii() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("SELECT", ObfuscationTransform::UnicodeFullwidth);
    assert_eq!(
        result.obfuscated,
        "\u{FF33}\u{FF25}\u{FF2C}\u{FF25}\u{FF23}\u{FF34}"
    );
}

#[test]
fn unicode_fullwidth_preserves_spaces() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("A B", ObfuscationTransform::UnicodeFullwidth);
    assert!(result.obfuscated.contains(' '));
}

#[test]
fn html_entity_decimal_encodes_all() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("<>", ObfuscationTransform::HtmlEntityDecimal);
    assert_eq!(result.obfuscated, "&#60;&#62;");
}

#[test]
fn html_entity_hex_encodes_all() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("<>", ObfuscationTransform::HtmlEntityHex);
    assert_eq!(result.obfuscated, "&#x3C;&#x3E;");
}

#[test]
fn case_randomization_changes_case() {
    let obf = PayloadObfuscator::new();
    let input = "select";
    let mut saw_upper = false;
    let mut saw_lower = false;
    for _ in 0..50 {
        let result = obf.apply_single(input, ObfuscationTransform::CaseRandomization);
        if result.obfuscated != input {
            saw_upper = true;
        }
        if result.obfuscated != "SELECT" {
            saw_lower = true;
        }
    }
    assert!(saw_upper, "should produce at least one uppercase variant");
    assert!(saw_lower, "should produce at least one lowercase variant");
}

#[test]
fn case_randomization_preserves_length() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("abcdef", ObfuscationTransform::CaseRandomization);
    assert_eq!(result.obfuscated.len(), 6);
}

#[test]
fn sql_comment_insertion_replaces_spaces() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("SELECT 1", ObfuscationTransform::SqlCommentInsertion);
    assert_eq!(result.obfuscated, "SELECT/**/1");
}

#[test]
fn html_comment_insertion_replaces_spaces() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("a b", ObfuscationTransform::HtmlCommentInsertion);
    assert_eq!(result.obfuscated, "a<!-- -->b");
}

#[test]
fn whitespace_substitution_no_regular_spaces() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("a b c", ObfuscationTransform::WhitespaceSubstitution);
    assert!(!result.obfuscated.contains(' '));
    assert_eq!(result.obfuscated.chars().count(), 5);
}

#[test]
fn string_concatenation_splits_payload() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("select", ObfuscationTransform::StringConcatenation);
    assert_eq!(result.obfuscated, "'sel'+'ect'");
}

#[test]
fn string_concatenation_single_char() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("x", ObfuscationTransform::StringConcatenation);
    assert_eq!(result.obfuscated, "x");
}

#[test]
fn character_escape_hex_encodes_ascii() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("AB", ObfuscationTransform::CharacterEscapeHex);
    assert_eq!(result.obfuscated, "\\x41\\x42");
}

#[test]
fn base64_wrap_encodes_correctly() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("Man", ObfuscationTransform::Base64Wrap);
    assert_eq!(result.obfuscated, "TWFu");
}

#[test]
fn base64_wrap_padding() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("A", ObfuscationTransform::Base64Wrap);
    assert_eq!(result.obfuscated, "QQ==");
}

#[test]
fn rot13_roundtrip() {
    let obf = PayloadObfuscator::new();
    let first = obf.apply_single("Hello", ObfuscationTransform::Rot13);
    let second = obf.apply_single(&first.obfuscated, ObfuscationTransform::Rot13);
    assert_eq!(second.obfuscated, "Hello");
}

#[test]
fn rot13_known_value() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("ABCabc", ObfuscationTransform::Rot13);
    assert_eq!(result.obfuscated, "NOPnop");
}

#[test]
fn hex_wrap_encodes_bytes() {
    let obf = PayloadObfuscator::new();
    let result = obf.apply_single("AB", ObfuscationTransform::HexWrap);
    assert_eq!(result.obfuscated, "4142");
}

#[test]
fn chain_composes_transforms() {
    let chain = ObfuscationChain::new()
        .push(ObfuscationTransform::SqlCommentInsertion)
        .push(ObfuscationTransform::UrlEncode);
    let obf = PayloadObfuscator::new();
    let result = obf.apply_chain("a b", &chain);
    assert_eq!(result.transforms_applied.len(), 2);
    assert!(!result.obfuscated.contains(' '));
    assert!(result.obfuscated.contains("%2F") || result.obfuscated.contains("%2A"));
}

#[test]
fn chain_url_then_unicode() {
    let chain = ObfuscationChain::new()
        .push(ObfuscationTransform::UrlEncode)
        .push(ObfuscationTransform::UnicodeFullwidth);
    let result = chain.apply("<");
    assert_ne!(result.obfuscated, "<");
    assert_eq!(result.transforms_applied.len(), 2);
}

#[test]
fn polymorphic_generates_distinct_variants() {
    let obf = PayloadObfuscator::with_seed(42);
    let variants = obf.generate_polymorphic("SELECT * FROM users", 10);
    assert!(variants.len() >= 10, "got {} variants", variants.len());
    let unique: std::collections::HashSet<_> = variants.iter().map(|v| &v.obfuscated).collect();
    assert_eq!(
        unique.len(),
        variants.len(),
        "all variants should be distinct"
    );
}

#[test]
fn polymorphic_all_preserve_original() {
    let obf = PayloadObfuscator::with_seed(99);
    let input = "alert(1)";
    let variants = obf.generate_polymorphic(input, 5);
    for v in &variants {
        assert_eq!(v.original, input);
    }
}

#[test]
fn polymorphic_each_has_transforms() {
    let obf = PayloadObfuscator::with_seed(7);
    let variants = obf.generate_polymorphic("test", 5);
    for v in &variants {
        assert!(!v.transforms_applied.is_empty());
        assert!(v.transforms_applied.len() <= 3);
    }
}

#[test]
fn url_encode_roundtrip() {
    let input = "<script>alert('xss')</script>";
    let obf = PayloadObfuscator::new();
    let encoded = obf.apply_single(input, ObfuscationTransform::UrlEncode);
    let decoded = url_decode(&encoded.obfuscated);
    assert_eq!(decoded, input);
}

#[test]
fn html_entity_decimal_roundtrip() {
    let input = "<img src=x>";
    let obf = PayloadObfuscator::new();
    let encoded = obf.apply_single(input, ObfuscationTransform::HtmlEntityDecimal);
    let decoded = html_entity_decode(&encoded.obfuscated);
    assert_eq!(decoded, input);
}

#[test]
fn html_entity_hex_roundtrip() {
    let input = "abc<>&";
    let obf = PayloadObfuscator::new();
    let encoded = obf.apply_single(input, ObfuscationTransform::HtmlEntityHex);
    let decoded = html_entity_decode(&encoded.obfuscated);
    assert_eq!(decoded, input);
}

#[test]
fn hex_wrap_roundtrip() {
    let input = "SELECT 1";
    let obf = PayloadObfuscator::new();
    let encoded = obf.apply_single(input, ObfuscationTransform::HexWrap);
    let decoded = hex_decode(&encoded.obfuscated).expect("valid hex");
    assert_eq!(decoded, input);
}

#[test]
fn all_transforms_enumerated() {
    let all = ObfuscationTransform::all();
    assert!(
        all.len() >= 10,
        "must have at least 10 transforms, got {}",
        all.len()
    );
}

#[test]
fn display_impl_formats_correctly() {
    assert_eq!(format!("{}", ObfuscationTransform::UrlEncode), "url-encode");
    assert_eq!(format!("{}", ObfuscationTransform::Rot13), "rot13");
    assert_eq!(format!("{}", ObfuscationTransform::HexWrap), "hex-wrap");
}

#[test]
fn empty_input_handled() {
    let obf = PayloadObfuscator::new();
    for &t in ObfuscationTransform::all() {
        let result = obf.apply_single("", t);
        assert_eq!(result.original, "");
    }
}

#[test]
fn chain_default_is_empty() {
    let chain = ObfuscationChain::default();
    assert!(chain.transforms().is_empty());
    let result = chain.apply("test");
    assert_eq!(result.obfuscated, "test");
}

#[test]
fn obfuscator_default_works() {
    let obf = PayloadObfuscator::default();
    let result = obf.apply_single("x", ObfuscationTransform::Rot13);
    assert_eq!(result.obfuscated, "k");
}
