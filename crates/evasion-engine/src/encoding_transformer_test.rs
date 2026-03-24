use super::*;

#[test]
fn sql_injection_applicable_strategies() {
    let transformer = EncodingTransformer::new();
    let strategies = transformer.applicable_strategies(VulnerabilityClass::SqlInjection);

    assert!(strategies.contains(&EncodingStrategy::DoubleUrlEncoding));
    assert!(strategies.contains(&EncodingStrategy::MixedCase));
    assert!(strategies.contains(&EncodingStrategy::CommentInsertion));
    assert!(strategies.contains(&EncodingStrategy::WhitespaceVariation));
    assert!(strategies.contains(&EncodingStrategy::ConcatenationSplitting));
    assert_eq!(strategies.len(), 5);
}

#[test]
fn xss_applicable_strategies() {
    let transformer = EncodingTransformer::new();
    let strategies = transformer.applicable_strategies(VulnerabilityClass::CrossSiteScripting);

    assert!(strategies.contains(&EncodingStrategy::DoubleUrlEncoding));
    assert!(strategies.contains(&EncodingStrategy::UnicodeNormalization));
    assert!(strategies.contains(&EncodingStrategy::MixedCase));
    assert!(strategies.contains(&EncodingStrategy::HtmlEntityEncoding));
    assert_eq!(strategies.len(), 4);
}

#[test]
fn path_traversal_applicable_strategies() {
    let transformer = EncodingTransformer::new();
    let strategies = transformer.applicable_strategies(VulnerabilityClass::PathTraversal);

    assert!(strategies.contains(&EncodingStrategy::DoubleUrlEncoding));
    assert!(strategies.contains(&EncodingStrategy::NullByteInsertion));
    assert_eq!(strategies.len(), 2);
}

#[test]
fn command_injection_applicable_strategies() {
    let transformer = EncodingTransformer::new();
    let strategies = transformer.applicable_strategies(VulnerabilityClass::CommandInjection);

    assert!(strategies.contains(&EncodingStrategy::DoubleUrlEncoding));
    assert!(strategies.contains(&EncodingStrategy::WhitespaceVariation));
    assert_eq!(strategies.len(), 2);
}

#[test]
fn encode_transforms_payload_for_each_strategy() {
    let transformer = EncodingTransformer::new();
    let payload = "' OR '1'='1";
    let results = transformer.encode(payload, VulnerabilityClass::SqlInjection);

    assert_eq!(results.len(), 5);
    for result in &results {
        assert_ne!(result.encoded, payload);
    }
}

#[test]
fn double_url_encoding_encodes_special_chars() {
    let transformer = EncodingTransformer::new();
    let payload = "<script>alert('xss')</script>";
    let results = transformer.encode(payload, VulnerabilityClass::CrossSiteScripting);

    let double_url = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::DoubleUrlEncoding)
        .unwrap();
    assert!(double_url.encoded.contains("%253C"));
    assert!(double_url.encoded.contains("%253E"));
    assert!(double_url.encoded.contains("%2527"));
}

#[test]
fn mixed_case_changes_letter_casing() {
    let transformer = EncodingTransformer::new();
    let payload = "select";
    let results = transformer.encode(payload, VulnerabilityClass::SqlInjection);

    let mixed = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::MixedCase)
        .unwrap();
    assert_ne!(mixed.encoded, payload);
    assert_eq!(mixed.encoded.to_lowercase(), payload.to_lowercase());
}

#[test]
fn null_byte_insertion_appends_null() {
    let transformer = EncodingTransformer::new();
    let payload = "../../../etc/passwd";
    let results = transformer.encode(payload, VulnerabilityClass::PathTraversal);

    let null_byte = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::NullByteInsertion)
        .unwrap();
    assert!(null_byte.encoded.ends_with("%00"));
}

#[test]
fn non_injection_classes_return_no_encodings() {
    let transformer = EncodingTransformer::new();
    let payload = "test";

    let broken_auth = transformer.encode(payload, VulnerabilityClass::BrokenAuthentication);
    assert!(broken_auth.is_empty());

    let broken_authz = transformer.encode(payload, VulnerabilityClass::BrokenAuthorization);
    assert!(broken_authz.is_empty());

    let misconfiguration =
        transformer.encode(payload, VulnerabilityClass::SecurityMisconfiguration);
    assert!(misconfiguration.is_empty());

    let sensitive_data = transformer.encode(payload, VulnerabilityClass::SensitiveDataExposure);
    assert!(sensitive_data.is_empty());

    let known_vuln = transformer.encode(payload, VulnerabilityClass::KnownVulnerableDependency);
    assert!(known_vuln.is_empty());

    let input_validation =
        transformer.encode(payload, VulnerabilityClass::InsufficientInputValidation);
    assert!(input_validation.is_empty());
}

#[test]
fn empty_payload_returns_empty_encodings() {
    let transformer = EncodingTransformer::new();
    let results = transformer.encode("", VulnerabilityClass::SqlInjection);
    assert!(results.is_empty());
}

#[test]
fn encoding_strategy_derives_work() {
    let strategy = EncodingStrategy::DoubleUrlEncoding;
    let cloned = strategy;
    assert_eq!(strategy, cloned);

    let debug_output = format!("{strategy:?}");
    assert!(debug_output.contains("DoubleUrlEncoding"));

    let serialized = serde_json::to_string(&strategy).unwrap();
    let deserialized: EncodingStrategy = serde_json::from_str(&serialized).unwrap();
    assert_eq!(strategy, deserialized);

    let mut set = std::collections::HashSet::new();
    set.insert(strategy);
    assert!(set.contains(&EncodingStrategy::DoubleUrlEncoding));
}

#[test]
fn encoded_payload_preserves_original() {
    let transformer = EncodingTransformer::new();
    let payload = "' OR '1'='1";
    let results = transformer.encode(payload, VulnerabilityClass::SqlInjection);

    for result in &results {
        assert_eq!(result.original, payload);
    }
}

#[test]
fn unicode_normalization_encodes_angle_brackets() {
    let transformer = EncodingTransformer::new();
    let payload = "<img src=x>";
    let results = transformer.encode(payload, VulnerabilityClass::CrossSiteScripting);

    let unicode = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::UnicodeNormalization)
        .unwrap();
    assert!(unicode.encoded.contains("\\u003c"));
    assert!(unicode.encoded.contains("\\u003e"));
}

#[test]
fn comment_insertion_inserts_sql_comments() {
    let transformer = EncodingTransformer::new();
    let payload = "' OR 1=1--";
    let results = transformer.encode(payload, VulnerabilityClass::SqlInjection);

    let commented = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::CommentInsertion)
        .unwrap();
    assert!(commented.encoded.contains("/**/"));
}

#[test]
fn whitespace_variation_replaces_spaces() {
    let transformer = EncodingTransformer::new();
    let payload = "cmd /c dir";
    let results = transformer.encode(payload, VulnerabilityClass::CommandInjection);

    let whitespace = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::WhitespaceVariation)
        .unwrap();
    assert!(whitespace.encoded.contains('\t'));
    assert!(!whitespace.encoded.contains(' '));
}

#[test]
fn html_entity_encoding_encodes_brackets() {
    let transformer = EncodingTransformer::new();
    let payload = "<b>bold</b>";
    let results = transformer.encode(payload, VulnerabilityClass::CrossSiteScripting);

    let html = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::HtmlEntityEncoding)
        .unwrap();
    assert!(html.encoded.contains("&#60;"));
    assert!(html.encoded.contains("&#62;"));
}

#[test]
fn concatenation_splitting_wraps_in_concat() {
    let transformer = EncodingTransformer::new();
    let payload = "admin";
    let results = transformer.encode(payload, VulnerabilityClass::SqlInjection);

    let concat = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::ConcatenationSplitting)
        .unwrap();
    assert!(concat.encoded.starts_with("CONCAT("));
    assert!(concat.encoded.contains("'ad'"));
    assert!(concat.encoded.contains("'min'"));
}

#[test]
fn default_impl_works() {
    let transformer = EncodingTransformer::default();
    let results = transformer.encode("test", VulnerabilityClass::SqlInjection);
    assert!(!results.is_empty());
}

#[test]
fn ssti_gets_double_url_and_unicode() {
    let transformer = EncodingTransformer::new();
    let strategies =
        transformer.applicable_strategies(VulnerabilityClass::ServerSideTemplateInjection);

    assert!(strategies.contains(&EncodingStrategy::DoubleUrlEncoding));
    assert!(strategies.contains(&EncodingStrategy::UnicodeNormalization));
    assert_eq!(strategies.len(), 2);
}

#[test]
fn ssrf_gets_only_double_url() {
    let transformer = EncodingTransformer::new();
    let strategies =
        transformer.applicable_strategies(VulnerabilityClass::ServerSideRequestForgery);

    assert!(strategies.contains(&EncodingStrategy::DoubleUrlEncoding));
    assert_eq!(strategies.len(), 1);
}

#[test]
fn double_url_encoding_encodes_all_special_chars() {
    let transformer = EncodingTransformer::new();
    let payload = r#"<>"& /\"#;
    let results = transformer.encode(payload, VulnerabilityClass::SqlInjection);
    let double_url = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::DoubleUrlEncoding)
        .unwrap();
    assert!(double_url.encoded.contains("%253C"));
    assert!(double_url.encoded.contains("%253E"));
    assert!(double_url.encoded.contains("%2522"));
    assert!(double_url.encoded.contains("%2526"));
    assert!(double_url.encoded.contains("%2520"));
    assert!(double_url.encoded.contains("%252F"));
    assert!(double_url.encoded.contains("%255C"));
}

#[test]
fn unicode_normalization_encodes_all_mapped_chars() {
    let transformer = EncodingTransformer::new();
    let payload = r#"<>'"&/"#;
    let results = transformer.encode(payload, VulnerabilityClass::CrossSiteScripting);
    let unicode = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::UnicodeNormalization)
        .unwrap();
    assert!(unicode.encoded.contains("\\u003c"));
    assert!(unicode.encoded.contains("\\u003e"));
    assert!(unicode.encoded.contains("\\u0027"));
    assert!(unicode.encoded.contains("\\u0022"));
    assert!(unicode.encoded.contains("\\u0026"));
    assert!(unicode.encoded.contains("\\u002f"));
}

#[test]
fn html_entity_encoding_encodes_all_mapped_chars() {
    let transformer = EncodingTransformer::new();
    let payload = r#"<>'"&"#;
    let results = transformer.encode(payload, VulnerabilityClass::CrossSiteScripting);
    let html = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::HtmlEntityEncoding)
        .unwrap();
    assert!(html.encoded.contains("&#60;"));
    assert!(html.encoded.contains("&#62;"));
    assert!(html.encoded.contains("&#39;"));
    assert!(html.encoded.contains("&#34;"));
    assert!(html.encoded.contains("&#38;"));
}

#[test]
fn concatenation_splitting_single_char() {
    let transformer = EncodingTransformer::new();
    let payload = "x";
    let results = transformer.encode(payload, VulnerabilityClass::SqlInjection);
    let concat = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::ConcatenationSplitting)
        .unwrap();
    assert_eq!(concat.encoded, "CONCAT('x')");
}

#[test]
fn header_injection_gets_double_url_encoding() {
    let transformer = EncodingTransformer::new();
    let strategies = transformer.applicable_strategies(VulnerabilityClass::HeaderInjection);
    assert!(strategies.contains(&EncodingStrategy::DoubleUrlEncoding));
    assert_eq!(strategies.len(), 1);
}

#[test]
fn open_redirect_gets_double_url_encoding() {
    let transformer = EncodingTransformer::new();
    let strategies = transformer.applicable_strategies(VulnerabilityClass::OpenRedirect);
    assert!(strategies.contains(&EncodingStrategy::DoubleUrlEncoding));
    assert_eq!(strategies.len(), 1);
}

#[test]
fn crlf_injection_gets_double_url_encoding() {
    let transformer = EncodingTransformer::new();
    let strategies = transformer.applicable_strategies(VulnerabilityClass::CrlfInjection);
    assert!(strategies.contains(&EncodingStrategy::DoubleUrlEncoding));
    assert_eq!(strategies.len(), 1);
}

#[test]
fn insecure_deserialization_gets_double_url_encoding() {
    let transformer = EncodingTransformer::new();
    let strategies = transformer.applicable_strategies(VulnerabilityClass::InsecureDeserialization);
    assert!(strategies.contains(&EncodingStrategy::DoubleUrlEncoding));
    assert_eq!(strategies.len(), 1);
}

#[test]
fn comment_insertion_handles_lowercase_keywords() {
    let transformer = EncodingTransformer::new();
    let payload = "select from where";
    let results = transformer.encode(payload, VulnerabilityClass::SqlInjection);
    let commented = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::CommentInsertion)
        .unwrap();
    assert!(commented.encoded.contains("select/**/"));
    assert!(commented.encoded.contains("from/**/"));
    assert!(commented.encoded.contains("where"));
}

#[test]
fn mixed_case_preserves_non_alpha() {
    let transformer = EncodingTransformer::new();
    let payload = "a1b2c";
    let results = transformer.encode(payload, VulnerabilityClass::SqlInjection);
    let mixed = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::MixedCase)
        .unwrap();
    assert!(mixed.encoded.contains('1'));
    assert!(mixed.encoded.contains('2'));
}

#[test]
fn encode_empty_payload_returns_empty_for_all_classes() {
    let transformer = EncodingTransformer::new();
    let classes = vec![
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::CommandInjection,
    ];
    for class in classes {
        let results = transformer.encode("", class);
        assert!(
            results.is_empty(),
            "empty payload should produce no encodings for {class:?}"
        );
    }
}

#[test]
fn encoded_payload_preserves_original_field() {
    let transformer = EncodingTransformer::new();
    let payload = "SELECT * FROM users";
    let results = transformer.encode(payload, VulnerabilityClass::SqlInjection);
    for encoded in &results {
        assert_eq!(encoded.original, payload);
    }
}

#[test]
fn encode_returns_one_result_per_strategy() {
    let transformer = EncodingTransformer::new();
    let strategies = transformer.applicable_strategies(VulnerabilityClass::SqlInjection);
    let results = transformer.encode("test", VulnerabilityClass::SqlInjection);
    assert_eq!(results.len(), strategies.len());
}

#[test]
fn double_url_encoding_encodes_special_chars_only() {
    let transformer = EncodingTransformer::new();
    let payload = "' OR 1=1";
    let results = transformer.encode(payload, VulnerabilityClass::SqlInjection);
    let double_encoded = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::DoubleUrlEncoding)
        .unwrap();
    assert!(
        double_encoded.encoded.contains("%2527"),
        "single quote should be double-encoded to %2527"
    );
    assert!(
        double_encoded.encoded.contains("%2520"),
        "space should be double-encoded to %2520"
    );
}

#[test]
fn encoding_strategy_serialization_roundtrip() {
    let strategies = vec![
        EncodingStrategy::DoubleUrlEncoding,
        EncodingStrategy::UnicodeNormalization,
        EncodingStrategy::MixedCase,
        EncodingStrategy::CommentInsertion,
        EncodingStrategy::WhitespaceVariation,
        EncodingStrategy::NullByteInsertion,
        EncodingStrategy::HtmlEntityEncoding,
        EncodingStrategy::ConcatenationSplitting,
    ];
    for strategy in strategies {
        let json = serde_json::to_string(&strategy).unwrap();
        let deserialized: EncodingStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, strategy);
    }
}

#[test]
fn default_encoding_transformer() {
    let transformer = EncodingTransformer::default();
    let strategies = transformer.applicable_strategies(VulnerabilityClass::SqlInjection);
    assert!(!strategies.is_empty());
}

#[test]
fn null_byte_insertion_appends_percent_00() {
    let transformer = EncodingTransformer::new();
    let payload = "../../etc/passwd";
    let results = transformer.encode(payload, VulnerabilityClass::PathTraversal);
    let null_byte = results
        .iter()
        .find(|r| r.strategy == EncodingStrategy::NullByteInsertion)
        .unwrap();
    assert!(
        null_byte.encoded.contains("%00"),
        "should contain null byte encoding"
    );
}
