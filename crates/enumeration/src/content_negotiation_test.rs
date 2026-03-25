use crate::content_negotiation::*;

#[test]
fn accept_manipulations_generated() {
    let manips = generate_accept_manipulations("https://api.example.com/v1/users");
    assert!(manips.len() >= 10);
    assert!(
        manips
            .iter()
            .any(|m| m.technique == AcceptManipulationTechnique::WildcardAccept)
    );
    assert!(
        manips
            .iter()
            .any(|m| m.technique == AcceptManipulationTechnique::XmlPreference)
    );
    assert!(
        manips
            .iter()
            .any(|m| m.technique == AcceptManipulationTechnique::YamlPreference)
    );
    assert!(
        manips
            .iter()
            .any(|m| m.technique == AcceptManipulationTechnique::CsvExfiltration)
    );
    assert!(
        manips
            .iter()
            .any(|m| m.technique == AcceptManipulationTechnique::QualityWeightTrick)
    );
    assert!(
        manips
            .iter()
            .any(|m| m.technique == AcceptManipulationTechnique::EmptyAccept)
    );
    assert!(
        manips
            .iter()
            .any(|m| m.technique == AcceptManipulationTechnique::InvalidMimeType)
    );
    assert!(
        manips
            .iter()
            .any(|m| m.technique == AcceptManipulationTechnique::AcceptLanguageOverflow)
    );
}

#[test]
fn accept_xml_preference_is_high_severity() {
    let manips = generate_accept_manipulations("https://api.example.com");
    let xml = manips
        .iter()
        .find(|m| m.technique == AcceptManipulationTechnique::XmlPreference)
        .unwrap();
    assert_eq!(xml.severity, ContentNegotiationSeverity::High);
    assert!(xml.accept_header.contains("application/xml"));
}

#[test]
fn accept_yaml_preference_is_high_severity() {
    let manips = generate_accept_manipulations("https://api.example.com");
    let yaml = manips
        .iter()
        .find(|m| m.technique == AcceptManipulationTechnique::YamlPreference)
        .unwrap();
    assert_eq!(yaml.severity, ContentNegotiationSeverity::High);
    assert!(yaml.accept_header.contains("yaml"));
}

#[test]
fn accept_empty_header() {
    let manips = generate_accept_manipulations("https://api.example.com");
    let empty = manips
        .iter()
        .find(|m| m.technique == AcceptManipulationTechnique::EmptyAccept)
        .unwrap();
    assert!(empty.accept_header.is_empty());
}

#[test]
fn accept_overflow_has_long_header() {
    let manips = generate_accept_manipulations("https://api.example.com");
    let overflow = manips
        .iter()
        .find(|m| m.technique == AcceptManipulationTechnique::AcceptLanguageOverflow)
        .unwrap();
    assert!(overflow.accept_header.len() > 500);
}

#[test]
fn serialization_confusion_payloads_generated() {
    let payloads = generate_serialization_confusion_payloads("{\"user\": \"test\"}");
    assert!(payloads.len() >= 6);
    assert!(
        payloads
            .iter()
            .any(|p| p.attack_vector == SerializationAttackVector::XxeInjection)
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.attack_vector == SerializationAttackVector::YamlDeserialization)
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.attack_vector == SerializationAttackVector::PolyglotPayload)
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.attack_vector == SerializationAttackVector::TypeJuggling)
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.attack_vector == SerializationAttackVector::SchemaBypass)
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.attack_vector == SerializationAttackVector::ParserDifferential)
    );
}

#[test]
fn xxe_payload_contains_entity_declaration() {
    let payloads = generate_serialization_confusion_payloads("{}");
    let xxe = payloads
        .iter()
        .find(|p| p.attack_vector == SerializationAttackVector::XxeInjection)
        .unwrap();
    assert!(xxe.payload.contains("DOCTYPE"));
    assert!(xxe.payload.contains("ENTITY"));
    assert!(xxe.payload.contains("etc/passwd"));
    assert_eq!(xxe.severity, ContentNegotiationSeverity::Critical);
}

#[test]
fn yaml_deser_payload_contains_python_exec() {
    let payloads = generate_serialization_confusion_payloads("{}");
    let yaml = payloads
        .iter()
        .find(|p| p.attack_vector == SerializationAttackVector::YamlDeserialization)
        .unwrap();
    assert!(yaml.payload.contains("python"));
    assert!(yaml.payload.contains("os.system"));
    assert_eq!(yaml.severity, ContentNegotiationSeverity::Critical);
}

#[test]
fn type_juggling_has_duplicate_keys() {
    let payloads = generate_serialization_confusion_payloads("{}");
    let juggle = payloads
        .iter()
        .find(|p| p.attack_vector == SerializationAttackVector::TypeJuggling)
        .unwrap();
    assert_eq!(juggle.payload.matches("\"amount\"").count(), 2);
}

#[test]
fn content_type_mismatches_generated() {
    let mismatches = generate_content_type_mismatches();
    assert!(mismatches.len() >= 7);
    assert!(
        mismatches
            .iter()
            .any(|m| m.technique == MismatchTechnique::JsonBodyWithXmlHeader)
    );
    assert!(
        mismatches
            .iter()
            .any(|m| m.technique == MismatchTechnique::XmlBodyWithJsonHeader)
    );
    assert!(
        mismatches
            .iter()
            .any(|m| m.technique == MismatchTechnique::FormBodyWithJsonHeader)
    );
    assert!(
        mismatches
            .iter()
            .any(|m| m.technique == MismatchTechnique::EmptyContentType)
    );
    assert!(
        mismatches
            .iter()
            .any(|m| m.technique == MismatchTechnique::CharsetOverride)
    );
}

#[test]
fn charset_override_uses_utf7() {
    let mismatches = generate_content_type_mismatches();
    let charset = mismatches
        .iter()
        .find(|m| m.technique == MismatchTechnique::CharsetOverride)
        .unwrap();
    assert!(charset.declared_type.contains("utf-7"));
    assert_eq!(charset.severity, ContentNegotiationSeverity::High);
}

#[test]
fn empty_content_type_mismatch() {
    let mismatches = generate_content_type_mismatches();
    let empty = mismatches
        .iter()
        .find(|m| m.technique == MismatchTechnique::EmptyContentType)
        .unwrap();
    assert!(empty.declared_type.is_empty());
}

#[test]
fn boundary_manipulations_generated() {
    let attacks = generate_boundary_manipulations("----WebKitFormBoundary");
    assert!(attacks.len() >= 7);
    assert!(
        attacks
            .iter()
            .any(|a| a.technique == BoundaryTechnique::BoundaryInject)
    );
    assert!(
        attacks
            .iter()
            .any(|a| a.technique == BoundaryTechnique::DuplicateBoundary)
    );
    assert!(
        attacks
            .iter()
            .any(|a| a.technique == BoundaryTechnique::NullByteBoundary)
    );
    assert!(
        attacks
            .iter()
            .any(|a| a.technique == BoundaryTechnique::OverlongBoundary)
    );
    assert!(
        attacks
            .iter()
            .any(|a| a.technique == BoundaryTechnique::MissingClosingBoundary)
    );
    assert!(
        attacks
            .iter()
            .any(|a| a.technique == BoundaryTechnique::BoundaryInFilename)
    );
    assert!(
        attacks
            .iter()
            .any(|a| a.technique == BoundaryTechnique::NestedMultipart)
    );
}

#[test]
fn boundary_inject_has_two_boundaries() {
    let attacks = generate_boundary_manipulations("test-boundary");
    let inject = attacks
        .iter()
        .find(|a| a.technique == BoundaryTechnique::BoundaryInject)
        .unwrap();
    assert_eq!(inject.content_type_header.matches("boundary=").count(), 2);
}

#[test]
fn boundary_overlong_is_large() {
    let attacks = generate_boundary_manipulations("test");
    let overlong = attacks
        .iter()
        .find(|a| a.technique == BoundaryTechnique::OverlongBoundary)
        .unwrap();
    assert!(overlong.content_type_header.len() > 8000);
}

#[test]
fn boundary_null_byte_present() {
    let attacks = generate_boundary_manipulations("myboundary");
    let null_byte = attacks
        .iter()
        .find(|a| a.technique == BoundaryTechnique::NullByteBoundary)
        .unwrap();
    assert!(null_byte.content_type_header.contains("%00"));
}

#[test]
fn boundary_nested_multipart() {
    let attacks = generate_boundary_manipulations("outer");
    let nested = attacks
        .iter()
        .find(|a| a.technique == BoundaryTechnique::NestedMultipart)
        .unwrap();
    assert!(nested.payload_snippet.contains("boundary=inner"));
    assert!(nested.payload_snippet.contains("--inner"));
}

#[test]
fn full_analysis_all_categories() {
    let findings = run_content_negotiation_analysis(
        "https://api.example.com/v1/data",
        Some("{\"test\": true}"),
        Some("----boundary"),
    );
    assert!(
        findings
            .iter()
            .any(|f| f.category == ContentNegotiationCategory::AcceptManipulation)
    );
    assert!(
        findings
            .iter()
            .any(|f| f.category == ContentNegotiationCategory::SerializationConfusion)
    );
    assert!(
        findings
            .iter()
            .any(|f| f.category == ContentNegotiationCategory::ContentTypeMismatch)
    );
    assert!(
        findings
            .iter()
            .any(|f| f.category == ContentNegotiationCategory::MultipartBoundaryAbuse)
    );
}

#[test]
fn full_analysis_without_optional_inputs() {
    let findings = run_content_negotiation_analysis("https://api.example.com", None, None);
    assert!(
        findings
            .iter()
            .any(|f| f.category == ContentNegotiationCategory::AcceptManipulation)
    );
    assert!(
        findings
            .iter()
            .any(|f| f.category == ContentNegotiationCategory::ContentTypeMismatch)
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.category == ContentNegotiationCategory::SerializationConfusion)
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.category == ContentNegotiationCategory::MultipartBoundaryAbuse)
    );
}

#[test]
fn display_impls_produce_expected_strings() {
    assert_eq!(
        format!("{}", ContentNegotiationSeverity::Critical),
        "Critical"
    );
    assert_eq!(
        format!("{}", AcceptManipulationTechnique::XmlPreference),
        "XML Preference"
    );
    assert_eq!(format!("{}", SerializationFormat::Json), "JSON");
    assert_eq!(
        format!("{}", SerializationAttackVector::XxeInjection),
        "XXE Injection"
    );
    assert_eq!(
        format!("{}", MismatchTechnique::CharsetOverride),
        "Charset Override"
    );
    assert_eq!(
        format!("{}", BoundaryTechnique::BoundaryInject),
        "Boundary Injection"
    );
    assert_eq!(
        format!("{}", ContentNegotiationCategory::AcceptManipulation),
        "Accept Header Manipulation"
    );
    assert_eq!(
        format!("{}", BoundaryTechnique::NestedMultipart),
        "Nested Multipart"
    );
    assert_eq!(format!("{}", SerializationFormat::Toml), "TOML");
}
