use super::input_validation_bypass::*;

#[test]
fn all_fourteen_categories_present() {
    let categories = ValidationBypassCategory::all();
    assert_eq!(categories.len(), 14);
}

#[test]
fn generate_all_returns_nonempty() {
    let payloads = ValidationBypassGenerator::generate_all();
    assert!(
        payloads.len() > 60,
        "expected 60+ total payloads, got {}",
        payloads.len()
    );
}

#[test]
fn every_category_has_payloads() {
    for cat in ValidationBypassCategory::all() {
        let payloads = ValidationBypassGenerator::generate_for_category(*cat);
        assert!(
            !payloads.is_empty(),
            "category {:?} returned zero payloads",
            cat
        );
    }
}

#[test]
fn every_category_payloads_tagged_correctly() {
    for cat in ValidationBypassCategory::all() {
        for p in ValidationBypassGenerator::generate_for_category(*cat) {
            assert_eq!(
                p.category, *cat,
                "payload '{}' tagged {:?} but generated under {:?}",
                p.payload, p.category, cat
            );
        }
    }
}

#[test]
fn risk_scores_within_range() {
    for cat in ValidationBypassCategory::all() {
        let score = cat.risk_score();
        assert!(
            (0.0..=10.0).contains(&score),
            "category {:?} score {} out of 0-10 range",
            cat,
            score
        );
    }
}

#[test]
fn display_impl_nonempty() {
    for cat in ValidationBypassCategory::all() {
        let display = format!("{}", cat);
        assert!(!display.is_empty());
    }
}

#[test]
fn field_type_display() {
    let pairs = [
        (FieldType::String, "string"),
        (FieldType::Integer, "integer"),
        (FieldType::Boolean, "boolean"),
        (FieldType::Email, "email"),
        (FieldType::Url, "url"),
        (FieldType::Filename, "filename"),
        (FieldType::Json, "json"),
        (FieldType::Xml, "xml"),
        (FieldType::Any, "any"),
    ];
    for (ft, expected) in pairs {
        assert_eq!(format!("{}", ft), expected);
    }
}

#[test]
fn type_juggling_has_magic_hash() {
    let payloads = ValidationBypassGenerator::type_juggling();
    assert!(payloads.iter().any(|p| p.payload.contains("0e")));
}

#[test]
fn type_juggling_has_nan() {
    let payloads = ValidationBypassGenerator::type_juggling();
    assert!(payloads.iter().any(|p| p.payload == "NaN"));
}

#[test]
fn length_boundary_has_255_and_256() {
    let payloads = ValidationBypassGenerator::length_boundary();
    assert!(payloads.iter().any(|p| p.payload.len() == 255));
    assert!(payloads.iter().any(|p| p.payload.len() == 256));
}

#[test]
fn length_boundary_has_zero_width_spaces() {
    let payloads = ValidationBypassGenerator::length_boundary();
    assert!(payloads.iter().any(|p| p.payload.contains('\u{200B}')));
}

#[test]
fn charset_confusable_has_fullwidth() {
    let payloads = ValidationBypassGenerator::charset_confusable();
    assert!(payloads.iter().any(|p| p.payload.contains('\u{FF41}')));
}

#[test]
fn charset_confusable_has_cyrillic_homoglyph() {
    let payloads = ValidationBypassGenerator::charset_confusable();
    assert!(payloads.iter().any(|p| p.payload.contains('\u{0430}')));
}

#[test]
fn encoding_chain_has_double_encode() {
    let payloads = ValidationBypassGenerator::encoding_chain();
    assert!(payloads.iter().any(|p| p.payload.contains("%253C")));
}

#[test]
fn encoding_chain_has_overlong_utf8() {
    let payloads = ValidationBypassGenerator::encoding_chain();
    assert!(payloads.iter().any(|p| p.payload.contains("%c0%ae")));
}

#[test]
fn null_byte_has_percent_zero_zero() {
    let payloads = ValidationBypassGenerator::null_byte_injection();
    assert!(payloads.iter().any(|p| p.payload.contains("%00")));
}

#[test]
fn null_byte_targets_filename_fields() {
    let payloads = ValidationBypassGenerator::null_byte_injection();
    let filename_count = payloads
        .iter()
        .filter(|p| p.target_field_type == FieldType::Filename)
        .count();
    assert!(
        filename_count >= 3,
        "expected >=3 filename-targeted null byte payloads, got {}",
        filename_count
    );
}

#[test]
fn array_injection_has_bracket_syntax() {
    let payloads = ValidationBypassGenerator::array_object_injection();
    assert!(payloads.iter().any(|p| p.payload.contains("[]=")));
}

#[test]
fn scientific_notation_has_infinity() {
    let payloads = ValidationBypassGenerator::scientific_notation();
    assert!(payloads.iter().any(|p| p.payload == "Infinity"));
}

#[test]
fn scientific_notation_has_hex() {
    let payloads = ValidationBypassGenerator::scientific_notation();
    assert!(payloads.iter().any(|p| p.payload.starts_with("0x")));
}

#[test]
fn negative_unsigned_has_underflow() {
    let payloads = ValidationBypassGenerator::negative_unsigned();
    assert!(payloads.iter().any(|p| p.payload == "-2147483649"));
}

#[test]
fn negative_unsigned_has_uint32_max() {
    let payloads = ValidationBypassGenerator::negative_unsigned();
    assert!(payloads.iter().any(|p| p.payload == "4294967295"));
}

#[test]
fn empty_null_missing_includes_whitespace_only() {
    let payloads = ValidationBypassGenerator::empty_null_missing();
    assert!(
        payloads
            .iter()
            .any(|p| p.payload.trim().is_empty() && !p.payload.is_empty())
    );
}

#[test]
fn multiline_has_crlf() {
    let payloads = ValidationBypassGenerator::multiline_regex_bypass();
    assert!(payloads.iter().any(|p| p.payload.contains("\r\n")));
}

#[test]
fn multiline_has_unicode_line_separator() {
    let payloads = ValidationBypassGenerator::multiline_regex_bypass();
    assert!(payloads.iter().any(|p| p.payload.contains('\u{2028}')));
}

#[test]
fn json_xml_has_duplicate_key() {
    let payloads = ValidationBypassGenerator::json_xml_type_confusion();
    let dup_key = payloads.iter().any(|p| {
        let first = p.payload.find("\"id\"");
        let last = p.payload.rfind("\"id\"");
        first.is_some() && last.is_some() && first != last
    });
    assert!(dup_key, "expected a duplicate JSON key payload");
}

#[test]
fn json_xml_has_xxe() {
    let payloads = ValidationBypassGenerator::json_xml_type_confusion();
    assert!(payloads.iter().any(|p| p.payload.contains("ENTITY")));
}

#[test]
fn prototype_pollution_has_proto() {
    let payloads = ValidationBypassGenerator::prototype_pollution();
    assert!(payloads.iter().any(|p| p.payload.contains("__proto__")));
}

#[test]
fn prototype_pollution_has_constructor_path() {
    let payloads = ValidationBypassGenerator::prototype_pollution();
    assert!(
        payloads
            .iter()
            .any(|p| p.payload.contains("constructor") && p.payload.contains("prototype"))
    );
}

#[test]
fn unicode_normalization_has_small_form_variants() {
    let payloads = ValidationBypassGenerator::unicode_normalization();
    assert!(payloads.iter().any(|p| p.payload.contains('\u{FE64}')));
}

#[test]
fn case_mapping_has_sharp_s() {
    let payloads = ValidationBypassGenerator::case_mapping_trick();
    assert!(payloads.iter().any(|p| p.payload.contains('\u{00DF}')));
}

#[test]
fn case_mapping_has_fi_ligature() {
    let payloads = ValidationBypassGenerator::case_mapping_trick();
    assert!(payloads.iter().any(|p| p.payload.contains('\u{FB01}')));
}

#[test]
fn generate_for_field_type_filters_correctly() {
    let filename_payloads = ValidationBypassGenerator::generate_for_field_type(FieldType::Filename);
    for p in &filename_payloads {
        assert!(
            p.target_field_type == FieldType::Filename || p.target_field_type == FieldType::Any,
            "payload '{}' has field type {:?} but should be Filename or Any",
            p.payload,
            p.target_field_type
        );
    }
    assert!(!filename_payloads.is_empty());
}

#[test]
fn generate_for_field_type_json_includes_type_confusion() {
    let json_payloads = ValidationBypassGenerator::generate_for_field_type(FieldType::Json);
    assert!(
        json_payloads
            .iter()
            .any(|p| p.category == ValidationBypassCategory::JsonXmlTypeConfusion),
        "JSON field type should include type confusion payloads"
    );
}

#[test]
fn no_duplicate_payloads_within_category() {
    for cat in ValidationBypassCategory::all() {
        let payloads = ValidationBypassGenerator::generate_for_category(*cat);
        let mut seen = std::collections::HashSet::new();
        for p in &payloads {
            assert!(
                seen.insert(&p.payload),
                "duplicate payload '{}' in category {:?}",
                p.payload,
                cat
            );
        }
    }
}

#[test]
fn all_payloads_have_descriptions() {
    for p in ValidationBypassGenerator::generate_all() {
        assert!(
            !p.description.is_empty(),
            "payload '{}' has empty description",
            p.payload
        );
    }
}

#[test]
fn category_count_matches_generate_all_categories() {
    let all = ValidationBypassGenerator::generate_all();
    let mut categories: std::collections::HashSet<ValidationBypassCategory> =
        std::collections::HashSet::new();
    for p in &all {
        categories.insert(p.category);
    }
    assert_eq!(
        categories.len(),
        ValidationBypassCategory::all().len(),
        "generate_all must produce payloads from every category"
    );
}
