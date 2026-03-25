use super::evasion_catalogue::*;
use super::waf_fingerprinter_v2::WafVendor;

#[test]
fn test_catalogue_has_100_plus_techniques() {
    let cat = EvasionCatalogue::new();
    assert!(
        cat.total_techniques() >= 100,
        "Expected 100+ techniques, got {}",
        cat.total_techniques()
    );
}

#[test]
fn test_get_by_id() {
    let cat = EvasionCatalogue::new();
    let tech = cat.get_by_id(1);
    assert!(tech.is_some());
    assert_eq!(tech.unwrap().id, 1);
    assert!(!tech.unwrap().name.is_empty());
}

#[test]
fn test_get_by_id_not_found() {
    let cat = EvasionCatalogue::new();
    assert!(cat.get_by_id(99999).is_none());
}

#[test]
fn test_search_by_payload_type_xss() {
    let cat = EvasionCatalogue::new();
    let query = CatalogueQuery::new().with_payload_type(PayloadType::Xss);
    let results = cat.search(&query);
    assert!(!results.is_empty());
    for r in &results {
        assert!(r.payload_types.contains(&PayloadType::Xss));
    }
}

#[test]
fn test_search_by_payload_type_sqli() {
    let cat = EvasionCatalogue::new();
    let query = CatalogueQuery::new().with_payload_type(PayloadType::Sqli);
    let results = cat.search(&query);
    assert!(!results.is_empty());
    for r in &results {
        assert!(r.payload_types.contains(&PayloadType::Sqli));
    }
}

#[test]
fn test_search_by_vendor() {
    let cat = EvasionCatalogue::new();
    let query = CatalogueQuery::new().with_vendor(WafVendor::Cloudflare);
    let results = cat.search(&query);
    assert!(!results.is_empty());
    for r in &results {
        assert!(r.target_vendors.contains(&WafVendor::Cloudflare));
    }
}

#[test]
fn test_search_by_encoding() {
    let cat = EvasionCatalogue::new();
    let query = CatalogueQuery::new().with_encoding(EvasionEncoding::DoubleUrlEncoding);
    let results = cat.search(&query);
    assert!(!results.is_empty());
    for r in &results {
        assert_eq!(r.encoding, EvasionEncoding::DoubleUrlEncoding);
    }
}

#[test]
fn test_search_by_min_success_rate() {
    let cat = EvasionCatalogue::new();
    let query = CatalogueQuery::new().with_min_success_rate(0.70);
    let results = cat.search(&query);
    assert!(!results.is_empty());
    for r in &results {
        assert!(r.success_rate >= 0.70);
    }
}

#[test]
fn test_search_by_stealth_level() {
    let cat = EvasionCatalogue::new();
    let query = CatalogueQuery::new().with_min_stealth(StealthLevel::Ghost);
    let results = cat.search(&query);
    assert!(!results.is_empty());
    for r in &results {
        assert_eq!(r.stealth_level, StealthLevel::Ghost);
    }
}

#[test]
fn test_search_by_tag() {
    let cat = EvasionCatalogue::new();
    let query = CatalogueQuery::new().with_tag("unicode");
    let results = cat.search(&query);
    assert!(!results.is_empty());
    for r in &results {
        assert!(r.tags.iter().any(|t| t.contains("unicode")));
    }
}

#[test]
fn test_search_combined_filters() {
    let cat = EvasionCatalogue::new();
    let query = CatalogueQuery::new()
        .with_payload_type(PayloadType::Xss)
        .with_encoding(EvasionEncoding::DoubleUrlEncoding);
    let results = cat.search(&query);
    assert!(!results.is_empty());
    for r in &results {
        assert!(r.payload_types.contains(&PayloadType::Xss));
        assert_eq!(r.encoding, EvasionEncoding::DoubleUrlEncoding);
    }
}

#[test]
fn test_composable_with() {
    let cat = EvasionCatalogue::new();
    let composable = cat.composable_with(1);
    assert!(!composable.is_empty());
}

#[test]
fn test_composable_with_nonexistent() {
    let cat = EvasionCatalogue::new();
    let composable = cat.composable_with(99999);
    assert!(composable.is_empty());
}

#[test]
fn test_top_techniques() {
    let cat = EvasionCatalogue::new();
    let top = cat.top_techniques(10);
    assert_eq!(top.len(), 10);
    for i in 0..top.len() - 1 {
        assert!(top[i].success_rate >= top[i + 1].success_rate);
    }
}

#[test]
fn test_payload_types_coverage() {
    let cat = EvasionCatalogue::new();
    let types = cat.payload_types();
    assert!(types.contains(&PayloadType::Xss));
    assert!(types.contains(&PayloadType::Sqli));
    assert!(types.contains(&PayloadType::CommandInjection));
    assert!(types.contains(&PayloadType::PathTraversal));
    assert!(types.contains(&PayloadType::Ssti));
    assert!(types.contains(&PayloadType::Ssrf));
}

#[test]
fn test_by_stealth_ghost() {
    let cat = EvasionCatalogue::new();
    let ghosts = cat.by_stealth(StealthLevel::Ghost);
    assert!(!ghosts.is_empty());
    for g in &ghosts {
        assert_eq!(g.stealth_level, StealthLevel::Ghost);
    }
}

#[test]
fn test_by_stealth_loud() {
    let cat = EvasionCatalogue::new();
    let loud = cat.by_stealth(StealthLevel::Loud);
    assert!(!loud.is_empty());
    for l in &loud {
        assert_eq!(l.stealth_level, StealthLevel::Loud);
    }
}

#[test]
fn test_all_techniques_have_names() {
    let cat = EvasionCatalogue::new();
    for i in 1..=cat.total_techniques() as u32 {
        if let Some(t) = cat.get_by_id(i) {
            assert!(!t.name.is_empty(), "Technique {} has empty name", i);
            assert!(
                !t.description.is_empty(),
                "Technique {} has empty description",
                i
            );
        }
    }
}

#[test]
fn test_all_techniques_have_payload_types() {
    let cat = EvasionCatalogue::new();
    for i in 1..=cat.total_techniques() as u32 {
        if let Some(t) = cat.get_by_id(i) {
            assert!(
                !t.payload_types.is_empty(),
                "Technique {} has no payload types",
                i
            );
        }
    }
}

#[test]
fn test_all_techniques_have_vendors() {
    let cat = EvasionCatalogue::new();
    for i in 1..=cat.total_techniques() as u32 {
        if let Some(t) = cat.get_by_id(i) {
            assert!(
                !t.target_vendors.is_empty(),
                "Technique {} has no vendors",
                i
            );
        }
    }
}

#[test]
fn test_success_rates_in_range() {
    let cat = EvasionCatalogue::new();
    for i in 1..=cat.total_techniques() as u32 {
        if let Some(t) = cat.get_by_id(i) {
            assert!(
                t.success_rate >= 0.0 && t.success_rate <= 1.0,
                "Technique {} has invalid success rate {}",
                i,
                t.success_rate
            );
        }
    }
}

#[test]
fn test_display_payload_types() {
    let types = vec![
        PayloadType::Xss,
        PayloadType::Sqli,
        PayloadType::CommandInjection,
        PayloadType::PathTraversal,
        PayloadType::Ssti,
        PayloadType::Ssrf,
        PayloadType::Xxe,
        PayloadType::Ldap,
        PayloadType::Xpath,
        PayloadType::Crlf,
        PayloadType::OpenRedirect,
        PayloadType::Deserialization,
    ];
    for t in types {
        assert!(!format!("{}", t).is_empty());
    }
}

#[test]
fn test_display_encodings() {
    let encs = vec![
        EvasionEncoding::None,
        EvasionEncoding::UrlEncoding,
        EvasionEncoding::DoubleUrlEncoding,
        EvasionEncoding::UnicodeNormalization,
        EvasionEncoding::OverlongUtf8,
        EvasionEncoding::HtmlEntity,
        EvasionEncoding::HexEncoding,
        EvasionEncoding::OctalEncoding,
        EvasionEncoding::Base64,
        EvasionEncoding::JsUnicode,
        EvasionEncoding::CssEscape,
        EvasionEncoding::MixedCase,
        EvasionEncoding::CommentInsertion,
        EvasionEncoding::WhitespaceVariation,
        EvasionEncoding::NullByte,
        EvasionEncoding::ChunkedTransfer,
        EvasionEncoding::Multipart,
        EvasionEncoding::CharSubstitution,
    ];
    for e in encs {
        assert!(!format!("{}", e).is_empty());
    }
}

#[test]
fn test_display_stealth_levels() {
    let levels = vec![
        StealthLevel::Loud,
        StealthLevel::Moderate,
        StealthLevel::Stealthy,
        StealthLevel::Ghost,
    ];
    for l in levels {
        assert!(!format!("{}", l).is_empty());
    }
}

#[test]
fn test_stealth_ordering() {
    assert!(StealthLevel::Loud < StealthLevel::Moderate);
    assert!(StealthLevel::Moderate < StealthLevel::Stealthy);
    assert!(StealthLevel::Stealthy < StealthLevel::Ghost);
}

#[test]
fn test_empty_query_returns_all() {
    let cat = EvasionCatalogue::new();
    let query = CatalogueQuery::new();
    let results = cat.search(&query);
    assert_eq!(results.len(), cat.total_techniques());
}

#[test]
fn test_search_command_injection() {
    let cat = EvasionCatalogue::new();
    let query = CatalogueQuery::new().with_payload_type(PayloadType::CommandInjection);
    let results = cat.search(&query);
    assert!(results.len() >= 5, "Expected at least 5 cmdi techniques");
}

#[test]
fn test_search_ssrf() {
    let cat = EvasionCatalogue::new();
    let query = CatalogueQuery::new().with_payload_type(PayloadType::Ssrf);
    let results = cat.search(&query);
    assert!(results.len() >= 3, "Expected at least 3 SSRF techniques");
}

#[test]
fn test_unique_ids() {
    let cat = EvasionCatalogue::new();
    let mut seen = std::collections::HashSet::new();
    for i in 1..=200u32 {
        if let Some(t) = cat.get_by_id(i) {
            assert!(seen.insert(t.id), "Duplicate ID {}", t.id);
        }
    }
}
