use super::dictionary_manager::*;

#[test]
fn test_new_manager_starts_empty() {
    let mgr = DictionaryManager::new();
    assert_eq!(mgr.loaded_count(), 0);
    assert_eq!(mgr.total_payload_count(), 0);
}

#[test]
fn test_lazy_loading_xss() {
    let mut mgr = DictionaryManager::new();
    assert!(!mgr.is_loaded(PayloadDictionary::Xss));
    let payloads = mgr.get_payloads(PayloadDictionary::Xss);
    assert!(!payloads.is_empty());
    assert!(mgr.is_loaded(PayloadDictionary::Xss));
}

#[test]
fn test_lazy_loading_sqli() {
    let mut mgr = DictionaryManager::new();
    let payloads = mgr.get_payloads(PayloadDictionary::Sqli);
    assert!(!payloads.is_empty());
    assert!(mgr.is_loaded(PayloadDictionary::Sqli));
}

#[test]
fn test_lazy_loading_ssti() {
    let mut mgr = DictionaryManager::new();
    let payloads = mgr.get_payloads(PayloadDictionary::Ssti);
    assert!(!payloads.is_empty());
    assert!(mgr.is_loaded(PayloadDictionary::Ssti));
}

#[test]
fn test_lazy_loading_ssrf() {
    let mut mgr = DictionaryManager::new();
    let payloads = mgr.get_payloads(PayloadDictionary::Ssrf);
    assert!(!payloads.is_empty());
    assert!(mgr.is_loaded(PayloadDictionary::Ssrf));
}

#[test]
fn test_lazy_loading_cmdi_v2() {
    let mut mgr = DictionaryManager::new();
    let payloads = mgr.get_payloads(PayloadDictionary::CmdiV2);
    assert!(!payloads.is_empty());
    assert!(mgr.is_loaded(PayloadDictionary::CmdiV2));
}

#[test]
fn test_no_reload_on_second_access() {
    let mut mgr = DictionaryManager::new();
    let count1 = mgr.get_payloads(PayloadDictionary::Xss).len();
    let count2 = mgr.get_payloads(PayloadDictionary::Xss).len();
    assert_eq!(count1, count2);
    assert_eq!(mgr.loaded_count(), 1);
}

#[test]
fn test_load_all_dictionaries() {
    let mut mgr = DictionaryManager::new();
    for dict in PayloadDictionary::all() {
        mgr.load_dictionary(*dict);
    }
    assert_eq!(mgr.loaded_count(), 5);
    assert!(mgr.total_payload_count() >= 700);
}

#[test]
fn test_search_finds_payloads() {
    let mut mgr = DictionaryManager::new();
    let results = mgr.search("alert", &[PayloadDictionary::Xss]);
    assert!(
        !results.is_empty(),
        "Search for 'alert' in XSS should return results"
    );
}

#[test]
fn test_search_by_tag() {
    let mut mgr = DictionaryManager::new();
    let results = mgr.search("Reflected", &[PayloadDictionary::Xss]);
    assert!(
        !results.is_empty(),
        "Search for 'Reflected' tag should return results"
    );
}

#[test]
fn test_search_case_insensitive() {
    let mut mgr = DictionaryManager::new();
    let results = mgr.search("SLEEP", &[PayloadDictionary::Sqli]);
    assert!(
        !results.is_empty(),
        "Case-insensitive search for 'SLEEP' should return results"
    );
}

#[test]
fn test_filter_by_aggressiveness() {
    let mut mgr = DictionaryManager::new();
    let stealth =
        mgr.filter_by_aggressiveness(PayloadDictionary::Sqli, PayloadAggressiveness::Stealth);
    assert!(!stealth.is_empty(), "Should have stealth SQLi payloads");
    let aggressive =
        mgr.filter_by_aggressiveness(PayloadDictionary::Sqli, PayloadAggressiveness::Aggressive);
    assert!(
        !aggressive.is_empty(),
        "Should have aggressive SQLi payloads"
    );
}

#[test]
fn test_custom_payload_import() {
    let mut mgr = DictionaryManager::new();
    let added = mgr.import_custom_payload(
        "custom<script>alert('custom')</script>".to_string(),
        PayloadDictionary::Xss,
        PayloadAggressiveness::Normal,
        vec!["custom".to_string()],
    );
    assert!(added, "Custom payload should be added");
    assert_eq!(mgr.custom_payload_count(), 1);
}

#[test]
fn test_custom_payload_deduplication() {
    let mut mgr = DictionaryManager::new();
    let first = mgr.import_custom_payload(
        "dedup_test_payload".to_string(),
        PayloadDictionary::Xss,
        PayloadAggressiveness::Normal,
        vec![],
    );
    let second = mgr.import_custom_payload(
        "dedup_test_payload".to_string(),
        PayloadDictionary::Xss,
        PayloadAggressiveness::Normal,
        vec![],
    );
    assert!(first, "First import should succeed");
    assert!(!second, "Duplicate import should be rejected");
    assert_eq!(mgr.custom_payload_count(), 1);
}

#[test]
fn test_dedup_against_library_payloads() {
    let mut mgr = DictionaryManager::new();
    mgr.load_dictionary(PayloadDictionary::Xss);
    let added = mgr.import_custom_payload(
        "<script>alert(1)</script>".to_string(),
        PayloadDictionary::Xss,
        PayloadAggressiveness::Normal,
        vec![],
    );
    assert!(
        !added,
        "Payload from library should be rejected as duplicate"
    );
}

#[test]
fn test_bulk_import() {
    let mut mgr = DictionaryManager::new();
    let payloads = vec![
        "bulk1_test".to_string(),
        "bulk2_test".to_string(),
        "bulk1_test".to_string(), // duplicate
        "bulk3_test".to_string(),
    ];
    let added = mgr.import_bulk(
        payloads,
        PayloadDictionary::Xss,
        PayloadAggressiveness::Normal,
        vec!["bulk".to_string()],
    );
    assert_eq!(added, 3, "Should add 3 unique payloads");
    assert_eq!(mgr.custom_payload_count(), 3);
}

#[test]
fn test_stats_recording() {
    let mut mgr = DictionaryManager::new();
    mgr.record_attempt("test_payload", true);
    mgr.record_attempt("test_payload", false);
    mgr.record_attempt("test_payload", true);

    let stats = mgr.get_stats("test_payload").unwrap();
    assert_eq!(stats.attempts, 3);
    assert_eq!(stats.successes, 2);
    assert!((stats.success_rate() - 0.6667).abs() < 0.01);
}

#[test]
fn test_stats_zero_attempts() {
    let stats = PayloadStats {
        attempts: 0,
        successes: 0,
    };
    assert_eq!(stats.success_rate(), 0.0);
}

#[test]
fn test_top_payloads() {
    let mut mgr = DictionaryManager::new();
    mgr.record_attempt("good_payload", true);
    mgr.record_attempt("good_payload", true);
    mgr.record_attempt("good_payload", true);
    mgr.record_attempt("bad_payload", false);
    mgr.record_attempt("bad_payload", false);
    mgr.record_attempt("bad_payload", true);
    mgr.record_attempt("meh_payload", true);
    mgr.record_attempt("meh_payload", false);

    let top = mgr.top_payloads(3, 2);
    assert_eq!(top.len(), 3);
    assert_eq!(top[0].0, "good_payload");
    assert!((top[0].1 - 1.0).abs() < 0.001);
}

#[test]
fn test_top_payloads_min_attempts_filter() {
    let mut mgr = DictionaryManager::new();
    mgr.record_attempt("one_shot", true);
    mgr.record_attempt("many_shots", true);
    mgr.record_attempt("many_shots", true);
    mgr.record_attempt("many_shots", true);

    let top = mgr.top_payloads(10, 2);
    assert_eq!(top.len(), 1);
    assert_eq!(top[0].0, "many_shots");
}

#[test]
fn test_search_custom_payloads() {
    let mut mgr = DictionaryManager::new();
    mgr.import_custom_payload(
        "custom_search_target".to_string(),
        PayloadDictionary::Xss,
        PayloadAggressiveness::Normal,
        vec!["searchable_tag".to_string()],
    );
    let results = mgr.search("searchable_tag", &[PayloadDictionary::Xss]);
    assert_eq!(results.len(), 1);
}

#[test]
fn test_tagged_entries_have_tags() {
    let mut mgr = DictionaryManager::new();
    let payloads = mgr.get_payloads(PayloadDictionary::Xss);
    for entry in payloads {
        assert!(
            !entry.tags.is_empty(),
            "Payload should have tags: {}",
            entry.payload
        );
    }
}

#[test]
fn test_default_trait() {
    let mgr = DictionaryManager::default();
    assert_eq!(mgr.loaded_count(), 0);
}

#[test]
fn test_ssti_aggressiveness_classification() {
    let mut mgr = DictionaryManager::new();
    let stealth =
        mgr.filter_by_aggressiveness(PayloadDictionary::Ssti, PayloadAggressiveness::Stealth);
    assert!(!stealth.is_empty(), "Detection payloads should be stealth");
    let aggressive =
        mgr.filter_by_aggressiveness(PayloadDictionary::Ssti, PayloadAggressiveness::Aggressive);
    assert!(!aggressive.is_empty(), "RCE payloads should be aggressive");
}

#[test]
fn test_ssrf_aggressiveness_classification() {
    let mut mgr = DictionaryManager::new();
    let stealth =
        mgr.filter_by_aggressiveness(PayloadDictionary::Ssrf, PayloadAggressiveness::Stealth);
    assert!(!stealth.is_empty(), "IP format bypass should be stealth");
    let aggressive =
        mgr.filter_by_aggressiveness(PayloadDictionary::Ssrf, PayloadAggressiveness::Aggressive);
    assert!(
        !aggressive.is_empty(),
        "Protocol smuggling should be aggressive"
    );
}
