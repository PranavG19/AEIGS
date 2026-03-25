use super::xss_payloads::*;

#[test]
fn test_total_payload_count_meets_minimum() {
    assert!(
        xss_payload_count() >= 140,
        "Expected 140+ XSS payloads, got {}",
        xss_payload_count()
    );
}

#[test]
fn test_reflected_payloads_minimum_count() {
    let reflected = xss_payloads_by_category(XssCategory::Reflected);
    assert!(
        reflected.len() >= 50,
        "Expected 50+ reflected XSS payloads, got {}",
        reflected.len()
    );
}

#[test]
fn test_stored_payloads_minimum_count() {
    let stored = xss_payloads_by_category(XssCategory::Stored);
    assert!(
        stored.len() >= 30,
        "Expected 30+ stored XSS payloads, got {}",
        stored.len()
    );
}

#[test]
fn test_dom_based_payloads_minimum_count() {
    let dom = xss_payloads_by_category(XssCategory::DomBased);
    assert!(
        dom.len() >= 30,
        "Expected 30+ DOM-based XSS payloads, got {}",
        dom.len()
    );
}

#[test]
fn test_mutation_xss_payloads_minimum_count() {
    let mutation = xss_payloads_by_category(XssCategory::MutationXss);
    assert!(
        mutation.len() >= 20,
        "Expected 20+ mutation XSS payloads, got {}",
        mutation.len()
    );
}

#[test]
fn test_polyglot_payloads_minimum_count() {
    let polyglot = xss_payloads_by_category(XssCategory::Polyglot);
    assert!(
        polyglot.len() >= 10,
        "Expected 10+ polyglot XSS payloads, got {}",
        polyglot.len()
    );
}

#[test]
fn test_all_contexts_covered() {
    for context in XssContext::all() {
        let payloads = xss_payloads_by_context(*context);
        assert!(
            !payloads.is_empty(),
            "No payloads for context {:?}",
            context
        );
    }
}

#[test]
fn test_waf_bypass_payloads_exist() {
    let bypass = xss_waf_bypass_payloads();
    assert!(
        bypass.len() >= 10,
        "Expected 10+ WAF bypass payloads, got {}",
        bypass.len()
    );
}

#[test]
fn test_event_handlers_exhaustive() {
    assert!(
        EVENT_HANDLERS.len() >= 100,
        "Expected 100+ event handlers, got {}",
        EVENT_HANDLERS.len()
    );
}

#[test]
fn test_event_handler_generation() {
    let payloads = generate_event_handler_payloads("img");
    assert_eq!(payloads.len(), EVENT_HANDLERS.len());
    assert!(payloads[0].starts_with("<img "));
    assert!(payloads[0].contains("=alert(1)>"));
}

#[test]
fn test_no_empty_payloads() {
    for payload in all_xss_payloads() {
        assert!(!payload.payload.is_empty(), "Empty payload found");
        assert!(
            !payload.description.is_empty(),
            "Empty description for payload: {}",
            payload.payload
        );
    }
}

#[test]
fn test_no_duplicate_payloads() {
    let all = all_xss_payloads();
    let mut seen = std::collections::HashSet::new();
    for p in &all {
        assert!(
            seen.insert(p.payload),
            "Duplicate payload found: {}",
            p.payload
        );
    }
}

#[test]
fn test_all_categories_represented_in_all() {
    let all = all_xss_payloads();
    for cat in XssCategory::all() {
        assert!(
            all.iter().any(|p| p.category == *cat),
            "Category {:?} missing from all payloads",
            cat
        );
    }
}

#[test]
fn test_reflected_contains_classic_vectors() {
    let reflected = xss_payloads_by_category(XssCategory::Reflected);
    let payloads: Vec<&str> = reflected.iter().map(|p| p.payload).collect();
    assert!(payloads.contains(&"<script>alert(1)</script>"));
    assert!(payloads.contains(&"<img src=x onerror=alert(1)>"));
    assert!(payloads.contains(&"<svg onload=alert(1)>"));
}

#[test]
fn test_stored_contains_exfiltration_vectors() {
    let stored = xss_payloads_by_category(XssCategory::Stored);
    let has_cookie_exfil = stored.iter().any(|p| p.payload.contains("document.cookie"));
    assert!(
        has_cookie_exfil,
        "Stored payloads should include cookie exfiltration"
    );
}

#[test]
fn test_dom_payloads_contain_fragment_vectors() {
    let dom = xss_payloads_by_category(XssCategory::DomBased);
    let has_fragment = dom.iter().any(|p| p.payload.starts_with('#'));
    assert!(
        has_fragment,
        "DOM payloads should include fragment-based vectors"
    );
}
