use super::*;

// ── Fixture JS patterns (≥5 required by acceptance criteria) ──

const FIXTURE_NO_ORIGIN_INNERHTML: &str = r#"
window.addEventListener('message', function(event) {
    document.getElementById('output').innerHTML = event.data;
});
"#;

const FIXTURE_NO_ORIGIN_EVAL: &str = r#"
window.addEventListener("message", function(e) {
    eval(e.data.code);
});
"#;

const FIXTURE_NO_ORIGIN_LOCATION: &str = r#"
window.addEventListener('message', (event) => {
    window.location.href = event.data.url;
});
"#;

const FIXTURE_ORIGIN_CHECK_SAFE: &str = r#"
window.addEventListener('message', function(event) {
    if (event.origin === 'https://trusted.com') {
        document.getElementById('msg').textContent = event.data;
    }
});
"#;

const FIXTURE_NO_ORIGIN_DOCUMENT_WRITE: &str = r#"
window.addEventListener("message", (e) => {
    document.write(e.data);
});
"#;

const FIXTURE_DATA_LEAK_NO_ORIGIN: &str = r#"
window.addEventListener('message', function(event) {
    var config = { secret: 'api_key_12345', user: 'admin' };
    event.source.postMessage(config, '*');
});
"#;

const FIXTURE_WINDOW_OPENER_NO_ORIGIN: &str = r#"
window.addEventListener('message', function(event) {
    window.opener.postMessage(document.cookie, '*');
});
"#;

const FIXTURE_PROTOTYPE_POLLUTION: &str = r#"
window.addEventListener("message", function(event) {
    Object.assign({}, event.data);
});
"#;

const FIXTURE_ONMESSAGE_HANDLER: &str = r#"
window.onmessage = function(event) {
    document.getElementById('display').innerHTML = event.data.html;
};
"#;

const FIXTURE_ARROW_NO_PARENS: &str = r#"
window.addEventListener('message', e => {
    eval(e.data);
});
"#;

const FIXTURE_MULTIPLE_LISTENERS: &str = r#"
window.addEventListener('message', function(event) {
    document.getElementById('a').innerHTML = event.data;
});
window.addEventListener('message', function(e) {
    window.location.assign(e.data.url);
});
"#;

const FIXTURE_ORIGIN_CHECK_STRICT_STILL_DANGEROUS: &str = r#"
window.addEventListener('message', function(event) {
    if (event.origin !== 'https://safe.com') return;
    eval(event.data.code);
});
"#;

const FIXTURE_PARENT_POSTMESSAGE: &str = r#"
window.addEventListener('message', function(event) {
    window.parent.postMessage({token: localStorage.getItem('jwt')}, '*');
});
"#;

const FIXTURE_SPREAD_MERGE: &str = r#"
window.addEventListener('message', function(event) {
    var settings = { ...event.data, updated: true };
    applySettings(settings);
});
"#;

const FIXTURE_FOR_IN_MERGE: &str = r#"
window.addEventListener('message', function(event) {
    for (let key in event.data) {
        config[key] = event.data[key];
    }
});
"#;

// ── Listener extraction tests ──

#[test]
fn extract_finds_addeventlistener_function() {
    let listeners = extract_message_listeners(FIXTURE_NO_ORIGIN_INNERHTML);
    assert_eq!(listeners.len(), 1);
    assert!(listeners[0].0.contains("innerHTML"));
}

#[test]
fn extract_finds_addeventlistener_arrow() {
    let listeners = extract_message_listeners(FIXTURE_NO_ORIGIN_LOCATION);
    assert_eq!(listeners.len(), 1);
    assert!(listeners[0].0.contains("location.href"));
}

#[test]
fn extract_finds_onmessage_handler() {
    let listeners = extract_message_listeners(FIXTURE_ONMESSAGE_HANDLER);
    assert_eq!(listeners.len(), 1);
    assert!(listeners[0].0.contains("innerHTML"));
}

#[test]
fn extract_finds_arrow_without_parens() {
    let listeners = extract_message_listeners(FIXTURE_ARROW_NO_PARENS);
    assert_eq!(listeners.len(), 1);
    assert!(listeners[0].0.contains("eval"));
}

#[test]
fn extract_finds_multiple_listeners() {
    let listeners = extract_message_listeners(FIXTURE_MULTIPLE_LISTENERS);
    assert_eq!(listeners.len(), 2);
}

#[test]
fn extract_returns_empty_for_no_listeners() {
    let listeners = extract_message_listeners("var x = 1; console.log(x);");
    assert!(listeners.is_empty());
}

// ── Origin validation tests ──

#[test]
fn origin_check_detected_strict_equality() {
    let body = "if (event.origin === 'https://trusted.com') { doStuff(); }";
    assert!(has_origin_validation(body));
}

#[test]
fn origin_check_detected_not_equal() {
    let body = "if (event.origin !== 'https://safe.com') return;";
    assert!(has_origin_validation(body));
}

#[test]
fn origin_check_detected_includes() {
    let body = "if (!allowedOrigins.includes(event.origin)) return;";
    assert!(has_origin_validation(body));
}

#[test]
fn origin_check_missing_for_vulnerable_handler() {
    let listeners = extract_message_listeners(FIXTURE_NO_ORIGIN_INNERHTML);
    assert!(!has_origin_validation(&listeners[0].0));
}

#[test]
fn origin_check_detected_in_safe_handler() {
    let listeners = extract_message_listeners(FIXTURE_ORIGIN_CHECK_SAFE);
    assert!(has_origin_validation(&listeners[0].0));
}

// ── Sink detection tests ──

#[test]
fn detect_innerhtml_sink() {
    let sinks = detect_sinks("element.innerHTML = event.data;");
    assert!(sinks.contains(&DomSink::InnerHtml));
}

#[test]
fn detect_eval_sink() {
    let sinks = detect_sinks("eval(e.data.code);");
    assert!(sinks.contains(&DomSink::Eval));
}

#[test]
fn detect_location_href_sink() {
    let sinks = detect_sinks("window.location.href = event.data.url;");
    assert!(sinks.contains(&DomSink::LocationHref));
}

#[test]
fn detect_document_write_sink() {
    let sinks = detect_sinks("document.write(e.data);");
    assert!(sinks.contains(&DomSink::DocumentWrite));
}

#[test]
fn detect_insert_adjacent_html_sink() {
    let sinks = detect_sinks("el.insertAdjacentHTML('beforeend', event.data);");
    assert!(sinks.contains(&DomSink::InsertAdjacentHtml));
}

#[test]
fn detect_no_sinks_in_safe_code() {
    let sinks = detect_sinks("console.log(event.data);");
    assert!(sinks.is_empty());
}

// ── Data response / window reference / prototype pollution detection ──

#[test]
fn detect_data_response_via_source() {
    let body = "event.source.postMessage(config, '*');";
    assert!(detects_data_response(body));
}

#[test]
fn detect_data_response_via_parent() {
    let body = "parent.postMessage(data, '*');";
    assert!(detects_data_response(body));
}

#[test]
fn detect_window_reference_opener() {
    let body = "window.opener.postMessage(document.cookie, '*');";
    assert!(detects_window_reference(body));
}

#[test]
fn detect_window_reference_parent() {
    let body = "window.parent.postMessage({token: jwt}, '*');";
    assert!(detects_window_reference(body));
}

#[test]
fn detect_prototype_pollution_object_assign() {
    let body = "Object.assign({}, event.data);";
    assert!(detects_prototype_pollution(body));
}

#[test]
fn detect_prototype_pollution_spread() {
    let body = "var cfg = { ...event.data };";
    assert!(detects_prototype_pollution(body));
}

#[test]
fn detect_prototype_pollution_for_in() {
    let body = "for (let key in event.data) { config[key] = event.data[key]; }";
    assert!(detects_prototype_pollution(body));
}

// ── Full analysis pipeline tests (5 fixture patterns) ──

#[test]
fn fixture_1_no_origin_innerhtml_is_exploitable() {
    let config = PostMessageConfig::default().with_target("https://victim.com/page");
    let result = analyze_postmessage(FIXTURE_NO_ORIGIN_INNERHTML, &config);

    assert_eq!(result.listeners_found.len(), 1);
    assert!(!result.listeners_found[0].has_origin_check);
    assert!(result.listeners_found[0]
        .sinks
        .contains(&DomSink::InnerHtml));

    let missing_origin = result
        .findings
        .iter()
        .any(|f| f.vuln_type == PostMessageVulnType::MissingOriginCheck);
    assert!(missing_origin, "should detect missing origin check");

    let sink_finding = result
        .findings
        .iter()
        .any(|f| f.vuln_type == PostMessageVulnType::DangerousSink);
    assert!(sink_finding, "should detect dangerous sink");
}

#[test]
fn fixture_2_no_origin_eval_is_critical() {
    let config = PostMessageConfig::default().with_target("https://victim.com/page");
    let result = analyze_postmessage(FIXTURE_NO_ORIGIN_EVAL, &config);

    assert!(
        result.summary.critical_count >= 1,
        "eval sink without origin check must be critical"
    );
    let eval_finding = result
        .findings
        .iter()
        .find(|f| f.sink == Some(DomSink::Eval));
    assert!(eval_finding.is_some());
    assert_eq!(
        eval_finding.unwrap().severity,
        PostMessageSeverity::Critical
    );
}

#[test]
fn fixture_3_no_origin_location_detected() {
    let config = PostMessageConfig::default().with_target("https://victim.com/page");
    let result = analyze_postmessage(FIXTURE_NO_ORIGIN_LOCATION, &config);

    let loc_finding = result
        .findings
        .iter()
        .find(|f| f.sink == Some(DomSink::LocationHref));
    assert!(loc_finding.is_some());
}

#[test]
fn fixture_4_data_leak_detected() {
    let config = PostMessageConfig::default().with_target("https://victim.com/page");
    let result = analyze_postmessage(FIXTURE_DATA_LEAK_NO_ORIGIN, &config);

    let leak = result
        .findings
        .iter()
        .any(|f| f.vuln_type == PostMessageVulnType::CrossOriginDataLeak);
    assert!(leak, "should detect cross-origin data leak");
}

#[test]
fn fixture_5_prototype_pollution_detected() {
    let config = PostMessageConfig::default().with_target("https://victim.com/page");
    let result = analyze_postmessage(FIXTURE_PROTOTYPE_POLLUTION, &config);

    let proto = result
        .findings
        .iter()
        .any(|f| f.vuln_type == PostMessageVulnType::PrototypePollution);
    assert!(proto, "should detect prototype pollution");
    assert!(result.summary.critical_count >= 1);
}

#[test]
fn fixture_safe_handler_produces_no_exploitable_findings() {
    let config = PostMessageConfig::default().with_target("https://victim.com/page");
    let result = analyze_postmessage(FIXTURE_ORIGIN_CHECK_SAFE, &config);

    assert_eq!(result.listeners_found.len(), 1);
    assert!(result.listeners_found[0].has_origin_check);
    let exploitable = result
        .findings
        .iter()
        .filter(|f| f.poc_html.is_some())
        .count();
    assert_eq!(
        exploitable, 0,
        "safe handler should have no exploitable findings"
    );
}

#[test]
fn fixture_window_opener_detected() {
    let config = PostMessageConfig::default().with_target("https://victim.com/page");
    let result = analyze_postmessage(FIXTURE_WINDOW_OPENER_NO_ORIGIN, &config);

    let opener = result
        .findings
        .iter()
        .any(|f| f.vuln_type == PostMessageVulnType::WindowReferenceAttack);
    assert!(opener, "should detect window.opener attack");
}

#[test]
fn fixture_spread_merge_detected() {
    let config = PostMessageConfig::default().with_target("https://victim.com/page");
    let result = analyze_postmessage(FIXTURE_SPREAD_MERGE, &config);

    let proto = result
        .findings
        .iter()
        .any(|f| f.vuln_type == PostMessageVulnType::PrototypePollution);
    assert!(
        proto,
        "spread merge should trigger prototype pollution finding"
    );
}

#[test]
fn fixture_document_write_no_origin() {
    let config = PostMessageConfig::default().with_target("https://victim.com/page");
    let result = analyze_postmessage(FIXTURE_NO_ORIGIN_DOCUMENT_WRITE, &config);

    let dw = result
        .findings
        .iter()
        .find(|f| f.sink == Some(DomSink::DocumentWrite));
    assert!(dw.is_some(), "should detect document.write sink");
    assert_eq!(dw.unwrap().severity, PostMessageSeverity::Critical);
}

#[test]
fn fixture_parent_postmessage_detected() {
    let config = PostMessageConfig::default().with_target("https://victim.com/page");
    let result = analyze_postmessage(FIXTURE_PARENT_POSTMESSAGE, &config);

    let window_ref = result
        .findings
        .iter()
        .any(|f| f.vuln_type == PostMessageVulnType::WindowReferenceAttack);
    assert!(window_ref, "should detect window.parent postMessage attack");
}

#[test]
fn fixture_for_in_merge_detected() {
    let config = PostMessageConfig::default().with_target("https://victim.com/page");
    let result = analyze_postmessage(FIXTURE_FOR_IN_MERGE, &config);

    let proto = result
        .findings
        .iter()
        .any(|f| f.vuln_type == PostMessageVulnType::PrototypePollution);
    assert!(
        proto,
        "for-in merge should trigger prototype pollution finding"
    );
}

// ── PoC generation tests ──

#[test]
fn poc_no_origin_contains_target_and_attacker() {
    let config = PostMessageConfig::default()
        .with_target("https://victim.com/app")
        .with_attacker_origin("https://evil.test");
    let poc = generate_no_origin_poc(&config);

    assert!(poc.contains("https://victim.com/app"));
    assert!(poc.contains("https://evil.test"));
    assert!(poc.contains("postMessage"));
    assert!(poc.contains("<iframe"));
}

#[test]
fn poc_sink_eval_contains_alert() {
    let config = PostMessageConfig::default().with_target("https://victim.com");
    let poc = generate_sink_poc(&config, DomSink::Eval);

    assert!(poc.contains("alert(document.domain)"));
    assert!(poc.contains("postMessage"));
}

#[test]
fn poc_sink_innerhtml_contains_img_onerror() {
    let config = PostMessageConfig::default().with_target("https://victim.com");
    let poc = generate_sink_poc(&config, DomSink::InnerHtml);

    assert!(poc.contains("onerror"));
}

#[test]
fn poc_data_leak_contains_exfil_listener() {
    let config = PostMessageConfig::default()
        .with_target("https://victim.com")
        .with_attacker_origin("https://evil.com");
    let poc = generate_data_leak_poc(&config);

    assert!(poc.contains("addEventListener"));
    assert!(poc.contains("exfil"));
    assert!(poc.contains("https://evil.com"));
}

#[test]
fn poc_window_ref_uses_window_open() {
    let config = PostMessageConfig::default().with_target("https://victim.com");
    let poc = generate_window_ref_poc(&config);

    assert!(poc.contains("window.open"));
}

#[test]
fn poc_prototype_pollution_sends_proto_payload() {
    let config = PostMessageConfig::default().with_target("https://victim.com");
    let poc = generate_prototype_pollution_poc(&config);

    assert!(poc.contains("__proto__"));
    assert!(poc.contains("isAdmin"));
}

#[test]
fn poc_generation_disabled_produces_no_pocs() {
    let config = PostMessageConfig::default()
        .with_target("https://victim.com/page")
        .with_poc_generation(false);
    let result = analyze_postmessage(FIXTURE_NO_ORIGIN_EVAL, &config);

    for finding in &result.findings {
        assert!(
            finding.poc_html.is_none(),
            "PoC should be None when generation disabled"
        );
    }
}

// ── Config builder tests ──

#[test]
fn config_default_values() {
    let config = PostMessageConfig::default();
    assert_eq!(config.attacker_origin, "https://evil.attacker.com");
    assert!(config.generate_poc);
    assert!(config.target_url.is_empty());
}

#[test]
fn config_builder_chain() {
    let config = PostMessageConfig::default()
        .with_target("https://app.test/page")
        .with_attacker_origin("https://my-evil.site")
        .with_poc_generation(false);

    assert_eq!(config.target_url, "https://app.test/page");
    assert_eq!(config.attacker_origin, "https://my-evil.site");
    assert!(!config.generate_poc);
}

// ── Display impl tests ──

#[test]
fn severity_display_non_empty() {
    assert!(!format!("{}", PostMessageSeverity::Info).is_empty());
    assert!(!format!("{}", PostMessageSeverity::Critical).is_empty());
}

#[test]
fn severity_ordering() {
    assert!(PostMessageSeverity::Info < PostMessageSeverity::Low);
    assert!(PostMessageSeverity::Low < PostMessageSeverity::Medium);
    assert!(PostMessageSeverity::Medium < PostMessageSeverity::High);
    assert!(PostMessageSeverity::High < PostMessageSeverity::Critical);
}

#[test]
fn vuln_type_display_non_empty() {
    assert!(!format!("{}", PostMessageVulnType::MissingOriginCheck).is_empty());
    assert!(!format!("{}", PostMessageVulnType::DangerousSink).is_empty());
    assert!(!format!("{}", PostMessageVulnType::CrossOriginDataLeak).is_empty());
    assert!(!format!("{}", PostMessageVulnType::WindowReferenceAttack).is_empty());
    assert!(!format!("{}", PostMessageVulnType::PrototypePollution).is_empty());
}

#[test]
fn dom_sink_display_non_empty() {
    assert!(!format!("{}", DomSink::InnerHtml).is_empty());
    assert!(!format!("{}", DomSink::Eval).is_empty());
    assert!(!format!("{}", DomSink::LocationHref).is_empty());
    assert!(!format!("{}", DomSink::DocumentWrite).is_empty());
    assert!(!format!("{}", DomSink::ScriptSrc).is_empty());
    assert!(!format!("{}", DomSink::InsertAdjacentHtml).is_empty());
}

// ── Summary correctness ──

#[test]
fn summary_counts_are_correct() {
    let config = PostMessageConfig::default().with_target("https://victim.com");
    let result = analyze_postmessage(FIXTURE_NO_ORIGIN_EVAL, &config);

    assert_eq!(result.summary.total_listeners, 1);
    assert!(result.summary.total_findings >= 2);
    assert!(result.summary.exploitable_count >= 1);
}

#[test]
fn multiple_listeners_all_analyzed() {
    let config = PostMessageConfig::default().with_target("https://victim.com");
    let result = analyze_postmessage(FIXTURE_MULTIPLE_LISTENERS, &config);

    assert_eq!(result.summary.total_listeners, 2);
    assert!(result.summary.total_findings >= 4);
}

#[test]
fn origin_check_with_dangerous_sink_still_reported() {
    let config = PostMessageConfig::default().with_target("https://victim.com");
    let result = analyze_postmessage(FIXTURE_ORIGIN_CHECK_STRICT_STILL_DANGEROUS, &config);

    let eval_finding = result
        .findings
        .iter()
        .find(|f| f.sink == Some(DomSink::Eval));
    assert!(
        eval_finding.is_some(),
        "eval sink should still be reported even with origin check"
    );
    assert_eq!(eval_finding.unwrap().severity, PostMessageSeverity::Medium);
}

#[test]
fn findings_sorted_by_severity_descending() {
    let config = PostMessageConfig::default().with_target("https://victim.com");
    let result = analyze_postmessage(FIXTURE_NO_ORIGIN_EVAL, &config);

    for window in result.findings.windows(2) {
        assert!(window[0].severity >= window[1].severity);
    }
}
