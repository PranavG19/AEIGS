use super::*;

// ─── 8 fixture JS strings with known DOM XSS patterns ───────────────

/// Fixture 1: location.hash → innerHTML (classic DOM XSS)
const FIXTURE_HASH_INNERHTML: &str = r#"
var hash = location.hash.substring(1);
document.getElementById("output").innerHTML = hash;
"#;

/// Fixture 2: document.referrer → document.write
const FIXTURE_REFERRER_DOCWRITE: &str = r#"
var ref = document.referrer;
document.write("<a href='" + ref + "'>Back</a>");
"#;

/// Fixture 3: URLSearchParams → eval
const FIXTURE_SEARCH_PARAMS_EVAL: &str = r#"
var params = new URLSearchParams(location.search);
var code = params.get("action");
eval(code);
"#;

/// Fixture 4: postMessage event.data → jQuery .html()
const FIXTURE_POSTMESSAGE_JQUERY: &str = r##"
window.addEventListener("message", function(event) {
    var msg = event.data;
    $("#container").html(msg);
});
"##;

/// Fixture 5: document.cookie → fetch URL construction
const FIXTURE_COOKIE_FETCH: &str = r#"
var session = document.cookie;
var url = "/api/data?token=" + session;
fetch(url);
"#;

/// Fixture 6: location.search → location.assign (open redirect / XSS via javascript:)
const FIXTURE_SEARCH_REDIRECT: &str = r#"
var search = location.search;
var redir = search.split("url=")[1];
location.assign(redir);
"#;

/// Fixture 7: window.name → script.src
const FIXTURE_WINDOWNAME_SCRIPTSRC: &str = r#"
var payload = window.name;
var s = document.createElement("script");
s.src = payload;
document.body.appendChild(s);
"#;

/// Fixture 8: location.href → setTimeout string execution
const FIXTURE_HREF_SETTIMEOUT: &str = r##"
var href = location.href;
var action = href.split("#")[1];
setTimeout(action, 100);
"##;

// ─── Fixture flow detection tests ────────────────────────────────────

#[test]
fn fixture_1_hash_to_innerhtml() {
    let result = analyze_js_taint(FIXTURE_HASH_INNERHTML);
    assert!(result.has_flows(), "should detect hash→innerHTML flow");
    let flow = &result.flows[0];
    assert_eq!(flow.source, TaintSource::LocationHash);
    assert_eq!(flow.sink, TaintSink::InnerHtml);
}

#[test]
fn fixture_2_referrer_to_docwrite() {
    let result = analyze_js_taint(FIXTURE_REFERRER_DOCWRITE);
    assert!(
        result.has_flows(),
        "should detect referrer→document.write flow"
    );
    let flow = &result.flows[0];
    assert_eq!(flow.source, TaintSource::DocumentReferrer);
    assert_eq!(flow.sink, TaintSink::DocumentWrite);
}

#[test]
fn fixture_3_searchparams_to_eval() {
    let result = analyze_js_taint(FIXTURE_SEARCH_PARAMS_EVAL);
    assert!(
        result.has_flows(),
        "should detect URLSearchParams→eval flow"
    );
    let has_eval = result.flows.iter().any(|f| f.sink == TaintSink::Eval);
    assert!(has_eval, "should find an eval sink");
}

#[test]
fn fixture_4_postmessage_to_jquery_html() {
    let result = analyze_js_taint(FIXTURE_POSTMESSAGE_JQUERY);
    assert!(
        result.has_flows(),
        "should detect postMessage→$.html() flow"
    );
    let has_jquery = result.flows.iter().any(|f| f.sink == TaintSink::JQueryHtml);
    assert!(has_jquery, "should find jQuery .html() sink");
}

#[test]
fn fixture_5_cookie_to_fetch() {
    let result = analyze_js_taint(FIXTURE_COOKIE_FETCH);
    assert!(result.has_flows(), "should detect cookie→fetch flow");
    let has_fetch = result.flows.iter().any(|f| f.sink == TaintSink::FetchUrl);
    assert!(has_fetch, "should find fetch URL sink");
}

#[test]
fn fixture_6_search_to_location_assign() {
    let result = analyze_js_taint(FIXTURE_SEARCH_REDIRECT);
    assert!(
        result.has_flows(),
        "should detect location.search→location.assign flow"
    );
    let has_assign = result
        .flows
        .iter()
        .any(|f| f.sink == TaintSink::LocationAssign);
    assert!(has_assign, "should find location.assign sink");
}

#[test]
fn fixture_7_windowname_to_scriptsrc() {
    let result = analyze_js_taint(FIXTURE_WINDOWNAME_SCRIPTSRC);
    assert!(
        result.has_flows(),
        "should detect window.name→script.src flow"
    );
    let flow = &result.flows[0];
    assert_eq!(flow.source, TaintSource::WindowName);
    assert_eq!(flow.sink, TaintSink::ScriptSrc);
}

#[test]
fn fixture_8_href_to_settimeout() {
    let result = analyze_js_taint(FIXTURE_HREF_SETTIMEOUT);
    assert!(
        result.has_flows(),
        "should detect location.href→setTimeout flow"
    );
    let has_timeout = result.flows.iter().any(|f| f.sink == TaintSink::SetTimeout);
    assert!(has_timeout, "should find setTimeout sink");
}

// ─── Source detection tests ──────────────────────────────────────────

#[test]
fn detects_location_hash_source() {
    let js = "var x = location.hash;";
    let result = analyze_js_taint(js);
    assert!(
        result
            .sources_found
            .iter()
            .any(|(s, _)| *s == TaintSource::LocationHash)
    );
}

#[test]
fn detects_location_search_source() {
    let js = "var q = location.search;";
    let result = analyze_js_taint(js);
    assert!(
        result
            .sources_found
            .iter()
            .any(|(s, _)| *s == TaintSource::LocationSearch)
    );
}

#[test]
fn detects_document_referrer_source() {
    let js = "var r = document.referrer;";
    let result = analyze_js_taint(js);
    assert!(
        result
            .sources_found
            .iter()
            .any(|(s, _)| *s == TaintSource::DocumentReferrer)
    );
}

#[test]
fn detects_document_cookie_source() {
    let js = "var c = document.cookie;";
    let result = analyze_js_taint(js);
    assert!(
        result
            .sources_found
            .iter()
            .any(|(s, _)| *s == TaintSource::DocumentCookie)
    );
}

#[test]
fn detects_postmessage_source() {
    let js = r#"window.addEventListener("message", function(e) { var d = event.data; });"#;
    let result = analyze_js_taint(js);
    assert!(
        result
            .sources_found
            .iter()
            .any(|(s, _)| *s == TaintSource::PostMessage)
    );
}

#[test]
fn detects_window_name_source() {
    let js = "var n = window.name;";
    let result = analyze_js_taint(js);
    assert!(
        result
            .sources_found
            .iter()
            .any(|(s, _)| *s == TaintSource::WindowName)
    );
}

#[test]
fn detects_urlsearchparams_source() {
    let js = "var p = new URLSearchParams(window.location.search);";
    let result = analyze_js_taint(js);
    assert!(
        result
            .sources_found
            .iter()
            .any(|(s, _)| *s == TaintSource::UrlSearchParams)
    );
}

// ─── Sink detection tests ────────────────────────────────────────────

#[test]
fn detects_innerhtml_sink() {
    let js = r#"document.getElementById("x").innerHTML = "hi";"#;
    let result = analyze_js_taint(js);
    assert!(
        result
            .sinks_found
            .iter()
            .any(|(s, _)| *s == TaintSink::InnerHtml)
    );
}

#[test]
fn detects_eval_sink() {
    let js = "eval(userInput);";
    let result = analyze_js_taint(js);
    assert!(
        result
            .sinks_found
            .iter()
            .any(|(s, _)| *s == TaintSink::Eval)
    );
}

#[test]
fn detects_document_write_sink() {
    let js = r#"document.write("<p>" + x + "</p>");"#;
    let result = analyze_js_taint(js);
    assert!(
        result
            .sinks_found
            .iter()
            .any(|(s, _)| *s == TaintSink::DocumentWrite)
    );
}

#[test]
fn detects_jquery_html_sink() {
    let js = r##"$("#output").html(content);"##;
    let result = analyze_js_taint(js);
    assert!(
        result
            .sinks_found
            .iter()
            .any(|(s, _)| *s == TaintSink::JQueryHtml)
    );
}

#[test]
fn detects_fetch_sink() {
    let js = "fetch(apiUrl);";
    let result = analyze_js_taint(js);
    assert!(
        result
            .sinks_found
            .iter()
            .any(|(s, _)| *s == TaintSink::FetchUrl)
    );
}

// ─── Propagation and edge-case tests ─────────────────────────────────

#[test]
fn traces_multi_hop_propagation() {
    let js = r#"
var hash = location.hash;
var decoded = decodeURIComponent(hash);
var trimmed = decoded.substring(1);
document.getElementById("x").innerHTML = trimmed;
"#;
    let result = analyze_js_taint(js);
    assert!(result.has_flows());
    let flow = result
        .flows
        .iter()
        .find(|f| f.propagation_chain.len() > 2)
        .expect("should have multi-hop chain");
    assert!(flow.propagation_chain.contains(&"decoded".to_string()));
    assert!(flow.propagation_chain.contains(&"trimmed".to_string()));
}

#[test]
fn no_flows_in_clean_code() {
    let js = r#"
var x = "safe";
document.getElementById("out").innerHTML = x;
"#;
    let result = analyze_js_taint(js);
    assert!(!result.has_flows(), "clean code should have no taint flows");
}

#[test]
fn ignores_commented_sources() {
    let js = r#"
// var x = location.hash;
var y = "safe";
"#;
    let result = analyze_js_taint(js);
    assert!(result.sources_found.is_empty());
}

#[test]
fn direct_source_in_sink() {
    let js = r#"document.write(location.hash);"#;
    let result = analyze_js_taint(js);
    assert!(result.has_flows());
    let flow = &result.flows[0];
    assert_eq!(flow.source, TaintSource::LocationHash);
    assert_eq!(flow.sink, TaintSink::DocumentWrite);
    assert_eq!(flow.propagation_chain, vec!["(direct)".to_string()]);
}

#[test]
fn concat_assignment_propagates_taint() {
    let js = r#"
var hash = location.hash;
var msg = "Hello " + hash;
document.getElementById("x").innerHTML = msg;
"#;
    let result = analyze_js_taint(js);
    assert!(result.has_flows());
}

#[test]
fn flow_display_format() {
    let flow = TaintFlow {
        source: TaintSource::LocationHash,
        sink: TaintSink::InnerHtml,
        propagation_chain: vec!["hash".to_string(), "decoded".to_string()],
        source_line: 1,
        sink_line: 3,
    };
    let display = format!("{flow}");
    assert!(display.contains("location.hash"));
    assert!(display.contains("innerHTML"));
    assert!(display.contains("hash → decoded"));
}

#[test]
fn source_display_names() {
    assert_eq!(format!("{}", TaintSource::LocationHash), "location.hash");
    assert_eq!(
        format!("{}", TaintSource::DocumentReferrer),
        "document.referrer"
    );
    assert_eq!(
        format!("{}", TaintSource::PostMessage),
        "postMessage event.data"
    );
}

#[test]
fn sink_display_names() {
    assert_eq!(format!("{}", TaintSink::InnerHtml), "innerHTML");
    assert_eq!(format!("{}", TaintSink::Eval), "eval()");
    assert_eq!(format!("{}", TaintSink::JQueryHtml), "$.html()");
    assert_eq!(format!("{}", TaintSink::FetchUrl), "fetch() URL");
}

#[test]
fn analysis_result_flow_count() {
    let result = analyze_js_taint(FIXTURE_HASH_INNERHTML);
    assert_eq!(result.flow_count(), result.flows.len());
}

#[test]
fn analysis_result_default_empty() {
    let result = TaintAnalysisResult::default();
    assert!(!result.has_flows());
    assert_eq!(result.flow_count(), 0);
}

// ─── Fixture coverage meta-test ──────────────────────────────────────

#[test]
fn at_least_seven_of_eight_fixtures_detected() {
    let fixtures = [
        FIXTURE_HASH_INNERHTML,
        FIXTURE_REFERRER_DOCWRITE,
        FIXTURE_SEARCH_PARAMS_EVAL,
        FIXTURE_POSTMESSAGE_JQUERY,
        FIXTURE_COOKIE_FETCH,
        FIXTURE_SEARCH_REDIRECT,
        FIXTURE_WINDOWNAME_SCRIPTSRC,
        FIXTURE_HREF_SETTIMEOUT,
    ];
    let detected = fixtures
        .iter()
        .filter(|js| analyze_js_taint(js).has_flows())
        .count();
    assert!(
        detected >= 7,
        "expected ≥7/8 fixtures detected, got {detected}/8"
    );
}

#[test]
fn all_eight_fixtures_detected() {
    let fixtures = [
        FIXTURE_HASH_INNERHTML,
        FIXTURE_REFERRER_DOCWRITE,
        FIXTURE_SEARCH_PARAMS_EVAL,
        FIXTURE_POSTMESSAGE_JQUERY,
        FIXTURE_COOKIE_FETCH,
        FIXTURE_SEARCH_REDIRECT,
        FIXTURE_WINDOWNAME_SCRIPTSRC,
        FIXTURE_HREF_SETTIMEOUT,
    ];
    for (i, js) in fixtures.iter().enumerate() {
        let result = analyze_js_taint(js);
        assert!(
            result.has_flows(),
            "fixture {} should have taint flows: {:?}",
            i + 1,
            result
        );
    }
}

// ─── Additional edge-case tests for robustness ───────────────────────

#[test]
fn outerhtml_sink_detected() {
    let js = r#"
var h = location.hash;
document.getElementById("x").outerHTML = h;
"#;
    let result = analyze_js_taint(js);
    assert!(result.has_flows());
    assert!(result.flows.iter().any(|f| f.sink == TaintSink::OuterHtml));
}

#[test]
fn location_replace_sink_detected() {
    let js = r#"
var dest = location.search;
location.replace(dest);
"#;
    let result = analyze_js_taint(js);
    assert!(result.has_flows());
    assert!(
        result
            .flows
            .iter()
            .any(|f| f.sink == TaintSink::LocationReplace)
    );
}

#[test]
fn window_open_sink_detected() {
    let js = r#"
var target = document.referrer;
window.open(target);
"#;
    let result = analyze_js_taint(js);
    assert!(result.has_flows());
    assert!(result.flows.iter().any(|f| f.sink == TaintSink::WindowOpen));
}

#[test]
fn jquery_append_sink_detected() {
    let js = r#"
var payload = location.hash;
$("body").append(payload);
"#;
    let result = analyze_js_taint(js);
    assert!(result.has_flows());
    assert!(
        result
            .flows
            .iter()
            .any(|f| f.sink == TaintSink::JQueryAppend)
    );
}

#[test]
fn empty_input_produces_no_flows() {
    let result = analyze_js_taint("");
    assert!(!result.has_flows());
    assert!(result.sources_found.is_empty());
    assert!(result.sinks_found.is_empty());
}

#[test]
fn line_numbers_are_correct() {
    let js = "var x = location.hash;\ndocument.getElementById('o').innerHTML = x;";
    let result = analyze_js_taint(js);
    assert!(result.has_flows());
    let flow = &result.flows[0];
    assert_eq!(flow.source_line, 1);
    assert_eq!(flow.sink_line, 2);
}
