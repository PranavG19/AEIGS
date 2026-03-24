use super::*;

// ── Fixture manifest JSON ──

const MANIFEST_V2_DANGEROUS: &str = r#"{
    "manifest_version": 2,
    "name": "Shady Extension",
    "version": "1.0.0",
    "permissions": [
        "<all_urls>",
        "tabs",
        "cookies",
        "webRequest",
        "webRequestBlocking",
        "storage"
    ],
    "content_scripts": [
        {
            "matches": ["<all_urls>"],
            "js": ["content.js"],
            "run_at": "document_start",
            "all_frames": true
        }
    ],
    "background": {
        "scripts": ["background.js"],
        "persistent": true
    },
    "web_accessible_resources": ["inject.html", "payload.js", "style.css"],
    "externally_connectable": {
        "matches": ["*://*/*"],
        "ids": ["*"]
    }
}"#;

const MANIFEST_V3_SAFE: &str = r#"{
    "manifest_version": 3,
    "name": "Safe Extension",
    "version": "2.0.0",
    "permissions": ["activeTab", "storage"],
    "host_permissions": [],
    "content_scripts": [
        {
            "matches": ["https://specific-site.com/*"],
            "js": ["content.js"],
            "run_at": "document_idle"
        }
    ],
    "background": {
        "service_worker": "sw.js"
    }
}"#;

const MANIFEST_V3_WILDCARD_WAR: &str = r#"{
    "manifest_version": 3,
    "name": "Exposed Extension",
    "version": "1.0.0",
    "permissions": ["storage"],
    "web_accessible_resources": [
        {
            "resources": ["*"],
            "matches": ["<all_urls>"]
        }
    ]
}"#;

const MANIFEST_V2_MINIMAL: &str = r#"{
    "manifest_version": 2,
    "name": "Minimal",
    "version": "0.1"
}"#;

const MANIFEST_V3_EXTERNAL_WILDCARD_DOMAIN: &str = r#"{
    "manifest_version": 3,
    "name": "External Ext",
    "version": "1.0.0",
    "permissions": ["storage"],
    "externally_connectable": {
        "matches": ["*://*.example.com/*"]
    }
}"#;

const MANIFEST_V2_CSP_STRING: &str = r#"{
    "manifest_version": 2,
    "name": "CSP Extension",
    "version": "1.0.0",
    "permissions": ["tabs"],
    "content_security_policy": "script-src 'self' 'unsafe-eval'; object-src 'self'"
}"#;

const MANIFEST_V3_CSP_OBJECT: &str = r#"{
    "manifest_version": 3,
    "name": "CSP Extension v3",
    "version": "1.0.0",
    "permissions": ["storage"],
    "content_security_policy": {
        "extension": "script-src 'self'; object-src 'none'"
    }
}"#;

// ── Fixture JS sources ──

const JS_DANGEROUS_BACKGROUND: &str = r#"
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === 'getCookies') {
        chrome.cookies.getAll({domain: request.domain}, function(cookies) {
            sendResponse({cookies: cookies});
        });
    }
    if (request.action === 'execute') {
        chrome.tabs.executeScript(sender.tab.id, {code: request.code});
    }
    if (request.action === 'debug') {
        chrome.debugger.attach({tabId: sender.tab.id}, "1.3");
    }
});
chrome.webRequest.onBeforeRequest.addListener(
    function(details) { return {cancel: false}; },
    {urls: ["<all_urls>"]},
    ["blocking"]
);
"#;

const JS_CONTENT_SCRIPT_XSS: &str = r#"
chrome.runtime.onMessage.addListener(function(msg) {
    document.getElementById('output').innerHTML = msg.data;
    eval(msg.code);
});
document.write('<div>' + response + '</div>');
"#;

const JS_MESSAGE_PASSING_EXTERNAL: &str = r#"
chrome.runtime.onMessageExternal.addListener(function(request, sender, sendResponse) {
    if (request.type === 'getData') {
        sendResponse({token: localStorage.getItem('auth_token')});
    }
});
chrome.runtime.onConnectExternal.addListener(function(port) {
    port.onMessage.addListener(function(msg) {
        port.postMessage({status: 'ok'});
    });
});
"#;

const JS_DATA_LEAKAGE: &str = r#"
chrome.storage.local.get('credentials', function(data) {
    window.postMessage({type: 'creds', data: chrome.storage.local}, '*');
    document.dispatchEvent(new CustomEvent('ext-data', {detail: data}));
    window.__extensionConfig = chrome.runtime.getManifest();
});
"#;

const JS_CROSS_EXTENSION_STORAGE: &str = r#"
chrome.storage.sync.get(null, function(items) {
    console.log('All synced data:', items);
});
chrome.storage.onChanged.addListener(function(changes, area) {
    for (let key in changes) {
        console.log('Changed:', key, changes[key]);
    }
});
chrome.storage.sync.set({shared_key: 'value'});
"#;

const JS_WAR_GETURL: &str = r#"
var frame = document.createElement('iframe');
frame.src = chrome.runtime.getURL('popup.html');
document.body.appendChild(frame);
"#;

const JS_CLEAN: &str = r#"
console.log('Hello from extension');
var x = 42;
document.getElementById('status').textContent = 'loaded';
"#;

const PAGE_WITH_EXTENSION_URLS: &str = r#"
<html>
<head>
    <link rel="stylesheet" href="chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/style.css">
    <script src="chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/inject.js"></script>
    <script src="chrome-extension://fedcbazyxwvutsrqponmlkjihgfedcba/tracker.js"></script>
</head>
</html>
"#;

const PAGE_NO_EXTENSIONS: &str = r#"
<html><head><title>Normal Page</title></head><body>Hello</body></html>
"#;

// ── Extension ID extraction tests ──

#[test]
fn extract_extension_ids_finds_two_unique_ids() {
    let ids = extract_extension_ids(PAGE_WITH_EXTENSION_URLS);
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&"abcdefghijklmnopqrstuvwxyzabcdef".to_string()));
    assert!(ids.contains(&"fedcbazyxwvutsrqponmlkjihgfedcba".to_string()));
}

#[test]
fn extract_extension_ids_deduplicates() {
    let source = r#"
        <script src="chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/a.js"></script>
        <script src="chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/b.js"></script>
    "#;
    let ids = extract_extension_ids(source);
    assert_eq!(ids.len(), 1);
}

#[test]
fn extract_extension_ids_returns_empty_for_no_extensions() {
    let ids = extract_extension_ids(PAGE_NO_EXTENSIONS);
    assert!(ids.is_empty());
}

// ── Manifest parsing tests ──

#[test]
fn parse_manifest_v2_dangerous() {
    let m = parse_manifest(MANIFEST_V2_DANGEROUS).unwrap();
    assert_eq!(m.manifest_version, 2);
    assert_eq!(m.name, "Shady Extension");
    assert!(m.permissions.contains(&"<all_urls>".to_string()));
    assert!(m.permissions.contains(&"cookies".to_string()));
    assert_eq!(m.content_scripts.len(), 1);
    assert!(m.content_scripts[0].all_frames);
    assert_eq!(m.content_scripts[0].run_at, "document_start");
    assert!(m.background.is_some());
    assert!(m.background.as_ref().unwrap().persistent);
    assert_eq!(m.web_accessible_resources.len(), 3);
    assert!(m.externally_connectable.is_some());
}

#[test]
fn parse_manifest_v3_safe() {
    let m = parse_manifest(MANIFEST_V3_SAFE).unwrap();
    assert_eq!(m.manifest_version, 3);
    assert_eq!(m.name, "Safe Extension");
    assert!(m.permissions.contains(&"activeTab".to_string()));
    assert!(m.host_permissions.is_empty());
    assert!(m.background.as_ref().unwrap().service_worker.is_some());
    assert!(!m.background.as_ref().unwrap().persistent);
}

#[test]
fn parse_manifest_v3_wildcard_war() {
    let m = parse_manifest(MANIFEST_V3_WILDCARD_WAR).unwrap();
    assert!(m.web_accessible_resources.contains(&"*".to_string()));
}

#[test]
fn parse_manifest_minimal_defaults() {
    let m = parse_manifest(MANIFEST_V2_MINIMAL).unwrap();
    assert_eq!(m.manifest_version, 2);
    assert!(m.permissions.is_empty());
    assert!(m.content_scripts.is_empty());
    assert!(m.background.is_none());
    assert!(m.web_accessible_resources.is_empty());
    assert!(m.externally_connectable.is_none());
}

#[test]
fn parse_manifest_invalid_json_returns_error() {
    let result = parse_manifest("not json at all {{{");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("invalid JSON"));
}

#[test]
fn parse_manifest_csp_string_v2() {
    let m = parse_manifest(MANIFEST_V2_CSP_STRING).unwrap();
    assert!(m.content_security_policy.is_some());
    assert!(m.content_security_policy.unwrap().contains("unsafe-eval"));
}

#[test]
fn parse_manifest_csp_object_v3() {
    let m = parse_manifest(MANIFEST_V3_CSP_OBJECT).unwrap();
    assert!(m.content_security_policy.is_some());
    assert!(m.content_security_policy.unwrap().contains("object-src"));
}

// ── Dangerous API detection tests ──

#[test]
fn detect_dangerous_apis_in_background_script() {
    let apis = detect_dangerous_apis(JS_DANGEROUS_BACKGROUND);
    assert!(apis.contains(&DangerousApi::CookiesGetAll));
    assert!(apis.contains(&DangerousApi::TabsExecuteScript));
    assert!(apis.contains(&DangerousApi::DebuggerAttach));
    assert!(apis.contains(&DangerousApi::WebRequestOnBeforeRequest));
}

#[test]
fn detect_dangerous_apis_returns_empty_for_clean_js() {
    let apis = detect_dangerous_apis(JS_CLEAN);
    assert!(apis.is_empty());
}

// ── Content script injection tests ──

#[test]
fn detect_content_script_injection_innerhtml_and_eval() {
    let issues = detect_content_script_injection(JS_CONTENT_SCRIPT_XSS);
    assert!(issues.len() >= 2);
    let has_innerhtml = issues.iter().any(|i| i.contains("innerHTML"));
    let has_eval = issues.iter().any(|i| i.contains("eval"));
    assert!(has_innerhtml, "should detect innerHTML from extension data");
    assert!(has_eval, "should detect eval on message data");
}

#[test]
fn detect_content_script_injection_clean_returns_empty() {
    let issues = detect_content_script_injection(JS_CLEAN);
    assert!(issues.is_empty());
}

// ── Message passing exposure tests ──

#[test]
fn detect_message_passing_external_listeners() {
    let issues = detect_message_passing_exposure(JS_MESSAGE_PASSING_EXTERNAL);
    assert!(issues.len() >= 2);
    let has_external = issues.iter().any(|i| i.contains("onMessageExternal"));
    let has_connect = issues.iter().any(|i| i.contains("onConnectExternal"));
    assert!(has_external);
    assert!(has_connect);
}

#[test]
fn detect_message_passing_no_sender_check() {
    let issues = detect_message_passing_exposure(JS_MESSAGE_PASSING_EXTERNAL);
    let has_no_sender = issues.iter().any(|i| i.contains("sender.id"));
    assert!(has_no_sender, "should flag missing sender.id validation");
}

#[test]
fn detect_message_passing_clean_returns_empty() {
    let issues = detect_message_passing_exposure(JS_CLEAN);
    assert!(issues.is_empty());
}

// ── Data leakage detection tests ──

#[test]
fn detect_data_leakage_postmessage_and_customevent() {
    let issues = detect_data_leakage(JS_DATA_LEAKAGE);
    assert!(issues.len() >= 2);
    let has_postmessage = issues.iter().any(|i| i.contains("postMessage"));
    let has_customevent = issues.iter().any(|i| i.contains("CustomEvent"));
    assert!(has_postmessage);
    assert!(has_customevent);
}

#[test]
fn detect_data_leakage_global_assignment() {
    let issues = detect_data_leakage(JS_DATA_LEAKAGE);
    let has_global = issues.iter().any(|i| i.contains("DOM global"));
    assert!(
        has_global,
        "should detect global assignment of extension data"
    );
}

#[test]
fn detect_data_leakage_clean_returns_empty() {
    let issues = detect_data_leakage(JS_CLEAN);
    assert!(issues.is_empty());
}

// ── Cross-extension storage tests ──

#[test]
fn detect_cross_extension_storage_sync_get_all() {
    let issues = detect_cross_extension_storage(JS_CROSS_EXTENSION_STORAGE);
    let has_get_null = issues.iter().any(|i| i.contains("all sync storage"));
    assert!(has_get_null);
}

#[test]
fn detect_cross_extension_storage_onchanged() {
    let issues = detect_cross_extension_storage(JS_CROSS_EXTENSION_STORAGE);
    let has_onchanged = issues.iter().any(|i| i.contains("storage changes"));
    assert!(has_onchanged);
}

#[test]
fn detect_cross_extension_storage_clean_returns_empty() {
    let issues = detect_cross_extension_storage(JS_CLEAN);
    assert!(issues.is_empty());
}

// ── Web accessible resource XSS detection ──

#[test]
fn detect_war_xss_html_file() {
    let wars = vec!["popup.html".to_string(), "style.css".to_string()];
    let issues = detect_war_xss_vectors(&wars, "");
    let has_html = issues.iter().any(|i| i.contains("popup.html"));
    assert!(has_html);
}

#[test]
fn detect_war_xss_js_file() {
    let wars = vec!["inject.js".to_string()];
    let issues = detect_war_xss_vectors(&wars, "");
    let has_js = issues.iter().any(|i| i.contains("inject.js"));
    assert!(has_js);
}

#[test]
fn detect_war_xss_wildcard() {
    let wars = vec!["*".to_string()];
    let issues = detect_war_xss_vectors(&wars, "");
    let has_wildcard = issues.iter().any(|i| i.contains("wildcard"));
    assert!(has_wildcard);
}

#[test]
fn detect_war_xss_geturl_in_js() {
    let wars: Vec<String> = Vec::new();
    let issues = detect_war_xss_vectors(&wars, JS_WAR_GETURL);
    let has_geturl = issues.iter().any(|i| i.contains("popup.html"));
    assert!(has_geturl, "should detect getURL loading HTML file");
}

// ── Full analysis pipeline tests ──

#[test]
fn full_analysis_dangerous_manifest_many_findings() {
    let config = ExtensionAnalysisConfig::default();
    let result = analyze_extension(
        Some(MANIFEST_V2_DANGEROUS),
        JS_DANGEROUS_BACKGROUND,
        Some(PAGE_WITH_EXTENSION_URLS),
        &config,
    );

    assert!(result.summary.total_findings >= 5);
    assert!(result.summary.critical_count >= 1);
    assert!(result.summary.high_count >= 1);
    assert!(result.extension_id.is_some());
    assert!(result.manifest.is_some());
}

#[test]
fn full_analysis_safe_manifest_minimal_findings() {
    let config = ExtensionAnalysisConfig::default();
    let result = analyze_extension(
        Some(MANIFEST_V3_SAFE),
        JS_CLEAN,
        Some(PAGE_NO_EXTENSIONS),
        &config,
    );

    assert_eq!(result.summary.critical_count, 0);
    assert!(result.extension_id.is_none());
}

#[test]
fn full_analysis_no_manifest_still_checks_js() {
    let config = ExtensionAnalysisConfig::default();
    let result = analyze_extension(None, JS_MESSAGE_PASSING_EXTERNAL, None, &config);

    assert!(result.manifest.is_none());
    let has_message = result
        .findings
        .iter()
        .any(|f| f.vuln_type == ExtensionVulnType::MessagePassingExposure);
    assert!(has_message, "should still detect message passing in JS");
}

#[test]
fn full_analysis_findings_sorted_by_severity() {
    let config = ExtensionAnalysisConfig::default();
    let result = analyze_extension(
        Some(MANIFEST_V2_DANGEROUS),
        JS_DANGEROUS_BACKGROUND,
        Some(PAGE_WITH_EXTENSION_URLS),
        &config,
    );

    for window in result.findings.windows(2) {
        assert!(window[0].severity >= window[1].severity);
    }
}

#[test]
fn full_analysis_externally_connectable_wildcard_flagged() {
    let config = ExtensionAnalysisConfig::default();
    let result = analyze_extension(Some(MANIFEST_V2_DANGEROUS), JS_CLEAN, None, &config);

    let has_ec = result
        .findings
        .iter()
        .any(|f| f.vuln_type == ExtensionVulnType::ExternallyConnectable);
    assert!(has_ec, "should flag wildcard externally_connectable");
}

#[test]
fn full_analysis_externally_connectable_wildcard_domain() {
    let config = ExtensionAnalysisConfig::default();
    let result = analyze_extension(
        Some(MANIFEST_V3_EXTERNAL_WILDCARD_DOMAIN),
        JS_CLEAN,
        None,
        &config,
    );

    let has_ec = result.findings.iter().any(|f| {
        f.vuln_type == ExtensionVulnType::ExternallyConnectable
            && f.description.contains("wildcard")
    });
    assert!(
        has_ec,
        "should flag wildcard domain in externally_connectable"
    );
}

#[test]
fn full_analysis_data_leakage_detected() {
    let config = ExtensionAnalysisConfig::default();
    let result = analyze_extension(Some(MANIFEST_V2_MINIMAL), JS_DATA_LEAKAGE, None, &config);

    let has_leak = result
        .findings
        .iter()
        .any(|f| f.vuln_type == ExtensionVulnType::ExtensionDataLeakage);
    assert!(has_leak, "should detect data leakage patterns");
}

#[test]
fn full_analysis_cross_extension_storage_detected() {
    let config = ExtensionAnalysisConfig::default();
    let result = analyze_extension(
        Some(MANIFEST_V2_MINIMAL),
        JS_CROSS_EXTENSION_STORAGE,
        None,
        &config,
    );

    let has_storage = result
        .findings
        .iter()
        .any(|f| f.vuln_type == ExtensionVulnType::CrossExtensionStorageAttack);
    assert!(
        has_storage,
        "should detect cross-extension storage patterns"
    );
}

#[test]
fn full_analysis_war_wildcard_flagged() {
    let config = ExtensionAnalysisConfig::default();
    let result = analyze_extension(Some(MANIFEST_V3_WILDCARD_WAR), JS_CLEAN, None, &config);

    let has_war = result
        .findings
        .iter()
        .any(|f| f.vuln_type == ExtensionVulnType::WebAccessibleResourceXss);
    assert!(has_war, "should flag wildcard web_accessible_resources");
}

#[test]
fn full_analysis_config_disables_checks() {
    let config = ExtensionAnalysisConfig::default()
        .with_permissions(false)
        .with_content_scripts(false)
        .with_message_passing(false)
        .with_web_accessible_resources(false)
        .with_background_apis(false)
        .with_data_leakage(false)
        .with_cross_extension(false)
        .with_externally_connectable(false);

    let result = analyze_extension(
        Some(MANIFEST_V2_DANGEROUS),
        JS_DANGEROUS_BACKGROUND,
        Some(PAGE_WITH_EXTENSION_URLS),
        &config,
    );

    let only_exposure = result
        .findings
        .iter()
        .all(|f| f.vuln_type == ExtensionVulnType::ExtensionIdExposure);
    assert!(
        only_exposure || result.findings.is_empty(),
        "with all checks disabled, only extension ID exposure (from page source) should remain"
    );
}

// ── Display implementation tests ──

#[test]
fn severity_display_labels() {
    assert_eq!(format!("{}", ExtensionSeverity::Info), "info");
    assert_eq!(format!("{}", ExtensionSeverity::Critical), "critical");
    assert_eq!(format!("{}", ExtensionSeverity::High), "high");
    assert_eq!(format!("{}", ExtensionSeverity::Medium), "medium");
    assert_eq!(format!("{}", ExtensionSeverity::Low), "low");
}

#[test]
fn severity_ordering() {
    assert!(ExtensionSeverity::Info < ExtensionSeverity::Low);
    assert!(ExtensionSeverity::Low < ExtensionSeverity::Medium);
    assert!(ExtensionSeverity::Medium < ExtensionSeverity::High);
    assert!(ExtensionSeverity::High < ExtensionSeverity::Critical);
}

#[test]
fn vuln_type_display_non_empty() {
    assert!(!format!("{}", ExtensionVulnType::ExtensionIdExposure).is_empty());
    assert!(!format!("{}", ExtensionVulnType::ContentScriptInjection).is_empty());
    assert!(!format!("{}", ExtensionVulnType::BackgroundApiAccess).is_empty());
    assert!(!format!("{}", ExtensionVulnType::MessagePassingExposure).is_empty());
    assert!(!format!("{}", ExtensionVulnType::DangerousPermission).is_empty());
    assert!(!format!("{}", ExtensionVulnType::WebAccessibleResourceXss).is_empty());
    assert!(!format!("{}", ExtensionVulnType::ExtensionDataLeakage).is_empty());
    assert!(!format!("{}", ExtensionVulnType::CrossExtensionStorageAttack).is_empty());
    assert!(!format!("{}", ExtensionVulnType::ExternallyConnectable).is_empty());
}

#[test]
fn dangerous_api_display_non_empty() {
    assert!(!format!("{}", DangerousApi::TabsExecuteScript).is_empty());
    assert!(!format!("{}", DangerousApi::CookiesGetAll).is_empty());
    assert!(!format!("{}", DangerousApi::DebuggerAttach).is_empty());
    assert!(!format!("{}", DangerousApi::WebRequestOnBeforeRequest).is_empty());
}

// ── Config builder tests ──

#[test]
fn config_default_all_enabled() {
    let c = ExtensionAnalysisConfig::default();
    assert!(c.check_permissions);
    assert!(c.check_content_scripts);
    assert!(c.check_message_passing);
    assert!(c.check_web_accessible_resources);
    assert!(c.check_background_apis);
    assert!(c.check_data_leakage);
    assert!(c.check_cross_extension);
    assert!(c.check_externally_connectable);
}

#[test]
fn config_builder_chain() {
    let c = ExtensionAnalysisConfig::default()
        .with_permissions(false)
        .with_content_scripts(false)
        .with_message_passing(false);
    assert!(!c.check_permissions);
    assert!(!c.check_content_scripts);
    assert!(!c.check_message_passing);
    assert!(c.check_background_apis);
}

// ── Permission analysis tests ──

#[test]
fn dangerous_permissions_flagged() {
    let m = parse_manifest(MANIFEST_V2_DANGEROUS).unwrap();
    let findings = analyze_permissions(&m);
    let has_all_urls = findings
        .iter()
        .any(|f| f.description.contains("<all_urls>"));
    let has_cookies = findings.iter().any(|f| f.description.contains("cookies"));
    let has_webrequest = findings
        .iter()
        .any(|f| f.description.contains("webRequest"));
    assert!(has_all_urls, "should flag <all_urls>");
    assert!(has_cookies, "should flag cookies permission");
    assert!(has_webrequest, "should flag webRequest permission");
}

#[test]
fn safe_permissions_no_critical() {
    let m = parse_manifest(MANIFEST_V3_SAFE).unwrap();
    let findings = analyze_permissions(&m);
    let critical = findings
        .iter()
        .filter(|f| f.severity == ExtensionSeverity::Critical)
        .count();
    assert_eq!(critical, 0);
}

// ── Summary correctness ──

#[test]
fn summary_counts_match_findings() {
    let config = ExtensionAnalysisConfig::default();
    let result = analyze_extension(
        Some(MANIFEST_V2_DANGEROUS),
        JS_DANGEROUS_BACKGROUND,
        Some(PAGE_WITH_EXTENSION_URLS),
        &config,
    );

    let actual_critical = result
        .findings
        .iter()
        .filter(|f| f.severity == ExtensionSeverity::Critical)
        .count();
    let actual_high = result
        .findings
        .iter()
        .filter(|f| f.severity == ExtensionSeverity::High)
        .count();
    let actual_medium = result
        .findings
        .iter()
        .filter(|f| f.severity == ExtensionSeverity::Medium)
        .count();

    assert_eq!(result.summary.total_findings, result.findings.len());
    assert_eq!(result.summary.critical_count, actual_critical);
    assert_eq!(result.summary.high_count, actual_high);
    assert_eq!(result.summary.medium_count, actual_medium);
}

#[test]
fn patterns_checked_count_nonzero() {
    let config = ExtensionAnalysisConfig::default();
    let result = analyze_extension(
        Some(MANIFEST_V2_DANGEROUS),
        JS_DANGEROUS_BACKGROUND,
        Some(PAGE_WITH_EXTENSION_URLS),
        &config,
    );

    assert!(
        result.summary.patterns_checked >= 8,
        "should check at least 8 patterns"
    );
}
