use crate::launch_handler_audit::*;

#[test]
fn no_launch_handler_no_issues() {
    assert!(analyze_launch_handler("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_launch_queue() {
    let body = r#"<script>window.launchQueue.setConsumer(params => {});</script>"#;
    let issues = analyze_launch_handler(body);
    assert!(issues.contains(&LaunchHandlerIssue::ApiDetected));
}

#[test]
fn detects_api_launch_params() {
    let body = r#"<script>if (window.LaunchParams) {}</script>"#;
    let issues = analyze_launch_handler(body);
    assert!(issues.contains(&LaunchHandlerIssue::ApiDetected));
}

#[test]
fn detects_url_injection() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            window.location = params.targetURL;
        });
    </script>"#;
    let issues = analyze_launch_handler(body);
    assert!(issues.contains(&LaunchHandlerIssue::UrlInjection));
}

#[test]
fn no_injection_with_validation() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            const url = new URL(params.targetURL);
            window.location = url.href;
        });
    </script>"#;
    let issues = analyze_launch_handler(body);
    assert!(!issues.contains(&LaunchHandlerIssue::UrlInjection));
}

#[test]
fn detects_file_handling() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            for (const f of params.files) { readFile(f); }
        });
    </script>"#;
    let issues = analyze_launch_handler(body);
    assert!(issues.contains(&LaunchHandlerIssue::FileHandling));
}

#[test]
fn no_files_without_keyword() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            navigate(params.targetURL);
        });
    </script>"#;
    let issues = analyze_launch_handler(body);
    assert!(!issues.contains(&LaunchHandlerIssue::FileHandling));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            fetch("/log", {body: JSON.stringify(params)});
        });
    </script>"#;
    let issues = analyze_launch_handler(body);
    assert!(issues.contains(&LaunchHandlerIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            console.log(params);
        });
    </script>"#;
    let issues = analyze_launch_handler(body);
    assert!(!issues.contains(&LaunchHandlerIssue::DataExfiltration));
}

#[test]
fn detects_no_input_validation() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            processData(params);
        });
    </script>"#;
    let issues = analyze_launch_handler(body);
    assert!(issues.contains(&LaunchHandlerIssue::NoInputValidation));
}

#[test]
fn no_validation_issue_with_sanitize() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            const safe = sanitize(params);
            processData(safe);
        });
    </script>"#;
    let issues = analyze_launch_handler(body);
    assert!(!issues.contains(&LaunchHandlerIssue::NoInputValidation));
}

#[test]
fn severity_injection_highest() {
    assert_eq!(
        launch_handler_severity(&LaunchHandlerIssue::UrlInjection),
        7.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        launch_handler_severity(&LaunchHandlerIssue::ApiDetected),
        2.5
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        LaunchHandlerIssue::ApiDetected,
        LaunchHandlerIssue::FileHandling,
    ];
    let mut seq = 0;
    let ops = launch_handler_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(LaunchHandlerIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        LaunchHandlerIssue::UrlInjection.to_string(),
        "url_injection"
    );
    assert_eq!(
        LaunchHandlerIssue::FileHandling.to_string(),
        "file_handling"
    );
    assert_eq!(
        LaunchHandlerIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        LaunchHandlerIssue::NoInputValidation.to_string(),
        "no_input_validation"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_launch_handler("").is_empty());
}

// LaunchHandlerSecurityIssue Tests

#[test]
pub fn security_empty_body_no_issues() {
    assert!(analyze_launch_handler_security("").is_empty());
}

#[test]
pub fn security_no_launch_handler_no_issues() {
    assert!(analyze_launch_handler_security("<html><body>hello</body></html>").is_empty());
}

#[test]
pub fn security_no_keywords_no_issues() {
    let body = r#"<script>window.addEventListener('load', () => {});</script>"#;
    assert!(analyze_launch_handler_security(body).is_empty());
}

// LaunchUrlExfiltration tests

#[test]
pub fn detects_launch_url_exfiltration_fetch() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            fetch('https://analytics.example.com', {
                method: 'POST',
                body: JSON.stringify({url: params.targetURL})
            });
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchUrlExfiltration));
}

#[test]
pub fn detects_launch_url_exfiltration_xhr() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', 'https://external.com/track');
            xhr.send(params.targetURL);
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchUrlExfiltration));
}

#[test]
pub fn detects_launch_url_exfiltration_beacon() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            navigator.sendBeacon('/analytics', params.targetURL);
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchUrlExfiltration));
}

#[test]
pub fn no_exfiltration_without_external_keywords() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            fetch('/api/local', {body: params.targetURL});
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(!issues.contains(&LaunchHandlerSecurityIssue::LaunchUrlExfiltration));
}

// LaunchWithoutValidation tests

#[test]
pub fn detects_launch_without_validation() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            processData(params.targetURL);
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchWithoutValidation));
}

#[test]
pub fn no_validation_issue_with_url_constructor() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            const url = new URL(params.targetURL);
            processData(url);
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(!issues.contains(&LaunchHandlerSecurityIssue::LaunchWithoutValidation));
}

#[test]
pub fn security_no_validation_issue_with_sanitize() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            const safe = sanitize(params.targetURL);
            processData(safe);
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(!issues.contains(&LaunchHandlerSecurityIssue::LaunchWithoutValidation));
}

#[test]
pub fn security_no_validation_issue_with_allowlist() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            if (allowlist.includes(params.targetURL)) {
                processData(params.targetURL);
            }
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(!issues.contains(&LaunchHandlerSecurityIssue::LaunchWithoutValidation));
}

// LaunchRedirectAbuse tests

#[test]
pub fn detects_launch_redirect_abuse_location() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            window.location = params.targetURL;
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchRedirectAbuse));
}

#[test]
pub fn detects_launch_redirect_abuse_href() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            location.href = params.targetURL;
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchRedirectAbuse));
}

#[test]
pub fn no_redirect_abuse_with_origin_check() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            if (new URL(params.targetURL).origin === window.origin) {
                window.location = params.targetURL;
            }
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(!issues.contains(&LaunchHandlerSecurityIssue::LaunchRedirectAbuse));
}

#[test]
pub fn no_redirect_abuse_with_allowlist() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            if (allowlist.test(params.targetURL)) {
                window.location = params.targetURL;
            }
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(!issues.contains(&LaunchHandlerSecurityIssue::LaunchRedirectAbuse));
}

// LaunchCrossOrigin tests

#[test]
pub fn detects_launch_cross_origin_postmessage() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            window.postMessage({url: params.targetURL}, '*');
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchCrossOrigin));
}

#[test]
pub fn detects_launch_cross_origin_parent() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            parent.postMessage(params.targetURL, '*');
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchCrossOrigin));
}

#[test]
pub fn no_cross_origin_without_postmessage() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            console.log(params.targetURL);
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(!issues.contains(&LaunchHandlerSecurityIssue::LaunchCrossOrigin));
}

// LaunchParamInjection tests

#[test]
pub fn detects_launch_param_injection_innerhtml() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            document.getElementById('target').innerHTML = params.targetURL;
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchParamInjection));
}

#[test]
pub fn detects_launch_param_injection_document_write() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            document.write(params.targetURL);
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchParamInjection));
}

#[test]
pub fn detects_launch_param_injection_outerhtml() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            element.outerHTML = params.targetURL;
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchParamInjection));
}

#[test]
pub fn no_param_injection_without_dom_methods() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            element.textContent = params.targetURL;
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(!issues.contains(&LaunchHandlerSecurityIssue::LaunchParamInjection));
}

// LaunchPersistence tests

#[test]
pub fn detects_launch_persistence_localstorage() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            localStorage.setItem('lastLaunch', params.targetURL);
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchPersistence));
}

#[test]
pub fn detects_launch_persistence_sessionstorage() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            sessionStorage.setItem('launch', params.targetURL);
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchPersistence));
}

#[test]
pub fn detects_launch_persistence_indexeddb() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            const request = indexedDB.open('launches');
            request.onsuccess = () => {
                db.put({url: params.targetURL});
            };
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchPersistence));
}

#[test]
pub fn no_persistence_without_storage() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            processData(params.targetURL);
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(!issues.contains(&LaunchHandlerSecurityIssue::LaunchPersistence));
}

// LaunchInBackground tests

#[test]
pub fn detects_launch_in_background_visibility() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            if (document.visibilityState === 'hidden') {
                processLaunch(params);
            }
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchInBackground));
}

#[test]
pub fn detects_launch_in_background_hidden() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            if (document.hidden === 'hidden') {
                processLaunch(params);
            }
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchInBackground));
}

#[test]
pub fn no_background_without_hidden_check() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            if (document.visibilityState === 'visible') {
                processLaunch(params);
            }
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(!issues.contains(&LaunchHandlerSecurityIssue::LaunchInBackground));
}

// LaunchFileAccess tests

#[test]
pub fn detects_launch_file_access_filereader() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            for (const file of params.files) {
                const reader = new FileReader();
                reader.readAsText(file);
            }
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchFileAccess));
}

#[test]
pub fn detects_launch_file_access_readastext() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            params.files[0].readAsText().then(text => console.log(text));
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchFileAccess));
}

#[test]
pub fn detects_launch_file_access_readasdataurl() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            for (const f of params.files) {
                reader.readAsDataURL(f);
            }
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchFileAccess));
}

#[test]
pub fn no_file_access_without_reader() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            console.log(params.files.length);
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(!issues.contains(&LaunchHandlerSecurityIssue::LaunchFileAccess));
}

// LaunchProtocolAbuse tests

#[test]
pub fn detects_launch_protocol_abuse_webplus() {
    let body = r#"<script>
        navigator.registerProtocolHandler('web+myapp', '/handle?url=%s');
        window.launchQueue.setConsumer(params => {
            handleProtocol(params);
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchProtocolAbuse));
}

#[test]
pub fn detects_launch_protocol_abuse_mailto() {
    let body = r#"<script>
        navigator.registerProtocolHandler('mailto', '/compose?to=%s');
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchProtocolAbuse));
}

#[test]
pub fn detects_launch_protocol_abuse_tel() {
    let body = r#"<script>
        navigator.registerProtocolHandler('tel', '/call?number=%s');
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchProtocolAbuse));
}

#[test]
pub fn no_protocol_abuse_without_register() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            handleProtocol(params);
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(!issues.contains(&LaunchHandlerSecurityIssue::LaunchProtocolAbuse));
}

// LaunchChaining tests

#[test]
pub fn detects_launch_chaining_window_open() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            const url = new URL(params.targetURL);
            window.open(url.href, '_blank', 'noopener');
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchChaining));
}

#[test]
pub fn detects_launch_chaining_iframe() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            const iframe = document.createElement('iframe');
            iframe.src = params.targetURL;
            if (iframe.origin === window.origin) {
                document.body.appendChild(iframe);
            }
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchChaining));
}

#[test]
pub fn no_chaining_without_window_open_or_iframe() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            const url = new URL(params.targetURL);
            if (url.origin === window.origin) {
                processUrl(url);
            }
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(!issues.contains(&LaunchHandlerSecurityIssue::LaunchChaining));
}

// Display tests

#[test]
pub fn display_all_security_variants() {
    assert_eq!(
        LaunchHandlerSecurityIssue::LaunchUrlExfiltration.to_string(),
        "launch_url_exfiltration"
    );
    assert_eq!(
        LaunchHandlerSecurityIssue::LaunchWithoutValidation.to_string(),
        "launch_without_validation"
    );
    assert_eq!(
        LaunchHandlerSecurityIssue::LaunchRedirectAbuse.to_string(),
        "launch_redirect_abuse"
    );
    assert_eq!(
        LaunchHandlerSecurityIssue::LaunchCrossOrigin.to_string(),
        "launch_cross_origin"
    );
    assert_eq!(
        LaunchHandlerSecurityIssue::LaunchParamInjection.to_string(),
        "launch_param_injection"
    );
    assert_eq!(
        LaunchHandlerSecurityIssue::LaunchPersistence.to_string(),
        "launch_persistence"
    );
    assert_eq!(
        LaunchHandlerSecurityIssue::LaunchInBackground.to_string(),
        "launch_in_background"
    );
    assert_eq!(
        LaunchHandlerSecurityIssue::LaunchFileAccess.to_string(),
        "launch_file_access"
    );
    assert_eq!(
        LaunchHandlerSecurityIssue::LaunchProtocolAbuse.to_string(),
        "launch_protocol_abuse"
    );
    assert_eq!(
        LaunchHandlerSecurityIssue::LaunchChaining.to_string(),
        "launch_chaining"
    );
}

// Severity tests

#[test]
pub fn severity_param_injection_highest() {
    assert_eq!(
        launch_handler_security_severity(&LaunchHandlerSecurityIssue::LaunchParamInjection),
        9.0
    );
}

#[test]
pub fn severity_url_exfiltration_high() {
    assert_eq!(
        launch_handler_security_severity(&LaunchHandlerSecurityIssue::LaunchUrlExfiltration),
        8.5
    );
}

#[test]
pub fn severity_redirect_abuse_high() {
    assert_eq!(
        launch_handler_security_severity(&LaunchHandlerSecurityIssue::LaunchRedirectAbuse),
        8.0
    );
}

#[test]
pub fn severity_protocol_abuse_medium_high() {
    assert_eq!(
        launch_handler_security_severity(&LaunchHandlerSecurityIssue::LaunchProtocolAbuse),
        7.5
    );
}

#[test]
pub fn severity_cross_origin_medium_high() {
    assert_eq!(
        launch_handler_security_severity(&LaunchHandlerSecurityIssue::LaunchCrossOrigin),
        7.0
    );
}

#[test]
pub fn severity_file_access_medium() {
    assert_eq!(
        launch_handler_security_severity(&LaunchHandlerSecurityIssue::LaunchFileAccess),
        6.5
    );
}

#[test]
pub fn severity_chaining_medium() {
    assert_eq!(
        launch_handler_security_severity(&LaunchHandlerSecurityIssue::LaunchChaining),
        6.0
    );
}

#[test]
pub fn severity_persistence_medium_low() {
    assert_eq!(
        launch_handler_security_severity(&LaunchHandlerSecurityIssue::LaunchPersistence),
        5.5
    );
}

#[test]
pub fn severity_background_low() {
    assert_eq!(
        launch_handler_security_severity(&LaunchHandlerSecurityIssue::LaunchInBackground),
        4.5
    );
}

#[test]
pub fn severity_without_validation_lowest() {
    assert_eq!(
        launch_handler_security_severity(&LaunchHandlerSecurityIssue::LaunchWithoutValidation),
        3.0
    );
}

// Operations tests

#[test]
pub fn security_to_operations_creates_entries() {
    let issues = vec![
        LaunchHandlerSecurityIssue::LaunchParamInjection,
        LaunchHandlerSecurityIssue::LaunchUrlExfiltration,
        LaunchHandlerSecurityIssue::LaunchRedirectAbuse,
    ];
    let mut seq = 0;
    let ops = launch_handler_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
pub fn security_to_operations_empty_list() {
    let issues = vec![];
    let mut seq = 0;
    let ops = launch_handler_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}

#[test]
pub fn security_to_operations_single_issue() {
    let issues = vec![LaunchHandlerSecurityIssue::LaunchFileAccess];
    let mut seq = 10;
    let ops = launch_handler_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 11);
}

// Multiple issues tests

#[test]
pub fn detects_multiple_security_issues() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            document.getElementById('target').innerHTML = params.targetURL;
            localStorage.setItem('launch', params.targetURL);
            fetch('https://analytics.com/track', {body: params.targetURL});
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchParamInjection));
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchPersistence));
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchUrlExfiltration));
    assert!(issues.len() >= 3);
}

#[test]
pub fn detects_validation_and_redirect_issues() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            window.location = params.targetURL;
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchWithoutValidation));
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchRedirectAbuse));
}

#[test]
pub fn detects_cross_origin_and_chaining() {
    let body = r#"<script>
        window.launchQueue.setConsumer(params => {
            window.postMessage(params.targetURL, '*');
            window.open(params.targetURL, '_blank');
            const url = new URL(params.targetURL);
            if (url.origin) {
                console.log('chained');
            }
        });
    </script>"#;
    let issues = analyze_launch_handler_security(body);
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchCrossOrigin));
    assert!(issues.contains(&LaunchHandlerSecurityIssue::LaunchChaining));
}
