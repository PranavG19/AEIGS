use crate::abort_controller_audit::*;

#[test]
fn test_api_detected_abort_controller() {
    let body = "<script>const controller = new AbortController();</script>";
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::ApiDetected));
}

#[test]
fn test_api_detected_abort_signal() {
    let body = "<script>function check(signal: AbortSignal) {}</script>";
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::ApiDetected));
}

#[test]
fn test_api_detected_signal_aborted() {
    let body = "<script>if (signal.aborted) return;</script>";
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::ApiDetected));
}

#[test]
fn test_denial_of_service_no_cleanup() {
    let body = r#"
        <script>
        const c = new AbortController();
        setInterval(() => {}, 100);
        c.abort();
        </script>
    "#;
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::DenialOfService));
}

#[test]
fn test_denial_of_service_with_cleanup() {
    let body = r#"
        <script>
        const c = new AbortController();
        const id = setInterval(() => {}, 100);
        clearInterval(id);
        c.abort();
        </script>
    "#;
    let issues = analyze_abort_controller(body);
    assert!(!issues.contains(&AbortControllerIssue::DenialOfService));
}

#[test]
fn test_security_bypass_csrf() {
    let body = r#"
        <script>
        const c = new AbortController();
        c.abort();
        const csrf = getToken();
        </script>
    "#;
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::SecurityBypass));
}

#[test]
fn test_security_bypass_auth() {
    let body = r#"
        <script>
        const signal = new AbortController().signal;
        signal.abort();
        const auth = verify();
        </script>
    "#;
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::SecurityBypass));
}

#[test]
fn test_race_condition_promise_race() {
    let body = r#"
        <script>
        const c = new AbortController();
        Promise.race([fetch('/api')]);
        c.abort();
        </script>
    "#;
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::RaceCondition));
}

#[test]
fn test_race_condition_xhr() {
    let body = r#"
        <script>
        const c = new AbortController();
        setTimeout(() => c.abort(), 100);
        const xhr = new XMLHttpRequest();
        </script>
    "#;
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::RaceCondition));
}

#[test]
fn test_resource_leak_no_cleanup() {
    let body = "<script>const c = new AbortController();</script>";
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::ResourceLeak));
}

#[test]
fn test_resource_leak_with_abort() {
    let body = r#"
        <script>
        const c = new AbortController();
        c.abort();
        </script>
    "#;
    let issues = analyze_abort_controller(body);
    assert!(!issues.contains(&AbortControllerIssue::ResourceLeak));
}

#[test]
fn test_resource_leak_with_finally() {
    let body = r#"
        <script>
        const c = new AbortController();
        fetch('/api').finally(() => {});
        </script>
    "#;
    let issues = analyze_abort_controller(body);
    assert!(!issues.contains(&AbortControllerIssue::ResourceLeak));
}

#[test]
fn test_no_issues_without_api() {
    let body = "<html><body>Hello World</body></html>";
    let issues = analyze_abort_controller(body);
    assert!(issues.is_empty());
}

#[test]
fn test_severity_mapping() {
    assert_eq!(
        abort_controller_severity(&AbortControllerIssue::ApiDetected),
        2.0
    );
    assert_eq!(
        abort_controller_severity(&AbortControllerIssue::DenialOfService),
        7.0
    );
    assert_eq!(
        abort_controller_severity(&AbortControllerIssue::SecurityBypass),
        7.5
    );
    assert_eq!(
        abort_controller_severity(&AbortControllerIssue::RaceCondition),
        6.5
    );
    assert_eq!(
        abort_controller_severity(&AbortControllerIssue::ResourceLeak),
        5.5
    );
}

#[test]
fn test_to_operations() {
    let issues = vec![
        AbortControllerIssue::ApiDetected,
        AbortControllerIssue::SecurityBypass,
    ];
    let mut seq = 1;
    let ops = abort_controller_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 3);
}

#[test]
fn test_display_trait() {
    assert_eq!(
        AbortControllerIssue::ApiDetected.to_string(),
        "api_detected"
    );
    assert_eq!(
        AbortControllerIssue::DenialOfService.to_string(),
        "denial_of_service"
    );
    assert_eq!(
        AbortControllerIssue::SecurityBypass.to_string(),
        "security_bypass"
    );
    assert_eq!(
        AbortControllerIssue::RaceCondition.to_string(),
        "race_condition"
    );
    assert_eq!(
        AbortControllerIssue::ResourceLeak.to_string(),
        "resource_leak"
    );
}

#[test]
fn test_missing_abort_controller_with_fetch() {
    let body = r#"
        <script>
        fetch('/api/data').then(r => r.json());
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::MissingAbortController));
}

#[test]
fn test_missing_abort_controller_with_xhr() {
    let body = r#"
        <script>
        const xhr = new XMLHttpRequest();
        xhr.open('GET', '/api/data');
        xhr.send();
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::MissingAbortController));
}

#[test]
fn test_no_missing_abort_controller_when_present() {
    let body = r#"
        <script>
        const controller = new AbortController();
        fetch('/api/data', { signal: controller.signal });
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(!issues.contains(&AbortControllerSecurityIssue::MissingAbortController));
}

#[test]
fn test_abort_signal_leak_window() {
    let body = r#"
        <script>
        const controller = new AbortController();
        window.signal = controller.signal;
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::AbortSignalLeak));
}

#[test]
fn test_abort_signal_leak_globalthis() {
    let body = r#"
        <script>
        const controller = new AbortController();
        globalThis.signal = controller.signal;
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::AbortSignalLeak));
}

#[test]
fn test_abort_signal_leak_export() {
    let body = r#"
        <script>
        const controller = new AbortController();
        export const signal = controller.signal;
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::AbortSignalLeak));
}

#[test]
fn test_abort_signal_leak_module_exports() {
    let body = r#"
        <script>
        const controller = new AbortController();
        module.exports.signal = controller.signal;
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::AbortSignalLeak));
}

#[test]
fn test_no_abort_signal_leak_local() {
    let body = r#"
        <script>
        const controller = new AbortController();
        const signal = controller.signal;
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(!issues.contains(&AbortControllerSecurityIssue::AbortSignalLeak));
}

#[test]
fn test_race_condition_on_abort_promise_race() {
    let body = r#"
        <script>
        const controller = new AbortController();
        Promise.race([fetch('/api')]);
        controller.abort();
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::RaceConditionOnAbort));
}

#[test]
fn test_race_condition_on_abort_promise_any() {
    let body = r#"
        <script>
        const controller = new AbortController();
        Promise.any([fetch('/api')]);
        controller.abort();
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::RaceConditionOnAbort));
}

#[test]
fn test_no_race_condition_with_event_listener() {
    let body = r#"
        <script>
        const controller = new AbortController();
        controller.signal.addEventListener('abort', () => {});
        Promise.race([fetch('/api')]);
        controller.abort();
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(!issues.contains(&AbortControllerSecurityIssue::RaceConditionOnAbort));
}

#[test]
fn test_unhandled_abort_error_no_try_catch() {
    let body = r#"
        <script>
        const controller = new AbortController();
        controller.abort();
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::UnhandledAbortError));
}

#[test]
fn test_handled_abort_error_with_try_catch() {
    let body = r#"
        <script>
        const controller = new AbortController();
        try {
            controller.abort();
        } catch (e) {
            console.error(e);
        }
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(!issues.contains(&AbortControllerSecurityIssue::UnhandledAbortError));
}

#[test]
fn test_handled_abort_error_with_abort_error_check() {
    let body = r#"
        <script>
        const controller = new AbortController();
        controller.abort();
        if (error.name === 'AbortError') return;
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(!issues.contains(&AbortControllerSecurityIssue::UnhandledAbortError));
}

#[test]
fn test_abort_controller_reuse() {
    let body = r#"
        <script>
        const controller = new AbortController();
        controller.abort();
        controller.abort();
        controller.abort();
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::AbortControllerReuse));
}

#[test]
fn test_no_abort_controller_reuse_multiple_controllers() {
    let body = r#"
        <script>
        const c1 = new AbortController();
        const c2 = new AbortController();
        c1.abort();
        c2.abort();
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(!issues.contains(&AbortControllerSecurityIssue::AbortControllerReuse));
}

#[test]
fn test_abort_timeout_missing_settimeout() {
    let body = r#"
        <script>
        const controller = new AbortController();
        fetch('/api', { signal: controller.signal });
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::AbortTimeoutMissing));
}

#[test]
fn test_no_abort_timeout_missing_with_settimeout() {
    let body = r#"
        <script>
        const controller = new AbortController();
        setTimeout(() => controller.abort(), 5000);
        fetch('/api', { signal: controller.signal });
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(!issues.contains(&AbortControllerSecurityIssue::AbortTimeoutMissing));
}

#[test]
fn test_no_abort_timeout_missing_with_abort_signal_timeout() {
    let body = r#"
        <script>
        const signal = AbortSignal.timeout(5000);
        fetch('/api', { signal });
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(!issues.contains(&AbortControllerSecurityIssue::AbortTimeoutMissing));
}

#[test]
fn test_cascading_abort_failure_multiple_signals() {
    let body = r#"
        <script>
        const c1 = new AbortController();
        const c2 = new AbortController();
        fetch('/api1', { signal: c1.signal });
        fetch('/api2', { signal: c2.signal });
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::CascadingAbortFailure));
}

#[test]
fn test_no_cascading_abort_failure_with_abort_all() {
    let body = r#"
        <script>
        const controllers = [new AbortController(), new AbortController()];
        fetch('/api1', { signal: controllers[0].signal });
        fetch('/api2', { signal: controllers[1].signal });
        function abortAll() {
            controllers.forEach(c => c.abort());
        }
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(!issues.contains(&AbortControllerSecurityIssue::CascadingAbortFailure));
}

#[test]
fn test_abort_without_cleanup() {
    let body = r#"
        <script>
        const controller = new AbortController();
        controller.abort();
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::AbortWithoutCleanup));
}

#[test]
fn test_no_abort_without_cleanup_with_remove_listener() {
    let body = r#"
        <script>
        const controller = new AbortController();
        controller.abort();
        element.removeEventListener('click', handler);
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(!issues.contains(&AbortControllerSecurityIssue::AbortWithoutCleanup));
}

#[test]
fn test_no_abort_without_cleanup_with_finally() {
    let body = r#"
        <script>
        const controller = new AbortController();
        fetch('/api').finally(() => controller.abort());
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(!issues.contains(&AbortControllerSecurityIssue::AbortWithoutCleanup));
}

#[test]
fn test_abort_signal_cross_origin() {
    let body = r#"
        <script>
        const controller = new AbortController();
        window.postMessage({ signal: controller.signal }, '*');
        fetch('/api', { mode: 'cors' });
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::AbortSignalCrossOrigin));
}

#[test]
fn test_no_abort_signal_cross_origin_without_postmessage() {
    let body = r#"
        <script>
        const controller = new AbortController();
        fetch('/api', { mode: 'cors' });
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(!issues.contains(&AbortControllerSecurityIssue::AbortSignalCrossOrigin));
}

#[test]
fn test_global_abort_controller_window() {
    let body = r#"
        <script>
        window.controller = new AbortController();
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::GlobalAbortController));
}

#[test]
fn test_global_abort_controller_globalthis() {
    let body = r#"
        <script>
        globalThis.controller = new AbortController();
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::GlobalAbortController));
}

#[test]
fn test_global_abort_controller_var() {
    let body = r#"
        <script>
        var controller = new AbortController();
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.contains(&AbortControllerSecurityIssue::GlobalAbortController));
}

#[test]
fn test_no_global_abort_controller_const() {
    let body = r#"
        <script>
        const controller = new AbortController();
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(!issues.contains(&AbortControllerSecurityIssue::GlobalAbortController));
}

#[test]
fn test_security_severity_mapping() {
    assert_eq!(
        abort_controller_security_severity(&AbortControllerSecurityIssue::MissingAbortController),
        4.5
    );
    assert_eq!(
        abort_controller_security_severity(&AbortControllerSecurityIssue::AbortSignalLeak),
        7.0
    );
    assert_eq!(
        abort_controller_security_severity(&AbortControllerSecurityIssue::RaceConditionOnAbort),
        6.5
    );
    assert_eq!(
        abort_controller_security_severity(&AbortControllerSecurityIssue::UnhandledAbortError),
        5.0
    );
    assert_eq!(
        abort_controller_security_severity(&AbortControllerSecurityIssue::AbortControllerReuse),
        6.0
    );
    assert_eq!(
        abort_controller_security_severity(&AbortControllerSecurityIssue::AbortTimeoutMissing),
        5.5
    );
    assert_eq!(
        abort_controller_security_severity(&AbortControllerSecurityIssue::CascadingAbortFailure),
        6.5
    );
    assert_eq!(
        abort_controller_security_severity(&AbortControllerSecurityIssue::AbortWithoutCleanup),
        5.5
    );
    assert_eq!(
        abort_controller_security_severity(&AbortControllerSecurityIssue::AbortSignalCrossOrigin),
        8.0
    );
    assert_eq!(
        abort_controller_security_severity(&AbortControllerSecurityIssue::GlobalAbortController),
        6.0
    );
}

#[test]
fn test_security_to_operations() {
    let issues = vec![
        AbortControllerSecurityIssue::AbortSignalLeak,
        AbortControllerSecurityIssue::GlobalAbortController,
    ];
    let mut seq = 10;
    let ops = abort_controller_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 12);
}

#[test]
fn test_security_display_trait() {
    assert_eq!(
        AbortControllerSecurityIssue::MissingAbortController.to_string(),
        "missing_abort_controller"
    );
    assert_eq!(
        AbortControllerSecurityIssue::AbortSignalLeak.to_string(),
        "abort_signal_leak"
    );
    assert_eq!(
        AbortControllerSecurityIssue::RaceConditionOnAbort.to_string(),
        "race_condition_on_abort"
    );
    assert_eq!(
        AbortControllerSecurityIssue::UnhandledAbortError.to_string(),
        "unhandled_abort_error"
    );
    assert_eq!(
        AbortControllerSecurityIssue::AbortControllerReuse.to_string(),
        "abort_controller_reuse"
    );
    assert_eq!(
        AbortControllerSecurityIssue::AbortTimeoutMissing.to_string(),
        "abort_timeout_missing"
    );
    assert_eq!(
        AbortControllerSecurityIssue::CascadingAbortFailure.to_string(),
        "cascading_abort_failure"
    );
    assert_eq!(
        AbortControllerSecurityIssue::AbortWithoutCleanup.to_string(),
        "abort_without_cleanup"
    );
    assert_eq!(
        AbortControllerSecurityIssue::AbortSignalCrossOrigin.to_string(),
        "abort_signal_cross_origin"
    );
    assert_eq!(
        AbortControllerSecurityIssue::GlobalAbortController.to_string(),
        "global_abort_controller"
    );
}

#[test]
fn test_empty_body_no_security_issues() {
    let body = "";
    let issues = analyze_abort_controller_security(body);
    assert!(issues.is_empty());
}

#[test]
fn test_multiple_security_issues_detected() {
    let body = r#"
        <script>
        fetch('/api/data');
        window.controller = new AbortController();
        globalThis.signal = controller.signal;
        controller.abort();
        </script>
    "#;
    let issues = analyze_abort_controller_security(body);
    assert!(issues.len() >= 3);
    assert!(issues.contains(&AbortControllerSecurityIssue::GlobalAbortController));
    assert!(issues.contains(&AbortControllerSecurityIssue::AbortSignalLeak));
    assert!(issues.contains(&AbortControllerSecurityIssue::UnhandledAbortError));
}
