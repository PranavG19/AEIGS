use crate::idle_detection_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_idle_detection("");
    assert!(issues.is_empty());
}

#[test]
fn no_idle_api_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_idle_detection(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_idle_detector_usage() {
    let body = "const detector = new IdleDetector();";
    let issues = analyze_idle_detection(body);
    assert!(issues.contains(&IdleDetectionIssue::IdleDetectorUsage));
}

#[test]
fn detects_idle_state_exfiltration() {
    let body = r#"
        const detector = new IdleDetector();
        detector.addEventListener('change', () => {
            fetch('/track?state=' + detector.userState);
        });
    "#;
    let issues = analyze_idle_detection(body);
    assert!(issues.contains(&IdleDetectionIssue::IdleStateExfiltration));
}

#[test]
fn no_exfiltration_without_send() {
    let body = r#"
        const detector = new IdleDetector();
        console.log(detector.userState);
    "#;
    let issues = analyze_idle_detection(body);
    assert!(!issues.contains(&IdleDetectionIssue::IdleStateExfiltration));
}

#[test]
fn detects_idle_change_tracking() {
    let body = r#"
        const detector = new IdleDetector();
        detector.addEventListener('change', handler);
    "#;
    let issues = analyze_idle_detection(body);
    assert!(issues.contains(&IdleDetectionIssue::IdleChangeTracking));
}

#[test]
fn detects_onchange_tracking() {
    let body = r#"
        const detector = new IdleDetector();
        detector.onchange = handler;
    "#;
    let issues = analyze_idle_detection(body);
    assert!(issues.contains(&IdleDetectionIssue::IdleChangeTracking));
}

#[test]
fn detects_screen_state_monitoring() {
    let body = r#"
        const detector = new IdleDetector();
        console.log(detector.screenState);
    "#;
    let issues = analyze_idle_detection(body);
    assert!(issues.contains(&IdleDetectionIssue::ScreenStateMonitoring));
}

#[test]
fn detects_continuous_idle_polling() {
    let body = r#"
        const detector = new IdleDetector();
        setInterval(() => { check(detector); }, 1000);
    "#;
    let issues = analyze_idle_detection(body);
    assert!(issues.contains(&IdleDetectionIssue::ContinuousIdlePolling));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        idle_detection_severity(&IdleDetectionIssue::IdleStateExfiltration),
        7.5
    );
}

#[test]
fn severity_usage_lowest() {
    assert_eq!(
        idle_detection_severity(&IdleDetectionIssue::IdleDetectorUsage),
        5.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        IdleDetectionIssue::IdleDetectorUsage,
        IdleDetectionIssue::ScreenStateMonitoring,
    ];
    let mut seq = 0;
    let ops = idle_detection_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        IdleDetectionIssue::IdleDetectorUsage.to_string(),
        "idle_detector_usage"
    );
    assert_eq!(
        IdleDetectionIssue::IdleStateExfiltration.to_string(),
        "idle_state_exfiltration"
    );
    assert_eq!(
        IdleDetectionIssue::ScreenStateMonitoring.to_string(),
        "screen_state_monitoring"
    );
    assert_eq!(
        IdleDetectionIssue::ContinuousIdlePolling.to_string(),
        "continuous_idle_polling"
    );
}

// ==================== IdleDetectionSecurityIssue Tests ====================

#[test]
fn security_empty_body_no_issues() {
    let issues = analyze_idle_detection_security("");
    assert!(issues.is_empty());
}

#[test]
fn security_no_idle_api_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_idle_detection_security(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_detector_without_permission() {
    let body = r#"
        const detector = new IdleDetector();
        detector.start();
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::DetectorWithoutPermission));
}

#[test]
fn no_detector_without_permission_when_permission_checked() {
    let body = r#"
        const permission = await navigator.permissions.query({ name: 'idle-detection' });
        const detector = new IdleDetector();
        detector.start();
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(!issues.contains(&IdleDetectionSecurityIssue::DetectorWithoutPermission));
}

#[test]
fn detects_idle_state_persistence_localstorage() {
    let body = r#"
        const detector = new IdleDetector();
        detector.addEventListener('change', () => {
            localStorage.setItem('idleState', detector.userState);
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::IdleStatePersistence));
}

#[test]
fn detects_idle_state_persistence_indexeddb() {
    let body = r#"
        const detector = new IdleDetector();
        const request = indexedDB.open('db');
        request.onsuccess = () => {
            store.put({ state: detector.screenState });
        };
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::IdleStatePersistence));
}

#[test]
fn no_idle_state_persistence_without_storage() {
    let body = r#"
        const detector = new IdleDetector();
        console.log(detector.userState);
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(!issues.contains(&IdleDetectionSecurityIssue::IdleStatePersistence));
}

#[test]
fn detects_cross_origin_idle_leak() {
    let body = r#"
        const detector = new IdleDetector();
        detector.addEventListener('change', () => {
            window.parent.postMessage({ idle: detector.userState }, '*');
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::CrossOriginIdleLeak));
}

#[test]
fn no_cross_origin_idle_leak_without_postmessage() {
    let body = r#"
        const detector = new IdleDetector();
        console.log(detector.userState);
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(!issues.contains(&IdleDetectionSecurityIssue::CrossOriginIdleLeak));
}

#[test]
fn detects_worker_based_detection() {
    let body = r#"
        const worker = new Worker('worker.js');
        const detector = new IdleDetector();
        worker.postMessage(detector.userState);
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::WorkerBasedDetection));
}

#[test]
fn detects_service_worker_detection() {
    let body = r#"
        self.addEventListener('message', (event) => {
            const detector = new IdleDetector();
            detector.start();
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::WorkerBasedDetection));
}

#[test]
fn no_worker_detection_without_worker() {
    let body = r#"
        const detector = new IdleDetector();
        detector.start();
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(!issues.contains(&IdleDetectionSecurityIssue::WorkerBasedDetection));
}

#[test]
fn detects_user_presence_fingerprint_useragent() {
    let body = r#"
        const detector = new IdleDetector();
        const fingerprint = {
            idle: detector.userState,
            ua: navigator.userAgent
        };
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::UserPresenceFingerprint));
}

#[test]
fn detects_user_presence_fingerprint_canvas() {
    let body = r#"
        const detector = new IdleDetector();
        const canvas = document.createElement('canvas');
        const data = canvas.toDataURL();
        const profile = { idle: detector.userState, canvas: data };
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::UserPresenceFingerprint));
}

#[test]
fn detects_user_presence_fingerprint_webgl() {
    let body = r#"
        const detector = new IdleDetector();
        const gl = canvas.getContext('webgl');
        const renderer = gl.getParameter(gl.RENDERER);
        const fp = { idle: detector.userState, renderer };
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::UserPresenceFingerprint));
}

#[test]
fn no_fingerprint_without_other_apis() {
    let body = r#"
        const detector = new IdleDetector();
        console.log(detector.userState);
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(!issues.contains(&IdleDetectionSecurityIssue::UserPresenceFingerprint));
}

#[test]
fn detects_unencrypted_idle_data() {
    let body = r#"
        const detector = new IdleDetector();
        detector.addEventListener('change', () => {
            fetch('http://example.com/track', {
                method: 'POST',
                body: JSON.stringify({ state: detector.userState })
            });
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::UnencryptedIdleData));
}

#[test]
fn no_unencrypted_idle_data_with_https() {
    let body = r#"
        const detector = new IdleDetector();
        detector.addEventListener('change', () => {
            fetch('https://example.com/track', {
                method: 'POST',
                body: JSON.stringify({ state: detector.userState })
            });
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(!issues.contains(&IdleDetectionSecurityIssue::UnencryptedIdleData));
}

#[test]
fn detects_absence_timing_attack_date_now() {
    let body = r#"
        const detector = new IdleDetector();
        let lastActive = Date.now();
        detector.addEventListener('change', () => {
            if (detector.userState === 'idle') {
                const duration = Date.now() - lastActive;
            }
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::AbsenceTimingAttack));
}

#[test]
fn detects_absence_timing_attack_performance_now() {
    let body = r#"
        const detector = new IdleDetector();
        let start = performance.now();
        detector.addEventListener('change', () => {
            if (detector.userState === 'idle') {
                const elapsed = performance.now() - start;
            }
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::AbsenceTimingAttack));
}

#[test]
fn no_timing_attack_without_timing_apis() {
    let body = r#"
        const detector = new IdleDetector();
        detector.addEventListener('change', () => {
            console.log(detector.userState);
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(!issues.contains(&IdleDetectionSecurityIssue::AbsenceTimingAttack));
}

#[test]
fn detects_screen_lock_detection() {
    let body = r#"
        const detector = new IdleDetector();
        detector.addEventListener('change', () => {
            if (detector.screenState === 'locked') {
                console.log('Screen locked!');
            }
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::ScreenLockDetection));
}

#[test]
fn detects_screen_unlock_detection() {
    let body = r#"
        const detector = new IdleDetector();
        detector.addEventListener('change', () => {
            if (detector.screenState === 'unlocked') {
                console.log('Screen unlocked!');
            }
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::ScreenLockDetection));
}

#[test]
fn no_screen_lock_detection_without_locked_check() {
    let body = r#"
        const detector = new IdleDetector();
        detector.addEventListener('change', () => {
            console.log(detector.screenState);
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(!issues.contains(&IdleDetectionSecurityIssue::ScreenLockDetection));
}

#[test]
fn detects_third_party_idle_sharing_com() {
    let body = r#"
        const detector = new IdleDetector();
        detector.addEventListener('change', () => {
            fetch('https://analytics.example.com/track', {
                method: 'POST',
                body: JSON.stringify({ state: detector.userState })
            });
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::ThirdPartyIdleSharing));
}

#[test]
fn detects_third_party_idle_sharing_net() {
    let body = r#"
        const detector = new IdleDetector();
        const xhr = new XMLHttpRequest();
        xhr.open('POST', 'https://tracker.net/api');
        xhr.send(JSON.stringify({ screenState: detector.screenState }));
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::ThirdPartyIdleSharing));
}

#[test]
fn no_third_party_sharing_without_external_domain() {
    let body = r#"
        const detector = new IdleDetector();
        detector.addEventListener('change', () => {
            fetch('/api/track', {
                method: 'POST',
                body: JSON.stringify({ state: detector.userState })
            });
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(!issues.contains(&IdleDetectionSecurityIssue::ThirdPartyIdleSharing));
}

#[test]
fn detects_auto_start_detection() {
    let body = r#"
        const detector = new IdleDetector();
        detector.start({ threshold: 60000 });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::AutoStartDetection));
}

#[test]
fn no_auto_start_with_click_listener() {
    let body = r#"
        const detector = new IdleDetector();
        button.addEventListener('click', () => {
            detector.start({ threshold: 60000 });
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(!issues.contains(&IdleDetectionSecurityIssue::AutoStartDetection));
}

#[test]
fn no_auto_start_with_onclick() {
    let body = r#"
        const detector = new IdleDetector();
        element.onclick = () => {
            detector.start({ threshold: 60000 });
        };
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(!issues.contains(&IdleDetectionSecurityIssue::AutoStartDetection));
}

#[test]
fn security_display_detector_without_permission() {
    assert_eq!(
        IdleDetectionSecurityIssue::DetectorWithoutPermission.to_string(),
        "detector_without_permission"
    );
}

#[test]
fn security_display_idle_state_persistence() {
    assert_eq!(
        IdleDetectionSecurityIssue::IdleStatePersistence.to_string(),
        "idle_state_persistence"
    );
}

#[test]
fn security_display_cross_origin_idle_leak() {
    assert_eq!(
        IdleDetectionSecurityIssue::CrossOriginIdleLeak.to_string(),
        "cross_origin_idle_leak"
    );
}

#[test]
fn security_display_worker_based_detection() {
    assert_eq!(
        IdleDetectionSecurityIssue::WorkerBasedDetection.to_string(),
        "worker_based_detection"
    );
}

#[test]
fn security_display_user_presence_fingerprint() {
    assert_eq!(
        IdleDetectionSecurityIssue::UserPresenceFingerprint.to_string(),
        "user_presence_fingerprint"
    );
}

#[test]
fn security_display_unencrypted_idle_data() {
    assert_eq!(
        IdleDetectionSecurityIssue::UnencryptedIdleData.to_string(),
        "unencrypted_idle_data"
    );
}

#[test]
fn security_display_absence_timing_attack() {
    assert_eq!(
        IdleDetectionSecurityIssue::AbsenceTimingAttack.to_string(),
        "absence_timing_attack"
    );
}

#[test]
fn security_display_screen_lock_detection() {
    assert_eq!(
        IdleDetectionSecurityIssue::ScreenLockDetection.to_string(),
        "screen_lock_detection"
    );
}

#[test]
fn security_display_third_party_idle_sharing() {
    assert_eq!(
        IdleDetectionSecurityIssue::ThirdPartyIdleSharing.to_string(),
        "third_party_idle_sharing"
    );
}

#[test]
fn security_display_auto_start_detection() {
    assert_eq!(
        IdleDetectionSecurityIssue::AutoStartDetection.to_string(),
        "auto_start_detection"
    );
}

#[test]
fn security_severity_unencrypted_highest() {
    assert_eq!(
        idle_detection_security_severity(&IdleDetectionSecurityIssue::UnencryptedIdleData),
        8.5
    );
}

#[test]
fn security_severity_third_party_sharing() {
    assert_eq!(
        idle_detection_security_severity(&IdleDetectionSecurityIssue::ThirdPartyIdleSharing),
        8.0
    );
}

#[test]
fn security_severity_cross_origin_leak() {
    assert_eq!(
        idle_detection_security_severity(&IdleDetectionSecurityIssue::CrossOriginIdleLeak),
        7.8
    );
}

#[test]
fn security_severity_absence_timing() {
    assert_eq!(
        idle_detection_security_severity(&IdleDetectionSecurityIssue::AbsenceTimingAttack),
        7.5
    );
}

#[test]
fn security_severity_auto_start_lowest() {
    assert_eq!(
        idle_detection_security_severity(&IdleDetectionSecurityIssue::AutoStartDetection),
        5.0
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        IdleDetectionSecurityIssue::DetectorWithoutPermission,
        IdleDetectionSecurityIssue::UnencryptedIdleData,
    ];
    let mut seq = 0;
    let ops = idle_detection_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty_issues() {
    let issues = vec![];
    let mut seq = 10;
    let ops = idle_detection_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 10);
}

#[test]
fn security_multiple_issues_detected() {
    let body = r#"
        const detector = new IdleDetector();
        detector.start();
        localStorage.setItem('idle', detector.userState);
        window.parent.postMessage({ idle: detector.userState }, '*');
        fetch('http://tracker.com/api', {
            method: 'POST',
            body: JSON.stringify({ state: detector.userState })
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.len() >= 4);
    assert!(issues.contains(&IdleDetectionSecurityIssue::DetectorWithoutPermission));
    assert!(issues.contains(&IdleDetectionSecurityIssue::IdleStatePersistence));
    assert!(issues.contains(&IdleDetectionSecurityIssue::CrossOriginIdleLeak));
    assert!(issues.contains(&IdleDetectionSecurityIssue::UnencryptedIdleData));
}

#[test]
fn security_edge_case_session_storage() {
    let body = r#"
        const detector = new IdleDetector();
        sessionStorage.setItem('state', detector.userState);
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::IdleStatePersistence));
}

#[test]
fn security_edge_case_audio_context_fingerprint() {
    let body = r#"
        const detector = new IdleDetector();
        const audioCtx = new AudioContext();
        const fp = { idle: detector.userState, audio: audioCtx };
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::UserPresenceFingerprint));
}

#[test]
fn security_edge_case_screen_dimensions_fingerprint() {
    let body = r#"
        const detector = new IdleDetector();
        const profile = {
            idle: detector.userState,
            screen: { w: screen.width, h: screen.height }
        };
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::UserPresenceFingerprint));
}

#[test]
fn security_edge_case_touchstart_gesture() {
    let body = r#"
        const detector = new IdleDetector();
        element.addEventListener('touchstart', () => {
            detector.start({ threshold: 60000 });
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(!issues.contains(&IdleDetectionSecurityIssue::AutoStartDetection));
}

#[test]
fn security_edge_case_org_domain() {
    let body = r#"
        const detector = new IdleDetector();
        fetch('https://tracking.org/api', {
            method: 'POST',
            body: JSON.stringify({ state: detector.screenState })
        });
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(issues.contains(&IdleDetectionSecurityIssue::ThirdPartyIdleSharing));
}

#[test]
fn security_no_false_positive_permission_in_variable_name() {
    let body = r#"
        const permissionButton = document.getElementById('btn');
        const detector = new IdleDetector();
        detector.start();
    "#;
    let issues = analyze_idle_detection_security(body);
    assert!(!issues.contains(&IdleDetectionSecurityIssue::DetectorWithoutPermission));
}
