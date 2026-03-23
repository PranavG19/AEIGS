use crate::resize_observer_audit::*;

#[test]
fn no_observer_no_issues() {
    assert!(analyze_resize_observer("<html></html>").is_empty());
}

#[test]
fn detects_observer() {
    let body = r#"<script>new ResizeObserver(cb).observe(el)</script>"#;
    let issues = analyze_resize_observer(body);
    assert!(issues.contains(&ResizeObserverIssue::ObserverDetected));
}

#[test]
fn detects_content_rect() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            const rect = entries[0].contentRect;
            console.log(rect.width, rect.height);
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer(body);
    assert!(issues.contains(&ResizeObserverIssue::ContentRectAccess));
}

#[test]
fn detects_border_box_size() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            const size = entries[0].borderBoxSize[0];
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer(body);
    assert!(issues.contains(&ResizeObserverIssue::BorderBoxSize));
}

#[test]
fn detects_device_pixel_content_box() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            const s = entries[0].devicePixelContentBoxSize;
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer(body);
    assert!(issues.contains(&ResizeObserverIssue::BorderBoxSize));
}

#[test]
fn detects_multiple_targets() {
    let body = r#"<script>
        const ro = new ResizeObserver(cb);
        ro.observe(el1);
        ro.observe(el2);
        ro.observe(el3);
        ro.observe(el4);
    </script>"#;
    let issues = analyze_resize_observer(body);
    assert!(issues.contains(&ResizeObserverIssue::MultipleTargets));
}

#[test]
fn no_multiple_with_few_targets() {
    let body = r#"<script>
        const ro = new ResizeObserver(cb);
        ro.observe(el1);
        ro.observe(el2);
    </script>"#;
    let issues = analyze_resize_observer(body);
    assert!(!issues.contains(&ResizeObserverIssue::MultipleTargets));
}

#[test]
fn detects_data_exfiltration_fetch() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            fetch("/track", {body: JSON.stringify(entries[0].contentRect)});
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer(body);
    assert!(issues.contains(&ResizeObserverIssue::DataExfiltration));
}

#[test]
fn detects_continuous_tracking() {
    let body = r#"<script>
        new ResizeObserver(cb).observe(el);
        requestAnimationFrame(loop);
    </script>"#;
    let issues = analyze_resize_observer(body);
    assert!(issues.contains(&ResizeObserverIssue::ContinuousTracking));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        resize_observer_severity(&ResizeObserverIssue::DataExfiltration),
        5.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        resize_observer_severity(&ResizeObserverIssue::ObserverDetected),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        ResizeObserverIssue::ObserverDetected,
        ResizeObserverIssue::DataExfiltration,
    ];
    let mut seq = 0;
    let ops = resize_observer_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        ResizeObserverIssue::ObserverDetected.to_string(),
        "observer_detected"
    );
    assert_eq!(
        ResizeObserverIssue::ContentRectAccess.to_string(),
        "content_rect_access"
    );
    assert_eq!(
        ResizeObserverIssue::BorderBoxSize.to_string(),
        "border_box_size"
    );
    assert_eq!(
        ResizeObserverIssue::MultipleTargets.to_string(),
        "multiple_targets"
    );
    assert_eq!(
        ResizeObserverIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        ResizeObserverIssue::ContinuousTracking.to_string(),
        "continuous_tracking"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_resize_observer("").is_empty());
}

#[test]
fn security_no_observer_no_issues() {
    assert!(analyze_resize_observer_security("<html></html>").is_empty());
}

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_resize_observer_security("").is_empty());
}

#[test]
fn security_detects_cross_origin_iframe() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            const iframe = document.querySelector('iframe');
            iframe.contentWindow.postMessage(entries[0].contentRect, '*');
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::CrossOriginResizeTracking));
}

#[test]
fn security_detects_cross_origin_postmessage() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            window.postMessage({type: 'resize', data: entries}, 'https://evil.com');
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::CrossOriginResizeTracking));
}

#[test]
fn security_detects_cross_origin_flag() {
    let body = r#"<script>
        const iframe = document.createElement('iframe');
        iframe.crossOrigin = 'anonymous';
        new ResizeObserver(cb).observe(iframe);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::CrossOriginResizeTracking));
}

#[test]
fn security_detects_fingerprinting_canvas() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            const fingerprint = canvas.toDataURL();
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeFingerprinting));
}

#[test]
fn security_detects_fingerprinting_screen_dimensions() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            const fp = screen.width + 'x' + screen.height;
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeFingerprinting));
}

#[test]
fn security_detects_fingerprinting_explicit() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            collectfingerprint(entries[0]);
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeFingerprinting));
}

#[test]
fn security_detects_layout_detection_inner_width() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            if (window.innerWidth < 768) {
                applyMobileLayout();
            }
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeBasedLayoutDetection));
}

#[test]
fn security_detects_layout_detection_match_media() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            const mq = window.matchMedia('(max-width: 600px)');
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeBasedLayoutDetection));
}

#[test]
fn security_detects_layout_detection_breakpoint() {
    let body = r#"<script>
        const breakpoint = 1024;
        new ResizeObserver((entries) => {
            checkBreakpoint(entries);
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeBasedLayoutDetection));
}

#[test]
fn security_detects_resize_in_worker() {
    let body = r#"<script>
        const worker = new Worker('resize-worker.js');
        new ResizeObserver((entries) => {
            worker.postMessage(entries);
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeInWorker));
}

#[test]
fn security_detects_resize_in_shared_worker() {
    let body = r#"<script>
        const sw = new SharedWorker('shared.js');
        new ResizeObserver((entries) => {
            sw.port.postMessage(entries);
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeInWorker));
}

#[test]
fn security_detects_intersection_observer_combo() {
    let body = r#"<script>
        const ro = new ResizeObserver(cb1);
        const io = new IntersectionObserver(cb2);
        ro.observe(el1);
        io.observe(el2);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeWithIntersectionObserver));
}

#[test]
fn security_detects_local_storage() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            localStorage.setItem('resize', JSON.stringify(entries));
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeToLocalStorage));
}

#[test]
fn security_detects_session_storage() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            sessionStorage.setItem('resize', JSON.stringify(entries));
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeToLocalStorage));
}

#[test]
fn security_detects_indexed_db() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            const req = indexedDB.open('myDB');
            req.onsuccess = () => { saveResize(entries); };
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeToLocalStorage));
}

#[test]
fn security_detects_timing_attack_performance_now() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            const start = performance.now();
            processResize(entries);
            const elapsed = performance.now() - start;
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeTimingAttack));
}

#[test]
fn security_detects_timing_attack_date_now() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            const ts = Date.now();
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeTimingAttack));
}

#[test]
fn security_detects_timing_attack_performance_mark() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            performance.mark('resize-start');
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeTimingAttack));
}

#[test]
fn security_detects_cross_tab_broadcast_channel() {
    let body = r#"<script>
        const bc = new BroadcastChannel('resize-channel');
        new ResizeObserver((entries) => {
            bc.postMessage(entries);
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeCrossTabCommunication));
}

#[test]
fn security_detects_cross_tab_local_storage() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            localStorage.setItem('shared-resize', JSON.stringify(entries));
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeCrossTabCommunication));
}

#[test]
fn security_detects_keylogging_keydown() {
    let body = r#"<script>
        document.addEventListener('keydown', (e) => {
            new ResizeObserver(cb).observe(e.target);
        });
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeBasedKeylogging));
}

#[test]
fn security_detects_keylogging_keypress() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            document.addEventListener('keypress', track);
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeBasedKeylogging));
}

#[test]
fn security_detects_keylogging_input() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            const input = entries[0].target;
            input.addEventListener('input', logValue);
        }).observe(document.querySelector('input'));
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeBasedKeylogging));
}

#[test]
fn security_detects_without_throttling() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            processEveryResize(entries);
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeWithoutThrottling));
}

#[test]
fn security_no_throttling_with_debounce() {
    let body = r#"<script>
        const debouncedResize = debounce(() => {}, 100);
        new ResizeObserver(debouncedResize).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(!issues.contains(&ResizeObserverIssue::ResizeWithoutThrottling));
}

#[test]
fn security_no_throttling_with_throttle() {
    let body = r#"<script>
        const throttledResize = throttle(() => {}, 100);
        new ResizeObserver(throttledResize).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(!issues.contains(&ResizeObserverIssue::ResizeWithoutThrottling));
}

#[test]
fn security_no_throttling_with_raf() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            requestAnimationFrame(() => process(entries));
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(!issues.contains(&ResizeObserverIssue::ResizeWithoutThrottling));
}

#[test]
fn security_no_throttling_with_settimeout() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            setTimeout(() => process(entries), 100);
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(!issues.contains(&ResizeObserverIssue::ResizeWithoutThrottling));
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        ResizeObserverIssue::CrossOriginResizeTracking,
        ResizeObserverIssue::ResizeFingerprinting,
    ];
    let mut seq = 0;
    let ops = resize_observer_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_new_variants() {
    assert_eq!(
        ResizeObserverIssue::CrossOriginResizeTracking.to_string(),
        "cross_origin_resize_tracking"
    );
    assert_eq!(
        ResizeObserverIssue::ResizeFingerprinting.to_string(),
        "resize_fingerprinting"
    );
    assert_eq!(
        ResizeObserverIssue::ResizeBasedLayoutDetection.to_string(),
        "resize_based_layout_detection"
    );
    assert_eq!(
        ResizeObserverIssue::ResizeInWorker.to_string(),
        "resize_in_worker"
    );
    assert_eq!(
        ResizeObserverIssue::ResizeWithIntersectionObserver.to_string(),
        "resize_with_intersection_observer"
    );
    assert_eq!(
        ResizeObserverIssue::ResizeToLocalStorage.to_string(),
        "resize_to_local_storage"
    );
    assert_eq!(
        ResizeObserverIssue::ResizeTimingAttack.to_string(),
        "resize_timing_attack"
    );
    assert_eq!(
        ResizeObserverIssue::ResizeCrossTabCommunication.to_string(),
        "resize_cross_tab_communication"
    );
    assert_eq!(
        ResizeObserverIssue::ResizeBasedKeylogging.to_string(),
        "resize_based_keylogging"
    );
    assert_eq!(
        ResizeObserverIssue::ResizeWithoutThrottling.to_string(),
        "resize_without_throttling"
    );
}

#[test]
fn severity_keylogging_highest() {
    assert_eq!(
        resize_observer_severity(&ResizeObserverIssue::ResizeBasedKeylogging),
        8.0
    );
}

#[test]
fn severity_cross_origin() {
    assert_eq!(
        resize_observer_severity(&ResizeObserverIssue::CrossOriginResizeTracking),
        7.5
    );
}

#[test]
fn severity_fingerprinting() {
    assert_eq!(
        resize_observer_severity(&ResizeObserverIssue::ResizeFingerprinting),
        7.0
    );
}

#[test]
fn severity_timing_attack() {
    assert_eq!(
        resize_observer_severity(&ResizeObserverIssue::ResizeTimingAttack),
        7.0
    );
}

#[test]
fn severity_local_storage() {
    assert_eq!(
        resize_observer_severity(&ResizeObserverIssue::ResizeToLocalStorage),
        6.5
    );
}

#[test]
fn severity_cross_tab() {
    assert_eq!(
        resize_observer_severity(&ResizeObserverIssue::ResizeCrossTabCommunication),
        6.5
    );
}

#[test]
fn severity_in_worker() {
    assert_eq!(
        resize_observer_severity(&ResizeObserverIssue::ResizeInWorker),
        6.0
    );
}

#[test]
fn severity_intersection_observer() {
    assert_eq!(
        resize_observer_severity(&ResizeObserverIssue::ResizeWithIntersectionObserver),
        5.0
    );
}

#[test]
fn severity_layout_detection() {
    assert_eq!(
        resize_observer_severity(&ResizeObserverIssue::ResizeBasedLayoutDetection),
        4.0
    );
}

#[test]
fn severity_without_throttling() {
    assert_eq!(
        resize_observer_severity(&ResizeObserverIssue::ResizeWithoutThrottling),
        3.5
    );
}

#[test]
fn security_multiple_issues_detected() {
    let body = r#"<script>
        const worker = new Worker('w.js');
        new ResizeObserver((entries) => {
            const ts = performance.now();
            localStorage.setItem('data', JSON.stringify(entries));
            worker.postMessage(entries);
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::ResizeInWorker));
    assert!(issues.contains(&ResizeObserverIssue::ResizeToLocalStorage));
    assert!(issues.contains(&ResizeObserverIssue::ResizeTimingAttack));
    assert!(issues.contains(&ResizeObserverIssue::ResizeWithoutThrottling));
}

#[test]
fn security_combined_tracking_scenario() {
    let body = r#"<script>
        const bc = new BroadcastChannel('tracking');
        new ResizeObserver((entries) => {
            const iframe = document.querySelector('iframe');
            const fp = screen.width + 'x' + screen.height;
            bc.postMessage({resize: entries, fingerprint: fp});
            iframe.contentWindow.postMessage(entries, '*');
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer_security(body);
    assert!(issues.contains(&ResizeObserverIssue::CrossOriginResizeTracking));
    assert!(issues.contains(&ResizeObserverIssue::ResizeFingerprinting));
    assert!(issues.contains(&ResizeObserverIssue::ResizeCrossTabCommunication));
}
