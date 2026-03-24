use crate::viewport_audit::*;

#[test]
fn empty_body_viewport_missing() {
    let issues = analyze_viewport("");
    assert!(issues.contains(&ViewportIssue::ViewportMissing));
}

#[test]
fn no_viewport_meta_reports_missing() {
    let body = "<html><head><meta charset='utf-8'></head></html>";
    let issues = analyze_viewport(body);
    assert!(issues.contains(&ViewportIssue::ViewportMissing));
}

#[test]
fn proper_viewport_no_issues() {
    let body = r#"<meta name="viewport" content="width=device-width, initial-scale=1.0">"#;
    let issues = analyze_viewport(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_zoom_disabled() {
    let body = r#"<meta name="viewport" content="width=device-width, user-scalable=no">"#;
    let issues = analyze_viewport(body);
    assert!(issues.contains(&ViewportIssue::ZoomDisabled));
}

#[test]
fn detects_zoom_disabled_zero() {
    let body = r#"<meta name="viewport" content="width=device-width, user-scalable=0">"#;
    let issues = analyze_viewport(body);
    assert!(issues.contains(&ViewportIssue::ZoomDisabled));
}

#[test]
fn detects_maximum_scale_one() {
    let body = r#"<meta name="viewport" content="width=device-width, maximum-scale=1.0">"#;
    let issues = analyze_viewport(body);
    assert!(issues.contains(&ViewportIssue::MaximumScaleOne));
}

#[test]
fn maximum_scale_two_ok() {
    let body = r#"<meta name="viewport" content="width=device-width, maximum-scale=2.0">"#;
    let issues = analyze_viewport(body);
    assert!(!issues.contains(&ViewportIssue::MaximumScaleOne));
}

#[test]
fn detects_minimal_initial_scale() {
    let body = r#"<meta name="viewport" content="width=device-width, initial-scale=0.1">"#;
    let issues = analyze_viewport(body);
    assert!(issues.contains(&ViewportIssue::MinimalInitialScale));
}

#[test]
fn initial_scale_one_ok() {
    let body = r#"<meta name="viewport" content="width=device-width, initial-scale=1.0">"#;
    let issues = analyze_viewport(body);
    assert!(!issues.contains(&ViewportIssue::MinimalInitialScale));
}

#[test]
fn detects_fixed_width_viewport() {
    let body = r#"<meta name="viewport" content="width=320">"#;
    let issues = analyze_viewport(body);
    assert!(issues.contains(&ViewportIssue::FixedWidthViewport));
}

#[test]
fn device_width_not_fixed() {
    let body = r#"<meta name="viewport" content="width=device-width">"#;
    let issues = analyze_viewport(body);
    assert!(!issues.contains(&ViewportIssue::FixedWidthViewport));
}

#[test]
fn detects_shrink_to_fit_disabled() {
    let body = r#"<meta name="viewport" content="width=device-width, shrink-to-fit=no">"#;
    let issues = analyze_viewport(body);
    assert!(issues.contains(&ViewportIssue::ShrinkToFitDisabled));
}

#[test]
fn severity_zoom_disabled_highest() {
    assert_eq!(viewport_severity(&ViewportIssue::ZoomDisabled), 5.5);
}

#[test]
fn severity_viewport_missing_lowest() {
    assert_eq!(viewport_severity(&ViewportIssue::ViewportMissing), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![ViewportIssue::ZoomDisabled, ViewportIssue::ViewportMissing];
    let mut seq = 0;
    let ops = viewport_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(ViewportIssue::ZoomDisabled.to_string(), "zoom_disabled");
    assert_eq!(
        ViewportIssue::MaximumScaleOne.to_string(),
        "maximum_scale_one"
    );
    assert_eq!(
        ViewportIssue::ViewportMissing.to_string(),
        "viewport_missing"
    );
    assert_eq!(
        ViewportIssue::FixedWidthViewport.to_string(),
        "fixed_width_viewport"
    );
    assert_eq!(
        ViewportIssue::ShrinkToFitDisabled.to_string(),
        "shrink_to_fit_disabled"
    );
}

#[test]
fn security_detects_viewport_exfiltration() {
    let body = r#"
        <script>
        const width = window.innerWidth;
        fetch('/track', { method: 'POST', body: JSON.stringify({ width }) });
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportExfiltration));
}

#[test]
fn security_detects_viewport_exfiltration_xmlhttprequest() {
    let body = r#"
        <script>
        const viewport = document.querySelector('meta[name="viewport"]');
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/collect');
        xhr.send(viewport);
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportExfiltration));
}

#[test]
fn security_detects_viewport_exfiltration_sendbeacon() {
    let body = r#"
        <script>
        const height = window.innerHeight;
        navigator.sendBeacon('/analytics', JSON.stringify({ height }));
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportExfiltration));
}

#[test]
fn security_detects_viewport_fingerprinting() {
    let body = r#"
        <script>
        const fingerprint = {
            width: screen.width,
            height: screen.height,
            ua: navigator.userAgent
        };
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportFingerprinting));
}

#[test]
fn security_detects_viewport_fingerprinting_navigator() {
    let body = r#"
        <script>
        const id = viewport + navigator.platform + screen.width;
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportFingerprinting));
}

#[test]
fn security_detects_viewport_phishing_risk() {
    let body = r#"
        <script>
        const overlay = document.createElement('div');
        overlay.style.position = 'absolute';
        overlay.style.width = window.innerWidth + 'px';
        overlay.style.zIndex = 9999;
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportPhishingRisk));
}

#[test]
fn security_detects_viewport_phishing_risk_overlay() {
    let body = r#"
        <style>
        .fake-ui {
            width: calc(viewport * 0.9);
            overlay: auto;
        }
        </style>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportPhishingRisk));
}

#[test]
fn security_detects_viewport_tracking_persistence() {
    let body = r#"
        <script>
        localStorage.setItem('viewport_width', window.innerWidth);
        localStorage.setItem('viewport_height', window.innerHeight);
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportTrackingPersistence));
}

#[test]
fn security_detects_viewport_tracking_persistence_sessionstorage() {
    let body = r#"
        <script>
        const vp = viewport || innerWidth;
        sessionStorage.setItem('dims', vp);
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportTrackingPersistence));
}

#[test]
fn security_detects_viewport_cross_origin() {
    let body = r#"
        <script>
        const dimensions = {
            width: window.innerWidth,
            height: window.innerHeight
        };
        parent.postMessage(dimensions, '*');
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportCrossOrigin));
}

#[test]
fn security_detects_viewport_keylogger_risk() {
    let body = r#"
        <script>
        document.addEventListener('keydown', (e) => {
            const context = {
                key: e.key,
                viewport: window.innerWidth
            };
        });
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportKeyloggerRisk));
}

#[test]
fn security_detects_viewport_keylogger_risk_keypress() {
    let body = r#"
        <script>
        window.onkeypress = function() {
            track(viewport, innerHeight);
        };
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportKeyloggerRisk));
}

#[test]
fn security_detects_viewport_keylogger_risk_keyup() {
    let body = r#"
        <script>
        input.addEventListener('keyup', () => {
            log(innerWidth, innerHeight);
        });
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportKeyloggerRisk));
}

#[test]
fn security_detects_viewport_clickjacking() {
    let body = r#"
        <script>
        const frame = document.createElement('iframe');
        frame.style.width = window.innerWidth + 'px';
        frame.style.opacity = '0.01';
        frame.style.pointerEvents = 'none';
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportClickjacking));
}

#[test]
fn security_detects_viewport_clickjacking_iframe_only() {
    let body = r#"
        <iframe style="width: calc(viewport - 10px)"></iframe>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportClickjacking));
}

#[test]
fn security_detects_viewport_screen_capture() {
    let body = r#"
        <script>
        navigator.mediaDevices.getDisplayMedia({
            video: {
                width: screen.width,
                height: screen.height
            }
        });
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportScreenCapture));
}

#[test]
fn security_detects_viewport_screen_capture_capturestream() {
    let body = r#"
        <script>
        const canvas = document.querySelector('canvas');
        canvas.width = viewport;
        const stream = canvas.captureStream();
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportScreenCapture));
}

#[test]
fn security_detects_viewport_orientation_tracking() {
    let body = r#"
        <script>
        const vp = { w: screen.width, h: screen.height };
        screen.orientation.addEventListener('change', () => {
            trackOrientation(screen.orientation.type);
        });
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportOrientationTracking));
}

#[test]
fn security_detects_viewport_resize_spying() {
    let body = r#"
        <script>
        const observer = new ResizeObserver(entries => {
            for (const entry of entries) {
                track(entry.target.clientWidth, window.innerHeight);
            }
        });
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportResizeSpying));
}

#[test]
fn security_empty_body() {
    let issues = analyze_viewport_security("");
    assert!(issues.is_empty());
}

#[test]
fn security_no_viewport() {
    let body = "<html><head><title>Test</title></head></html>";
    let issues = analyze_viewport_security(body);
    assert!(issues.is_empty());
}

#[test]
fn security_severity_viewport_exfiltration() {
    assert_eq!(
        viewport_security_severity(&ViewportSecurityIssue::ViewportExfiltration),
        7.5
    );
}

#[test]
fn security_severity_viewport_keylogger_risk() {
    assert_eq!(
        viewport_security_severity(&ViewportSecurityIssue::ViewportKeyloggerRisk),
        7.0
    );
}

#[test]
fn security_severity_viewport_clickjacking() {
    assert_eq!(
        viewport_security_severity(&ViewportSecurityIssue::ViewportClickjacking),
        6.5
    );
}

#[test]
fn security_severity_viewport_screen_capture() {
    assert_eq!(
        viewport_security_severity(&ViewportSecurityIssue::ViewportScreenCapture),
        6.5
    );
}

#[test]
fn security_severity_viewport_fingerprinting() {
    assert_eq!(
        viewport_security_severity(&ViewportSecurityIssue::ViewportFingerprinting),
        6.0
    );
}

#[test]
fn security_severity_viewport_phishing_risk() {
    assert_eq!(
        viewport_security_severity(&ViewportSecurityIssue::ViewportPhishingRisk),
        6.0
    );
}

#[test]
fn security_severity_viewport_cross_origin() {
    assert_eq!(
        viewport_security_severity(&ViewportSecurityIssue::ViewportCrossOrigin),
        5.5
    );
}

#[test]
fn security_severity_viewport_tracking_persistence() {
    assert_eq!(
        viewport_security_severity(&ViewportSecurityIssue::ViewportTrackingPersistence),
        5.0
    );
}

#[test]
fn security_severity_viewport_orientation_tracking() {
    assert_eq!(
        viewport_security_severity(&ViewportSecurityIssue::ViewportOrientationTracking),
        4.5
    );
}

#[test]
fn security_severity_viewport_resize_spying() {
    assert_eq!(
        viewport_security_severity(&ViewportSecurityIssue::ViewportResizeSpying),
        4.0
    );
}

#[test]
fn security_operations_creates_entries() {
    let issues = vec![
        ViewportSecurityIssue::ViewportExfiltration,
        ViewportSecurityIssue::ViewportFingerprinting,
    ];
    let mut seq = 0;
    let ops = viewport_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_operations_empty_vec() {
    let issues: Vec<ViewportSecurityIssue> = vec![];
    let mut seq = 0;
    let ops = viewport_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn security_combined_multiple_issues() {
    let body = r#"
        <script>
        const dims = {
            width: window.innerWidth,
            height: window.innerHeight,
            ua: navigator.userAgent,
            platform: navigator.platform
        };
        fetch('/track', { method: 'POST', body: JSON.stringify(dims) });
        localStorage.setItem('fingerprint', JSON.stringify(dims));
        document.addEventListener('keydown', (e) => {
            console.log(e.key, dims);
        });
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportExfiltration));
    assert!(issues.contains(&ViewportSecurityIssue::ViewportFingerprinting));
    assert!(issues.contains(&ViewportSecurityIssue::ViewportTrackingPersistence));
    assert!(issues.contains(&ViewportSecurityIssue::ViewportKeyloggerRisk));
    assert_eq!(issues.len(), 4);
}

#[test]
fn security_combined_clickjacking_scenario() {
    let body = r#"
        <script>
        const frame = document.createElement('iframe');
        frame.style.width = window.innerWidth + 'px';
        frame.style.height = window.innerHeight + 'px';
        frame.style.pointerEvents = 'auto';
        parent.postMessage({ type: 'ready', dims: [innerWidth, innerHeight] }, '*');
        </script>
    "#;
    let issues = analyze_viewport_security(body);
    assert!(issues.contains(&ViewportSecurityIssue::ViewportClickjacking));
    assert!(issues.contains(&ViewportSecurityIssue::ViewportCrossOrigin));
    assert_eq!(issues.len(), 2);
}

#[test]
fn security_display_variants() {
    assert_eq!(
        ViewportSecurityIssue::ViewportExfiltration.to_string(),
        "viewport_exfiltration"
    );
    assert_eq!(
        ViewportSecurityIssue::ViewportFingerprinting.to_string(),
        "viewport_fingerprinting"
    );
    assert_eq!(
        ViewportSecurityIssue::ViewportPhishingRisk.to_string(),
        "viewport_phishing_risk"
    );
    assert_eq!(
        ViewportSecurityIssue::ViewportTrackingPersistence.to_string(),
        "viewport_tracking_persistence"
    );
    assert_eq!(
        ViewportSecurityIssue::ViewportCrossOrigin.to_string(),
        "viewport_cross_origin"
    );
    assert_eq!(
        ViewportSecurityIssue::ViewportKeyloggerRisk.to_string(),
        "viewport_keylogger_risk"
    );
    assert_eq!(
        ViewportSecurityIssue::ViewportClickjacking.to_string(),
        "viewport_clickjacking"
    );
    assert_eq!(
        ViewportSecurityIssue::ViewportScreenCapture.to_string(),
        "viewport_screen_capture"
    );
    assert_eq!(
        ViewportSecurityIssue::ViewportOrientationTracking.to_string(),
        "viewport_orientation_tracking"
    );
    assert_eq!(
        ViewportSecurityIssue::ViewportResizeSpying.to_string(),
        "viewport_resize_spying"
    );
}
